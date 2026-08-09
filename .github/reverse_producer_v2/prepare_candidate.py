#!/usr/bin/env python3
"""Fixed, secret-free Job A wrapper for an untrusted reverse candidate.

Job A is the only place candidate code may run.  This wrapper deliberately does
not let a candidate choose its command, manifest path, output path, interpreter,
or environment.  Its two output files are treated as hostile bytes by Job B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional, Sequence, Tuple


MAX_RAW_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_RAW_RECEIPT_BYTES = 1024 * 1024
MAX_CANDIDATE_STDOUT_BYTES = 1024 * 1024
MAX_CANDIDATE_STDERR_BYTES = 1024 * 1024
POST_EXIT_GRACE_SECONDS = 2.0
POST_KILL_GRACE_SECONDS = 2.0
COPY_CHUNK = 1024 * 1024
SHA40 = re.compile(r"^[0-9a-f]{40}$")
PREPARE_RECEIPT_SCHEMA = "spspy.trusted-reverse-producer-v2.prepare-receipt"
CANONICAL_SCRIPT = Path("tools/reverse_candidate_build_v2.py")
CANONICAL_CONFIG = Path("config/reverse_producer_v2.json")
CANONICAL_WORKFLOW_PATH = ".github/workflows/trusted-reverse-producer-v2.yml"
TRUSTED_REPOSITORY = "tonyaiuser/babata-board"
CANONICAL_BUILDER_AUTHORITY_REF = "refs/heads/main"
CANONICAL_SIGNER_WORKFLOW_REF = TRUSTED_REPOSITORY + "/" + CANONICAL_WORKFLOW_PATH + "@" + CANONICAL_BUILDER_AUTHORITY_REF
RAW_ARCHIVE_NAME = "raw-reverse.tar"
RAW_RECEIPT_NAME = "raw-reverse-receipt.json"
CANDIDATE_ARCHIVE_NAME = "release-payload.tar"
CANDIDATE_RECEIPT_NAME = "release-receipt.json"
FIXED_TEST_COMMAND = (
    "/usr/bin/python3",
    "-I",
    "-B",
    "-S",
    "-m",
    "unittest",
    "discover",
    "-s",
    "tests",
    "-p",
    "test_*.py",
)
UNITTEST_SUMMARY = re.compile(
    rb"(?m)^Ran ([1-9][0-9]*) tests? in [^\r\n]+\r?\n\r?\nOK(?: \([^\r\n]*\))?\r?$"
)


class PrepareError(RuntimeError):
    pass


class _CappedLog:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.bytes = 0
        self.digest = hashlib.sha256()
        self.exceeded = False
        # The retained bytes are capped as well.  They are needed only to
        # recognize the stdlib unittest summary; the receipt records hashes
        # and sizes, never candidate-controlled text.
        self._sample = bytearray()

    def add(self, data: bytes) -> None:
        self.bytes += len(data)
        self.digest.update(data)
        if self.bytes > self.limit:
            self.exceeded = True
        remaining = self.limit - len(self._sample)
        if remaining > 0:
            self._sample.extend(data[:remaining])

    def sample(self) -> bytes:
        return bytes(self._sample)

    def evidence(self) -> dict[str, Any]:
        return {"bytes": self.bytes, "sha256": self.digest.hexdigest(), "cap_bytes": self.limit, "within_cap": not self.exceeded}


def _fail(message: str) -> None:
    raise PrepareError(message)


def _clean_environment(home: Path, temporary: Path) -> dict[str, str]:
    # Keep the candidate away from inherited credentials, config, tool caches,
    # proxies, and the GitHub runtime environment.  The only writable locations
    # available to it are unique directories under RUNNER_TEMP.
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    return {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(temporary),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PIP_NO_CACHE_DIR": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git_value(candidate: Path, expression: str, environment: dict[str, str]) -> str:
    process = subprocess.run(
        ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(candidate), "rev-parse", "--verify", expression],
        check=False,
        cwd=str(candidate),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if process.returncode != 0:
        _fail(f"candidate git identity cannot be resolved: {expression}")
    value = process.stdout.strip()
    if not SHA40.fullmatch(value):
        _fail(f"candidate git identity is not a full SHA: {expression}")
    return value


def _require_regular(path: Path, *, max_bytes: int) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PrepareError(f"required candidate output is missing: {path.name}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        _fail(f"candidate output is not a single-link regular file: {path.name}")
    if info.st_size <= 0 or info.st_size > max_bytes:
        _fail(f"candidate output violates byte cap: {path.name}")
    return info


def _publish_exclusive(temporary: Path, destination: Path) -> None:
    """Publish a new file without replacing a same-UID adversary's path."""
    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise PrepareError(f"wrapper output target already exists: {destination.name}") from exc
    except OSError as exc:
        raise PrepareError(f"cannot publish wrapper output: {destination.name}") from exc
    temporary.unlink()


def _copy_checked(source: Path, destination: Path, *, max_bytes: int) -> Tuple[int, str]:
    _require_regular(source, max_bytes=max_bytes)
    if not hasattr(os, "O_NOFOLLOW"):
        _fail("platform lacks required O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    try:
        input_info = os.fstat(descriptor)
        if not stat.S_ISREG(input_info.st_mode) or input_info.st_nlink != 1 or input_info.st_size <= 0 or input_info.st_size > max_bytes:
            _fail(f"candidate output changed while being copied: {source.name}")
        digest = hashlib.sha256()
        written = 0
        temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as input_file, temporary.open("xb") as output_file:
                while True:
                    chunk = input_file.read(COPY_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        _fail(f"candidate output exceeds byte cap while copying: {source.name}")
                    digest.update(chunk)
                    output_file.write(chunk)
                output_file.flush()
                os.fsync(output_file.fileno())
            if written != input_info.st_size:
                _fail(f"candidate output changed while being copied: {source.name}")
            os.chmod(temporary, 0o600)
            _publish_exclusive(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return written, digest.hexdigest()
    finally:
        os.close(descriptor)


def _write_new_file(destination: Path, content: bytes) -> None:
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    if not hasattr(os, "O_NOFOLLOW"):
        _fail("platform lacks required O_NOFOLLOW")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        written = 0
        while written < len(content):
            written += os.write(descriptor, content[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        _publish_exclusive(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _validate_untrusted_json(path: Path) -> None:
    try:
        with path.open("r", encoding="utf-8", newline="") as input_file:
            text = input_file.read(MAX_RAW_RECEIPT_BYTES + 1)
    except (OSError, UnicodeDecodeError) as exc:
        raise PrepareError("candidate raw receipt is not UTF-8") from exc
    if len(text.encode("utf-8")) > MAX_RAW_RECEIPT_BYTES:
        _fail("candidate raw receipt exceeds byte cap")
    try:
        decoded = json.loads(text, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (ValueError, json.JSONDecodeError) as exc:
        raise PrepareError(f"candidate raw receipt is not strict JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        _fail("candidate raw receipt must be a JSON object")


def _signal_direct_leader(process_id: int, sig: int) -> bool:
    """Signal only the unreaped direct child; never a numeric process group."""
    try:
        os.kill(process_id, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        raise PrepareError("cannot terminate direct candidate process") from exc


def _run_fixed_command(
    command: Sequence[str],
    candidate: Path,
    environment: dict[str, str],
    timeout_seconds: int,
    *,
    phase: str,
) -> tuple[int, _CappedLog, _CappedLog]:
    """Run one fixed command while draining capped logs.

    This deliberately manages only the direct leader.  It never signals a
    numeric process group: a reaped group leader's number could be reused.  If
    descendants keep stdout/stderr open after a naturally exited leader, the
    wrapper closes those pipes after a fixed grace period and fails.  Any
    escaped descendants remain confined to secret-free Job A and can only
    produce hostile bytes for Job B's fresh-VM strict finalizer.
    """
    process = subprocess.Popen(
        list(command),
        cwd=str(candidate),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout = _CappedLog(MAX_CANDIDATE_STDOUT_BYTES)
    stderr = _CappedLog(MAX_CANDIDATE_STDERR_BYTES)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, stdout)
    selector.register(process.stderr, selectors.EVENT_READ, stderr)
    deadline = time.monotonic() + timeout_seconds
    terminate_at: Optional[float] = None
    kill_at: Optional[float] = None
    leader_reaped = False
    reaping_started = False
    pipes_deadline: Optional[float] = None
    failure: Optional[str] = None
    exit_code: Optional[int] = None
    try:
        while selector.get_map() or not leader_reaped:
            now = time.monotonic()
            if not leader_reaped:
                observed_exit_code = process.poll()
                if observed_exit_code is not None:
                    # This is the sole natural-exit reap path.  From here on,
                    # do not signal the numeric PID again.
                    leader_reaped = True
                    reaping_started = True
                    exit_code = observed_exit_code
                    pipes_deadline = now + POST_EXIT_GRACE_SECONDS
            if not leader_reaped and failure is None and now >= deadline:
                failure = f"fixed {phase} exceeded fixed timeout"
                _signal_direct_leader(process.pid, signal.SIGTERM)
                terminate_at = now
            if not leader_reaped and (stdout.exceeded or stderr.exceeded):
                if failure is None:
                    failure = f"fixed {phase} stdout or stderr exceeded fixed byte cap"
                    _signal_direct_leader(process.pid, signal.SIGTERM)
                    terminate_at = now
            if not leader_reaped and terminate_at is not None and now >= terminate_at + POST_EXIT_GRACE_SECONDS and kill_at is None:
                _signal_direct_leader(process.pid, signal.SIGKILL)
                kill_at = now
            if not leader_reaped and kill_at is not None and now >= kill_at + POST_KILL_GRACE_SECONDS:
                failure = failure or f"fixed {phase} leader did not exit after SIGKILL"
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                break
            if leader_reaped and selector.get_map() and pipes_deadline is not None and now >= pipes_deadline:
                failure = failure or f"fixed {phase} descendants kept output pipes open after leader exit"
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                break
            wait_seconds = min(0.1, max(0.0, deadline - now)) if failure is None and not leader_reaped else 0.05
            for key, _mask in selector.select(wait_seconds):
                stream = key.fileobj
                data = os.read(stream.fileno(), COPY_CHUNK)
                if not data:
                    selector.unregister(stream)
                    stream.close()
                    continue
                key.data.add(data)
        if not leader_reaped:
            # No PID-directed signal is attempted once wait() successfully
            # reaps the direct leader.  A timed-out wait leaves it unreaped,
            # so one final direct SIGKILL remains safe.
            try:
                exit_code = process.wait(timeout=POST_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                _signal_direct_leader(process.pid, signal.SIGKILL)
                exit_code = process.wait(timeout=POST_KILL_GRACE_SECONDS)
            leader_reaped = True
            reaping_started = True
        if failure is not None:
            _fail(failure)
        if exit_code != 0:
            _fail(f"fixed {phase} exited {exit_code}")
        if stdout.exceeded or stderr.exceeded:
            _fail(f"fixed {phase} stdout or stderr exceeded fixed byte cap")
        return exit_code, stdout, stderr
    except BaseException:
        # Only signal the direct leader before any reaping path begins.
        if not reaping_started:
            _signal_direct_leader(process.pid, signal.SIGTERM)
            _signal_direct_leader(process.pid, signal.SIGKILL)
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


def _positive_unittest_count(stderr: _CappedLog) -> int:
    """Require the final trusted unittest summary to report at least one test.

    Python's unittest runner writes its summary to stderr.  The wrapper does
    not accept candidate configuration or a candidate-selected test command;
    this check only proves that the fixed command reached its standard success
    summary before the fixed builder is allowed to run.
    """
    matches = list(UNITTEST_SUMMARY.finditer(stderr.sample()))
    if len(matches) != 1:
        _fail("fixed unittest command did not emit one positive successful test summary")
    return int(matches[0].group(1))


def _remaining_budget_seconds(overall_deadline: float, *, phase: str) -> int:
    """Return a whole-second budget that cannot extend past the shared limit."""
    remaining = int(overall_deadline - time.monotonic())
    if remaining < 1:
        _fail(f"fixed overall timeout expired before {phase}")
    return remaining


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(COPY_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tool_evidence(path: str, environment: dict[str, str]) -> dict[str, str]:
    executable = Path(path)
    try:
        version = subprocess.check_output([path, "--version"], env=environment, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, timeout=10).splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError) as exc:
        raise PrepareError(f"trusted tool cannot be identified: {path}") from exc
    return {"path": path, "sha256": _sha256_file(executable), "version": version}


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")


def prepare_candidate(
    candidate: Path,
    output_dir: Path,
    expected_commit: str,
    expected_tree: str,
    candidate_repository: str,
    workflow_repository: str,
    signer_workflow_ref: str,
    builder_authority_ref: str,
    workflow_commit: str,
    workflow_blob: str,
    timeout_seconds: int,
) -> dict[str, str]:
    if not all(SHA40.fullmatch(value) for value in (expected_commit, expected_tree, workflow_commit, workflow_blob)):
        _fail("candidate and workflow identifiers must be full SHAs")
    if (
        candidate_repository != TRUSTED_REPOSITORY
        or workflow_repository != TRUSTED_REPOSITORY
        or signer_workflow_ref != CANONICAL_SIGNER_WORKFLOW_REF
        or builder_authority_ref != CANONICAL_BUILDER_AUTHORITY_REF
    ):
        _fail("workflow authority does not match the fixed trusted main workflow")
    candidate = candidate.resolve(strict=True)
    if not candidate.is_dir():
        _fail("candidate directory is not a directory")
    try:
        output_parent = output_dir.parent.resolve(strict=True)
    except OSError as exc:
        raise PrepareError("wrapper output parent is unavailable") from exc
    output_dir = output_parent / output_dir.name
    if output_dir.exists() or output_dir.is_symlink():
        _fail("wrapper output directory must not exist before candidate execution")
    # Do not create the wrapper-owned output directory until both direct
    # commands are reaped and their pipes have closed.  A candidate does not
    # receive this path.
    with tempfile.TemporaryDirectory(prefix="trusted-reverse-v2-", dir=output_parent) as temporary:
        temporary_root = Path(temporary)
        environment = _clean_environment(temporary_root / "home", temporary_root / "tmp")
        if _git_value(candidate, "HEAD", environment) != expected_commit:
            _fail("checked out candidate commit differs from requested SHA")
        if _git_value(candidate, "HEAD^{tree}", environment) != expected_tree:
            _fail("checked out candidate tree differs from requested tree SHA")
        script = candidate / CANONICAL_SCRIPT
        config = candidate / CANONICAL_CONFIG
        for required in (script, config):
            info = required.lstat() if required.exists() or required.is_symlink() else None
            if info is None or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                _fail(f"candidate is missing a safe canonical input: {required.relative_to(candidate)}")
        candidate_output = temporary_root / "candidate-output"
        candidate_output.mkdir(mode=0o700)
        raw_archive = candidate_output / CANDIDATE_ARCHIVE_NAME
        raw_receipt = candidate_output / CANDIDATE_RECEIPT_NAME
        # This is deliberately independent of candidate configuration.  It
        # covers every normal unittest module under tests/ and must finish with
        # a positive stdlib success summary before packaging can begin.
        overall_deadline = time.monotonic() + timeout_seconds
        test_timeout_seconds = _remaining_budget_seconds(overall_deadline, phase="unittest")
        test_exit_code, test_stdout, test_stderr = _run_fixed_command(
            FIXED_TEST_COMMAND,
            candidate,
            environment,
            test_timeout_seconds,
            phase="unittest",
        )
        test_count = _positive_unittest_count(test_stderr)
        build_timeout_seconds = _remaining_budget_seconds(overall_deadline, phase="candidate builder")
        build_command = [
            "/usr/bin/python3",
            "-I",
            "-B",
            "-S",
            str(script),
            "--candidate-root", str(candidate),
            "--source-commit", expected_commit,
            "--source-tree", expected_tree,
            "--candidate-repository", candidate_repository,
            "--workflow-repository", workflow_repository,
            "--workflow-path", CANONICAL_WORKFLOW_PATH,
            "--workflow-ref", builder_authority_ref,
            "--signer-workflow-ref", signer_workflow_ref,
            "--workflow-commit", workflow_commit,
            "--workflow-blob", workflow_blob,
            "--output-dir", str(candidate_output),
        ]
        build_exit_code, build_stdout, build_stderr = _run_fixed_command(
            build_command,
            candidate,
            environment,
            build_timeout_seconds,
            phase="candidate builder",
        )
        try:
            output_dir.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise PrepareError("wrapper output directory was pre-created during candidate execution") from exc
        if output_dir.is_symlink() or not output_dir.is_dir():
            _fail("wrapper output directory is unsafe after candidate execution")
        # The archive is copied by open file descriptor to a wrapper-owned
        # directory.  The candidate's self-reported receipt is checked only as
        # hostile JSON and represented below solely by its digest.
        archive_bytes, archive_digest = _copy_checked(raw_archive, output_dir / RAW_ARCHIVE_NAME, max_bytes=MAX_RAW_ARCHIVE_BYTES)
        receipt_bytes, receipt_digest = _copy_checked(raw_receipt, temporary_root / "candidate-receipt.checked.json", max_bytes=MAX_RAW_RECEIPT_BYTES)
        _validate_untrusted_json(temporary_root / "candidate-receipt.checked.json")
        trusted_receipt = {
            "candidate": {
                "commit": expected_commit,
                "config_sha256": _sha256_file(config),
                "repository": candidate_repository,
                "script_sha256": _sha256_file(script),
                "tree": expected_tree,
            },
            "candidate_raw_receipt": {"bytes": receipt_bytes, "sha256": receipt_digest},
            "commands": {
                "build": {
                    "argv": [
                    "/usr/bin/python3", "-I", "-B", "-S", str(CANONICAL_SCRIPT), "--candidate-root", ".",
                    "--source-commit", expected_commit, "--source-tree", expected_tree,
                    "--candidate-repository", candidate_repository,
                    "--workflow-repository", workflow_repository, "--workflow-path", CANONICAL_WORKFLOW_PATH,
                    "--workflow-ref", builder_authority_ref, "--workflow-commit", workflow_commit,
                    "--signer-workflow-ref", signer_workflow_ref,
                    "--workflow-blob", workflow_blob, "--output-dir", ".wrapper-owned-output",
                    ],
                    "cwd": ".",
                    "timeout_seconds": build_timeout_seconds,
                },
                "tests": {
                    "argv": list(FIXED_TEST_COMMAND),
                    "cwd": ".",
                    "timeout_seconds": test_timeout_seconds,
                },
            },
            "execution": {
                "build": {"exit_code": build_exit_code, "stderr": build_stderr.evidence(), "stdout": build_stdout.evidence()},
                "tests": {
                    "exit_code": test_exit_code,
                    "positive_test_count": test_count,
                    "stderr": test_stderr.evidence(),
                    "stdout": test_stdout.evidence(),
                },
            },
            "limits": {
                "raw_archive_bytes": MAX_RAW_ARCHIVE_BYTES,
                "raw_receipt_bytes": MAX_RAW_RECEIPT_BYTES,
                "stderr_bytes": MAX_CANDIDATE_STDERR_BYTES,
                "stdout_bytes": MAX_CANDIDATE_STDOUT_BYTES,
                "overall_prepare_seconds": timeout_seconds,
            },
            "raw_archive": {"bytes": archive_bytes, "sha256": archive_digest},
            "schema": PREPARE_RECEIPT_SCHEMA,
            "tools": {
                "git": _tool_evidence("/usr/bin/git", environment),
                "python": _tool_evidence("/usr/bin/python3", environment),
                "wrapper": {"path": ".github/reverse_producer_v2/prepare_candidate.py", "sha256": _sha256_file(Path(__file__))},
            },
            "workflow": {
                "blob": workflow_blob,
                "commit": workflow_commit,
                "path": CANONICAL_WORKFLOW_PATH,
                "builder_authority_ref": builder_authority_ref,
                "signer_workflow_ref": signer_workflow_ref,
                "repository": workflow_repository,
            },
            "version": 1,
        }
        receipt_target = output_dir / RAW_RECEIPT_NAME
        _write_new_file(receipt_target, _canonical_json(trusted_receipt))
    return {
        "raw_archive_bytes": str(archive_bytes),
        "raw_archive_sha256": archive_digest,
        "raw_receipt_bytes": str(receipt_target.stat().st_size),
        "raw_receipt_sha256": _sha256_file(receipt_target),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--candidate-repository", required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--signer-workflow-ref", required=True)
    parser.add_argument("--builder-authority-ref", required=True)
    parser.add_argument("--workflow-commit", required=True)
    parser.add_argument("--workflow-blob", required=True)
    parser.add_argument("--timeout-seconds", default=1200, type=int)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.timeout_seconds < 1 or args.timeout_seconds > 1200:
            _fail("timeout must be between 1 and 1200 seconds")
        result = prepare_candidate(
            args.candidate_dir,
            args.output_dir,
            args.source_commit.lower(),
            args.source_tree.lower(),
            args.candidate_repository,
            args.workflow_repository,
            args.signer_workflow_ref,
            args.builder_authority_ref,
            args.workflow_commit.lower(),
            args.workflow_blob.lower(),
            args.timeout_seconds,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (PrepareError, OSError, subprocess.SubprocessError) as exc:
        print(f"trusted reverse v2 prepare: {exc}", file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
