#!/usr/bin/env python3
"""Publish the FB dashboard as one verified, lease-protected Git transaction."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath


MONTH_PATTERN = re.compile(r"^\d{4}-\d{2}$")
BATCH_PATH_PATTERN = re.compile(
    r"^fb_verify_batches/(?P<month>\d{4}-\d{2})/"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*\.html)$"
)
MAIN_DESTINATION = "fb_verify_dashboard.html"
JOURNAL_SCHEMA_VERSION = 2


class PublishError(RuntimeError):
    pass


class PublishLockBusy(PublishError):
    pass


def _git(repo: Path | None, *arguments: str, text: bool = False, check: bool = True):
    command = ["git"]
    if repo is not None:
        command += ["-C", str(repo)]
    command += list(arguments)
    try:
        return subprocess.run(
            command,
            check=check,
            capture_output=True,
            text=text,
            timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        detail = (stderr or "").strip()
        raise PublishError(
            f"git command failed ({' '.join(command)}): {detail or f'exit {exc.returncode}'}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise PublishError(f"git command timed out: {' '.join(command)}") from exc


def _parse_month(value: str) -> str:
    if not MONTH_PATTERN.fullmatch(value):
        raise PublishError("publish month must use YYYY-MM")
    try:
        parsed = datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise PublishError("publish month is not a real calendar month") from exc
    if parsed.strftime("%Y-%m") != value:
        raise PublishError("publish month is not canonical")
    return value


def _canonical_repo_url(value: str) -> str:
    # Preserve network/scp-style URLs exactly. Resolve an existing local bare
    # remote once so clone and origin-url verification bind to the same target.
    if "://" not in value and not re.match(r"^[^/]+@[^:]+:", value):
        candidate = Path(value).expanduser()
        if candidate.exists():
            return str(candidate.resolve())
    return value


def _regular_source(path: Path, label: str) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise PublishError(f"{label} is unreadable: {path}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise PublishError(f"{label} must be a regular file: {path}")
    return resolved


def _load_release(args):
    month = _parse_month(args.month)
    dashboard = _regular_source(Path(args.dashboard_source), "dashboard source")
    if dashboard.name != MAIN_DESTINATION or dashboard.parent.name != month:
        raise PublishError(
            "dashboard source must be <data-root>/<YYYY-MM>/fb_verify_dashboard.html"
        )
    release = {MAIN_DESTINATION: dashboard.read_bytes()}
    sources = {MAIN_DESTINATION: dashboard}

    has_batch_source = bool(args.batch_source)
    has_batch_destination = bool(args.batch_destination)
    if has_batch_source != has_batch_destination:
        raise PublishError("batch source and destination must be provided together")
    if has_batch_source:
        match = BATCH_PATH_PATTERN.fullmatch(args.batch_destination)
        if not match or match.group("month") != month:
            raise PublishError(
                "batch destination must be fb_verify_batches/<month>/<safe-name>.html"
            )
        batch = _regular_source(Path(args.batch_source), "batch source")
        if (
            batch.parent.name != "batches"
            or batch.parent.parent != dashboard.parent
            or batch.name != match.group("name")
        ):
            raise PublishError(
                "batch source must be <month>/batches/<destination-basename>"
            )
        release[args.batch_destination] = batch.read_bytes()
        sources[args.batch_destination] = batch

    for destination, content in release.items():
        if not content:
            raise PublishError(f"refusing to publish an empty FB page: {destination}")
    return month, release, sources


class PublishLock:
    """Lock the persistent checkout-parent directory, never a replaceable file."""

    def __init__(self, directory: Path):
        self.path = directory
        self.descriptor = None

    def __enter__(self):
        try:
            before = self.path.lstat()
        except OSError as exc:
            raise PublishError(f"cannot inspect publish lock directory {self.path}: {exc}") from exc
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise PublishError(f"publish lock anchor must be a real directory: {self.path}")
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise PublishError(f"cannot open publish lock {self.path}: {exc}") from exc
        try:
            opened = os.fstat(descriptor)
            fd_path = os.stat(f"/dev/fd/{descriptor}")
            if not stat.S_ISDIR(opened.st_mode) or (
                opened.st_dev, opened.st_ino
            ) != (before.st_dev, before.st_ino) or (
                not stat.S_ISDIR(fd_path.st_mode)
                or fd_path.st_ino != opened.st_ino
            ):
                raise PublishError(f"publish lock directory inode changed: {self.path}")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise PublishLockBusy(f"FB Pages publish lock is busy: {self.path}") from exc
            after = self.path.lstat()
            if stat.S_ISLNK(after.st_mode) or (
                after.st_dev, after.st_ino
            ) != (opened.st_dev, opened.st_ino):
                raise PublishError(f"publish lock directory was replaced: {self.path}")
        except Exception:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)
            raise
        self.descriptor = descriptor
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.descriptor is not None:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self.descriptor = None


def _ensure_checkout(repo_url: str, worktree: Path):
    if worktree.is_symlink():
        raise PublishError(f"publish worktree must not be a symlink: {worktree}")
    if worktree.exists():
        check = _git(
            worktree, "rev-parse", "--is-inside-work-tree", text=True, check=False
        )
        if check.returncode != 0 or check.stdout.strip() != "true":
            raise PublishError(f"publish path is not a Git worktree: {worktree}")
        return

    worktree.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{worktree.name}.clone.", dir=worktree.parent)
    )
    try:
        _git(
            None,
            "clone",
            "--branch",
            "main",
            "--single-branch",
            "--",
            repo_url,
            str(temporary),
        )
        os.replace(temporary, worktree)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _status_bytes(repo: Path) -> bytes:
    return _git(
        repo, "status", "--porcelain=v1", "-z", "--untracked-files=all"
    ).stdout


def _nul_paths(output: bytes):
    return {item.decode("utf-8") for item in output.split(b"\0") if item}


def _staged_paths(repo: Path):
    return _nul_paths(
        _git(
            repo,
            "diff",
            "--cached",
            "--name-only",
            "--no-renames",
            "-z",
            "HEAD",
            "--",
        ).stdout
    )


def _unstaged_paths(repo: Path):
    return _nul_paths(
        _git(repo, "diff", "--name-only", "--no-renames", "-z", "--").stdout
    )


def _untracked_paths(repo: Path):
    return _nul_paths(
        _git(repo, "ls-files", "--others", "--exclude-standard", "-z", "--").stdout
    )


def _remote_head(repo: Path) -> str:
    output = _git(
        repo, "ls-remote", "--exit-code", "origin", "refs/heads/main", text=True
    ).stdout.split()
    if len(output) != 2 or output[1] != "refs/heads/main":
        raise PublishError("origin/main did not resolve to exactly one commit")
    commit = output[0]
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise PublishError("origin/main returned an invalid object id")
    return commit


def _rev_parse(repo: Path, revision: str) -> str:
    return _git(repo, "rev-parse", "--verify", revision, text=True).stdout.strip()


def _verify_checkout_identity(repo: Path, expected_repo_url: str):
    origin_url = _git(repo, "remote", "get-url", "origin", text=True).stdout.strip()
    if _canonical_repo_url(origin_url) != expected_repo_url:
        raise PublishError("FB Pages origin URL disagrees with configured repository")
    branch = _git(repo, "symbolic-ref", "--quiet", "HEAD", text=True, check=False)
    if branch.returncode != 0 or branch.stdout.strip() != "refs/heads/main":
        raise PublishError("FB Pages checkout must be on local branch main")


def _inspect_clean_checkout(repo: Path, expected_repo_url: str) -> str:
    if _status_bytes(repo):
        raise PublishError("FB Pages worktree or index is not clean")
    _verify_checkout_identity(repo, expected_repo_url)
    return _remote_head(repo)


def _bind_clean_checkout_to_remote(
    repo: Path, expected_repo_url: str, expected_remote: str | None = None
) -> str:
    remote = _inspect_clean_checkout(repo, expected_repo_url)
    if expected_remote is not None and remote != expected_remote:
        raise PublishError("origin/main changed before the FB publish transaction started")

    _git(repo, "fetch", "--no-tags", "origin", "refs/heads/main")
    fetched = _rev_parse(repo, "FETCH_HEAD^{commit}")
    if fetched != remote:
        raise PublishError("origin/main changed while establishing publish baseline")
    _git(repo, "merge", "--ff-only", fetched)
    head = _rev_parse(repo, "HEAD^{commit}")
    if head != remote or _status_bytes(repo):
        raise PublishError("FB Pages HEAD is not cleanly bound to origin/main")
    return head


def _converge_clean_checkout_to_remote(repo: Path, expected_repo_url: str) -> str:
    """Fast-forward a known-clean checkout before granting journal authority.

    A clean local branch can still be ahead because a human committed in the
    dedicated clone.  That is not ours to reset.  `merge --ff-only` accepts
    only an ancestor relationship, so an ahead/diverged branch fails before a
    journal is created or any page bytes are touched.
    """
    remote = _inspect_clean_checkout(repo, expected_repo_url)
    _git(repo, "fetch", "--no-tags", "origin", "refs/heads/main")
    fetched = _rev_parse(repo, "FETCH_HEAD^{commit}")
    if fetched != remote:
        raise PublishError("origin/main changed while converging clean FB checkout")
    _git(repo, "merge", "--ff-only", fetched)
    head = _rev_parse(repo, "HEAD^{commit}")
    if head != remote or _status_bytes(repo):
        raise PublishError("FB Pages checkout did not safely converge to origin/main")
    return head


def _ensure_destination_parent(repo: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise PublishError(f"unsafe FB Pages destination: {relative}")
    current = repo
    for part in pure.parts[:-1]:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise PublishError(f"unsafe destination parent: {current}")
        else:
            current.mkdir()
    return repo.joinpath(*pure.parts)


def _atomic_write(destination: Path, content: bytes, temporary: Path):
    """Durably replace a page without creating an untracked worktree file.

    The temporary pathname lives in the checkout parent, is generated and
    fsync'ed into the journal before this function is called, and is therefore
    recoverable after SIGKILL.  A target directory mounted on another device
    would turn replace into a non-atomic cross-device operation, so refuse it.
    """
    try:
        temp_status = temporary.lstat()
        raise PublishError(f"FB publish temporary already exists: {temporary}")
    except FileNotFoundError:
        pass
    if destination.parent.stat().st_dev != temporary.parent.stat().st_dev:
        raise PublishError("FB publish temporary and destination are on different filesystems")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _test_crash("temp_after_fsync")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(directory: Path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _journal_path(parent: Path, worktree: Path) -> Path:
    return parent / f".{worktree.name}.fb-pages-publish-journal.json"


def _source_hashes(release) -> dict[str, str]:
    return {
        destination: hashlib.sha256(content).hexdigest()
        for destination, content in sorted(release.items())
    }


def _journal_write(path: Path, payload):
    """Atomically replace the crash-recovery record and durably name it."""
    try:
        if path.exists() or path.is_symlink():
            status = path.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
                raise PublishError(f"FB publish journal is not a regular file: {path}")
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=f".{path.name}.{os.getpid()}.",
                suffix=".tmp", delete=False,
            ) as handle:
                temporary = Path(handle.name)
                os.fchmod(handle.fileno(), 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            _fsync_directory(path.parent)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    except PublishError:
        raise
    except OSError as exc:
        raise PublishError(f"cannot durably write FB publish journal: {exc}") from exc


def _journal_clear(path: Path):
    try:
        if not path.exists() and not path.is_symlink():
            return
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise PublishError(f"FB publish journal is not a regular file: {path}")
        path.unlink()
        _fsync_directory(path.parent)
    except PublishError:
        raise
    except OSError as exc:
        raise PublishError(f"cannot durably clear FB publish journal: {exc}") from exc


def _journal_destination_allowed(month: str, destination: str) -> bool:
    if destination == MAIN_DESTINATION:
        return True
    match = BATCH_PATH_PATTERN.fullmatch(destination)
    return bool(match and match.group("month") == month)


def _object_id(value) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{40,64}", value))


def _new_journal(parent: Path, worktree: Path, repo_url: str, month: str, initial: str, release):
    status = parent.stat()
    nonce = secrets.token_hex(24)
    allowlist = sorted(release)
    return {
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "repo_url": repo_url,
        "worktree": str(worktree),
        "parent_device": status.st_dev,
        "parent_inode": status.st_ino,
        "month": month,
        "initial_commit": initial,
        "allowlist": allowlist,
        "source_sha256": _source_hashes(release),
        "planned_paths": None,
        "temp_nonce": nonce,
        "temp_files": {
            destination: f".{worktree.name}.fb-pages-write.{nonce}.{index}.tmp"
            for index, destination in enumerate(allowlist)
        },
        "staged_paths": None,
        "prepared_tree": None,
        "verified_commit": None,
        "verified_tree": None,
    }


def _planned_paths(repo: Path, initial: str, release) -> list[str]:
    """Return the immutable release delta before any worktree mutation."""
    planned = []
    for destination, content in sorted(release.items()):
        if _revision_blob(repo, initial, destination) != content:
            planned.append(destination)
    return planned


def _journal_temp_path(parent: Path, journal: dict, destination: str) -> Path:
    name = journal["temp_files"][destination]
    candidate = parent / name
    if candidate.parent != parent or candidate.name != name:
        raise PublishError("FB publish journal temporary escapes checkout parent")
    return candidate


def _clear_journal_temps(parent: Path, journal: dict):
    """Remove only the random, journal-bound external write temporaries."""
    removed = False
    for destination in journal["allowlist"]:
        temporary = _journal_temp_path(parent, journal, destination)
        try:
            status = temporary.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise PublishError(f"FB publish recovery found unsafe journal temporary: {temporary}")
        temporary.unlink()
        removed = True
    if removed:
        _fsync_directory(parent)


def _read_journal(path: Path, parent: Path, worktree: Path, repo_url: str):
    """Read a fully specified journal.  Ambiguity is never recoverable."""
    try:
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise PublishError(f"FB publish journal is not a regular file: {path}")
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except PublishError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublishError(f"FB publish journal is corrupt: {exc}") from exc
    expected_keys = {
        "schema_version", "repo_url", "worktree", "parent_device", "parent_inode",
        "month", "initial_commit", "allowlist", "source_sha256", "planned_paths",
        "temp_nonce", "temp_files", "prepared_tree", "staged_paths", "verified_commit",
        "verified_tree",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise PublishError("FB publish journal has an unrecognized schema")
    parent_status = parent.stat()
    if (
        payload["schema_version"] != JOURNAL_SCHEMA_VERSION
        or payload["repo_url"] != repo_url
        or payload["worktree"] != str(worktree)
        or payload["parent_device"] != parent_status.st_dev
        or payload["parent_inode"] != parent_status.st_ino
        or not isinstance(payload["month"], str)
        or not MONTH_PATTERN.fullmatch(payload["month"])
        or not _object_id(payload["initial_commit"])
    ):
        raise PublishError("FB publish journal identity is invalid")
    try:
        _parse_month(payload["month"])
    except PublishError as exc:
        raise PublishError("FB publish journal month is invalid") from exc
    allowlist = payload["allowlist"]
    hashes = payload["source_sha256"]
    if (
        not isinstance(allowlist, list)
        or allowlist != sorted(set(allowlist))
        or not allowlist
        or not all(isinstance(item, str) and _journal_destination_allowed(payload["month"], item) for item in allowlist)
        or not isinstance(hashes, dict)
        or set(hashes) != set(allowlist)
        or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values())
    ):
        raise PublishError("FB publish journal allowlist is invalid")
    planned_paths = payload["planned_paths"]
    if planned_paths is not None and (
        not isinstance(planned_paths, list)
        or planned_paths != sorted(set(planned_paths))
        or not set(planned_paths).issubset(set(allowlist))
    ):
        raise PublishError("FB publish journal planned paths are invalid")
    nonce = payload["temp_nonce"]
    temp_files = payload["temp_files"]
    expected_temp_files = {
        destination: f".{worktree.name}.fb-pages-write.{nonce}.{index}.tmp"
        for index, destination in enumerate(allowlist)
    }
    if (
        not isinstance(nonce, str)
        or not re.fullmatch(r"[a-f0-9]{48}", nonce)
        or not isinstance(temp_files, dict)
        or temp_files != expected_temp_files
    ):
        raise PublishError("FB publish journal temporary protocol is invalid")
    for key in ("prepared_tree", "verified_commit", "verified_tree"):
        value = payload[key]
        if value is not None and not _object_id(value):
            raise PublishError("FB publish journal object id is invalid")
    staged_paths = payload["staged_paths"]
    if staged_paths is not None and (
        not isinstance(staged_paths, list)
        or staged_paths != sorted(set(staged_paths))
        or not staged_paths
        or not set(staged_paths).issubset(set(allowlist))
    ):
        raise PublishError("FB publish journal staged paths are invalid")
    if planned_paths is None:
        raise PublishError("FB publish journal has no durable mutation plan")
    if payload["prepared_tree"] is not None and staged_paths is None:
        raise PublishError("FB publish journal prepared tree has no staged paths")
    if payload["verified_commit"] is None and payload["verified_tree"] is not None:
        raise PublishError("FB publish journal has a commit/tree mismatch")
    if payload["verified_commit"] is not None and (
        payload["prepared_tree"] is None
        or staged_paths is None
        or payload["verified_tree"] != payload["prepared_tree"]
    ):
        raise PublishError("FB publish journal verified transaction is incomplete")
    return payload


def _test_crash(point: str):
    # Test-only fault point.  SIGKILL deliberately bypasses Python cleanup.
    if (
        os.environ.get("FB_VERIFY_TEST_MODE") == "1"
        and os.environ.get("FB_VERIFY_TEST_CRASH_AT") == point
    ):
        os.kill(os.getpid(), signal.SIGKILL)


def _test_fail(point: str):
    if (
        os.environ.get("FB_VERIFY_TEST_MODE") == "1"
        and os.environ.get("FB_VERIFY_TEST_FAIL_AT") == point
    ):
        raise PublishError(f"injected FB publish failure at {point}")


def _verify_sources(sources, expected):
    for destination, path in sources.items():
        try:
            actual = path.read_bytes()
        except OSError as exc:
            raise PublishError(f"FB page source changed or disappeared: {path}") from exc
        if actual != expected[destination]:
            raise PublishError(f"FB page source changed during publish: {path}")


def _show(repo: Path, object_spec: str) -> bytes:
    return _git(repo, "show", object_spec).stdout


def _verify_release_bytes(repo: Path, revision: str | None, release):
    for destination, expected in release.items():
        object_spec = f":{destination}" if revision is None else f"{revision}:{destination}"
        if _show(repo, object_spec) != expected:
            location = "index" if revision is None else f"commit {revision}"
            raise PublishError(f"FB page {location} bytes mismatch: {destination}")
        stage = _git(
            repo,
            "ls-files",
            "--stage",
            "--",
            destination,
            text=True,
        ).stdout.strip()
        if revision is None and (not stage or stage.split()[0] != "100644"):
            raise PublishError(f"FB page index mode is not 100644: {destination}")
        if revision is None:
            _assert_ordinary_index_flags(repo, destination, present=True)


def _verify_remote_release(repo: Path, commit: str, release):
    if _remote_head(repo) != commit:
        raise PublishError("remote main does not point to the verified FB release commit")
    _git(
        repo,
        "fetch",
        "--force",
        "--no-tags",
        "origin",
        "refs/heads/main:refs/remotes/origin/main",
    )
    fetched = _rev_parse(repo, "refs/remotes/origin/main^{commit}")
    if fetched != commit or _remote_head(repo) != commit:
        raise PublishError("remote main changed during post-push verification")
    for destination, expected in release.items():
        if _show(repo, f"refs/remotes/origin/main:{destination}") != expected:
            raise PublishError(f"remote FB page bytes mismatch: {destination}")


def _restore(repo: Path, commit: str, destinations, source_hashes):
    _git(repo, "reset", "--hard", commit)
    # `git clean -f` deliberately skips ignored paths.  A destination created
    # by this transaction can become ignored after a crash, so remove only an
    # exact journal-owned target that is absent from the restoration commit.
    for destination in sorted(destinations):
        if _revision_blob(repo, commit, destination) is not None:
            continue
        parts = PurePosixPath(destination).parts
        parent = repo
        missing_parent = False
        for part in parts[:-1]:
            parent = parent / part
            try:
                status = parent.lstat()
            except FileNotFoundError:
                missing_parent = True
                break
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise PublishError("FB publish rollback found an unsafe destination parent")
        if missing_parent:
            continue
        target = parent / parts[-1]
        try:
            status = target.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise PublishError("FB publish rollback found an unsafe new destination")
        expected_hash = source_hashes.get(destination)
        if (
            not isinstance(expected_hash, str)
            or hashlib.sha256(target.read_bytes()).hexdigest() != expected_hash
        ):
            raise PublishError("FB publish rollback refuses unknown new destination bytes")
        target.unlink()
        _fsync_directory(parent)
    _git(repo, "clean", "-f", "-d", "--", *sorted(destinations))
    if _rev_parse(repo, "HEAD^{commit}") != commit or _status_bytes(repo):
        raise PublishError("FB Pages transaction rollback did not restore a clean checkout")
    _assert_destinations_at_revision(repo, commit, destinations)


def _revision_blob(repo: Path, revision: str, destination: str):
    object_spec = f":{destination}" if revision == ":" else f"{revision}:{destination}"
    result = _git(repo, "show", object_spec, check=False)
    if result.returncode == 0:
        return result.stdout
    return None


def _working_blob(repo: Path, destination: str):
    parts = PurePosixPath(destination).parts
    current = repo
    for part in parts[:-1]:
        current = current / part
        try:
            status = current.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise PublishError("FB publish destination has an unsafe parent path")
    target = current / parts[-1]
    try:
        status = target.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(status.st_mode):
        raise PublishError("FB publish recovery found a symlinked transaction path")
    if not stat.S_ISREG(status.st_mode):
        raise PublishError("FB publish recovery found a non-file transaction path")
    return target.read_bytes()


def _tree_mode(repo: Path, revision: str, destination: str):
    output = _git(repo, "ls-tree", "-z", revision, "--", destination).stdout
    if not output:
        return None
    entries = [entry for entry in output.split(b"\0") if entry]
    if len(entries) != 1 or b"\t" not in entries[0]:
        raise PublishError("FB publish destination has an ambiguous tree entry")
    metadata, raw_path = entries[0].split(b"\t", 1)
    fields = metadata.split()
    if len(fields) != 3 or raw_path.decode("utf-8") != destination:
        raise PublishError("FB publish destination tree entry is malformed")
    return fields[0].decode("ascii")


def _index_mode(repo: Path, destination: str):
    output = _git(repo, "ls-files", "--stage", "-z", "--", destination).stdout
    if not output:
        return None
    entries = [entry for entry in output.split(b"\0") if entry]
    if len(entries) != 1 or b"\t" not in entries[0]:
        raise PublishError("FB publish destination has an ambiguous index entry")
    metadata, raw_path = entries[0].split(b"\t", 1)
    fields = metadata.split()
    if len(fields) != 3 or fields[2] != b"0" or raw_path.decode("utf-8") != destination:
        raise PublishError("FB publish destination index entry is malformed")
    return fields[0].decode("ascii")


def _index_tag(repo: Path, destination: str, option: str):
    """Return one ls-files status tag, rejecting ambiguous index records."""
    output = _git(repo, "ls-files", option, "-z", "--", destination).stdout
    if not output:
        return None
    entries = [entry for entry in output.split(b"\0") if entry]
    if len(entries) != 1 or len(entries[0]) < 3 or entries[0][1:2] != b" ":
        raise PublishError("FB publish destination has ambiguous index flags")
    tag = entries[0][:1]
    raw_path = entries[0][2:]
    if raw_path.decode("utf-8") != destination:
        raise PublishError("FB publish destination index flag path is malformed")
    try:
        return tag.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PublishError("FB publish destination index flag is malformed") from exc


def _assert_ordinary_index_flags(repo: Path, destination: str, *, present: bool):
    # -t exposes skip-worktree, -v lowercases assume-unchanged, and -f
    # lowercases fsmonitor-valid.  A publisher target must be an ordinary
    # cached entry under every view; otherwise git add may silently skip it.
    tags = tuple(_index_tag(repo, destination, option) for option in ("-t", "-v", "-f"))
    expected = ("H", "H", "H") if present else (None, None, None)
    if tags != expected:
        raise PublishError(
            f"FB publish destination has non-ordinary index flags: {destination}"
        )


def _assert_destinations_at_revision(repo: Path, revision: str, destinations):
    """Prove tree, index and actual filesystem bytes match one revision."""
    for destination in sorted(destinations):
        baseline = _revision_blob(repo, revision, destination)
        tree_mode = _tree_mode(repo, revision, destination)
        index = _revision_blob(repo, ":", destination)
        _assert_ordinary_index_flags(repo, destination, present=index is not None)
        index_mode = _index_mode(repo, destination)
        working = _working_blob(repo, destination)
        if baseline is None:
            _assert_ordinary_index_flags(repo, destination, present=False)
            if tree_mode is not None or index is not None or index_mode is not None or working is not None:
                raise PublishError(
                    f"FB publish destination is not absent at its baseline: {destination}"
                )
        elif (
            tree_mode != "100644"
            or index_mode != "100644"
            or index != baseline
            or working != baseline
        ):
            raise PublishError(
                f"FB publish destination differs from its tracked baseline: {destination}"
            )
        else:
            _assert_ordinary_index_flags(repo, destination, present=True)


def _assert_journal_owned_postreset_state(repo: Path, journal: dict):
    """Prove reset completed while an ignored new target escaped git clean."""
    for destination in journal["allowlist"]:
        initial = _revision_blob(repo, journal["initial_commit"], destination)
        initial_mode = _tree_mode(repo, journal["initial_commit"], destination)
        index = _revision_blob(repo, ":", destination)
        index_mode = _index_mode(repo, destination)
        working = _working_blob(repo, destination)
        _assert_ordinary_index_flags(repo, destination, present=initial is not None)
        if index != initial or index_mode != initial_mode:
            raise PublishError("FB publish post-reset index differs from its baseline")
        if initial is None:
            if initial_mode is not None:
                raise PublishError("FB publish post-reset baseline type is invalid")
            if working is not None and hashlib.sha256(working).hexdigest() != journal["source_sha256"][destination]:
                raise PublishError("FB publish post-reset new destination has unknown bytes")
        elif initial_mode != "100644" or working != initial:
            raise PublishError("FB publish post-reset tracked destination differs from baseline")


def _preflight_destinations(repo: Path, initial: str, release):
    """Reject ignored or non-baseline destinations before journal creation."""
    for destination in sorted(release):
        ignored = _git(
            repo,
            "check-ignore",
            "--quiet",
            "--no-index",
            "--",
            destination,
            check=False,
        )
        if ignored.returncode == 0:
            raise PublishError(f"FB publish destination is ignored by Git: {destination}")
        if ignored.returncode != 1:
            raise PublishError(
                f"git check-ignore could not classify FB publish destination: {destination}"
            )
    _assert_destinations_at_revision(repo, initial, release)


def _assert_journal_owned_precommit_state(repo: Path, journal):
    """Prove the index/worktree are one of our write/add crash states."""
    allowed = set(journal["allowlist"])
    planned = set(journal["planned_paths"])
    staged = _staged_paths(repo)
    unstaged = _unstaged_paths(repo)
    untracked = _untracked_paths(repo)
    changed = staged | unstaged | untracked
    if not changed.issubset(planned):
        raise PublishError(
            "FB publish recovery found unknown dirty, staged, or untracked user paths"
        )
    staged_paths = journal["staged_paths"]
    if staged_paths is None:
        # `git add` can return successfully immediately before the journal is
        # updated.  The pre-add plan proves exactly which index entries may
        # have changed, so accept only a source-exact subset of that plan.
        # Before add, source-exact worktree writes are unstaged.  After a real
        # add completes, Git leaves no unstaged/untracked transaction paths.
        if (
            not staged.issubset(planned)
            or untracked
            or (staged and unstaged)
        ):
            raise PublishError("FB publish recovery found an unjournaled add mutation")
    else:
        expected_staged = set(staged_paths)
        if staged != expected_staged or unstaged or untracked:
            raise PublishError("FB publish recovery state is not the journaled add phase")

    for destination, expected_hash in journal["source_sha256"].items():
        initial = _revision_blob(repo, journal["initial_commit"], destination)
        expected = bytes.fromhex(expected_hash)
        working = _working_blob(repo, destination)
        index = _revision_blob(repo, ":", destination)
        _assert_ordinary_index_flags(repo, destination, present=index is not None)
        if staged_paths is None:
            if destination in staged:
                if (
                    destination not in planned
                    or index is None
                    or working is None
                    or hashlib.sha256(index).digest() != expected
                    or hashlib.sha256(working).digest() != expected
                ):
                    raise PublishError("FB publish recovery unjournaled add bytes are invalid")
            else:
                if index != initial:
                    raise PublishError("FB publish recovery index differs from its baseline")
                if working is None:
                    if initial is not None:
                        raise PublishError("FB publish recovery lost a baseline page")
                elif (
                    hashlib.sha256(working).digest() != expected
                    and (initial is None or hashlib.sha256(working).digest() != hashlib.sha256(initial).digest())
                ):
                    raise PublishError("FB publish recovery found unknown page bytes")
        elif destination in set(staged_paths):
            if (
                index is None
                or working is None
                or hashlib.sha256(index).digest() != expected
                or hashlib.sha256(working).digest() != expected
            ):
                raise PublishError("FB publish recovery staged page bytes are invalid")
        else:
            if index != initial or working != initial:
                raise PublishError("FB publish recovery changed an unstaged page")


def _verify_journal_commit(repo: Path, journal: dict, commit: str):
    initial = journal["initial_commit"]
    expected_tree = journal["verified_tree"] or journal["prepared_tree"]
    if expected_tree is None:
        raise PublishError("FB publish journal cannot prove a local commit")
    if journal["verified_commit"] is not None and commit != journal["verified_commit"]:
        raise PublishError("FB publish recovery found an unjournaled local commit")
    parents = _git(repo, "rev-list", "--parents", "-n", "1", commit, text=True).stdout.split()
    if parents != [commit, initial] or _rev_parse(repo, f"{commit}^{{tree}}") != expected_tree:
        raise PublishError("FB publish journal commit ancestry or tree is invalid")
    changed = _nul_paths(
        _git(
            repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "--no-renames",
            "-r", "-z", commit,
        ).stdout
    )
    if not changed or changed != set(journal["staged_paths"]):
        raise PublishError("FB publish journal commit paths are invalid")
    for destination, digest in journal["source_sha256"].items():
        if hashlib.sha256(_show(repo, f"{commit}:{destination}")).hexdigest() != digest:
            raise PublishError("FB publish journal commit bytes are invalid")


def _prove_journal_owned_local_state(repo: Path, journal: dict) -> str:
    _verify_checkout_identity(repo, journal["repo_url"])
    head = _rev_parse(repo, "HEAD^{commit}")
    if head == journal["initial_commit"]:
        # A failed transaction can be killed after reset/clean completed but
        # before its journal unlink became durable.  This state is safe only
        # when the *entire* checkout (index, tracked worktree and untracked
        # paths) is clean at the exact journal baseline.  A clean local-ahead
        # commit cannot enter here because its HEAD differs from `initial`.
        checkout_status = _status_bytes(repo)
        if checkout_status:
            _assert_journal_owned_precommit_state(repo, journal)
        else:
            try:
                _assert_destinations_at_revision(
                    repo, journal["initial_commit"], journal["allowlist"]
                )
            except PublishError:
                # `git clean -f` omits ignored files.  Accept only a new,
                # source-exact journal target with an initial-exact index;
                # `_restore` will unlink that exact target durably.
                _assert_journal_owned_postreset_state(repo, journal)
        if not checkout_status and journal["verified_commit"] is not None:
            # A rejected push commonly leaves a verified commit dangling
            # after reset.  Prove its exact parent/tree/path/source relation;
            # do not accept a clean checkout merely because a journal names
            # an arbitrary object id.
            _verify_journal_commit(repo, journal, journal["verified_commit"])
    else:
        _verify_journal_commit(repo, journal, head)
        if _status_bytes(repo):
            raise PublishError("FB publish recovery found dirty state after a journaled commit")
    return head


def _recover_journal(repo: Path, journal_path: Path, journal: dict):
    """Converge a deliberately narrow interrupted transaction, or stop untouched.

    We only ever reset a worktree after proving that its HEAD and every dirty
    path are part of the journaled transaction.  This matters because this is
    a persistent checkout and a stale journal must never turn into permission
    to erase a human's work.
    """
    head = _prove_journal_owned_local_state(repo, journal)
    _clear_journal_temps(journal_path.parent, journal)
    initial = journal["initial_commit"]

    remote = _remote_head(repo)
    verified = journal["verified_commit"]
    if remote == initial:
        # The remote never moved.  The journal proves every local mutation is
        # ours, so remove it before starting a fresh transaction.
        _restore(repo, initial, journal["allowlist"], journal["source_sha256"])
    elif verified is not None and remote == verified:
        # A push reached the remote before the process died.  Fetch the ref,
        # validate its immutable tree, then make the local clone match it.
        _git(
            repo, "fetch", "--force", "--no-tags", "origin",
            "refs/heads/main:refs/remotes/origin/main",
        )
        if _rev_parse(repo, "refs/remotes/origin/main^{commit}") != verified:
            raise PublishError("FB publish recovery remote ref changed during verification")
        _verify_journal_commit(repo, journal, verified)
        _restore(repo, verified, journal["allowlist"], journal["source_sha256"])
    else:
        raise PublishError(
            "FB publish recovery refuses a remote that is neither the journal baseline nor verified commit"
        )
    _journal_clear(journal_path)


def publish(args) -> str:
    month, release, sources = _load_release(args)
    repo_url = _canonical_repo_url(args.repo)
    configured_worktree = Path(args.worktree).expanduser()
    if not configured_worktree.is_absolute():
        configured_worktree = Path.cwd() / configured_worktree
    if configured_worktree.name in {"", ".", ".."}:
        raise PublishError("publish worktree path has no safe basename")
    configured_parent = configured_worktree.parent
    configured_parent.mkdir(parents=True, exist_ok=True)
    parent_lstat = configured_parent.lstat()
    if stat.S_ISLNK(parent_lstat.st_mode) or not stat.S_ISDIR(parent_lstat.st_mode):
        raise PublishError("publish checkout parent must be a real directory")
    canonical_parent = configured_parent.resolve(strict=True)
    canonical_status = canonical_parent.stat()
    if (canonical_status.st_dev, canonical_status.st_ino) != (
        parent_lstat.st_dev, parent_lstat.st_ino
    ):
        raise PublishError("publish checkout parent canonicalization changed its inode")
    worktree = canonical_parent / configured_worktree.name

    with PublishLock(canonical_parent):
        _ensure_checkout(repo_url, worktree)
        journal_path = _journal_path(canonical_parent, worktree)
        if journal_path.exists() or journal_path.is_symlink():
            journal = _read_journal(journal_path, canonical_parent, worktree, repo_url)
            _recover_journal(worktree, journal_path, journal)
        initial = None
        commit = None
        push_completed = False
        journal = None
        try:
            # The baseline is recorded *before* fetch/merge, page writes, or
            # index changes.  A SIGKILL at any later point therefore has a
            # durable, fsync'ed proof of exactly what may be recovered.
            initial = _converge_clean_checkout_to_remote(worktree, repo_url)
            _preflight_destinations(worktree, initial, release)
            journal = _new_journal(
                canonical_parent, worktree, repo_url, month, initial, release
            )
            # Freeze the exact release delta before any page or index
            # mutation.  This records the only paths a killed add may have
            # staged while staged_paths is still None.
            journal["planned_paths"] = _planned_paths(worktree, initial, release)
            _journal_write(journal_path, journal)
            _bind_clean_checkout_to_remote(worktree, repo_url, initial)
            allowed = set(release)
            planned = set(journal["planned_paths"])
            for destination, content in release.items():
                if destination not in planned:
                    continue
                target = _ensure_destination_parent(worktree, destination)
                _atomic_write(
                    target,
                    content,
                    _journal_temp_path(canonical_parent, journal, destination),
                )
            _test_crash("write")
            if planned:
                _git(worktree, "add", "--", *sorted(planned))

            staged = _staged_paths(worktree)
            if not staged.issubset(allowed):
                raise PublishError(
                    f"FB release index contains unrelated paths: {sorted(staged - allowed)}"
                )
            if _unstaged_paths(worktree) or _untracked_paths(worktree):
                raise PublishError("FB release worktree changed outside the verified index")
            _verify_sources(sources, release)
            _verify_release_bytes(worktree, None, release)

            diff = _git(worktree, "diff", "--cached", "--quiet", check=False)
            if diff.returncode == 0:
                _verify_remote_release(worktree, initial, release)
                _restore(worktree, initial, allowed, journal["source_sha256"])
                _journal_clear(journal_path)
                return f"no-changes:{initial[:12]}"
            if diff.returncode != 1 or not staged:
                raise PublishError("unable to determine the exact FB release diff")

            # Recheck bytes immediately before freezing the index tree. Hooks
            # may run during commit, so the resulting commit must retain this
            # exact tree and this exact parent.
            _verify_sources(sources, release)
            _verify_release_bytes(worktree, None, release)
            expected_tree = _git(worktree, "write-tree", text=True).stdout.strip()
            journal["staged_paths"] = sorted(staged)
            journal["prepared_tree"] = expected_tree
            _journal_write(journal_path, journal)
            _test_crash("add")
            _test_fail("after_add_journal")
            _git(
                worktree,
                "-c",
                "user.name=spspy-fb-publisher",
                "-c",
                "user.email=spspy-fb-publisher@localhost",
                "commit",
                "--no-gpg-sign",
                "-m",
                f"update fb verify dashboard {month}",
            )
            commit = _rev_parse(worktree, "HEAD^{commit}")
            parents = _git(
                worktree, "rev-list", "--parents", "-n", "1", commit, text=True
            ).stdout.split()
            if parents != [commit, initial]:
                raise PublishError("FB release commit parent changed unexpectedly")
            if _rev_parse(worktree, f"{commit}^{{tree}}") != expected_tree:
                raise PublishError("FB release commit tree changed after index verification")
            committed_paths = _nul_paths(
                _git(
                    worktree,
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--name-only",
                    "--no-renames",
                    "-r",
                    "-z",
                    commit,
                ).stdout
            )
            if committed_paths != staged or not committed_paths.issubset(allowed):
                raise PublishError("FB release commit diff contains unexpected paths")
            _verify_sources(sources, release)
            _verify_release_bytes(worktree, commit, release)
            if _rev_parse(worktree, "HEAD^{commit}") != commit:
                raise PublishError("local main changed after FB release verification")
            journal["verified_commit"] = commit
            journal["verified_tree"] = expected_tree
            _journal_write(journal_path, journal)
            _test_crash("commit")

            _git(
                worktree,
                "push",
                "--no-follow-tags",
                f"--force-with-lease=refs/heads/main:{initial}",
                "origin",
                f"{commit}:refs/heads/main",
            )
            push_completed = True
            _test_crash("push")
            _verify_remote_release(worktree, commit, release)
            _verify_sources(sources, release)
            _prove_journal_owned_local_state(worktree, journal)
            _restore(worktree, commit, allowed, journal["source_sha256"])
            _journal_clear(journal_path)
            return f"pushed:{commit[:12]}"
        except Exception:
            if initial is not None and journal is not None:
                target = commit if push_completed and commit is not None else initial
                try:
                    _prove_journal_owned_local_state(worktree, journal)
                    _restore(worktree, target, release, journal["source_sha256"])
                    _journal_clear(journal_path)
                except Exception as rollback_error:
                    raise PublishError(
                        f"FB publish failed and checkout cleanup refused: {rollback_error}"
                    )
            raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--month", required=True)
    parser.add_argument("--dashboard-source", required=True)
    parser.add_argument("--batch-source")
    parser.add_argument("--batch-destination")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        result = publish(args)
    except PublishLockBusy as exc:
        print(str(exc), file=sys.stderr)
        return 75
    except Exception as exc:
        print(f"FB Pages publish refused: {exc}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
