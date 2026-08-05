#!/usr/bin/env python3
"""Acquire a crash-safe advisory file lock and run a target under it.

The lock descriptor is deliberately inherited across ``exec`` and child
processes.  A nested verifier entrypoint can therefore validate and reuse the
same open-file-description lock without opening a second lock or deadlocking.
The recommended ``--supervise`` mode keeps the original owner process alive,
forwards terminal signals to a dedicated target process group, reaps it, and
removes the lock only after target cleanup has completed.
"""

import argparse
from datetime import datetime, timezone
import errno
import fcntl
import json
import math
import os
import pathlib
import re
import select
import signal
import stat
import subprocess
import sys
import time


class LockBusyError(Exception):
    pass


def canonical_path(raw):
    path = pathlib.Path(raw)
    return str(path.parent.resolve()) + os.sep + path.name


def process_is_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


PROTOCOL_MARKER = ".fcntl-protocol-v2"
INNER_LOCK = ".fcntl"
OWNER_TOKEN = "token"
LEASE_RECOVERY_MARKER = ".lease-recovery-v1"
# POSIX ``kill -0 0`` checks the caller's own process group and therefore
# succeeds without delivering a signal.  Publishing this compatibility
# sentinel means a v1 reader that cached the pid can never decide that a v2
# generation died, then unlink a later v2 generation after normal turnover.
PUBLIC_PID_SENTINEL = "0"
OWNER_PID_ENV = "FB_VERIFY_LOCK_OWNER_PID"
OWNER_TOKEN_ENV = "FB_VERIFY_LOCK_OWNER_TOKEN"
OWNER_PATH_ENV = "FB_VERIFY_LOCK_OWNER_PATH"
SUPERVISED_TARGET_ENV = "FB_VERIFY_LOCK_SUPERVISED_TARGET"
SUPERVISOR_READY_FD_ENV = "FB_VERIFY_LOCK_SUPERVISOR_READY_FD"
FORWARDED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
SIGNAL_EXIT_CODES = {
    signal.SIGHUP: 129,
    signal.SIGINT: 130,
    signal.SIGTERM: 143,
}
ATTEMPT_READY_SCHEMA_VERSION = 1
ATTEMPT_READY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "attempt_id",
        "run_id",
        "release_id",
        "ledger_dir",
        "started_at",
    }
)
ATTEMPT_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ATTEMPT_READY_MAX_BYTES = 4096
DEFAULT_SIGNAL_GRACE_SECONDS = 5.0
DEFAULT_DRAIN_TERM_GRACE_SECONDS = 1.0
DEFAULT_GROUP_GONE_GRACE_SECONDS = 2.0
DEFAULT_LEASE_GRACE_SECONDS = 2.0
POLL_INTERVAL_SECONDS = 0.02


def _fixed_duration(test_env_name, default):
    """Allow short deterministic durations only in explicitly isolated tests."""
    if os.environ.get("FB_VERIFY_TEST_MODE") != "1":
        return default
    raw = os.environ.get(test_env_name, "")
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"invalid test duration: {test_env_name}") from exc
    if not math.isfinite(value) or not 0.05 <= value <= 5.0:
        raise RuntimeError(f"invalid test duration: {test_env_name}")
    return value


def _canonical_directory(raw):
    return str(pathlib.Path(raw).resolve())


def _expected_attempt_ledger_dir(target):
    configured = os.environ.get("FB_VERIFY_ATTEMPT_LEDGER_DIR", "")
    if configured:
        return _canonical_directory(configured)
    data_root = os.environ.get("FB_VERIFY_DATA_ROOT", "")
    if data_root:
        return _canonical_directory(pathlib.Path(data_root) / "attempt_ledger")
    return _canonical_directory(pathlib.Path(canonical_path(target)).parent / "data" / "attempt_ledger")


def _strict_json_object(raw):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError("attempt readiness has duplicate fields")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise RuntimeError("attempt readiness is malformed") from exc


def validate_attempt_ready(raw, expected_ledger_dir, expected_release_id):
    metadata = _strict_json_object(raw)
    if not isinstance(metadata, dict) or frozenset(metadata) != ATTEMPT_READY_FIELDS:
        raise RuntimeError("attempt readiness schema is invalid")
    if isinstance(metadata.get("schema_version"), bool) or \
       metadata.get("schema_version") != ATTEMPT_READY_SCHEMA_VERSION:
        raise RuntimeError("attempt readiness schema is unsupported")
    if metadata.get("kind") != "fb_attempt":
        raise RuntimeError("attempt readiness kind is invalid")
    for field in ("attempt_id", "run_id", "release_id"):
        if not isinstance(metadata.get(field), str) or not ATTEMPT_TOKEN_RE.fullmatch(metadata[field]):
            raise RuntimeError(f"attempt readiness {field} is invalid")
    if metadata["attempt_id"] != metadata["run_id"]:
        raise RuntimeError("attempt readiness ids do not match")
    if metadata["release_id"] != expected_release_id:
        raise RuntimeError("attempt readiness release does not match supervisor")
    ledger_dir = metadata.get("ledger_dir")
    if not isinstance(ledger_dir, str) or not ledger_dir or len(ledger_dir) > 4096:
        raise RuntimeError("attempt readiness ledger directory is invalid")
    if _canonical_directory(ledger_dir) != expected_ledger_dir:
        raise RuntimeError("attempt readiness ledger directory does not match supervisor")
    started_at = metadata.get("started_at")
    if not isinstance(started_at, str) or len(started_at) > 64:
        raise RuntimeError("attempt readiness timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("attempt readiness timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RuntimeError("attempt readiness timestamp is invalid")
    return {
        **metadata,
        "ledger_dir": expected_ledger_dir,
        "started_at": parsed.isoformat(),
    }


def read_legacy_pid(path):
    try:
        raw_pid = (path / "pid").read_text(encoding="ascii").strip()
        pid = int(raw_pid, 10)
        if pid <= 0 or str(pid) != raw_pid:
            raise ValueError
        return pid
    except (OSError, UnicodeError, ValueError) as exc:
        raise LockBusyError(
            "legacy lock directory has no trustworthy owner; fail-closed "
            "(confirm no old process, then move it aside manually)"
        ) from exc


def make_protocol_dir(path):
    owner = path.with_name(
        f".{path.name}.owner.{os.getpid()}.{time.time_ns()}"
    )
    owner.mkdir(mode=0o700)
    owner.chmod(0o700)
    published = False
    try:
        token = f"{os.getpid()}-{time.time_ns()}"
        protocol_path = owner / PROTOCOL_MARKER
        pid_path = owner / "pid"
        token_path = owner / OWNER_TOKEN
        protocol_path.write_text("2\n", encoding="ascii")
        pid_path.write_text(PUBLIC_PID_SENTINEL + "\n", encoding="ascii")
        token_path.write_text(token + "\n", encoding="ascii")
        for private_file in (protocol_path, pid_path, token_path):
            private_file.chmod(0o600)
        inner = owner / INNER_LOCK
        descriptor = os.open(str(inner), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.set_inheritable(descriptor, True)
            directory_fd = os.open(str(owner), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            # Publishing a symlink is atomic and strictly no-replace: if a v1
            # process won mkdir (even before writing pid), this raises EEXIST
            # and its empty owner directory is never overwritten.
            os.symlink(owner.name, path)
            published = True
            return descriptor, owner, token
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        if not published and owner.exists():
            for child in owner.iterdir():
                child.unlink()
            owner.rmdir()


def protocol_owner(path):
    if path.is_symlink():
        target = os.readlink(path)
        prefix = f".{path.name}.owner."
        if os.path.isabs(target) or os.sep in target or not target.startswith(prefix):
            raise RuntimeError("lock symlink target is outside the protocol allowlist")
        owner = path.parent / target
        try:
            owner_status = owner.lstat()
        except FileNotFoundError as exc:
            raise RuntimeError("lock owner directory is missing") from exc
        if not stat.S_ISDIR(owner_status.st_mode) or owner.is_symlink():
            raise RuntimeError("lock owner directory is missing")
        if owner.resolve().parent != path.parent.resolve():
            raise RuntimeError("lock owner resolves outside the lock parent")
        return owner
    if path.is_dir():
        # Transitional support for an already-created v2 real directory.
        return path
    return None


def _recoverable_owner_pid(public_path, owner):
    prefix = f".{public_path.name}.owner."
    if not owner.name.startswith(prefix):
        raise RuntimeError("published owner generation name is invalid")
    generation = owner.name[len(prefix):].split(".")
    if len(generation) != 2 or any(not item.isdigit() for item in generation):
        raise RuntimeError("published owner generation identity is invalid")
    owner_pid = int(generation[0], 10)
    if owner_pid <= 0 or str(owner_pid) != generation[0]:
        raise RuntimeError("published owner pid is invalid")
    return owner_pid


def _validate_recoverable_owner(public_path, owner, descriptor):
    if not public_path.is_symlink() or os.readlink(public_path) != owner.name:
        raise RuntimeError("recoverable public owner changed")
    owner_status = owner.lstat()
    if (
        not stat.S_ISDIR(owner_status.st_mode)
        or owner.is_symlink()
        or owner_status.st_uid != os.geteuid()
        or stat.S_IMODE(owner_status.st_mode) != 0o700
    ):
        raise RuntimeError("recoverable owner directory is unsafe")
    expected_names = {
        PROTOCOL_MARKER, "pid", OWNER_TOKEN, INNER_LOCK, LEASE_RECOVERY_MARKER
    }
    if {item.name for item in owner.iterdir()} != expected_names:
        raise RuntimeError("recoverable owner contents are unexpected")
    owner_pid = _recoverable_owner_pid(public_path, owner)
    values = {}
    for name in (PROTOCOL_MARKER, "pid", OWNER_TOKEN, LEASE_RECOVERY_MARKER):
        candidate = owner / name
        metadata = candidate.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or candidate.is_symlink()
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > 256
        ):
            raise RuntimeError(f"recoverable owner file is unsafe: {name}")
        values[name] = candidate.read_text(encoding="ascii")
    if values[PROTOCOL_MARKER] != "2\n" or values["pid"] != "0\n":
        raise RuntimeError("recoverable owner protocol changed")
    token = values[OWNER_TOKEN].removesuffix("\n")
    if values[OWNER_TOKEN] != token + "\n" or not re.fullmatch(
        rf"{owner_pid}-[0-9]+", token
    ):
        raise RuntimeError("recoverable owner token is invalid")
    if values[LEASE_RECOVERY_MARKER] != f"1:{token}\n":
        raise RuntimeError("recoverable lease marker is invalid")
    inner = owner / INNER_LOCK
    inner_status = inner.lstat()
    descriptor_status = os.fstat(descriptor)
    if (
        not stat.S_ISREG(inner_status.st_mode)
        or inner.is_symlink()
        or inner_status.st_uid != os.geteuid()
        or stat.S_IMODE(inner_status.st_mode) != 0o600
        or inner_status.st_nlink != 1
        or (descriptor_status.st_dev, descriptor_status.st_ino)
        != (inner_status.st_dev, inner_status.st_ino)
    ):
        raise RuntimeError("recoverable lease inode changed")
    return owner_pid


def _remove_recoverable_owner(public_path, owner):
    public_path.unlink()
    parent_fd = os.open(str(public_path.parent), os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    for name in (
        PROTOCOL_MARKER, "pid", OWNER_TOKEN, LEASE_RECOVERY_MARKER, INNER_LOCK
    ):
        (owner / name).unlink()
    owner.rmdir()
    parent_fd = os.open(str(public_path.parent), os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def acquire_existing_protocol(public_path, owner):
    inner = owner / INNER_LOCK
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(inner), flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recovery_marker = owner / LEASE_RECOVERY_MARKER
        if not recovery_marker.exists():
            # Arbitrary crash remnants remain fail-closed.  Automatic recovery
            # is allowed only for the explicit marker written after a bounded
            # supervisor lease-convergence failure.
            raise LockBusyError(
                "published protocol owner is not reusable; fail-closed "
                "(unmarked crash remnants require manual review)"
            )
        owner_pid = _validate_recoverable_owner(public_path, owner, descriptor)
        if process_is_alive(owner_pid):
            raise LockBusyError("recoverable lock owner process is still alive")
        if _validate_recoverable_owner(public_path, owner, descriptor) != owner_pid:
            raise RuntimeError("recoverable owner identity changed")
        # The exact old inode is independently locked, the original owner is
        # dead, and the marker binds this generation's token.  Remove only
        # that generation while the probe remains locked, then let acquire()
        # compete normally for a fresh no-replace generation.
        _remove_recoverable_owner(public_path, owner)
        return None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def acquire(lock_path):
    """Acquire a v2 kernel lock that remains safe for v1 mkdir clients.

    The public path resolves to a directory containing the POSIX process-group
    sentinel ``pid=0`` so legacy ``kill -0`` readers always treat it as live.
    Its inner ``.fcntl`` file supplies crash-safe ownership.  A brand-new owner
    directory is prepared completely and then a relative, allowlisted symlink
    is created with no-replace semantics, eliminating the old
    mkdir-then-write empty-owner window.
    """
    path = pathlib.Path(lock_path)
    for _ in range(100):
        try:
            status = path.lstat()
        except FileNotFoundError:
            try:
                return make_protocol_dir(path)
            except FileExistsError:
                continue
        owner = protocol_owner(path)
        if owner is None:
            raise LockBusyError(
                "lock path is not a protocol directory; fail-closed during migration"
            )
        protocol_files = (owner / PROTOCOL_MARKER, owner / "pid", owner / INNER_LOCK,
                          owner / OWNER_TOKEN)
        safe_protocol = True
        for candidate in protocol_files:
            try:
                candidate_status = candidate.lstat()
            except FileNotFoundError:
                safe_protocol = False
                break
            if not stat.S_ISREG(candidate_status.st_mode) or candidate.is_symlink():
                safe_protocol = False
                break
        if safe_protocol:
            recovered = acquire_existing_protocol(path, owner)
            if recovered is None:
                continue
            return recovered

        if path.is_symlink():
            raise RuntimeError("allowlisted lock owner lacks protocol files")
        # Legacy mkdir owners cannot be proven safe to recycle.  In
        # particular, a dead pid may already have been read by a sleeping v1
        # contender.  Preserve the evidence and refuse all automatic takeover.
        pid = read_legacy_pid(owner)
        if process_is_alive(pid):
            raise LockBusyError(f"legacy lock owner pid={pid} is still alive")
        raise LockBusyError(
            f"dead legacy lock owner pid={pid}; fail-closed and preserve evidence"
        )
    raise RuntimeError("lock path changed repeatedly while acquiring")


def inherited_fd(fd_env, lock_path, active_env):
    raw_fd = os.environ.get(fd_env, "")
    active_path = os.environ.get(active_env, "")
    if not raw_fd or active_path != lock_path:
        raise RuntimeError("inherited lock metadata is missing or targets another lock")
    try:
        descriptor = int(raw_fd, 10)
    except ValueError as exc:
        raise RuntimeError("inherited lock descriptor is not an integer") from exc
    if descriptor < 0:
        raise RuntimeError("inherited lock descriptor is negative")
    try:
        owner = protocol_owner(pathlib.Path(lock_path))
        if owner is None:
            raise RuntimeError("inherited lock path is not a protocol directory")
        inner = owner / INNER_LOCK
        inner_status = inner.lstat()
        if not stat.S_ISREG(inner_status.st_mode) or inner.is_symlink():
            raise RuntimeError("inherited inner lock is not a regular file")
        fd_stat = os.fstat(descriptor)
        path_stat = inner_status
    except OSError as exc:
        raise RuntimeError(f"inherited lock descriptor is not usable: {exc}") from exc
    if (fd_stat.st_dev, fd_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
        raise RuntimeError("inherited descriptor does not reference the requested lock file")
    try:
        # Re-locking the inherited open file description is nonblocking and
        # idempotent.  A spoofed descriptor opened independently cannot bypass
        # a lock held by another process.
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise BlockingIOError from exc
        raise
    os.set_inheritable(descriptor, True)
    return descriptor


def release_owned(lock_path, fd_env, active_env):
    """Remove this outer owner's published pathname while its fd is still live.

    This is deliberately a separate action from acquiring.  It is invoked by
    the outer shell's EXIT trap; nested entrypoints inherit the descriptor but
    have a different pid and cannot release their parent's owner directory.
    """
    owner_pid = os.environ.get(OWNER_PID_ENV, "")
    token = os.environ.get(OWNER_TOKEN_ENV, "")
    expected_owner = os.environ.get(OWNER_PATH_ENV, "")
    if not owner_pid or not token or not expected_owner:
        raise RuntimeError("no outer-owner release capability is present")
    # The acquisition helper execs the outer target, so its PID is retained as
    # the published owner capability.  At final cleanup that target must in
    # turn *exec this helper* to release the lock.  Checking our own PID (not
    # our parent PID) is essential: a nested child can exec a helper whose
    # parent happens to be the outer target and would otherwise be able to
    # remove the public lock while its parent still runs.
    if str(os.getpid()) != owner_pid:
        raise RuntimeError("only the original outer target may release this lock")
    canonical = canonical_path(lock_path)
    if os.environ.get(active_env) != canonical:
        raise RuntimeError("outer-owner release targets another lock")
    descriptor = inherited_fd(fd_env, canonical, active_env)
    path = pathlib.Path(canonical)
    owner = protocol_owner(path)
    if owner is None or str(owner) != expected_owner:
        raise RuntimeError("published lock owner changed before release")
    # Do not trust a child-controlled environment variable alone.  The
    # immutable owner-directory name embeds the acquiring PID, while the
    # public pid file deliberately remains the legacy-safe sentinel ``0``.
    # This also prevents a nested child from rewriting OWNER_PID_ENV to its
    # own PID before execing us.
    owner_prefix = f".{path.name}.owner.{owner_pid}."
    if not owner.name.startswith(owner_prefix):
        raise RuntimeError("outer-owner PID does not match the published owner directory")
    token_path = owner / OWNER_TOKEN
    token_status = token_path.lstat()
    if not stat.S_ISREG(token_status.st_mode) or token_path.is_symlink():
        raise RuntimeError("published lock token is unsafe")
    if token_path.read_text(encoding="ascii") != token + "\n":
        raise RuntimeError("published lock token changed before release")
    inner_status = (owner / INNER_LOCK).lstat()
    fd_status = os.fstat(descriptor)
    if (fd_status.st_dev, fd_status.st_ino) != (inner_status.st_dev, inner_status.st_ino):
        raise RuntimeError("release descriptor is not this owner's lock")
    # Unlink only the exact public symlink we published.  The owner remains
    # locked until this function returns, so a normal v1 contender can never
    # observe a dead owner while it is being removed.
    if not path.is_symlink() or os.readlink(path) != owner.name:
        raise RuntimeError("public lock path changed before release")
    path.unlink()
    parent_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    for name in (PROTOCOL_MARKER, "pid", OWNER_TOKEN, INNER_LOCK):
        child = owner / name
        try:
            child.unlink()
        except FileNotFoundError:
            raise RuntimeError(f"owner file disappeared during release: {name}")
    owner.rmdir()
    parent_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def test_pause_after_acquire():
    if os.environ.get("FB_VERIFY_TEST_MODE") != "1":
        return
    ready_raw = os.environ.get("FB_VERIFY_TEST_LOCK_READY_FILE", "")
    continue_raw = os.environ.get("FB_VERIFY_TEST_LOCK_CONTINUE_FILE", "")
    if not ready_raw:
        return
    ready = pathlib.Path(ready_raw)
    ready.parent.mkdir(parents=True, exist_ok=True)
    ready.write_text(f"{os.getpid()}\n", encoding="utf-8")
    if not continue_raw:
        return
    proceed = pathlib.Path(continue_raw)
    deadline = time.monotonic() + 30
    while not proceed.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for test continuation: {proceed}")
        time.sleep(0.02)


def test_pause_before_supervised_target():
    """Exercise the published-owner/pre-spawn signal window in isolation."""
    if os.environ.get("FB_VERIFY_TEST_MODE") != "1":
        return
    ready_raw = os.environ.get("FB_VERIFY_TEST_SUPERVISOR_INIT_READY_FILE", "")
    continue_raw = os.environ.get("FB_VERIFY_TEST_SUPERVISOR_INIT_CONTINUE_FILE", "")
    if not ready_raw:
        return
    ready = pathlib.Path(ready_raw)
    ready.parent.mkdir(parents=True, exist_ok=True)
    ready.write_text(f"{os.getpid()}\n", encoding="utf-8")
    if not continue_raw:
        return
    proceed = pathlib.Path(continue_raw)
    deadline = time.monotonic() + 30
    while not proceed.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for test continuation: {proceed}")
        time.sleep(0.02)


class TargetSupervisor:
    """Bounded signal forwarding and process-group lifecycle supervision."""

    def __init__(self, nested_active=False):
        self.child = None
        self.pgid = None
        self.pending_signals = []
        self.previous_handlers = {}
        self.ready = False
        self.attempt_metadata = None
        self.first_signal = None
        self.signal_deadline = None
        self.signal_forwarded = False
        self.force_kill_sent = False
        self.force_reap_deadline = None
        self.accepting_signals = True
        owner_signal_grace = _fixed_duration(
            "FB_VERIFY_TEST_SUPERVISOR_SIGNAL_GRACE_SECONDS",
            DEFAULT_SIGNAL_GRACE_SECONDS,
        )
        self.signal_grace = owner_signal_grace
        # An active supervisor is itself inside the outer owner's target
        # group.  It must reach its own deadline, reap its nested group, and
        # commit fallback evidence before the outer owner reaches the same
        # terminal deadline.  Both deadlines remain fixed; the nested handoff
        # reserves the final third of the owner's grace for group confirmation,
        # fallback persistence, and return through the outer shell.
        if nested_active:
            self.signal_grace = max(
                POLL_INTERVAL_SECONDS, owner_signal_grace / 3.0
            )
        self.drain_grace = _fixed_duration(
            "FB_VERIFY_TEST_SUPERVISOR_DRAIN_GRACE_SECONDS",
            DEFAULT_DRAIN_TERM_GRACE_SECONDS,
        )
        self.group_gone_grace = _fixed_duration(
            "FB_VERIFY_TEST_SUPERVISOR_GROUP_GONE_GRACE_SECONDS",
            DEFAULT_GROUP_GONE_GRACE_SECONDS,
        )
        if nested_active:
            self.group_gone_grace = min(
                self.group_gone_grace,
                max(POLL_INTERVAL_SECONDS, owner_signal_grace / 3.0),
            )

    def _handle_signal(self, signum, _frame):
        if not self.accepting_signals or self.first_signal is not None:
            return
        self.first_signal = signum
        self.signal_deadline = time.monotonic() + self.signal_grace
        if self.ready:
            self._forward_first_signal()

    def _group_exists(self):
        if self.pgid is None:
            return False
        try:
            os.killpg(self.pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _send_group_signal(self, signum):
        if self.pgid is None:
            return False
        try:
            os.killpg(self.pgid, signum)
        except ProcessLookupError:
            return False
        except PermissionError:
            return False
        return True

    def _forward_first_signal(self):
        if self.first_signal is None or self.signal_forwarded:
            return
        self.signal_forwarded = True
        self._send_group_signal(self.first_signal)

    def _force_kill_group(self):
        if self.force_kill_sent:
            return
        self.force_kill_sent = True
        self.force_reap_deadline = time.monotonic() + self.group_gone_grace
        self._send_group_signal(signal.SIGKILL)

    def _enforce_signal_deadline(self):
        if self.first_signal is None or self.signal_deadline is None:
            return
        if time.monotonic() >= self.signal_deadline:
            self._forward_first_signal()
            self._force_kill_group()

    def install(self):
        for signum in FORWARDED_SIGNALS:
            self.previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle_signal)

    def restore(self):
        for signum, handler in self.previous_handlers.items():
            signal.signal(signum, handler)

    def start(self, target, descriptor, environment, extra_pass_fds=()):
        self.child = subprocess.Popen(
            target,
            env=environment,
            pass_fds=(descriptor, *extra_pass_fds),
            start_new_session=True,
        )
        self.pgid = self.child.pid
        return self.child

    def mark_ready(self, metadata=None):
        self.ready = True
        self.attempt_metadata = metadata
        self._forward_first_signal()

    def wait_for_attempt_ready(
        self, descriptor, expected_ledger_dir, expected_release_id, timeout=30
    ):
        deadline = time.monotonic() + timeout
        payload = b""
        while True:
            self._enforce_signal_deadline()
            if self.child is not None and self.child.poll() is not None:
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("target did not complete its signal-ready handshake")
            readable, _, _ = select.select([descriptor], [], [], min(0.05, remaining))
            if not readable:
                continue
            chunk = os.read(descriptor, ATTEMPT_READY_MAX_BYTES + 1 - len(payload))
            if not chunk:
                if self.child is not None and self.child.poll() is not None:
                    return False
                raise RuntimeError("target closed attempt readiness before metadata")
            payload += chunk
            if len(payload) > ATTEMPT_READY_MAX_BYTES:
                raise RuntimeError("attempt readiness is too large")
            if b"\n" not in payload:
                continue
            raw, remainder = payload.split(b"\n", 1)
            if not raw or remainder:
                raise RuntimeError("attempt readiness must be exactly one line")
            metadata = validate_attempt_ready(
                raw, expected_ledger_dir, expected_release_id
            )
            self.mark_ready(metadata)
            return True

    def _wait_group_gone(self, deadline):
        while time.monotonic() < deadline:
            if not self._group_exists():
                return True
            time.sleep(POLL_INTERVAL_SECONDS)
        return not self._group_exists()

    def _drain_group_after_leader(self, signalled):
        if not self._group_exists():
            return True
        if signalled:
            self._forward_first_signal()
            deadline = self.signal_deadline or time.monotonic()
        else:
            self._send_group_signal(signal.SIGTERM)
            deadline = time.monotonic() + self.drain_grace
        if self._wait_group_gone(deadline):
            return True
        self._force_kill_group()
        return self._wait_group_gone(
            time.monotonic() + self.group_gone_grace
        )

    def wait(self):
        if self.child is None:
            raise RuntimeError("supervised target was not started")
        leader_return_code = None
        while True:
            leader_return_code = self.child.poll()
            if leader_return_code is not None:
                break
            self._enforce_signal_deadline()
            if self.force_kill_sent and self.force_reap_deadline is not None and \
               time.monotonic() >= self.force_reap_deadline:
                break
            time.sleep(POLL_INTERVAL_SECONDS)

        leader_reaped = leader_return_code is not None
        self.accepting_signals = False
        group_gone = self._drain_group_after_leader(self.first_signal is not None)
        if leader_return_code is None:
            leader_return_code = self.child.poll()
            leader_reaped = leader_return_code is not None
        if self.first_signal is not None:
            exit_code = SIGNAL_EXIT_CODES[self.first_signal]
        elif leader_return_code is None:
            exit_code = 70
        elif leader_return_code < 0:
            exit_code = 128 + (-leader_return_code)
        else:
            exit_code = leader_return_code
        return {
            "exit_code": exit_code,
            "leader_return_code": leader_return_code,
            "leader_reaped": leader_reaped,
            "group_gone": group_gone,
            "first_signal": self.first_signal,
            "forced_kill": self.force_kill_sent,
        }

    def abort_and_reap(self):
        self.accepting_signals = False
        if self.child is None:
            return {"leader_reaped": True, "group_gone": True}
        if self._group_exists():
            self._send_group_signal(signal.SIGTERM)
            self._wait_group_gone(time.monotonic() + self.drain_grace)
        if self._group_exists():
            self._force_kill_group()
        deadline = time.monotonic() + self.group_gone_grace
        while self.child.poll() is None and time.monotonic() < deadline:
            time.sleep(POLL_INTERVAL_SECONDS)
        return {
            "leader_reaped": self.child.poll() is not None,
            "group_gone": self._wait_group_gone(deadline),
        }


def _validated_owner_snapshot(lock_path, descriptor):
    path = pathlib.Path(canonical_path(lock_path))
    owner_pid = os.environ.get(OWNER_PID_ENV, "")
    token = os.environ.get(OWNER_TOKEN_ENV, "")
    expected_owner = os.environ.get(OWNER_PATH_ENV, "")
    if str(os.getpid()) != owner_pid or not token or not expected_owner:
        raise RuntimeError("lease owner capability is missing")
    owner = protocol_owner(path)
    if owner is None or str(owner) != expected_owner:
        raise RuntimeError("lease owner path changed")
    owner_status = owner.lstat()
    if (
        not stat.S_ISDIR(owner_status.st_mode)
        or owner.is_symlink()
        or owner_status.st_uid != os.geteuid()
        or stat.S_IMODE(owner_status.st_mode) != 0o700
    ):
        raise RuntimeError("lease owner directory is unsafe")
    if not path.is_symlink() or os.readlink(path) != owner.name:
        raise RuntimeError("lease public path changed")
    token_path = owner / OWNER_TOKEN
    token_status = token_path.lstat()
    if (
        not stat.S_ISREG(token_status.st_mode)
        or token_path.is_symlink()
        or token_status.st_uid != os.geteuid()
        or token_path.read_text(encoding="ascii") != token + "\n"
    ):
        raise RuntimeError("lease owner token changed")
    inner = owner / INNER_LOCK
    inner_status = inner.lstat()
    descriptor_status = os.fstat(descriptor)
    if (
        not stat.S_ISREG(inner_status.st_mode)
        or inner.is_symlink()
        or inner_status.st_uid != os.geteuid()
        or stat.S_IMODE(inner_status.st_mode) != 0o600
        or (descriptor_status.st_dev, descriptor_status.st_ino)
        != (inner_status.st_dev, inner_status.st_ino)
    ):
        raise RuntimeError("lease inner inode changed")
    return {
        "path": path,
        "owner": owner,
        "token": token,
        "inner": inner,
        "identity": (inner_status.st_dev, inner_status.st_ino),
    }


def _revalidate_owner_snapshot(snapshot):
    path = snapshot["path"]
    owner = protocol_owner(path)
    if owner is None or owner != snapshot["owner"]:
        raise RuntimeError("lease owner rebound during convergence")
    if not path.is_symlink() or os.readlink(path) != owner.name:
        raise RuntimeError("lease public path rebound during convergence")
    token_path = owner / OWNER_TOKEN
    token_status = token_path.lstat()
    if (
        not stat.S_ISREG(token_status.st_mode)
        or token_path.is_symlink()
        or token_status.st_uid != os.geteuid()
        or token_path.read_text(encoding="ascii") != snapshot["token"] + "\n"
    ):
        raise RuntimeError("lease token rebound during convergence")
    inner_status = snapshot["inner"].lstat()
    if (
        not stat.S_ISREG(inner_status.st_mode)
        or snapshot["inner"].is_symlink()
        or inner_status.st_uid != os.geteuid()
        or stat.S_IMODE(inner_status.st_mode) != 0o600
        or (inner_status.st_dev, inner_status.st_ino) != snapshot["identity"]
    ):
        raise RuntimeError("lease inode rebound during convergence")


def _publish_lease_recovery_marker(snapshot):
    """Authorize later recovery of this exact escaped-lease generation."""
    _revalidate_owner_snapshot(snapshot)
    marker = snapshot["owner"] / LEASE_RECOVERY_MARKER
    payload = f"1:{snapshot['token']}\n".encode("ascii")
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = None
    try:
        try:
            descriptor = os.open(str(marker), flags, 0o600)
        except FileExistsError:
            metadata = marker.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or marker.is_symlink()
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or marker.read_bytes() != payload
            ):
                raise RuntimeError("lease recovery marker changed")
        else:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise RuntimeError("cannot write lease recovery marker")
                offset += written
            os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    owner_fd = os.open(str(snapshot["owner"]), os.O_RDONLY)
    try:
        os.fsync(owner_fd)
    finally:
        os.close(owner_fd)
    _revalidate_owner_snapshot(snapshot)


def converge_owned_lease(lock_path, descriptor, fd_env, active_env):
    snapshot = _validated_owner_snapshot(lock_path, descriptor)
    try:
        os.close(descriptor)
    except OSError as exc:
        raise RuntimeError("cannot close original lease descriptor") from exc
    os.environ[fd_env] = "-1"
    deadline = time.monotonic() + _fixed_duration(
        "FB_VERIFY_TEST_SUPERVISOR_LEASE_GRACE_SECONDS",
        DEFAULT_LEASE_GRACE_SECONDS,
    )
    while True:
        _revalidate_owner_snapshot(snapshot)
        probe = os.open(
            str(snapshot["inner"]),
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            probe_status = os.fstat(probe)
            if (probe_status.st_dev, probe_status.st_ino) != snapshot["identity"]:
                raise RuntimeError("lease probe opened another inode")
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
            else:
                os.set_inheritable(probe, True)
                os.environ[fd_env] = str(probe)
                os.environ[active_env] = canonical_path(lock_path)
                _revalidate_owner_snapshot(snapshot)
                return probe
        except BaseException:
            os.close(probe)
            raise
        os.close(probe)
        if time.monotonic() >= deadline:
            _publish_lease_recovery_marker(snapshot)
            return None
        time.sleep(POLL_INTERVAL_SECONDS)


def _same_attempt_terminal(record, metadata):
    try:
        started = datetime.fromisoformat(record["started_at"].replace("Z", "+00:00"))
        expected = datetime.fromisoformat(metadata["started_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return False
    return (
        record.get("attempt_id") == metadata["attempt_id"]
        and record.get("run_id") == metadata["run_id"]
        and record.get("release_id") == metadata["release_id"]
        and started == expected
        and record.get("state") in {"failed", "partial", "succeeded", "skipped"}
    )


def ensure_fallback_terminal(metadata, fallback_exit_code):
    try:
        import pipeline_status

        snapshot = pipeline_status.inspect_attempt_ledger(metadata["ledger_dir"])
        if snapshot["busy"]:
            return False
        matching = [
            record for record in snapshot["records"]
            if record["attempt_id"] == metadata["attempt_id"]
        ]
        if len(matching) == 1:
            return _same_attempt_terminal(matching[0], metadata)
        if matching:
            return False
        record = pipeline_status.make_attempt_record(
            attempt_id=metadata["attempt_id"],
            run_id=metadata["run_id"],
            release_id=metadata["release_id"],
            phase="unknown",
            exit_code=fallback_exit_code,
            publish_ok=False,
            terminated_early=True,
            truncated=0,
            pending=0,
            failed=0,
            body_complete=False,
            started_at=metadata["started_at"],
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        try:
            pipeline_status.write_attempt_ledger(metadata["ledger_dir"], record)
            return True
        except pipeline_status.AttemptLedgerCollision:
            snapshot = pipeline_status.inspect_attempt_ledger(metadata["ledger_dir"])
            if snapshot["busy"]:
                return False
            matching = [
                item for item in snapshot["records"]
                if item["attempt_id"] == metadata["attempt_id"]
            ]
            return len(matching) == 1 and _same_attempt_terminal(matching[0], metadata)
    except Exception:
        return False


def _fallback_required(lifecycle, metadata):
    return bool(
        metadata
        and (
            lifecycle["exit_code"] != 0
            or lifecycle["first_signal"] is not None
            or lifecycle["forced_kill"]
        )
    )


def _fallback_exit_code(lifecycle):
    if lifecycle["first_signal"] is not None:
        return SIGNAL_EXIT_CODES[lifecycle["first_signal"]]
    return 143


def supervised_target(args, descriptor, active, supervisor):
    child_environment = os.environ.copy()
    child_environment[SUPERVISED_TARGET_ENV] = canonical_path(args.target[0])
    ready_read = None
    ready_write = None
    lifecycle = {
        "exit_code": 70,
        "leader_return_code": None,
        "leader_reaped": True,
        "group_gone": True,
        "first_signal": supervisor.first_signal,
        "forced_kill": False,
    }
    try:
        try:
            test_pause_before_supervised_target()
            extra_pass_fds = ()
            if args.ready_handshake:
                ready_read, ready_write = os.pipe()
                os.set_inheritable(ready_write, True)
                child_environment[SUPERVISOR_READY_FD_ENV] = str(ready_write)
                extra_pass_fds = (ready_write,)
            supervisor.start(
                args.target, descriptor, child_environment,
                extra_pass_fds=extra_pass_fds,
            )
            if ready_write is not None:
                os.close(ready_write)
                ready_write = None
            if ready_read is not None:
                ready = supervisor.wait_for_attempt_ready(
                    ready_read,
                    _expected_attempt_ledger_dir(args.target[0]),
                    os.environ.get("FB_VERIFY_RELEASE_ID", "source_local"),
                )
                if not ready:
                    raise RuntimeError("target exited before attempt readiness")
            else:
                supervisor.mark_ready()
            lifecycle = supervisor.wait()
        except (OSError, RuntimeError, TimeoutError, subprocess.SubprocessError) as exc:
            drained = supervisor.abort_and_reap()
            lifecycle.update(
                {
                    "exit_code": (
                        SIGNAL_EXIT_CODES[supervisor.first_signal]
                        if supervisor.first_signal is not None else 70
                    ),
                    "leader_reaped": drained["leader_reaped"],
                    "group_gone": drained["group_gone"],
                    "first_signal": supervisor.first_signal,
                    "forced_kill": supervisor.force_kill_sent,
                }
            )
            print(f"cannot supervise {args.label} target: {exc}", file=sys.stderr)
        finally:
            for pipe_fd in (ready_read, ready_write):
                if pipe_fd is not None:
                    try:
                        os.close(pipe_fd)
                    except OSError:
                        pass

        lifecycle_safe = lifecycle["leader_reaped"] and lifecycle["group_gone"]
        metadata = supervisor.attempt_metadata
        needs_fallback = _fallback_required(lifecycle, metadata)

        if active:
            if needs_fallback and not ensure_fallback_terminal(
                metadata, _fallback_exit_code(lifecycle)
            ):
                return 70
            return lifecycle["exit_code"] if lifecycle_safe else 70

        if not lifecycle_safe:
            return 70
        try:
            probe = converge_owned_lease(
                args.lock, descriptor, args.fd_env, args.active_env
            )
        except (OSError, RuntimeError):
            return 70
        if probe is None:
            return 70
        try:
            if needs_fallback and not ensure_fallback_terminal(
                metadata, _fallback_exit_code(lifecycle)
            ):
                return 70
            try:
                release_owned(args.lock, args.fd_env, args.active_env)
            except (OSError, RuntimeError) as exc:
                print(f"cannot release {args.label} lock {args.lock}: {exc}", file=sys.stderr)
                return 70
            return lifecycle["exit_code"]
        finally:
            try:
                os.close(probe)
            except OSError:
                pass
    finally:
        supervisor.accepting_signals = False
        supervisor.restore()


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True)
    parser.add_argument("--fd-env", required=True)
    parser.add_argument("--active-env", required=True)
    parser.add_argument("--label", default="operation")
    parser.add_argument("--busy-exit", type=int, default=75)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--release-owned", action="store_true")
    parser.add_argument(
        "--supervise", action="store_true",
        help="run target in a new session, forward signals, reap it, then release",
    )
    parser.add_argument(
        "--ready-handshake", action="store_true",
        help="queue signals until target writes readiness to the provided fd",
    )
    parser.add_argument(
        "--exit-code", type=int,
        help="original outer-target exit code to preserve after a successful release",
    )
    parser.add_argument("target", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.target and args.target[0] == "--":
        args.target = args.target[1:]
    if args.release_owned and (args.validate_only or args.supervise or args.target):
        parser.error("--release-owned cannot be combined with a target, --supervise or --validate-only")
    if args.validate_only and args.supervise:
        parser.error("--validate-only cannot be combined with --supervise")
    if args.ready_handshake and not args.supervise:
        parser.error("--ready-handshake requires --supervise")
    if args.exit_code is not None and not args.release_owned:
        parser.error("--exit-code is only valid with --release-owned")
    if args.exit_code is not None and not 0 <= args.exit_code <= 255:
        parser.error("--exit-code must be in the range 0..255")
    if not args.validate_only and not args.release_owned and not args.target:
        parser.error("a target command is required")
    return args


def main(argv=None):
    args = parse_args(argv)
    lock_path = canonical_path(args.lock)
    pathlib.Path(lock_path).parent.mkdir(parents=True, exist_ok=True)

    if args.release_owned:
        try:
            release_owned(lock_path, args.fd_env, args.active_env)
        except (OSError, RuntimeError) as exc:
            print(f"cannot release {args.label} lock {lock_path}: {exc}", file=sys.stderr)
            return 70
        return 0 if args.exit_code is None else args.exit_code

    active = bool(os.environ.get(args.active_env))
    supervisor = None
    if args.supervise:
        # Install handlers before acquisition.  A TERM in the narrow interval
        # between publishing the owner and spawning the target is queued, not
        # allowed to strand a published lock owner.
        supervisor = TargetSupervisor(nested_active=active)
        supervisor.install()
    try:
        if active:
            descriptor = inherited_fd(args.fd_env, lock_path, args.active_env)
        else:
            descriptor, owner, token = acquire(lock_path)
    except (BlockingIOError, LockBusyError) as exc:
        if supervisor is not None:
            supervisor.restore()
        detail = f" ({exc})" if str(exc) else ""
        print(f"another {args.label} is active; lock={lock_path}{detail}", file=sys.stderr)
        return args.busy_exit
    except (OSError, RuntimeError) as exc:
        if supervisor is not None:
            supervisor.restore()
        print(f"cannot establish {args.label} lock {lock_path}: {exc}", file=sys.stderr)
        return 70

    os.environ[args.fd_env] = str(descriptor)
    os.environ[args.active_env] = lock_path
    if not active:
        os.environ[OWNER_PID_ENV] = str(os.getpid())
        os.environ[OWNER_TOKEN_ENV] = token
        os.environ[OWNER_PATH_ENV] = str(owner)
    if args.validate_only:
        return 0

    if args.supervise:
        return supervised_target(args, descriptor, active, supervisor)

    try:
        test_pause_after_acquire()
    except (OSError, TimeoutError) as exc:
        print(f"test lock pause failed: {exc}", file=sys.stderr)
        return 70
    os.execvpe(args.target[0], args.target, os.environ)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
