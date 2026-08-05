#!/usr/bin/env python3
"""Run a command under a crash-safe, exec-inherited fcntl lock.

The public lock path is only a compatibility symlink: legacy mkdir/pid clients
see pid=0 and remain excluded.  Ownership lives on the persistent runtime
``data/`` directory inode, a non-empty business root that deploys never rename.
A contender locks that directory *before* inspecting or repairing compatibility
metadata, so rebuilding the protocol directory cannot fork ownership inodes.
The kernel releases ownership automatically when the last inherited fd closes.
"""

import argparse
import errno
import fcntl
import os
import pathlib
import stat
import sys
import time


PROTOCOL_MARKER = ".fcntl-protocol-v3"
PUBLIC_PID_SENTINEL = "0"


class LockBusyError(Exception):
    pass


def canonical_path(raw):
    path = pathlib.Path(raw)
    return str(path.parent.resolve(strict=True)) + os.sep + path.name


def fsync_directory(path):
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor, payload, context):
    """Write every byte, with deterministic short/failed-write test hooks."""
    offset = 0
    test_mode = os.environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1"
    forced_max = 0
    if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_WRITE_MAX_BYTES"):
        try:
            forced_max = int(os.environ["SP_SINGLE_PAGE_TEST_WRITE_MAX_BYTES"], 10)
        except ValueError as exc:
            raise OSError("invalid forced short-write size") from exc
        if forced_max < 1 or forced_max > 3:
            raise OSError("forced short-write size must be 1..3")
    if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_RAISE_WRITE_CONTEXT") == context:
        raise OSError(f"injected write failure: {context}")
    while offset < len(payload):
        if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_ZERO_WRITE_CONTEXT") == context:
            count = 0
        else:
            chunk = payload[offset:]
            if forced_max:
                chunk = chunk[:min(forced_max, (offset % forced_max) + 1)]
            count = os.write(descriptor, chunk)
        if count <= 0:
            raise OSError(f"zero-length write while publishing {context}")
        offset += count


def validate_protocol_dir(protocol):
    status = protocol.lstat()
    if not stat.S_ISDIR(status.st_mode) or protocol.is_symlink():
        raise RuntimeError("stable lock protocol path is not a real directory")
    marker = protocol / PROTOCOL_MARKER
    pid = protocol / "pid"
    for candidate in (marker, pid):
        candidate_status = candidate.lstat()
        if not stat.S_ISREG(candidate_status.st_mode) or candidate.is_symlink():
            raise RuntimeError(f"unsafe lock protocol file: {candidate}")
    if marker.read_text(encoding="ascii") != "3\n":
        raise RuntimeError("unsupported lock protocol marker")
    if pid.read_text(encoding="ascii") != PUBLIC_PID_SENTINEL + "\n":
        raise RuntimeError("unsafe legacy compatibility sentinel")


def build_protocol_dir(protocol):
    parent = protocol.parent
    temporary = parent / f".{protocol.name}.init.{os.getpid()}.{time.time_ns()}"
    temporary.mkdir(mode=0o700)
    try:
        for name, content in ((PROTOCOL_MARKER, "3\n"), ("pid", "0\n")):
            path = temporary / name
            descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                write_all(descriptor, content.encode("ascii"), "lock-protocol")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        fsync_directory(temporary)
        try:
            os.rename(str(temporary), str(protocol))
        except OSError as exc:
            if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
        fsync_directory(parent)
    finally:
        if temporary.exists():
            for child in temporary.iterdir():
                child.unlink()
            temporary.rmdir()


def process_is_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def validate_or_publish(lock_path):
    path = pathlib.Path(lock_path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    protocol = parent / f".{path.name}.protocol-v3"

    try:
        path_status = path.lstat()
    except FileNotFoundError:
        path_status = None

    if path_status is not None and not stat.S_ISLNK(path_status.st_mode):
        if stat.S_ISDIR(path_status.st_mode):
            try:
                raw = (path / "pid").read_text(encoding="ascii").strip()
                pid = int(raw, 10)
            except (OSError, UnicodeError, ValueError) as exc:
                raise LockBusyError("legacy lock has no trustworthy owner; fail-closed") from exc
            if pid > 0 and process_is_alive(pid):
                raise LockBusyError(f"legacy lock owner pid={pid} is still alive")
            raise LockBusyError("legacy lock remnant requires manual review; fail-closed")
        raise RuntimeError("lock path is neither the protocol symlink nor a legacy directory")

    if not protocol.exists():
        build_protocol_dir(protocol)
    validate_protocol_dir(protocol)

    if path_status is None:
        try:
            os.symlink(protocol.name, str(path))
            fsync_directory(parent)
        except FileExistsError:
            pass

    if not path.is_symlink() or os.readlink(str(path)) != protocol.name:
        raise RuntimeError("public lock path does not reference the stable protocol directory")
    if path.resolve() != protocol.resolve():
        raise RuntimeError("public lock resolves outside its stable protocol directory")


def lock_runtime_directory(directory):
    directory_path = pathlib.Path(directory)
    before = directory_path.lstat()
    if not stat.S_ISDIR(before.st_mode) or directory_path.is_symlink():
        raise RuntimeError("runtime lock root must be a real directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(directory_path), flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        descriptor_status = os.fstat(descriptor)
        path_status = directory_path.lstat()
        if not stat.S_ISDIR(path_status.st_mode) or directory_path.is_symlink():
            raise RuntimeError("runtime lock root changed type while acquiring it")
        if (descriptor_status.st_dev, descriptor_status.st_ino) != (path_status.st_dev, path_status.st_ino):
            raise RuntimeError("runtime lock directory changed while acquiring it")
        os.set_inheritable(descriptor, True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def inherited_descriptor(fd_env, active_env, lock_path, directory):
    if os.environ.get(active_env) != lock_path:
        raise RuntimeError("inherited lock targets another path")
    try:
        descriptor = int(os.environ.get(fd_env, ""), 10)
    except ValueError as exc:
        raise RuntimeError("inherited lock descriptor is invalid") from exc
    if descriptor < 0:
        raise RuntimeError("inherited lock descriptor is negative")
    descriptor_status = os.fstat(descriptor)
    directory_path = pathlib.Path(directory)
    path_status = directory_path.lstat()
    if not stat.S_ISDIR(path_status.st_mode) or directory_path.is_symlink():
        raise RuntimeError("persistent runtime lock directory is unsafe")
    if (descriptor_status.st_dev, descriptor_status.st_ino) != (path_status.st_dev, path_status.st_ino):
        raise RuntimeError("inherited descriptor does not reference the persistent data directory")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise LockBusyError from exc
        raise
    os.set_inheritable(descriptor, True)
    return descriptor


def test_pause_after_acquire():
    if os.environ.get("SP_SINGLE_PAGE_TEST_MODE") != "1":
        return
    ready_raw = os.environ.get("SP_SINGLE_PAGE_TEST_LOCK_READY_FILE", "")
    continue_raw = os.environ.get("SP_SINGLE_PAGE_TEST_LOCK_CONTINUE_FILE", "")
    if not ready_raw:
        return
    ready = pathlib.Path(ready_raw)
    ready.parent.mkdir(parents=True, exist_ok=True)
    ready.write_text(f"{os.getpid()}\n", encoding="ascii")
    if not continue_raw:
        return
    proceed = pathlib.Path(continue_raw)
    deadline = time.monotonic() + 30
    while not proceed.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {proceed}")
        time.sleep(0.02)


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True)
    parser.add_argument("--lock-dir", required=True)
    parser.add_argument("--fd-env", required=True)
    parser.add_argument("--active-env", required=True)
    parser.add_argument("--label", default="operation")
    parser.add_argument("--busy-exit", type=int, default=75)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("target", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.target and args.target[0] == "--":
        args.target = args.target[1:]
    if not args.validate_only and not args.target:
        parser.error("a target command is required")
    return args


def main(argv=None):
    args = parse_args(argv)
    lock_path = canonical_path(args.lock)
    # Resolve only the parent.  Resolving the final component would turn a
    # caller-supplied data-directory symlink into its target before lstat(),
    # defeating the explicit no-symlink boundary below.
    lock_directory = canonical_path(args.lock_dir)
    try:
        if os.environ.get(args.active_env):
            descriptor = inherited_descriptor(args.fd_env, args.active_env, lock_path, lock_directory)
            validate_or_publish(lock_path)
        else:
            # Acquire the persistent data-directory inode first.  If another
            # process holds it, do not inspect or repair the compatibility tree.
            descriptor = lock_runtime_directory(lock_directory)
            try:
                validate_or_publish(lock_path)
            except BaseException:
                os.close(descriptor)
                raise
    except (BlockingIOError, LockBusyError) as exc:
        detail = f" ({exc})" if str(exc) else ""
        print(f"another {args.label} is active; lock={lock_path}{detail}", file=sys.stderr)
        return args.busy_exit
    except (OSError, RuntimeError) as exc:
        print(f"cannot establish {args.label} lock {lock_path}: {exc}", file=sys.stderr)
        return 70

    os.environ[args.fd_env] = str(descriptor)
    os.environ[args.active_env] = lock_path
    if args.validate_only:
        return 0
    try:
        test_pause_after_acquire()
    except (OSError, TimeoutError) as exc:
        print(f"test lock pause failed: {exc}", file=sys.stderr)
        return 70
    os.execvpe(args.target[0], args.target, os.environ)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
