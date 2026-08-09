"""Crash-durable Darwin release selection for already verified v2 artifacts.

`current.payload` is only the atomically selected canonical tar.  Selection is
not extraction or deployment, and candidate bytes are never executable input.
Every production call repeats the artifact module's complete offline R1/R2
verification from raw evidence plus out-of-band ExpectedAuthority objects.
"""
from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_PAYLOAD = 280 * 1024 * 1024
NATIVE_SOURCE_SHA256 = "7ad2b1f58076d7baff7e2aa8d7abeee6d7f6e91c06e4a02f37363d38084454c8"
PRODUCTION_HELPER_PATH = "/Library/Application Support/SPSPY/libexec/sp-release-seatbelt-v3"
# These are deliberately unset until a root-owned installation is separately
# reviewed and sealed.  Public activation/inspection/recovery therefore fail
# closed; local tests use the explicit internal helper hooks below.
PRODUCTION_HELPER_BINARY_SHA256 = None
PRODUCTION_HELPER_CDHASH = None
PRODUCTION_HELPER_ARCH = None
NATIVE_CLANG = "/usr/bin/clang"
NATIVE_BUILD_FLAGS = ("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fno-common",
                      "-fstack-protector-strong", "-Wl,-bind_at_load", "-DSP_TEST_ALLOW_OWNER_HELPER=1")
NATIVE_TOTAL_TIMEOUT_SECONDS = 60
NATIVE_CLEANUP_TIMEOUT_SECONDS = 5
PYTHON_NATIVE_TIMEOUT_SECONDS = 72
CAS_LOCK_TIMEOUT_SECONDS = 5.0
CAS_LOCK_RETRY_SECONDS = 0.01
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CAS_TEMP = re.compile(r"^\.([0-9a-f]{64})\.([0-9a-f]{32})\.tmp$")
ZERO_SHA256 = "0" * 64
_RECONCILIATION_KEYS = frozenset({
    "protocol", "operation", "classification", "state_sha256", "epoch", "phase",
    "recovery_from_phase", "prior_present", "current", "current_sha256",
})
_INSPECT_CLASSIFICATIONS = frozenset({
    "FRESH", "BUSY", "ACTIVE", "BLOCKED", "DEBRIS", "TERMINAL_COMMITTED",
    "TERMINAL_ROLLED_BACK", "RECOVERABLE_COMMITTED", "RECOVERABLE_ROLLED_BACK",
    "RECOVERABLE_ROLLBACK_REQUIRED",
})
_RECOVER_CLASSIFICATIONS = frozenset({"RECOVERED_COMMITTED", "RECOVERED_ROLLED_BACK"})
_ARTIFACT_MODULE = None
_HELPER_RECORD = None
_HELPER_TEMPORARY = None


class ActivationError(RuntimeError):
    pass


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _hex64(value, label):
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ActivationError("%s must be lowercase SHA-256" % label)
    return value


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_nlink)


def _open_private_root_readonly(root):
    """Open an activation root without creating or repairing any control file."""
    flags = (os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(os.fspath(root), flags)
    except (OSError, TypeError, ValueError) as exc:
        raise ActivationError("activation root is unavailable") from exc
    try:
        DirFDStore._check_dir(fd, "activation root")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _control_name_exists(root_fd, name):
    try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ActivationError("activation root could not be inspected read-only") from exc


def _selection_root_is_fresh(root):
    """Return true only when both durable state and selected current are absent."""
    root_fd = _open_private_root_readonly(root)
    try:
        return (not _control_name_exists(root_fd, ".sp-release-v2.state") and
                not _control_name_exists(root_fd, "current.payload"))
    finally:
        os.close(root_fd)


def _selection_fd_is_fresh(root_fd):
    return (not _control_name_exists(root_fd, ".sp-release-v2.state") and
            not _control_name_exists(root_fd, "current.payload"))


def _open_locked_selector(root_fd, *, create):
    flags = (os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) |
             getattr(os, "O_CLOEXEC", 0))
    created = False
    if create:
        try:
            fd = os.open(".sp-release-v2.lock", flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root_fd)
            created = True
        except FileExistsError:
            fd = os.open(".sp-release-v2.lock", flags, dir_fd=root_fd)
    else:
        fd = os.open(".sp-release-v2.lock", flags, dir_fd=root_fd)
    try:
        if created:
            os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        named = os.stat(".sp-release-v2.lock", dir_fd=root_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0 or
                (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise ActivationError("selector lock metadata is unsafe")
        deadline = time.monotonic() + CAS_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise ActivationError("selector lock acquisition failed") from exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ActivationError("selector lock is busy after bounded wait") from exc
                time.sleep(min(CAS_LOCK_RETRY_SECONDS, remaining))
        if created:
            os.fsync(fd)
            os.fsync(root_fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_regular_fd(fd, *, maximum=MAX_PAYLOAD, exact_mode=None, exact_uid=None, allow_empty=False):
    if type(fd) is not int or fd < 0:
        raise ActivationError("file descriptor is invalid")
    duplicate = os.dup(fd)
    try:
        before = os.fstat(duplicate)
        required_uid = os.getuid() if exact_uid is None else exact_uid
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != required_uid or before.st_nlink != 1 or
                (exact_mode is not None and stat.S_IMODE(before.st_mode) != exact_mode) or
                before.st_size < 0 or before.st_size > maximum or (before.st_size == 0 and not allow_empty)):
            raise ActivationError("regular file metadata is unsafe")
        chunks = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(duplicate, min(65536, before.st_size - offset), offset)
            if not chunk:
                raise ActivationError("regular file was truncated")
            chunks.append(chunk)
            offset += len(chunk)
        if os.pread(duplicate, 1, offset):
            raise ActivationError("regular file grew during read")
        after = os.fstat(duplicate)
        if _fingerprint(before) != _fingerprint(after):
            raise ActivationError("regular file changed during read")
        return b"".join(chunks), before
    finally:
        os.close(duplicate)


def _snapshot_regular_fd(fd, *, label):
    """Freeze owner-private input bytes and retain an identity guard."""
    if type(fd) is not int or fd < 0:
        raise ActivationError("%s descriptor is invalid" % label)
    try:
        guard_fd = os.dup(fd)
    except OSError as exc:
        raise ActivationError("%s descriptor is unavailable" % label) from exc
    try:
        data, identity = _read_regular_fd(guard_fd, exact_mode=0o600)
        return data, identity, guard_fd
    except BaseException:
        os.close(guard_fd)
        raise


def _anonymous_private_snapshot(data, *, label):
    """Return an owner-private unlinked snapshot outside any activation root."""
    if type(data) is not bytes or not data or len(data) > MAX_PAYLOAD:
        raise ActivationError("%s bytes are invalid" % label)
    writer_fd = parent_fd = None
    path = None
    try:
        writer_fd, path = tempfile.mkstemp(prefix="spspy-v3-recovery-snapshot-", dir="/private/tmp")
        os.fchmod(writer_fd, 0o600)
        parent_fd = os.open("/private/tmp", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        os.unlink(path)
        path = None
        os.fsync(parent_fd)
        _write_all(writer_fd, data)
        os.fsync(writer_fd)
        before = os.fstat(writer_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 0 or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_size != len(data)):
            raise ActivationError("%s metadata is unsafe" % label)
        observed = b"".join(os.pread(writer_fd, min(65536, len(data) - offset), offset)
                            for offset in range(0, len(data), 65536))
        if observed != data:
            raise ActivationError("%s bytes changed" % label)
        os.lseek(writer_fd, 0, os.SEEK_SET)
        result = writer_fd
        writer_fd = None
        return result
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if writer_fd is not None:
            os.close(writer_fd)
        if path is not None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def _require_unchanged_snapshot_fd(guard_fd, identity, *, label):
    try:
        observed = os.fstat(guard_fd)
    except OSError as exc:
        raise ActivationError("%s changed after stable snapshot" % label) from exc
    if _fingerprint(observed) != _fingerprint(identity):
        raise ActivationError("%s changed after stable snapshot" % label)


def _write_all(fd, data):
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise ActivationError("durable write made no progress")
        offset += written


def _close_all(*descriptors):
    first_error = None
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


class DirFDStore:
    """Owner-only CAS with recoverable link publication and directory fsyncs."""

    def __init__(self, root):
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        self.fd = None
        self.lock_fd = None
        try:
            self.fd = os.open(os.fspath(root), flags)
            self._check_dir(self.fd, "activation root")
            self.lock_fd = self._open_control(".sp-release-v2.cas.lock")
        except BaseException:
            try:
                self.close()
            except OSError:
                pass
            raise

    @classmethod
    def from_fd(cls, root_fd):
        """Open the CAS on the caller's already pinned activation-root inode."""
        if type(root_fd) is not int or root_fd < 0:
            raise ActivationError("activation root descriptor is invalid")
        self = cls.__new__(cls)
        self.fd = None
        self.lock_fd = None
        try:
            self.fd = os.dup(root_fd)
            self._check_dir(self.fd, "activation root")
            source = os.fstat(root_fd)
            duplicate = os.fstat(self.fd)
            if (source.st_dev, source.st_ino, source.st_mode, source.st_uid) != (
                    duplicate.st_dev, duplicate.st_ino, duplicate.st_mode, duplicate.st_uid):
                raise ActivationError("activation root descriptor identity differs")
            self.lock_fd = self._open_control(".sp-release-v2.cas.lock")
            return self
        except BaseException:
            try:
                self.close()
            except OSError:
                pass
            raise

    @staticmethod
    def _check_dir(fd, label):
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink < 2):
            raise ActivationError("%s metadata is unsafe" % label)

    @staticmethod
    def _check_control(fd, label, *, allowed_links=(1,)):
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink not in allowed_links):
            raise ActivationError("%s metadata is unsafe" % label)
        return info

    def _open_control(self, name):
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        created = False
        try:
            fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self.fd)
            created = True
        except FileExistsError:
            fd = os.open(name, flags, dir_fd=self.fd)
        try:
            if created:
                os.fchmod(fd, 0o600)
            self._check_control(fd, "CAS lock")
            os.fsync(fd)
            os.fsync(self.fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        first_error = None
        for attribute in ("lock_fd", "fd"):
            descriptor = getattr(self, attribute)
            setattr(self, attribute, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if first_error is None:
                        first_error = exc
        if first_error is not None:
            raise first_error

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def _directory(self, name):
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=self.fd)
            created = True
        except FileExistsError:
            pass
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        child = os.open(name, flags, dir_fd=self.fd)
        try:
            self._check_dir(child, "CAS objects")
            os.fsync(child)
            if created:
                os.fsync(self.fd)
            return child
        except BaseException:
            os.close(child)
            raise

    @contextlib.contextmanager
    def _locked_objects(self):
        if not (0 < CAS_LOCK_TIMEOUT_SECONDS < NATIVE_TOTAL_TIMEOUT_SECONDS) or CAS_LOCK_RETRY_SECONDS <= 0:
            raise ActivationError("CAS lock deadline configuration is invalid")
        deadline = time.monotonic() + CAS_LOCK_TIMEOUT_SECONDS
        acquired = False
        objects = None
        try:
            while True:
                try:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN):
                        raise ActivationError("CAS lock acquisition failed") from exc
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ActivationError("CAS lock is busy after bounded wait") from exc
                    time.sleep(min(CAS_LOCK_RETRY_SECONDS, remaining))
            self._check_control(self.lock_fd, "CAS lock")
            objects = self._directory("objects")
            self._recover_temporary_links(objects)
            yield objects
        finally:
            try:
                if objects is not None:
                    os.close(objects)
            finally:
                if acquired:
                    fcntl.flock(self.lock_fd, fcntl.LOCK_UN)

    @staticmethod
    def _stat_name(parent_fd, name):
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)

    @classmethod
    def _read_object(cls, parent_fd, name, *, allowed_links=(1,)):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            before = cls._check_control(fd, "CAS object", allowed_links=allowed_links)
            if before.st_size <= 0 or before.st_size > MAX_PAYLOAD:
                raise ActivationError("CAS object size is unsafe")
            chunks = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    raise ActivationError("CAS object was truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise ActivationError("CAS object grew during read")
            after = os.fstat(fd)
            if _fingerprint(before) != _fingerprint(after):
                raise ActivationError("CAS object changed during read")
            return b"".join(chunks)
        finally:
            os.close(fd)

    @classmethod
    def _recover_temporary_links(cls, objects_fd):
        changed = False
        for name in os.listdir(objects_fd):
            match = _CAS_TEMP.fullmatch(name)
            if match is None:
                continue
            digest = match.group(1)
            temp = cls._stat_name(objects_fd, name)
            if (not stat.S_ISREG(temp.st_mode) or temp.st_uid != os.getuid() or
                    stat.S_IMODE(temp.st_mode) != 0o600 or temp.st_nlink not in (1, 2)):
                raise ActivationError("CAS recovery temporary is unsafe")
            try:
                target = cls._stat_name(objects_fd, digest)
            except FileNotFoundError:
                target = None
            if temp.st_nlink == 2:
                if (target is None or not stat.S_ISREG(target.st_mode) or target.st_dev != temp.st_dev or
                        target.st_ino != temp.st_ino or target.st_uid != os.getuid() or
                        stat.S_IMODE(target.st_mode) != 0o600 or target.st_nlink != 2):
                    raise ActivationError("CAS recovery link pair is ambiguous")
            elif target is not None:
                if (not stat.S_ISREG(target.st_mode) or target.st_uid != os.getuid() or
                        stat.S_IMODE(target.st_mode) != 0o600 or target.st_nlink != 1):
                    raise ActivationError("CAS recovery target is unsafe")
            os.unlink(name, dir_fd=objects_fd)
            os.fsync(objects_fd)
            changed = True
            if target is not None:
                cls._read_object(objects_fd, digest)
        if changed:
            os.fsync(objects_fd)

    @classmethod
    def _write_once(cls, parent_fd, digest, data):
        temporary = ".%s.%s.tmp" % (digest, secrets.token_hex(16))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            cls._check_control(fd, "CAS temporary")
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            try:
                os.link(temporary, digest, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
                os.fsync(parent_fd)
            except FileExistsError:
                pass
            os.unlink(temporary, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except BaseException:
            # Leave only the exact recoverable temp/link shape.  The next
            # locked operation validates and completes cleanup before access.
            raise
        existing = cls._read_object(parent_fd, digest)
        if existing != data or _sha(existing) != digest:
            raise ActivationError("CAS digest collision")

    def put_bytes(self, data):
        if type(data) is not bytes or not data or len(data) > MAX_PAYLOAD:
            raise ActivationError("CAS snapshot bytes are invalid")
        digest = _sha(data)
        with self._locked_objects() as objects:
            try:
                existing = self._read_object(objects, digest)
            except FileNotFoundError:
                self._write_once(objects, digest, data)
            else:
                if existing != data:
                    raise ActivationError("CAS digest collision")
        return digest

    def put_fd(self, source_fd):
        data, _ = _read_regular_fd(source_fd, exact_mode=0o600)
        return self.put_bytes(data)

    def open_cas(self, digest):
        _hex64(digest, "CAS digest")
        with self._locked_objects() as objects:
            data = self._read_object(objects, digest)
            if _sha(data) != digest:
                raise ActivationError("CAS object digest differs")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(digest, flags, dir_fd=objects)
            try:
                self._check_control(fd, "CAS object")
                check, _ = _read_regular_fd(fd, exact_mode=0o600)
                if check != data:
                    raise ActivationError("CAS object changed before open")
                os.lseek(fd, 0, os.SEEK_SET)
                return fd
            except BaseException:
                os.close(fd)
                raise


def _artifact_module():
    global _ARTIFACT_MODULE
    if _ARTIFACT_MODULE is None:
        path = Path(__file__).with_name("sp_release_artifact_v2.py")
        spec = importlib.util.spec_from_file_location("_spspy_artifact_v2_for_activation", path)
        if spec is None or spec.loader is None:
            raise ActivationError("artifact verifier module is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _ARTIFACT_MODULE = module
    return _ARTIFACT_MODULE


class _HelperRecord:
    __slots__ = ("path", "digest", "fingerprint", "uid", "mode", "execution")

    def __init__(self, *, path, digest, fingerprint, uid=None, mode=0o700, execution="snapshot"):
        self.path = path
        self.digest = digest
        self.fingerprint = fingerprint
        self.uid = os.getuid() if uid is None else uid
        self.mode = mode
        self.execution = execution


class _DarwinStatFS(ctypes.Structure):
    _fields_ = (
        ("f_bsize", ctypes.c_uint32), ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64), ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64), ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64), ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32), ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32), ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16), ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024), ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    )


def _require_local_trusted_filesystem(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    statfs = _DarwinStatFS()
    fstatfs = libc.fstatfs
    fstatfs.argtypes = (ctypes.c_int, ctypes.POINTER(_DarwinStatFS))
    fstatfs.restype = ctypes.c_int
    if fstatfs(fd, ctypes.byref(statfs)) != 0:
        raise ActivationError("production helper filesystem could not be verified")
    filesystem = bytes(statfs.f_fstypename).split(b"\0", 1)[0]
    if not (statfs.f_flags & 0x00001000) or filesystem not in (b"apfs", b"hfs"):
        raise ActivationError("production helper filesystem is not trusted local storage")


def _require_no_extended_acl(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_get_entry = libc.acl_get_entry
    acl_get_entry.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
    acl_get_entry.restype = ctypes.c_int
    acl_free = libc.acl_free
    acl_free.argtypes = (ctypes.c_void_p,)
    acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = acl_get_fd_np(fd, 0x00000100)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise ActivationError("production helper ACL could not be verified")
    try:
        entry = ctypes.c_void_p()
        result = acl_get_entry(acl, 0, ctypes.byref(entry))
        if result == 0:
            raise ActivationError("production helper path has an extended ACL")
        if result != 1:
            raise ActivationError("production helper ACL inspection failed")
    finally:
        acl_free(acl)


def _require_not_effectively_writable(fd):
    try:
        writable = os.access(".", os.W_OK, dir_fd=fd, effective_ids=True, follow_symlinks=False)
    except (NotImplementedError, TypeError, ValueError) as exc:
        raise ActivationError("effective-write verification is unavailable") from exc
    if writable:
        raise ActivationError("production helper path is writable by the runtime identity")


def _require_name_not_effectively_writable(parent_fd, name):
    try:
        writable = os.access(name, os.W_OK, dir_fd=parent_fd, effective_ids=True, follow_symlinks=False)
    except (NotImplementedError, TypeError, ValueError) as exc:
        raise ActivationError("effective-write verification is unavailable") from exc
    if writable:
        raise ActivationError("production helper binary is writable by the runtime identity")


def _production_helper():
    if os.geteuid() == 0:
        raise ActivationError("production selector must not run as root")
    authorities = (PRODUCTION_HELPER_BINARY_SHA256, PRODUCTION_HELPER_CDHASH, PRODUCTION_HELPER_ARCH)
    if (not all(isinstance(value, str) and value for value in authorities) or
            _HEX64.fullmatch(PRODUCTION_HELPER_BINARY_SHA256) is None or
            re.fullmatch(r"[0-9a-f]{40}", PRODUCTION_HELPER_CDHASH) is None):
        raise ActivationError("root-owned production helper authority is not sealed")
    path = Path(PRODUCTION_HELPER_PATH)
    if not path.is_absolute() or ".." in path.parts:
        raise ActivationError("production helper path authority is invalid")
    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    current = Path("/")
    try:
        root_info = os.fstat(directory_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or
                (stat.S_IMODE(root_info.st_mode) & 0o022)):
            raise ActivationError("production helper root directory is unsafe")
        _require_local_trusted_filesystem(directory_fd)
        _require_no_extended_acl(directory_fd)
        _require_not_effectively_writable(directory_fd)
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                              dir_fd=directory_fd)
            info = os.fstat(next_fd)
            current = current / component
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or (stat.S_IMODE(info.st_mode) & 0o022) or
                    info.st_nlink < 2):
                os.close(next_fd)
                raise ActivationError("production helper directory chain is unsafe")
            try:
                _require_local_trusted_filesystem(next_fd)
                _require_no_extended_acl(next_fd)
                _require_not_effectively_writable(next_fd)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(directory_fd)
            directory_fd = next_fd
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        helper_fd = os.open(path.name, flags, dir_fd=directory_fd)
        try:
            data, info = _read_regular_fd(helper_fd, maximum=8 * 1024 * 1024,
                                          exact_mode=0o555, exact_uid=0)
            if _sha(data) != PRODUCTION_HELPER_BINARY_SHA256:
                raise ActivationError("production helper binary authority differs")
            named = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise ActivationError("production helper named inode differs")
            _require_local_trusted_filesystem(helper_fd)
            _require_no_extended_acl(helper_fd)
            _require_name_not_effectively_writable(directory_fd, path.name)
        finally:
            os.close(helper_fd)
    except OSError as exc:
        raise ActivationError("root-owned production helper is unavailable") from exc
    finally:
        os.close(directory_fd)
    try:
        completed = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", os.fspath(path)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ActivationError("production helper code-signing check failed") from exc
    cdhashes = re.findall(rb"^CDHash=([0-9a-f]{40})$", completed.stderr, re.MULTILINE)
    if completed.returncode != 0 or cdhashes != [PRODUCTION_HELPER_CDHASH.encode("ascii")]:
        raise ActivationError("production helper code-signing authority differs")
    try:
        architecture = subprocess.run(
            ["/usr/bin/lipo", "-archs", os.fspath(path)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            check=False, timeout=10)
        observed_architecture = architecture.stdout.decode("ascii", "strict").strip()
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError) as exc:
        raise ActivationError("production helper architecture check failed") from exc
    if (architecture.returncode != 0 or architecture.stderr != b"" or
            observed_architecture != PRODUCTION_HELPER_ARCH):
        raise ActivationError("production helper architecture authority differs")
    return _HelperRecord(path=os.fspath(path), digest=PRODUCTION_HELPER_BINARY_SHA256,
                         fingerprint=_fingerprint(info), uid=0, mode=0o555, execution="installed")


def _open_source(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(os.fspath(path), flags)
    try:
        data, info = _read_regular_fd(fd, maximum=2 * 1024 * 1024)
        if _sha(data) != NATIVE_SOURCE_SHA256:
            raise ActivationError("audited native source pin differs")
        return fd, data, _fingerprint(info)
    except BaseException:
        os.close(fd)
        raise


def _verify_helper(record):
    fd = _open_verified_helper(record)
    os.close(fd)
    return record


def _open_verified_helper(record):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(record.path, flags)
    try:
        data, info = _read_regular_fd(fd, maximum=8 * 1024 * 1024,
                                     exact_mode=record.mode, exact_uid=record.uid)
        if _fingerprint(info) != record.fingerprint or _sha(data) != record.digest:
            raise ActivationError("native helper changed after trusted build")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_held_helper_fd(fd, record):
    duplicate = os.dup(fd)
    try:
        before = os.fstat(duplicate)
        allowed_links = (0, 1) if record.execution == "snapshot" else (1,)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != record.uid or before.st_nlink not in allowed_links or
                stat.S_IMODE(before.st_mode) != record.mode or before.st_size <= 0 or before.st_size > 8 * 1024 * 1024):
            raise ActivationError("held native helper metadata is unsafe")
        chunks = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(duplicate, min(65536, before.st_size - offset), offset)
            if not chunk:
                raise ActivationError("held native helper was truncated")
            chunks.append(chunk)
            offset += len(chunk)
        if os.pread(duplicate, 1, offset):
            raise ActivationError("held native helper grew")
        after = os.fstat(duplicate)
        stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                  before.st_ctime_ns, before.st_mode, before.st_uid, before.st_nlink)
        observed = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                    after.st_ctime_ns, after.st_mode, after.st_uid, after.st_nlink)
        data = b"".join(chunks)
        if stable != observed or _sha(data) != record.digest:
            raise ActivationError("held native helper changed")
        return data
    finally:
        os.close(duplicate)


@contextlib.contextmanager
def _execution_helper_snapshot(source_fd, record):
    """Materialize an internal-test executable from an already pinned FD.

    Darwin has no fexecve/execveat and rejects Mach-O execution through
    /dev/fd.  This random owner-private snapshot is only a local canary/test
    mechanism; production executes the sealed installed helper directly.  The
    native program still binds the snapshot's named inode to `audit_fd`.
    """
    data = _read_held_helper_fd(source_fd, record)
    temporary = tempfile.TemporaryDirectory(prefix="spspy-v3-native-exec-", dir="/private/tmp")
    directory = Path(temporary.name)
    os.chmod(directory, 0o700)
    directory_fd = audit_fd = None
    target = directory / "selector"
    immutable = False
    try:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o700)
        try:
            os.fchmod(target_fd, 0o700)
            _write_all(target_fd, data)
            os.fsync(target_fd)
        finally:
            os.close(target_fd)
        os.fsync(directory_fd)
        audit_fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        observed, info = _read_regular_fd(audit_fd, maximum=8 * 1024 * 1024, exact_mode=0o700)
        if observed != data or _sha(observed) != record.digest:
            raise ActivationError("native execution snapshot differs")
        if hasattr(os, "chflags") and hasattr(stat, "UF_IMMUTABLE"):
            os.chflags(target, stat.UF_IMMUTABLE, follow_symlinks=False)
            immutable = True
        yield os.fspath(target), audit_fd
    finally:
        if immutable:
            try:
                os.chflags(target, 0, follow_symlinks=False)
            except OSError:
                pass
        close_error = None
        try:
            _close_all(audit_fd, directory_fd)
        except OSError as exc:
            close_error = exc
        try:
            temporary.cleanup()
        finally:
            if close_error is not None:
                raise close_error


def _helper():
    global _HELPER_RECORD, _HELPER_TEMPORARY
    if _HELPER_RECORD is not None:
        return _verify_helper(_HELPER_RECORD)
    source = Path(__file__).resolve().parents[1] / "native" / "sp_release_seatbelt_v2.c"
    source_fd, source_bytes, source_fingerprint = _open_source(source)
    try:
        temporary = tempfile.TemporaryDirectory(prefix="spspy-v2-native-build-", dir="/private/tmp")
        directory = Path(temporary.name)
        os.chmod(directory, 0o700)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(directory_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ActivationError("native build directory is unsafe")
            snapshot = directory / "sp_release_seatbelt_v2.c"
            snapshot_fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.fchmod(snapshot_fd, 0o600)
                _write_all(snapshot_fd, source_bytes)
                os.fsync(snapshot_fd)
            finally:
                os.close(snapshot_fd)
            os.fsync(directory_fd)
            snapshot_read = os.open(snapshot, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                snapshot_bytes, _ = _read_regular_fd(snapshot_read, maximum=2 * 1024 * 1024, exact_mode=0o600)
                if snapshot_bytes != source_bytes:
                    raise ActivationError("native source snapshot differs")
            finally:
                os.close(snapshot_read)
            target = directory / "sp_release_seatbelt_v2"
            completed = subprocess.run([NATIVE_CLANG, *NATIVE_BUILD_FLAGS, "-o", os.fspath(target), os.fspath(snapshot)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env={"PATH": "/usr/bin:/bin", "LANG": "C"}, check=False, timeout=30)
            if completed.returncode != 0:
                raise ActivationError("fixed native helper did not compile: %s" % completed.stderr.decode("utf-8", "replace")[:512])
            source_after, after_info = _read_regular_fd(source_fd, maximum=2 * 1024 * 1024)
            if source_after != source_bytes or _fingerprint(after_info) != source_fingerprint:
                raise ActivationError("native source changed during build")
            os.chmod(target, 0o700, follow_symlinks=False)
            target_fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                target_bytes, target_info = _read_regular_fd(target_fd, maximum=8 * 1024 * 1024, exact_mode=0o700)
            finally:
                os.close(target_fd)
            os.fsync(directory_fd)
            record = _HelperRecord(path=os.fspath(target), digest=_sha(target_bytes), fingerprint=_fingerprint(target_info))
            _HELPER_TEMPORARY = temporary  # Managed through interpreter shutdown.
            _HELPER_RECORD = record
            return _verify_helper(record)
        except BaseException:
            temporary.cleanup()
            raise
        finally:
            os.close(directory_fd)
    finally:
        os.close(source_fd)


def _reverify(*, envelope_bytes, payload, trusted_root_bytes, trusted_policy_bytes,
              r1_authority, r2_authority, gh_runner):
    artifact = _artifact_module()
    try:
        proof = artifact.reverify_for_activation(
            envelope_bytes=envelope_bytes, payload=payload, trusted_root_bytes=trusted_root_bytes,
            trusted_policy_bytes=trusted_policy_bytes, r1_authority=r1_authority,
            r2_authority=r2_authority, gh_runner=gh_runner)
    except Exception as exc:
        raise ActivationError("full activation re-verification failed") from exc
    proof_type = getattr(artifact, "ActivationReverifyResult", None)
    if proof_type is None or not isinstance(proof, proof_type):
        raise ActivationError("activation verifier returned invalid proof")
    values = {
        "authority_digest": proof.authority_digest,
        "trusted_root_digest": proof.trusted_root_digest,
        "payload_digest": proof.payload_digest,
        "envelope_digest": proof.envelope_digest,
    }
    for label, value in values.items():
        _hex64(value, label)
    if (values["payload_digest"] != _sha(payload) or values["trusted_root_digest"] != _sha(trusted_root_bytes) or
            values["envelope_digest"] != _sha(envelope_bytes)):
        raise ActivationError("activation verifier proof digest differs")
    return values


def _run_native_command(arguments, *, helper_record, helper_fd=None, pass_fds, timeout_message):
    with contextlib.ExitStack() as stack:
        if helper_fd is None:
            helper_fd = _open_verified_helper(helper_record)
            stack.callback(os.close, helper_fd)
        elif type(helper_fd) is not int or helper_fd < 0:
            raise ActivationError("native helper descriptor is invalid")
        if helper_record.execution == "installed":
            _read_held_helper_fd(helper_fd, helper_record)
            executable, audit_fd = helper_record.path, helper_fd
        elif helper_record.execution == "snapshot":
            executable, audit_fd = stack.enter_context(_execution_helper_snapshot(helper_fd, helper_record))
        else:
            raise ActivationError("native helper execution authority is invalid")
        command = [executable, *arguments, str(audit_fd), helper_record.digest]
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       pass_fds=tuple(dict.fromkeys((*pass_fds, audit_fd))),
                                       close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        except OSError as exc:
            raise ActivationError("native helper could not be started") from exc
        try:
            stdout, stderr = process.communicate(timeout=PYTHON_NATIVE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=NATIVE_CLEANUP_TIMEOUT_SECONDS + 2)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    stdout, stderr = process.communicate(timeout=2)
                except subprocess.TimeoutExpired as exc:
                    if process.stdout is not None:
                        process.stdout.close()
                    if process.stderr is not None:
                        process.stderr.close()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired as wait_exc:
                        raise ActivationError(timeout_message) from wait_exc
                    stdout = exc.output or b""
                    stderr = exc.stderr or b""
        else:
            timed_out = False
        return process.returncode, stdout, stderr, timed_out


def _run_preflight(*, root_fd, selector_fd, previous_fd, epoch, nonce, payload_digest,
                   previous_digest, helper_record, helper_fd):
    prior_present = previous_fd is not None
    previous_argument = str(previous_fd) if prior_present else "-1"
    arguments = ["--preflight", str(root_fd), str(selector_fd), previous_argument,
                 "1" if prior_present else "0", str(epoch), nonce, payload_digest, previous_digest]
    inherited = (root_fd, selector_fd, previous_fd) if prior_present else (root_fd, selector_fd)
    returncode, stdout, stderr, timed_out = _run_native_command(
        arguments, helper_record=helper_record, helper_fd=helper_fd, pass_fds=inherited,
        timeout_message="native semantic preflight exceeded its bounded deadline")
    if timed_out or returncode != 0 or stdout != b"SP_RELEASE_V3 PREFLIGHT_OK\n" or stderr != b"":
        raise ActivationError("native semantic preflight rejected activation (exit=%d, stdout=%r, stderr=%s)" %
                              (returncode, stdout[:128], stderr.decode("utf-8", "replace")[:512]))


def _run_parent(*, root_fd, payload_fd, previous_fd=None, selector_fd=None, epoch, nonce, payload_digest,
                previous_digest, authority_digest, trusted_root_digest, envelope_digest,
                helper_record=None, helper_fd=None):
    if type(epoch) is not int or epoch <= 0:
        raise ActivationError("transaction epoch is invalid")
    for label, value in (("nonce", nonce), ("payload digest", payload_digest), ("previous digest", previous_digest),
                         ("authority digest", authority_digest), ("trusted root digest", trusted_root_digest),
                         ("envelope digest", envelope_digest)):
        _hex64(value, label)
    if nonce == ZERO_SHA256:
        raise ActivationError("transaction nonce cannot be zero")
    if type(root_fd) is not int or root_fd < 0 or type(payload_fd) is not int or payload_fd < 0:
        raise ActivationError("native transaction descriptor is invalid")
    prior_present = previous_fd is not None
    if prior_present:
        if type(previous_fd) is not int or previous_fd < 0:
            raise ActivationError("previous input descriptor is invalid")
        if previous_digest == ZERO_SHA256:
            raise ActivationError("present previous input requires a nonzero digest")
        if previous_digest == payload_digest:
            raise ActivationError("payload and previous digests must differ")
        previous_argument = str(previous_fd)
    else:
        if previous_digest != ZERO_SHA256:
            raise ActivationError("absent previous input requires the zero digest")
        previous_argument = "-1"
    record = _helper() if helper_record is None else _verify_helper(helper_record)
    owned_helper_fd = helper_fd is None
    owned_selector_fd = selector_fd is None
    try:
        if owned_helper_fd:
            helper_fd = _open_verified_helper(record)
        if owned_selector_fd:
            selector_fd = _open_locked_selector(root_fd, create=True)
        if owned_selector_fd:
            _run_preflight(root_fd=root_fd, selector_fd=selector_fd, previous_fd=previous_fd,
                           epoch=epoch, nonce=nonce, payload_digest=payload_digest,
                           previous_digest=previous_digest, helper_record=record, helper_fd=helper_fd)
        arguments = ["--sealed-parent", str(root_fd), str(selector_fd), str(payload_fd), previous_argument,
               "1" if prior_present else "0", str(epoch), nonce, payload_digest, previous_digest,
               authority_digest, trusted_root_digest, envelope_digest]
        inherited = ((root_fd, selector_fd, payload_fd, previous_fd) if prior_present else
                     (root_fd, selector_fd, payload_fd))
        returncode, stdout, stderr, timed_out = _run_native_command(
            arguments, helper_record=record, helper_fd=helper_fd, pass_fds=inherited,
            timeout_message="native transaction exceeded total deadline and is UNCERTAIN")
    finally:
        _close_all(selector_fd if owned_selector_fd else None,
                   helper_fd if owned_helper_fd else None)
    if returncode == 0 and stdout == b"SP_RELEASE_V3 COMMITTED\n" and stderr == b"":
        return {"phase": "COMMITTED", "helper_sha256": record.digest,
                "prior_present": prior_present}
    if returncode == 10 and stdout == b"SP_RELEASE_V3 ROLLED_BACK\n" and stderr == b"":
        return {"phase": "ROLLED_BACK", "helper_sha256": record.digest,
                "prior_present": prior_present}
    if timed_out:
        raise ActivationError("native transaction exceeded total deadline and is UNCERTAIN")
    if returncode in (76, 77) and stdout == b"SP_RELEASE_V3 RECOVERY_REQUIRED\n":
        raise ActivationError("durable state requires manual recovery; existing state/current were preserved")
    raise ActivationError("native transaction is UNCERTAIN (exit=%d, stdout=%r, stderr=%s)" %
                          (returncode, stdout[:128], stderr.decode("utf-8", "replace")[:512]))


def _json_object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ActivationError("native reconciliation JSON has duplicate fields")
        result[key] = value
    return result


def _parse_reconciliation_line(stdout, *, prefix, operation):
    if (not isinstance(stdout, bytes) or not stdout.endswith(b"\n") or
            stdout.count(b"\n") != 1 or not stdout.startswith(prefix)):
        raise ActivationError("native reconciliation output framing is invalid")
    encoded = stdout[len(prefix):-1]
    if not encoded or len(encoded) > 4096:
        raise ActivationError("native reconciliation JSON size is invalid")
    try:
        document = encoded.decode("ascii", "strict")
        value = json.loads(document, object_pairs_hook=_json_object_without_duplicates,
                           parse_constant=lambda unused: (_ for _ in ()).throw(
                               ActivationError("native reconciliation JSON contains a non-finite number")))
    except ActivationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ActivationError("native reconciliation JSON is invalid") from exc
    if not isinstance(value, dict) or frozenset(value) != _RECONCILIATION_KEYS:
        raise ActivationError("native reconciliation JSON fields are invalid")
    if value["protocol"] != "SP_RELEASE_V3" or value["operation"] != operation:
        raise ActivationError("native reconciliation protocol binding is invalid")
    classification = value["classification"]
    allowed = _INSPECT_CLASSIFICATIONS if operation == "INSPECT" else _RECOVER_CLASSIFICATIONS
    if classification not in allowed:
        raise ActivationError("native reconciliation classification is invalid")
    for field in ("state_sha256", "current_sha256"):
        _hex64(value[field], field.replace("_", " "))
    epoch = value["epoch"]
    if type(epoch) is not int or epoch < 0 or epoch > (1 << 64) - 1:
        raise ActivationError("native reconciliation epoch is invalid")
    if type(value["phase"]) is not int or value["phase"] < 0 or value["phase"] > 8:
        raise ActivationError("native reconciliation phase is invalid")
    if (type(value["recovery_from_phase"]) is not int or value["recovery_from_phase"] < 0 or
            value["recovery_from_phase"] > 7):
        raise ActivationError("native reconciliation recovery from phase is invalid")
    if value["phase"] == 8 and value["recovery_from_phase"] != 4:
        raise ActivationError("native reconciliation rollback recovery origin is invalid")
    if type(value["prior_present"]) is not bool:
        raise ActivationError("native reconciliation prior presence is invalid")
    if value["current"] not in ("ABSENT", "PAYLOAD", "PRIOR", "UNKNOWN"):
        raise ActivationError("native reconciliation current classification is invalid")
    if (value["current"] == "ABSENT" and value["current_sha256"] != ZERO_SHA256):
        raise ActivationError("native reconciliation current digest is inconsistent")
    if (value["current"] in ("PAYLOAD", "PRIOR") and
            value["current_sha256"] == ZERO_SHA256):
        raise ActivationError("native reconciliation current digest is inconsistent")
    phase = value["phase"]
    origin = value["recovery_from_phase"]
    prior = value["prior_present"]
    current = value["current"]
    if phase == 0:
        if (value["epoch"] != 0 or value["state_sha256"] != ZERO_SHA256 or origin != 0 or prior):
            raise ActivationError("native reconciliation empty-state semantics are inconsistent")
    else:
        if value["epoch"] == 0 or value["state_sha256"] == ZERO_SHA256:
            raise ActivationError("native reconciliation durable-state semantics are inconsistent")
        if phase == 7:
            if origin < 1 or origin > 6:
                raise ActivationError("native reconciliation uncertain origin is invalid")
        elif phase == 8:
            if origin != 4:
                raise ActivationError("native reconciliation rollback recovery origin is invalid")
        elif origin != 0:
            raise ActivationError("native reconciliation unexpected recovery origin is invalid")
    if not prior and current == "PRIOR":
        raise ActivationError("native reconciliation absent prior cannot classify current as prior")
    prior_current = "PRIOR" if prior else "ABSENT"
    if classification == "FRESH" and not (phase == 0 and current == "ABSENT"):
        raise ActivationError("native fresh inspection semantics are inconsistent")
    if classification in ("BUSY", "ACTIVE") and not (phase == 0 and current == "UNKNOWN"):
        raise ActivationError("native busy inspection semantics are inconsistent")
    if classification == "DEBRIS":
        if ((phase == 0 and current not in ("ABSENT", "UNKNOWN")) or
                (phase != 0 and current != "UNKNOWN")):
            raise ActivationError("native debris inspection semantics are inconsistent")
    if classification == "BLOCKED" and phase == 0 and current not in ("ABSENT", "UNKNOWN"):
        raise ActivationError("native blocked inspection semantics are inconsistent")
    if classification == "TERMINAL_COMMITTED" and not (phase == 5 and current == "PAYLOAD"):
        raise ActivationError("native committed terminal semantics are inconsistent")
    if classification == "TERMINAL_ROLLED_BACK" and not (phase == 6 and current == prior_current):
        raise ActivationError("native rolled-back terminal semantics are inconsistent")
    if classification == "RECOVERABLE_COMMITTED":
        if current != "PAYLOAD" or not (phase in (2, 3) or (phase == 7 and origin in (2, 3, 5))):
            raise ActivationError("native recoverable commit semantics are inconsistent")
    if classification == "RECOVERABLE_ROLLED_BACK":
        allowed_rolled = (phase in (1, 2, 3, 4, 8) or
                          (phase == 7 and origin in (1, 2, 3, 4, 6)))
        if current != prior_current or not allowed_rolled:
            raise ActivationError("native recoverable rollback semantics are inconsistent")
    if classification == "RECOVERABLE_ROLLBACK_REQUIRED":
        if current != "PAYLOAD" or not (phase in (4, 8) or (phase == 7 and origin == 4)):
            raise ActivationError("native rollback-intent semantics are inconsistent")
    if classification == "RECOVERED_COMMITTED" and not (phase == 5 and origin == 0 and current == "PAYLOAD"):
        raise ActivationError("native recovered commit semantics are inconsistent")
    if classification == "RECOVERED_ROLLED_BACK" and not (
            phase == 6 and origin == 0 and current == prior_current):
        raise ActivationError("native recovered rollback semantics are inconsistent")
    return value


def _inspect_reconciliation_fd(root_fd, record):
    arguments = ["--inspect", str(root_fd)]
    returncode, stdout, stderr, timed_out = _run_native_command(
        arguments, helper_record=record, pass_fds=(root_fd,),
        timeout_message="native read-only reconciliation inspection exceeded its deadline")
    if timed_out or returncode != 0 or stderr != b"":
        raise ActivationError("native reconciliation inspection failed (exit=%d, stdout=%r, stderr=%s)" %
                              (returncode, stdout[:128], stderr.decode("utf-8", "replace")[:512]))
    return _parse_reconciliation_line(stdout, prefix=b"SP_RELEASE_V3_INSPECT ", operation="INSPECT")


def _inspect_reconciliation(root, *, helper_record):
    """Internal explicit-helper test hook; public callers cannot inject a binary."""
    record = _verify_helper(helper_record)
    root_fd = _open_private_root_readonly(root)
    try:
        return _inspect_reconciliation_fd(root_fd, record)
    finally:
        os.close(root_fd)


def inspect_reconciliation(root):
    """Classify durable activation state without creating or changing root entries."""
    record = _production_helper()
    root_fd = _open_private_root_readonly(root)
    try:
        return _inspect_reconciliation_fd(root_fd, record)
    finally:
        os.close(root_fd)


def _recover_interrupted(root, expected_state_sha256, previous_fd=None, *, helper_record):
    """Reconcile one proven interrupted transaction; this never retries its nonce."""
    _hex64(expected_state_sha256, "expected state digest")
    if expected_state_sha256 == ZERO_SHA256:
        raise ActivationError("expected interrupted state digest cannot be zero")
    record = _verify_helper(helper_record)
    root_fd = _open_private_root_readonly(root)
    previous_guard = recovery_snapshot_fd = None
    try:
        prior_present = previous_fd is not None
        if prior_present:
            previous_bytes, previous_identity, previous_guard = _snapshot_regular_fd(
                previous_fd, label="previous recovery input")
            _require_unchanged_snapshot_fd(
                previous_fd, previous_identity, label="previous recovery input descriptor")
            recovery_snapshot_fd = _anonymous_private_snapshot(
                previous_bytes, label="previous recovery snapshot")
            _require_unchanged_snapshot_fd(
                previous_fd, previous_identity, label="previous recovery input descriptor")
            previous_argument = str(recovery_snapshot_fd)
        else:
            previous_identity = None
            previous_argument = "-1"
        arguments = ["--recover", str(root_fd), previous_argument,
                     "1" if prior_present else "0", expected_state_sha256]
        inherited = (root_fd, recovery_snapshot_fd) if prior_present else (root_fd,)
        returncode, stdout, stderr, timed_out = _run_native_command(
            arguments, helper_record=record, pass_fds=inherited,
            timeout_message="native recovery exceeded its deadline; reconciliation remains required")
        if returncode == 0 and stderr == b"":
            return _parse_reconciliation_line(
                stdout, prefix=b"SP_RELEASE_V3_RECOVER ", operation="RECOVER")
        if timed_out:
            raise ActivationError("native recovery exceeded its deadline; reconciliation remains required")
        if stdout == b"SP_RELEASE_V3 RECOVERY_BLOCKED\n":
            raise ActivationError("native recovery was blocked; root state/current were preserved")
        raise ActivationError("native recovery is uncertain (exit=%d, stdout=%r, stderr=%s)" %
                              (returncode, stdout[:128], stderr.decode("utf-8", "replace")[:512]))
    finally:
        _close_all(previous_guard, recovery_snapshot_fd, root_fd)


def recover_interrupted(root, expected_state_sha256, previous_fd=None):
    """Public recovery uses only the sealed, root-owned preinstalled helper."""
    record = _production_helper()
    return _recover_interrupted(root, expected_state_sha256, previous_fd, helper_record=record)


def _activate_verified(*, root, envelope_bytes, canonical_tar_fd, trusted_root_bytes, trusted_policy_bytes,
                       r1_authority, r2_authority, previous_fd=None, epoch, nonce, gh_runner=None,
                       helper_record):
    """Repeat complete R1/R2 verification and select the sealed canonical tar."""
    if type(epoch) is not int or epoch <= 0:
        raise ActivationError("transaction epoch is invalid")
    _hex64(nonce, "nonce")
    if nonce == ZERO_SHA256:
        raise ActivationError("transaction nonce cannot be zero")
    record = _verify_helper(helper_record)
    helper_fd = _open_verified_helper(record)
    root_fd = selector_fd = payload_guard = previous_guard = None
    try:
        root_fd = _open_private_root_readonly(root)
        fresh = _selection_fd_is_fresh(root_fd)
        if fresh and previous_fd is not None:
            raise ActivationError("fresh activation root requires an absent previous input")
        payload, payload_identity, payload_guard = _snapshot_regular_fd(canonical_tar_fd, label="payload input")
        if previous_fd is None:
            previous = None
            previous_identity = None
            previous_digest = ZERO_SHA256
        else:
            previous, previous_identity, previous_guard = _snapshot_regular_fd(
                previous_fd, label="previous input")
            previous_digest = _sha(previous)
        payload_digest = _sha(payload)
        if previous is not None and payload_digest == previous_digest:
            raise ActivationError("payload and previous digests must differ")

        if not fresh:
            selector_fd = _open_locked_selector(root_fd, create=False)
            _run_preflight(root_fd=root_fd, selector_fd=selector_fd, previous_fd=previous_guard,
                           epoch=epoch, nonce=nonce, payload_digest=payload_digest,
                           previous_digest=previous_digest, helper_record=record, helper_fd=helper_fd)

        proof = _reverify(
            envelope_bytes=envelope_bytes, payload=payload, trusted_root_bytes=trusted_root_bytes,
            trusted_policy_bytes=trusted_policy_bytes, r1_authority=r1_authority,
            r2_authority=r2_authority, gh_runner=gh_runner)
        _require_unchanged_snapshot_fd(payload_guard, payload_identity, label="payload input")
        _require_unchanged_snapshot_fd(canonical_tar_fd, payload_identity, label="payload input descriptor")
        if previous_guard is not None:
            _require_unchanged_snapshot_fd(previous_guard, previous_identity, label="previous input")
            _require_unchanged_snapshot_fd(previous_fd, previous_identity, label="previous input descriptor")
        if proof["payload_digest"] != payload_digest:
            raise ActivationError("verified payload snapshot digest differs")

        if fresh:
            selector_fd = _open_locked_selector(root_fd, create=True)
            _run_preflight(root_fd=root_fd, selector_fd=selector_fd, previous_fd=None,
                           epoch=epoch, nonce=nonce, payload_digest=payload_digest,
                           previous_digest=ZERO_SHA256, helper_record=record, helper_fd=helper_fd)

        with DirFDStore.from_fd(root_fd) as store:
            stored_payload_digest = store.put_bytes(payload)
            stored_previous_digest = ZERO_SHA256 if previous is None else store.put_bytes(previous)
            if stored_payload_digest != payload_digest or stored_previous_digest != previous_digest:
                raise ActivationError("CAS snapshot differs after full verification")
            payload_fd = rollback_fd = None
            try:
                payload_fd = store.open_cas(payload_digest)
                if previous is not None:
                    rollback_fd = store.open_cas(previous_digest)
                return _run_parent(
                    root_fd=store.fd, selector_fd=selector_fd, payload_fd=payload_fd,
                    previous_fd=rollback_fd, epoch=epoch, nonce=nonce, payload_digest=payload_digest,
                    previous_digest=previous_digest, authority_digest=proof["authority_digest"],
                    trusted_root_digest=proof["trusted_root_digest"],
                    envelope_digest=proof["envelope_digest"], helper_record=record, helper_fd=helper_fd)
            finally:
                _close_all(rollback_fd, payload_fd)
    finally:
        _close_all(previous_guard, payload_guard, selector_fd, root_fd, helper_fd)


def activate_verified(*, root, envelope_bytes, canonical_tar_fd, trusted_root_bytes, trusted_policy_bytes,
                      r1_authority, r2_authority, previous_fd=None, epoch, nonce, gh_runner=None):
    """Production entrypoint; unavailable until root-owned helper authority is sealed."""
    if type(epoch) is not int or epoch <= 0:
        raise ActivationError("transaction epoch is invalid")
    _hex64(nonce, "nonce")
    if nonce == ZERO_SHA256:
        raise ActivationError("transaction nonce cannot be zero")
    if type(canonical_tar_fd) is not int or canonical_tar_fd < 0 or (
            previous_fd is not None and (type(previous_fd) is not int or previous_fd < 0)):
        raise ActivationError("activation input descriptor is invalid")
    record = _production_helper()
    return _activate_verified(
        root=root, envelope_bytes=envelope_bytes, canonical_tar_fd=canonical_tar_fd,
        trusted_root_bytes=trusted_root_bytes, trusted_policy_bytes=trusted_policy_bytes,
        r1_authority=r1_authority, r2_authority=r2_authority, previous_fd=previous_fd,
        epoch=epoch, nonce=nonce, gh_runner=gh_runner, helper_record=record)


class DenyNetworkNotifier:
    def notify(self, *unused, **unused_kwargs):
        raise ActivationError("canary networking is denied")


def _write_private(path, data):
    fd = os.open(os.fspath(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def run_canary(*, payload, root=None, notifier=None):
    """Exercise only the fixed native selector and isolated temporary bytes."""
    if not isinstance(payload, bytes) or not payload:
        raise ActivationError("canary payload is invalid")
    if notifier is not None and not isinstance(notifier, DenyNetworkNotifier):
        raise ActivationError("canary accepts only the deny-network notifier")
    base = Path(tempfile.mkdtemp(prefix="spspy-v2-canary-", dir=root))
    transaction = base / "transaction"
    transaction.mkdir(mode=0o700)
    os.chmod(transaction, 0o700)
    payload_path = base / "payload.bin"
    _write_private(payload_path, payload)
    payload_input = os.open(payload_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with DirFDStore(transaction) as store:
            payload_digest = store.put_fd(payload_input)
            payload_fd = store.open_cas(payload_digest)
            try:
                outcome = _run_parent(root_fd=store.fd, payload_fd=payload_fd, previous_fd=None, epoch=1,
                                      nonce=secrets.token_hex(32), payload_digest=payload_digest,
                                      previous_digest=ZERO_SHA256, authority_digest=_sha(b"canary-authority-v3"),
                                      trusted_root_digest=_sha(b"canary-trusted-root-v3"),
                                      envelope_digest=_sha(b"canary-envelope-v3"))
            finally:
                os.close(payload_fd)
    finally:
        os.close(payload_input)
    selected = transaction / "current.payload"
    if outcome["phase"] != "COMMITTED" or selected.read_bytes() != payload:
        raise ActivationError("canary native selection differs")
    return {"directory": os.fspath(base), "phase": outcome["phase"], "payload_sha256": payload_digest,
            "notifier": "network-denied", "semantics": "selected-data-not-deployed"}
