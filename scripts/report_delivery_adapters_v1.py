"""Durable, fail-closed adapters for the pure report-delivery outbox.

All side effects are explicit: callers supply the store root and transports.
There is deliberately no environment discovery, subprocess use, or network I/O.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import stat
import fcntl
import tempfile
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any

from scripts import report_delivery_outbox_v1 as outbox

_LOCK = ".report-delivery.lock"
_ACTIVE = "active.json"
_RECEIPTS = "receipts"
_TMP = re.compile(r"^\.active\.tmp\.[0-9a-f]{32}$")
_RECEIPT_TMP = re.compile(r"^\.receipt\.tmp\.([0-9a-f]{64})$")
_RECEIPT_SCHEMA = "report-delivery-receipt/v1"
_ERROR_CLASS = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PRODUCTION_CANARY_COMPONENT = re.compile(
    r"(?:^|[-_.])(?:prod(?:uction)?|live)(?:$|[-_.])", re.IGNORECASE
)


class AdapterError(Exception): pass
class StoreIntegrityError(AdapterError): pass
class StoreBusy(AdapterError): pass
class PendingTransaction(AdapterError): pass
class CommitUncertain(AdapterError):
    def __init__(self, message, before_sha=None, after_sha=None):
        super().__init__(message); self.before_sha, self.after_sha = before_sha, after_sha
class StoreCommitUncertain(CommitUncertain): pass
class TransportFailure(AdapterError): pass
class DedupeIntegrityError(AdapterError): pass


class RecoveryResult(str, Enum):
    APPLIED = "applied"
    NOT_APPLIED = "not_applied"
    DIVERGED = "diverged"


@dataclass(frozen=True, slots=True)
class Snapshot:
    record: outbox.OutboxRecord
    record_sha256: str
    resume_action: str


@dataclass(frozen=True, slots=True)
class FinalReceipt:
    outbox_id: str
    record_sha256: str
    outcome: str
    publication_outcome: str
    delivery_outcome: str
    dedupe_outcome: str
    channel: Any
    delivered_count: int


@dataclass(frozen=True, slots=True)
class GithubPolicy:
    """An exact allowlist; a target outside it is never sent to a transport."""
    repository: str
    ref: str
    path_prefix: str
    def __post_init__(self):
        if (not isinstance(self.repository, str) or len(self.repository.encode("utf-8")) > 255
                or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository)):
            raise ValueError("invalid GithubPolicy repository")
        if not isinstance(self.ref, str):
            raise ValueError("invalid GithubPolicy ref")
        tail = self.ref[11:] if self.ref.startswith("refs/heads/") else ""
        components = tail.split("/") if tail else ()
        if (not tail or len(self.ref.encode("utf-8")) > 255 or ".." in self.ref
                or "//" in self.ref or self.ref.endswith((".", "/")) or "@{" in self.ref
                or any(char in self.ref for char in " ~^:?*[\\")
                or any(unicodedata.category(char) == "Cc" for char in self.ref)
                or any(part.startswith(".") or part.endswith(".lock") for part in components)):
            raise ValueError("invalid GithubPolicy ref")
        if not isinstance(self.path_prefix, str):
            raise ValueError("invalid GithubPolicy path prefix")
        prefix = self.path_prefix.rstrip("/")
        pieces = prefix.split("/")
        if (not prefix or prefix != unicodedata.normalize("NFC", prefix) or prefix.startswith("/")
                or len(prefix.encode("utf-8")) > 1024 or "\\" in prefix
                or any(not part or part in (".", "..") for part in pieces)
                or any(unicodedata.category(char) == "Cc" for char in prefix)):
            raise ValueError("invalid GithubPolicy path prefix")
        object.__setattr__(self, "path_prefix", prefix)
    def allows(self, target):
        return (target.repository == self.repository and target.ref == self.ref and
                (target.path == self.path_prefix or target.path.startswith(self.path_prefix + "/")))


@dataclass(frozen=True, slots=True)
class CanaryPolicy:
    """Explicit synthetic-target guard for the fake-only canary helper."""
    canonical_root: str
    allowed_temp_base: str
    repository: str = "synthetic/report-delivery-canary"
    ref: str = "refs/heads/report-delivery-canary"
    path: str = "synthetic/report-delivery/canary.png"
    def __post_init__(self):
        if (not isinstance(self.repository, str) or not self.repository.startswith("synthetic/")
                or not isinstance(self.ref, str) or not self.ref.startswith("refs/heads/")
                or self.ref == "refs/heads/main" or "canary" not in self.ref[11:].lower()
                or not isinstance(self.path, str) or not self.path.startswith("synthetic/")
                or any(token in self.repository.lower() or token in self.path.lower()
                       for token in ("production", "live/"))):
            raise ValueError("CanaryPolicy must bind a synthetic target")
        for field_name in ("canonical_root", "allowed_temp_base"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError("CanaryPolicy must bind canonical filesystem paths")
            absolute = os.path.abspath(value)
            if value != absolute or value != os.path.realpath(value):
                raise ValueError("CanaryPolicy must bind canonical filesystem paths")
        try:
            relative = os.path.relpath(self.canonical_root, self.allowed_temp_base)
            inside = os.path.commonpath((self.canonical_root, self.allowed_temp_base)) == self.allowed_temp_base
        except ValueError as error:
            raise ValueError("CanaryPolicy root must be inside the allowed temp base") from error
        try:
            base_stat = os.lstat(self.allowed_temp_base)
        except OSError as error:
            raise ValueError("CanaryPolicy temp base must be an existing directory") from error
        components = [component for component in self.canonical_root.split(os.sep) if component]
        if (not inside or relative in ("", ".") or relative == os.pardir
                or relative.startswith(os.pardir + os.sep)
                or not stat.S_ISDIR(base_stat.st_mode)
                or any(_PRODUCTION_CANARY_COMPONENT.search(component) for component in components)):
            raise ValueError("CanaryPolicy root must be a synthetic child of the allowed temp base")
    def allows(self, target):
        return (target.repository == self.repository and target.ref == self.ref and target.path == self.path)


def _sha(value): return hashlib.sha256(value).hexdigest()
def _mode(st): return stat.S_IMODE(st.st_mode)
def _regular(st, mode, uid):
    return stat.S_ISREG(st.st_mode) and _mode(st) == mode and st.st_uid == uid and st.st_nlink == 1


def _fingerprint(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _root_fingerprint(st):
    return st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_nlink


def _secure_root(st, uid):
    return stat.S_ISDIR(st.st_mode) and _mode(st) == 0o700 and st.st_uid == uid


def _verify_root_binding(root, fs, uid, fd, expected=None, *, allow_nlink_change=False):
    try:
        current = fs.fstat(fd)
        named = fs.lstat(root)
    except OSError as error:
        raise StoreIntegrityError("store root binding is unavailable") from error
    current_fingerprint = _root_fingerprint(current)
    named_fingerprint = _root_fingerprint(named)
    expected_matches = (expected is None
                        or current_fingerprint == expected
                        or (allow_nlink_change and current_fingerprint[:-1] == expected[:-1]))
    if (not _secure_root(current, uid) or not _secure_root(named, uid)
            or current_fingerprint != named_fingerprint
            or not expected_matches):
        raise StoreIntegrityError("store root changed or became unsafe")
    return current_fingerprint


def _check_root(root, fs, uid):
    st = fs.lstat(root)
    if not _secure_root(st, uid):
        raise StoreIntegrityError("store root must be a same-owner 0700 directory")
    flags = fs.O_RDONLY | getattr(fs, "O_DIRECTORY", 0) | getattr(fs, "O_CLOEXEC", 0) | getattr(fs, "O_NOFOLLOW", 0)
    try:
        fd = fs.open(root, flags)
    except OSError as error:
        raise StoreIntegrityError("store root changed while opening") from error
    try:
        _verify_root_binding(root, fs, uid, fd, _root_fingerprint(st))
        return fd
    except Exception:
        fs.close(fd)
        raise


def _read_fd(fs, fd, limit=33 * 1024 * 1024):
    chunks, size = [], 0
    while True:
        data = fs.read(fd, 65536)
        if not data: return b"".join(chunks)
        size += len(data)
        if size > limit: raise StoreIntegrityError("store file exceeds limit")
        chunks.append(data)


def _open_checked(fs, dfd, name, flags, mode, uid):
    try:
        fd = fs.open(name, flags | getattr(fs, "O_CLOEXEC", 0) | getattr(fs, "O_NOFOLLOW", 0), dir_fd=dfd)
    except OSError as error:
        if error.errno == errno.ELOOP: raise StoreIntegrityError("symlinked store file") from error
        raise
    st = fs.fstat(fd)
    try:
        named = fs.stat(name, dir_fd=dfd, follow_symlinks=False)
    except OSError as error:
        fs.close(fd)
        raise StoreIntegrityError("store file binding is unavailable") from error
    if (not _regular(st, mode, uid) or not _regular(named, mode, uid)
            or _fingerprint(st) != _fingerprint(named)):
        fs.close(fd); raise StoreIntegrityError("unsafe store file")
    return fd, st


def _verify_lock_binding(fs, dfd, lockfd, uid, expected):
    try:
        current = fs.fstat(lockfd)
        named = fs.stat(_LOCK, dir_fd=dfd, follow_symlinks=False)
    except OSError as error:
        raise StoreIntegrityError("store lock binding is unavailable") from error
    if (not _regular(current, 0o600, uid) or not _regular(named, 0o600, uid)
            or _fingerprint(current) != expected
            or _fingerprint(named) != expected):
        raise StoreIntegrityError("store lock changed or became unsafe")


def _store_fence(root, fs, uid, dfd, root_identity, lockfd, lock_identity):
    """Revalidate the two identities that authorize store mutations.

    Directory-relative syscalls keep mutations on the opened root, while this
    fence fails closed if either public path is rebound between checkpoints.
    """
    _verify_root_binding(root, fs, uid, dfd, root_identity, allow_nlink_change=True)
    _verify_lock_binding(fs, dfd, lockfd, uid, lock_identity)


def _fsync_directory_locked(fs, directory_fd, fence):
    fence()
    fs.fsync(directory_fd)
    fence()


def _clean_active_temps_locked(fs, dfd, uid, fence):
    """Validate the complete active-temp set before performing any cleanup."""
    fence()
    names = fs.listdir(dfd)
    fence()
    targets = []
    for name in names:
        if name.startswith(".active.tmp."):
            if not _TMP.fullmatch(name):
                raise StoreIntegrityError("unsafe stale temporary name")
            targets.append(name)

    opened = []
    try:
        for name in targets:
            fd, initial = _open_checked(fs, dfd, name, fs.O_RDONLY, 0o600, uid)
            opened.append((name, fd, _fingerprint(initial)))
            fence()
        for name, fd, initial_fingerprint in opened:
            current = fs.fstat(fd)
            named = fs.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (_fingerprint(current) != initial_fingerprint
                    or _fingerprint(named) != initial_fingerprint):
                raise StoreIntegrityError("stale temporary changed before cleanup")
            fence()
            fs.unlink(name, dir_fd=dfd)
            fence()
    finally:
        for unused_name, fd, unused_fingerprint in reversed(opened):
            fs.close(fd)


def _read_checked(fs, dfd, name, mode, uid, limit):
    fd, before = _open_checked(fs, dfd, name, fs.O_RDONLY, mode, uid)
    try:
        value = _read_fd(fs, fd, limit)
        after = fs.fstat(fd)
        named = fs.stat(name, dir_fd=dfd, follow_symlinks=False)
        if _fingerprint(before) != _fingerprint(after) or _fingerprint(before) != _fingerprint(named):
            raise StoreIntegrityError("store file changed while reading")
        if len(value) != before.st_size:
            raise StoreIntegrityError("store file changed while reading")
        return value
    finally:
        fs.close(fd)


def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8") + b"\n"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _write_all(fs, fd, value):
    offset = 0
    while offset < len(value):
        written = fs.write(fd, value[offset:])
        if not written: raise OSError("short store write")
        offset += written


def _receipt_bytes(record, record_sha256, terminal_action):
    return _canonical_json({
        "channel": None if record.delivery.channel is None else record.delivery.channel.value,
        "dedupe_outcome": record.dedupe.outcome.value,
        "delivered_count": len(record.delivery.delivered_handles),
        "delivery_outcome": record.delivery.outcome.value,
        "outbox_id": record.outbox_id,
        "publication_outcome": record.publication.outcome.value,
        "schema": _RECEIPT_SCHEMA,
        "terminal_action": terminal_action,
        "terminal_record_sha256": record_sha256,
    })


def _parse_receipt_bytes(data, expected_id=None):
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as error:
        raise StoreIntegrityError("invalid receipt") from error
    keys = {
        "schema", "outbox_id", "terminal_action", "terminal_record_sha256",
        "publication_outcome", "delivery_outcome", "dedupe_outcome", "channel",
        "delivered_count",
    }
    if not isinstance(obj, dict) or set(obj) != keys or _canonical_json(obj) != data:
        raise StoreIntegrityError("invalid receipt")
    if obj["schema"] != _RECEIPT_SCHEMA:
        raise StoreIntegrityError("invalid receipt")
    outbox_id = obj["outbox_id"]
    if not isinstance(outbox_id, str) or not re.fullmatch(r"rdo1-[0-9a-f]{64}", outbox_id):
        raise StoreIntegrityError("invalid receipt")
    if expected_id is not None and outbox_id != expected_id:
        raise StoreIntegrityError("invalid receipt")
    sha = obj["terminal_record_sha256"]
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise StoreIntegrityError("invalid receipt")
    terminal = obj["terminal_action"]
    publication = obj["publication_outcome"]
    delivery = obj["delivery_outcome"]
    dedupe = obj["dedupe_outcome"]
    channel = obj["channel"]
    count = obj["delivered_count"]
    if type(count) is not int or count < 0:
        raise StoreIntegrityError("invalid receipt")
    valid_complete = (
        terminal == "complete" and publication in ("published", "conflict")
        and delivery == "sent" and dedupe == "applied"
        and channel in ("primary", "fallback") and count > 0
        and ((publication == "published" and channel == "primary")
             or (publication == "conflict" and channel == "fallback"))
    )
    valid_conflict = (
        terminal == "terminal_conflict" and publication == "conflict"
        and delivery == "not_sent" and dedupe == "not_applied"
        and channel is None and count == 0
    )
    if not (valid_complete or valid_conflict):
        raise StoreIntegrityError("invalid receipt")
    return FinalReceipt(outbox_id, sha, terminal, publication, delivery, dedupe, channel, count)


def initialize_store(root, *, fs=os, uid=None):
    """Create a new empty store, or validate and clean only safe stale temps."""
    uid = fs.getuid() if uid is None else uid
    try:
        fs.mkdir(root, 0o700)
    except FileExistsError:
        pass
    dfd = _check_root(root, fs, uid)
    root_identity = _root_fingerprint(fs.fstat(dfd))
    lockfd = None
    locked = False
    fence = None
    try:
        create_flags = (fs.O_RDWR | fs.O_CREAT | fs.O_EXCL
                        | getattr(fs, "O_CLOEXEC", 0) | getattr(fs, "O_NOFOLLOW", 0))
        try:
            lockfd = fs.open(_LOCK, create_flags, 0o600, dir_fd=dfd)
        except FileExistsError:
            open_flags = fs.O_RDWR | getattr(fs, "O_CLOEXEC", 0) | getattr(fs, "O_NOFOLLOW", 0)
            try:
                lockfd = fs.open(_LOCK, open_flags, dir_fd=dfd)
            except OSError as error:
                raise StoreIntegrityError("store lock is unavailable") from error
        except OSError as error:
            raise StoreIntegrityError("store lock is unavailable") from error
        try:
            lock_stat = fs.fstat(lockfd)
            named_lock = fs.stat(_LOCK, dir_fd=dfd, follow_symlinks=False)
        except OSError as error:
            raise StoreIntegrityError("store lock binding is unavailable") from error
        if (not _regular(lock_stat, 0o600, uid) or not _regular(named_lock, 0o600, uid)
                or _fingerprint(lock_stat) != _fingerprint(named_lock)):
            raise StoreIntegrityError("store lock changed or became unsafe")
        lock_identity = _fingerprint(lock_stat)
        fence = lambda: _store_fence(
            root, fs, uid, dfd, root_identity, lockfd, lock_identity
        )
        fence()
        fs.fsync(lockfd)
        fence()
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX)
            locked = True
            fence()

            # Receipts state is created or trusted only while the same lock is held.
            fence()
            try:
                fs.mkdir(_RECEIPTS, 0o700, dir_fd=dfd)
            except FileExistsError:
                rst = fs.stat(_RECEIPTS, dir_fd=dfd, follow_symlinks=False)
                if not stat.S_ISDIR(rst.st_mode) or _mode(rst) != 0o700 or rst.st_uid != uid:
                    raise StoreIntegrityError("unsafe receipts directory")
            fence()

            _clean_active_temps_locked(fs, dfd, uid, fence)
            _fsync_directory_locked(fs, dfd, fence)
            fence()
        finally:
            if locked:
                try:
                    fence()
                finally:
                    fcntl.flock(lockfd, fcntl.LOCK_UN)
    finally:
        try:
            _verify_root_binding(root, fs, uid, dfd)
        finally:
            if lockfd is not None:
                fs.close(lockfd)
            fs.close(dfd)


class OutboxTransaction:
    def __init__(self, root, *, fs=os, uid=None, clock=None, nonblocking=True):
        self.fs, self.uid, self.root, self.clock = fs, (fs.getuid() if uid is None else uid), root, clock
        self.dfd = _check_root(root, fs, self.uid)
        self._root_identity = _root_fingerprint(fs.fstat(self.dfd))
        self.lockfd = None; self._lock_identity = None; self._counter = 0
        try:
            self.lockfd, before = _open_checked(fs, self.dfd, _LOCK, fs.O_RDWR, 0o600, self.uid)
            try: fcntl.flock(self.lockfd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
            except BlockingIOError as error: raise StoreBusy("store is already coordinated") from error
            try:
                after = fs.fstat(self.lockfd)
                named = fs.stat(_LOCK, dir_fd=self.dfd, follow_symlinks=False)
            except OSError as error:
                raise StoreIntegrityError("lock binding is unavailable") from error
            if (not _regular(after, 0o600, self.uid) or not _regular(named, 0o600, self.uid)
                    or _fingerprint(before) != _fingerprint(after)
                    or _fingerprint(after) != _fingerprint(named)):
                raise StoreIntegrityError("lock changed while acquiring")
            self._lock_identity = _fingerprint(after)
            self._verify_bindings()
            rst = fs.stat(_RECEIPTS, dir_fd=self.dfd, follow_symlinks=False)
            if not stat.S_ISDIR(rst.st_mode) or _mode(rst) != 0o700 or rst.st_uid != self.uid:
                raise StoreIntegrityError("unsafe receipts directory")
            self._verify_bindings()
            self._clean_stale_locked()
        except Exception:
            if self.lockfd is not None: fs.close(self.lockfd)
            fs.close(self.dfd); raise
    def close(self):
        if self.dfd is not None:
            try:
                if self.lockfd is not None:
                    try:
                        self._verify_bindings()
                        fcntl.flock(self.lockfd, fcntl.LOCK_UN)
                    finally: self.fs.close(self.lockfd); self.lockfd = None
            finally:
                self.fs.close(self.dfd); self.dfd = None
    def __enter__(self): return self
    def __exit__(self, *unused): self.close()
    def _verify_bindings(self):
        if self.lockfd is None or self._lock_identity is None:
            raise StoreIntegrityError("store lock is unavailable")
        _store_fence(self.root, self.fs, self.uid, self.dfd, self._root_identity,
                     self.lockfd, self._lock_identity)
    def _active_bytes(self):
        self._verify_bindings()
        try:
            try:
                return _read_checked(self.fs, self.dfd, _ACTIVE, 0o600, self.uid, 33 * 1024 * 1024)
            except FileNotFoundError:
                return None
        finally:
            self._verify_bindings()
    def _clean_stale_locked(self):
        _clean_active_temps_locked(self.fs, self.dfd, self.uid, self._verify_bindings)
        self._recover_receipt_temps_locked()
        _fsync_directory_locked(self.fs, self.dfd, self._verify_bindings)
    def load_active(self):
        value = self._active_bytes()
        if value is None: return None
        record = outbox.parse_canonical_bytes(value)
        return Snapshot(record, _sha(value), outbox.resume_action(record).value)
    def _temp_name(self, value):
        self._counter += 1
        seed = (str(self._counter) + _sha(value)).encode()
        return ".active.tmp." + hashlib.sha256(seed).hexdigest()[:32]
    def _commit_bytes(self, value):
        before = self._active_bytes(); before_sha = None if before is None else _sha(before)
        name = self._temp_name(value); fd = None; renamed = False; replace_attempted = False
        try:
            fd = self.fs.open(name, self.fs.O_WRONLY | self.fs.O_CREAT | self.fs.O_EXCL | getattr(self.fs, "O_CLOEXEC", 0) | getattr(self.fs, "O_NOFOLLOW", 0), 0o600, dir_fd=self.dfd)
            self._verify_bindings()
            _write_all(self.fs, fd, value); self.fs.fsync(fd)
            written = self.fs.fstat(fd)
            if not _regular(written, 0o600, self.uid) or written.st_size != len(value):
                raise StoreIntegrityError("unsafe active temporary")
            self.fs.close(fd); fd = None
            exact = _read_checked(self.fs, self.dfd, name, 0o600, self.uid, 33 * 1024 * 1024)
            self._verify_bindings()
            if exact != value: raise StoreIntegrityError("temporary record changed")
            self._verify_bindings()
            replace_attempted = True
            self.fs.replace(name, _ACTIVE, src_dir_fd=self.dfd, dst_dir_fd=self.dfd)
            renamed = True
            self._verify_bindings()
            _fsync_directory_locked(self.fs, self.dfd, self._verify_bindings)
            if self._active_bytes() != value: raise StoreIntegrityError("commit verification failed")
        except Exception as error:
            if fd is not None: self.fs.close(fd)
            if renamed or replace_attempted:
                try:
                    after = self._active_bytes()
                    after_sha = None if after is None else _sha(after)
                except Exception:
                    after_sha = None
                raise StoreCommitUncertain("commit outcome is uncertain", before_sha, after_sha) from error
            self._verify_bindings()
            try:
                self.fs.unlink(name, dir_fd=self.dfd)
                self._verify_bindings()
            except FileNotFoundError: pass
            raise
    def recover_commit(self, *, expected_before, expected_after):
        current = self._active_bytes()
        if current == expected_after:
            _fsync_directory_locked(self.fs, self.dfd, self._verify_bindings)
            return RecoveryResult.APPLIED
        if current == expected_before: return RecoveryResult.NOT_APPLIED
        return RecoveryResult.DIVERGED
    def _save(self, record): self._commit_bytes(outbox.canonical_bytes(record)); return self.load_active()
    def ensure(self, record):
        outbox.canonical_bytes(record)
        receipt = self._read_receipt(record.outbox_id)
        if receipt:
            return receipt
        active = self.load_active()
        if active is None: return self._save(record)
        if active.record.outbox_id == record.outbox_id: return active
        action = outbox.resume_action(active.record)
        if action in (outbox.ResumeAction.COMPLETE, outbox.ResumeAction.TERMINAL_CONFLICT): self.finalize(); return self.ensure(record)
        raise PendingTransaction("a different outbox record is active")
    def _transition(self, func, *args, **kwargs):
        active = self.load_active()
        if active is None: raise StoreIntegrityError("no active record")
        return self._save(func(active.record, *args, **kwargs))
    def prepare(self, **oids): return self._transition(outbox.prepare_publication, **oids)
    def begin_publication(self): return self._transition(outbox.begin_publication)
    def mark_publication_published(self): return self._transition(outbox.mark_publication_published)
    def mark_publication_conflict(self): return self._transition(outbox.mark_publication_conflict)
    def confirm_existing_publication(self, **oids): return self._transition(outbox.confirm_existing_publication, **oids)
    def begin_delivery(self, channel): return self._transition(outbox.begin_delivery, channel)
    def confirm_delivery_sent(self): return self._transition(outbox.confirm_delivery_sent)
    def mark_dedupe_applied(self, handles): return self._transition(outbox.mark_dedupe_applied, applied_handles=handles)
    def _receipt_name(self, outbox_id):
        if not re.fullmatch(r"rdo1-[0-9a-f]{64}", outbox_id): raise StoreIntegrityError("invalid outbox id")
        return outbox_id[5:] + ".json"
    def _receipt_temp_name(self, outbox_id):
        self._receipt_name(outbox_id)
        return ".receipt.tmp." + outbox_id[5:]
    def _receipts_fd(self):
        self._verify_bindings()
        fd = self.fs.open(_RECEIPTS, self.fs.O_RDONLY | getattr(self.fs, "O_DIRECTORY", 0) |
                          getattr(self.fs, "O_CLOEXEC", 0) | getattr(self.fs, "O_NOFOLLOW", 0), dir_fd=self.dfd)
        current, named = self.fs.fstat(fd), self.fs.stat(_RECEIPTS, dir_fd=self.dfd, follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode) or _mode(current) != 0o700 or current.st_uid != self.uid or
                not stat.S_ISDIR(named.st_mode) or _mode(named) != 0o700 or named.st_uid != self.uid or
                (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino)):
            self.fs.close(fd); raise StoreIntegrityError("unsafe receipts directory")
        self._verify_bindings()
        return fd
    def _read_receipt_data_from_fd(self, rfd, outbox_id):
        return _read_checked(self.fs, rfd, self._receipt_name(outbox_id), 0o600, self.uid, 8192)
    def _recover_receipt_temps_locked(self):
        rfd = self._receipts_fd()
        try:
            self._verify_bindings()
            names = self.fs.listdir(rfd)
            self._verify_bindings()
            targets = []
            for name in names:
                if name.startswith(".receipt.tmp."):
                    match = _RECEIPT_TMP.fullmatch(name)
                    if not match:
                        raise StoreIntegrityError("unsafe stale receipt temporary name")
                    targets.append((name, match))
            for name, match in targets:
                temp_data = _read_checked(self.fs, rfd, name, 0o600, self.uid, 8192)
                self._verify_bindings()
                receipt = _parse_receipt_bytes(temp_data)
                if receipt.outbox_id[5:] != match.group(1):
                    raise StoreIntegrityError("stale receipt temporary mismatch")
                final_name = self._receipt_name(receipt.outbox_id)
                try:
                    final_data = _read_checked(self.fs, rfd, final_name, 0o600, self.uid, 8192)
                except FileNotFoundError:
                    self._verify_bindings()
                    try:
                        self.fs.replace(name, final_name, src_dir_fd=rfd, dst_dir_fd=rfd)
                        self._verify_bindings()
                        _fsync_directory_locked(self.fs, rfd, self._verify_bindings)
                        if _read_checked(self.fs, rfd, final_name, 0o600, self.uid, 8192) != temp_data:
                            raise StoreIntegrityError("receipt recovery verification failed")
                        self._verify_bindings()
                    except Exception as error:
                        after = None
                        try: after = _read_checked(self.fs, rfd, final_name, 0o600, self.uid, 8192)
                        except Exception: pass
                        raise StoreCommitUncertain("receipt recovery outcome is uncertain", None,
                                                   None if after is None else _sha(after)) from error
                else:
                    self._verify_bindings()
                    if final_data != temp_data:
                        raise StoreIntegrityError("stale receipt conflicts with final receipt")
                    self._verify_bindings()
                    self.fs.unlink(name, dir_fd=rfd)
                    self._verify_bindings()
                    _fsync_directory_locked(self.fs, rfd, self._verify_bindings)
        finally:
            self.fs.close(rfd)
    def _read_receipt(self, outbox_id):
        rfd = self._receipts_fd()
        try:
            try: data = self._read_receipt_data_from_fd(rfd, outbox_id)
            except FileNotFoundError: return None
        finally: self.fs.close(rfd)
        return _parse_receipt_bytes(data, outbox_id)
    def finalize(self):
        active = self.load_active()
        if active is None: return None
        action = outbox.resume_action(active.record)
        if action not in (outbox.ResumeAction.COMPLETE, outbox.ResumeAction.TERMINAL_CONFLICT): raise PendingTransaction("record is not terminal")
        outcome = "complete" if action is outbox.ResumeAction.COMPLETE else "terminal_conflict"
        payload = _receipt_bytes(active.record, active.record_sha256, outcome)
        receipt = _parse_receipt_bytes(payload, active.record.outbox_id)
        rfd = self._receipts_fd()
        renamed = False
        try:
            name = self._receipt_name(active.record.outbox_id)
            temp = self._receipt_temp_name(active.record.outbox_id)
            try:
                existing_data = self._read_receipt_data_from_fd(rfd, active.record.outbox_id)
            except FileNotFoundError:
                existing_data = None
            if existing_data is not None:
                _parse_receipt_bytes(existing_data, active.record.outbox_id)
                if existing_data != payload: raise StoreIntegrityError("receipt conflicts with active record")
            else:
                try:
                    temp_data = _read_checked(self.fs, rfd, temp, 0o600, self.uid, 8192)
                except FileNotFoundError:
                    fd = self.fs.open(temp, self.fs.O_WRONLY | self.fs.O_CREAT | self.fs.O_EXCL |
                                      getattr(self.fs, "O_CLOEXEC", 0) | getattr(self.fs, "O_NOFOLLOW", 0),
                                      0o600, dir_fd=rfd)
                    try:
                        self._verify_bindings()
                        _write_all(self.fs, fd, payload); self.fs.fsync(fd)
                        written = self.fs.fstat(fd)
                        if not _regular(written, 0o600, self.uid) or written.st_size != len(payload):
                            raise StoreIntegrityError("unsafe receipt temporary")
                    finally: self.fs.close(fd)
                    temp_data = _read_checked(self.fs, rfd, temp, 0o600, self.uid, 8192)
                self._verify_bindings()
                if temp_data != payload:
                    raise StoreIntegrityError("receipt temporary conflicts with active record")
                self._verify_bindings()
                try:
                    self.fs.replace(temp, name, src_dir_fd=rfd, dst_dir_fd=rfd)
                    renamed = True
                    self._verify_bindings()
                    _fsync_directory_locked(self.fs, rfd, self._verify_bindings)
                    if self._read_receipt_data_from_fd(rfd, active.record.outbox_id) != payload:
                        raise StoreIntegrityError("receipt commit verification failed")
                except Exception as error:
                    after = None
                    try: after = self._read_receipt_data_from_fd(rfd, active.record.outbox_id)
                    except Exception: pass
                    raise StoreCommitUncertain("receipt commit outcome is uncertain", None,
                                               None if after is None else _sha(after)) from error
        finally:
            self.fs.close(rfd)
        self._verify_bindings()
        try:
            self.fs.unlink(_ACTIVE, dir_fd=self.dfd)
            self._verify_bindings()
            _fsync_directory_locked(self.fs, self.dfd, self._verify_bindings)
        except Exception as error:
            try:
                after = self._active_bytes()
                after_sha = None if after is None else _sha(after)
            except Exception:
                after_sha = None
            raise StoreCommitUncertain("active cleanup outcome is uncertain",
                                       active.record_sha256, after_sha) from error
        return receipt


def open_transaction(root, *, fs=os, uid=None, clock=None, nonblocking=True): return OutboxTransaction(root, fs=fs, uid=uid, clock=clock, nonblocking=nonblocking)


def _response(value):
    if (not isinstance(value, dict) or type(value.get("status")) is not int
            or not isinstance(value.get("body", {}), dict)):
        raise TransportFailure("transport response is not structured")
    return value["status"], value.get("body", {})
def _call(transport, method, path, body=None): return _response(transport.request(method, path, body))
def _pre_cas_call(transport, method, path, body=None):
    try: return _call(transport, method, path, body)
    except (KeyboardInterrupt, MemoryError, SystemExit): raise
    except Exception as error: raise TransportFailure("pre-CAS transport failed") from error
def _oid(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value): raise TransportFailure("invalid remote object id")
    return value


def _decode_blob(body):
    if not isinstance(body, dict) or body.get("encoding", "base64") != "base64":
        raise TransportFailure("invalid blob response")
    content = body.get("content")
    if not isinstance(content, str): raise TransportFailure("invalid blob response")
    try: return base64.b64decode("".join(content.split()).encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as error: raise TransportFailure("invalid blob response") from error


def _tree_entries(body):
    if isinstance(body, dict) and body.get("truncated", False) is not False:
        raise TransportFailure("truncated tree response")
    entries = body.get("tree") if isinstance(body, dict) else None
    if not isinstance(entries, list): raise TransportFailure("invalid tree response")
    return entries


def _target_entries(body, path):
    return [entry for entry in _tree_entries(body)
            if isinstance(entry, dict) and entry.get("path") == path]


def _github_evidence(record, transport, ancestry):
    """Return published, not_published, or unknown from authoritative reads."""
    target = record.intent.target
    prefix = "/repos/" + target.repository + "/git"
    try:
        status, ref = _call(transport, "GET", prefix + "/ref/" + target.ref[5:])
        if not 200 <= status < 300: return "unknown"
        tip = _oid(ref.get("object", {}).get("sha"))
        descendant = ancestry(record.publication.remote_commit, tip)
        if type(descendant) is not bool: return "unknown"
        if not descendant:
            # A 409/422 is a deterministic path conflict only when the
            # authoritative ref has actually moved away from our prepared base.
            return "unknown" if tip == record.publication.remote_base else "not_published"
        status, commit = _call(transport, "GET", prefix + "/commits/" + tip)
        if not 200 <= status < 300: return "unknown"
        tree_oid = _oid(commit.get("tree", {}).get("sha"))
        status, tree = _call(transport, "GET", prefix + "/trees/" + tree_oid + "?recursive=1")
        if not 200 <= status < 300: return "unknown"
        matches = _target_entries(tree, target.path)
        # Once the candidate is an ancestor, an absent or overwritten current
        # path cannot prove that the candidate CAS itself failed.
        if len(matches) != 1: return "unknown"
        if _oid(matches[0].get("sha")) != record.publication.remote_blob: return "unknown"
        status, blob = _call(transport, "GET", prefix + "/blobs/" + record.publication.remote_blob)
        if not 200 <= status < 300: return "unknown"
        return "published" if _decode_blob(blob) == record.intent.image else "unknown"
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except Exception:
        return "unknown"


def publish_github(transaction, transport, *, ancestry, policy):
    """Perform exactly one force=false CAS; only a durable candidate may reach PATCH."""
    snap = transaction.load_active()
    if snap is None: raise StoreIntegrityError("no active record")
    record, target = snap.record, snap.record.intent.target
    outbox.canonical_bytes(record)
    if not isinstance(policy, GithubPolicy) or not policy.allows(target): raise TransportFailure("target is outside GithubPolicy")
    prefix = "/repos/" + target.repository + "/git"
    if record.publication.outcome is outbox.CasOutcome.UNKNOWN:
        return reconcile_github(transaction, transport, ancestry=ancestry, policy=policy)
    if record.publication.outcome is not outbox.CasOutcome.NOT_SENT: return snap
    if record.publication.remote_base is None:
        for _ in range(3):
            status, ref = _pre_cas_call(transport, "GET", prefix + "/ref/" + target.ref[5:])
            if not 200 <= status < 300: raise TransportFailure("reference lookup failed")
            base = _oid(ref.get("object", {}).get("sha")); status, parent = _pre_cas_call(transport, "GET", prefix + "/commits/" + base)
            if not 200 <= status < 300: raise TransportFailure("base commit lookup failed")
            base_tree = _oid(parent.get("tree", {}).get("sha")); status, listing = _pre_cas_call(transport, "GET", prefix + "/trees/" + base_tree + "?recursive=1")
            if not 200 <= status < 300: raise TransportFailure("tree lookup failed")
            matches = _target_entries(listing, target.path)
            if len(matches) > 1: raise TransportFailure("ambiguous target path")
            if matches:
                old_blob = _oid(matches[0].get("sha")); status, old = _pre_cas_call(transport, "GET", prefix + "/blobs/" + old_blob)
                if not 200 <= status < 300: raise TransportFailure("existing blob lookup failed")
                same = _decode_blob(old) == record.intent.image
                if same: return transaction.confirm_existing_publication(remote_base=base, remote_blob=old_blob, remote_commit=base)
            status, made_blob = _pre_cas_call(transport, "POST", prefix + "/blobs", {"content": base64.b64encode(record.intent.image).decode("ascii"), "encoding": "base64"})
            if not 200 <= status < 300: raise TransportFailure("blob creation failed before CAS")
            blob_oid = _oid(made_blob.get("sha")); status, made_tree = _pre_cas_call(transport, "POST", prefix + "/trees", {"base_tree": base_tree, "tree": [{"path": target.path, "mode": "100644", "type": "blob", "sha": blob_oid}]})
            if not 200 <= status < 300: raise TransportFailure("tree creation failed before CAS")
            tree_oid = _oid(made_tree.get("sha")); status, made_commit = _pre_cas_call(transport, "POST", prefix + "/commits", {"message": "report delivery", "tree": tree_oid, "parents": [base]})
            if not 200 <= status < 300: raise TransportFailure("commit creation failed before CAS")
            commit_oid = _oid(made_commit.get("sha")); status, verify = _pre_cas_call(transport, "GET", prefix + "/commits/" + commit_oid)
            parents = verify.get("parents") if isinstance(verify, dict) else None
            parent_oids = [_oid(item.get("sha")) for item in parents] if isinstance(parents, list) and all(isinstance(item, dict) for item in parents) else []
            if (not 200 <= status < 300 or _oid(verify.get("tree", {}).get("sha")) != tree_oid
                    or parent_oids != [base]): raise TransportFailure("candidate commit verification failed")
            status, verify_tree = _pre_cas_call(transport, "GET", prefix + "/trees/" + tree_oid + "?recursive=1")
            matches = _target_entries(verify_tree, target.path)
            if not 200 <= status < 300 or len(matches) != 1 or _oid(matches[0].get("sha")) != blob_oid: raise TransportFailure("candidate tree verification failed")
            status, verify_blob = _pre_cas_call(transport, "GET", prefix + "/blobs/" + blob_oid)
            exact = 200 <= status < 300 and _decode_blob(verify_blob) == record.intent.image
            if not exact: raise TransportFailure("candidate blob verification failed")
            status, now = _pre_cas_call(transport, "GET", prefix + "/ref/" + target.ref[5:])
            if not 200 <= status < 300: raise TransportFailure("reference recheck failed")
            if _oid(now.get("object", {}).get("sha")) == base:
                transaction.prepare(remote_base=base, remote_blob=blob_oid, remote_commit=commit_oid)
                record = transaction.load_active().record
                break
        else: raise TransportFailure("base changed too often before durable prepare")
    transaction.begin_publication()
    try: status, ignored = _call(transport, "PATCH", prefix + "/refs/" + target.ref[5:], {"sha": record.publication.remote_commit, "force": False})
    except (KeyboardInterrupt, MemoryError, SystemExit): raise
    except Exception: return transaction.load_active()
    if status in (409, 422):
        evidence = _github_evidence(transaction.load_active().record, transport, ancestry)
        if evidence == "published": return transaction.mark_publication_published()
        if evidence == "not_published": return transaction.mark_publication_conflict()
        return transaction.load_active()
    if not 200 <= status < 300: return transaction.load_active()
    return reconcile_github(transaction, transport, ancestry=ancestry, policy=policy)


def reconcile_github(transaction, transport, *, ancestry, policy):
    snap = transaction.load_active()
    if snap is None: raise StoreIntegrityError("no active record")
    record = snap.record; target = record.intent.target
    outbox.canonical_bytes(record)
    if not isinstance(policy, GithubPolicy) or not policy.allows(target): raise TransportFailure("target is outside GithubPolicy")
    if record.publication.outcome is not outbox.CasOutcome.UNKNOWN: return snap
    evidence = _github_evidence(record, transport, ancestry)
    return transaction.mark_publication_published() if evidence == "published" else transaction.load_active()


def deliver(transaction, transport):
    snap = transaction.load_active()
    if snap is None: raise StoreIntegrityError("no active record")
    record = snap.record
    if record.delivery.outcome is outbox.DeliveryOutcome.UNKNOWN: return snap
    if record.publication.outcome is outbox.CasOutcome.PUBLISHED: channel, payload = outbox.DeliveryChannel.PRIMARY, record.intent.primary.payload
    elif outbox.fallback_eligible(record): channel, payload = outbox.DeliveryChannel.FALLBACK, record.intent.fallback.payload
    else: return snap
    expected_ack = len(record.intent.primary.handles if channel is outbox.DeliveryChannel.PRIMARY
                       else record.intent.fallback.handles)
    frozen = bytes(payload); transaction.begin_delivery(channel)
    try: response = transport.send(channel.value, frozen, idempotency_key=record.outbox_id)
    except (KeyboardInterrupt, MemoryError, SystemExit): raise
    except Exception: return transaction.load_active()
    if (isinstance(response, dict) and set(response) == {"status", "ack"}
            and type(response.get("status")) is int and 200 <= response["status"] < 300
            and type(response.get("ack")) is int and response["ack"] == expected_ack):
        return transaction.confirm_delivery_sent()
    return transaction.load_active()


def apply_dedupe(transaction, adapter):
    snap = transaction.load_active()
    if snap is None or snap.record.delivery.outcome is not outbox.DeliveryOutcome.SENT: return snap
    if snap.record.dedupe.outcome is outbox.DedupeOutcome.APPLIED: return snap
    record, handles = snap.record, outbox.dedupe_eligible_handles(snap.record)
    payload = record.intent.primary.payload if record.delivery.channel is outbox.DeliveryChannel.PRIMARY else record.intent.fallback.payload
    digest = _sha((record.delivery.channel.value + "\0" + "\0".join(handles)).encode() + b"\0" + payload)
    result = adapter.apply(record.outbox_id, digest, handles)
    if not isinstance(result, dict) or set(result) != {"outbox_id", "digest", "outcome"} or result.get("outbox_id") != record.outbox_id: raise DedupeIntegrityError("dedupe acknowledgement is not bound to outbox id")
    if result.get("digest") != digest: raise DedupeIntegrityError("same id has different delivered digest")
    if result.get("outcome") not in ("applied", "unchanged"): raise DedupeIntegrityError("dedupe acknowledgement is not explicit")
    return transaction.mark_dedupe_applied(handles)


def project(snapshot, *, error_class=None):
    if (error_class is not None
            and (not isinstance(error_class, str) or not _ERROR_CLASS.fullmatch(error_class))):
        raise ValueError("error_class is invalid")
    if isinstance(snapshot, FinalReceipt):
        return {"state": snapshot.outcome, "outbox_id": snapshot.outbox_id, "record_sha": snapshot.record_sha256,
                "resume_action": None, "publication_outcome": snapshot.publication_outcome,
                "delivery_outcome": snapshot.delivery_outcome, "dedupe_outcome": snapshot.dedupe_outcome,
                "channel": snapshot.channel, "delivered_count": snapshot.delivered_count,
                "degraded": snapshot.publication_outcome == "conflict",
                "reconcile_required": False, "error_class": error_class}
    record = snapshot.record if isinstance(snapshot, Snapshot) else snapshot
    outbox.canonical_bytes(record)
    action = outbox.resume_action(record).value
    return {"state": action, "outbox_id": record.outbox_id, "record_sha": outbox.record_sha256(record), "resume_action": action, "publication_outcome": record.publication.outcome.value, "delivery_outcome": record.delivery.outcome.value, "dedupe_outcome": record.dedupe.outcome.value, "channel": None if record.delivery.channel is None else record.delivery.channel.value, "delivered_count": len(record.delivery.delivered_handles), "degraded": record.publication.outcome is outbox.CasOutcome.CONFLICT, "reconcile_required": record.publication.outcome is outbox.CasOutcome.UNKNOWN or record.delivery.outcome is outbox.DeliveryOutcome.UNKNOWN, "error_class": error_class}


def _default_canary_policy(root):
    canonical_root = os.path.realpath(os.path.abspath(os.fspath(root)))
    allowed_temp_base = os.path.realpath(os.path.abspath(tempfile.gettempdir()))
    return CanaryPolicy(canonical_root=canonical_root, allowed_temp_base=allowed_temp_base)


def controlled_canary(root, record, *, fs=os, policy=None):
    """Run a complete synthetic-only flow; it has no caller-controlled transport."""
    if policy is None:
        try:
            policy = _default_canary_policy(root)
        except ValueError as error:
            raise AdapterError("canary root is not synthetic") from error
    if not isinstance(policy, CanaryPolicy) or not policy.allows(record.intent.target): raise AdapterError("canary target is not synthetic")
    supplied_root = os.path.abspath(os.fspath(root))
    if (supplied_root != policy.canonical_root
            or os.path.realpath(supplied_root) != policy.canonical_root):
        raise AdapterError("canary root does not match CanaryPolicy")
    try:
        fs.mkdir(root, 0o700)
    except FileExistsError as error:
        raise AdapterError("canary root must be fresh") from error
    anchor_fd = _check_root(root, fs, fs.getuid())
    anchor_identity = _root_fingerprint(fs.fstat(anchor_fd))
    a, b, c, d, e = ("a" * 40, "b" * 40, "c" * 40, "d" * 40, "e" * 40)
    class FakeGithub:
        patched = False
        def request(self, method, path, body=None):
            if method == "POST" and path.endswith("/blobs"): return {"status": 201, "body": {"sha": c}}
            if method == "POST" and path.endswith("/trees"): return {"status": 201, "body": {"sha": d}}
            if method == "POST" and path.endswith("/commits"): return {"status": 201, "body": {"sha": e}}
            if method == "PATCH": self.patched = True; return {"status": 200, "body": {}}
            if method == "GET" and "/ref/" in path: return {"status": 200, "body": {"object": {"sha": e if self.patched else a}}}
            if method == "GET" and path.endswith("/commits/" + a): return {"status": 200, "body": {"tree": {"sha": b}}}
            if method == "GET" and path.endswith("/commits/" + e): return {"status": 200, "body": {"tree": {"sha": d}, "parents": [{"sha": a}]}}
            if method == "GET" and "/trees/" in path: return {"status": 200, "body": {"tree": [] if b in path else [{"path": record.intent.target.path, "sha": c}]}}
            if method == "GET" and path.endswith("/blobs/" + c): return {"status": 200, "body": {"content": base64.b64encode(record.intent.image).decode()}}
            return {"status": 500, "body": {}}
    class FakeDelivery:
        def send(self, channel, payload, **kwargs): return {"status": 200, "ack": 1}
    class FakeDedupe:
        def apply(self, outbox_id, digest, handles): return {"outbox_id": outbox_id, "digest": digest, "outcome": "applied"}
    try:
        initialize_store(root, fs=fs)
        with open_transaction(root, fs=fs) as tx:
            tx.ensure(record); github_policy = GithubPolicy(record.intent.target.repository, record.intent.target.ref, record.intent.target.path)
            publish_github(tx, FakeGithub(), ancestry=lambda ancestor, tip: ancestor == tip, policy=github_policy)
            deliver(tx, FakeDelivery()); apply_dedupe(tx, FakeDedupe())
            result = project(tx.finalize())
        _verify_root_binding(root, fs, fs.getuid(), anchor_fd, anchor_identity,
                             allow_nlink_change=True)
        return result
    finally:
        fs.close(anchor_fd)


__all__ = ["AdapterError", "StoreIntegrityError", "StoreBusy", "PendingTransaction", "CommitUncertain", "StoreCommitUncertain", "TransportFailure", "DedupeIntegrityError", "RecoveryResult", "Snapshot", "FinalReceipt", "GithubPolicy", "CanaryPolicy", "initialize_store", "open_transaction", "OutboxTransaction", "publish_github", "reconcile_github", "deliver", "apply_dedupe", "project", "controlled_canary"]
