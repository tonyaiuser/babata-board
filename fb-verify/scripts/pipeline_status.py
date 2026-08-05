#!/usr/bin/env python3
"""Persist FB pipeline status plus immutable, release-aware attempt evidence.

``pipeline_status.json`` remains the mutable latest-status convenience view.  The
attempt ledger intentionally has different semantics: every terminal attempt is
committed once under its immutable attempt id, never replaces a prior record,
and contains only a compact allowlisted classification (never raw failures).
"""

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from state_io import atomic_write_json


ATTEMPT_LEDGER_SCHEMA_VERSION = 1
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TEMP_NAME_RE = re.compile(
    r"^\.(?P<attempt>[A-Za-z0-9][A-Za-z0-9._-]{0,127})\."
    r"(?P<pid>[1-9][0-9]*)\.(?P<nonce>[0-9]+)\.tmp$"
)
PHASES = frozenset(
    {
        "preflight",
        "build",
        "state",
        "atomic",
        "ingest",
        "merge",
        "verify",
        "images",
        "stats",
        "batch_build",
        "publish",
        "notify",
        "complete",
        "unknown",
    }
)
TERMINAL_STATES = frozenset({"failed", "partial", "succeeded", "skipped"})
LEDGER_STATES = TERMINAL_STATES
LOCAL_FAILURE_PHASES = frozenset({"build", "merge", "state", "atomic", "batch_build"})
SIGNAL_EXIT_CODES = frozenset({129, 130, 143})
ATTEMPT_SIGNATURES = frozenset(
    {
        "succeeded",
        "skipped_idempotent",
        "recoverable_interrupted",
        "recoverable_incomplete",
        *(f"local_{item}_error" for item in LOCAL_FAILURE_PHASES),
        *(f"recoverable_{item}_error" for item in PHASES),
    }
)
LEDGER_FIELDS = frozenset(
    {
        "schema_version",
        "attempt_id",
        "run_id",
        "release_id",
        "phase",
        "state",
        "exit_code",
        "signature",
        "started_at",
        "finished_at",
        "pause_recommended",
    }
)


class AttemptLedgerError(RuntimeError):
    """Raised when immutable attempt evidence cannot be safely committed/read."""


class AttemptLedgerCollision(AttemptLedgerError):
    """Raised when an immutable attempt id already has a final record."""


class AttemptLedgerBusy(AttemptLedgerError):
    """Raised when a verified writer still owns any staging transaction."""


def as_bool(value):
    return str(value).strip().lower() in {"1", "true", "yes"}


def _require_token(value, field):
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise AttemptLedgerError(f"invalid {field}")
    return value


def _parse_timestamp(value, field):
    if not isinstance(value, str) or len(value) > 64:
        raise AttemptLedgerError(f"invalid {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttemptLedgerError(f"invalid {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AttemptLedgerError(f"invalid {field}")
    return parsed


def _require_nonnegative_count(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AttemptLedgerError(f"invalid {field}")
    return value


def _require_bool(value, field):
    if not isinstance(value, bool):
        raise AttemptLedgerError(f"invalid {field}")
    return value


def _fsync_directory(directory_fd):
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise AttemptLedgerError("cannot fsync attempt ledger directory") from exc


def _close_fd(descriptor):
    """Close one descriptor; callers decide whether close affects semantics."""
    os.close(descriptor)


def _close_best_effort(descriptor):
    if descriptor is None:
        return
    try:
        _close_fd(descriptor)
    except OSError:
        # close(2) error semantics vary by platform.  In this single-threaded
        # helper, an immediately fstat-able descriptor is still ours and may
        # be retried once; EBADF means the original close already consumed it.
        try:
            os.fstat(descriptor)
        except OSError:
            return
        try:
            _close_fd(descriptor)
        except OSError:
            pass


def _validate_private_regular(metadata, *, links, size=None, field="record"):
    if not stat.S_ISREG(metadata.st_mode):
        raise AttemptLedgerError(f"{field} is not a regular file")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AttemptLedgerError(f"{field} ownership or mode is unsafe")
    if metadata.st_nlink != links:
        raise AttemptLedgerError(f"{field} link count is unsafe")
    if size is not None and metadata.st_size != size:
        raise AttemptLedgerError(f"{field} size changed")
    return metadata


def _open_private_ledger_directory(value):
    directory = Path(value)
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = directory.lstat()
    except OSError as exc:
        raise AttemptLedgerError("cannot create attempt ledger directory") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AttemptLedgerError("attempt ledger directory is not a real directory")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise AttemptLedgerError("attempt ledger directory ownership or mode is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(directory), flags)
    except OSError as exc:
        raise AttemptLedgerError("cannot open attempt ledger directory") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            raise AttemptLedgerError("attempt ledger directory changed while opening")
    except AttemptLedgerError:
        _close_best_effort(descriptor)
        raise
    except OSError as exc:
        _close_best_effort(descriptor)
        raise AttemptLedgerError("cannot validate attempt ledger directory") from exc
    return directory, descriptor


def classify_attempt(
    *, phase, exit_code, publish_ok, terminated_early, truncated, pending, failed,
    skipped=False, body_complete=False,
):
    """Return a low-cardinality terminal classification without raw errors."""
    if phase not in PHASES:
        raise AttemptLedgerError("invalid phase")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise AttemptLedgerError("invalid exit_code")
    _require_bool(publish_ok, "publish_ok")
    _require_bool(terminated_early, "terminated_early")
    _require_bool(skipped, "skipped")
    _require_bool(body_complete, "body_complete")
    _require_nonnegative_count(truncated, "truncated")
    _require_nonnegative_count(pending, "pending")
    _require_nonnegative_count(failed, "failed")
    status = evaluate_status(
        exit_code=exit_code,
        publish_ok=publish_ok,
        terminated_early=terminated_early,
        truncated=truncated,
        pending=pending,
        failed=failed,
        skipped=skipped,
        body_complete=body_complete,
    )["state"]
    signature, pause_recommended = _expected_attempt_semantics(
        phase=phase, state=status, exit_code=exit_code
    )
    return status, signature, pause_recommended


def _expected_attempt_semantics(*, phase, state, exit_code):
    """Canonical state/exit/phase -> signature contract used by the producer."""
    if phase not in PHASES or state not in LEDGER_STATES:
        raise AttemptLedgerError("invalid attempt semantics")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise AttemptLedgerError("invalid attempt exit semantics")
    if state == "succeeded":
        if exit_code != 0:
            raise AttemptLedgerError("succeeded attempt must exit zero")
        return "succeeded", False
    if state == "skipped":
        if exit_code != 0:
            raise AttemptLedgerError("skipped attempt must exit zero")
        return "skipped_idempotent", False
    if state == "partial":
        if exit_code != 0:
            raise AttemptLedgerError("partial attempt must exit zero")
        return "recoverable_incomplete", False
    if exit_code == 0:
        raise AttemptLedgerError("failed attempt must exit nonzero")
    if exit_code in SIGNAL_EXIT_CODES:
        return "recoverable_interrupted", False
    if phase in LOCAL_FAILURE_PHASES:
        return f"local_{phase}_error", True
    return f"recoverable_{phase}_error", False


def make_attempt_record(
    *, attempt_id, run_id, release_id, phase, exit_code, publish_ok,
    terminated_early, truncated, pending, failed, skipped=False,
    body_complete=False, started_at, finished_at=None,
):
    """Build and validate a compact immutable terminal-attempt record."""
    attempt_id = _require_token(attempt_id, "attempt_id")
    run_id = _require_token(run_id, "run_id")
    release_id = _require_token(release_id, "release_id")
    if attempt_id != run_id:
        raise AttemptLedgerError("attempt_id and run_id must match")
    started = _parse_timestamp(started_at, "started_at")
    if finished_at is None:
        finished = datetime.now(timezone.utc)
    else:
        finished = _parse_timestamp(finished_at, "finished_at")
    if finished < started:
        raise AttemptLedgerError("finished_at predates started_at")
    state, signature, pause_recommended = classify_attempt(
        phase=phase,
        exit_code=exit_code,
        publish_ok=publish_ok,
        terminated_early=terminated_early,
        truncated=truncated,
        pending=pending,
        failed=failed,
        skipped=skipped,
        body_complete=body_complete,
    )
    _require_token(signature, "signature")
    record = {
        "schema_version": ATTEMPT_LEDGER_SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "run_id": run_id,
        "release_id": release_id,
        "phase": phase,
        "state": state,
        "exit_code": exit_code,
        "signature": signature,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "pause_recommended": pause_recommended,
    }
    validate_attempt_record(record)
    return record


def validate_attempt_record(record):
    """Strict reader/writer validation; unknown fields could contain secrets."""
    if not isinstance(record, dict) or frozenset(record) != LEDGER_FIELDS:
        raise AttemptLedgerError("invalid attempt ledger schema")
    if isinstance(record.get("schema_version"), bool) or \
       record.get("schema_version") != ATTEMPT_LEDGER_SCHEMA_VERSION:
        raise AttemptLedgerError("unsupported attempt ledger schema")
    attempt_id = _require_token(record.get("attempt_id"), "attempt_id")
    run_id = _require_token(record.get("run_id"), "run_id")
    if attempt_id != run_id:
        raise AttemptLedgerError("attempt_id and run_id must match")
    _require_token(record.get("release_id"), "release_id")
    phase = record.get("phase")
    if phase not in PHASES:
        raise AttemptLedgerError("invalid phase")
    state = record.get("state")
    if state not in LEDGER_STATES:
        raise AttemptLedgerError("invalid state")
    exit_code = record.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise AttemptLedgerError("invalid exit_code")
    signature = _require_token(record.get("signature"), "signature")
    if signature not in ATTEMPT_SIGNATURES:
        raise AttemptLedgerError("invalid signature")
    started = _parse_timestamp(record.get("started_at"), "started_at")
    finished = _parse_timestamp(record.get("finished_at"), "finished_at")
    if finished < started:
        raise AttemptLedgerError("finished_at predates started_at")
    if not isinstance(record.get("pause_recommended"), bool):
        raise AttemptLedgerError("invalid pause_recommended")
    expected_signature, expected_pause = _expected_attempt_semantics(
        phase=phase, state=state, exit_code=exit_code
    )
    if signature != expected_signature or record["pause_recommended"] is not expected_pause:
        raise AttemptLedgerError("attempt semantic tuple is inconsistent")
    return record


def write_attempt_ledger(ledger_dir, record):
    """Commit exactly one immutable record with explicit durability phases.

    Before the first directory fsync, any linked final is rolled back.  If that
    rollback cannot be proven durable, the locked staging name is deliberately
    retained; after this function closes its fd, strict readers classify that
    unlocked staging artifact as uncertain and reject the whole ledger.  Once
    the first directory fsync and final identity check have completed, the
    final record is durable.  Later staging cleanup errors are therefore
    non-fatal and must never turn a successful commit into a reported failure.
    """
    record = validate_attempt_record(record)
    directory, directory_fd = _open_private_ledger_directory(ledger_dir)
    attempt_name = record["attempt_id"] + ".json"
    temporary_name = f".{record['attempt_id']}.{os.getpid()}.{time.time_ns()}.tmp"
    temporary_fd = None
    temporary_exists = False
    linked = False
    uncertain_link_result = False
    durable = False
    rollback_proven = False
    payload = (
        json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    try:
        try:
            existing = os.stat(attempt_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            raise AttemptLedgerCollision("attempt ledger collision")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        temporary_exists = True
        fcntl.flock(temporary_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fchmod(temporary_fd, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(temporary_fd, payload[offset:])
            if written <= 0:
                raise AttemptLedgerError("attempt ledger staging write failed")
            offset += written
        os.fsync(temporary_fd)
        temporary_meta = _validate_private_regular(
            os.fstat(temporary_fd), links=1, size=len(payload), field="staging fd"
        )
        named_meta = _validate_private_regular(
            os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False),
            links=1,
            size=len(payload),
            field="staging name",
        )
        if (
            named_meta.st_dev != temporary_meta.st_dev
            or named_meta.st_ino != temporary_meta.st_ino
            or named_meta.st_dev != os.fstat(directory_fd).st_dev
        ):
            raise AttemptLedgerError("attempt ledger staging identity changed")
        try:
            os.link(
                temporary_name,
                attempt_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            linked = True
        except OSError as exc:
            # link(2) errors are not assumed to mean "nothing happened".  If
            # the final now aliases our still-open staging inode, enter the
            # post-link rollback path.  If the probe itself is inconclusive,
            # retain staging as a fail-closed uncertainty marker rather than
            # risk exposing an apparently committed final after API failure.
            final_observed = False
            try:
                maybe_final = os.stat(
                    attempt_name, dir_fd=directory_fd, follow_symlinks=False
                )
                final_observed = True
                current_temp = os.fstat(temporary_fd)
                linked = (
                    stat.S_ISREG(maybe_final.st_mode)
                    and (maybe_final.st_dev, maybe_final.st_ino)
                    == (current_temp.st_dev, current_temp.st_ino)
                )
            except FileNotFoundError:
                linked = False
            except OSError:
                uncertain_link_result = True
            if not linked and not uncertain_link_result and final_observed:
                # A different final won the no-replace race.  It is not ours
                # to unlink; this is a normal immutable-id collision.
                if isinstance(exc, FileExistsError):
                    raise AttemptLedgerCollision("attempt ledger collision") from exc
                uncertain_link_result = True
            if not linked:
                if uncertain_link_result:
                    raise AttemptLedgerError("attempt ledger link result is uncertain") from exc
                if isinstance(exc, FileExistsError):
                    raise AttemptLedgerCollision("attempt ledger collision") from exc
                raise AttemptLedgerError("attempt ledger link failed before commit") from exc
            raise AttemptLedgerError("attempt ledger link result is uncertain") from exc

        try:
            _fsync_directory(directory_fd)
            current_fd = _validate_private_regular(
                os.fstat(temporary_fd), links=2, size=len(payload), field="linked staging fd"
            )
            current_temp = _validate_private_regular(
                os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False),
                links=2,
                size=len(payload),
                field="linked staging name",
            )
            final_meta = _validate_private_regular(
                os.stat(attempt_name, dir_fd=directory_fd, follow_symlinks=False),
                links=2,
                size=len(payload),
                field="linked final name",
            )
            expected_identity = (current_fd.st_dev, current_fd.st_ino)
            if (
                (current_temp.st_dev, current_temp.st_ino) != expected_identity
                or (final_meta.st_dev, final_meta.st_ino) != expected_identity
            ):
                raise AttemptLedgerError("attempt ledger linked names changed identity")
        except (OSError, AttemptLedgerError) as exc:
            raise AttemptLedgerError("attempt ledger commit was not proven durable") from exc
        durable = True

        # From here on, cleanup can affect only the staging alias.  The first
        # directory fsync already made the validated final link durable.
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
            temporary_exists = False
        except OSError:
            try:
                os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                temporary_exists = False
            except OSError:
                temporary_exists = True
        if not temporary_exists:
            try:
                _fsync_directory(directory_fd)
            except AttemptLedgerError:
                pass
            try:
                cleaned_final = _validate_private_regular(
                    os.stat(attempt_name, dir_fd=directory_fd, follow_symlinks=False),
                    links=1,
                    size=len(payload),
                    field="durable final name",
                )
                if (cleaned_final.st_dev, cleaned_final.st_ino) != (
                    temporary_meta.st_dev,
                    temporary_meta.st_ino,
                ):
                    # The durable record existed when commit completed.  A
                    # later same-user mutation is left for strict readers; do
                    # not misreport the already-completed commit as a failure.
                    pass
            except (OSError, AttemptLedgerError):
                pass
        return directory / attempt_name
    except FileExistsError as exc:
        raise AttemptLedgerCollision("attempt ledger collision") from exc
    except AttemptLedgerCollision:
        raise
    except AttemptLedgerError:
        raise
    except OSError as exc:
        raise AttemptLedgerError("attempt ledger atomic commit failed") from exc
    finally:
        if linked and not durable:
            rollback_fsync_ok = False
            try:
                os.unlink(attempt_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            try:
                _fsync_directory(directory_fd)
                rollback_fsync_ok = True
            except AttemptLedgerError:
                pass
            try:
                os.stat(attempt_name, dir_fd=directory_fd, follow_symlinks=False)
                final_absent = False
            except FileNotFoundError:
                final_absent = True
            except OSError:
                final_absent = False
            rollback_proven = rollback_fsync_ok and final_absent
            if rollback_proven:
                linked = False
        # A pre-link failure or proven rollback may remove staging.  An
        # unproven rollback deliberately retains it as an unlocked, detectable
        # uncertain artifact once the fd is closed.
        if temporary_exists and not durable and not uncertain_link_result and \
           (not linked or rollback_proven):
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
                temporary_exists = False
                try:
                    _fsync_directory(directory_fd)
                except AttemptLedgerError:
                    pass
            except OSError:
                pass
        _close_best_effort(temporary_fd)
        _close_best_effort(directory_fd)


def _strict_json_object(raw):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AttemptLedgerError("attempt ledger contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise AttemptLedgerError("attempt ledger JSON is malformed") from exc


def _read_final_attempt(directory_fd, name):
    attempt_id = name[:-5]
    _require_token(attempt_id, "ledger filename attempt_id")
    descriptor = None
    try:
        before = _validate_private_regular(
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
            links=1,
            field="attempt ledger final",
        )
        if before.st_size <= 0 or before.st_size > 8192:
            raise AttemptLedgerError("attempt ledger final size is unsafe")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        opened = _validate_private_regular(
            os.fstat(descriptor), links=1, size=before.st_size, field="attempt ledger final fd"
        )
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AttemptLedgerError("attempt ledger final changed while opening")
        raw = b""
        while len(raw) <= 8192:
            chunk = os.read(descriptor, min(4096, 8193 - len(raw)))
            if not chunk:
                break
            raw += chunk
        if not raw or len(raw) > 8192:
            raise AttemptLedgerError("attempt ledger final size is unsafe")
    except OSError as exc:
        raise AttemptLedgerError("cannot read attempt ledger final") from exc
    finally:
        _close_best_effort(descriptor)
    record = validate_attempt_record(_strict_json_object(raw))
    if record["attempt_id"] != attempt_id:
        raise AttemptLedgerError("attempt ledger filename does not match record")
    return record


def _staging_is_active(directory_fd, name, final_names):
    match = TEMP_NAME_RE.fullmatch(name)
    if not match:
        raise AttemptLedgerError("unexpected attempt ledger entry")
    descriptor = None
    try:
        before = _validate_private_regular(
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
            links=1,
            field="attempt ledger staging",
        )
        if match.group("attempt") + ".json" in final_names:
            raise AttemptLedgerError("attempt ledger staging aliases a final attempt")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        opened = _validate_private_regular(
            os.fstat(descriptor), links=1, size=before.st_size, field="attempt ledger staging fd"
        )
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AttemptLedgerError("attempt ledger staging changed while opening")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        raise AttemptLedgerError("stale or uncertain attempt ledger staging exists")
    except OSError as exc:
        raise AttemptLedgerError("cannot validate attempt ledger staging") from exc
    finally:
        _close_best_effort(descriptor)


def inspect_attempt_ledger(ledger_dir):
    """Return a strict snapshot without exposing an old prefix while busy."""
    directory, directory_fd = _open_private_ledger_directory(ledger_dir)
    try:
        names = sorted(os.listdir(directory_fd))
        if len(names) > 5000:
            raise AttemptLedgerError("attempt ledger contains too many entries")
        final_names = {name for name in names if name.endswith(".json") and not name.startswith(".")}
        records = []
        active_staging = False
        for name in names:
            if name in final_names:
                records.append(_read_final_attempt(directory_fd, name))
            elif name.startswith(".") and name.endswith(".tmp"):
                active_staging = (
                    _staging_is_active(directory_fd, name, final_names)
                    or active_staging
                )
            else:
                raise AttemptLedgerError("unexpected attempt ledger entry")
        if active_staging:
            return {"available": False, "busy": True, "records": []}
        return {"available": True, "busy": False, "records": records}
    except OSError as exc:
        raise AttemptLedgerError("cannot enumerate attempt ledger") from exc
    finally:
        _close_best_effort(directory_fd)


def read_attempt_ledger(ledger_dir):
    """Read all records, or fail distinctly while a transaction is active."""
    snapshot = inspect_attempt_ledger(ledger_dir)
    if snapshot["busy"]:
        raise AttemptLedgerBusy("attempt ledger has an active staging transaction")
    return snapshot["records"]


def has_exact_success_record(ledger_dir, attempt_id, release_id):
    attempt_id = _require_token(attempt_id, "attempt_id")
    release_id = _require_token(release_id, "release_id")
    records = read_attempt_ledger(ledger_dir)
    matching = [record for record in records if record["attempt_id"] == attempt_id]
    if len(matching) != 1:
        return False
    record = matching[0]
    return (
        record["release_id"] == release_id
        and record["state"] == "succeeded"
        and record["exit_code"] == 0
        and record["signature"] == "succeeded"
        and record["pause_recommended"] is False
    )


def evaluate_status(
    *, exit_code, publish_ok, terminated_early, truncated, pending, failed,
    skipped=False, in_progress=False, body_complete=True
):
    gates = {
        "body_complete": bool(body_complete),
        "exit_zero": exit_code == 0,
        "publish_ok": bool(publish_ok),
        "not_terminated_early": not bool(terminated_early),
        "truncated_zero": truncated == 0,
        "pending_zero": pending == 0,
        "failed_zero": failed == 0,
    }
    stamp_eligible = all(gates.values()) and not skipped and not in_progress
    if in_progress:
        state = "in_progress"
    elif exit_code != 0:
        state = "failed"
    elif skipped:
        state = "skipped"
    elif stamp_eligible:
        state = "succeeded"
    else:
        state = "partial"
    return {
        "state": state,
        "stamp_eligible": stamp_eligible,
        "gates": gates,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out")
    parser.add_argument("--date")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("--publish-ok", default="0")
    parser.add_argument("--terminated-early", default="0")
    parser.add_argument("--truncated", type=int, default=0)
    parser.add_argument("--pending", type=int, default=0)
    parser.add_argument("--failed", type=int, default=0)
    parser.add_argument("--skipped", default="0")
    parser.add_argument("--in-progress", default="0")
    parser.add_argument("--body-complete", default="0")
    parser.add_argument("--write-attempt-ledger", action="store_true")
    parser.add_argument("--check-success-ledger", action="store_true")
    parser.add_argument("--ledger-dir")
    parser.add_argument("--attempt-id", default="")
    parser.add_argument("--release-id", default="")
    parser.add_argument("--phase", default="unknown")
    parser.add_argument("--started-at", default="")
    parser.add_argument("--finished-at", default="")
    args = parser.parse_args(argv)
    if args.write_attempt_ledger and args.check_success_ledger:
        parser.error("ledger write and success check modes are mutually exclusive")
    if args.check_success_ledger:
        if args.out or args.date or args.exit_code is not None:
            parser.error("--out/--date/--exit-code are invalid with --check-success-ledger")
        if not args.ledger_dir or not args.attempt_id or not args.release_id:
            parser.error("success ledger check requires --ledger-dir, --attempt-id and --release-id")
        try:
            matched = has_exact_success_record(
                args.ledger_dir, args.attempt_id, args.release_id
            )
        except AttemptLedgerError as exc:
            print(f"attempt ledger success check refused: {exc}", file=sys.stderr)
            return 1
        return 0 if matched else 1
    if args.write_attempt_ledger:
        if args.out or args.date:
            parser.error("--out/--date are invalid with --write-attempt-ledger")
        if not args.ledger_dir or not args.attempt_id or not args.run_id or not args.release_id or not args.started_at:
            parser.error("attempt ledger requires --ledger-dir, --attempt-id, --run-id, --release-id and --started-at")
        if args.exit_code is None:
            parser.error("attempt ledger write requires --exit-code")
        try:
            record = make_attempt_record(
                attempt_id=args.attempt_id,
                run_id=args.run_id,
                release_id=args.release_id,
                phase=args.phase,
                exit_code=args.exit_code,
                publish_ok=as_bool(args.publish_ok),
                terminated_early=as_bool(args.terminated_early),
                truncated=args.truncated,
                pending=args.pending,
                failed=args.failed,
                skipped=as_bool(args.skipped),
                body_complete=as_bool(args.body_complete),
                started_at=args.started_at,
                finished_at=args.finished_at or None,
            )
            written = write_attempt_ledger(args.ledger_dir, record)
        except AttemptLedgerError as exc:
            print(f"attempt ledger refused: {exc}", file=sys.stderr)
            return 70
        print(written.name)
        return 0
    if not args.out or not args.date or args.exit_code is None:
        parser.error("--out, --date and --exit-code are required for pipeline status")
    result = evaluate_status(
        exit_code=args.exit_code,
        publish_ok=as_bool(args.publish_ok),
        terminated_early=as_bool(args.terminated_early),
        truncated=args.truncated,
        pending=args.pending,
        failed=args.failed,
        skipped=as_bool(args.skipped),
        in_progress=as_bool(args.in_progress),
        body_complete=as_bool(args.body_complete),
    )
    payload = {
        "schema_version": 1,
        "producer": "run_daily_fb_verify",
        "date": args.date,
        "run_id": args.run_id,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "exit_code": args.exit_code,
        "publish_ok": as_bool(args.publish_ok),
        "terminated_early": as_bool(args.terminated_early),
        "truncated": args.truncated,
        "pending": args.pending,
        "failed": args.failed,
        "body_complete": as_bool(args.body_complete),
        **result,
    }
    atomic_write_json(args.out, payload)
    print(payload["state"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
