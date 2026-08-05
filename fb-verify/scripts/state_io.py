#!/usr/bin/env python3
"""Durable atomic state writes for the FB verification pipeline."""

import hashlib
import json
import os
import time
from pathlib import Path


def _fsync_directory(directory):
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _write_temp(target, data, suffix="tmp"):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{time.time_ns()}.{suffix}"
    )
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return temporary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_bytes(path, data):
    target = Path(path)
    temporary = _write_temp(target, data)
    try:
        os.replace(temporary, target)
        _fsync_directory(target.parent)
    finally:
        temporary.unlink(missing_ok=True)


def json_bytes(value):
    return (
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def atomic_write_json(path, value):
    atomic_write_bytes(path, json_bytes(value))


def _transaction_identity(paths):
    resolved = sorted(str(Path(path).resolve()) for path in paths)
    digest = hashlib.sha256("\0".join(resolved).encode()).hexdigest()[:16]
    journal_dir = Path(resolved[0]).parent
    return digest, journal_dir / f".fbverify-transaction-{digest}.json"


def recover_json_transaction(journal_path):
    """Roll back an interrupted transaction described by a durable journal."""
    journal_path = Path(journal_path)
    if not journal_path.exists():
        return False
    with journal_path.open(encoding="utf-8") as handle:
        journal = json.load(handle)
    if (
        not isinstance(journal, dict)
        or journal.get("schema_version") != 1
        or not isinstance(journal.get("entries"), list)
    ):
        raise RuntimeError(f"invalid transaction journal; manual recovery required: {journal_path}")

    errors = []
    for entry in reversed(journal["entries"]):
        target = Path(entry["target"])
        backup = Path(entry["backup"])
        staged = Path(entry["staged"])
        try:
            if entry["existed"]:
                if not backup.exists():
                    raise RuntimeError(f"missing rollback backup for {target}")
                os.replace(backup, target)
                _fsync_directory(target.parent)
            else:
                target.unlink(missing_ok=True)
                _fsync_directory(target.parent)
            staged.unlink(missing_ok=True)
        except Exception as exc:
            errors.append(f"{target}: {exc}")
    if errors:
        raise RuntimeError(
            f"transaction recovery incomplete; journal preserved at {journal_path}: "
            + "; ".join(errors)
        )
    for entry in journal["entries"]:
        Path(entry["backup"]).unlink(missing_ok=True)
        Path(entry["staged"]).unlink(missing_ok=True)
    journal_path.unlink()
    _fsync_directory(journal_path.parent)
    return True


def recoverable_json_transaction(path_values, *, fail_after_replace=None):
    """Commit multiple JSON states with rollback and next-run crash recovery.

    All JSON is serialized and every new file/backup is fsynced before the
    journal becomes visible. The journal is removed only after all destination
    hashes have been verified. A journal left by a killed process is rolled
    back before the next transaction starts.
    """
    items = [(Path(path).resolve(), value) for path, value in path_values]
    if not items:
        return
    if len({path for path, _ in items}) != len(items):
        raise ValueError("transaction target paths must be distinct")
    txid, journal_path = _transaction_identity(path for path, _ in items)
    if recover_json_transaction(journal_path):
        # Callers necessarily loaded their in-memory inputs before arriving at
        # commit. Those inputs may have observed a half-applied transaction, so
        # never write them after recovery. A clean rerun must re-read old state.
        raise RuntimeError(
            f"recovered interrupted transaction at {journal_path}; rerun required"
        )

    if fail_after_replace is None and os.environ.get("FB_VERIFY_TEST_MODE") == "1":
        raw = os.environ.get("FB_VERIFY_TEST_FAIL_AFTER_REPLACE")
        if raw:
            fail_after_replace = int(raw)

    entries = []
    journal_written = False
    try:
        for target, value in items:
            data = json_bytes(value)
            staged = _write_temp(target, data, suffix=f"{txid}.staged")
            existed = target.exists()
            backup = target.with_name(f".{target.name}.{txid}.backup")
            backup.unlink(missing_ok=True)
            if existed:
                backup_temp = _write_temp(target, target.read_bytes(), suffix=f"{txid}.backup-tmp")
                os.replace(backup_temp, backup)
                _fsync_directory(target.parent)
            entries.append(
                {
                    "target": str(target),
                    "staged": str(staged),
                    "backup": str(backup),
                    "existed": existed,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        journal = {
            "schema_version": 1,
            "transaction_id": txid,
            "entries": entries,
        }
        atomic_write_json(journal_path, journal)
        journal_written = True
        for index, entry in enumerate(entries, 1):
            os.replace(entry["staged"], entry["target"])
            _fsync_directory(Path(entry["target"]).parent)
            if fail_after_replace is not None and index == fail_after_replace:
                raise RuntimeError(f"injected transaction failure after replace {index}")
        for entry in entries:
            actual = hashlib.sha256(Path(entry["target"]).read_bytes()).hexdigest()
            if actual != entry["sha256"]:
                raise RuntimeError(f"post-transaction hash mismatch: {entry['target']}")
    except Exception:
        if journal_written:
            recover_json_transaction(journal_path)
        else:
            for entry in entries:
                Path(entry["staged"]).unlink(missing_ok=True)
                Path(entry["backup"]).unlink(missing_ok=True)
        raise

    # The durable journal is the transaction's rollback marker. Remove and
    # fsync it *before* deleting backups: if the process dies after commit hash
    # verification, a remaining journal must always still have every backup it
    # needs. Once the journal disappearance is durable, leftover backups are
    # harmless orphans and the next transaction cleans their deterministic
    # names before staging new ones.
    journal_path.unlink()
    _fsync_directory(journal_path.parent)
    for entry in entries:
        Path(entry["backup"]).unlink(missing_ok=True)
        Path(entry["staged"]).unlink(missing_ok=True)
