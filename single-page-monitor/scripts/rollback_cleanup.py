#!/usr/bin/env python3
"""Durable cleanup for rollback journals detached from the selected release."""

import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import sys
import time


if len(sys.argv) not in {6, 7}:
    raise SystemExit("usage: rollback_cleanup.py MODE ROOT RUNTIME ROLLBACK EXPECTED_CURRENT [TRUSTED_LEGACY_SHA]")
MODE, ROOT_RAW, RUNTIME_RAW, ROLLBACK_RAW, EXPECTED_CURRENT = sys.argv[1:6]
ROOT_INPUT = pathlib.Path(ROOT_RAW)
RUNTIME_INPUT = pathlib.Path(RUNTIME_RAW)
ROOT = ROOT_INPUT.resolve()
RUNTIME = RUNTIME_INPUT
CURRENT = ROOT / "current"
TRUSTED_LEGACY = set()
if len(sys.argv) == 7 and re.fullmatch(r"[a-f0-9]{64}", sys.argv[6]):
    TRUSTED_LEGACY.add(sys.argv[6])
if os.environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1":
    test_sha = os.environ.get("SP_SINGLE_PAGE_TEST_TRUSTED_LEGACY_SHA", "")
    if re.fullmatch(r"[a-f0-9]{64}", test_sha):
        TRUSTED_LEGACY.add(test_sha)
ALLOWED = {
    "run_daily.sh", "run_daily.sh.present",
    "check_health.mjs", "check_health.mjs.present",
    "locked_exec.py", "locked_exec.py.present",
    ".precommit_check_health.mjs", ".precommit_check_health.mjs.present",
    ".stable-health-migration.json", ".stable-health-migration.json.present",
    ".rollback-manifest.json",
}
AUTHORITY_NAME = ".rollback-manifest.json"
BASE_REQUIRED = {
    "run_daily.sh", "run_daily.sh.present",
    "check_health.mjs", "check_health.mjs.present",
}
HELPER_PAIR = {
    "locked_exec.py", "locked_exec.py.present",
}
MARKER_PAIR = {
    ".stable-health-migration.json", ".stable-health-migration.json.present",
}
PRECOMMIT_PAIR = {
    ".precommit_check_health.mjs", ".precommit_check_health.mjs.present",
}
ENTRY_PAIRS = (
    (HELPER_PAIR, "helper"),
    (MARKER_PAIR, "marker"),
    (PRECOMMIT_PAIR, "precommit health"),
)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
CURRENT_BINDING_DOMAIN = b"spspy-single-page-detached-cleanup-current-v1\0"


def pause(point):
    requested_points = {
        os.environ.get("SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT"),
        os.environ.get("SP_SINGLE_PAGE_TEST_PAUSE_POINT"),
    }
    if os.environ.get("SP_SINGLE_PAGE_TEST_MODE") != "1" or point not in requested_points:
        return
    ready = pathlib.Path(os.environ["SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE"])
    continuation = pathlib.Path(os.environ["SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE"])
    with ready.open("x", encoding="ascii") as handle:
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        os.fsync(handle.fileno())
    while not continuation.exists():
        time.sleep(0.02)


def fsync_root(point=None):
    if point:
        pause(point)
    descriptor = os.open(str(ROOT), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(directory, point=None):
    descriptor = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if point:
        pause(point)


def current_binding(current_target):
    if current_target is None:
        identity = b"ABSENT"
    elif isinstance(current_target, str):
        identity = b"PRESENT\0" + current_target.encode("utf-8")
    else:
        raise SystemExit("invalid detached cleanup expected current identity")
    return hashlib.sha256(CURRENT_BINDING_DOMAIN + identity).hexdigest()


def safe_uncommitted_temporary(path, final_name):
    """Return the constrained identity of a private publisher scratch file.

    A cleanup record is committed solely by replacing its final pathname and
    fsyncing ROOT.  A process can die at any earlier byte boundary, so the
    temporary file deliberately has no semantic meaning on restart.  We may
    discard it only when the name, parent, object type, permissions, ownership
    and link count all prove it is an uncommitted private scratch file.  A
    symlink, an unexpected name, or anything with broader sharing remains a
    fail-closed condition instead of becoming deletion authority.
    """
    bound = re.fullmatch(
        rf"{re.escape(final_name)}\.tmp-bound-([a-f0-9]{{64}})-([a-f0-9]{{32}})",
        path.name,
    )
    legacy = re.fullmatch(rf"{re.escape(final_name)}\.tmp-([a-f0-9]{{32}})", path.name)
    if not bound and not legacy:
        return False
    status = path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(status.st_mode) or
            stat.S_IMODE(status.st_mode) != 0o600 or status.st_uid != os.geteuid() or
            status.st_nlink != 1 or path.resolve(strict=True).parent != ROOT):
        raise SystemExit(f"unsafe uncommitted detached cleanup temporary: {path}")
    if bound:
        return {"format": "bound", "binding": bound.group(1), "nonce": bound.group(2)}
    return {"format": "legacy", "binding": None, "nonce": legacy.group(1)}


def validate_current_target(raw, label="detached cleanup current target"):
    parts = pathlib.PurePosixPath(raw).parts
    if os.path.isabs(raw) or len(parts) != 2 or parts[0] != "releases" or parts[1] in {"", ".", ".."}:
        raise SystemExit(f"{label} is unsafe")
    return raw


def validate_runtime_root():
    """Require lexical deploy/runtime paths to be real and directly related."""
    try:
        root_status = ROOT_INPUT.lstat()
        status = RUNTIME.lstat()
    except FileNotFoundError as exc:
        raise SystemExit("detached cleanup deploy or runtime root is missing") from exc
    if (not ROOT_INPUT.is_absolute() or ROOT_INPUT.is_symlink() or
            not stat.S_ISDIR(root_status.st_mode) or ROOT_INPUT.resolve(strict=True) != ROOT):
        raise SystemExit("detached cleanup deploy root is unsafe")
    if (not RUNTIME.is_absolute() or RUNTIME.parent != ROOT_INPUT or
            RUNTIME.is_symlink() or not stat.S_ISDIR(status.st_mode) or
            RUNTIME.parent.resolve(strict=True) != ROOT or
            RUNTIME.resolve(strict=True).parent != ROOT):
        raise SystemExit("detached cleanup runtime root is unsafe")


def actual_current():
    try:
        status = CURRENT.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(status.st_mode):
        raise SystemExit("detached cleanup current is unsafe")
    return validate_current_target(os.readlink(CURRENT))


def validate_selected_current(target):
    if target is None:
        return
    validate_current_target(target, "detached cleanup selected current")
    releases = ROOT / "releases"
    releases_status = releases.lstat()
    if releases.is_symlink() or not stat.S_ISDIR(releases_status.st_mode):
        raise SystemExit("detached cleanup releases root is unsafe")
    release = ROOT / pathlib.PurePosixPath(target)
    release_status = release.lstat()
    if (release.is_symlink() or not stat.S_ISDIR(release_status.st_mode) or
            release.resolve(strict=True).parent != releases.resolve(strict=True)):
        raise SystemExit("detached cleanup selected release is unsafe")
    monitor = release / "single-page-monitor"
    monitor_status = monitor.lstat()
    if (monitor.is_symlink() or not stat.S_ISDIR(monitor_status.st_mode) or
            monitor.resolve(strict=True).parent != release.resolve(strict=True)):
        raise SystemExit("detached cleanup selected monitor is unsafe")
    for name in ("run_daily.sh", "check_health.mjs"):
        entry = monitor / name
        entry_status = entry.lstat()
        if (entry.is_symlink() or not stat.S_ISREG(entry_status.st_mode) or
                entry.resolve(strict=True).parent != monitor.resolve(strict=True)):
            raise SystemExit(f"detached cleanup selected entrypoint is unsafe: {name}")


def regular_bytes(path, label):
    status = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(status.st_mode) or path.resolve(strict=True).parent != path.parent.resolve():
        raise SystemExit(f"unsafe {label}: {path}")
    return status, path.read_bytes()


def runtime_state():
    files = {}
    for name in ("run_daily.sh", "check_health.mjs"):
        status, content = regular_bytes(RUNTIME / name, f"runtime {name}")
        files[name] = {
            "mode": stat.S_IMODE(status.st_mode),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
    helper = RUNTIME / "locked_exec.py"
    try:
        helper_status, helper_content = regular_bytes(helper, "runtime locked_exec.py")
    except FileNotFoundError:
        pass
    else:
        files["locked_exec.py"] = {
            "mode": stat.S_IMODE(helper_status.st_mode),
            "sha256": hashlib.sha256(helper_content).hexdigest(),
            "size": len(helper_content),
        }
    marker = RUNTIME / ".stable-health-migration.json"
    try:
        marker_status = marker.lstat()
    except FileNotFoundError:
        marker_sha = None
        marker_metadata = None
    else:
        if marker.is_symlink() or not stat.S_ISREG(marker_status.st_mode):
            raise SystemExit("unsafe restored migration marker")
        marker_content = marker.read_bytes()
        marker_sha = hashlib.sha256(marker_content).hexdigest()
        marker_metadata = {
            "mode": stat.S_IMODE(marker_status.st_mode),
            "sha256": marker_sha,
            "size": len(marker_content),
        }
    phase_artifacts = {}
    for name in (".deployment-phase", ".precommit_check_health.mjs"):
        candidate = RUNTIME / name
        try:
            candidate_status = candidate.lstat()
        except FileNotFoundError:
            phase_artifacts[name] = None
            continue
        if candidate.is_symlink() or not stat.S_ISREG(candidate_status.st_mode):
            raise SystemExit(f"unsafe live cleanup phase artifact: {candidate}")
        content = candidate.read_bytes()
        phase_artifacts[name] = {
            "mode": stat.S_IMODE(candidate_status.st_mode),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
    return {
        "current_target": actual_current(),
        "marker_sha256": marker_sha,
        "marker": marker_metadata,
        "runtime": files,
        "deployment_phase": phase_artifacts[".deployment-phase"],
        "precommit_health": phase_artifacts[".precommit_check_health.mjs"],
    }


def validate_cleanup_manifest(entries, state=None, partial=False):
    """Validate deletion evidence and, when supplied, bind it to live state.

    The same validator is used for an immediate create, recovered scratch,
    immutable record and partially deleted tombstone.  A partial tombstone may
    naturally contain only one member of a pair after an unlink, so it retains
    the per-entry checks while the complete authority manifest carries the
    pair/profile and restored-state relationship checks.
    """
    if not isinstance(entries, dict):
        raise SystemExit("detached cleanup manifest entries are not an object")
    entry_names = set(entries)
    backup_names = entry_names - {AUTHORITY_NAME}
    if not entry_names.issubset(ALLOWED):
        raise SystemExit("detached cleanup manifest has an unsupported entry set")
    for name, metadata in entries.items():
        if (not isinstance(metadata, dict) or set(metadata) != {"mode", "sha256", "size"} or
                not isinstance(metadata.get("mode"), int) or isinstance(metadata["mode"], bool) or
                metadata["mode"] < 0 or metadata["mode"] > 0o7777 or
                not isinstance(metadata.get("size"), int) or isinstance(metadata["size"], bool) or
                metadata["size"] < 0 or not isinstance(metadata.get("sha256"), str) or
                not re.fullmatch(r"[a-f0-9]{64}", metadata["sha256"])):
            raise SystemExit(f"invalid detached cleanup manifest metadata: {name}")
        if name.endswith(".present") and (
                metadata["size"] != 0 or metadata["sha256"] != EMPTY_SHA256):
            raise SystemExit(f"invalid detached cleanup sentinel metadata: {name}")
    if partial:
        return None
    if not BASE_REQUIRED.issubset(backup_names):
        raise SystemExit("detached cleanup manifest is missing a required runtime pair")
    pair_presence = {}
    for pair, label in ENTRY_PAIRS:
        intersection = pair.intersection(backup_names)
        if intersection and intersection != pair:
            missing_base = next(name[:-8] if name.endswith(".present") else name for name in pair)
            raise SystemExit(
                f"incomplete rollback journal pair: {missing_base}; "
                f"detached cleanup manifest has an incomplete {label} pair"
            )
        pair_presence[label] = intersection == pair
    helper_present = pair_presence["helper"]
    legacy_two_pair = (
        backup_names == BASE_REQUIRED and
        entries["check_health.mjs"]["sha256"] in TRUSTED_LEGACY
    )
    if not helper_present and not legacy_two_pair:
        raise SystemExit("detached rollback is missing an authenticated lock-helper profile")
    if state is None:
        return "helper" if helper_present else "legacy"
    state_keys = {
        "current_target", "marker_sha256", "marker", "runtime",
        "deployment_phase", "precommit_health",
    }
    if not isinstance(state, dict) or set(state) != state_keys or not isinstance(state.get("runtime"), dict):
        raise SystemExit("detached cleanup state has an unsupported schema")
    if state["deployment_phase"] is not None:
        raise SystemExit("detached cleanup state retains a deployment phase gate")
    if legacy_two_pair and state["current_target"] is not None:
        raise SystemExit("detached two-file cleanup state retains a current target")
    runtime_names = {"run_daily.sh", "check_health.mjs"}
    if helper_present:
        runtime_names.add("locked_exec.py")
    if set(state["runtime"]) != runtime_names:
        raise SystemExit("detached cleanup runtime profile differs from rollback")
    for name in runtime_names:
        if entries[name] != state["runtime"][name]:
            raise SystemExit(f"restored runtime does not match rollback backup: {name}")
    marker_present = pair_presence["marker"]
    if marker_present:
        if (entries[".stable-health-migration.json"] != state["marker"] or
                entries[".stable-health-migration.json"]["sha256"] != state["marker_sha256"]):
            raise SystemExit("restored marker differs from rollback")
    elif state["marker"] is not None or state["marker_sha256"] is not None:
        raise SystemExit("unexpected restored marker")
    precommit_present = pair_presence["precommit health"]
    if precommit_present:
        if entries[".precommit_check_health.mjs"] != state["precommit_health"]:
            raise SystemExit("restored precommit health differs from rollback")
    elif state["precommit_health"] is not None:
        raise SystemExit("unexpected restored precommit health")
    return "helper" if helper_present else "legacy"


def directory_manifest(directory, partial=False):
    status = directory.lstat()
    if directory.is_symlink() or not stat.S_ISDIR(status.st_mode) or directory.resolve(strict=True).parent != ROOT:
        raise SystemExit(f"unsafe detached rollback directory: {directory}")
    manifest = {}
    for entry in directory.iterdir():
        if entry.name not in ALLOWED:
            raise SystemExit(f"unknown detached rollback entry: {entry}")
        entry_status, content = regular_bytes(entry, "detached rollback entry")
        if entry.name.endswith(".present") and content != b"":
            raise SystemExit(f"detached rollback sentinel is not empty: {entry}")
        manifest[entry.name] = {
            "mode": stat.S_IMODE(entry_status.st_mode),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
    validate_cleanup_manifest(manifest, partial=partial)
    return manifest


def expected_current_payload(expected_current):
    if expected_current == "__ABSENT__":
        return {"kind": "absent"}, None
    if not isinstance(expected_current, str) or expected_current == "":
        raise SystemExit("detached cleanup expected current is missing")
    target = validate_current_target(expected_current, "detached cleanup expected current")
    return {"kind": "target", "value": target}, target


def decode_expected_current(payload):
    if isinstance(payload, dict) and set(payload) == {"kind"} and payload.get("kind") == "absent":
        return None
    if (isinstance(payload, dict) and set(payload) == {"kind", "value"} and
            payload.get("kind") == "target" and isinstance(payload.get("value"), str)):
        return validate_current_target(payload["value"], "detached rollback authority expected current")
    raise SystemExit("detached rollback authority has an invalid expected current")


def rollback_authority_profile(entries, expected_current):
    names = set(entries) - {AUTHORITY_NAME}
    if (expected_current is None and entries.get("check_health.mjs", {}).get("sha256") in TRUSTED_LEGACY and
            not MARKER_PAIR.intersection(names)):
        return "legacy"
    if HELPER_PAIR.issubset(names):
        return "helper"
    raise SystemExit("detached rollback authority has no supported transaction profile")


def read_rollback_authority(rollback):
    authority = rollback / AUTHORITY_NAME
    status, raw = regular_bytes(authority, "detached rollback authority")
    if stat.S_IMODE(status.st_mode) != 0o600:
        raise SystemExit("detached rollback authority has unsafe permissions")
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid detached rollback authority: {exc}")
    keys = {"schema", "kind", "release", "profile", "expected_current", "entries"}
    release_match = re.fullmatch(r"\.rollback-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)", rollback.name)
    if (not isinstance(payload, dict) or set(payload) != keys or
            type(payload.get("schema")) is not int or payload["schema"] != 1 or
            payload.get("kind") != "spspy-single-page-detached-rollback-authority" or
            release_match is None or payload.get("release") != release_match.group(1)):
        raise SystemExit("unsupported detached rollback authority schema")
    expected_current = decode_expected_current(payload.get("expected_current"))
    validate_cleanup_manifest(payload.get("entries"))
    profile = rollback_authority_profile(payload["entries"], expected_current)
    if payload.get("profile") != profile:
        raise SystemExit("detached rollback authority profile is inconsistent")
    physical = directory_manifest(rollback)
    if AUTHORITY_NAME not in physical:
        raise SystemExit("detached rollback authority is missing from its journal")
    backups = {name: metadata for name, metadata in physical.items() if name != AUTHORITY_NAME}
    if backups != payload["entries"]:
        raise SystemExit("detached rollback authority does not bind its journal")
    return payload, physical, expected_current


def seal():
    rollback = pathlib.Path(ROLLBACK_RAW)
    match = re.fullmatch(r"\.rollback-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)", rollback.name)
    if not match or rollback.parent.resolve() != ROOT:
        raise SystemExit("unsafe detached rollback authority target")
    expected_payload, wanted_current = expected_current_payload(EXPECTED_CURRENT)
    state = runtime_state()
    if state["current_target"] != wanted_current:
        raise SystemExit("current changed before detached rollback authority publication")
    manifest = flush_rollback_backups(rollback, wanted_current, state)
    if directory_manifest(rollback) != manifest or runtime_state() != state:
        raise SystemExit("rollback or runtime changed immediately before authority publication")
    profile = rollback_authority_profile(manifest, wanted_current)
    payload = {
        "schema": 1,
        "kind": "spspy-single-page-detached-rollback-authority",
        "release": match.group(1),
        "profile": profile,
        "expected_current": expected_payload,
        "entries": manifest,
    }
    authority = rollback / AUTHORITY_NAME
    nonce = secrets.token_hex(16)
    temporary = rollback / f"{AUTHORITY_NAME}.tmp-{nonce}"
    if authority.exists() or authority.is_symlink() or temporary.exists() or temporary.is_symlink():
        raise SystemExit("detached rollback authority publication path already exists")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        content = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        pause("after_detached_authority_temp_create")
        written = os.write(descriptor, content[:max(1, len(content) // 2)])
        if written <= 0:
            raise SystemExit("unable to write detached rollback authority")
        pause("after_detached_authority_temp_partial_write")
        while written < len(content):
            wrote = os.write(descriptor, content[written:])
            if wrote <= 0:
                raise SystemExit("unable to finish detached rollback authority")
            written += wrote
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    pause("after_detached_authority_file_fsync_before_replace")
    os.replace(temporary, authority)
    pause("after_detached_authority_replace_before_dir_fsync")
    fsync_directory(rollback, "after_detached_authority_dir_fsync_before_root_fsync")
    fsync_root()
    pause("after_detached_authority_root_fsync")


def verify():
    """Revalidate a sealed journal against the untouched pre-transaction state."""
    rollback = pathlib.Path(ROLLBACK_RAW)
    match = re.fullmatch(r"\.rollback-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)", rollback.name)
    if (not match or rollback.parent.resolve() != ROOT or rollback.is_symlink()):
        raise SystemExit("unsafe detached rollback verification target")
    _, wanted_current = expected_current_payload(EXPECTED_CURRENT)
    state = runtime_state()
    if state["current_target"] != wanted_current:
        raise SystemExit("current changed before detached rollback authority verification")
    validate_selected_current(wanted_current)
    authority, manifest, authority_current = read_rollback_authority(rollback)
    validate_cleanup_manifest(manifest, state=state)
    authority_profile = rollback_authority_profile(manifest, wanted_current)
    if (authority_current != wanted_current or authority["profile"] != authority_profile):
        raise SystemExit("detached rollback authority differs from pre-transaction state")
    if authority_profile == "legacy":
        _, restored_health = regular_bytes(RUNTIME / "check_health.mjs", "verified legacy health checker")
        if b"spspy-single-page-stable-health" in restored_health:
            raise SystemExit("verified two-file rollback health checker has stable identity")


def flush_rollback_backups(rollback, wanted_current, state):
    """Flush and revalidate every backup for seal()'s authority payload."""
    rollback_status = rollback.lstat()
    if (rollback.is_symlink() or not stat.S_ISDIR(rollback_status.st_mode) or
            rollback.parent.resolve(strict=True) != ROOT or
            rollback.resolve(strict=True).parent != ROOT):
        raise SystemExit("detached rollback preparation target is not a directory")
    rollback_identity = (
        rollback_status.st_dev, rollback_status.st_ino, rollback_status.st_mode,
        rollback_status.st_uid, rollback_status.st_nlink,
    )
    if state["current_target"] != wanted_current:
        raise SystemExit("current changed before detached rollback backup flush")
    validate_selected_current(wanted_current)
    manifest = directory_manifest(rollback)
    if AUTHORITY_NAME in manifest:
        raise SystemExit("detached rollback authority exists before backup flush")
    validate_cleanup_manifest(manifest, state=state)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    for name in sorted(manifest):
        entry = rollback / name
        descriptor = os.open(str(entry), flags)
        try:
            descriptor_status = os.fstat(descriptor)
            path_status = entry.lstat()
            if (not stat.S_ISREG(descriptor_status.st_mode) or entry.is_symlink() or
                    (descriptor_status.st_dev, descriptor_status.st_ino) !=
                    (path_status.st_dev, path_status.st_ino) or
                    entry.resolve(strict=True).parent != rollback.resolve(strict=True)):
                raise SystemExit(f"rollback backup changed type before fsync: {name}")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
            observed = {
                "mode": stat.S_IMODE(descriptor_status.st_mode),
                "sha256": digest.hexdigest(),
                "size": size,
            }
            if observed != manifest[name]:
                raise SystemExit(f"rollback backup changed before fsync: {name}")
            if (os.environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1" and
                    os.environ.get("SP_SINGLE_PAGE_TEST_FAIL_ROLLBACK_FSYNC_NAME") == name):
                raise OSError(f"injected rollback backup fsync failure: {name}")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        pause(f"after_detached_backup_fsync_{name}")
    fsync_directory(rollback, "after_detached_backup_directory_fsync")
    final_status = rollback.lstat()
    final_identity = (
        final_status.st_dev, final_status.st_ino, final_status.st_mode,
        final_status.st_uid, final_status.st_nlink,
    )
    if final_identity != rollback_identity or directory_manifest(rollback) != manifest:
        raise SystemExit("detached rollback changed during durable backup flush")
    if runtime_state() != state:
        raise SystemExit("runtime changed during durable rollback backup flush")
    return manifest


def validate_record(path):
    _, raw = regular_bytes(path, "detached cleanup record")
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid detached cleanup record: {exc}")
    keys = {"schema", "kind", "release", "rollback", "tombstone", "nonce", "state", "entries"}
    if not isinstance(payload, dict) or set(payload) != keys:
        raise SystemExit("unsupported detached cleanup record schema")
    release = payload.get("release")
    nonce = payload.get("nonce")
    final_name = f".rollback-cleanup-detached-{release}.json"
    state = payload.get("state")
    entries = payload.get("entries")
    profile = validate_cleanup_manifest(entries, state=state)
    if isinstance(state, dict):
        validate_selected_current(state.get("current_target"))
    if profile == "legacy":
        _, legacy_health = regular_bytes(RUNTIME / "check_health.mjs", "restored legacy health checker")
        if b"spspy-single-page-stable-health" in legacy_health:
            raise SystemExit("detached two-file cleanup health checker has stable identity")
    if (type(payload.get("schema")) is not int or payload["schema"] != 1 or
            payload.get("kind") != "spspy-single-page-detached-rollback-cleanup" or
            not isinstance(release, str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*", release) or
            payload.get("rollback") != f".rollback-{release}" or
            not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce) or
            payload.get("tombstone") != f".rollback-tombstone-detached-{release}-{nonce}" or
            payload.get("state") != runtime_state() or
            path.name not in {final_name, final_name + ".pending"}):
        raise SystemExit("detached cleanup record does not bind restored runtime")
    return payload


def finish(record_path, payload):
    original = ROOT / payload["rollback"]
    tombstone = ROOT / payload["tombstone"]
    original_exists = original.exists() or original.is_symlink()
    tombstone_exists = tombstone.exists() or tombstone.is_symlink()
    if original_exists and tombstone_exists:
        raise SystemExit("detached rollback and tombstone both exist")
    if original_exists:
        if directory_manifest(original) != payload["entries"]:
            raise SystemExit("detached rollback differs from cleanup manifest")
        os.replace(original, tombstone)
        fsync_root("after_detached_rollback_rename_before_root_fsync")
        tombstone_exists = True
    if tombstone_exists:
        remaining = directory_manifest(tombstone, partial=True)
        for name, metadata in remaining.items():
            if payload["entries"].get(name) != metadata:
                raise SystemExit("detached tombstone differs from cleanup manifest")
        for entry in sorted(tombstone.iterdir(), key=lambda item: item.name):
            entry.unlink()
            pause(f"after_detached_tombstone_unlink_{entry.name}")
        tombstone.rmdir()
        fsync_root("after_detached_tombstone_rmdir_before_root_fsync")
    record_path.unlink()
    fsync_root("after_detached_record_unlink_before_root_fsync")


def resume():
    candidates = {}
    rollback_directories = []
    sealed_rollbacks = []
    transaction_releases = set()
    current_restore_intents = []
    pattern = re.compile(
        r"(\.rollback-cleanup-detached-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)\.json)(\.pending)?"
    )
    temporary_bound_pattern = re.compile(
        r"(\.rollback-cleanup-detached-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*\.json)"
        r"\.tmp-bound-[a-f0-9]{64}-[a-f0-9]{32}"
    )
    temporary_legacy_pattern = re.compile(
        r"(\.rollback-cleanup-detached-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*\.json)\.tmp-[a-f0-9]{32}"
    )
    orphaned_temporaries = {}
    for candidate in ROOT.iterdir():
        match = pattern.fullmatch(candidate.name)
        if match:
            final_name = match.group(1)
            transaction_releases.add(match.group(2))
            if final_name in candidates:
                raise SystemExit("multiple detached cleanup records for one rollback")
            candidates[final_name] = candidate
            continue
        temporary_match = (
            temporary_bound_pattern.fullmatch(candidate.name) or
            temporary_legacy_pattern.fullmatch(candidate.name)
        )
        if temporary_match:
            orphaned_temporaries.setdefault(temporary_match.group(1), []).append(candidate)
            temporary_release = re.fullmatch(
                r"\.rollback-cleanup-detached-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)\.json",
                temporary_match.group(1),
            ).group(1)
            transaction_releases.add(temporary_release)
            continue
        current_intent_match = re.fullmatch(
            r"\.current-precurrent-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)\.tmp",
            candidate.name,
        )
        if current_intent_match:
            intent_status = candidate.lstat()
            if (not stat.S_ISLNK(intent_status.st_mode) or intent_status.st_uid != os.geteuid() or
                    intent_status.st_nlink != 1 or candidate.parent.resolve(strict=True) != ROOT):
                raise SystemExit("unsafe caught-current restore intent")
            current_restore_intents.append((candidate, current_intent_match.group(1)))
            transaction_releases.add(current_intent_match.group(1))
            continue
        rollback_match = re.fullmatch(r"\.rollback-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)", candidate.name)
        if rollback_match:
            candidate_status = candidate.lstat()
            if (candidate.is_symlink() or not stat.S_ISDIR(candidate_status.st_mode) or
                    candidate.resolve(strict=True).parent != ROOT):
                raise SystemExit(f"unsafe detached rollback candidate: {candidate}")
            rollback_directories.append((candidate, rollback_match.group(1)))
            transaction_releases.add(rollback_match.group(1))
            try:
                (candidate / AUTHORITY_NAME).lstat()
            except FileNotFoundError:
                pass
            else:
                sealed_rollbacks.append((candidate, rollback_match.group(1)))
    # No cleanup action may run while evidence from another transaction remains
    # unvalidated.  A single deployment can legitimately leave a rollback plus
    # its final record or scratch, but two release identities are always
    # ambiguous and therefore fail before any live or evidence mutation.
    if len(transaction_releases) > 1:
        raise SystemExit("multiple detached cleanup transaction releases are ambiguous")

    # An immutable final record and a scratch record for the same transaction
    # cannot be produced by one successful publication.  Keep the ambiguity
    # fail-closed rather than guessing which object owns deletion authority.
    validated_temporaries = []
    for final_name, temporaries in orphaned_temporaries.items():
        if final_name in candidates:
            raise SystemExit("committed detached cleanup record has an unexpected temporary")
        if len(temporaries) != 1:
            raise SystemExit("multiple detached cleanup temporaries for one rollback")
        temporary = temporaries[0]
        scratch = safe_uncommitted_temporary(temporary, final_name)
        if not scratch:
            raise SystemExit("invalid detached cleanup temporary name")
        if scratch["format"] == "legacy":
            raise SystemExit("legacy detached cleanup temporary has no durable expected-current binding")
        validated_temporaries.append((temporary, final_name, scratch))
    sealed_paths = {rollback for rollback, _ in sealed_rollbacks}
    observed_current = actual_current()
    for rollback, release in rollback_directories:
        if rollback in sealed_paths:
            continue
        final_name = f".rollback-cleanup-detached-{release}.json"
        if final_name in candidates or final_name in orphaned_temporaries:
            continue
        if observed_current == f"releases/{release}":
            # A pre-manifest selected residue from the previous protocol is
            # left to the existing selected-release proof below.
            continue
        raise SystemExit("unsealed detached rollback has no durable expected-current authority")
    gated_precurrent = []
    for rollback, release in sealed_rollbacks:
        final_name = f".rollback-cleanup-detached-{release}.json"
        if final_name in candidates or final_name in orphaned_temporaries:
            continue
        authority, _, expected_current = read_rollback_authority(rollback)
        state = runtime_state()
        if state["deployment_phase"] is None:
            continue
        selected_target = f"releases/{release}"
        matching_intent = [intent for intent, intent_release in current_restore_intents if intent_release == release]
        if state["current_target"] == expected_current:
            gated_precurrent.append((rollback, authority, len(matching_intent) == 1))
        elif state["current_target"] == selected_target and len(matching_intent) == 1:
            gated_precurrent.append((rollback, authority, True))
        elif state["current_target"] != f"releases/{release}":
            raise SystemExit("sealed gated rollback binds neither pre-current nor selected current")
    if len(gated_precurrent) > 1:
        raise SystemExit("multiple sealed pre-current transactions are ambiguous")
    if gated_precurrent:
        _, _, caught_intent = gated_precurrent[0]
        recover_precurrent(caught=caught_intent)
        return resume()
    if current_restore_intents:
        raise SystemExit("caught-current restore intent has no active sealed transaction")
    bare_recoveries = []
    for rollback, release in sealed_rollbacks:
        final_name = f".rollback-cleanup-detached-{release}.json"
        if final_name in candidates or final_name in orphaned_temporaries:
            continue
        authority, manifest, expected_current = read_rollback_authority(rollback)
        state = runtime_state()
        if state["deployment_phase"] is not None:
            # The ordinary selected-release recovery still owns an interrupted
            # live transaction.  A sealed rollback is detached cleanup
            # authority only after the phase gate's absence is durable.
            continue
        selected_target = f"releases/{release}"
        if state["current_target"] == selected_target:
            # A committed residue belongs to recover_durable_current_marker,
            # which performs the selected-release proof after this preflight.
            continue
        if state["current_target"] != expected_current:
            raise SystemExit("sealed detached rollback expected current changed")
        profile = validate_cleanup_manifest(manifest, state=state)
        if authority["profile"] != rollback_authority_profile(manifest, expected_current):
            raise SystemExit("sealed detached rollback profile differs from restored runtime")
        bare_recoveries.append((rollback, expected_current))
    if len(bare_recoveries) > 1:
        raise SystemExit("multiple sealed detached rollbacks match restored runtime")
    for temporary, final_name, scratch in validated_temporaries:
        release = re.fullmatch(
            r"\.rollback-cleanup-detached-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)\.json",
            final_name,
        ).group(1)
        rollback = ROOT / f".rollback-{release}"
        # A scratch record alone never authorizes deletion.  Its matching
        # private rollback journal must still be present, and the same strict
        # restore-state validation performed by create() below will rebuild a
        # brand-new committed record before cleanup begins.
        if not rollback.exists() or rollback.is_symlink():
            raise SystemExit("uncommitted detached cleanup temporary has no intact rollback journal")
        # Do not unlink then create a new scratch record: SIGKILL in that
        # handoff would lose the only durable release binding.  Rewrite this
        # already-proven private inode in place and replace it only after the
        # complete replacement record is file-fsynced.
        authority, manifest, expected_current = read_rollback_authority(rollback)
        if scratch["binding"] != current_binding(expected_current):
            raise SystemExit("detached cleanup temporary differs from rollback authority")
        state = runtime_state()
        if state["current_target"] != expected_current:
            raise SystemExit("detached cleanup temporary expected current changed")
        nonce = scratch["nonce"]
        profile = validate_cleanup_manifest(manifest, state=state)
        if authority["profile"] != rollback_authority_profile(manifest, expected_current):
            raise SystemExit("detached cleanup temporary profile differs from rollback authority")
        expected_argument = "__ABSENT__" if expected_current is None else expected_current
        create(str(rollback), expected_argument, temporary, nonce)
    for rollback, expected_current in bare_recoveries:
        expected_argument = "__ABSENT__" if expected_current is None else expected_current
        create(str(rollback), expected_argument)
    for final_name, record_path in sorted(candidates.items()):
        payload = validate_record(record_path)
        final_path = ROOT / final_name
        if record_path != final_path:
            os.replace(record_path, final_path)
            fsync_root("after_detached_record_replace_before_root_fsync")
            record_path = final_path
        finish(record_path, payload)


def create(rollback_raw=ROLLBACK_RAW, expected_current=EXPECTED_CURRENT,
           existing_temporary=None, publication_nonce=None):
    rollback = pathlib.Path(rollback_raw)
    match = re.fullmatch(r"\.rollback-([0-9]{8}T[0-9]{6}Z-[1-9][0-9]*)", rollback.name)
    if not match or rollback.parent.resolve() != ROOT:
        raise SystemExit("unsafe detached rollback target")
    _, wanted_current = expected_current_payload(expected_current)
    state = runtime_state()
    if wanted_current is None and state["current_target"] is not None:
        raise SystemExit("restored current exists before detached first-legacy cleanup")
    if wanted_current is not None and state["current_target"] != wanted_current:
        raise SystemExit("restored current changed before detached cleanup")
    validate_selected_current(wanted_current)
    binding = current_binding(wanted_current)
    manifest = directory_manifest(rollback)
    profile = validate_cleanup_manifest(manifest, state=state)
    if AUTHORITY_NAME in manifest:
        authority, authority_manifest, authority_current = read_rollback_authority(rollback)
        authority_profile = rollback_authority_profile(manifest, wanted_current)
        if (authority_current != wanted_current or authority["profile"] != authority_profile or
                authority_manifest != manifest):
            raise SystemExit("detached rollback authority expected current differs from cleanup request")
    else:
        raise SystemExit("detached cleanup has no durable rollback authority")
    _, restored_health = regular_bytes(RUNTIME / "check_health.mjs", "restored legacy health checker")
    if profile == "legacy" and b"spspy-single-page-stable-health" in restored_health:
        raise SystemExit("detached two-file cleanup health checker has stable identity")
    release = match.group(1)
    nonce = publication_nonce or secrets.token_hex(16)
    if not re.fullmatch(r"[a-f0-9]{32}", nonce):
        raise SystemExit("invalid detached cleanup publication nonce")
    final_path = ROOT / f".rollback-cleanup-detached-{release}.json"
    temporary = pathlib.Path(existing_temporary) if existing_temporary is not None else (
        final_path.with_name(final_path.name + f".tmp-bound-{binding}-{nonce}"))
    if final_path.exists() or final_path.is_symlink():
        raise SystemExit("detached cleanup record already exists")
    if existing_temporary is not None:
        scratch = safe_uncommitted_temporary(temporary, final_path.name)
        if (not scratch or scratch["format"] != "bound" or scratch["binding"] != binding or
                scratch["nonce"] != nonce):
            raise SystemExit("invalid detached cleanup recovery temporary")
    elif temporary.exists() or temporary.is_symlink():
        raise SystemExit("detached cleanup record already exists")
    payload = {
        "schema": 1, "kind": "spspy-single-page-detached-rollback-cleanup", "release": release,
        "rollback": rollback.name, "tombstone": f".rollback-tombstone-detached-{release}-{nonce}",
        "nonce": nonce, "state": state, "entries": manifest,
    }
    flags = os.O_WRONLY | (os.O_TRUNC if existing_temporary is not None else os.O_CREAT | os.O_EXCL)
    descriptor = os.open(str(temporary), flags, 0o600)
    try:
        content = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        pause("after_detached_record_temp_create")
        written = os.write(descriptor, content[:max(1, len(content) // 2)])
        if written <= 0:
            raise SystemExit("unable to write detached cleanup record temporary")
        pause("after_detached_record_temp_partial_write")
        while written < len(content):
            wrote = os.write(descriptor, content[written:])
            if wrote <= 0:
                raise SystemExit("unable to finish detached cleanup record temporary")
            written += wrote
        if existing_temporary is not None:
            pause("after_detached_record_recovery_rewrite_before_file_fsync")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    pause("after_detached_record_file_fsync_before_replace")
    os.replace(temporary, final_path)
    fsync_root("after_detached_record_replace_before_root_fsync")
    pause("after_detached_record_root_fsync")
    finish(final_path, validate_record(final_path))


def recover_precurrent(caught=False, preserve=False):
    if preserve and not caught:
        raise SystemExit("only caught rollback recovery may preserve its active transaction")
    gate = RUNTIME / ".deployment-phase"
    gate_status, gate_raw = regular_bytes(gate, "pre-current deployment phase gate")
    if (stat.S_IMODE(gate_status.st_mode) & 0o022 or gate_status.st_uid != os.geteuid() or
            gate_status.st_nlink != 1):
        raise SystemExit("pre-current deployment phase gate is writable")
    gate_identity = (
        gate_status.st_dev, gate_status.st_ino, gate_status.st_mode,
        gate_status.st_uid, gate_status.st_nlink, gate_raw,
    )
    try:
        phase = json.loads(gate_raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid pre-current deployment phase gate: {exc}")
    phase_keys = {
        "fallback_sha256", "kind", "mode", "release_id", "schema",
        "wrapper_id", "wrapper_sha256", "wrapper_version",
    }
    release_id = phase.get("release_id") if isinstance(phase, dict) else None
    release_match = re.fullmatch(
        r"([0-9]{8}T[0-9]{6}Z-([1-9][0-9]*)):\2",
        release_id or "",
    )
    if (not isinstance(phase, dict) or set(phase) != phase_keys or
            type(phase.get("schema")) is not int or phase["schema"] != 1 or
            phase.get("kind") != "spspy-single-page-deployment-phase" or
            phase.get("mode") not in {"legacy_fallback", "fail_closed"} or release_match is None or
            not isinstance(phase.get("wrapper_id"), str) or
            not isinstance(phase.get("wrapper_version"), int) or isinstance(phase["wrapper_version"], bool) or
            phase["wrapper_version"] < 1 or not isinstance(phase.get("wrapper_sha256"), str) or
            not re.fullmatch(r"[a-f0-9]{64}", phase["wrapper_sha256"]) or
            (phase["mode"] == "fail_closed" and phase.get("fallback_sha256") is not None) or
            (phase["mode"] == "legacy_fallback" and
             (not isinstance(phase.get("fallback_sha256"), str) or
              not re.fullmatch(r"[a-f0-9]{64}", phase["fallback_sha256"])))):
        raise SystemExit("pre-current deployment phase gate has an unsupported schema")
    release = release_match.group(1)
    rollback = ROOT / f".rollback-{release}"
    current_temporary = ROOT / f".current-precurrent-{release}.tmp"
    for candidate in ROOT.iterdir():
        other_match = re.fullmatch(r"\.rollback-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*", candidate.name)
        cleanup_match = re.fullmatch(
            r"\.rollback-cleanup-detached-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*\.json"
            r"(?:\.pending|\.tmp-(?:bound-[a-f0-9]{64}-)?[a-f0-9]{32})?",
            candidate.name,
        )
        current_intent_match = re.fullmatch(
            r"\.current-precurrent-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*\.tmp",
            candidate.name,
        )
        if other_match:
            candidate_status = candidate.lstat()
            if (candidate.is_symlink() or not stat.S_ISDIR(candidate_status.st_mode) or
                    candidate.resolve(strict=True).parent != ROOT):
                raise SystemExit(f"unsafe rollback candidate conflicts with pre-current recovery: {candidate}")
            if candidate != rollback:
                raise SystemExit("another rollback transaction conflicts with pre-current recovery")
        elif cleanup_match:
            # A gate is durably earlier than any detached cleanup publication.
            # Thus even a same-release record or scratch is an impossible mixed
            # state, and must be rejected before restoring a live byte.
            raise SystemExit("detached cleanup publication conflicts with active pre-current recovery")
        elif current_intent_match and candidate != current_temporary:
            raise SystemExit("another caught-current restore intent conflicts with pre-current recovery")
    authority, manifest, expected_current = read_rollback_authority(rollback)
    selected_target = f"releases/{release}"
    observed_current = actual_current()
    if caught:
        if ROLLBACK_RAW:
            required_rollback = pathlib.Path(ROLLBACK_RAW)
            _, required_expected = expected_current_payload(EXPECTED_CURRENT)
            try:
                required_status = required_rollback.lstat()
            except FileNotFoundError as exc:
                raise SystemExit("caught rollback request is missing") from exc
            if (not required_rollback.is_absolute() or required_rollback.name != rollback.name or
                    required_rollback.is_symlink() or not stat.S_ISDIR(required_status.st_mode) or
                    required_rollback.parent.resolve(strict=True) != ROOT or
                    required_rollback.resolve(strict=True) != rollback.resolve(strict=True) or
                    required_expected != expected_current):
                raise SystemExit("caught rollback request does not bind active rollback authority")
        if observed_current not in {expected_current, selected_target}:
            raise SystemExit("caught rollback current binds neither expected nor selected release")
    elif observed_current != expected_current:
        raise SystemExit("pre-current rollback authority does not bind current")
    validate_selected_current(expected_current)
    if observed_current == selected_target:
        validate_selected_current(selected_target)
    if expected_current == selected_target:
        raise SystemExit("pre-current rollback authority names the selected release")
    backup_entries = authority["entries"]
    if authority["profile"] == "legacy":
        if (expected_current is not None or phase["mode"] != "legacy_fallback" or
                phase["fallback_sha256"] != backup_entries["check_health.mjs"]["sha256"]):
            raise SystemExit("legacy pre-current gate does not bind rollback authority")
    elif authority["profile"] == "helper":
        if expected_current is None or phase["mode"] != "fail_closed":
            raise SystemExit("stable pre-current gate does not bind rollback authority")
    else:
        raise SystemExit("pre-current rollback authority has an unsupported profile")

    releases = ROOT / "releases"
    release_path = releases / release
    monitor = release_path / "single-page-monitor"
    wrapper = monitor / "stable_check_health.mjs"
    for directory, parent, label in (
        (releases, ROOT, "releases"),
        (release_path, releases, "pre-current release"),
        (monitor, release_path, "pre-current monitor"),
    ):
        directory_status = directory.lstat()
        if (directory.is_symlink() or not stat.S_ISDIR(directory_status.st_mode) or
                directory.resolve(strict=True).parent != parent.resolve(strict=True) or
                (directory != releases and directory_status.st_mode & 0o222)):
            raise SystemExit(f"unsafe {label} directory")
    wrapper_status, wrapper_content = regular_bytes(wrapper, "pre-current selected health wrapper")
    wrapper_id = re.search(rb'const STABLE_WRAPPER_ID = "([^"]+)";', wrapper_content)
    wrapper_version = re.search(rb"const STABLE_WRAPPER_VERSION = ([0-9]+);", wrapper_content)
    if (wrapper.resolve(strict=True).parent != monitor.resolve(strict=True) or wrapper_status.st_mode & 0o222 or
            not wrapper_id or not wrapper_version or phase["wrapper_id"] != "spspy-single-page-stable-health" or
            wrapper_id.group(1).decode("ascii") != phase["wrapper_id"] or
            int(wrapper_version.group(1)) != phase["wrapper_version"] or
            hashlib.sha256(wrapper_content).hexdigest() != phase["wrapper_sha256"]):
        raise SystemExit("pre-current gate does not bind its immutable release wrapper")

    restored_names = (
        "run_daily.sh", "check_health.mjs", "locked_exec.py",
        ".stable-health-migration.json", ".precommit_check_health.mjs",
    )
    plans = []
    allowed_temporaries = set()
    for name in restored_names:
        pair = {name, f"{name}.present"}
        present = pair.issubset(backup_entries)
        if pair.intersection(backup_entries) and not present:
            raise SystemExit(f"pre-current rollback has an incomplete pair: {name}")
        target = RUNTIME / name
        try:
            target_status = target.lstat()
        except FileNotFoundError:
            target_status = None
        if target_status is not None and (target.is_symlink() or not stat.S_ISREG(target_status.st_mode) or
                target.resolve(strict=True).parent != RUNTIME.resolve(strict=True)):
            raise SystemExit(f"unsafe pre-current runtime restore target: {target}")
        if present:
            backup = rollback / name
            backup_status, content = regular_bytes(backup, f"pre-current rollback {name}")
            metadata = backup_entries[name]
            observed_metadata = {
                "mode": stat.S_IMODE(backup_status.st_mode),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            if observed_metadata != metadata:
                raise SystemExit(f"pre-current rollback changed after authority validation: {name}")
            temporary = target.with_name(f".{target.name}.precurrent-{release}.tmp")
            allowed_temporaries.add(temporary.name)
            try:
                temporary_status = temporary.lstat()
            except FileNotFoundError:
                temporary_status = None
            if temporary_status is not None and (
                    temporary.is_symlink() or not stat.S_ISREG(temporary_status.st_mode) or
                    temporary.resolve(strict=True).parent != RUNTIME.resolve(strict=True) or
                    temporary_status.st_uid != os.geteuid() or temporary_status.st_nlink != 1 or
                    stat.S_IMODE(temporary_status.st_mode) not in {0o600, metadata["mode"]}):
                raise SystemExit(f"unsafe pre-current restore temporary: {temporary}")
            plans.append((name, target, temporary, metadata, content, temporary_status is not None))
        else:
            plans.append((name, target, None, None, None, False))
    for candidate in RUNTIME.iterdir():
        if ".precurrent-" in candidate.name and candidate.name.endswith(".tmp") and candidate.name not in allowed_temporaries:
            raise SystemExit(f"unknown pre-current restore temporary: {candidate}")

    current_temporary_exists = False
    current_temporary_identity = None

    def validated_current_intent():
        intent_status = current_temporary.lstat()
        if (not stat.S_ISLNK(intent_status.st_mode) or intent_status.st_uid != os.geteuid() or
                intent_status.st_nlink != 1 or current_temporary.parent.resolve(strict=True) != ROOT):
            raise SystemExit("unsafe caught-current restore temporary")
        intent_target = os.readlink(current_temporary)
        if intent_target != expected_current:
            raise SystemExit("caught-current restore temporary binds another target")
        return (
            intent_status.st_dev, intent_status.st_ino, intent_status.st_mode,
            intent_status.st_uid, intent_status.st_nlink, intent_target,
        )

    if caught and observed_current in {expected_current, selected_target} and expected_current is not None:
        try:
            current_temporary_identity = validated_current_intent()
        except FileNotFoundError:
            pass
        else:
            current_temporary_exists = True
    else:
        try:
            current_temporary.lstat()
        except FileNotFoundError:
            pass
        else:
            raise SystemExit("unexpected caught-current restore temporary")

    # No live target changes until every source, target, temporary, gate,
    # wrapper, authority and pair has passed the full preflight above.
    prewrite_gate_status, prewrite_gate_raw = regular_bytes(gate, "pre-current gate before first restore write")
    prewrite_gate_identity = (
        prewrite_gate_status.st_dev, prewrite_gate_status.st_ino, prewrite_gate_status.st_mode,
        prewrite_gate_status.st_uid, prewrite_gate_status.st_nlink, prewrite_gate_raw,
    )
    if actual_current() != observed_current or prewrite_gate_identity != gate_identity:
        raise SystemExit("pre-current current or gate changed during restore preflight")
    if caught and observed_current == selected_target:
        if expected_current is None:
            CURRENT.unlink()
        else:
            if not current_temporary_exists:
                os.symlink(expected_current, current_temporary)
                current_temporary_identity = validated_current_intent()
                pause("after_caught_current_temp_create_before_root_fsync")
                if validated_current_intent() != current_temporary_identity:
                    raise SystemExit("caught-current restore intent changed before intent fsync")
                fsync_root()
                pause("after_caught_current_temp_fsync")
            current_temporary_now = validated_current_intent()
            if current_temporary_now != current_temporary_identity:
                raise SystemExit("caught-current restore intent changed before current replace")
            os.replace(current_temporary, CURRENT)
        fsync_root("after_caught_current_restore_before_root_fsync")
        pause("after_caught_current_restore_fsync")
        caught_gate_status, caught_gate_raw = regular_bytes(
            gate, "pre-current gate after caught current restore",
        )
        caught_gate_identity = (
            caught_gate_status.st_dev, caught_gate_status.st_ino, caught_gate_status.st_mode,
            caught_gate_status.st_uid, caught_gate_status.st_nlink, caught_gate_raw,
        )
        if actual_current() != expected_current or caught_gate_identity != gate_identity:
            raise SystemExit("caught rollback current or gate changed before live restore")
    elif caught and current_temporary_exists:
        current_temporary_now = validated_current_intent()
        if current_temporary_now != current_temporary_identity:
            raise SystemExit("caught-current restore intent changed before cleanup")
        current_temporary.unlink()
        fsync_root("after_caught_current_intent_unlink_before_root_fsync")
        pause("after_caught_current_intent_unlink_fsync")
    for name, target, temporary, metadata, content, temporary_exists in plans:
        if temporary is not None:
            flags = os.O_WRONLY | (os.O_TRUNC if temporary_exists else os.O_CREAT | os.O_EXCL)
            descriptor = os.open(str(temporary), flags, 0o600)
            try:
                written = 0
                while written < len(content):
                    count = os.write(descriptor, content[written:])
                    if count <= 0:
                        raise SystemExit(f"unable to restore pre-current runtime file: {name}")
                    written += count
                os.fchmod(descriptor, metadata["mode"])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            pause(f"after_precurrent_restore_temp_fsync_{name}")
            os.replace(temporary, target)
        else:
            try:
                target.lstat()
            except FileNotFoundError:
                pass
            else:
                target.unlink()
        fsync_directory(RUNTIME, f"after_precurrent_restore_{name}_fsync")
    if actual_current() != expected_current:
        raise SystemExit("current changed during pre-current rollback restore")
    state_with_gate = runtime_state()
    if state_with_gate["deployment_phase"] is None:
        raise SystemExit("pre-current deployment phase gate disappeared during restore")
    final_gate_status, final_gate_raw = regular_bytes(gate, "pre-current deployment phase gate before unlink")
    final_gate_identity = (
        final_gate_status.st_dev, final_gate_status.st_ino, final_gate_status.st_mode,
        final_gate_status.st_uid, final_gate_status.st_nlink, final_gate_raw,
    )
    if final_gate_identity != gate_identity:
        raise SystemExit("pre-current deployment phase gate changed during restore")
    restored_with_gate = runtime_state()
    restored_for_validation = dict(restored_with_gate)
    restored_for_validation["deployment_phase"] = None
    validate_cleanup_manifest(manifest, state=restored_for_validation)
    if (rollback_authority_profile(manifest, expected_current) != authority["profile"] or
            restored_with_gate["current_target"] != expected_current):
        raise SystemExit("pre-current rollback did not restore its durable authority state")
    if preserve:
        return
    gate.unlink()
    pause("after_precurrent_gate_unlink_before_dir_fsync")
    fsync_directory(RUNTIME, "after_precurrent_gate_unlink_fsync")
    restored_state = runtime_state()
    validate_cleanup_manifest(manifest, state=restored_state)
    if (rollback_authority_profile(manifest, expected_current) != authority["profile"] or
            restored_state["current_target"] != expected_current):
        raise SystemExit("pre-current rollback did not restore its durable authority state")
    pause("before_detached_cleanup_create")
    create(str(rollback), "__ABSENT__" if expected_current is None else expected_current)


validate_runtime_root()

if MODE == "seal":
    seal()
elif MODE == "verify":
    verify()
elif MODE == "recover-precurrent":
    recover_precurrent()
elif MODE == "recover-caught":
    recover_precurrent(caught=True)
elif MODE == "recover-caught-preserve":
    recover_precurrent(caught=True, preserve=True)
elif MODE == "resume":
    resume()
elif MODE == "create":
    create()
else:
    raise SystemExit("unsupported detached cleanup mode")
