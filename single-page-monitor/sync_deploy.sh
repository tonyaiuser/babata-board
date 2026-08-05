#!/usr/bin/env bash
# Build, durably publish, and atomically activate one immutable release.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SOURCE_DIR}/.." && pwd -P)"
DEPLOY_ROOT="${SP_SINGLE_PAGE_DEPLOY_ROOT:-$HOME/.spspy-single-page-monitor}"
RUNTIME_DIR="${DEPLOY_ROOT}/single-page-monitor"
RELEASES_DIR="${DEPLOY_ROOT}/releases"
DATA_DIR="${SP_SINGLE_PAGE_DATA_DIR:-${RUNTIME_DIR}/data}"
LOCK_PATH="${SP_SINGLE_PAGE_LOCK_DIR:-${DATA_DIR}/run_daily.lock}"
DEPLOY_LOCK_PATH="${DEPLOY_ROOT}/deploy.lock"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
NODE_BIN="${NODE_BIN:-$(command -v node)}"
NPM_BIN="${NPM_BIN:-$(command -v npm)}"
PLUTIL_BIN="${PLUTIL_BIN:-/usr/bin/plutil}"
LOCK_HELPER="${SOURCE_DIR}/scripts/locked_exec.py"

"${PYTHON_BIN}" - "${DEPLOY_ROOT}" "${RUNTIME_DIR}" "${RELEASES_DIR}" \
  "${DEPLOY_ROOT}/.pages" "${RUNTIME_DIR}/logs" "${RUNTIME_DIR}/reports" "${DATA_DIR}" <<'PY' || exit 70
import os, pathlib, stat, sys

root, runtime, releases, pages, logs, reports, data = map(pathlib.Path, sys.argv[1:])
if not root.is_absolute() or not runtime.is_absolute():
    raise SystemExit("deploy and runtime roots must be absolute")
try:
    root_status = root.lstat()
except FileNotFoundError:
    parent_status = root.parent.lstat()
    if root.parent.is_symlink() or not stat.S_ISDIR(parent_status.st_mode):
        raise SystemExit("deploy root parent is unsafe")
    os.mkdir(root, 0o755)
    root_status = root.lstat()
if root.is_symlink() or not stat.S_ISDIR(root_status.st_mode):
    raise SystemExit("deploy root must be a real directory")
root_real = root.resolve(strict=True)

def ensure_direct(path, parent, label):
    if path.parent != parent:
        raise SystemExit(f"{label} is not a direct child of its required parent")
    try:
        status = path.lstat()
    except FileNotFoundError:
        os.mkdir(path, 0o755)
        status = path.lstat()
    if (path.is_symlink() or not stat.S_ISDIR(status.st_mode) or
            path.resolve(strict=True).parent != parent.resolve(strict=True)):
        raise SystemExit(f"{label} must be a real direct child directory")

ensure_direct(runtime, root, "runtime root")
ensure_direct(releases, root, "releases root")
ensure_direct(pages, root, "pages root")
ensure_direct(logs, runtime, "runtime logs")
ensure_direct(reports, runtime, "runtime reports")
if data == runtime / "data":
    try:
        ensure_direct(data, runtime, "runtime data")
    except SystemExit as exc:
        # Keep the public lock-root diagnostic stable even though the fixed
        # deploy-root lock now validates the runtime tree before the nested
        # data-lock helper gets a chance to report the same unsafe symlink.
        if str(exc) == "runtime data must be a real direct child directory":
            raise SystemExit("runtime lock root must be a real directory") from exc
        raise
else:
    data.mkdir(parents=True, exist_ok=True)
    data_status = data.lstat()
    if data.is_symlink() or not stat.S_ISDIR(data_status.st_mode):
        raise SystemExit("external data root must be a real directory")
PY

# Every deploy first owns a lock on the immutable deploy-root identity.  This
# serializes the complete startup-resume -> staging -> commit/rollback lifetime
# even when two callers choose different external DATA_DIR values.  Daily jobs
# intentionally do not take this lock; they continue to share only the data
# runtime lock acquired below.
if [[ -z "${SP_SINGLE_PAGE_DEPLOY_LOCK_ACTIVE:-}" ]]; then
  exec "${PYTHON_BIN}" "${LOCK_HELPER}" \
    --lock "${DEPLOY_LOCK_PATH}" --lock-dir "${DEPLOY_ROOT}" \
    --fd-env SP_SINGLE_PAGE_DEPLOY_LOCK_FD \
    --active-env SP_SINGLE_PAGE_DEPLOY_LOCK_ACTIVE --label "single-page deployment" \
    --busy-exit 75 -- /bin/bash "${SOURCE_DIR}/sync_deploy.sh" "$@"
fi
"${PYTHON_BIN}" "${LOCK_HELPER}" \
  --lock "${DEPLOY_LOCK_PATH}" --lock-dir "${DEPLOY_ROOT}" \
  --fd-env SP_SINGLE_PAGE_DEPLOY_LOCK_FD \
  --active-env SP_SINGLE_PAGE_DEPLOY_LOCK_ACTIVE --label "single-page deployment" \
  --busy-exit 75 --validate-only

# The inherited data lock still serializes deployment writes with daily jobs.
# Both descriptors remain inherited across the nested exec chain and are
# released by the kernel on every ordinary exit or crash.
if [[ -z "${SP_SINGLE_PAGE_LOCK_ACTIVE:-}" ]]; then
  exec "${PYTHON_BIN}" "${LOCK_HELPER}" \
    --lock "${LOCK_PATH}" --lock-dir "${DATA_DIR}" --fd-env SP_SINGLE_PAGE_LOCK_FD \
    --active-env SP_SINGLE_PAGE_LOCK_ACTIVE --label "single-page runtime" \
    --busy-exit 75 -- /bin/bash "${SOURCE_DIR}/sync_deploy.sh" "$@"
fi
"${PYTHON_BIN}" "${LOCK_HELPER}" \
  --lock "${LOCK_PATH}" --lock-dir "${DATA_DIR}" --fd-env SP_SINGLE_PAGE_LOCK_FD \
  --active-env SP_SINGLE_PAGE_LOCK_ACTIVE --label "single-page runtime" \
  --busy-exit 75 --validate-only

if [[ "${SP_SINGLE_PAGE_TEST_MODE:-0}" == "1" && \
      "${SP_SINGLE_PAGE_TEST_EXIT_AFTER_LOCK:-0}" == "1" ]]; then
  exit 96
fi

RELEASE_ID="$(date -u '+%Y%m%dT%H%M%SZ')-$$"
STAGE_DIR="${RELEASES_DIR}/.${RELEASE_ID}.stage"
FINAL_RELEASE="${RELEASES_DIR}/${RELEASE_ID}"
ROLLBACK_DIR="${DEPLOY_ROOT}/.rollback-${RELEASE_ID}"
OLD_CURRENT_PRESENT=0
OLD_CURRENT_TARGET=""
LIVE_CHANGED=0
COMMITTED=0
PHASE_ACTIVE=0
GATE_INSTALLED=0
PRESERVE_TRANSACTION=0
PRESERVE_CAUGHT_TRANSACTION=0
PHASE_GATE="${RUNTIME_DIR}/.deployment-phase"
MIGRATION_MARKER="${RUNTIME_DIR}/.stable-health-migration.json"
MIGRATION_STATE=""
LEGACY_CHECKER_SHA=""
TRUSTED_PRODUCTION_LEGACY_SHA="687e4d40ffd56c01444d83620560f9734b1ecfbfd2afb2de112cd4defadc9362"

fsync_directory() {
  "${PYTHON_BIN}" - "$1" <<'PY'
import os, sys
descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

acquire_phase_lock() {
  exec 9<"${RUNTIME_DIR}"
  "${PYTHON_BIN}" - "${RUNTIME_DIR}" 9 <<'PY'
import errno, fcntl, os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
fd = int(sys.argv[2])
status = path.lstat()
if not stat.S_ISDIR(status.st_mode) or path.is_symlink():
    raise SystemExit("runtime phase lock root must be a real directory")
fd_status = os.fstat(fd)
if (fd_status.st_dev, fd_status.st_ino) != (status.st_dev, status.st_ino):
    raise SystemExit("runtime phase descriptor/path inode mismatch")
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError as exc:
    if exc.errno in (errno.EACCES, errno.EAGAIN):
        raise SystemExit(75)
    raise
PY
  PHASE_ACTIVE=1
}

install_phase_gate() {
  local mode="$1"
  local fallback_sha="$2"
  local wrapper="$3"
  "${PYTHON_BIN}" - "${PHASE_GATE}" "${RELEASE_ID}:$$" "${mode}" \
    "${fallback_sha}" "${wrapper}" <<'PY'
import hashlib, json, os, pathlib, re, stat, sys
path = pathlib.Path(sys.argv[1])
token = sys.argv[2]
mode = sys.argv[3]
fallback_sha = sys.argv[4]
wrapper = pathlib.Path(sys.argv[5])
wrapper_status = wrapper.lstat()
if wrapper.is_symlink() or not stat.S_ISREG(wrapper_status.st_mode):
    raise SystemExit(f"unsafe stable health wrapper: {wrapper}")
wrapper_bytes = wrapper.read_bytes()
id_match = re.search(rb'const STABLE_WRAPPER_ID = "([^"]+)";', wrapper_bytes)
version_match = re.search(rb'const STABLE_WRAPPER_VERSION = ([0-9]+);', wrapper_bytes)
if not id_match or not version_match:
    raise SystemExit("stable health wrapper identity is missing")
if mode not in {"legacy_fallback", "fail_closed"}:
    raise SystemExit(f"unsupported deployment phase mode: {mode}")
if mode == "legacy_fallback" and not re.fullmatch(r"[a-f0-9]{64}", fallback_sha):
    raise SystemExit("legacy fallback phase requires a trusted checker SHA")
try:
    status = path.lstat()
except FileNotFoundError:
    status = None
if status is not None and (not stat.S_ISREG(status.st_mode) or path.is_symlink()):
    raise SystemExit(f"unsafe deployment phase gate: {path}")
temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
payload = {
    "schema": 1,
    "kind": "spspy-single-page-deployment-phase",
    "mode": mode,
    "release_id": token,
    "wrapper_id": id_match.group(1).decode("ascii"),
    "wrapper_version": int(version_match.group(1)),
    "wrapper_sha256": hashlib.sha256(wrapper_bytes).hexdigest(),
    "fallback_sha256": fallback_sha if mode == "legacy_fallback" else None,
}
try:
    with temporary.open("x", encoding="ascii") as handle:
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    descriptor = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
}

install_migration_marker() {
  local wrapper="${RUNTIME_DIR}/check_health.mjs"
  "${PYTHON_BIN}" - "${MIGRATION_MARKER}" "${wrapper}" <<'PY'
import hashlib, json, os, pathlib, re, stat, sys
path = pathlib.Path(sys.argv[1])
wrapper = pathlib.Path(sys.argv[2])

def write_all(descriptor, content, context):
    offset = 0
    test_mode = os.environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1"
    forced_max = 0
    if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_WRITE_MAX_BYTES"):
        forced_max = int(os.environ["SP_SINGLE_PAGE_TEST_WRITE_MAX_BYTES"], 10)
        if forced_max < 1 or forced_max > 3:
            raise OSError("forced short-write size must be 1..3")
    if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_RAISE_WRITE_CONTEXT") == context:
        raise OSError(f"injected write failure: {context}")
    while offset < len(content):
        if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_ZERO_WRITE_CONTEXT") == context:
            count = 0
        else:
            chunk = content[offset:]
            if forced_max:
                chunk = chunk[:min(forced_max, (offset % forced_max) + 1)]
            count = os.write(descriptor, chunk)
        if count <= 0:
            raise OSError(f"zero-length write while publishing {context}")
        offset += count

status = wrapper.lstat()
if wrapper.is_symlink() or not stat.S_ISREG(status.st_mode):
    raise SystemExit(f"unsafe installed stable health wrapper: {wrapper}")
wrapper_bytes = wrapper.read_bytes()
id_match = re.search(rb'const STABLE_WRAPPER_ID = "([^"]+)";', wrapper_bytes)
version_match = re.search(rb'const STABLE_WRAPPER_VERSION = ([0-9]+);', wrapper_bytes)
if not id_match or not version_match:
    raise SystemExit("installed stable health wrapper identity is missing")
try:
    old_status = path.lstat()
except FileNotFoundError:
    old_status = None
if old_status is not None and (path.is_symlink() or not stat.S_ISREG(old_status.st_mode)):
    raise SystemExit(f"unsafe stable migration marker: {path}")
payload = {
    "schema": 2,
    "kind": "spspy-single-page-stable-health-migration",
    "wrapper_id": id_match.group(1).decode("ascii"),
    "wrapper_version": int(version_match.group(1)),
    "wrapper_sha256": hashlib.sha256(wrapper_bytes).hexdigest(),
}
temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
try:
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        payload_bytes = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        try:
            write_all(descriptor, payload_bytes, "marker-install")
        except OSError as exc:
            # Exit 74 is private to this shell/Python boundary.  It lets the
            # caller preserve the sealed gate and rollback authority only for
            # an indeterminate marker write, while ordinary post-replace fsync
            # failures keep using the established caught-rollback recovery.
            print(str(exc), file=sys.stderr)
            raise SystemExit(74) from exc
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    if os.environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1" and os.environ.get("SP_SINGLE_PAGE_TEST_FAIL_MARKER_FSYNC") == "1":
        raise OSError("injected stable migration marker directory fsync failure")
    parent = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
}

# A process can be killed after `current` has been renamed and its parent
# directory fsynced, but before the migration marker is installed.  Do not
# blindly treat that state as a first migration (or silently accept a random
# marker).  The only recoverable form is a complete, immutable selected
# release whose three stable runtime files are *byte-for-byte* the files in
# that release.  This makes the repair an idempotent completion of the same
# durable commit rather than a new, partially authenticated migration.
recover_durable_current_marker() {
  "${PYTHON_BIN}" - "${DEPLOY_ROOT}" "${RUNTIME_DIR}" "${MIGRATION_MARKER}" \
    "${TRUSTED_PRODUCTION_LEGACY_SHA}" <<'PY'
import hashlib, json, os, pathlib, re, secrets, stat, sys, time

root = pathlib.Path(sys.argv[1]).resolve()
runtime = pathlib.Path(sys.argv[2])
marker = pathlib.Path(sys.argv[3])
trusted_legacy = {sys.argv[4]}
if os.environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1":
    test_legacy = os.environ.get("SP_SINGLE_PAGE_TEST_TRUSTED_LEGACY_SHA", "")
    if re.fullmatch(r"[a-f0-9]{64}", test_legacy):
        trusted_legacy.add(test_legacy)
releases = root / "releases"
current = root / "current"
marker_kind = "spspy-single-page-stable-health-migration"
wrapper_id = "spspy-single-page-stable-health"

def write_all(descriptor, content, context):
    offset = 0
    test_mode = os.environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1"
    forced_max = 0
    if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_WRITE_MAX_BYTES"):
        forced_max = int(os.environ["SP_SINGLE_PAGE_TEST_WRITE_MAX_BYTES"], 10)
        if forced_max < 1 or forced_max > 3:
            raise OSError("forced short-write size must be 1..3")
    if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_RAISE_WRITE_CONTEXT") == context:
        raise OSError(f"injected write failure: {context}")
    while offset < len(content):
        if test_mode and os.environ.get("SP_SINGLE_PAGE_TEST_ZERO_WRITE_CONTEXT") == context:
            count = 0
        else:
            chunk = content[offset:]
            if forced_max:
                chunk = chunk[:min(forced_max, (offset % forced_max) + 1)]
            count = os.write(descriptor, chunk)
        if count <= 0:
            raise OSError(f"zero-length write while publishing {context}")
        offset += count

def regular(path, label):
    try:
        status = path.lstat()
    except FileNotFoundError as exc:
        raise SystemExit(f"{label} is missing: {path}") from exc
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise SystemExit(f"{label} is unsafe: {path}")
    resolved = path.resolve(strict=True)
    return status, resolved

def directory(path, label, expected_parent=None):
    try:
        status = path.lstat()
    except FileNotFoundError as exc:
        raise SystemExit(f"{label} is missing: {path}") from exc
    if path.is_symlink() or not stat.S_ISDIR(status.st_mode):
        raise SystemExit(f"{label} is unsafe: {path}")
    resolved = path.resolve(strict=True)
    if expected_parent is not None and resolved.parent != expected_parent:
        raise SystemExit(f"{label} resolves outside its expected parent: {path}")
    return resolved

def decode_marker(raw, label):
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid stable migration marker {label}: {exc}")
    keys = {"schema", "kind", "wrapper_id", "wrapper_version", "wrapper_sha256"}
    if not isinstance(payload, dict) or set(payload) != keys:
        raise SystemExit(f"unsupported stable migration marker schema {label}")
    if (not isinstance(payload.get("schema"), int) or isinstance(payload["schema"], bool) or
            payload["schema"] not in {1, 2} or payload.get("kind") != marker_kind or
            payload.get("wrapper_id") != wrapper_id or
            not isinstance(payload.get("wrapper_version"), int) or isinstance(payload["wrapper_version"], bool) or
            payload["wrapper_version"] <= 0 or
            not isinstance(payload.get("wrapper_sha256"), str) or
            not re.fullmatch(r"[a-f0-9]{64}", payload["wrapper_sha256"])):
        raise SystemExit(f"unsupported stable migration marker schema {label}")
    return payload

def marker_payload(path):
    try:
        status = path.lstat()
    except FileNotFoundError:
        return None
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise SystemExit(f"unsafe stable migration marker: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"cannot read stable migration marker: {path}: {exc}")
    return decode_marker(raw, str(path)), raw

def test_pause(point):
    if (os.environ.get("SP_SINGLE_PAGE_TEST_MODE") != "1" or
            os.environ.get("SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT") != point):
        return
    ready_raw = os.environ.get("SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE", "")
    continue_raw = os.environ.get("SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE", "")
    if not ready_raw or not continue_raw:
        raise SystemExit("recovery pause hook requires ready and continue paths")
    ready = pathlib.Path(ready_raw)
    with ready.open("x", encoding="ascii") as handle:
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        os.fsync(handle.fileno())
    while not pathlib.Path(continue_raw).exists():
        time.sleep(0.02)

# No current means this is not this narrowly-defined post-commit recovery.
try:
    current_status = current.lstat()
except FileNotFoundError:
    print("none")
    raise SystemExit(0)
if not stat.S_ISLNK(current_status.st_mode):
    raise SystemExit(f"refusing unsafe non-symlink current path: {current}")
raw = os.readlink(current)
parts = pathlib.PurePosixPath(raw).parts
if os.path.isabs(raw) or len(parts) != 2 or parts[0] != "releases" or parts[1] in {"", ".", ".."}:
    raise SystemExit(f"refusing unsafe current target: {raw}")
release_name = parts[1]
rollback = root / f".rollback-{release_name}"
cleanup_record = root / f".rollback-cleanup-{release_name}.json"
# `.pending` is understood only as a complete record produced by the legacy
# publisher.  New records never reuse a fixed temporary pathname: a kill after
# O_EXCL but before the first durable byte must not turn into a permanent
# malformed record on the next run.
cleanup_pending = cleanup_record.with_name(cleanup_record.name + ".pending")
cleanup_temp_pattern = re.compile(rf"{re.escape(cleanup_record.name)}\.tmp-[a-f0-9]{{32}}")
allowed_rollback = {
    "run_daily.sh", "run_daily.sh.present",
    "check_health.mjs", "check_health.mjs.present",
    "locked_exec.py", "locked_exec.py.present",
    ".precommit_check_health.mjs", ".precommit_check_health.mjs.present",
    ".stable-health-migration.json", ".stable-health-migration.json.present",
    ".rollback-manifest.json",
}

def uncommitted_cleanup_temporaries():
    return [candidate for candidate in root.iterdir() if cleanup_temp_pattern.fullmatch(candidate.name)]

def discard_uncommitted_cleanup_temporary(candidate):
    """Discard only a private, non-committed scratch file from this protocol.

    Scratch contents may be empty or truncated after SIGKILL, so they cannot
    be parsed for proof.  The exact random namespace, regular-file identity,
    restrictive mode, single link, owner, and direct deploy-root parent are
    the proof boundary.  Anything else remains fail-closed.
    """
    status = candidate.lstat()
    if (candidate.is_symlink() or not stat.S_ISREG(status.st_mode) or
            stat.S_IMODE(status.st_mode) != 0o600 or status.st_uid != os.geteuid() or
            status.st_nlink != 1 or candidate.resolve(strict=True).parent != root):
        raise SystemExit(f"unsafe uncommitted rollback cleanup temporary: {candidate}")
    candidate.unlink()

releases_real = directory(releases, "releases directory")
runtime_real = directory(runtime, "stable runtime")
release = root / "releases" / parts[1]
release_real = directory(release, "current release", releases_real)
monitor = release / "single-page-monitor"
monitor_real = directory(monitor, "current monitor", release_real)

# An already-authenticated v2 marker deliberately does not require its old
# selected release to contain today's stable wrappers: stable launchers are
# meant to keep pinning an older immutable release across upgrades.  Only a
# missing or legacy-v1 marker enters the much stricter repair path below.
marker_result = marker_payload(marker)
old, old_raw = marker_result if marker_result is not None else (None, None)
_, runtime_health_real = regular(runtime / "check_health.mjs", "runtime health wrapper")
if runtime_health_real.parent != runtime_real:
    raise SystemExit("runtime health wrapper resolves outside stable runtime")
runtime_health = runtime_health_real.read_bytes()
runtime_id = re.search(rb'const STABLE_WRAPPER_ID = "([^"]+)";', runtime_health)
runtime_version = re.search(rb'const STABLE_WRAPPER_VERSION = ([0-9]+);', runtime_health)
if not runtime_id or not runtime_version or runtime_id.group(1).decode("ascii") != wrapper_id:
    raise SystemExit("runtime stable health wrapper identity is missing")
runtime_marker = {
    "schema": 2,
    "kind": marker_kind,
    "wrapper_id": wrapper_id,
    "wrapper_version": int(runtime_version.group(1)),
    "wrapper_sha256": hashlib.sha256(runtime_health).hexdigest(),
}
gate = runtime / ".deployment-phase"
fallback = runtime / ".precommit_check_health.mjs"
gate_exists = gate.exists() or gate.is_symlink()
fallback_exists = fallback.exists() or fallback.is_symlink()
marker_installed = old == runtime_marker
cleanup_only = False
tombstone_resume = False
if marker_installed and not gate_exists and not fallback_exists:
    try:
        rollback_status = rollback.lstat()
    except FileNotFoundError:
        rollback_status = None
    try:
        cleanup_record_status = cleanup_record.lstat()
    except FileNotFoundError:
        cleanup_record_status = None
    try:
        cleanup_pending_status = cleanup_pending.lstat()
    except FileNotFoundError:
        cleanup_pending_status = None
    cleanup_temporaries = uncommitted_cleanup_temporaries()
    if cleanup_temporaries and (cleanup_record_status is not None or cleanup_pending_status is not None):
        raise SystemExit("committed rollback cleanup record has an unexpected temporary")
    # A random temporary has no deletion authority.  It is safe to discard
    # only after the strict private-file checks above; then a later run may
    # publish a fresh complete record with a different nonce.
    for cleanup_temporary in cleanup_temporaries:
        discard_uncommitted_cleanup_temporary(cleanup_temporary)
    if cleanup_temporaries:
        descriptor = os.open(str(root), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if rollback_status is None and cleanup_record_status is None and cleanup_pending_status is None:
        print("migrated")
        raise SystemExit(0)
    if rollback_status is not None and (rollback.is_symlink() or not stat.S_ISDIR(rollback_status.st_mode)):
        raise SystemExit(f"unsafe selected-release rollback residue: {rollback}")
    if cleanup_record_status is not None and (cleanup_record.is_symlink() or not stat.S_ISREG(cleanup_record_status.st_mode)):
        raise SystemExit(f"unsafe selected-release rollback cleanup record: {cleanup_record}")
    if cleanup_pending_status is not None and (cleanup_pending.is_symlink() or not stat.S_ISREG(cleanup_pending_status.st_mode)):
        raise SystemExit(f"unsafe selected-release rollback cleanup pending record: {cleanup_pending}")
    if cleanup_record_status is not None and cleanup_pending_status is not None:
        raise SystemExit("multiple selected-release cleanup records")
    if rollback_status is None and cleanup_pending_status is not None:
        raise SystemExit("pending cleanup record exists without intact rollback journal")
    cleanup_only = True
    tombstone_resume = rollback_status is None
if marker_installed and gate_exists and not fallback_exists:
    # A kill before the current commit leaves an authenticated old marker and
    # a gate naming the not-yet-selected release.  That is not marker recovery:
    # leave the marker untouched and let the ordinary serialized deployment
    # replace this stale pre-current transaction.  A gate claiming the selected
    # current falls through to the strict post-current proof below.
    gate_status = gate.lstat()
    if not gate.is_symlink() and stat.S_ISREG(gate_status.st_mode):
        try:
            early_phase = json.loads(gate.read_text(encoding="ascii"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            early_phase = None
        release_id = early_phase.get("release_id") if isinstance(early_phase, dict) else None
        if isinstance(release_id, str) and release_id.split(":", 1)[0] != parts[1]:
            print("migrated_precurrent")
            raise SystemExit(0)

scripts = monitor / "scripts"
scripts_real = directory(scripts, "current release scripts", monitor_real)

# The release is only a proof source if it is immutable all the way down.
for walk_root, dirnames, filenames in os.walk(release_real, followlinks=False):
    current_dir = pathlib.Path(walk_root)
    current_status = current_dir.lstat()
    if current_dir.is_symlink() or not stat.S_ISDIR(current_status.st_mode) or current_status.st_mode & 0o222:
        raise SystemExit(f"selected current release is not readonly: {current_dir}")
    for name in [*dirnames, *filenames]:
        candidate = current_dir / name
        status = candidate.lstat()
        if candidate.is_symlink():
            resolved = candidate.resolve(strict=True)
            if release_real not in (resolved, *resolved.parents):
                raise SystemExit(f"selected current release symlink escapes release: {candidate}")
        elif not (stat.S_ISREG(status.st_mode) or stat.S_ISDIR(status.st_mode)) or status.st_mode & 0o222:
            raise SystemExit(f"selected current release contains unsafe or writable path: {candidate}")

pairs = (
    (runtime / "run_daily.sh", monitor / "stable_run_daily.sh", "runtime daily wrapper"),
    (runtime / "check_health.mjs", monitor / "stable_check_health.mjs", "runtime health wrapper"),
    (runtime / "locked_exec.py", scripts / "locked_exec.py", "runtime lock helper"),
)
release_bytes = {}
for installed, expected, label in pairs:
    _, installed_real = regular(installed, label)
    _, expected_real = regular(expected, f"selected {label}")
    if installed_real.parent != runtime_real:
        raise SystemExit(f"{label} resolves outside stable runtime")
    if expected_real.parent not in {monitor_real, scripts_real} or release_real not in expected_real.parents:
        raise SystemExit(f"selected {label} escapes selected release: {expected}")
    actual = installed_real.read_bytes()
    wanted = expected_real.read_bytes()
    if actual != wanted:
        raise SystemExit(f"{label} does not exactly match selected release")
    release_bytes[label] = actual

health = release_bytes["runtime health wrapper"]
id_match = re.search(rb'const STABLE_WRAPPER_ID = "([^"]+)";', health)
version_match = re.search(rb'const STABLE_WRAPPER_VERSION = ([0-9]+);', health)
if not id_match or not version_match or id_match.group(1).decode("ascii") != wrapper_id:
    raise SystemExit("selected stable health wrapper identity is missing")
expected_marker = {
    "schema": 2,
    "kind": marker_kind,
    "wrapper_id": wrapper_id,
    "wrapper_version": int(version_match.group(1)),
    "wrapper_sha256": hashlib.sha256(health).hexdigest(),
}
if expected_marker != runtime_marker:
    raise SystemExit("runtime health wrapper differs from selected release")

def read_cleanup_record(record_path=cleanup_record):
    _, record_real = regular(record_path, "rollback cleanup record")
    if record_real.parent != root:
        raise SystemExit("rollback cleanup record resolves outside deploy root")
    try:
        payload = json.loads(record_real.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid rollback cleanup record: {exc}")
    keys = {"schema", "kind", "release", "current_target", "marker_sha256", "nonce", "tombstone", "entries"}
    nonce = payload.get("nonce") if isinstance(payload, dict) else None
    expected_tombstone = f".rollback-tombstone-{release_name}-{nonce}" if isinstance(nonce, str) else None
    entries = payload.get("entries") if isinstance(payload, dict) else None
    base_required = {
        "run_daily.sh", "run_daily.sh.present",
        "check_health.mjs", "check_health.mjs.present",
    }
    helper_pair = {
        "locked_exec.py", "locked_exec.py.present",
    }
    entry_names = set(entries) if isinstance(entries, dict) else set()
    backup_entry_names = entry_names - {".rollback-manifest.json"}
    optional_pairs = (
        {".stable-health-migration.json", ".stable-health-migration.json.present"},
        {".precommit_check_health.mjs", ".precommit_check_health.mjs.present"},
    )
    legacy_two_pair = (
        isinstance(entries, dict) and backup_entry_names == base_required and
        isinstance(entries.get("check_health.mjs"), dict) and
        entries["check_health.mjs"].get("sha256") in trusted_legacy
    )
    helper_intersection = helper_pair.intersection(backup_entry_names)
    optional_pairs_complete = all(
        not pair.intersection(backup_entry_names) or pair.intersection(backup_entry_names) == pair
        for pair in optional_pairs
    )
    if (not isinstance(payload, dict) or set(payload) != keys or
            type(payload.get("schema")) is not int or payload["schema"] != 1 or
            payload.get("kind") != "spspy-single-page-rollback-cleanup" or
            payload.get("release") != release_name or payload.get("current_target") != raw or
            not isinstance(payload.get("marker_sha256"), str) or
            payload["marker_sha256"] != hashlib.sha256(marker.read_bytes()).hexdigest() or
            not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{32}", nonce) or
            payload.get("tombstone") != expected_tombstone or not isinstance(entries, dict) or
            not base_required.issubset(backup_entry_names) or not entry_names.issubset(allowed_rollback) or
            (not legacy_two_pair and helper_intersection != helper_pair) or
            not optional_pairs_complete or
            record_path.name not in {cleanup_record.name, cleanup_pending.name}):
        raise SystemExit("rollback cleanup record does not bind selected committed release")
    for name, metadata in entries.items():
        if (not isinstance(metadata, dict) or set(metadata) != {"mode", "sha256", "size"} or
                not isinstance(metadata.get("mode"), int) or isinstance(metadata["mode"], bool) or
                metadata["mode"] < 0 or metadata["mode"] > 0o7777 or
                not isinstance(metadata.get("size"), int) or isinstance(metadata["size"], bool) or metadata["size"] < 0 or
                not isinstance(metadata.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", metadata["sha256"])):
            raise SystemExit(f"invalid rollback cleanup manifest entry: {name}")
        if name.endswith(".present") and (
                metadata["size"] != 0 or
                metadata["sha256"] != hashlib.sha256(b"").hexdigest()):
            raise SystemExit(f"invalid rollback cleanup sentinel metadata: {name}")
    return payload

def finish_tombstone_cleanup(payload):
    tombstone = root / payload["tombstone"]
    try:
        tombstone_status = tombstone.lstat()
    except FileNotFoundError:
        tombstone_status = None
    if tombstone_status is not None:
        if tombstone.is_symlink() or not stat.S_ISDIR(tombstone_status.st_mode) or tombstone.resolve(strict=True).parent != root:
            raise SystemExit(f"unsafe rollback tombstone: {tombstone}")
        entries = list(tombstone.iterdir())
        for entry in entries:
            metadata = payload["entries"].get(entry.name)
            status = entry.lstat()
            if (metadata is None or entry.is_symlink() or not stat.S_ISREG(status.st_mode) or
                    entry.resolve(strict=True).parent != tombstone.resolve(strict=True)):
                raise SystemExit(f"unknown or unsafe rollback tombstone entry: {entry}")
            content = entry.read_bytes()
            if (stat.S_IMODE(status.st_mode) != metadata["mode"] or len(content) != metadata["size"] or
                    hashlib.sha256(content).hexdigest() != metadata["sha256"]):
                raise SystemExit(f"rollback tombstone entry does not match durable manifest: {entry}")
        for entry in sorted(entries, key=lambda item: item.name):
            entry.unlink()
            test_pause(f"after_tombstone_unlink_{entry.name}")
        tombstone.rmdir()
        test_pause("after_tombstone_rmdir_before_root_fsync")
        descriptor = os.open(str(root), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    cleanup_record.unlink()
    test_pause("after_cleanup_record_unlink_before_root_fsync")
    descriptor = os.open(str(root), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

if tombstone_resume:
    cleanup_payload = read_cleanup_record()
    finish_tombstone_cleanup(cleanup_payload)
    print("recovered_tombstone")
    raise SystemExit(0)

# Every repair must be linked to the exact interrupted transaction.  The gate
# is installed and fsynced before live files change; its release_id includes
# the release basename and the creator PID.  The rollback journal is also
# fsynced before the gate.  Together they prove whether the live marker is the
# old legitimate marker, is absent in a first migration, or is already the new
# marker with only cleanup left to finish.
def authenticated_phase():
    try:
        gate_status = gate.lstat()
    except FileNotFoundError as exc:
        raise SystemExit("missing deployment phase gate blocks marker recovery") from exc
    if gate.is_symlink() or not stat.S_ISREG(gate_status.st_mode):
        raise SystemExit(f"unsafe deployment phase gate: {gate}")
    try:
        payload = json.loads(gate.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid deployment phase gate: {gate}: {exc}")
    keys = {"fallback_sha256", "kind", "mode", "release_id", "schema", "wrapper_id", "wrapper_sha256", "wrapper_version"}
    release_match = re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-([1-9][0-9]*)", release_name)
    expected_phase_id = f"{release_name}:{release_match.group(1)}" if release_match else None
    if (not isinstance(payload, dict) or set(payload) != keys or
            type(payload.get("schema")) is not int or payload["schema"] != 1 or
            payload.get("kind") != "spspy-single-page-deployment-phase" or
            payload.get("mode") not in {"legacy_fallback", "fail_closed"} or
            expected_phase_id is None or payload.get("release_id") != expected_phase_id or
            payload.get("wrapper_id") != wrapper_id or
            type(payload.get("wrapper_version")) is not int or payload["wrapper_version"] <= 0 or
            payload["wrapper_version"] != expected_marker["wrapper_version"] or
            payload.get("wrapper_sha256") != expected_marker["wrapper_sha256"]):
        raise SystemExit("deployment phase gate does not bind selected current release")
    return payload

phase = None if cleanup_only else authenticated_phase()
rollback_real = directory(rollback, "interrupted rollback journal", root)
rollback_entry_names = set()
rollback_entry_manifest = {}
for entry in rollback.iterdir():
    if entry.name not in allowed_rollback:
        raise SystemExit(f"unknown rollback journal entry blocks marker recovery: {entry}")
    status = entry.lstat()
    if entry.is_symlink() or not stat.S_ISREG(status.st_mode) or entry.resolve(strict=True).parent != rollback_real:
        raise SystemExit(f"unsafe rollback journal entry: {entry}")
    rollback_entry_names.add(entry.name)
    content = entry.read_bytes()
    rollback_entry_manifest[entry.name] = {
        "mode": stat.S_IMODE(status.st_mode),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }

def backed_up(name):
    saved = rollback / name
    present = rollback / f"{name}.present"
    saved_exists = saved.exists() or saved.is_symlink()
    present_exists = present.exists() or present.is_symlink()
    if saved_exists != present_exists:
        raise SystemExit(f"incomplete rollback journal pair: {name}")
    if not saved_exists:
        return None
    _, saved_real = regular(saved, f"rollback {name}")
    _, present_real = regular(present, f"rollback {name} sentinel")
    if saved_real.parent != rollback_real or present_real.parent != rollback_real or present_real.read_bytes() != b"":
        raise SystemExit(f"invalid rollback journal pair: {name}")
    return saved_real.read_bytes()

old_daily = backed_up("run_daily.sh")
old_health = backed_up("check_health.mjs")
old_helper = backed_up("locked_exec.py")
old_marker_raw = backed_up(".stable-health-migration.json")
old_precommit = backed_up(".precommit_check_health.mjs")
legacy_two_pair_names = {
    "run_daily.sh", "run_daily.sh.present",
    "check_health.mjs", "check_health.mjs.present",
}
legacy_missing_helper = (
    old_daily is not None and old_health is not None and old_helper is None and
    old_marker_raw is None and old_precommit is None and
    rollback_entry_names - {".rollback-manifest.json"} == legacy_two_pair_names and
    hashlib.sha256(old_health).hexdigest() in trusted_legacy and wrapper_id.encode() not in old_health
)
if old_daily is None or old_health is None or (old_helper is None and not legacy_missing_helper):
    raise SystemExit("rollback journal does not contain the prior stable runtime")

authority_name = ".rollback-manifest.json"
if authority_name in rollback_entry_names:
    if rollback_entry_manifest[authority_name]["mode"] != 0o600:
        raise SystemExit("rollback authority has unsafe permissions")
    try:
        authority = json.loads((rollback / authority_name).read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid rollback authority: {exc}")
    authority_keys = {"schema", "kind", "release", "profile", "expected_current", "entries"}
    backup_manifest = {
        name: metadata for name, metadata in rollback_entry_manifest.items()
        if name != authority_name
    }
    expected_identity = authority.get("expected_current") if isinstance(authority, dict) else None
    expected_valid = isinstance(expected_identity, dict) and (
        (set(expected_identity) == {"kind"} and expected_identity.get("kind") == "absent") or
        (set(expected_identity) == {"kind", "value"} and expected_identity.get("kind") == "target" and
         isinstance(expected_identity.get("value"), str) and
         not os.path.isabs(expected_identity["value"]) and
         len(pathlib.PurePosixPath(expected_identity["value"]).parts) == 2 and
         pathlib.PurePosixPath(expected_identity["value"]).parts[0] == "releases" and
         pathlib.PurePosixPath(expected_identity["value"]).parts[1] not in {"", ".", ".."})
    )
    authority_profile = (
        "legacy"
        if (expected_identity == {"kind": "absent"} and old_marker_raw is None and
            hashlib.sha256(old_health).hexdigest() in trusted_legacy and wrapper_id.encode() not in old_health)
        else "helper"
    )
    if (not isinstance(authority, dict) or set(authority) != authority_keys or
            type(authority.get("schema")) is not int or authority["schema"] != 1 or
            authority.get("kind") != "spspy-single-page-detached-rollback-authority" or
            authority.get("release") != release_name or authority.get("profile") != authority_profile or
            not expected_valid or authority.get("entries") != backup_manifest or
            (legacy_missing_helper and expected_identity != {"kind": "absent"})):
        raise SystemExit("rollback authority does not bind the interrupted transaction")

old_marker = decode_marker(old_marker_raw, "in rollback journal") if old_marker_raw is not None else None
if old_marker is not None:
    old_id = re.search(rb'const STABLE_WRAPPER_ID = "([^"]+)";', old_health)
    old_version = re.search(rb'const STABLE_WRAPPER_VERSION = ([0-9]+);', old_health)
    if (not old_id or not old_version or old_id.group(1).decode("ascii") != old_marker["wrapper_id"] or
            int(old_version.group(1)) != old_marker["wrapper_version"] or
            hashlib.sha256(old_health).hexdigest() != old_marker["wrapper_sha256"]):
        raise SystemExit("rollback marker does not bind the prior health wrapper")

if marker_installed:
    # Marker installation succeeded; this run only completes stale artifact
    # cleanup.  The rollback marker may legitimately describe the old release.
    pass
elif old is None:
    if old_marker_raw is not None:
        raise SystemExit("missing live marker disagrees with rollback journal")
else:
    if old_marker_raw is None or old_raw != old_marker_raw or old != old_marker:
        raise SystemExit("live marker does not match the interrupted rollback journal")

if cleanup_only:
    if old_marker is None:
        old_sha = hashlib.sha256(old_health).hexdigest()
        if old_sha not in trusted_legacy or wrapper_id.encode() in old_health:
            raise SystemExit("rollback-only cleanup has no trusted prior migration evidence")
        if old_helper is None and not legacy_missing_helper:
            raise SystemExit("rollback-only legacy cleanup is missing an authenticated lock-helper profile")
elif phase["mode"] == "fail_closed":
    if phase.get("fallback_sha256") is not None or old_marker is None:
        raise SystemExit("invalid fail-closed deployment transaction evidence")
    if fallback_exists:
        raise SystemExit("unexpected fallback with fail-closed phase gate")
else:
    fallback_sha = phase.get("fallback_sha256")
    if (old_marker is not None or not isinstance(fallback_sha, str) or
            not re.fullmatch(r"[a-f0-9]{64}", fallback_sha) or
            hashlib.sha256(old_health).hexdigest() != fallback_sha or wrapper_id.encode() in old_health):
        raise SystemExit("invalid first-migration rollback evidence")
    if old_helper is None and not legacy_missing_helper:
        raise SystemExit("first-migration rollback is missing an authenticated lock-helper profile")
    if fallback_exists:
        _, fallback_real = regular(fallback, "precommit health fallback")
        fallback_bytes = fallback_real.read_bytes()
        if (fallback_real.parent != runtime_real or fallback_bytes != old_health or
                hashlib.sha256(fallback_bytes).hexdigest() != fallback_sha):
            raise SystemExit("precommit health fallback does not match rollback journal")
    elif not marker_installed:
        raise SystemExit("missing first-migration fallback blocks marker recovery")

if not marker_installed:
    temporary = marker.with_name(marker.name + f".{os.getpid()}.recover.tmp")
    try:
        descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            payload = (json.dumps(expected_marker, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            write_all(descriptor, payload, "marker-recovery")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, marker)
        descriptor = os.open(str(runtime), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

if not cleanup_only:
    # Cleanup has an intentional durable order.  A legacy fallback disappears
    # and is fsynced first; the authenticating gate disappears and is fsynced
    # last.  A retry can prove either intermediate state from the retained
    # rollback journal.
    try:
        fallback.unlink()
    except FileNotFoundError:
        pass
    descriptor = os.open(str(runtime), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    gate.unlink()
    descriptor = os.open(str(runtime), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    test_pause("after_gate_unlink_fsync")

# The rollback journal is no longer part of the safety proof once the gate's
# deletion is durable.  Persist a complete content manifest, then rename the
# whole directory and fsync the deploy root.  That rename is the logical
# deletion commit; physical deletion may be resumed from any entry boundary.
test_pause("before_rollback_delete")
rollback_manifest = {}
for entry in sorted(rollback.iterdir(), key=lambda item: item.name):
    status = entry.lstat()
    content = entry.read_bytes()
    rollback_manifest[entry.name] = {
        "mode": stat.S_IMODE(status.st_mode),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }

try:
    cleanup_record.lstat()
except FileNotFoundError:
    try:
        cleanup_pending.lstat()
    except FileNotFoundError:
        nonce = secrets.token_hex(16)
        cleanup_payload = {
            "schema": 1,
            "kind": "spspy-single-page-rollback-cleanup",
            "release": release_name,
            "current_target": raw,
            "marker_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
            "nonce": nonce,
            "tombstone": f".rollback-tombstone-{release_name}-{nonce}",
            "entries": rollback_manifest,
        }
        cleanup_temporary = cleanup_record.with_name(cleanup_record.name + f".tmp-{nonce}")
        descriptor = os.open(str(cleanup_temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            record_bytes = (json.dumps(cleanup_payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            test_pause("after_cleanup_record_temp_create")
            written = os.write(descriptor, record_bytes[:max(1, len(record_bytes) // 2)])
            if written <= 0:
                raise SystemExit("unable to write rollback cleanup record temporary")
            test_pause("after_cleanup_record_temp_partial_write")
            while written < len(record_bytes):
                wrote = os.write(descriptor, record_bytes[written:])
                if wrote <= 0:
                    raise SystemExit("unable to finish rollback cleanup record temporary")
                written += wrote
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        test_pause("after_cleanup_record_file_fsync_before_replace")
        os.replace(cleanup_temporary, cleanup_record)
    else:
        cleanup_payload = read_cleanup_record(cleanup_pending)
        if cleanup_payload["entries"] != rollback_manifest:
            raise SystemExit("pending cleanup record does not match intact rollback journal")
        os.replace(cleanup_pending, cleanup_record)
    test_pause("after_cleanup_record_replace_before_root_fsync")
    descriptor = os.open(str(root), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    test_pause("after_cleanup_record_root_fsync")
else:
    cleanup_payload = read_cleanup_record()
    if cleanup_payload["entries"] != rollback_manifest:
        raise SystemExit("rollback cleanup record does not match intact rollback journal")

tombstone = root / cleanup_payload["tombstone"]
try:
    tombstone.lstat()
except FileNotFoundError:
    pass
else:
    raise SystemExit(f"rollback tombstone already exists before logical deletion: {tombstone}")
os.replace(rollback, tombstone)
test_pause("after_rollback_rename_before_root_fsync")
descriptor = os.open(str(root), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
test_pause("after_rollback_rename_fsync")
test_pause("before_tombstone_physical_delete")
finish_tombstone_cleanup(cleanup_payload)
print("recovered")
PY
}

detached_rollback_cleanup() {
  local mode="$1"
  local rollback_path="${2:-}"
  local expected_current="${3:-}"
  "${PYTHON_BIN}" "${SOURCE_DIR}/scripts/rollback_cleanup.py" \
    "${mode}" "${DEPLOY_ROOT}" "${RUNTIME_DIR}" "${rollback_path}" "${expected_current}" \
    "${TRUSTED_PRODUCTION_LEGACY_SHA}"
}

resume_detached_rollback_cleanups() {
  detached_rollback_cleanup resume "" ""
}

discard_restored_rollback() {
  local expected="__ABSENT__"
  if [[ "${OLD_CURRENT_PRESENT}" == "1" ]]; then expected="${OLD_CURRENT_TARGET}"; fi
  fault_point before_detached_cleanup_create || return $?
  detached_rollback_cleanup create "${ROLLBACK_DIR}" "${expected}"
}

seal_rollback_authority() {
  local expected="__ABSENT__"
  if [[ "${OLD_CURRENT_PRESENT}" == "1" ]]; then expected="${OLD_CURRENT_TARGET}"; fi
  detached_rollback_cleanup seal "${ROLLBACK_DIR}" "${expected}"
}

verify_rollback_authority() {
  local expected="__ABSENT__"
  if [[ "${OLD_CURRENT_PRESENT}" == "1" ]]; then expected="${OLD_CURRENT_TARGET}"; fi
  detached_rollback_cleanup verify "${ROLLBACK_DIR}" "${expected}"
}

recover_caught_rollback() {
  local expected="__ABSENT__"
  local mode="recover-caught"
  if [[ "${OLD_CURRENT_PRESENT}" == "1" ]]; then expected="${OLD_CURRENT_TARGET}"; fi
  if [[ "${PRESERVE_CAUGHT_TRANSACTION}" == "1" ]]; then mode="recover-caught-preserve"; fi
  detached_rollback_cleanup "${mode}" "${ROLLBACK_DIR}" "${expected}"
}

remove_phase_gate() {
  "${PYTHON_BIN}" - "${PHASE_GATE}" <<'PY'
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
try:
    path.unlink()
except FileNotFoundError:
    pass
descriptor = os.open(str(path.parent), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

remove_committed_phase_artifacts() {
  "${PYTHON_BIN}" - "${RUNTIME_DIR}/.precommit_check_health.mjs" "${PHASE_GATE}" <<'PY'
import os, pathlib, stat, sys
paths = [pathlib.Path(raw) for raw in sys.argv[1:]]
for path in paths:
    try:
        status = path.lstat()
    except FileNotFoundError:
        continue
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise SystemExit(f"unsafe committed phase artifact: {path}")
    path.unlink()
descriptor = os.open(str(paths[0].parent), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

atomic_install() {
  local source="$1"
  local target="$2"
  local mode="$3"
  local temporary="${target}.${RELEASE_ID}.tmp"
  "${PYTHON_BIN}" - "${source}" "${temporary}" "${target}" "${mode}" <<'PY'
import os, shutil, sys
source, temporary, target, mode = sys.argv[1:5]
try:
    with open(source, "rb") as reader, open(temporary, "xb") as writer:
        shutil.copyfileobj(reader, writer)
        os.fchmod(writer.fileno(), int(mode, 8))
        writer.flush()
        os.fsync(writer.fileno())
    os.replace(temporary, target)
    parent = os.open(os.path.dirname(target), os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
}

atomic_current() {
  local relative_target="$1"
  local allow_test_injection="${2:-0}"
  local temporary="${DEPLOY_ROOT}/.current.${RELEASE_ID}.tmp"
  "${PYTHON_BIN}" - "${temporary}" "${DEPLOY_ROOT}/current" "${relative_target}" \
    "${allow_test_injection}" <<'PY'
import os, pathlib, signal, sys
temporary, current, target = map(pathlib.Path, sys.argv[1:4])
inject = sys.argv[4] == "1" and os.environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1"
try:
    os.symlink(str(target), temporary)
    os.replace(temporary, current)
    if inject and os.environ.get("SP_SINGLE_PAGE_TEST_FAIL_CURRENT_FSYNC") == "1":
        raise OSError("injected current directory fsync failure")
    descriptor = os.open(str(current.parent), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if inject and os.environ.get("SP_SINGLE_PAGE_TEST_TERM_AFTER_COMMIT") == "1":
        os.kill(os.getppid(), signal.SIGTERM)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
}

validate_current() {
  "${PYTHON_BIN}" - "${DEPLOY_ROOT}" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1]).resolve()
current = root / "current"
releases = root / "releases"
releases_status = releases.lstat()
if not stat.S_ISDIR(releases_status.st_mode) or releases.is_symlink():
    raise SystemExit(f"releases must be a real directory: {releases}")
try:
    status = current.lstat()
except FileNotFoundError:
    raise SystemExit(0)
if not stat.S_ISLNK(status.st_mode):
    raise SystemExit(f"refusing unsafe non-symlink current path: {current}")
raw = os.readlink(current)
parts = pathlib.PurePosixPath(raw).parts
if os.path.isabs(raw) or len(parts) != 2 or parts[0] != "releases" or parts[1] in {"", ".", ".."}:
    raise SystemExit(f"refusing unsafe current target: {raw}")
release = root / "releases" / parts[1]
status = release.lstat()
if not stat.S_ISDIR(status.st_mode) or release.is_symlink():
    raise SystemExit(f"current release is not a real directory: {release}")
release_real = release.resolve(strict=True)
if release_real.parent != releases.resolve(strict=True):
    raise SystemExit("current release resolves outside releases")
monitor = release / "single-page-monitor"
monitor_status = monitor.lstat()
if not stat.S_ISDIR(monitor_status.st_mode) or monitor.is_symlink():
    raise SystemExit(f"current monitor path is not a real directory: {monitor}")
monitor_real = monitor.resolve(strict=True)
if monitor_real.parent != release_real:
    raise SystemExit("current monitor resolves outside selected release")
runner = monitor / "run_daily.sh"
health = monitor / "check_health.mjs"
for path in (runner, health):
    status = path.lstat()
    if not stat.S_ISREG(status.st_mode) or path.is_symlink():
        raise SystemExit(f"current release entrypoint is unsafe: {path}")
    resolved = path.resolve(strict=True)
    if resolved.parent != monitor_real or release_real not in resolved.parents:
        raise SystemExit(f"current release entrypoint escapes selected release: {path}")
print(raw)
PY
}

inspect_migration_state() {
  "${PYTHON_BIN}" - "${MIGRATION_MARKER}" "${RUNTIME_DIR}/check_health.mjs" \
    "${OLD_CURRENT_PRESENT}" "${TRUSTED_PRODUCTION_LEGACY_SHA}" <<'PY'
import hashlib, json, pathlib, re, stat, sys

marker = pathlib.Path(sys.argv[1])
runtime_checker = pathlib.Path(sys.argv[2])
current_present = sys.argv[3] == "1"
trusted_legacy = {sys.argv[4]}
# A test fixture may supply exactly one additional full SHA.  This is not a
# production compatibility path: test mode is required and no textual or
# structural identity is ever accepted as a legacy checker.
if (os := __import__("os")).environ.get("SP_SINGLE_PAGE_TEST_MODE") == "1":
    test_sha = os.environ.get("SP_SINGLE_PAGE_TEST_TRUSTED_LEGACY_SHA", "")
    if re.fullmatch(r"[a-f0-9]{64}", test_sha):
        trusted_legacy.add(test_sha)
stable_id = b'spspy-single-page-stable-health'

try:
    marker_status = marker.lstat()
except FileNotFoundError:
    marker_status = None
if marker_status is not None:
    if marker.is_symlink() or not stat.S_ISREG(marker_status.st_mode):
        raise SystemExit(f"unsafe stable migration marker: {marker}")
    try:
        payload = json.loads(marker.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid stable migration marker: {marker}: {exc}")
    expected_keys = {"schema", "kind", "wrapper_id", "wrapper_version", "wrapper_sha256"}
    valid = (
        isinstance(payload, dict) and set(payload) == expected_keys and
        type(payload.get("schema")) is int and payload["schema"] == 2 and
        payload.get("kind") == "spspy-single-page-stable-health-migration" and
        payload.get("wrapper_id") == "spspy-single-page-stable-health" and
        isinstance(payload.get("wrapper_version"), int) and
        not isinstance(payload.get("wrapper_version"), bool) and
        payload["wrapper_version"] > 0 and
        isinstance(payload.get("wrapper_sha256"), str) and
        re.fullmatch(r"[a-f0-9]{64}", payload["wrapper_sha256"])
    )
    if not valid:
        raise SystemExit(f"unsupported stable migration marker schema: {marker}")
    try:
        checker_status = runtime_checker.lstat()
    except FileNotFoundError:
        raise SystemExit(f"stable migration marker exists but runtime health wrapper is missing: {runtime_checker}")
    if runtime_checker.is_symlink() or not stat.S_ISREG(checker_status.st_mode):
        raise SystemExit(f"stable migration marker exists but runtime health wrapper is unsafe: {runtime_checker}")
    checker_bytes = runtime_checker.read_bytes()
    checker_sha = hashlib.sha256(checker_bytes).hexdigest()
    wrapper_id = re.search(rb'const STABLE_WRAPPER_ID = "([^"]+)";', checker_bytes)
    wrapper_version = re.search(rb'const STABLE_WRAPPER_VERSION = ([0-9]+);', checker_bytes)
    if (checker_sha != payload["wrapper_sha256"] or not wrapper_id or not wrapper_version or
            wrapper_id.group(1).decode("ascii") != payload["wrapper_id"] or
            int(wrapper_version.group(1)) != payload["wrapper_version"] or
            stable_id not in checker_bytes):
        raise SystemExit("stable migration marker does not bind the installed stable health wrapper")
    print("migrated")
    raise SystemExit(0)

if current_present:
    print("unmarked_current")
    raise SystemExit(0)

try:
    checker_status = runtime_checker.lstat()
except FileNotFoundError:
    print("none")
    raise SystemExit(0)
if runtime_checker.is_symlink() or not stat.S_ISREG(checker_status.st_mode):
    raise SystemExit(f"unsafe unmarked runtime health checker: {runtime_checker}")
checker_bytes = runtime_checker.read_bytes()
checker_sha = hashlib.sha256(checker_bytes).hexdigest()

if stable_id in checker_bytes:
    print("stable")
    raise SystemExit(0)

if checker_sha in trusted_legacy:
    print(f"legacy:{checker_sha}")
    raise SystemExit(0)

raise SystemExit(
    f"unmarked runtime health checker has no trusted legacy or stable identity: {runtime_checker} sha256={checker_sha}"
)
PY
}

verify_legacy_checker() {
  "${PYTHON_BIN}" - "${RUNTIME_DIR}/check_health.mjs" "${LEGACY_CHECKER_SHA}" <<'PY'
import hashlib, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
status = path.lstat()
if path.is_symlink() or not stat.S_ISREG(status.st_mode):
    raise SystemExit(f"legacy health checker changed type before fallback copy: {path}")
payload = path.read_bytes()
actual = hashlib.sha256(payload).hexdigest()
if actual != expected or b"spspy-single-page-stable-health" in payload:
    raise SystemExit(f"legacy health checker changed before fallback copy: {path}")
PY
}

backup_live_file() {
  local name="$1"
  local source="${RUNTIME_DIR}/${name}"
  if [[ -L "${source}" || ( -e "${source}" && ! -f "${source}" ) ]]; then
    echo "Refusing unsafe stable entrypoint before commit: ${source}" >&2
    return 70
  fi
  if [[ -f "${source}" ]]; then
    cp -p "${source}" "${ROLLBACK_DIR}/${name}"
    : > "${ROLLBACK_DIR}/${name}.present"
    chmod 600 "${ROLLBACK_DIR}/${name}.present"
  fi
}

remove_generated_release() {
  local generated="$1"
  if [[ -n "${generated}" && "${generated}" == "${RELEASES_DIR}/"* && -d "${generated}" ]]; then
    chmod -R u+w "${generated}" 2>/dev/null || true
    rm -rf -- "${generated}"
    fsync_directory "${RELEASES_DIR}" 2>/dev/null || true
  fi
}

cleanup() {
  local code="$?"
  set +e
  if [[ "${PRESERVE_TRANSACTION}" == "1" ]]; then
    trap - EXIT INT TERM HUP
    exit 70
  fi
  if [[ "${GATE_INSTALLED}" == "1" && "${COMMITTED}" != "1" ]]; then
    # The Python recovery state machine validates and freezes every authority,
    # source, target, temporary, gate, release and current identity before its
    # first write.  A selected current is durably reset to the authority's
    # expected current first, so any later SIGKILL becomes ordinary pre-current
    # recovery.  On any failure preserve every remaining transaction object.
    if ! recover_caught_rollback; then
      echo "Deployment rollback validation or recovery failed; preserving the complete transaction." >&2
      PRESERVE_TRANSACTION=1
      trap - EXIT INT TERM HUP
      exit 70
    fi
    LIVE_CHANGED=0
    PHASE_ACTIVE=0
    exec 9<&-
    if [[ "${PRESERVE_CAUGHT_TRANSACTION}" == "1" ]]; then
      trap - EXIT INT TERM HUP
      exit 70
    fi
    GATE_INSTALLED=0
  fi
  if [[ "${PHASE_ACTIVE}" == "1" && "${COMMITTED}" != "1" ]]; then
    # Holding fd 9 proves only lock ownership.  If gate publication did not
    # return successfully, never unlink an unproven path that may predate us.
    echo "Deployment gate publication was not proven; preserving the complete transaction." >&2
    PRESERVE_TRANSACTION=1
    trap - EXIT INT TERM HUP
    exit 70
  fi
  if [[ "${COMMITTED}" != "1" && \
        ( -e "${ROLLBACK_DIR}" || -L "${ROLLBACK_DIR}" ) ]]; then
    if ! discard_restored_rollback; then
      echo "Detached rollback cleanup did not converge; preserving the complete transaction." >&2
      PRESERVE_TRANSACTION=1
      trap - EXIT INT TERM HUP
      exit 70
    fi
  fi
  if [[ -n "${STAGE_DIR:-}" && -d "${STAGE_DIR}" ]]; then
    rm -rf -- "${STAGE_DIR}"
  fi
  if [[ "${COMMITTED}" != "1" ]]; then
    remove_generated_release "${FINAL_RELEASE:-}"
  fi
  # Never recursively delete a rollback journal here.  Before commit it is
  # preserved as evidence if cleanup itself is interrupted; after commit the
  # durable manifest+tombstone transaction below owns its removal.
  trap - EXIT INT TERM HUP
  exit "${code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

fault_point() {
  local point="$1"
  if [[ "${SP_SINGLE_PAGE_TEST_MODE:-0}" == "1" && \
        "${SP_SINGLE_PAGE_TEST_FAIL_POINT:-}" == "${point}" ]]; then
    echo "Injected deployment failure at ${point}." >&2
    return 97
  fi
  if [[ "${SP_SINGLE_PAGE_TEST_MODE:-0}" == "1" && \
        "${SP_SINGLE_PAGE_TEST_SIGNAL_POINT:-}" == "${point}" ]]; then
    kill -TERM "$$"
  fi
  if [[ "${SP_SINGLE_PAGE_TEST_MODE:-0}" == "1" && \
        "${SP_SINGLE_PAGE_TEST_PAUSE_POINT:-}" == "${point}" ]]; then
    [[ -n "${SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE:-}" ]] || return 70
    [[ -n "${SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE:-}" ]] || return 70
    printf '%s\n' "$$" > "${SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE}"
    while [[ ! -e "${SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE:-}" ]]; do :; done
  fi
}

# The deployment itself must retain its inherited fcntl descriptor for its
# entire lifetime.  Its test suites intentionally spawn isolated deployment
# fixtures, though; passing the production descriptor and its active-path
# assertion into those fixtures makes locked_exec reject their different data
# roots before their tests even begin.  Strip *only* the two capability
# variables from the npm-test child.  This subshell never closes or unsets the
# descriptor in the deploy shell, so subsequent live validation still proves
# ownership of the original runtime data inode.
run_npm_test_without_runtime_lock() {
  local test_dir="$1"
  (
    cd "${test_dir}"
    env -u SP_SINGLE_PAGE_DEPLOY_LOCK_ACTIVE -u SP_SINGLE_PAGE_DEPLOY_LOCK_FD \
      -u SP_SINGLE_PAGE_LOCK_ACTIVE -u SP_SINGLE_PAGE_LOCK_FD \
      "${NPM_BIN}" test
  )
}

# Validate every live pointer before staging and before any stable wrapper can
# change.  A corrupt/dangling/escaping current fails closed with zero live edits.
if ! resume_detached_rollback_cleanups; then
  exit 70
fi
OLD_CURRENT_TARGET="$(validate_current)"
if [[ -n "${OLD_CURRENT_TARGET}" ]]; then
  OLD_CURRENT_PRESENT=1
fi
if [[ "${OLD_CURRENT_PRESENT}" == "1" ]]; then
  # Complete only the narrowly proven post-current crash state before reading
  # the marker as policy.  This is deliberately before staging: a recovered
  # marker is durable even if the following ordinary deployment later fails.
  RECOVERY_RESULT=""
  if ! RECOVERY_RESULT="$(recover_durable_current_marker)"; then
    # Python's safety proofs use descriptive non-zero exits; normalize the
    # public deployment contract to the fail-closed status used everywhere
    # else in this script.
    exit 70
  fi
  if [[ "${RECOVERY_RESULT}" == "migrated_precurrent" ]]; then
    if ! detached_rollback_cleanup recover-precurrent "" ""; then
      exit 70
    fi
  fi
fi
set +e
MIGRATION_INSPECTION="$(inspect_migration_state)"
MIGRATION_INSPECTION_STATUS=$?
set -e
if [[ "${MIGRATION_INSPECTION_STATUS}" != "0" ]]; then
  exit 70
fi
if [[ "${MIGRATION_INSPECTION}" == legacy:* ]]; then
  MIGRATION_STATE="legacy"
  LEGACY_CHECKER_SHA="${MIGRATION_INSPECTION#legacy:}"
else
  MIGRATION_STATE="${MIGRATION_INSPECTION}"
fi

# A no-current runtime is recoverable only during its first, authenticated
# legacy migration.  In particular, never turn an interrupted or migrated
# stable wrapper into its own fallback checker.
if [[ "${OLD_CURRENT_PRESENT}" != "1" && "${MIGRATION_STATE}" != "legacy" ]]; then
  echo "No current release and no authenticated first-legacy migration; refusing all live changes." >&2
  exit 70
fi

if [[ "${SP_SINGLE_PAGE_TEST_SKIP_SOURCE_PRECHECK:-0}" != "1" ]]; then
  run_npm_test_without_runtime_lock "${SOURCE_DIR}"
fi
"${NODE_BIN}" --check "${REPO_ROOT}/top200_june_single_page_scan.mjs"
"${NODE_BIN}" --check "${SOURCE_DIR}/monitor.mjs"
"${NODE_BIN}" --check "${SOURCE_DIR}/build_dashboard.mjs"
"${NODE_BIN}" --check "${SOURCE_DIR}/check_health.mjs"
"${NODE_BIN}" --check "${SOURCE_DIR}/stable_check_health.mjs"
"${PYTHON_BIN}" - "${LOCK_HELPER}" "${SOURCE_DIR}/scripts/rollback_cleanup.py" \
  "${SOURCE_DIR}/scripts/notify_dingtalk.py" \
  "${SOURCE_DIR}/tests/test_notify_dingtalk.py" <<'PY'
import pathlib, sys
for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    compile(path.read_bytes(), str(path), "exec")
PY
bash -n "${SOURCE_DIR}/run_daily.sh"
bash -n "${SOURCE_DIR}/stable_run_daily.sh"
bash -n "${SOURCE_DIR}/sync_deploy.sh"

mkdir -p "${STAGE_DIR}/single-page-monitor/lib" "${STAGE_DIR}/single-page-monitor/tests" \
  "${STAGE_DIR}/single-page-monitor/scripts"
cp "${REPO_ROOT}/top200_june_single_page_scan.mjs" "${STAGE_DIR}/"
cp "${SOURCE_DIR}/lib/"*.mjs "${STAGE_DIR}/single-page-monitor/lib/"
cp "${SOURCE_DIR}/tests/"*.mjs "${STAGE_DIR}/single-page-monitor/tests/"
cp "${SOURCE_DIR}/tests/"*.py "${STAGE_DIR}/single-page-monitor/tests/"
cp "${SOURCE_DIR}/scripts/locked_exec.py" "${SOURCE_DIR}/scripts/rollback_cleanup.py" \
  "${SOURCE_DIR}/scripts/notify_dingtalk.py" \
  "${STAGE_DIR}/single-page-monitor/scripts/"
for name in monitor.mjs build_dashboard.mjs check_health.mjs run_daily.sh sync_deploy.sh \
  stable_run_daily.sh stable_check_health.mjs config.json package.json package-lock.json README.md \
  com.spspy.single-page-monitor.plist com.spspy.single-page-monitor.health.plist; do
  cp "${SOURCE_DIR}/${name}" "${STAGE_DIR}/single-page-monitor/${name}"
done
chmod 755 "${STAGE_DIR}/single-page-monitor/run_daily.sh" \
  "${STAGE_DIR}/single-page-monitor/sync_deploy.sh" \
  "${STAGE_DIR}/single-page-monitor/stable_run_daily.sh" \
  "${STAGE_DIR}/single-page-monitor/stable_check_health.mjs" \
  "${STAGE_DIR}/single-page-monitor/scripts/locked_exec.py" \
  "${STAGE_DIR}/single-page-monitor/scripts/rollback_cleanup.py" \
  "${STAGE_DIR}/single-page-monitor/scripts/notify_dingtalk.py"

"${PYTHON_BIN}" - \
  "${STAGE_DIR}/single-page-monitor/scripts/notify_dingtalk.py" \
  "${STAGE_DIR}/single-page-monitor/tests/test_notify_dingtalk.py" <<'PY'
import pathlib, stat, sys
expected = ((pathlib.Path(sys.argv[1]), 0o755), (pathlib.Path(sys.argv[2]), 0o644))
for path, mode in expected:
    value = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(value.st_mode):
        raise SystemExit(f"staged notifier artifact is unsafe: {path}")
    if stat.S_IMODE(value.st_mode) != mode:
        raise SystemExit(f"staged notifier artifact has wrong mode: {path}")
    compile(path.read_bytes(), str(path), "exec")
PY

(cd "${STAGE_DIR}/single-page-monitor" && "${NPM_BIN}" ci --omit=dev)

# This is the exact staged tree and exact staged package script.  Deployment
# integration tests self-skip under this marker to avoid recursive deploys;
# all runtime/unit tests execute from the isolated stage.
(
  export SP_SINGLE_PAGE_STAGE_SELFTEST=1
  run_npm_test_without_runtime_lock "${STAGE_DIR}/single-page-monitor"
)
(cd "${STAGE_DIR}/single-page-monitor" && \
  "${PYTHON_BIN}" -m unittest -q tests.test_notify_dingtalk)
"${NODE_BIN}" --check "${STAGE_DIR}/top200_june_single_page_scan.mjs"
"${NODE_BIN}" --check "${STAGE_DIR}/single-page-monitor/monitor.mjs"
"${NODE_BIN}" --check "${STAGE_DIR}/single-page-monitor/build_dashboard.mjs"
"${NODE_BIN}" --check "${STAGE_DIR}/single-page-monitor/check_health.mjs"
"${NODE_BIN}" --check "${STAGE_DIR}/single-page-monitor/stable_check_health.mjs"
bash -n "${STAGE_DIR}/single-page-monitor/run_daily.sh"
bash -n "${STAGE_DIR}/single-page-monitor/stable_run_daily.sh"
bash -n "${STAGE_DIR}/single-page-monitor/sync_deploy.sh"
"${PLUTIL_BIN}" -lint "${STAGE_DIR}/single-page-monitor/com.spspy.single-page-monitor.plist" >/dev/null
"${PLUTIL_BIN}" -lint "${STAGE_DIR}/single-page-monitor/com.spspy.single-page-monitor.health.plist" >/dev/null
for forbidden in data logs reports .pages; do
  [[ ! -e "${STAGE_DIR}/single-page-monitor/${forbidden}" ]] || {
    echo "Staged release unexpectedly contains runtime path: ${forbidden}" >&2
    exit 70
  }
done

chmod -R a-w "${STAGE_DIR}"
"${PYTHON_BIN}" - "${STAGE_DIR}" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
for path in sorted(root.rglob("*"), key=lambda item: (len(item.parts), str(item)), reverse=True):
    status = path.lstat()
    if stat.S_ISREG(status.st_mode) or stat.S_ISDIR(status.st_mode):
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    elif stat.S_ISLNK(status.st_mode):
        resolved = path.resolve(strict=True)
        if root.resolve() not in (resolved, *resolved.parents):
            raise SystemExit(f"staged symlink escapes release: {path}")
    else:
        raise SystemExit(f"unsupported staged path: {path}")
descriptor = os.open(str(root), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
fault_point before_release

mv "${STAGE_DIR}" "${FINAL_RELEASE}"
STAGE_DIR=""
fsync_directory "${RELEASES_DIR}"

# Revalidate immediately before the live transaction.  This catches any
# out-of-band pointer mutation while the isolated release was being built.
CURRENT_BEFORE_COMMIT="$(validate_current)"
if [[ "${CURRENT_BEFORE_COMMIT}" != "${OLD_CURRENT_TARGET}" ]]; then
  echo "current changed outside the deployment lock; refusing live commit." >&2
  exit 75
fi

mkdir "${ROLLBACK_DIR}"
backup_live_file run_daily.sh
backup_live_file check_health.mjs
backup_live_file locked_exec.py
backup_live_file .precommit_check_health.mjs
backup_live_file .stable-health-migration.json

# Only the authenticated first legacy migration may have started before the
# lock helper existed.  Every already-migrated runtime still needs the full
# three-file rollback set before any live path is touched; otherwise preserve
# the journal for operator review instead of committing a cleanup state we
# cannot later prove.
if [[ ! -f "${ROLLBACK_DIR}/locked_exec.py.present" && "${MIGRATION_STATE}" != "legacy" ]]; then
  echo "Refusing migrated runtime with no prior locked_exec.py rollback pair." >&2
  exit 70
fi

# Persist the exact pre-transaction current identity and backup manifest as
# one rollback-directory unit before the phase gate or any live path changes.
# This closes the restore-complete -> cleanup-scratch-open crash window.
if ! seal_rollback_authority; then
  echo "Unable to publish durable rollback authority before live deployment." >&2
  PRESERVE_TRANSACTION=1
  exit 70
fi
if ! verify_rollback_authority; then
  echo "Rollback authority changed after publication; preserving the complete transaction." >&2
  PRESERVE_TRANSACTION=1
  exit 70
fi

acquire_phase_lock
fault_point after_phase_lock
PHASE_MODE="fail_closed"
PHASE_FALLBACK_SHA=""
if [[ "${MIGRATION_STATE}" == "legacy" ]]; then
  PHASE_MODE="legacy_fallback"
  PHASE_FALLBACK_SHA="${LEGACY_CHECKER_SHA}"
fi
install_phase_gate "${PHASE_MODE}" "${PHASE_FALLBACK_SHA}" \
  "${FINAL_RELEASE}/single-page-monitor/stable_check_health.mjs"
GATE_INSTALLED=1
LIVE_CHANGED=1
if [[ "${MIGRATION_STATE}" == "legacy" && -f "${RUNTIME_DIR}/check_health.mjs" ]]; then
  verify_legacy_checker
  if [[ ! -e "${RUNTIME_DIR}/.precommit_check_health.mjs" && \
        ! -L "${RUNTIME_DIR}/.precommit_check_health.mjs" ]]; then
    atomic_install "${RUNTIME_DIR}/check_health.mjs" \
      "${RUNTIME_DIR}/.precommit_check_health.mjs" 755
  elif [[ -L "${RUNTIME_DIR}/.precommit_check_health.mjs" || \
          ! -f "${RUNTIME_DIR}/.precommit_check_health.mjs" ]]; then
    echo "Unsafe precommit health fallback; refusing first migration." >&2
    exit 70
  fi
fi
atomic_install "${FINAL_RELEASE}/single-page-monitor/scripts/locked_exec.py" \
  "${RUNTIME_DIR}/locked_exec.py" 755
fault_point after_lock_helper
atomic_install "${FINAL_RELEASE}/single-page-monitor/stable_run_daily.sh" \
  "${RUNTIME_DIR}/run_daily.sh" 755
fault_point after_daily_wrapper
atomic_install "${FINAL_RELEASE}/single-page-monitor/stable_check_health.mjs" \
  "${RUNTIME_DIR}/check_health.mjs" 755
fault_point after_health_wrapper
fsync_directory "${RUNTIME_DIR}"
fsync_directory "${DEPLOY_ROOT}"
fault_point final_fsync

# `current` is the sole commit point and is switched last.  At this instant all
# stable launchers and their helper are already durable.  A hard crash before
# here leaves the old current (new wrappers either remain compatible or fail
# closed); a hard crash after os.replace+fsync leaves a complete new runtime.
# From immediately before the durable commit onward, termination signals are
# ignored.  `atomic_current` performs replace+directory-fsync as one child
# operation; once it returns, every live file is already a complete new set.
trap '' INT TERM HUP
atomic_current "releases/${RELEASE_ID}" 1
# Test-only pause immediately after os.replace(current)+parent fsync and
# before marker installation.  This is the otherwise uncatchable SIGKILL
# window exercised by the recovery proof above.
fault_point after_current_fsync_before_marker
# The release pointer is not a completed migration until the stable-wrapper
# identity is durably bound.  Leave COMMITTED unset so any marker failure
# rolls the pointer and all live files back to their exact previous state.
if install_migration_marker; then
  :
else
  MARKER_INSTALL_STATUS="$?"
  if [[ "${MARKER_INSTALL_STATUS}" == "74" ]]; then
    PRESERVE_CAUGHT_TRANSACTION=1
  fi
  exit 70
fi
COMMITTED=1
LIVE_CHANGED=0

if [[ "${SP_SINGLE_PAGE_TEST_MODE:-0}" == "1" && \
      "${SP_SINGLE_PAGE_TEST_PAUSE_POINT:-}" == "after_current" ]]; then
  printf '%s\n' "$$" > "${SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE:?}"
  while [[ ! -e "${SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE:-}" ]]; do :; done
fi

# The current commit is already durable and signals remain ignored.  Retry the
# bounded phase cleanup until fallback+gate deletion is itself durable; a new
# current can therefore never be paired with a non-zero deployment exit.
set +e
while ! remove_committed_phase_artifacts; do sleep 1; done
exec 9<&-
PHASE_ACTIVE=0
GATE_INSTALLED=0
if ! recover_durable_current_marker; then
  echo "Committed release is healthy, but durable rollback cleanup did not converge." >&2
  exit 70
fi
echo "Activated immutable single-page release: ${FINAL_RELEASE}"
echo "Persistent data/logs/reports/pages were not copied or overwritten."
trap - EXIT
exit 0
