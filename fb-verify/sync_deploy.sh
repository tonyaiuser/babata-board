#!/usr/bin/env bash
# Build and atomically activate an immutable FB verifier code release.
# Persistent data always remains at DEPLOY_DIR/data and is never seeded from
# the source checkout.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="${FB_VERIFY_DEPLOY_DIR:-$HOME/.spspy-fb-verify/fb-verify}"
RELEASES_DIR="${DEPLOY_DIR}/releases"
DEPLOY_LOCK="${DEPLOY_DIR}/.deploy.lock"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"

# The lock fd survives exec and is released by the kernel on every exit/crash.
# A direct source/release invocation therefore cannot bypass deployment locking.
mkdir -p "$DEPLOY_DIR"
if [[ -z "${FB_VERIFY_DEPLOY_LOCK_ACTIVE:-}" ]]; then
  exec "$PYTHON_BIN" "${SOURCE_DIR}/scripts/locked_exec.py" \
    --lock "$DEPLOY_LOCK" \
    --fd-env FB_VERIFY_DEPLOY_LOCK_FD \
    --active-env FB_VERIFY_DEPLOY_LOCK_ACTIVE \
    --label "FB verifier deployment" --busy-exit 75 -- \
    "${SOURCE_DIR}/sync_deploy.sh" "$@"
fi
"$PYTHON_BIN" "${SOURCE_DIR}/scripts/locked_exec.py" \
  --lock "$DEPLOY_LOCK" \
  --fd-env FB_VERIFY_DEPLOY_LOCK_FD \
  --active-env FB_VERIFY_DEPLOY_LOCK_ACTIVE \
  --label "FB verifier deployment" --busy-exit 75 --validate-only

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ "${FB_VERIFY_TEST_EXIT_AFTER_LOCK:-0}" == "1" ]]; then
  printf 'injected deployment exit immediately after lock acquisition\n' >&2
  exit 96
fi

NODE_BIN="${NODE_BIN:-$(command -v node)}"
PLUTIL_BIN="${PLUTIL_BIN:-/usr/bin/plutil}"
RELEASE_ID="$(date -u '+%Y%m%dT%H%M%SZ')-$$"
STAGE_DIR="${RELEASES_DIR}/.${RELEASE_ID}.stage"
FINAL_RELEASE="${RELEASES_DIR}/${RELEASE_ID}"
ROLLBACK_NEEDED=0
RUNTIME_COMMITTED=0
GATE_INSTALLED=0
OLD_CURRENT_PRESENT=0
OLD_CURRENT_TARGET=""
ROLLBACK_DIR="${DEPLOY_DIR}/.deploy-rollback-${RELEASE_ID}"
DEPLOY_GATE="${DEPLOY_DIR}/.deployment.gate"
GATE_TOKEN="${RELEASE_ID}:$$"
STABLE_NAMES="run_daily_fb_verify.sh run_nightly_single_page_fb_verify.sh sync_deploy.sh README.md com.spspy.fb-verify.plist com.spspy.single-page-fb-nightly.plist"
ENTRYPOINT_NAMES="run_daily_fb_verify.sh run_nightly_single_page_fb_verify.sh sync_deploy.sh"

safe_remove_stage() {
  if [[ -n "${STAGE_DIR:-}" ]] && [[ "$STAGE_DIR" == "${RELEASES_DIR}/."*.stage ]]; then
    rm -rf -- "$STAGE_DIR"
  fi
}

atomic_install() {
  local source="$1"
  local target="$2"
  local mode="$3"
  local temporary="${target}.${RELEASE_ID}.tmp"
  "$PYTHON_BIN" - "$source" "$temporary" "$target" "$mode" <<'PY'
import os, shutil, sys
source, temporary, target, mode = sys.argv[1:5]
try:
    with open(source, "rb") as reader, open(temporary, "xb") as writer:
        shutil.copyfileobj(reader, writer)
        os.fchmod(writer.fileno(), int(mode, 8))
        writer.flush()
        os.fsync(writer.fileno())
    os.replace(temporary, target)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
}

atomic_restore() {
  local source="$1"
  local target="$2"
  local temporary="${target}.${RELEASE_ID}.rollback"
  if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
     [[ "${FB_VERIFY_TEST_FAIL_ROLLBACK_RESTORE:-0}" == "1" ]]; then
    printf 'injected rollback restore failure\n' >&2
    return 1
  fi
  "$PYTHON_BIN" - "$source" "$temporary" "$target" <<'PY'
import os, shutil, stat, sys
source, temporary, target = sys.argv[1:4]
try:
    with open(source, "rb") as reader, open(temporary, "xb") as writer:
        shutil.copyfileobj(reader, writer)
        os.fchmod(writer.fileno(), stat.S_IMODE(os.fstat(reader.fileno()).st_mode))
        writer.flush()
        os.fsync(writer.fileno())
    os.replace(temporary, target)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
}

fsync_directory() {
  local directory="$1"
  "$PYTHON_BIN" - "$directory" <<'PY'
import os, sys
descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

atomic_symlink_wrapper() {
  local target="$1"
  local temporary="${target}.${RELEASE_ID}.failclosed-link"
  local release_target="releases/${RELEASE_ID}/deployment_entrypoint.sh"
  "$PYTHON_BIN" - "$temporary" "$target" "$release_target" <<'PY'
import os, pathlib, sys
temporary, target, release_target = map(pathlib.Path, sys.argv[1:4])
try:
    os.symlink(str(release_target), temporary)
    os.replace(temporary, target)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
}

install_failclosed_regular() {
  local name="$1"
  local target_name="${FB_VERIFY_TEST_FAIL_FAILCLOSED_WRAPPER_NAME:-run_nightly_single_page_fb_verify.sh}"
  if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && [[ "$name" == "$target_name" ]] && \
     [[ "${FB_VERIFY_TEST_FAIL_FAILCLOSED_WRAPPER_INSTALL:-0}" == "1" ]]; then
    printf 'injected fail-closed regular-wrapper install failure: %s\n' "$name" >&2
    return 1
  fi
  atomic_install "${FINAL_RELEASE}/deployment_entrypoint.sh" "${DEPLOY_DIR}/${name}" 755
}

record_failclosed_failure() {
  local details="$1"
  "$PYTHON_BIN" - "${ROLLBACK_DIR}/FAILCLOSED_WRAPPER_FAILURES" "$details" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
with path.open("a", encoding="utf-8") as handle:
    handle.write(sys.argv[2] + "\n")
    handle.flush()
    os.fsync(handle.fileno())
descriptor = os.open(str(path.parent), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

converge_failclosed_wrappers() {
  local name
  local install_code
  local failed=""
  # If restoring the old generation is not provably durable, every stable
  # executable must instead converge on the already-validated new launcher.
  # A relative symlink to the immutable release is the independent fallback if
  # copying the regular wrapper itself fails.
  for name in $ENTRYPOINT_NAMES; do
    install_failclosed_regular "$name"
    install_code=$?
    if [[ "$install_code" != "0" ]]; then
      atomic_symlink_wrapper "${DEPLOY_DIR}/${name}"
      install_code=$?
    fi
    if [[ "$install_code" != "0" ]]; then
      failed="${failed}${failed:+,}${name}"
      printf 'cannot converge stable entrypoint to fail-closed wrapper: %s\n' "$name" >&2
    fi
  done

  fsync_directory "$DEPLOY_DIR"
  install_code=$?
  if [[ "$install_code" != "0" ]]; then
    failed="${failed}${failed:+,}DEPLOY_DIR_FSYNC"
  fi

  "$PYTHON_BIN" - "${FINAL_RELEASE}/deployment_entrypoint.sh" "$DEPLOY_DIR" \
    $ENTRYPOINT_NAMES <<'PY'
import os, pathlib, stat, sys
source = pathlib.Path(sys.argv[1])
deploy = pathlib.Path(sys.argv[2])
expected_link = pathlib.Path("releases") / source.parent.name / source.name
expected_bytes = source.read_bytes()
for name in sys.argv[3:]:
    target = deploy / name
    if target.is_symlink():
        if pathlib.Path(os.readlink(target)) != expected_link:
            raise SystemExit(f"unexpected fail-closed symlink target: {target}")
        continue
    status = target.lstat()
    if not stat.S_ISREG(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o755:
        raise SystemExit(f"fail-closed wrapper is not a mode-0755 regular file: {target}")
    if target.read_bytes() != expected_bytes:
        raise SystemExit(f"fail-closed wrapper bytes differ from validated launcher: {target}")
PY
  install_code=$?
  if [[ "$install_code" != "0" ]]; then
    failed="${failed}${failed:+,}VERIFY"
  fi

  if [[ -n "$failed" ]]; then
    record_failclosed_failure "$failed"
    install_code=$?
    if [[ "$install_code" != "0" ]]; then
      printf 'could not durably record fail-closed convergence failure: %s\n' "$failed" >&2
    fi
    return 1
  fi
  return 0
}

cleanup() {
  local code=$?
  local rollback_ok=1
  local rollback_code=0
  set +e
  if [[ "$ROLLBACK_NEEDED" == "1" ]] && [[ "$RUNTIME_COMMITTED" != "1" ]]; then
    # Roll back both the current pointer and every stable entry if any
    # post-switch install fails. Each path is always a complete old or new
    # file; an already-started wrapper has already pinned a complete release.
    for name in $STABLE_NAMES; do
      if [[ -f "${ROLLBACK_DIR}/${name}" ]]; then
        atomic_restore "${ROLLBACK_DIR}/${name}" "${DEPLOY_DIR}/${name}"
        rollback_code=$?
      else
        "$PYTHON_BIN" - "${DEPLOY_DIR}/${name}" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
try:
    path.unlink()
except FileNotFoundError:
    pass
PY
        rollback_code=$?
      fi
      if [[ "$rollback_code" != "0" ]]; then
        rollback_ok=0
      fi
    done
    if [[ "$rollback_ok" == "1" ]] && [[ "$OLD_CURRENT_PRESENT" == "1" ]]; then
      rollback_link="${DEPLOY_DIR}/.current.${RELEASE_ID}.rollback"
      ln -s "$OLD_CURRENT_TARGET" "$rollback_link"
      rollback_code=$?
      if [[ "$rollback_code" == "0" ]]; then
        "$PYTHON_BIN" - "$rollback_link" "${DEPLOY_DIR}/current" <<'PY'
import os, sys
os.replace(sys.argv[1], sys.argv[2])
PY
        rollback_code=$?
      fi
      [[ "$rollback_code" == "0" ]] || rollback_ok=0
    elif [[ "$rollback_ok" == "1" ]]; then
      "$PYTHON_BIN" - "${DEPLOY_DIR}/current" <<'PY'
import pathlib, sys
try:
    pathlib.Path(sys.argv[1]).unlink()
except FileNotFoundError:
    pass
PY
      rollback_code=$?
      [[ "$rollback_code" == "0" ]] || rollback_ok=0
    fi
    if [[ "$rollback_ok" == "1" ]]; then
      if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
         [[ "${FB_VERIFY_TEST_FAIL_ROLLBACK_FSYNC:-0}" == "1" ]]; then
        printf 'injected rollback directory fsync failure\n' >&2
        false
      else
        fsync_directory "$DEPLOY_DIR"
      fi
      rollback_code=$?
      [[ "$rollback_code" == "0" ]] || rollback_ok=0
    fi
    if [[ "$rollback_ok" != "1" ]]; then
      printf 'rollback was incomplete; converging all stable entrypoints to gate-aware wrappers\n' >&2
      converge_failclosed_wrappers
      rollback_code=$?
      if [[ "$rollback_code" != "0" ]]; then
        printf 'fail-closed entrypoint convergence was incomplete; retaining evidence\n' >&2
      fi
      printf 'retaining deployment gate and rollback evidence\n' >&2
      code=70
    else
      ROLLBACK_NEEDED=0
      rm -rf -- "$ROLLBACK_DIR"
    fi
  fi
  # Never lift the gate after a failed restore/fsync: doing so could expose a
  # mixed wrapper/current set.  A successful rollback is durable before this
  # owner-safe gate release is attempted.
  if [[ "$GATE_INSTALLED" == "1" ]] && [[ "$ROLLBACK_NEEDED" != "1" ]]; then
    "$PYTHON_BIN" - "$DEPLOY_GATE" "$GATE_TOKEN" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
try:
    if path.is_symlink() or path.read_text(encoding="ascii") != sys.argv[2] + "\n":
        raise SystemExit("deployment gate ownership changed before rollback completion")
    path.unlink()
    descriptor = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
except FileNotFoundError:
    raise SystemExit("deployment gate disappeared before rollback completion")
PY
    rollback_code=$?
    if [[ "$rollback_code" != "0" ]]; then
      printf 'failed to remove deployment gate after durable rollback\n' >&2
      code=70
    else
      GATE_INSTALLED=0
    fi
  fi
  safe_remove_stage
  if [[ "$ROLLBACK_NEEDED" != "1" ]]; then
    rm -rf -- "$ROLLBACK_DIR"
  fi
  trap - EXIT
  # The initial lock helper execs this shell, preserving its PID as the
  # release capability.  Replace this exact outer shell with the helper only
  # after every rollback/gate/evidence action above is finished; a nested
  # process that merely inherited the fd cannot satisfy that PID check.
  if [[ "${FB_VERIFY_LOCK_OWNER_PID:-}" == "$$" ]]; then
    exec "$PYTHON_BIN" "${SOURCE_DIR}/scripts/locked_exec.py" \
      --lock "$DEPLOY_LOCK" --fd-env FB_VERIFY_DEPLOY_LOCK_FD \
      --active-env FB_VERIFY_DEPLOY_LOCK_ACTIVE --label "FB verifier deployment" \
      --release-owned --exit-code "$code"
  fi
  exit "$code"
}
trap cleanup EXIT

mkdir -p "$RELEASES_DIR"
if [[ ! -d "${DEPLOY_DIR}/data" ]] || [[ -L "${DEPLOY_DIR}/data" ]]; then
  printf 'persistent data directory must be explicitly initialized before deploy: %s\n' \
    "${DEPLOY_DIR}/data" >&2
  exit 66
fi
mkdir -p "${STAGE_DIR}/scripts" "${STAGE_DIR}/tests"
rsync -a --delete --exclude '__pycache__/' --exclude '*.pyc' \
  "${SOURCE_DIR}/scripts/" "${STAGE_DIR}/scripts/"
[[ -f "${STAGE_DIR}/scripts/notify_dingtalk.py" ]] || { printf 'staged release missing notifier\n' >&2; exit 2; }
cp "${SOURCE_DIR}/tests/test_notify_dingtalk.py" "${STAGE_DIR}/tests/test_notify_dingtalk.py"
chmod 0644 "${STAGE_DIR}/scripts/notify_dingtalk.py" "${STAGE_DIR}/tests/test_notify_dingtalk.py"
for name in \
  README.md \
  deployment_entrypoint.sh \
  run_daily_fb_verify.sh \
  run_nightly_single_page_fb_verify.sh \
  sync_deploy.sh \
  com.spspy.fb-verify.plist \
  com.spspy.single-page-fb-nightly.plist; do
  cp "${SOURCE_DIR}/${name}" "${STAGE_DIR}/${name}"
done
chmod +x \
  "${STAGE_DIR}/deployment_entrypoint.sh" \
  "${STAGE_DIR}/run_daily_fb_verify.sh" \
  "${STAGE_DIR}/run_nightly_single_page_fb_verify.sh" \
  "${STAGE_DIR}/sync_deploy.sh"

# A directory rename is only a durable release publication after every staged
# regular file (including its final mode) and every directory entry has been
# flushed.  Do this after chmod so an executable bit cannot be lost across a
# power failure.
"$PYTHON_BIN" - "$STAGE_DIR" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
for path in sorted(root.rglob("*"), key=lambda item: (len(item.parts), str(item)), reverse=True):
    status = path.lstat()
    if stat.S_ISREG(status.st_mode):
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    elif stat.S_ISDIR(status.st_mode):
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        raise SystemExit(f"staged release contains unsupported non-regular path: {path}")
descriptor = os.open(str(root), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY

# Validate the complete isolated release before anything live is changed.
"$PYTHON_BIN" - "${STAGE_DIR}/scripts" "${STAGE_DIR}/tests/test_notify_dingtalk.py" <<'PY'
import pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
files = sorted(root.glob("*.py"))
if not files:
    raise SystemExit("staged release has no Python scripts")
for path in files:
    compile(path.read_bytes(), str(path), "exec")
test_path = pathlib.Path(sys.argv[2])
for path in (root / "notify_dingtalk.py", test_path):
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o644 or details.st_nlink != 1:
        raise SystemExit(f"staged notifier artifact is unsafe: {path}")
compile(test_path.read_bytes(), str(test_path), "exec")
PY
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" "${STAGE_DIR}/tests/test_notify_dingtalk.py"
HOME="${STAGE_DIR}/.validation-no-home" PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" - "${STAGE_DIR}/scripts/notify_dingtalk.py" <<'PY'
import contextlib, io, os, runpy, sys
target = sys.argv[1]
production_home = "/Users/tonyaiuser"
production_secret_dir = production_home + "/.openclaw/secrets/sp-monitor"
credential_components = {".openclaw", "secrets", "sp-monitor", "report_delivery.json"}
if os.path.exists(os.environ["HOME"]):
    raise SystemExit("notifier validation HOME must not exist")
def audit(event, args):
    if event.startswith("socket."):
        raise RuntimeError("network disabled during notifier validation")
    if event == "open" and args:
        try:
            path = os.fspath(args[0])
        except TypeError:
            return
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if path == production_home or path.startswith(production_secret_dir + "/") or \
           (not os.path.isabs(path) and path in credential_components):
            raise RuntimeError("credential read during notifier validation")
sys.addaudithook(audit)
sys.argv = [target, "--verified-count", "1", "--matched-count", "1", "--fresh-count", "0", "--multi-site-count", "0", "--matched-products-json", "[]", "--batch-url", "", "--dashboard-url", "https://example.invalid/dashboard", "--dry-run"]
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    try:
        runpy.run_path(target, run_name="__main__")
    except SystemExit as exc:
        if exc.code not in (0, None): raise
if out.getvalue() != 'NOTIFY_SUMMARY_JSON {"sent":false,"dry_run":true}\n' or err.getvalue():
    raise SystemExit("staged notifier dry-run validation failed")
PY
found_node=0
for file in "${STAGE_DIR}/scripts/"*.mjs; do
  [[ -f "$file" ]] || continue
  found_node=1
  "$NODE_BIN" --check "$file"
done
[[ "$found_node" == "1" ]] || { printf 'staged release has no Node scripts\n' >&2; exit 2; }
bash -n "${STAGE_DIR}/deployment_entrypoint.sh"
bash -n "${STAGE_DIR}/run_daily_fb_verify.sh"
bash -n "${STAGE_DIR}/run_nightly_single_page_fb_verify.sh"
bash -n "${STAGE_DIR}/sync_deploy.sh"
if [[ ! -x "$PLUTIL_BIN" ]]; then
  printf 'plist validator is unavailable: %s\n' "$PLUTIL_BIN" >&2
  exit 2
fi
"$PLUTIL_BIN" -lint "${STAGE_DIR}/com.spspy.fb-verify.plist" >/dev/null
"$PLUTIL_BIN" -lint "${STAGE_DIR}/com.spspy.single-page-fb-nightly.plist" >/dev/null
[[ ! -e "${STAGE_DIR}/data" ]] || { printf 'staged release unexpectedly contains data\n' >&2; exit 2; }

# Test-only coordination point used to prove that every installed stable file
# comes from the validated stage, even if the mutable source changes afterward.
if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ -n "${FB_VERIFY_TEST_VALIDATION_READY_FILE:-}" ]]; then
  "$PYTHON_BIN" - \
    "$FB_VERIFY_TEST_VALIDATION_READY_FILE" \
    "${FB_VERIFY_TEST_VALIDATION_CONTINUE_FILE:-}" <<'PY'
import pathlib, sys, time
ready = pathlib.Path(sys.argv[1])
ready.parent.mkdir(parents=True, exist_ok=True)
ready.write_text("ready\n", encoding="utf-8")
if sys.argv[2]:
    proceed = pathlib.Path(sys.argv[2])
    deadline = time.monotonic() + 30
    while not proceed.exists():
        if time.monotonic() >= deadline:
            raise SystemExit(f"timed out waiting for {proceed}")
        time.sleep(0.02)
PY
fi

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ "${FB_VERIFY_TEST_FAIL_BEFORE_SWITCH:-0}" == "1" ]]; then
  printf 'injected deployment failure before release switch\n' >&2
  exit 97
fi

# Stage and releases share a filesystem, so this rename publishes an immutable
# release directory atomically. The current symlink is the single code commit
# point; already-running wrappers have resolved and retain their old release.
mv "$STAGE_DIR" "$FINAL_RELEASE"
STAGE_DIR=""
fsync_directory "$RELEASES_DIR"
if [[ -L "${DEPLOY_DIR}/current" ]]; then
  OLD_CURRENT_PRESENT=1
  OLD_CURRENT_TARGET="$(readlink "${DEPLOY_DIR}/current")"
elif [[ -e "${DEPLOY_DIR}/current" ]]; then
  printf 'refusing to replace non-symlink current path: %s\n' "${DEPLOY_DIR}/current" >&2
  exit 2
fi
mkdir "$ROLLBACK_DIR"
for name in $STABLE_NAMES; do
  if [[ -e "${DEPLOY_DIR}/${name}" ]] || [[ -L "${DEPLOY_DIR}/${name}" ]]; then
    cp -p "${DEPLOY_DIR}/${name}" "${ROLLBACK_DIR}/${name}"
  fi
done
ROLLBACK_NEEDED=1

# Gate every stable entrypoint before draining processes that may have read an
# older wrapper/release but have not acquired its legacy mkdir lock yet.
if [[ -e "$DEPLOY_GATE" ]] || [[ -L "$DEPLOY_GATE" ]]; then
  printf 'deployment gate already exists; refusing to overwrite: %s\n' "$DEPLOY_GATE" >&2
  exit 75
fi
GATE_INSTALLED=1
"$PYTHON_BIN" - "$DEPLOY_GATE" "$GATE_TOKEN" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
with path.open("x", encoding="ascii") as handle:
    handle.write(sys.argv[2] + "\n")
    handle.flush()
    os.fsync(handle.fileno())
descriptor = os.open(str(path.parent), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY

# Launchd keeps these stable paths.  While the gate exists, the validated
# launcher returns 75 before resolving current; no post-gate old process can
# start.  Then wait for every pre-gate old entrypoint to leave.
wrapper_index=0
for name in run_daily_fb_verify.sh run_nightly_single_page_fb_verify.sh sync_deploy.sh; do
  atomic_install "${FINAL_RELEASE}/deployment_entrypoint.sh" "${DEPLOY_DIR}/${name}" 755
  wrapper_index=$((wrapper_index + 1))
  if [[ "$wrapper_index" == "1" ]] && \
     [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
     [[ "${FB_VERIFY_TEST_FAIL_DURING_WRAPPER_INSTALL:-0}" == "1" ]]; then
    printf 'injected deployment failure during stable wrapper install\n' >&2
    exit 98
  fi
done
"$PYTHON_BIN" "${FINAL_RELEASE}/scripts/wait_for_legacy_entrypoints.py" \
  --deploy-root "$DEPLOY_DIR" --source-root "$SOURCE_DIR" \
  --timeout "${FB_VERIFY_DEPLOY_DRAIN_TIMEOUT:-30}"

current_temp="${DEPLOY_DIR}/.current.${RELEASE_ID}.tmp"
ln -s "releases/${RELEASE_ID}" "$current_temp"
"$PYTHON_BIN" - "$current_temp" "${DEPLOY_DIR}/current" <<'PY'
import os, pathlib, sys
temporary = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
os.replace(temporary, target)
PY
if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ "${FB_VERIFY_TEST_FAIL_AFTER_CURRENT_REPLACE:-0}" == "1" ]]; then
  printf 'injected failure after current replace and before directory fsync\n' >&2
  exit 99
fi
"$PYTHON_BIN" - "$DEPLOY_DIR" <<'PY'
import os, sys
descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY

for name in README.md com.spspy.fb-verify.plist com.spspy.single-page-fb-nightly.plist; do
  atomic_install "${FINAL_RELEASE}/${name}" "${DEPLOY_DIR}/${name}" 644
done
if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ "${FB_VERIFY_TEST_FAIL_FINAL_FSYNC:-0}" == "1" ]]; then
  printf 'injected final deployment-directory fsync failure\n' >&2
  exit 100
fi
"$PYTHON_BIN" - "$DEPLOY_DIR" <<'PY'
import os, sys
descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
RUNTIME_COMMITTED=1
ROLLBACK_NEEDED=0
rm -rf -- "$ROLLBACK_DIR"
"$PYTHON_BIN" - "$DEPLOY_GATE" "$GATE_TOKEN" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
if path.is_symlink() or path.read_text(encoding="ascii") != sys.argv[2] + "\n":
    raise SystemExit("deployment gate ownership changed before commit")
path.unlink()
descriptor = os.open(str(path.parent), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
GATE_INSTALLED=0

printf 'FB verification release %s activated at %s (persistent data unchanged)\n' \
  "$RELEASE_ID" "$DEPLOY_DIR"
