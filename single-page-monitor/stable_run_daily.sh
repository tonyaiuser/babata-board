#!/usr/bin/env bash
# Stable launchd entrypoint.  It acquires the shared kernel lock, resolves one
# immutable release to an absolute path, then execs that pinned release.
set -euo pipefail

DEPLOY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
RUNTIME_DIR="${DEPLOY_ROOT}/single-page-monitor"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
LOCK_HELPER="${RUNTIME_DIR}/locked_exec.py"
LOCK_PATH="${RUNTIME_DIR}/data/run_daily.lock"

export SP_SINGLE_PAGE_DATA_DIR="${SP_SINGLE_PAGE_DATA_DIR:-${RUNTIME_DIR}/data}"
export SP_SINGLE_PAGE_LOG_DIR="${SP_SINGLE_PAGE_LOG_DIR:-${RUNTIME_DIR}/logs}"
export SP_SINGLE_PAGE_REPORTS_DIR="${SP_SINGLE_PAGE_REPORTS_DIR:-${RUNTIME_DIR}/reports}"
export SP_SINGLE_PAGE_LOCK_DIR="${SP_SINGLE_PAGE_LOCK_DIR:-${LOCK_PATH}}"
export SP_SINGLE_PAGE_LOCK_HELPER="${SP_SINGLE_PAGE_LOCK_HELPER:-${LOCK_HELPER}}"
export SP_SINGLE_PAGE_DEPLOY_ROOT="${SP_SINGLE_PAGE_DEPLOY_ROOT:-${DEPLOY_ROOT}}"
export SP_SINGLE_PAGE_PAGES_DIR="${SP_SINGLE_PAGE_PAGES_DIR:-${DEPLOY_ROOT}/.pages/babata-board-pages-main}"

if [[ -z "${SP_SINGLE_PAGE_LOCK_ACTIVE:-}" ]]; then
  exec "${PYTHON_BIN}" "${LOCK_HELPER}" \
    --lock "${SP_SINGLE_PAGE_LOCK_DIR}" --lock-dir "${SP_SINGLE_PAGE_DATA_DIR}" \
    --fd-env SP_SINGLE_PAGE_LOCK_FD \
    --active-env SP_SINGLE_PAGE_LOCK_ACTIVE --label "single-page runtime" \
    --busy-exit 75 -- "${RUNTIME_DIR}/run_daily.sh" "$@"
fi
"${PYTHON_BIN}" "${LOCK_HELPER}" \
  --lock "${SP_SINGLE_PAGE_LOCK_DIR}" --lock-dir "${SP_SINGLE_PAGE_DATA_DIR}" \
  --fd-env SP_SINGLE_PAGE_LOCK_FD \
  --active-env SP_SINGLE_PAGE_LOCK_ACTIVE --label "single-page runtime" \
  --busy-exit 75 --validate-only

set +e
PINNED_RUNNER="$("${PYTHON_BIN}" - "${DEPLOY_ROOT}" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve()
current = root / "current"
releases = root / "releases"
releases_status = releases.lstat()
if not stat.S_ISDIR(releases_status.st_mode) or releases.is_symlink():
    raise SystemExit(f"releases must be a real directory: {releases}")
try:
    status = current.lstat()
except FileNotFoundError as exc:
    raise SystemExit("No validated single-page-monitor release is active.") from exc
if not stat.S_ISLNK(status.st_mode):
    raise SystemExit(f"current must be a symlink: {current}")
raw = os.readlink(current)
parts = pathlib.PurePosixPath(raw).parts
if os.path.isabs(raw) or len(parts) != 2 or parts[0] != "releases" or parts[1] in {"", ".", ".."}:
    raise SystemExit(f"unsafe current target: {raw}")
release = root / "releases" / parts[1]
release_status = release.lstat()
if not stat.S_ISDIR(release_status.st_mode) or release.is_symlink():
    raise SystemExit(f"current release is not a real directory: {release}")
release_real = release.resolve(strict=True)
if release_real.parent != releases.resolve(strict=True):
    raise SystemExit("current release resolves outside releases")
monitor = release / "single-page-monitor"
monitor_status = monitor.lstat()
if not stat.S_ISDIR(monitor_status.st_mode) or monitor.is_symlink():
    raise SystemExit(f"release monitor path is not a real directory: {monitor}")
monitor_real = monitor.resolve(strict=True)
if monitor_real.parent != release_real:
    raise SystemExit("release monitor resolves outside the selected release")
runner = monitor / "run_daily.sh"
runner_status = runner.lstat()
if not stat.S_ISREG(runner_status.st_mode) or runner.is_symlink() or not os.access(runner, os.X_OK):
    raise SystemExit(f"pinned runner is not an executable regular file: {runner}")
runner_real = runner.resolve(strict=True)
if runner_real.parent != monitor_real or release_real not in runner_real.parents:
    raise SystemExit("pinned runner resolves outside the selected release")
print(runner_real)
PY
)"
pin_code="$?"
set -e
if [[ "${pin_code}" != "0" || -z "${PINNED_RUNNER}" ]]; then
  exit 70
fi

if [[ "${SP_SINGLE_PAGE_TEST_MODE:-0}" == "1" ]] && \
   [[ -n "${SP_SINGLE_PAGE_TEST_PIN_READY_FILE:-}" ]]; then
  printf '%s\n' "${PINNED_RUNNER}" > "${SP_SINGLE_PAGE_TEST_PIN_READY_FILE}"
  if [[ -n "${SP_SINGLE_PAGE_TEST_PIN_CONTINUE_FILE:-}" ]]; then
    pin_wait_count=0
    while [[ ! -e "${SP_SINGLE_PAGE_TEST_PIN_CONTINUE_FILE}" ]]; do
      sleep 0.02
      pin_wait_count=$((pin_wait_count + 1))
      if (( pin_wait_count > 1500 )); then
        echo "Timed out waiting for pinned-release test continuation." >&2
        exit 70
      fi
    done
  fi
fi

exec "${PINNED_RUNNER}" "$@"
