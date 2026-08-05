#!/usr/bin/env bash
# 每晚一次完整单页扫描 → FB 增量验证。
#
# 现有每小时巡检只做 products.json 可用性与数量检查，不能产生单页命中；本脚本才是
# 夜间完整扫描入口。单页监控的原始钉钉通过环境变量关闭，只有 FB 验证到新组后才会推送。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
DATA_ROOT="${FB_VERIFY_DATA_ROOT:-${SCRIPT_DIR}/data}"
MONITOR_DIR="${SP_SINGLE_PAGE_MONITOR_DIR:-/Users/tonyaiuser/.spspy-single-page-monitor/single-page-monitor}"
LOG_DIR="${FB_VERIFY_LOG_DIR:-$HOME/.openclaw/logs/automation}"
LOG_FILE="${LOG_DIR}/fb_nightly.log"
LOCK_FILE="${FB_VERIFY_RUN_LOCK_PATH:-${DATA_ROOT}/run_daily.lock}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
SELF_TARGET="${SCRIPT_DIR}/run_nightly_single_page_fb_verify.sh"

if [[ "${FB_VERIFY_LOCK_SUPERVISED_TARGET:-}" != "$SELF_TARGET" ]]; then
  exec "$PYTHON_BIN" "${SCRIPTS_DIR}/locked_exec.py" \
    --lock "$LOCK_FILE" \
    --fd-env FB_VERIFY_RUN_LOCK_FD \
    --active-env FB_VERIFY_RUN_LOCK_ACTIVE \
    --label "FB verifier run" --busy-exit 75 \
    --supervise -- "$SELF_TARGET" "$@"
fi

mkdir -p "$LOG_DIR" "$DATA_ROOT"

log() {
  printf '[%s] %s\n' "$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S%z')" "$*" | tee -a "$LOG_FILE"
}

LOCK_ACQUIRED=0
handle_termination() {
  local signal_exit_code="$1"
  trap '' HUP INT TERM
  exit "$signal_exit_code"
}

cleanup() {
  local code=$?
  trap - EXIT
  trap '' HUP INT TERM
  set +e
  if [[ "$code" == "0" ]]; then
    log "===== nightly single-page → FB run end OK ====="
  else
    log "===== nightly single-page → FB run FAILED exit=${code} ====="
  fi
  LOCK_ACQUIRED=0
  exit "$code"
}
trap cleanup EXIT
trap 'handle_termination 129' HUP
trap 'handle_termination 130' INT
trap 'handle_termination 143' TERM

"$PYTHON_BIN" "${SCRIPTS_DIR}/locked_exec.py" \
  --lock "$LOCK_FILE" \
  --fd-env FB_VERIFY_RUN_LOCK_FD \
  --active-env FB_VERIFY_RUN_LOCK_ACTIVE \
  --label "FB verifier run" --busy-exit 75 --validate-only
LOCK_ACQUIRED=1

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ -n "${FB_VERIFY_TEST_LOCK_READY_FILE:-}" ]]; then
  : > "$FB_VERIFY_TEST_LOCK_READY_FILE"
  while [[ -n "${FB_VERIFY_TEST_LOCK_CONTINUE_FILE:-}" ]] && \
        [[ ! -e "${FB_VERIFY_TEST_LOCK_CONTINUE_FILE}" ]]; do
    sleep 0.02
  done
fi

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ "${FB_VERIFY_TEST_EXIT_AFTER_LOCK:-0}" == "1" ]]; then
  log "injected nightly exit immediately after lock acquisition"
  exit 96
fi

if [[ ! -x "${MONITOR_DIR}/run_daily.sh" ]]; then
  log "missing deployed single-page monitor: ${MONITOR_DIR}/run_daily.sh"
  exit 2
fi

log "===== nightly single-page → FB run start ====="
log "--- step 1/2: full single-page scan and dashboard publish (raw single-page DingTalk disabled) ---"
SP_SINGLE_PAGE_RUN_KIND=nightly_fb SP_SINGLE_PAGE_SEND_DINGTALK=0 "${MONITOR_DIR}/run_daily.sh"

log "--- step 2/2: FB incremental verification (same-day incremental allowed) ---"
FB_VERIFY_ALLOW_SAME_DAY=1 "${SCRIPT_DIR}/run_daily_fb_verify.sh"

log "===== nightly pipeline finished ====="
