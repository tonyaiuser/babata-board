#!/usr/bin/env bash
# 每日 FB 广告库验证流水线编排入口。
#
# 在单页监控(com.spspy.single-page-monitor, 每天 08:30 启动)之后运行，
# 对持久事件流中新发现且尚未处理的单页产品做 FB 广告库验证 + 抓产品图，更新月累计看板，发布到
# GitHub Pages babata-board 仓库。详见同目录 README.md。
#
# 幂等：仅当天已完整发布且无待重试组才跳过（见 data/last_published_success.txt）。
# 并发保护：data/run_daily.lock 的内核 fcntl/flock 锁。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
# Validate the bounded image-step policy (wall 60..1200s, grace 1..30s) before
# creating log/data directories, acquiring locks, reading durable state, or
# starting any pipeline command.
IMAGE_WALL_TIMEOUT_SECONDS="${FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS:-1200}"
IMAGE_WATCHDOG_GRACE_SECONDS="${FB_VERIFY_IMAGE_WATCHDOG_GRACE_SECONDS:-10}"
# A direct invocation validates policy before the lock helper is allowed to
# create the lock parent.  A nested nightly -> daily call enters its own active
# supervisor first, then validates in that supervised child.
if [[ -z "${FB_VERIFY_RUN_LOCK_ACTIVE:-}" ]]; then
  "$PYTHON_BIN" "${SCRIPTS_DIR}/run_with_watchdog.py" \
    --daily-policy --validate-only \
    --timeout-seconds "$IMAGE_WALL_TIMEOUT_SECONDS" \
    --grace-seconds "$IMAGE_WATCHDOG_GRACE_SECONDS"
fi

DATA_ROOT="${FB_VERIFY_DATA_ROOT:-${SCRIPT_DIR}/data}"
# 线上 launchd 从 ~/.spspy-fb-verify/fb-verify 运行整套部署副本；本地手动运行时默认同目录脚本。
NODE_SCRIPTS_DIR="${FB_VERIFY_NODE_SCRIPTS_DIR:-$SCRIPTS_DIR}"

LOG_DIR="${FB_VERIFY_LOG_DIR:-$HOME/.openclaw/logs/automation}"
LOG_FILE="${LOG_DIR}/fb_verify.log"
ERR_FILE="${LOG_DIR}/fb_verify.err.log"
LOCK_FILE="${FB_VERIFY_RUN_LOCK_PATH:-${DATA_ROOT}/run_daily.lock}"
SELF_TARGET="${SCRIPT_DIR}/run_daily_fb_verify.sh"

# The owner helper remains alive while this target runs.  A nested invocation
# gets an active (non-owning) supervisor so TERM/HUP/INT cascade through the
# nightly -> daily boundary without releasing the outer lock early.
if [[ "${FB_VERIFY_LOCK_SUPERVISED_TARGET:-}" != "$SELF_TARGET" ]]; then
  exec "$PYTHON_BIN" "${SCRIPTS_DIR}/locked_exec.py" \
    --lock "$LOCK_FILE" \
    --fd-env FB_VERIFY_RUN_LOCK_FD \
    --active-env FB_VERIFY_RUN_LOCK_ACTIVE \
    --label "FB verifier run" --busy-exit 75 \
    --supervise --ready-handshake -- "$SELF_TARGET" "$@"
fi

# Every supervised child validates the policy itself.  Direct calls have
# intentionally performed the same check once before lock-parent creation.
"$PYTHON_BIN" "${SCRIPTS_DIR}/run_with_watchdog.py" \
  --daily-policy --validate-only \
  --timeout-seconds "$IMAGE_WALL_TIMEOUT_SECONDS" \
  --grace-seconds "$IMAGE_WATCHDOG_GRACE_SECONDS"

mkdir -p "$LOG_DIR" "$DATA_ROOT"

TODAY="$(TZ=Asia/Shanghai date +%Y-%m-%d)"
MONTH="$(TZ=Asia/Shanghai date +%Y-%m)"
RUN_SLUG="$(TZ=Asia/Shanghai date +%Y-%m-%d-%H%M%S)-$$"
MONTH_DIR="${DATA_ROOT}/${MONTH}"
# Attempts, completed checkpoints, and a fully published/drained run are
# distinct states.  Only the last of these is eligible for same-day idempotency.
ATTEMPT_FILE="${DATA_ROOT}/last_attempt_date.txt"
ATTEMPT_ID_FILE="${DATA_ROOT}/last_attempt_id.txt"
PUBLISHED_SUCCESS_FILE="${DATA_ROOT}/last_published_success.txt"
PIPELINE_STATUS_FILE="${FB_VERIFY_PIPELINE_STATUS_FILE:-${DATA_ROOT}/pipeline_status.json}"
ATTEMPT_LEDGER_DIR="${FB_VERIFY_ATTEMPT_LEDGER_DIR:-${DATA_ROOT}/attempt_ledger}"
# The stable deployment wrapper resolves and exports this from its immutable
# release directory exactly once.  Direct source runs use a fixed local marker;
# neither path consults the mutable `current` symlink here.
RELEASE_ID="${FB_VERIFY_RELEASE_ID:-source_local}"

# Resolve Node only after the run lock is owned.  A missing local executable is
# a terminal attempt failure, not an untracked preflight exit.
NODE_BIN="${NODE_BIN:-}"
BUILD_PAGE_SCRIPT="${FB_VERIFY_BUILD_PAGE_SCRIPT:-${SCRIPTS_DIR}/build_fb_verify_page.py}"
MERGE_SCRIPT="${FB_VERIFY_MERGE_SCRIPT:-${SCRIPTS_DIR}/merge_duplicate_query_groups.py}"
PREVIOUS_MONTH="$($PYTHON_BIN -c 'from datetime import datetime; import sys; d=datetime.strptime(sys.argv[1], "%Y-%m"); print(f"{d.year - (1 if d.month == 1 else 0):04d}-{(12 if d.month == 1 else d.month - 1):02d}")' "$MONTH")"
PREVIOUS_MONTH_DIR="${DATA_ROOT}/${PREVIOUS_MONTH}"
PREVIOUS_UNIQUE_JSON="${PREVIOUS_MONTH_DIR}/unique_products.json"
PREVIOUS_FULL_VERIFY_JSON="${PREVIOUS_MONTH_DIR}/product_verify_full.json"
PREVIOUS_IMAGES_JSON="${PREVIOUS_MONTH_DIR}/product_images.json"

SOURCE_NEW_HITS_CSV="${FB_VERIFY_NEW_HITS_CSV:-/Users/tonyaiuser/.spspy-single-page-monitor/single-page-monitor/reports/${MONTH}/new_hits.csv}"
MONITOR_EVENTS_JSONL="${FB_VERIFY_MONITOR_EVENTS_JSONL:-/Users/tonyaiuser/.spspy-single-page-monitor/single-page-monitor/data/events.jsonl}"
EVENT_CUTOFF_FILE="${FB_VERIFY_EVENT_CUTOFF_FILE:-${DATA_ROOT}/event_ingest_cutover_at.txt}"
MAX_GROUPS_PER_DAY="${FB_VERIFY_MAX_GROUPS:-40}"
BLANK_STREAK_LIMIT="${FB_VERIFY_BLANK_STREAK:-5}"
TARGET_DATE_OVERRIDE="${FB_VERIFY_TARGET_DATE:-}"
# 正常的 13:30 定时任务保持“一天成功一次”的幂等语义；夜间完整单页扫描完成后会传 1，
# 允许在同一天再消费新增事件。未验证组和 checkpoint 仍会确保不会重复查询同一产品组。
ALLOW_SAME_DAY="${FB_VERIFY_ALLOW_SAME_DAY:-0}"
# Image fetching is intentionally bounded separately from the full FB run.
# The helper puts only its child in a new process group, so a timeout leaves
# this shell alive to durably mark the attempt failed and release its lock.
IMAGE_FETCH_SCRIPT="${FB_VERIFY_IMAGE_FETCH_SCRIPT:-${SCRIPTS_DIR}/fetch_new_images.py}"

PAGES_REPO="${FB_VERIFY_PAGES_REPO:-https://github.com/tonyaiuser/babata-board.git}"
PAGES_DIR="${FB_VERIFY_PAGES_DIR:-${DATA_ROOT}/.pages/babata-board}"
PAGES_PUBLISH_SCRIPT="${FB_VERIFY_PAGES_PUBLISH_SCRIPT:-${SCRIPTS_DIR}/publish_fb_pages.py}"
PUBLIC_URL="${FB_VERIFY_PUBLIC_URL:-https://tonyaiuser.github.io/babata-board/fb_verify_dashboard.html}"
PUBLISH="${FB_VERIFY_PUBLISH:-1}"

# 钉钉推送：三态 send(真发) / dryrun(仅固定安全摘要，不读凭证不发) / off(完全跳过)。
# --no-dingtalk 命令行参数 或 FB_VERIFY_DINGTALK=0 都等价于 off；
# FB_VERIFY_DINGTALK_DRY_RUN=1 等价于 dryrun。手动验收测试时用这两个开关之一，避免真发消息打扰用户。
DINGTALK_MODE="send"
if [[ "${FB_VERIFY_DINGTALK:-1}" == "0" ]]; then
  DINGTALK_MODE="off"
elif [[ "${FB_VERIFY_DINGTALK_DRY_RUN:-0}" == "1" ]]; then
  DINGTALK_MODE="dryrun"
fi
for arg in "$@"; do
  if [[ "$arg" == "--no-dingtalk" ]]; then
    DINGTALK_MODE="off"
  elif [[ "$arg" == "--dingtalk-dry-run" ]]; then
    DINGTALK_MODE="dryrun"
  fi
done

mkdir -p "$MONTH_DIR"

log() {
  printf '[%s] %s\n' "$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S%z')" "$*" | tee -a "$LOG_FILE"
}

log_err() {
  printf '[%s] %s\n' "$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S%z')" "$*" | tee -a "$LOG_FILE" >> "$ERR_FILE"
}

atomic_write_text() {
  local target="$1"
  local value="$2"
  "$PYTHON_BIN" - "$target" "$value" <<'PY'
import os, pathlib, sys, time
target = pathlib.Path(sys.argv[1])
target.parent.mkdir(parents=True, exist_ok=True)
temporary = target.with_name(f".{target.name}.{os.getpid()}.{time.time_ns()}.tmp")
try:
    with temporary.open("x", encoding="utf-8") as handle:
        handle.write(sys.argv[2] + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)
    directory_fd = os.open(str(target.parent), os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    temporary.unlink(missing_ok=True)
PY
}

LOCK_ACQUIRED=0
PUBLISHED_OK=0
TERMINATED_EARLY=0
TRUNCATED_COUNT=0
PENDING_COUNT=0
FAILED_COUNT=0
PIPELINE_SKIPPED=0
STAMP_ADVANCED=0
PIPELINE_BODY_COMPLETE=0
ATTEMPT_PHASE="preflight"
ATTEMPT_STARTED_AT=""
ATTEMPT_LEDGER_WRITTEN=0

persist_terminal_attempt_ledger() {
  if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
     [[ "${FB_VERIFY_TEST_FAIL_ATTEMPT_LEDGER:-0}" == "1" ]]; then
    return 70
  fi
  "$PYTHON_BIN" "${SCRIPTS_DIR}/pipeline_status.py" \
    --write-attempt-ledger --ledger-dir "$ATTEMPT_LEDGER_DIR" \
    --attempt-id "$RUN_SLUG" --run-id "$RUN_SLUG" --release-id "$RELEASE_ID" \
    --phase "$ATTEMPT_PHASE" --started-at "$ATTEMPT_STARTED_AT" \
    --exit-code "$1" --publish-ok "$PUBLISHED_OK" \
    --terminated-early "$TERMINATED_EARLY" --truncated "$TRUNCATED_COUNT" \
    --pending "$PENDING_COUNT" --failed "$FAILED_COUNT" \
    --skipped "$PIPELINE_SKIPPED" --body-complete "$PIPELINE_BODY_COMPLETE"
}

persist_final_pipeline_status() {
  if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
     [[ "${FB_VERIFY_TEST_FAIL_STATUS_DOWNGRADE:-0}" == "1" ]] && \
     [[ "$1" != "0" ]]; then
    return 70
  fi
  "$PYTHON_BIN" "${SCRIPTS_DIR}/pipeline_status.py" \
    --out "$PIPELINE_STATUS_FILE" --date "$TODAY" --run-id "$RUN_SLUG" \
    --exit-code "$1" --publish-ok "$PUBLISHED_OK" \
    --terminated-early "$TERMINATED_EARLY" --truncated "$TRUNCATED_COUNT" \
    --pending "$PENDING_COUNT" --failed "$FAILED_COUNT" \
    --body-complete "$PIPELINE_BODY_COMPLETE" >> "$LOG_FILE" 2>> "$ERR_FILE"
}

invalidate_published_success_stamp() {
  if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
     [[ "${FB_VERIFY_TEST_FAIL_STAMP_INVALIDATION:-0}" == "1" ]]; then
    return 70
  fi
  atomic_write_text "$PUBLISHED_SUCCESS_FILE" "invalidated:${TODAY}:${RUN_SLUG}"
}

handle_termination() {
  # EXIT performs the durable terminal write.  Disable repeated signal delivery
  # first so it cannot interrupt the one-record commit path.
  local signal_exit_code="$1"
  trap '' HUP INT TERM
  exit "$signal_exit_code"
}

signal_supervisor_ready() {
  local ready_fd="${FB_VERIFY_LOCK_SUPERVISOR_READY_FD:-}"
  if [[ ! "$ready_fd" =~ ^[0-9]+$ ]]; then
    log_err "supervisor readiness descriptor is missing or invalid"
    exit 70
  fi
  if ! "$PYTHON_BIN" - \
      "$ready_fd" "$RUN_SLUG" "$RELEASE_ID" "$ATTEMPT_LEDGER_DIR" \
      "$ATTEMPT_STARTED_AT" <<'PY'
import json, os, pathlib, sys
descriptor = int(sys.argv[1], 10)
attempt_id, release_id, ledger_dir, started_at = sys.argv[2:6]
payload = json.dumps({
    "schema_version": 1,
    "kind": "fb_attempt",
    "attempt_id": attempt_id,
    "run_id": attempt_id,
    "release_id": release_id,
    "ledger_dir": str(pathlib.Path(ledger_dir).resolve()),
    "started_at": started_at,
}, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
if len(payload) > 4096:
    raise SystemExit("attempt readiness metadata is too large")
offset = 0
while offset < len(payload):
    written = os.write(descriptor, payload[offset:])
    if written <= 0:
        raise SystemExit("attempt readiness metadata write failed")
    offset += written
PY
  then
    log_err "failed to complete supervisor readiness handshake"
    exit 70
  fi
  eval "exec ${ready_fd}>&-"
  unset FB_VERIFY_LOCK_SUPERVISOR_READY_FD
}

cleanup() {
  local code=$?
  local status_code=0
  local stamp_code=0
  local ledger_code=0
  trap - EXIT
  trap '' HUP INT TERM
  # The exit path itself must not be stopped halfway through durable cleanup.
  set +e
  # Persist the terminal status only while this process owns the run lock.
  # A rejected concurrent invocation must not overwrite the active run's
  # status, and the lock is released only after the pipeline_status.py write
  # and immutable ledger commit are durable.
  if [[ "$LOCK_ACQUIRED" == "1" ]]; then
    if [[ "$PIPELINE_SKIPPED" != "1" ]]; then
      persist_final_pipeline_status "$code"
      status_code=$?
      if [[ "$status_code" != "0" ]]; then
        log_err "failed to atomically persist pipeline status: ${PIPELINE_STATUS_FILE}"
        ATTEMPT_PHASE="state"
        code=70
      fi

      # The success stamp is deliberately the final durable state write. It is
      # eligible only after the body summary and final status both succeeded.
      if [[ "$code" == "0" ]] && [[ "$PIPELINE_BODY_COMPLETE" == "1" ]] && \
         [[ "$PUBLISHED_OK" == "1" ]] && [[ "$TERMINATED_EARLY" != "1" ]] && \
         [[ "$TRUNCATED_COUNT" == "0" ]] && [[ "$PENDING_COUNT" == "0" ]] && \
         [[ "$FAILED_COUNT" == "0" ]]; then
        log "===== run_daily_fb_verify.sh end OK; committing published-success stamp ====="
        ATTEMPT_PHASE="atomic"
        atomic_write_text "$PUBLISHED_SUCCESS_FILE" "$TODAY"
        stamp_code=$?
        if [[ "$stamp_code" == "0" ]]; then
          STAMP_ADVANCED=1
          ATTEMPT_PHASE="complete"
        else
          code=70
          log_err "failed to atomically persist published-success stamp: ${PUBLISHED_SUCCESS_FILE}"
          ATTEMPT_PHASE="atomic"
          persist_final_pipeline_status "$code"
        fi
      elif [[ "$code" == "0" ]]; then
        log "===== run_daily_fb_verify.sh end PARTIAL; success stamp remains invalid ====="
      else
        log_err "===== run_daily_fb_verify.sh end FAILED exit=${code}; success stamp remains invalid ====="
      fi
    else
      log "===== run_daily_fb_verify.sh end SKIPPED; preserving prior success state ====="
    fi

    # The ledger is intentionally committed after all outcome-changing writes,
    # so it records the actual final terminal result.  It never replaces a
    # prior record.  A failed commit is fail-closed: a newly written success
    # stamp is invalidated and the mutable view is downgraded before unlock.
    if [[ "$ATTEMPT_LEDGER_WRITTEN" != "1" ]]; then
      persist_terminal_attempt_ledger "$code" >> "$LOG_FILE" 2>> "$ERR_FILE"
      ledger_code=$?
      if [[ "$ledger_code" == "0" ]]; then
        ATTEMPT_LEDGER_WRITTEN=1
      else
        log_err "failed to commit immutable attempt ledger: ${ATTEMPT_LEDGER_DIR}"
        if [[ "$code" == "0" ]]; then
          code=70
        fi
        if [[ "$STAMP_ADVANCED" == "1" ]]; then
          ATTEMPT_PHASE="atomic"
          invalidate_published_success_stamp
          stamp_code=$?
          if [[ "$stamp_code" != "0" ]]; then
            log_err "failed to invalidate published-success stamp after ledger failure: ${PUBLISHED_SUCCESS_FILE}"
          fi
          STAMP_ADVANCED=0
        fi
        if [[ "$PIPELINE_SKIPPED" != "1" ]]; then
          ATTEMPT_PHASE="state"
          persist_final_pipeline_status "$code"
          status_code=$?
          if [[ "$status_code" != "0" ]]; then
            log_err "failed to downgrade pipeline status after ledger failure: ${PIPELINE_STATUS_FILE}"
          fi
        fi
      fi
    fi
    if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
       [[ -n "${FB_VERIFY_TEST_FINAL_STATE_READY_FILE:-}" ]]; then
      "$PYTHON_BIN" - \
        "$FB_VERIFY_TEST_FINAL_STATE_READY_FILE" \
        "${FB_VERIFY_TEST_FINAL_STATE_CONTINUE_FILE:-}" <<'PY'
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
    # The non-active supervisor is the sole lock owner and releases only after
    # this cleanup returns.  A nested active supervisor never releases it.
    LOCK_ACQUIRED=0
  elif [[ "$code" != "0" ]]; then
    log_err "===== run_daily_fb_verify.sh end FAILED exit=${code} ====="
  fi
  exit "$code"
}
trap cleanup EXIT
trap 'handle_termination 129' HUP
trap 'handle_termination 130' INT
trap 'handle_termination 143' TERM

# --- 并发锁 ---
# locked_exec keeps the fd inheritable, so nightly -> daily reuses this exact
# open-file-description lock while unrelated invocations still fail with 75.
"$PYTHON_BIN" "${SCRIPTS_DIR}/locked_exec.py" \
  --lock "$LOCK_FILE" \
  --fd-env FB_VERIFY_RUN_LOCK_FD \
  --active-env FB_VERIFY_RUN_LOCK_ACTIVE \
  --label "FB verifier run" --busy-exit 75 --validate-only
LOCK_ACQUIRED=1
ATTEMPT_STARTED_AT="$("$PYTHON_BIN" - <<'PY'
from datetime import datetime
from zoneinfo import ZoneInfo

print(datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(timespec="seconds"))
PY
)"
ATTEMPT_PHASE="build"
signal_supervisor_ready

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ -n "${FB_VERIFY_TEST_LOCK_READY_FILE:-}" ]]; then
  : > "$FB_VERIFY_TEST_LOCK_READY_FILE"
  while [[ -n "${FB_VERIFY_TEST_LOCK_CONTINUE_FILE:-}" ]] && \
        [[ ! -e "${FB_VERIFY_TEST_LOCK_CONTINUE_FILE}" ]]; do
    sleep 0.02
  done
fi

if [[ -z "$NODE_BIN" ]]; then
  NODE_BIN="$(command -v node || true)"
elif [[ "$NODE_BIN" != */* ]]; then
  NODE_BIN="$(command -v "$NODE_BIN" || true)"
fi
if [[ -z "$NODE_BIN" ]] || [[ ! -x "$NODE_BIN" ]] || \
   [[ ! -r "${NODE_SCRIPTS_DIR}/run_verify_new_groups.mjs" ]] || \
   [[ ! -r "${NODE_SCRIPTS_DIR}/fb_product_verify.mjs" ]]; then
  log_err "missing required local FB verification build dependency"
  exit 66
fi

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ "${FB_VERIFY_TEST_EXIT_AFTER_LOCK:-0}" == "1" ]]; then
  log_err "injected daily exit immediately after lock acquisition"
  exit 96
fi

log "===== run_daily_fb_verify.sh start (month=${MONTH} today=${TODAY}) ====="

# --- 幂等跳过：可变三元组之外，还必须有同一发布版的不可变成功记录 ---
SUCCESS_STATE_MATCH=0
SUCCESS_TUPLE_MATCH=0
SUCCESS_ATTEMPT_ID=""
if [[ -f "$PUBLISHED_SUCCESS_FILE" ]] && [[ -f "$ATTEMPT_ID_FILE" ]] && \
   [[ -f "$PIPELINE_STATUS_FILE" ]]; then
  SUCCESS_TUPLE_MATCH="$($PYTHON_BIN - "$PUBLISHED_SUCCESS_FILE" "$ATTEMPT_ID_FILE" "$PIPELINE_STATUS_FILE" "$TODAY" <<'PY'
import json, pathlib, sys
stamp_path = pathlib.Path(sys.argv[1])
attempt_path = pathlib.Path(sys.argv[2])
status_path = pathlib.Path(sys.argv[3])
today = sys.argv[4]
try:
    stamp = stamp_path.read_text(encoding="utf-8").strip()
    attempt = attempt_path.read_text(encoding="utf-8").strip()
    status = json.loads(status_path.read_text(encoding="utf-8"))
    matched = (
        stamp == today and bool(attempt)
        and status.get("date") == today
        and status.get("run_id") == attempt
        and status.get("state") == "succeeded"
        and status.get("stamp_eligible") is True
    )
except Exception:
    matched = False
print("1" if matched else "0")
PY
)"
fi
if [[ "$SUCCESS_TUPLE_MATCH" == "1" ]]; then
  SUCCESS_ATTEMPT_ID="$(tr -d '[:space:]' < "$ATTEMPT_ID_FILE")"
  if "$PYTHON_BIN" "${SCRIPTS_DIR}/pipeline_status.py" \
      --check-success-ledger --ledger-dir "$ATTEMPT_LEDGER_DIR" \
      --attempt-id "$SUCCESS_ATTEMPT_ID" --release-id "$RELEASE_ID" \
      >> "$LOG_FILE" 2>> "$ERR_FILE"; then
    SUCCESS_STATE_MATCH=1
  else
    log "mutable success tuple has no exact immutable success evidence; rerun required"
  fi
fi
if [[ "$SUCCESS_STATE_MATCH" == "1" ]] && [[ "$ALLOW_SAME_DAY" != "1" ]]; then
  PIPELINE_SKIPPED=1
  ATTEMPT_PHASE="complete"
  log "already fully published and drained today (${TODAY}), skip (idempotent). stamp=${PUBLISHED_SUCCESS_FILE}"
  exit 0
elif [[ "$SUCCESS_STATE_MATCH" == "1" ]]; then
  log "already fully published today (${TODAY}), but FB_VERIFY_ALLOW_SAME_DAY=1: run incremental pass."
fi

# Writing the new attempt id first invalidates the old success tuple even if a
# later atomic write fails. Forced same-day runs also replace the old date stamp
# with an explicit non-success value before performing pipeline work.
ATTEMPT_PHASE="state"
atomic_write_text "$ATTEMPT_ID_FILE" "$RUN_SLUG"
atomic_write_text "$ATTEMPT_FILE" "$TODAY"
"$PYTHON_BIN" "${SCRIPTS_DIR}/pipeline_status.py" \
  --out "$PIPELINE_STATUS_FILE" --date "$TODAY" --run-id "$RUN_SLUG" \
  --exit-code 0 --publish-ok 0 --terminated-early 0 --truncated 0 \
  --pending 0 --failed 0 --body-complete 0 --in-progress 1 >> "$LOG_FILE" 2>> "$ERR_FILE"
if [[ -f "$PUBLISHED_SUCCESS_FILE" ]] && \
   [[ "$(cat "$PUBLISHED_SUCCESS_FILE" 2>/dev/null)" == "$TODAY" ]]; then
  atomic_write_text "$PUBLISHED_SUCCESS_FILE" "invalidated:${TODAY}:${RUN_SLUG}"
fi

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ "${FB_VERIFY_TEST_EXIT_AFTER_BEGIN:-0}" == "1" ]]; then
  log_err "injected failure after attempt began"
  exit 91
fi

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ "${FB_VERIFY_TEST_FORCE_SUCCESS_AFTER_BEGIN:-0}" == "1" ]]; then
  PUBLISHED_OK=1
  PIPELINE_BODY_COMPLETE=1
  ATTEMPT_PHASE="complete"
  exit 0
fi

if [[ "${FB_VERIFY_TEST_MODE:-0}" == "1" ]] && \
   [[ -n "${FB_VERIFY_TEST_SIGNAL_READY_FILE:-}" ]]; then
  : > "$FB_VERIFY_TEST_SIGNAL_READY_FILE"
  while [[ ! -e "${FB_VERIFY_TEST_SIGNAL_CONTINUE_FILE:-}" ]]; do
    sleep 0.02
  done
fi

UNIQUE_JSON="${MONTH_DIR}/unique_products.json"
FULL_VERIFY_JSON="${MONTH_DIR}/product_verify_full.json"
IMAGES_JSON="${MONTH_DIR}/product_images.json"
DASHBOARD_HTML="${MONTH_DIR}/fb_verify_dashboard.html"
BATCH_HTML=""
BATCH_RELATIVE_PATH=""
BATCH_PUBLIC_URL=""

# --- 1. 摄入本月尚未处理的新命中 ---
# 首选单页监控的 append-only events.jsonl；这样晚间完整扫描发现的单页不会在次日
# 被 new_hits.csv 覆盖后漏掉。CSV 只在事件流缺失时作为兼容兜底。
ATTEMPT_PHASE="ingest"
log "--- step 1/7: ingest_new_hits (events=${MONITOR_EVENTS_JSONL} csv_fallback=${SOURCE_NEW_HITS_CSV}) ---"
INGEST_ARGS=(--monitor-events-jsonl "$MONITOR_EVENTS_JSONL" --new-hits-csv "$SOURCE_NEW_HITS_CSV" --month "$MONTH" --unique-json "$UNIQUE_JSON" --full-verify-json "$FULL_VERIFY_JSON")
[[ -f "$PREVIOUS_UNIQUE_JSON" ]] && INGEST_ARGS+=(--previous-unique-json "$PREVIOUS_UNIQUE_JSON")
[[ -f "$PREVIOUS_FULL_VERIFY_JSON" ]] && INGEST_ARGS+=(--previous-full-verify-json "$PREVIOUS_FULL_VERIFY_JSON")
[[ -n "$TARGET_DATE_OVERRIDE" ]] && INGEST_ARGS+=(--date "$TARGET_DATE_OVERRIDE")
if [[ -z "$TARGET_DATE_OVERRIDE" ]] && [[ -f "$EVENT_CUTOFF_FILE" ]]; then
  EVENT_CUTOFF="$(tr -d '[:space:]' < "$EVENT_CUTOFF_FILE")"
  [[ -n "$EVENT_CUTOFF" ]] && INGEST_ARGS+=(--not-before "$EVENT_CUTOFF")
elif [[ -z "$TARGET_DATE_OVERRIDE" ]]; then
  log "WARN: event cutoff file missing; historical events may be backfilled: ${EVENT_CUTOFF_FILE}"
fi
INGEST_OUT="$("$PYTHON_BIN" "${SCRIPTS_DIR}/ingest_new_hits.py" "${INGEST_ARGS[@]}" 2> >(tee -a "$ERR_FILE" >&2))"
echo "$INGEST_OUT" >> "$LOG_FILE"
echo "$INGEST_OUT"
INGEST_SUMMARY="$(printf '%s\n' "$INGEST_OUT" | \
  "$PYTHON_BIN" "${SCRIPTS_DIR}/validate_pipeline_summary.py" --kind ingest \
  2> >(tee -a "$ERR_FILE" >&2))"

# --- 2. 同款合并（新组并入老组 / 新组彼此合并） ---
ATTEMPT_PHASE="merge"
log "--- step 2/7: merge_duplicate_query_groups ---"
MERGE_OUT="$("$PYTHON_BIN" "$MERGE_SCRIPT" \
  --unique-json "$UNIQUE_JSON" --full-verify-json "$FULL_VERIFY_JSON" 2> >(tee -a "$ERR_FILE" >&2))"
echo "$MERGE_OUT" >> "$LOG_FILE"
echo "$MERGE_OUT"
MERGE_SUMMARY="$(printf '%s\n' "$MERGE_OUT" | \
  "$PYTHON_BIN" "${SCRIPTS_DIR}/validate_pipeline_summary.py" --kind merge \
  2> >(tee -a "$ERR_FILE" >&2))"

# --- 3. 只验证新增(未验证)组，FB 广告库查询 ---
ATTEMPT_PHASE="verify"
log "--- step 3/7: run_verify_new_groups (max=${MAX_GROUPS_PER_DAY} blank_streak=${BLANK_STREAK_LIMIT}) ---"
VERIFY_OUT="$("$NODE_BIN" "${NODE_SCRIPTS_DIR}/run_verify_new_groups.mjs" \
  --unique-json "$UNIQUE_JSON" \
  --checkpoint-json "$FULL_VERIFY_JSON" \
  --verify-script "${NODE_SCRIPTS_DIR}/fb_product_verify.mjs" \
  --log-file "$LOG_FILE" \
  --max-groups "$MAX_GROUPS_PER_DAY" \
  --blank-streak "$BLANK_STREAK_LIMIT" 2> >(tee -a "$ERR_FILE" >&2))"
echo "$VERIFY_OUT"
VERIFY_SUMMARY="$(printf '%s\n' "$VERIFY_OUT" | \
  "$PYTHON_BIN" "${SCRIPTS_DIR}/validate_pipeline_summary.py" --kind verify \
  2> >(tee -a "$ERR_FILE" >&2))"
VERIFIED_COUNT="$($PYTHON_BIN -c "import json,sys; print(json.loads(sys.argv[1])['verified'])" "$VERIFY_SUMMARY")"
VERIFIED_GIDS="$($PYTHON_BIN -c "import json,sys; print(','.join(json.loads(sys.argv[1])['verified_group_ids']))" "$VERIFY_SUMMARY")"
FAILED_COUNT="$($PYTHON_BIN -c "import json,sys; print(json.loads(sys.argv[1])['failed'])" "$VERIFY_SUMMARY")"
PENDING_COUNT="$($PYTHON_BIN -c "import json,sys; print(json.loads(sys.argv[1])['pending'])" "$VERIFY_SUMMARY")"
TRUNCATED_COUNT="$($PYTHON_BIN -c "import json,sys; print(json.loads(sys.argv[1])['truncated'])" "$VERIFY_SUMMARY")"
TERMINATED_EARLY="$($PYTHON_BIN -c "import json,sys; print('1' if json.loads(sys.argv[1])['terminated_early'] else '0')" "$VERIFY_SUMMARY")"

# 钉钉只面向“双重验证成功”的信号：本轮完成查询不等于确认投放；只有相关广告数 > 0 才匹配。
MATCHED_COUNT=0
FRESH_COUNT=0
MULTI_COUNT=0
MATCHED_GIDS=""
MATCHED_PRODUCTS_JSON="[]"

# --- 4. 只抓新增产品的主图（已缓存的自动跳过） ---
ATTEMPT_PHASE="images"
log "--- step 4/7: fetch_new_images ---"
IMAGE_ARGS=(--unique-json "$UNIQUE_JSON" --images-json "$IMAGES_JSON" --full-verify-json "$FULL_VERIFY_JSON")
[[ -f "$PREVIOUS_IMAGES_JSON" ]] && IMAGE_ARGS+=(--previous-images-json "$PREVIOUS_IMAGES_JSON")
IMAGES_OUT="$("$PYTHON_BIN" "${SCRIPTS_DIR}/run_with_watchdog.py" \
  --daily-policy \
  --timeout-seconds "$IMAGE_WALL_TIMEOUT_SECONDS" \
  --grace-seconds "$IMAGE_WATCHDOG_GRACE_SECONDS" -- \
  "$PYTHON_BIN" "$IMAGE_FETCH_SCRIPT" "${IMAGE_ARGS[@]}" \
  2> >(tee -a "$ERR_FILE" >&2))"
echo "$IMAGES_OUT" >> "$LOG_FILE"
echo "$IMAGES_OUT"
IMAGES_SUMMARY="$(printf '%s\n' "$IMAGES_OUT" | \
  "$PYTHON_BIN" "${SCRIPTS_DIR}/validate_pipeline_summary.py" --kind images \
  2> >(tee -a "$ERR_FILE" >&2))"

# 图片缓存更新后再生成通知统计，确保本轮新增产品也能带主图和单页链接。
if [[ "${VERIFIED_COUNT:-0}" -gt 0 ]]; then
  ATTEMPT_PHASE="stats"
  STATS_OUT="$("$PYTHON_BIN" "${SCRIPTS_DIR}/compute_verify_stats.py" \
    --full-verify-json "$FULL_VERIFY_JSON" \
    --unique-json "$UNIQUE_JSON" \
    --images-json "$IMAGES_JSON" \
    --group-ids "$VERIFIED_GIDS")"
  echo "$STATS_OUT" >> "$LOG_FILE"
  STATS_SUMMARY="$(printf '%s\n' "$STATS_OUT" | \
    "$PYTHON_BIN" "${SCRIPTS_DIR}/validate_pipeline_summary.py" --kind stats \
    2> >(tee -a "$ERR_FILE" >&2))"
  MATCHED_COUNT="$($PYTHON_BIN -c "import json,sys; print(json.loads(sys.argv[1])['matched'])" "$STATS_SUMMARY")"
  FRESH_COUNT="$($PYTHON_BIN -c "import json,sys; print(json.loads(sys.argv[1])['fresh'])" "$STATS_SUMMARY")"
  MULTI_COUNT="$($PYTHON_BIN -c "import json,sys; print(json.loads(sys.argv[1])['multi_site'])" "$STATS_SUMMARY")"
  MATCHED_GIDS="$($PYTHON_BIN -c "import json,sys; print(','.join(json.loads(sys.argv[1])['matched_group_ids']))" "$STATS_SUMMARY")"
  MATCHED_PRODUCTS_JSON="$($PYTHON_BIN -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['matched_products'], ensure_ascii=False, separators=(',',':')))" "$STATS_SUMMARY")"
fi

# --- 5. 重生成月累计看板 ---
ATTEMPT_PHASE="build"
log "--- step 5/7: build_fb_verify_page ---"
BUILD_OUT="$("$PYTHON_BIN" "$BUILD_PAGE_SCRIPT" \
  --unique-json "$UNIQUE_JSON" \
  --full-verify-json "$FULL_VERIFY_JSON" \
  --images-json "$IMAGES_JSON" \
  --view-kind monthly \
  --out "$DASHBOARD_HTML" 2> >(tee -a "$ERR_FILE" >&2))"
echo "$BUILD_OUT" >> "$LOG_FILE"
echo "$BUILD_OUT"
BUILD_SUMMARY="$(printf '%s\n' "$BUILD_OUT" | \
  "$PYTHON_BIN" "${SCRIPTS_DIR}/validate_pipeline_summary.py" --kind build \
    --build-view-kind monthly \
  2> >(tee -a "$ERR_FILE" >&2))"

if [[ "${MATCHED_COUNT:-0}" -gt 0 ]] && [[ -n "$MATCHED_GIDS" ]]; then
  BATCH_RELATIVE_PATH="fb_verify_batches/${MONTH}/${RUN_SLUG}.html"
  BATCH_HTML="${MONTH_DIR}/batches/${RUN_SLUG}.html"
  BATCH_PUBLIC_URL="${PUBLIC_URL%/*}/${BATCH_RELATIVE_PATH}"
  mkdir -p "$(dirname "$BATCH_HTML")"
  log "--- step 5b/7: build current FB match batch page (${MATCHED_COUNT} groups) ---"
  ATTEMPT_PHASE="batch_build"
  BATCH_BUILD_OUT="$("$PYTHON_BIN" "$BUILD_PAGE_SCRIPT" \
    --unique-json "$UNIQUE_JSON" \
    --full-verify-json "$FULL_VERIFY_JSON" \
    --images-json "$IMAGES_JSON" \
    --view-kind batch \
    --group-ids "$MATCHED_GIDS" \
    --view-title "本轮 FB 确认产品（${MATCHED_COUNT}）" \
    --view-subtitle "本次增量验证确认有相关投放的产品；产品图可直接打开来源单页。" \
    --out "$BATCH_HTML" 2> >(tee -a "$ERR_FILE" >&2))"
  echo "$BATCH_BUILD_OUT" >> "$LOG_FILE"
  echo "$BATCH_BUILD_OUT"
  BATCH_BUILD_SUMMARY="$(printf '%s\n' "$BATCH_BUILD_OUT" | \
    "$PYTHON_BIN" "${SCRIPTS_DIR}/validate_pipeline_summary.py" --kind build \
      --build-view-kind batch --expected-group-ids "$MATCHED_GIDS" \
    2> >(tee -a "$ERR_FILE" >&2))"
  "$PYTHON_BIN" - "$BATCH_BUILD_SUMMARY" "$MATCHED_COUNT" <<'PY'
import json, sys
summary = json.loads(sys.argv[1])
expected = int(sys.argv[2])
actual = (summary["total_groups"], summary["found"], summary["unverified"])
required = (expected, expected, 0)
if actual != required:
    raise SystemExit(
        "batch BUILD_SUMMARY_JSON contract mismatch: "
        f"expected total/found/unverified={required}, got {actual}"
    )
PY
fi

# --- 6. 发布到 GitHub Pages babata-board 仓库 ---
ATTEMPT_PHASE="publish"
PUBLISH_RESULT="skipped(disabled)"
if [[ "$PUBLISH" == "1" ]]; then
  log "--- step 6/7: publish to babata-board (${PUBLIC_URL}) ---"
  if [[ ! -r "$PAGES_PUBLISH_SCRIPT" ]]; then
    log_err "missing FB Pages publisher: ${PAGES_PUBLISH_SCRIPT}; run source fb-verify/sync_deploy.sh"
    exit 2
  fi
  PUBLISH_ARGS=(
    --repo "$PAGES_REPO"
    --worktree "$PAGES_DIR"
    --month "$MONTH"
    --dashboard-source "$DASHBOARD_HTML"
  )
  if [[ -n "$BATCH_HTML" ]] && [[ -f "$BATCH_HTML" ]]; then
    PUBLISH_ARGS+=(
      --batch-source "$BATCH_HTML"
      --batch-destination "$BATCH_RELATIVE_PATH"
    )
  fi
  PUBLISH_RESULT="$(
    "$PYTHON_BIN" "$PAGES_PUBLISH_SCRIPT" "${PUBLISH_ARGS[@]}" \
      2> >(tee -a "$ERR_FILE" >&2)
  )"
  case "$PUBLISH_RESULT" in
    pushed:*|no-changes:*) ;;
    *)
      log_err "FB Pages publisher returned an invalid success result: ${PUBLISH_RESULT}"
      exit 2
      ;;
  esac
  printf '%s\n' "$PUBLISH_RESULT" >> "$LOG_FILE"
  log "FB Pages transaction verified. result=${PUBLISH_RESULT} url=${PUBLIC_URL}"
  PUBLISHED_OK=1
else
  log "--- step 6/7: publish disabled (FB_VERIFY_PUBLISH=0) ---"
fi

# --- 7. 钉钉推送：仅看板重生成+Pages 发布都成功、且本轮新验证组中至少一个确认有相关投放时才发。
#        同一个 group 一旦写入 checkpoint，后续 runner 的 verified_count 就是 0；因此可安全
#        支持同日早晚两轮不同的新组各发一次，不会为同一组重复推送。
#        DingTalk 发送失败按 best-effort 处理：记错误日志，但不影响本次运行整体成功（不阻塞 stamp）。
ATTEMPT_PHASE="notify"
NOTIFY_RESULT="skipped"
if [[ "$DINGTALK_MODE" == "off" ]]; then
  NOTIFY_RESULT="off"
  log "--- step 7/7: dingtalk disabled (--no-dingtalk / FB_VERIFY_DINGTALK=0) ---"
elif [[ "$PUBLISHED_OK" != "1" ]]; then
  NOTIFY_RESULT="skipped(publish-disabled)"
  log "--- step 7/7: dingtalk skipped (publish disabled, nothing to announce) ---"
elif [[ "${VERIFIED_COUNT:-0}" -le 0 ]]; then
  NOTIFY_RESULT="skipped(0-new-groups)"
  log "--- step 7/7: dingtalk skipped (0 new groups verified today) ---"
elif [[ "${MATCHED_COUNT:-0}" -le 0 ]]; then
  NOTIFY_RESULT="skipped(0-new-matched-groups)"
  log "--- step 7/7: dingtalk skipped (${VERIFIED_COUNT} groups queried, 0 confirmed relevant FB ads) ---"
else
  log "--- step 7/7: notify_dingtalk (mode=${DINGTALK_MODE} verified=${VERIFIED_COUNT} matched=${MATCHED_COUNT}) ---"

  NOTIFY_ARGS=(--verified-count "$VERIFIED_COUNT" --matched-count "$MATCHED_COUNT" --fresh-count "$FRESH_COUNT" --multi-site-count "$MULTI_COUNT" \
    --matched-products-json "$MATCHED_PRODUCTS_JSON" --batch-url "$BATCH_PUBLIC_URL" --dashboard-url "$PUBLIC_URL")
  [[ "$DINGTALK_MODE" == "dryrun" ]] && NOTIFY_ARGS+=(--dry-run)

  set +e
  NOTIFY_OUT="$("$PYTHON_BIN" "${SCRIPTS_DIR}/notify_dingtalk.py" "${NOTIFY_ARGS[@]}" 2> >(tee -a "$ERR_FILE" >&2))"
  NOTIFY_CODE=$?
  set -e
  echo "$NOTIFY_OUT" >> "$LOG_FILE"
  echo "$NOTIFY_OUT"

  if [[ "$NOTIFY_CODE" == "0" ]]; then
    if [[ "$DINGTALK_MODE" == "send" ]]; then
      NOTIFY_RESULT="sent"
    else
      NOTIFY_RESULT="dryrun-ok"
    fi
  else
    log_err "dingtalk notify failed (non-fatal, pipeline still counts as success). exit=${NOTIFY_CODE}"
    NOTIFY_RESULT="failed"
  fi
fi

# --- 汇总一行 ---
"$PYTHON_BIN" - "$INGEST_SUMMARY" "$MERGE_SUMMARY" "$VERIFY_SUMMARY" "$IMAGES_SUMMARY" "$BUILD_SUMMARY" "$PUBLISH_RESULT" "$NOTIFY_RESULT" <<'PY' | tee -a "$LOG_FILE"
import json, sys
ingest, merge, verify, images, build, publish_result, notify_result = sys.argv[1:8]
i, m, v, im, b = map(json.loads, (ingest, merge, verify, images, build))
print(
    "SUMMARY "
    f"new_groups_added={i.get('groups_added','?')} "
    f"merged_buckets={m.get('buckets_merged','?')} "
    f"fb_verified_today={v.get('verified','?')}/{v.get('todo','?')} "
    f"fb_failed_today={v.get('failed',0)} "
    f"pending={v.get('pending','?')} "
    f"truncated={v.get('truncated','?')} "
    f"terminated_early={v.get('terminated_early','?')} "
    f"images_new_ok={sum((im.get(k,0) or 0) for k in ('new_shopify_ok','new_og_ok','previous_cache_ok','cross_site_ok','ad_preview_ok','video_frame_ok'))}/{im.get('total','?')} "
    f"dashboard_groups={b.get('total_groups','?')} dashboard_found={b.get('found','?')} "
    f"publish={publish_result} dingtalk={notify_result}"
)
PY

log "===== pipeline finished ====="
PIPELINE_BODY_COMPLETE=1
ATTEMPT_PHASE="complete"
