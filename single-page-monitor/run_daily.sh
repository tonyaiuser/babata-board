#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOY_ROOT="${SP_SINGLE_PAGE_DEPLOY_ROOT:-$HOME/.spspy-single-page-monitor}"
RUNTIME_DIR="${DEPLOY_ROOT}/single-page-monitor"
DATA_DIR="${SP_SINGLE_PAGE_DATA_DIR:-${RUNTIME_DIR}/data}"
LOG_DIR="${SP_SINGLE_PAGE_LOG_DIR:-${RUNTIME_DIR}/logs}"
REPORTS_DIR="${SP_SINGLE_PAGE_REPORTS_DIR:-${RUNTIME_DIR}/reports}"
STATUS_PATH="${DATA_DIR}/run_status.json"
LOCK_DIR="${SP_SINGLE_PAGE_LOCK_DIR:-${DATA_DIR}/run_daily.lock}"
RUN_ID="$(date '+%Y%m%dT%H%M%S')-$$"
HEARTBEAT_INTERVAL="${SP_SINGLE_PAGE_HEARTBEAT_INTERVAL:-60}"
RUN_KIND="${SP_SINGLE_PAGE_RUN_KIND:-daily}"
CURRENT_CHILD_PID=""

NODE_BIN="${NODE_BIN:-$(command -v node)}"
MONTH="${SP_SINGLE_PAGE_MONTH:-$(date +%Y-%m)}"
PREV_MONTH="${SP_SINGLE_PAGE_PREV_MONTH:-$(python3 - "${MONTH}" <<'PY'
import sys
from datetime import date

year, month = map(int, sys.argv[1].split("-"))
if month == 1:
    year -= 1
    month = 12
else:
    month -= 1
print(f"{year:04d}-{month:02d}")
PY
)}"
LIMIT="${SP_SINGLE_PAGE_LIMIT:-200}"
WORKERS="${SP_SINGLE_PAGE_WORKERS:-6}"
MAX_JSON_PAGES="${SP_SINGLE_PAGE_MAX_JSON_PAGES:-6}"
MAX_CREATED="${SP_SINGLE_PAGE_MAX_CREATED:-80}"
MAX_UPDATED="${SP_SINGLE_PAGE_MAX_UPDATED:-35}"
CHECKPOINT_EVERY="${SP_SINGLE_PAGE_CHECKPOINT_EVERY:-10}"
FETCH_MODE="${SP_SINGLE_PAGE_FETCH_MODE:-auto}"
REQUEST_TIMEOUT="${SP_SINGLE_PAGE_TIMEOUT:-30000}"
PAGE_TIMEOUT="${SP_SINGLE_PAGE_PAGE_TIMEOUT:-12000}"
MIN_REQUEST_INTERVAL_MS="${SP_SINGLE_PAGE_MIN_REQUEST_INTERVAL_MS:-900}"
REQUEST_JITTER_MS="${SP_SINGLE_PAGE_REQUEST_JITTER_MS:-500}"
BACKOFF_BASE_MS="${SP_SINGLE_PAGE_BACKOFF_BASE_MS:-2000}"
BACKOFF_MAX_MS="${SP_SINGLE_PAGE_BACKOFF_MAX_MS:-60000}"
MAX_CONSECUTIVE_FAILURES="${SP_SINGLE_PAGE_MAX_CONSECUTIVE_FAILURES:-3}"
CACHE_TTL_HOURS="${SP_SINGLE_PAGE_CACHE_TTL_HOURS:-18}"
CACHE_MAX_ENTRIES="${SP_SINGLE_PAGE_CACHE_MAX_ENTRIES:-50000}"
INCLUDE_PREV="${SP_SINGLE_PAGE_INCLUDE_PREV:-1}"
PAGES_REPO="${SP_SINGLE_PAGE_PAGES_REPO:-https://github.com/tonyaiuser/babata-board.git}"
PAGES_DIR="${SP_SINGLE_PAGE_PAGES_DIR:-${DEPLOY_ROOT}/.pages/babata-board-pages-main}"
PUBLIC_BASE="${SP_SINGLE_PAGE_PUBLIC_BASE:-https://tonyaiuser.github.io/babata-board/single-page-monitor}"
SEND_DINGTALK="${SP_SINGLE_PAGE_SEND_DINGTALK:-1}"
DINGTALK_CONFIG="${SP_SINGLE_PAGE_DINGTALK_CONFIG:-/Users/tonyaiuser/.openclaw/workspace/skills/sp-monitor/run.py}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
LOCK_HELPER="${SP_SINGLE_PAGE_LOCK_HELPER:-${SCRIPT_DIR}/scripts/locked_exec.py}"

mkdir -p "${DATA_DIR}" "${LOG_DIR}" "${REPORTS_DIR}"

# The fd remains owned by this shell across exec and while it waits for every
# child.  Kernel close-on-exit/crash releases ownership; the stable lock inode
# and public compatibility path are never deleted or recycled.
if [[ -z "${SP_SINGLE_PAGE_LOCK_ACTIVE:-}" ]]; then
  exec "${PYTHON_BIN}" "${LOCK_HELPER}" \
    --lock "${LOCK_DIR}" --lock-dir "${DATA_DIR}" --fd-env SP_SINGLE_PAGE_LOCK_FD \
    --active-env SP_SINGLE_PAGE_LOCK_ACTIVE --label "single-page runtime" \
    --busy-exit 75 -- "${SCRIPT_DIR}/run_daily.sh" "$@"
fi
"${PYTHON_BIN}" "${LOCK_HELPER}" \
  --lock "${LOCK_DIR}" --lock-dir "${DATA_DIR}" --fd-env SP_SINGLE_PAGE_LOCK_FD \
  --active-env SP_SINGLE_PAGE_LOCK_ACTIVE --label "single-page runtime" \
  --busy-exit 75 --validate-only

cd "${REPO_DIR}"
exec > >(tee -a "${LOG_DIR}/daily_$(date '+%Y-%m-%d').log")
exec 2> >(tee -a "${LOG_DIR}/daily_error_$(date '+%Y-%m-%d').log" >&2)

write_status() {
  local stage="$1"
  local state="$2"
  local message="${3:-}"

  RUN_STATUS_PATH="${STATUS_PATH}" \
  RUN_ID="${RUN_ID}" \
  RUN_PID="$$" \
  RUN_STAGE="${stage}" \
  RUN_STATE="${state}" \
  RUN_MESSAGE="${message}" \
  RUN_MONTH="${MONTH}" \
  RUN_PREV_MONTH="${PREV_MONTH}" \
  RUN_LIMIT="${LIMIT}" \
  RUN_KIND="${RUN_KIND}" \
  python3 <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["RUN_STATUS_PATH"])
now = datetime.now(timezone.utc).isoformat()
run_id = os.environ["RUN_ID"]
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    payload = {}

if payload.get("run_id") != run_id:
    payload = {
        "run_id": run_id,
        "started_at": now,
    }

payload.update({
    "pid": int(os.environ["RUN_PID"]),
    "stage": os.environ["RUN_STAGE"],
    "state": os.environ["RUN_STATE"],
    "message": os.environ["RUN_MESSAGE"],
    "month": os.environ["RUN_MONTH"],
    "prev_month": os.environ["RUN_PREV_MONTH"],
    "limit": int(os.environ["RUN_LIMIT"]),
    "run_kind": os.environ["RUN_KIND"],
    "heartbeat_at": now,
    "updated_at": now,
})
if os.environ["RUN_STATE"] in {"succeeded", "failed"}:
    payload["finished_at"] = now

temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
os.replace(temp, path)
PY
}

finish_run() {
  local code="$1"
  if [[ "${code}" == "0" ]]; then
    write_status "completed" "succeeded" "daily run completed"
  else
    write_status "failed" "failed" "daily run failed exit=${code}"
  fi
  trap - EXIT
  exit "${code}"
}

stop_run() {
  local signal="$1"
  local code="$2"
  if [[ -n "${CURRENT_CHILD_PID}" ]] && kill -0 "${CURRENT_CHILD_PID}" 2>/dev/null; then
    kill "-${signal}" "${CURRENT_CHILD_PID}" 2>/dev/null || true
    wait "${CURRENT_CHILD_PID}" 2>/dev/null || true
  fi
  exit "${code}"
}

run_with_heartbeat() {
  local stage="$1"
  shift

  write_status "${stage}" "running" "started"
  "$@" &
  local child_pid="$!"
  CURRENT_CHILD_PID="${child_pid}"
  while kill -0 "${child_pid}" 2>/dev/null; do
    sleep "${HEARTBEAT_INTERVAL}"
    write_status "${stage}" "running" "child_pid=${child_pid}"
  done
  local child_code=0
  wait "${child_pid}" || child_code="$?"
  CURRENT_CHILD_PID=""
  if [[ "${child_code}" != "0" ]]; then
    return "${child_code}"
  fi
  write_status "${stage}" "running" "finished"
}

trap 'finish_run $?' EXIT
trap 'stop_run TERM 143' TERM
trap 'stop_run INT 130' INT

find "${LOG_DIR}" \( -name "daily_*.log" -o -name "daily_error_*.log" \) -mtime +30 -delete 2>/dev/null || true

write_status "starting" "running" "daily run started"

run_monitor() {
  local target_month="$1"

  "${NODE_BIN}" "${SCRIPT_DIR}/monitor.mjs" \
    --month "${target_month}" \
    --limit "${LIMIT}" \
    --workers "${WORKERS}" \
    --max-json-pages "${MAX_JSON_PAGES}" \
    --max-created "${MAX_CREATED}" \
    --max-updated "${MAX_UPDATED}" \
    --checkpoint-every "${CHECKPOINT_EVERY}" \
    --fetch-mode "${FETCH_MODE}" \
    --timeout "${REQUEST_TIMEOUT}" \
    --page-timeout "${PAGE_TIMEOUT}" \
    --min-request-interval-ms "${MIN_REQUEST_INTERVAL_MS}" \
    --request-jitter-ms "${REQUEST_JITTER_MS}" \
    --backoff-base-ms "${BACKOFF_BASE_MS}" \
    --backoff-max-ms "${BACKOFF_MAX_MS}" \
    --max-consecutive-failures "${MAX_CONSECUTIVE_FAILURES}" \
    --cache-ttl-hours "${CACHE_TTL_HOURS}" \
    --cache-max-entries "${CACHE_MAX_ENTRIES}"
}

copy_dashboard_dir() {
  local src_dir="$1"
  local dst_dir="$2"

  mkdir -p "${dst_dir}"
  rm -f "${dst_dir}/dashboard_data.json" "${dst_dir}/duplicate_groups.json"
  for name in dashboard.html dashboard_desktop.png dashboard_mobile.png; do
    if [[ -f "${src_dir}/${name}" ]]; then
      cp "${src_dir}/${name}" "${dst_dir}/${name}"
    fi
  done
}

send_dingtalk() {
  local label="$1"
  local data_path="${REPORTS_DIR}/latest/dashboard_data.json"

  if [[ "${SEND_DINGTALK}" != "1" ]]; then
    return
  fi
  if [[ ! -f "${DINGTALK_CONFIG}" ]]; then
    echo "DingTalk config not found: ${DINGTALK_CONFIG}" >&2
    return
  fi

  DINGTALK_CONFIG="${DINGTALK_CONFIG}" \
  DING_LABEL="${label}" \
  DING_DATA_PATH="${data_path}" \
  DING_LATEST_URL="${PUBLIC_BASE}/latest.html" \
  DING_MONTH_URL="${PUBLIC_BASE}/${MONTH}.html" \
  DING_IMAGE_URL="${PUBLIC_BASE}/reports/latest/dashboard_desktop.png?v=${RUN_ID}" \
  python3 <<'PY'
import ast
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

config_path = Path(os.environ["DINGTALK_CONFIG"])
source = config_path.read_text(encoding="utf-8")
module = ast.parse(source)
values = {}
for node in module.body:
    if not isinstance(node, ast.Assign):
        continue
    for target in node.targets:
        if isinstance(target, ast.Name) and target.id in {"DINGTALK_WEBHOOK", "DINGTALK_SECRET"}:
            values[target.id] = ast.literal_eval(node.value)

webhook = values.get("DINGTALK_WEBHOOK")
secret = values.get("DINGTALK_SECRET")
if not webhook or not secret:
    raise SystemExit("missing DingTalk webhook or secret")

data = json.loads(Path(os.environ["DING_DATA_PATH"]).read_text(encoding="utf-8"))
summary = data.get("summary", {})
products = data.get("products", [])
month_counts = Counter(item.get("source_month") or "unknown" for item in products)
month_line = " / ".join(f"{month}: {count}" for month, count in sorted(month_counts.items(), reverse=True))

label = os.environ["DING_LABEL"]
latest_url = os.environ["DING_LATEST_URL"]
month_url = os.environ["DING_MONTH_URL"]
image_url = os.environ["DING_IMAGE_URL"]
text = f"""### SP 单页监控看板（{label}）

![SP单页看板]({image_url})

- 单页产品：{summary.get("hit_pages", len(products))}
- 命中站点：{summary.get("hit_sites", 0)}
- Top20 旗舰站：{summary.get("top20_flagship_sites", 0)}
- 核心候选站：{summary.get("core_candidate_sites", 0)}
- 重复组：{summary.get("duplicate_groups", 0)}
- 月份信号：{month_line}
- 排序：按首次发现单页时间倒序，最新发现排在最前

[打开最新看板]({latest_url})

[只看本月]({month_url})
"""

payload = {
    "msgtype": "markdown",
    "markdown": {
        "title": f"SP 单页监控看板（{label}）",
        "text": text,
    },
}
timestamp = str(round(time.time() * 1000))
string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
sign = urllib.parse.quote_plus(base64.b64encode(hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).digest()).decode("utf-8"))
separator = "&" if "?" in webhook else "?"
url = f"{webhook}{separator}timestamp={timestamp}&sign={sign}"
request = urllib.request.Request(
    url,
    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=20) as response:
    print(response.read().decode("utf-8"))
PY
}

run_with_heartbeat "scan_current_month" run_monitor "${MONTH}"

if [[ "${INCLUDE_PREV}" == "1" && ! -f "${REPORTS_DIR}/${PREV_MONTH}/hits.csv" ]]; then
  run_with_heartbeat "scan_previous_month" run_monitor "${PREV_MONTH}"
fi

run_with_heartbeat "dashboard_month" "${NODE_BIN}" "${SCRIPT_DIR}/build_dashboard.mjs" \
  --month "${MONTH}" \
  --workers "${WORKERS}"

MONTHS="${MONTH}"
LABEL="${MONTH}"
if [[ "${INCLUDE_PREV}" == "1" && -f "${REPORTS_DIR}/${PREV_MONTH}/hits.csv" ]]; then
  MONTHS="${MONTH},${PREV_MONTH}"
  LABEL="${PREV_MONTH} + ${MONTH}"
fi

run_with_heartbeat "dashboard_latest" "${NODE_BIN}" "${SCRIPT_DIR}/build_dashboard.mjs" \
  --months "${MONTHS}" \
  --out latest \
  --label "${LABEL}" \
  --workers "${WORKERS}"

if [[ ! -d "${PAGES_DIR}/.git" ]]; then
  write_status "publish_pages" "running" "clone pages repository"
  mkdir -p "$(dirname "${PAGES_DIR}")"
  git clone "${PAGES_REPO}" "${PAGES_DIR}"
fi

write_status "publish_pages" "running" "publishing GitHub Pages files"
git -C "${PAGES_DIR}" pull --ff-only origin main
mkdir -p "${PAGES_DIR}/single-page-monitor/reports"
copy_dashboard_dir "${REPORTS_DIR}/${MONTH}" "${PAGES_DIR}/single-page-monitor/reports/${MONTH}"
copy_dashboard_dir "${REPORTS_DIR}/latest" "${PAGES_DIR}/single-page-monitor/reports/latest"
cp "${REPORTS_DIR}/${MONTH}/dashboard.html" "${PAGES_DIR}/single-page-monitor/${MONTH}.html"
cp "${REPORTS_DIR}/latest/dashboard.html" "${PAGES_DIR}/single-page-monitor/latest.html"

git -C "${PAGES_DIR}" add single-page-monitor
if ! git -C "${PAGES_DIR}" diff --cached --quiet; then
  git -C "${PAGES_DIR}" commit -m "update single-page dashboard ${MONTH}"
  git -C "${PAGES_DIR}" push origin main
fi

write_status "notify_dingtalk" "running" "sending DingTalk message"
send_dingtalk "${LABEL}"
