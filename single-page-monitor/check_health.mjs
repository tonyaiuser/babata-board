#!/usr/bin/env node
// SPSPY_LEGACY_HEALTH_CHECKER_ID=spspy-single-page-legacy-health-v1

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import https from "node:https";
import { fileURLToPath } from "node:url";
import { atomicWriteFile } from "./lib/file_utils.mjs";

const __filename = fileURLToPath(import.meta.url);
const PROJECT_DIR = path.dirname(__filename);
const DATA_DIR = process.env.SP_SINGLE_PAGE_DATA_DIR || path.join(PROJECT_DIR, "data");
const REPORTS_DIR = process.env.SP_SINGLE_PAGE_REPORTS_DIR || path.join(PROJECT_DIR, "reports");
const STATUS_PATH = path.join(DATA_DIR, "run_status.json");
const ALERT_STATE_PATH = path.join(DATA_DIR, "health_alert_state.json");

function parseArgs(argv) {
  const out = new Map();
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith("--")) continue;
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) out.set(key, "yes");
    else {
      out.set(key, next);
      i += 1;
    }
  }
  return out;
}

function readJson(file, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function localYmd(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function minutesBetween(a, b) {
  return Math.round((a.getTime() - b.getTime()) / 60000);
}

function fileMtime(file) {
  try {
    return fs.statSync(file).mtime;
  } catch {
    return null;
  }
}

function pidAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(Number(pid), 0);
    return true;
  } catch {
    return false;
  }
}

function parsePythonConstant(source, name) {
  const pattern = new RegExp(`${name}\\s*=\\s*["']([^"']+)["']`);
  return source.match(pattern)?.[1] || "";
}

function loadDingTalkConfig() {
  const webhook = process.env.SP_DINGTALK_WEBHOOK || process.env.DINGTALK_WEBHOOK || "";
  const secret = process.env.SP_DINGTALK_SECRET || process.env.DINGTALK_SECRET || "";
  if (webhook && secret) return { webhook, secret };

  const configPath =
    process.env.SP_SINGLE_PAGE_DINGTALK_CONFIG ||
    "/Users/tonyaiuser/.openclaw/workspace/skills/sp-monitor/run.py";
  try {
    const source = fs.readFileSync(configPath, "utf8");
    return {
      webhook: parsePythonConstant(source, "DINGTALK_WEBHOOK"),
      secret: parsePythonConstant(source, "DINGTALK_SECRET"),
    };
  } catch {
    return { webhook: "", secret: "" };
  }
}

function postJson(url, payload) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    const req = https.request(
      url,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": body.length,
        },
        timeout: 20000,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      }
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("DingTalk request timed out")));
    req.end(body);
  });
}

async function sendDingTalk(message, alertKey, throttleMinutes) {
  const state = readJson(ALERT_STATE_PATH, {});
  const now = new Date();
  const lastAt = state.last_alert_at ? new Date(state.last_alert_at) : null;
  if (
    state.last_alert_key === alertKey &&
    lastAt &&
    minutesBetween(now, lastAt) < throttleMinutes
  ) {
    return "throttled";
  }

  const { webhook, secret } = loadDingTalkConfig();
  if (!webhook || !secret) return "missing_config";

  const timestamp = String(Date.now());
  const sign = crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}\n${secret}`)
    .digest("base64");
  const separator = webhook.includes("?") ? "&" : "?";
  const url = `${webhook}${separator}timestamp=${timestamp}&sign=${encodeURIComponent(sign)}`;
  const payload = {
    msgtype: "markdown",
    markdown: {
      title: "SP 单页监控健康检查",
      text: message,
    },
  };
  const response = await postJson(url, payload);
  await atomicWriteFile(
    ALERT_STATE_PATH,
    JSON.stringify(
      {
        ...state,
        last_alert_key: alertKey,
        last_alert_at: now.toISOString(),
        last_response: response,
      },
      null,
      2
    ) + "\n"
  );
  return response;
}

async function sendRecovery(message) {
  const state = readJson(ALERT_STATE_PATH, {});
  if (!state.last_alert_key || state.last_recovery_for === state.last_alert_key) return "not_needed";

  const { webhook, secret } = loadDingTalkConfig();
  if (!webhook || !secret) return "missing_config";
  const timestamp = String(Date.now());
  const sign = crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}\n${secret}`)
    .digest("base64");
  const separator = webhook.includes("?") ? "&" : "?";
  const url = `${webhook}${separator}timestamp=${timestamp}&sign=${encodeURIComponent(sign)}`;
  const response = await postJson(url, {
    msgtype: "markdown",
    markdown: { title: "SP 单页监控已恢复", text: message },
  });
  await atomicWriteFile(
    ALERT_STATE_PATH,
    JSON.stringify(
      {
        ...state,
        last_recovery_for: state.last_alert_key,
        last_recovery_at: new Date().toISOString(),
        last_recovery_response: response,
      },
      null,
      2
    ) + "\n"
  );
  return response;
}

function evaluateHealth(options) {
  const now = new Date();
  const today = localYmd(now);
  const month = options.month || today.slice(0, 7);
  const status = readJson(STATUS_PATH, null);
  const latestJsonMtime = fileMtime(path.join(DATA_DIR, "latest.json"));
  const hitsMtime = fileMtime(path.join(REPORTS_DIR, month, "hits.csv"));
  const dashboardMtime = fileMtime(path.join(REPORTS_DIR, "latest", "dashboard.html"));
  const progress = readJson(path.join(REPORTS_DIR, month, "progress.json"), null);
  const completedToday =
    (status?.state === "succeeded" && status.finished_at && localYmd(new Date(status.finished_at)) === today) ||
    (latestJsonMtime && localYmd(latestJsonMtime) === today &&
      hitsMtime && localYmd(hitsMtime) === today &&
      dashboardMtime && localYmd(dashboardMtime) === today);

  const scheduleAt = new Date(now.getFullYear(), now.getMonth(), now.getDate(), options.hour, options.minute, 0, 0);
  const expectedReadyAt = new Date(scheduleAt.getTime() + options.graceMinutes * 60000);
  const afterExpectedReady = now >= expectedReadyAt;

  const running = status?.state === "running" && pidAlive(status.pid);
  const heartbeatAt = status?.heartbeat_at ? new Date(status.heartbeat_at) : null;
  const startedAt = status?.started_at ? new Date(status.started_at) : null;
  const finishedAt = status?.finished_at ? new Date(status.finished_at) : null;
  const heartbeatAge = running && heartbeatAt ? minutesBetween(now, heartbeatAt) : null;
  const runtimeEnd = finishedAt && ["succeeded", "failed"].includes(status?.state) ? finishedAt : now;
  const runtime = startedAt ? minutesBetween(runtimeEnd, startedAt) : null;
  const progressAt = progress?.updated_at ? new Date(progress.updated_at) : null;
  const currentProgress =
    running && startedAt && progressAt && progressAt >= startedAt && progress?.month === month ? progress : null;
  const progressAge = currentProgress && progressAt ? minutesBetween(now, progressAt) : null;

  const issues = [];
  const issueCodes = [];
  if (status?.state === "failed" && finishedAt && localYmd(finishedAt) === today) {
    const message = status.message ? `：${status.message}` : "";
    issues.push(`今天自动任务失败${message}`);
    issueCodes.push("run_failed");
  } else if (running) {
    if (heartbeatAge !== null && heartbeatAge > options.maxHeartbeatMinutes) {
      issues.push(`运行心跳超过 ${heartbeatAge} 分钟未更新`);
      issueCodes.push("heartbeat_stale");
    }
    if (String(status?.stage || "").startsWith("scan_") && runtime !== null && runtime > options.maxProgressMinutes) {
      if (!currentProgress) {
        issues.push(`扫描运行 ${runtime} 分钟仍没有可用进度记录`);
        issueCodes.push("scan_progress_missing");
      } else if (progressAge !== null && progressAge > options.maxProgressMinutes) {
        issues.push(`扫描进度已 ${progressAge} 分钟未推进`);
        issueCodes.push("scan_progress_stale");
      }
    }
    if (runtime !== null && runtime > options.maxRuntimeMinutes) {
      issues.push(`运行时间 ${runtime} 分钟，超过阈值 ${options.maxRuntimeMinutes} 分钟`);
      issueCodes.push("runtime_exceeded");
    }
  } else if (status?.state === "running" && status?.pid && !pidAlive(status.pid)) {
    issues.push(`状态显示运行中，但进程 ${status.pid} 已不存在`);
    issueCodes.push("stale_pid");
  } else if (!completedToday && afterExpectedReady) {
    issues.push(`今天 ${today} 还没有生成单页监控结果`);
    issueCodes.push("not_completed");
  }

  const ok = issues.length === 0;
  const summary = {
    ok,
    today,
    month,
    stage: status?.stage || "unknown",
    state: status?.state || "unknown",
    run_kind: status?.run_kind || "unknown",
    pid: status?.pid || null,
    pid_alive: status?.pid ? pidAlive(status.pid) : false,
    started_at: status?.started_at || "",
    heartbeat_at: status?.heartbeat_at || "",
    finished_at: status?.finished_at || "",
    heartbeat_age_minutes: heartbeatAge,
    runtime_minutes: runtime,
    latest_json_mtime: latestJsonMtime?.toISOString() || "",
    hits_mtime: hitsMtime?.toISOString() || "",
    dashboard_mtime: dashboardMtime?.toISOString() || "",
    completed_today: Boolean(completedToday),
    scan_progress_sites: currentProgress?.completed_sites ?? null,
    scan_progress_total: currentProgress?.total_sites ?? null,
    scan_progress_domain: currentProgress?.last_domain || "",
    scan_progress_age_minutes: progressAge,
    issues,
    issue_codes: issueCodes,
  };
  return summary;
}

function formatMarkdown(summary) {
  const status = summary.ok ? "正常" : "异常";
  const issueText = summary.issues.length ? summary.issues.map((item) => `- ${item}`).join("\n") : "- 暂无异常";
  return `### SP 单页监控健康检查：${status}

- 日期：${summary.today}
- 任务类型：${summary.run_kind}
- 阶段：${summary.stage}
- 状态：${summary.state}
- PID：${summary.pid || "-"}（${summary.pid_alive ? "存在" : "不存在"}）
- 已运行：${summary.runtime_minutes ?? "-"} 分钟
- 心跳距今：${summary.heartbeat_age_minutes ?? "-"} 分钟
- 扫描进度：${summary.scan_progress_sites ?? "-"}/${summary.scan_progress_total ?? "-"}${summary.scan_progress_domain ? `（${summary.scan_progress_domain}）` : ""}
- 今日完成：${summary.completed_today ? "是" : "否"}

${issueText}
`;
}

function formatRecovery(summary) {
  return `### SP 单页监控：已恢复正常

- 日期：${summary.today}
- 任务类型：${summary.run_kind}
- 阶段：${summary.stage}
- 状态：${summary.state}
- 本轮耗时：${summary.runtime_minutes ?? "-"} 分钟
- 今日完成：${summary.completed_today ? "是" : "否"}

上一次健康告警已经解除。
`;
}

const cli = parseArgs(process.argv);
const options = {
  month: cli.get("--month") || "",
  hour: Number(cli.get("--hour") || 10),
  minute: Number(cli.get("--minute") || 20),
  graceMinutes: Number(cli.get("--grace-minutes") || 150),
  maxHeartbeatMinutes: Number(cli.get("--max-heartbeat-minutes") || 45),
  maxProgressMinutes: Number(cli.get("--max-progress-minutes") || 60),
  maxRuntimeMinutes: Number(cli.get("--max-runtime-minutes") || 540),
  notify: (cli.get("--notify") || "no") === "yes",
  json: (cli.get("--json") || "no") === "yes",
  throttleMinutes: Number(cli.get("--alert-throttle-minutes") || 1440),
};

const summary = evaluateHealth(options);
if (options.json) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(formatMarkdown(summary));
}

if (!summary.ok && options.notify) {
  const key = `${summary.today}|${summary.issue_codes.join(",")}`;
  const result = await sendDingTalk(formatMarkdown(summary), key, options.throttleMinutes);
  console.log(`DingTalk: ${result}`);
} else if (summary.ok && options.notify) {
  const result = await sendRecovery(formatRecovery(summary));
  if (result !== "not_needed") console.log(`DingTalk recovery: ${result}`);
}

process.exit(summary.ok ? 0 : 2);
