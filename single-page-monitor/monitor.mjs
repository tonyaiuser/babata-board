#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { atomicWriteFile } from "./lib/file_utils.mjs";
import { validateScanOptions } from "./lib/scan_helpers.mjs";

const __filename = fileURLToPath(import.meta.url);
const PROJECT_DIR = path.dirname(__filename);
const REPO_DIR = path.dirname(PROJECT_DIR);
const ENGINE = path.join(REPO_DIR, "top200_june_single_page_scan.mjs");
const CONFIG_PATH = path.join(PROJECT_DIR, "config.json");
const DATA_DIR = process.env.SP_SINGLE_PAGE_DATA_DIR || path.join(PROJECT_DIR, "data");
const REPORTS_DIR = process.env.SP_SINGLE_PAGE_REPORTS_DIR || path.join(PROJECT_DIR, "reports");
const STATE_PATH = path.join(DATA_DIR, "state.json");
const LATEST_PATH = path.join(DATA_DIR, "latest.json");
const EVENTS_PATH = path.join(DATA_DIR, "events.jsonl");

function parseArgs(argv) {
  const parsed = new Map();
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith("--")) continue;
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      parsed.set(key, "yes");
    } else {
      parsed.set(key, next);
      i += 1;
    }
  }
  return parsed;
}

async function readJson(file, fallback, { strict = false } = {}) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch (error) {
    if (strict && error?.code !== "ENOENT") {
      throw new Error(`Cannot read valid JSON from ${file}: ${error.message}`);
    }
    return fallback;
  }
}

function localDateParts(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: process.env.TZ || "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(date);
  return Object.fromEntries(parts.map((part) => [part.type, part.value]));
}

function localYmd(date = new Date()) {
  const { year, month, day } = localDateParts(date);
  return `${year}-${month}-${day}`;
}

function localMonth(date = new Date()) {
  return localYmd(date).slice(0, 7);
}

function csvEscape(value) {
  const text = String(value ?? "");
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function toCsv(rows, fields) {
  return [
    fields.join(","),
    ...rows.map((row) => fields.map((field) => csvEscape(row[field])).join(",")),
  ].join("\n") + "\n";
}

function sameValue(a, b) {
  return String(a ?? "") === String(b ?? "");
}

function eventKey(event) {
  return [
    event.type,
    event.domain,
    event.handle || event.url,
    event.run_date,
    event.signal_date || "",
    event.field || "",
  ].join("|");
}

async function appendEvents(events) {
  if (!events.length) return;
  const lines = events.map((event) => JSON.stringify(event)).join("\n") + "\n";
  await fs.appendFile(EVENTS_PATH, lines, "utf8");
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];
    if (quoted) {
      if (ch === '"' && next === '"') {
        value += '"';
        i += 1;
      } else if (ch === '"') {
        quoted = false;
      } else {
        value += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ",") {
      row.push(value);
      value = "";
    } else if (ch === "\n") {
      row.push(value);
      rows.push(row);
      row = [];
      value = "";
    } else if (ch !== "\r") {
      value += ch;
    }
  }
  if (value.length || row.length) {
    row.push(value);
    rows.push(row);
  }
  const headers = rows.shift() || [];
  return rows
    .filter((cols) => cols.some((col) => col !== ""))
    .map((cols) => Object.fromEntries(headers.map((header, index) => [header, cols[index] || ""])));
}

async function runEngine(args) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.mkdir(REPORTS_DIR, { recursive: true });

  const reportDir = path.join(REPORTS_DIR, args.month);
  await fs.mkdir(reportDir, { recursive: true });

  const hitsCsv = path.join(reportDir, "hits.csv");
  const sitesCsv = path.join(reportDir, "sites.csv");
  const summaryMd = path.join(reportDir, "summary.md");
  const progressJson = path.join(reportDir, "progress.json");
  const cacheJson = path.join(DATA_DIR, "classification_cache.json");

  if (args.skip_scan === "yes") {
    return { reportDir, hitsCsv, sitesCsv, summaryMd };
  }

  const engineArgs = [
    ENGINE,
    "--month",
    args.month,
    "--limit",
    String(args.limit),
    "--workers",
    String(args.workers),
    "--max-json-pages",
    String(args.max_json_pages),
    "--max-created",
    String(args.max_created),
    "--max-updated",
    String(args.max_updated),
    "--checkpoint-every",
    String(args.checkpoint_every),
    "--fetch-mode",
    args.fetch_mode,
    "--timeout",
    String(args.timeout),
    "--page-timeout",
    String(args.page_timeout),
    "--min-request-interval-ms",
    String(args.min_request_interval_ms),
    "--request-jitter-ms",
    String(args.request_jitter_ms),
    "--backoff-base-ms",
    String(args.backoff_base_ms),
    "--backoff-max-ms",
    String(args.backoff_max_ms),
    "--max-consecutive-failures",
    String(args.max_consecutive_failures),
    "--cache-ttl-hours",
    String(args.cache_ttl_hours),
    "--cache-max-entries",
    String(args.cache_max_entries),
    "--cache-json",
    cacheJson,
    "--hits-csv",
    hitsCsv,
    "--sites-csv",
    sitesCsv,
    "--md",
    summaryMd,
    "--progress-json",
    progressJson,
  ];
  if (args.update_validation === "yes") {
    engineArgs.push("--update-validation", "yes");
  }

  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, engineArgs, {
      cwd: REPO_DIR,
      stdio: "inherit",
    });
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`single-page scan failed with exit code ${code}`));
    });
  });

  return { reportDir, hitsCsv, sitesCsv, summaryMd, progressJson };
}

async function updateState({ month, hitsCsv, sitesCsv, reportDir }) {
  const now = new Date().toISOString();
  const hits = parseCsv(await fs.readFile(hitsCsv, "utf8"));
  const sites = parseCsv(await fs.readFile(sitesCsv, "utf8"));
  for (const site of sites) {
    if (!site.month_candidates && site.june_candidates) site.month_candidates = site.june_candidates;
  }
  const state = await readJson(STATE_PATH, {
    version: 2,
    created_at: now,
    products: {},
    runs: [],
    events: [],
  }, { strict: true });
  state.products ||= {};
  state.runs ||= [];
  state.events ||= [];
  if (!state.version || state.version < 2) state.version = 2;

  const newHits = [];
  const events = [];
  const runDate = localYmd(new Date(now));
  const seenKeys = new Set();
  for (const hit of hits) {
    const key = `${hit.domain}|${hit.handle || hit.url}`;
    const existing = state.products[key];
    seenKeys.add(key);
    if (!existing) {
      newHits.push({ ...hit, first_seen_at: now, first_seen_month: month });
      events.push({
        type: "single_page_first_detected",
        run_at: now,
        run_date: runDate,
        month,
        domain: hit.domain,
        handle: hit.handle,
        url: hit.url,
        title: hit.product_title || hit.page_title,
        tier: hit.tier,
        date_basis: hit.date_basis,
        signal_date: hit.signal_date,
        created_at: hit.created_at,
        published_at: hit.published_at,
        updated_at: hit.updated_at,
        lastmod: hit.lastmod || "",
      });
      state.products[key] = {
        first_seen_at: now,
        first_seen_month: month,
        first_detected_single_page_at: now,
        first_detected_single_page_month: month,
        first_detected_signal_date: hit.signal_date,
        first_detected_date_basis: hit.date_basis,
        first_url: hit.url,
        first_tier: hit.tier,
      };
    } else {
      if (existing.active === false) {
        events.push({
          type: "single_page_reappeared",
          run_at: now,
          run_date: runDate,
          month,
          domain: hit.domain,
          handle: hit.handle,
          url: hit.url,
          title: hit.product_title || hit.page_title,
          previous_last_seen_at: existing.last_seen_at || "",
          signal_date: hit.signal_date,
          date_basis: hit.date_basis,
        });
      }
      const changedFields = [
        ["signal_date", hit.signal_date],
        ["date_basis", hit.date_basis],
        ["created_at", hit.created_at],
        ["published_at", hit.published_at],
        ["updated_at", hit.updated_at],
        ["lastmod", hit.lastmod || ""],
        ["title", hit.product_title || hit.page_title],
        ["tier", hit.tier],
      ].filter(([field, value]) => !sameValue(existing[field], value));
      for (const [field, value] of changedFields) {
        events.push({
          type: "single_page_changed",
          field,
          run_at: now,
          run_date: runDate,
          month,
          domain: hit.domain,
          handle: hit.handle,
          url: hit.url,
          old_value: existing[field] || "",
          new_value: value || "",
          signal_date: hit.signal_date,
          date_basis: hit.date_basis,
        });
      }
    }
    state.products[key] = {
      ...state.products[key],
      domain: hit.domain,
      handle: hit.handle,
      title: hit.product_title || hit.page_title,
      active: true,
      active_month: month,
      last_seen_at: now,
      last_seen_month: month,
      last_url: hit.url,
      tier: hit.tier,
      date_basis: hit.date_basis,
      signal_date: hit.signal_date,
      created_at: hit.created_at,
      published_at: hit.published_at,
      updated_at: hit.updated_at,
      lastmod: hit.lastmod || "",
      standard_score: hit.standard_score,
      landing_score: hit.landing_score,
    };
  }

  if (args.full_reconcile === "yes") {
    for (const [key, product] of Object.entries(state.products)) {
      if (product.last_seen_month !== month || seenKeys.has(key) || product.active === false) continue;
      events.push({
        type: "single_page_not_seen_in_run",
        run_at: now,
        run_date: runDate,
        month,
        domain: product.domain,
        handle: product.handle,
        url: product.last_url || product.first_url || "",
        title: product.title || "",
        previous_last_seen_at: product.last_seen_at || "",
      });
      product.active = false;
      product.inactive_at = now;
      product.inactive_month = month;
    }
  }

  const newFields = [
    "first_seen_at",
    "first_seen_month",
    "rank_index",
    "domain",
    "monthly_visits",
    "top_country",
    "tier",
    "url",
    "handle",
    "product_title",
    "page_title",
    "date_basis",
    "signal_date",
    "created_at",
    "published_at",
    "updated_at",
    "lastmod",
  ];
  const newHitsCsv = path.join(reportDir, "new_hits.csv");
  await atomicWriteFile(newHitsCsv, toCsv(newHits, newFields), "utf8");

  const uniqueEvents = [];
  const seenEventKeys = new Set();
  for (const event of events) {
    const key = eventKey(event);
    if (seenEventKeys.has(key)) continue;
    seenEventKeys.add(key);
    uniqueEvents.push(event);
  }
  const eventFields = [
    "type",
    "field",
    "run_at",
    "run_date",
    "month",
    "domain",
    "handle",
    "url",
    "title",
    "old_value",
    "new_value",
    "date_basis",
    "signal_date",
    "created_at",
    "published_at",
    "updated_at",
    "lastmod",
    "previous_last_seen_at",
  ];
  await atomicWriteFile(path.join(reportDir, "events.csv"), toCsv(uniqueEvents, eventFields), "utf8");
  await appendEvents(uniqueEvents);

  state.last_run_at = now;
  state.last_month = month;
  state.last_run_id = `${month}-${now}`;
  const cachedProducts = sites.reduce((sum, site) => sum + Number(site.cached_products || 0), 0);
  const networkRequests = sites.reduce((sum, site) => sum + Number(site.network_requests || 0), 0);
  const throttleEvents = sites.reduce((sum, site) => sum + Number(site.throttle_events || 0), 0);
  const pageTimeouts = sites.reduce((sum, site) => sum + Number(site.page_timeouts || 0), 0);
  const sampledStrongCandidates = sites.reduce((sum, site) => sum + Number(site.sampled_strong_candidates || 0), 0);
  const sampledWeakCandidates = sites.reduce((sum, site) => sum + Number(site.sampled_weak_candidates || 0), 0);
  const strongHitPages = sites.reduce((sum, site) => sum + Number(site.strong_hit_count || 0), 0);
  const weakHitPages = sites.reduce((sum, site) => sum + Number(site.weak_hit_count || 0), 0);
  const circuitOpenSites = sites.filter((site) => site.circuit_open === "yes").length;
  state.runs.push({
    run_id: state.last_run_id,
    run_at: now,
    month,
    sites_scanned: sites.length,
    hit_pages: hits.length,
    new_hit_pages: newHits.length,
    event_count: uniqueEvents.length,
    cached_products: cachedProducts,
    network_requests: networkRequests,
    throttle_events: throttleEvents,
    page_timeouts: pageTimeouts,
    sampled_strong_candidates: sampledStrongCandidates,
    sampled_weak_candidates: sampledWeakCandidates,
    strong_hit_pages: strongHitPages,
    weak_hit_pages: weakHitPages,
    circuit_open_sites: circuitOpenSites,
  });
  state.runs = state.runs.slice(-120);
  state.events = [...state.events, ...uniqueEvents].slice(-2000);
  await atomicWriteFile(STATE_PATH, JSON.stringify(state, null, 2) + "\n", "utf8");

  const hitSites = sites.filter((site) => site.status === "has_month_single_page");
  const siteFields = [
    "rank_index",
    "domain",
    "monthly_visits",
    "top_country",
    "tier",
    "hit_count",
    "strongest_basis",
    "first_hit_url",
    "first_hit_title",
    "month_candidates",
    "sampled_products",
    "selected_strong_candidates",
    "selected_weak_candidates",
    "sampled_strong_candidates",
    "sampled_weak_candidates",
    "strong_hit_count",
    "weak_hit_count",
    "scan_quality",
    "coverage_pct",
    "fetch_failures",
    "blocked_products",
    "page_timeouts",
    "cached_products",
    "skipped_products",
    "browser_fallbacks",
    "network_requests",
    "throttle_events",
    "circuit_open",
    "circuit_reason",
    "failure_reasons",
  ];
  const byPriority = (a, b) =>
    Number(b.hit_count || 0) - Number(a.hit_count || 0) ||
    Number(b.monthly_visits || 0) - Number(a.monthly_visits || 0) ||
    Number(a.rank_index || 0) - Number(b.rank_index || 0);
  const top20SinglePageSites = hitSites
    .filter((site) => site.tier === "top20_flagship")
    .sort(byPriority);
  const coreCandidates = hitSites
    .filter((site) => site.tier === "core_candidate")
    .sort(byPriority);
  const needsRescan = sites
    .filter(
      (site) =>
        site.status === "scan_error" ||
        ["error", "blocked", "incomplete", "partial"].includes(site.scan_quality) ||
        (site.status !== "has_month_single_page" &&
          Number(site.month_candidates || site.june_candidates || 0) > 0 &&
          Number(site.sampled_products || 0) === 0)
    )
    .sort((a, b) => Number(a.rank_index || 0) - Number(b.rank_index || 0));

  await atomicWriteFile(path.join(reportDir, "top20_single_page_sites.csv"), toCsv(top20SinglePageSites, siteFields), "utf8");
  await atomicWriteFile(path.join(reportDir, "core_candidates.csv"), toCsv(coreCandidates, siteFields), "utf8");
  await atomicWriteFile(
    path.join(reportDir, "needs_rescan.csv"),
    toCsv(needsRescan, [
      "rank_index",
      "domain",
      "monthly_visits",
      "top_country",
      "status",
      "month_candidates",
      "sampled_products",
      "selected_strong_candidates",
      "selected_weak_candidates",
      "sampled_strong_candidates",
      "sampled_weak_candidates",
      "strong_hit_count",
      "weak_hit_count",
      "scan_quality",
      "coverage_pct",
      "fetch_failures",
      "blocked_products",
      "page_timeouts",
      "cached_products",
      "skipped_products",
      "browser_fallbacks",
      "network_requests",
      "throttle_events",
      "circuit_open",
      "circuit_reason",
      "failure_reasons",
      "first_hit_url",
    ]),
    "utf8"
  );

  const summary = {
    generated_at: now,
    month,
    sites_scanned: sites.length,
    hit_sites: hitSites.length,
    hit_pages: hits.length,
    new_hit_pages: newHits.length,
    event_count: uniqueEvents.length,
    top20_flagship_sites: top20SinglePageSites.length,
    core_candidate_sites: coreCandidates.length,
    needs_rescan_sites: needsRescan.length,
    blocked_sites: sites.filter((site) => site.scan_quality === "blocked").length,
    partial_sites: sites.filter((site) => ["partial", "incomplete"].includes(site.scan_quality)).length,
    cached_products: cachedProducts,
    network_requests: networkRequests,
    throttle_events: throttleEvents,
    page_timeouts: pageTimeouts,
    sampled_strong_candidates: sampledStrongCandidates,
    sampled_weak_candidates: sampledWeakCandidates,
    strong_hit_pages: strongHitPages,
    weak_hit_pages: weakHitPages,
    circuit_open_sites: circuitOpenSites,
    report_dir: reportDir,
  };
  await atomicWriteFile(LATEST_PATH, JSON.stringify(summary, null, 2) + "\n", "utf8");
  return { summary, newHitsCsv };
}

const cli = parseArgs(process.argv);
const config = await readJson(CONFIG_PATH, {}, { strict: true });
const args = {
  month: cli.get("--month") || config.month || localMonth(),
  limit: Number(cli.get("--limit") || config.limit || 200),
  workers: Number(cli.get("--workers") || config.workers || 6),
  max_json_pages: Number(cli.get("--max-json-pages") || config.max_json_pages || 6),
  max_created: Number(cli.get("--max-created") || config.max_created || 80),
  max_updated: Number(cli.get("--max-updated") || config.max_updated || 35),
  checkpoint_every: Number(cli.get("--checkpoint-every") || config.checkpoint_every || 10),
  fetch_mode: cli.get("--fetch-mode") || config.fetch_mode || "auto",
  timeout: Number(cli.get("--timeout") || config.timeout || 30000),
  page_timeout: Number(cli.get("--page-timeout") || config.page_timeout || 12000),
  min_request_interval_ms: Number(cli.get("--min-request-interval-ms") || config.min_request_interval_ms || 900),
  request_jitter_ms: Number(cli.get("--request-jitter-ms") || config.request_jitter_ms || 500),
  backoff_base_ms: Number(cli.get("--backoff-base-ms") || config.backoff_base_ms || 2000),
  backoff_max_ms: Number(cli.get("--backoff-max-ms") || config.backoff_max_ms || 60000),
  max_consecutive_failures: Number(cli.get("--max-consecutive-failures") || config.max_consecutive_failures || 3),
  cache_ttl_hours: Number(cli.get("--cache-ttl-hours") || config.cache_ttl_hours || 18),
  cache_max_entries: Number(cli.get("--cache-max-entries") || config.cache_max_entries || 50000),
  update_validation: cli.get("--update-validation") || config.update_validation || "no",
  skip_scan: cli.get("--skip-scan") || config.skip_scan || "no",
  full_reconcile: cli.get("--full-reconcile") || config.full_reconcile || "no",
};
validateScanOptions(args);

console.log(`SP single-page monitor | month=${args.month} limit=${args.limit} workers=${args.workers} skip_scan=${args.skip_scan}`);
const outputs = await runEngine(args);
const { summary, newHitsCsv } = await updateState({ month: args.month, ...outputs });
console.log(
  `Single-page monitor done | hit_sites=${summary.hit_sites} hit_pages=${summary.hit_pages} new=${summary.new_hit_pages}`
);
console.log(`Report: ${outputs.summaryMd}`);
console.log(`New hits: ${newHitsCsv}`);
