#!/usr/bin/env node

import fs from "node:fs/promises";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { detectAccessIssue, shouldTryBrowserFallback } from "./lib/scan_helpers.mjs";
import { atomicWriteFile } from "./lib/file_utils.mjs";

function resolvePlaywrightPath() {
  const explicit = process.env.SP_PLAYWRIGHT_PATH || process.env.PLAYWRIGHT_PATH || "";
  const explicitIndex = explicit && (explicit.endsWith(".js") ? explicit : path.join(explicit, "index.js"));
  if (explicitIndex && existsSync(explicitIndex)) return explicitIndex;

  const require = createRequire(import.meta.url);
  const selfDir = path.dirname(fileURLToPath(import.meta.url));
  try {
    return require.resolve("playwright", {
      paths: [selfDir, path.join(selfDir, "single-page-monitor")],
    });
  } catch {}

  throw new Error(
    "Playwright module not found. Set SP_PLAYWRIGHT_PATH to playwright's index.js, " +
      "or run `npm install` inside single-page-monitor/."
  );
}

const PLAYWRIGHT_PATH = resolvePlaywrightPath();
const playwrightModule = await import(pathToFileURL(PLAYWRIGHT_PATH).href);
const playwright = playwrightModule.default || playwrightModule;
const { chromium } = playwright;

const __filename = fileURLToPath(import.meta.url);
const PROJECT_DIR = path.dirname(__filename);
const CHROME_PATH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 1) {
  if (!process.argv[i].startsWith("--")) continue;
  args.set(process.argv[i], process.argv[i + 1] && !process.argv[i + 1].startsWith("--") ? process.argv[++i] : "yes");
}

const MONTHS = (args.get("--months") || args.get("--month") || "2026-06")
  .split(",")
  .map((month) => month.trim())
  .filter(Boolean);
const MONTH = MONTHS[0] || "2026-06";
const DASHBOARD_LABEL = args.get("--label") || (MONTHS.length > 1 ? `${MONTHS.at(-1)} - ${MONTHS[0]}` : MONTH);
const LATEST_MONTH = MONTHS.slice().sort().at(-1) || MONTH;
const OUT_KEY = args.get("--out") || MONTH;
const WORKERS = Number(args.get("--workers") || 6);
const TIMEOUT = Number(args.get("--timeout") || 25000);
const DATA_DIR = process.env.SP_SINGLE_PAGE_DATA_DIR || path.join(PROJECT_DIR, "data");
const REPORTS_DIR = process.env.SP_SINGLE_PAGE_REPORTS_DIR || path.join(PROJECT_DIR, "reports");
const REPORT_DIR = path.join(REPORTS_DIR, OUT_KEY);
const LATEST_JSON = path.join(DATA_DIR, "latest.json");
const STATE_JSON = path.join(DATA_DIR, "state.json");
const OUT_JSON = path.join(REPORT_DIR, "dashboard_data.json");
const OUT_HTML = path.join(REPORT_DIR, "dashboard.html");
const OUT_DUPLICATES = path.join(REPORT_DIR, "duplicate_groups.json");

const USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

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

async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return fallback;
  }
}

function stripHtml(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function absoluteUrl(url, baseUrl) {
  if (!url) return "";
  if (url.startsWith("//")) return `https:${url}`;
  try {
    return new URL(url, baseUrl).toString();
  } catch {
    return url;
  }
}

function metaContent(html, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns = [
    new RegExp(`<meta[^>]+property=["']${escaped}["'][^>]+content=["']([^"']+)["'][^>]*>`, "i"),
    new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+property=["']${escaped}["'][^>]*>`, "i"),
    new RegExp(`<meta[^>]+name=["']${escaped}["'][^>]+content=["']([^"']+)["'][^>]*>`, "i"),
    new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+name=["']${escaped}["'][^>]*>`, "i"),
  ];
  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match) return match[1].replace(/&amp;/g, "&");
  }
  return "";
}

function firstImageFromHtml(html, baseUrl) {
  const og = metaContent(html, "og:image") || metaContent(html, "twitter:image");
  if (og) return absoluteUrl(og, baseUrl);
  const imageMatch = html.match(/<img[^>]+(?:src|data-src|data-original)=["']([^"']+)["'][^>]*>/i);
  return imageMatch ? absoluteUrl(imageMatch[1], baseUrl) : "";
}

async function fetchViaPage(page, url) {
  const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT }).catch(() => null);
  if (!response) return { status: 0, text: "", finalUrl: url, transport: "browser" };
  let text = "";
  try {
    text = await response.text();
  } catch {
    text = await page.content();
  }
  return { status: response.status(), text, finalUrl: page.url(), transport: "browser" };
}

async function fetchViaRequest(context, url) {
  try {
    const response = await context.request.get(url, { timeout: TIMEOUT, failOnStatusCode: false });
    const result = {
      status: response.status(),
      text: await response.text(),
      finalUrl: response.url(),
      transport: "request",
    };
    await response.dispose().catch(() => {});
    return result;
  } catch {
    return { status: 0, text: "", finalUrl: url, transport: "request" };
  }
}

async function fetchResource(context, page, url, state) {
  if (state.forceBrowser) return fetchViaPage(page, url);
  const direct = await fetchViaRequest(context, url);
  const issue = detectAccessIssue(direct);
  if (!shouldTryBrowserFallback(issue)) return direct;
  state.directFailures += 1;
  if (["forbidden", "rate_limited", "bot_challenge"].includes(issue) || state.directFailures >= 2) {
    state.forceBrowser = true;
  }
  return fetchViaPage(page, url);
}

function productJsonUrl(hit) {
  return `https://${hit.domain}/products/${hit.handle}.json`;
}

async function enrichHit(context, page, fetchState, hit, siteMap) {
  const site = siteMap.get(`${hit.source_month}|${hit.domain}`) || siteMap.get(hit.domain) || {};
  const enriched = {
    ...hit,
    rank_index: Number(hit.rank_index || 0),
    monthly_visits: Number(hit.monthly_visits || 0),
    hit_count: Number(site.hit_count || 0),
    image_url: "",
    image_urls: [],
    price: "",
    compare_at_price: "",
    currency: "",
    vendor: "",
    product_type: "",
    tags: [],
    description: "",
    source_detail: "",
  };

  const jsonResp = await fetchResource(context, page, productJsonUrl(hit), fetchState);
  if (jsonResp.status === 200) {
    try {
      const product = JSON.parse(jsonResp.text).product;
      if (product) {
        const images = (product.images || [])
          .map((image) => absoluteUrl(image.src || image, hit.url))
          .filter(Boolean);
        const variant = product.variants?.[0] || {};
        enriched.image_urls = images;
        enriched.image_url = absoluteUrl(product.image?.src || images[0] || "", hit.url);
        enriched.price = variant.price || "";
        enriched.compare_at_price = variant.compare_at_price || "";
        enriched.vendor = product.vendor || "";
        enriched.product_type = product.product_type || "";
        enriched.tags = Array.isArray(product.tags) ? product.tags : String(product.tags || "").split(",").map((tag) => tag.trim()).filter(Boolean);
        enriched.description = stripHtml(product.body_html).slice(0, 220);
        enriched.source_detail = "product_json";
      }
    } catch {
      // Fall back to page metadata.
    }
  }

  if (!enriched.image_url || !enriched.description || !enriched.price) {
    const pageResp = await fetchResource(context, page, hit.url, fetchState);
    if (pageResp.status === 200) {
      const html = pageResp.text;
      enriched.image_url ||= firstImageFromHtml(html, hit.url);
      enriched.image_urls = enriched.image_urls.length ? enriched.image_urls : [enriched.image_url].filter(Boolean);
      enriched.price ||= metaContent(html, "product:price:amount");
      enriched.currency ||= metaContent(html, "product:price:currency");
      enriched.description ||= stripHtml(metaContent(html, "og:description") || metaContent(html, "description")).slice(0, 220);
      enriched.source_detail = enriched.source_detail ? `${enriched.source_detail}+html_meta` : "html_meta";
    }
  }

  enriched.display_title = enriched.product_title || enriched.page_title || enriched.title || enriched.handle;
  enriched.display_title = String(enriched.display_title || "").replace(/\s+/g, " ").trim();
  return enriched;
}

function jsString(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

function signalDateValue(product) {
  return String(product.signal_date || product.created_at || product.published_at || product.updated_at || "");
}

function productDateValue(product) {
  return String(product.first_seen_at || signalDateValue(product));
}

function freshnessWeight(product) {
  const value = productDateValue(product);
  const day = Number(value.slice(8, 10) || 1);
  const year = Number(value.slice(0, 4) || LATEST_MONTH.slice(0, 4));
  const month = Number(value.slice(5, 7) || LATEST_MONTH.slice(5, 7));
  const daysInMonth = new Date(year, month, 0).getDate() || 30;
  return Math.max(1, Math.min(100, Math.round((day / daysInMonth) * 100)));
}

function duplicateKey(product) {
  let text = String(product.display_title || product.product_title || product.page_title || product.handle || "").toLowerCase();
  text = text
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\b(50|49|off|sale|hot|last|day|buy|get|free|now|limited|time|2026|sold|pcs|uk|us|new)\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text.length >= 12 ? text : `${product.domain}|${product.handle}`;
}

function attachRankingMeta(products) {
  const groups = new Map();
  for (const product of products) {
    product.sort_date = productDateValue(product);
    product.freshness_weight = freshnessWeight(product);
    product.duplicate_key = duplicateKey(product);
    if (!groups.has(product.duplicate_key)) groups.set(product.duplicate_key, []);
    groups.get(product.duplicate_key).push(product);
  }

  const duplicateGroups = [];
  for (const [key, group] of groups) {
    group.sort(
      (a, b) =>
        productDateValue(b).localeCompare(productDateValue(a)) ||
        signalDateValue(b).localeCompare(signalDateValue(a)) ||
        Number(b.monthly_visits || 0) - Number(a.monthly_visits || 0)
    );
    group.forEach((product, index) => {
      product.duplicate_count = group.length;
      product.duplicate_rank = index + 1;
      product.duplicate_keep = index === 0;
    });
    if (group.length > 1) {
      duplicateGroups.push({
        duplicate_key: key,
        count: group.length,
        keep_url: group[0].url,
        keep_title: group[0].display_title,
        products: group.map((product) => ({
          domain: product.domain,
          handle: product.handle,
          url: product.url,
          title: product.display_title,
          created_at: product.created_at,
          published_at: product.published_at,
          first_seen_at: product.first_seen_at,
          signal_date: product.signal_date,
          date_basis: product.date_basis,
        })),
      });
    }
  }

  return duplicateGroups.sort((a, b) => b.count - a.count || a.duplicate_key.localeCompare(b.duplicate_key));
}

function attachStateMeta(products, state) {
  const stateProducts = state?.products || {};
  for (const product of products) {
    const key = `${product.domain}|${product.handle || product.url}`;
    const existing = stateProducts[key] || {};
    product.first_seen_at = existing.first_seen_at || "";
    product.first_seen_month = existing.first_seen_month || product.source_month || "";
    product.last_seen_at = existing.last_seen_at || "";
    product.last_seen_month = existing.last_seen_month || "";
    product.signal_sort_date = signalDateValue(product);
  }
}

function buildHtml(payload) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SP 单页监控看板 ${payload.label}</title>
<style>
*,*::before,*::after{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:#f3f4f6;color:#111827}
body.auth-locked{overflow:hidden;background:#111827}
body.auth-locked .header,body.auth-locked .controls,body.auth-locked .main{filter:blur(8px);opacity:.18;pointer-events:none;user-select:none}
body.auth-unlocked .auth-gate{display:none}
button,input,select{font:inherit}
.auth-gate{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,rgba(17,24,39,.96),rgba(37,99,235,.88));padding:20px}
.auth-card{width:min(430px,100%);background:#fff;border:1px solid rgba(255,255,255,.24);border-radius:8px;box-shadow:0 24px 80px rgba(0,0,0,.35);padding:24px}
.auth-kicker{font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#2563eb;margin-bottom:8px}
.auth-title{font-size:22px;line-height:1.2;font-weight:800;margin:0;color:#111827}
.auth-copy{font-size:13px;line-height:1.5;color:#4b5563;margin:10px 0 18px}
.auth-form{display:grid;grid-template-columns:1fr auto;gap:8px}
.auth-input{min-width:0;border:1px solid #d1d5db;border-radius:8px;padding:10px 11px;color:#111827;background:#fff}
.auth-input:focus{outline:2px solid rgba(37,99,235,.24);border-color:#2563eb}
.auth-submit{border:1px solid #2563eb;border-radius:8px;background:#2563eb;color:#fff;font-weight:800;padding:10px 14px;cursor:pointer;white-space:nowrap}
.auth-error{min-height:18px;margin-top:10px;font-size:12px;font-weight:700;color:#dc2626}
.auth-note{margin-top:14px;font-size:12px;color:#6b7280}
.header{background:#17202f;color:#fff;padding:18px 24px 20px;border-bottom:1px solid #0f172a}
.header-inner{max-width:1440px;margin:0 auto}
.topline{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
h1{font-size:22px;line-height:1.2;margin:0 0 6px;font-weight:750;letter-spacing:0}
.meta{font-size:13px;color:#cbd5e1}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.stat{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.16);border-radius:8px;padding:8px 11px;min-width:108px}
.stat b{display:block;font-size:20px;line-height:1.1}
.stat span{font-size:12px;color:#cbd5e1}
.controls{position:sticky;top:0;z-index:20;background:#fff;border-bottom:1px solid #e5e7eb}
.controls-inner{max-width:1440px;margin:0 auto;padding:12px 24px;display:grid;grid-template-columns:minmax(220px,1fr) auto auto;gap:10px;align-items:center}
.search{width:100%;border:1px solid #d1d5db;border-radius:8px;padding:9px 11px;color:#111827;background:#fff}
.tabs{display:flex;gap:6px;overflow:auto}
.tab{border:1px solid #d1d5db;background:#f9fafb;color:#374151;border-radius:8px;padding:8px 10px;white-space:nowrap;cursor:pointer}
.tab.active{background:#2563eb;border-color:#2563eb;color:#fff}
.toggle{display:flex;align-items:center;gap:7px;border:1px solid #d1d5db;border-radius:8px;padding:8px 10px;background:#fff;color:#374151;font-size:13px;font-weight:650;white-space:nowrap}
.toggle input{width:16px;height:16px}
.main{max-width:1440px;margin:0 auto;padding:18px 24px 28px}
.layout{display:block}
.badge{display:inline-flex;align-items:center;border-radius:999px;padding:2px 7px;font-size:11px;font-weight:700;white-space:nowrap}
.badge-top{background:#fef3c7;color:#92400e}
.badge-core{background:#dbeafe;color:#1d4ed8}
.badge-count{background:#ecfdf5;color:#047857}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
.result-title{font-size:15px;font-weight:750;color:#374151}
.result-title span{color:#2563eb}
.result-note{font-size:12px;color:#64748b;margin-top:4px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:13px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;box-shadow:0 1px 2px rgba(15,23,42,.05)}
.image-wrap{position:relative;aspect-ratio:4/3;background:#eef2f7;display:flex;align-items:center;justify-content:center;overflow:hidden}
.image-wrap img{width:100%;height:100%;object-fit:cover;display:block}
.placeholder{font-size:13px;color:#64748b;padding:16px;text-align:center}
.rank{position:absolute;left:8px;top:8px;background:rgba(15,23,42,.78);color:#fff;border-radius:999px;font-size:11px;font-weight:750;padding:3px 7px}
.tier{position:absolute;right:8px;top:8px}
.body{padding:12px}
.title{font-size:14px;font-weight:750;line-height:1.35;min-height:38px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.desc{font-size:12px;line-height:1.4;color:#64748b;margin-top:7px;min-height:34px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.chip{border-radius:6px;padding:4px 6px;font-size:11px;font-weight:650;background:#f3f4f6;color:#374151}
.chip-price{background:#ecfdf5;color:#047857}
.chip-date{background:#fef3c7;color:#92400e}
.chip-score{background:#f5f3ff;color:#6d28d9}
.chip-signal{background:#fee2e2;color:#b91c1c}
.chip-dup{background:#e0f2fe;color:#0369a1}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}
.btn{border:1px solid #d1d5db;border-radius:8px;padding:8px;text-align:center;text-decoration:none;font-size:12px;font-weight:750;color:#111827;background:#fff;cursor:pointer}
.btn.primary{background:#2563eb;border-color:#2563eb;color:#fff}
.empty{padding:50px 20px;text-align:center;color:#64748b;background:#fff;border:1px solid #e5e7eb;border-radius:8px}
@media(max-width:900px){
  .controls-inner{grid-template-columns:1fr}
  .main,.header,.controls-inner{padding-left:14px;padding-right:14px}
}
@media(max-width:560px){
  h1{font-size:18px}
  .grid{grid-template-columns:1fr}
  .stats{display:grid;grid-template-columns:repeat(2,1fr)}
  .auth-form{grid-template-columns:1fr}
}
</style>
</head>
<body class="auth-locked">
<div id="auth-gate" class="auth-gate" role="dialog" aria-modal="true" aria-labelledby="auth-title">
  <section class="auth-card">
    <h2 id="auth-title" class="auth-title">公司邮箱登录</h2>
    <p class="auth-copy">这个 SP 单页监控看板仅允许已授权的公司邮箱访问。验证通过后，本机浏览器会记住邮箱。</p>
    <form id="auth-form" class="auth-form">
      <input id="auth-email" class="auth-input" type="email" autocomplete="email" inputmode="email" placeholder="请输入公司邮箱" required>
      <button class="auth-submit" type="submit">进入看板</button>
    </form>
    <div id="auth-error" class="auth-error" aria-live="polite"></div>
    <div class="auth-note">请输入完整邮箱，未授权邮箱无法访问。</div>
  </section>
</div>
<header class="header">
  <div class="header-inner">
    <div class="topline">
      <div>
        <h1>SP 单页监控看板 · ${payload.label}</h1>
        <div class="meta">Top200 Shopify/SP 站 · 单页创建/发布/更新信号 · 生成时间 ${payload.generated_at}</div>
      </div>
      <div class="meta">单页项目独立运行，不改变动态 Top20 旗舰逻辑</div>
    </div>
    <div class="stats">
      <div class="stat"><b>${payload.summary.hit_sites}</b><span>命中站点</span></div>
      <div class="stat"><b>${payload.summary.hit_pages}</b><span>单页产品</span></div>
      <div class="stat"><b>${payload.summary.top20_flagship_sites}</b><span>Top20 内站点</span></div>
      <div class="stat"><b>${payload.summary.core_candidate_sites}</b><span>核心候选站</span></div>
      <div class="stat"><b>${payload.summary.duplicate_groups}</b><span>同款重复组</span></div>
      <div class="stat"><b>${payload.summary.needs_rescan_sites}</b><span>待补扫站</span></div>
    </div>
  </div>
</header>
<section class="controls">
  <div class="controls-inner">
    <input id="search" class="search" placeholder="搜索产品、域名、handle、类型">
    <div class="tabs" id="tabs"></div>
    <label class="toggle"><input id="dedupe" type="checkbox">隐藏同款重复</label>
  </div>
</section>
<main class="main">
  <div class="layout">
    <section>
      <div class="toolbar">
        <div>
          <div class="result-title">产品单页 <span id="result-count">0</span></div>
          <div class="result-note">排名按首次发现为单页的时间倒序；更新信号单独显示，避免同一产品每天因更新日期变化被当成新单页。</div>
        </div>
      </div>
      <div id="grid" class="grid"></div>
      <div id="empty" class="empty" style="display:none">没有符合当前筛选条件的单页产品</div>
    </section>
  </div>
</main>
<script>
const AUTH_STORAGE_KEY = "sp_single_page_dashboard_email";
const AUTH_DOMAIN_HASH = "fce3633eb094ab6e645b37e8039e27d3f2c5439242f87e5d6931e91758dd4ff8";
const DATA = ${jsString(payload)};
const latestSeenDay = DATA.products.map(item => firstSeenDate(item).slice(0, 10)).filter(Boolean).sort().at(-1) || "";
const tabs = [
  ["all", "全部"],
  ["top20", "Top20 内"],
  ["core", "核心候选"],
  ["hot", "站点命中≥5"],
  ["newest", "最新发现"]
];
let activeTab = "all";

const fmt = new Intl.NumberFormat("zh-CN");
function normalizeEmail(value){ return String(value || "").trim().toLowerCase(); }
function emailDomain(value){
  const match = normalizeEmail(value).match(/^[^\\s@]+@([^\\s@]+\\.[^\\s@]+)$/);
  return match ? match[1] : "";
}
async function sha256Hex(value){
  const bytes = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}
async function isAllowedEmail(value){
  const domain = emailDomain(value);
  if (!domain || !globalThis.crypto?.subtle) return false;
  return await sha256Hex(domain) === AUTH_DOMAIN_HASH;
}
function showAuthError(message){
  const el = document.getElementById("auth-error");
  if (el) el.textContent = message;
}
function unlockDashboard(email){
  try { localStorage.setItem(AUTH_STORAGE_KEY, normalizeEmail(email)); } catch {}
  document.body.classList.remove("auth-locked");
  document.body.classList.add("auth-unlocked");
  document.getElementById("auth-gate")?.setAttribute("aria-hidden", "true");
  render();
}
async function initAuth(){
  let saved = "";
  try { saved = normalizeEmail(localStorage.getItem(AUTH_STORAGE_KEY)); } catch {}
  if (await isAllowedEmail(saved)) {
    unlockDashboard(saved);
    return;
  }
  const form = document.getElementById("auth-form");
  const input = document.getElementById("auth-email");
  if (saved && input) input.value = saved;
  form?.addEventListener("submit", async event => {
    event.preventDefault();
    const email = normalizeEmail(input?.value);
    if (!(await isAllowedEmail(email))) {
      showAuthError("该邮箱暂无访问权限。");
      input?.focus();
      return;
    }
    showAuthError("");
    unlockDashboard(email);
  });
  input?.focus();
}
function shortDate(value){ return value ? value.slice(5, 10) : ""; }
function sortDate(item){ return String(item.sort_date || item.created_at || item.published_at || ""); }
function firstSeenDate(item){ return String(item.first_seen_at || item.sort_date || ""); }
function firstSeenChipText(item){ return "发现 " + shortDate(firstSeenDate(item)); }
function dateChipText(item){
  const value = item.signal_date || item.created_at || item.published_at || item.updated_at || "";
  const label = item.date_basis === "updated_month" || item.date_basis === "sitemap_lastmod_month" ? "更新" : "上线";
  return shortDate(value) + " " + label;
}
function priceText(item){
  if (!item.price) return "价格未取到";
  const currency = item.currency || "";
  return currency ? currency + " " + item.price : item.price;
}
function esc(value){
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[ch]));
}
function tierBadge(item){
  return item.tier === "top20_flagship"
    ? '<span class="badge badge-top">Top20</span>'
    : '<span class="badge badge-core">核心</span>';
}
function spreadByDomain(items){
  const queues = new Map();
  const domainOrder = [];
  for (const item of items) {
    const domain = item.domain || "";
    if (!queues.has(domain)) {
      queues.set(domain, []);
      domainOrder.push(domain);
    }
    queues.get(domain).push(item);
  }
  const out = [];
  let remaining = items.length;
  while (remaining > 0) {
    for (const domain of domainOrder) {
      const queue = queues.get(domain);
      if (!queue || !queue.length) continue;
      out.push(queue.shift());
      remaining -= 1;
    }
  }
  return out;
}
function filteredItems(){
  const q = document.getElementById("search").value.trim().toLowerCase();
  let items = DATA.products.slice();
  if (activeTab === "top20") items = items.filter(item => item.tier === "top20_flagship");
  if (activeTab === "core") items = items.filter(item => item.tier === "core_candidate");
  if (activeTab === "hot") items = items.filter(item => Number(item.hit_count || 0) >= 5);
  if (activeTab === "newest") items = items.filter(item => firstSeenDate(item).slice(0, 10) === latestSeenDay);
  if (document.getElementById("dedupe").checked) items = items.filter(item => item.duplicate_keep !== false);
  if (q) {
    items = items.filter(item => [
      item.domain, item.handle, item.display_title, item.product_type, item.description, (item.tags || []).join(" ")
    ].join(" ").toLowerCase().includes(q));
  }
  items.sort((a,b) => {
    return sortDate(b).localeCompare(sortDate(a)) ||
      Number(b.freshness_weight || 0) - Number(a.freshness_weight || 0) ||
      Number(b.hit_count || 0) - Number(a.hit_count || 0) ||
      Number(b.monthly_visits || 0) - Number(a.monthly_visits || 0);
  });
  return spreadByDomain(items);
}
function renderTabs(){
  const el = document.getElementById("tabs");
  el.innerHTML = tabs.map(([id,label]) => '<button class="tab '+(activeTab===id?'active':'')+'" data-tab="'+id+'">'+label+'</button>').join("");
  el.querySelectorAll("button").forEach(btn => btn.addEventListener("click", () => {
    activeTab = btn.dataset.tab;
    render();
  }));
}
function renderGrid(){
  const items = filteredItems();
  document.getElementById("result-count").textContent = items.length;
  const grid = document.getElementById("grid");
  const empty = document.getElementById("empty");
  empty.style.display = items.length ? "none" : "block";
  grid.innerHTML = items.map((item, index) => {
    const image = item.image_url
      ? '<img src="'+esc(item.image_url)+'" alt="'+esc(item.display_title || item.handle)+'" loading="lazy" referrerpolicy="no-referrer">'
      : '<div class="placeholder">未取到产品图<br>'+esc(item.domain)+'</div>';
    const type = item.product_type ? '<span class="chip">'+esc(item.product_type)+'</span>' : "";
    const compare = item.compare_at_price ? '<span class="chip">原价 '+esc(item.compare_at_price)+'</span>' : "";
    const duplicate = Number(item.duplicate_count || 1) > 1 ? '<span class="chip chip-dup">同款 '+item.duplicate_count+'</span>' : "";
    return '<article class="card">'+
      '<div class="image-wrap">'+image+'<span class="rank">#'+(index + 1)+'</span><span class="tier">'+tierBadge(item)+'</span></div>'+
      '<div class="body">'+
        '<div class="title">'+esc(item.display_title || item.handle)+'</div>'+
        '<div class="desc">'+esc(item.description || item.page_title || item.handle)+'</div>'+
        '<div class="chips">'+
          '<span class="chip">'+esc(item.domain)+'</span>'+
          '<span class="chip chip-price">'+esc(priceText(item))+'</span>'+
          compare+
          '<span class="chip chip-signal">'+firstSeenChipText(item)+'</span>'+
          '<span class="chip chip-date">'+dateChipText(item)+'</span>'+
          '<span class="chip chip-score">LP '+item.landing_score+'</span>'+
          '<span class="chip">站点#'+item.rank_index+'</span>'+
          '<span class="chip">站内 '+item.hit_count+' 页</span>'+
          duplicate+
          type+
        '</div>'+
        '<div class="actions"><a class="btn primary" href="'+esc(item.url)+'" target="_blank" rel="noopener">打开单页</a><button class="btn" data-copy="'+esc(item.url)+'">复制链接</button></div>'+
      '</div>'+
    '</article>';
  }).join("");
  grid.querySelectorAll("[data-copy]").forEach(btn => btn.addEventListener("click", async () => {
    await navigator.clipboard.writeText(btn.dataset.copy).catch(() => {});
    btn.textContent = "已复制";
    setTimeout(() => btn.textContent = "复制链接", 1200);
  }));
}
function render(){
  renderTabs();
  renderGrid();
}
document.getElementById("search").addEventListener("input", renderGrid);
document.getElementById("dedupe").addEventListener("change", render);
initAuth().catch(() => showAuthError("验证失败，请稍后再试。"));
</script>
</body>
</html>`;
}

async function waitForPreviewImages(page) {
  await page.evaluate(async () => {
    const images = Array.from(document.images).slice(0, 16);
    images.forEach((image) => {
      image.loading = "eager";
    });
    await Promise.all(
      images.map((image) => {
        if (image.complete) return true;
        return new Promise((resolve) => {
          const done = () => resolve(true);
          image.addEventListener("load", done, { once: true });
          image.addEventListener("error", done, { once: true });
          setTimeout(done, 4000);
        });
      })
    );
  });
}

async function renderDashboardScreenshots(htmlPath, reportDir) {
  const browser = await chromium.launch({ headless: true, executablePath: CHROME_PATH });
  try {
    const targets = [
      {
        name: "dashboard_desktop.png",
        viewport: { width: 1280, height: 768 },
        deviceScaleFactor: 1,
      },
      {
        name: "dashboard_mobile.png",
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 2,
      },
    ];
    for (const target of targets) {
      const context = await browser.newContext({
        viewport: target.viewport,
        deviceScaleFactor: target.deviceScaleFactor,
        userAgent: USER_AGENT,
      });
      const page = await context.newPage();
      await page.goto(pathToFileURL(htmlPath).href, { waitUntil: "domcontentloaded", timeout: 60000 });
      await page.evaluate(() => {
        if (typeof unlockDashboard === "function") {
          unlockDashboard("screenshot@local.invalid");
        } else {
          document.body.classList.remove("auth-locked");
          document.body.classList.add("auth-unlocked");
          document.getElementById("auth-gate")?.setAttribute("aria-hidden", "true");
        }
      });
      await page.waitForSelector(".card, #empty", { timeout: 15000 }).catch(() => {});
      await waitForPreviewImages(page);
      await page.screenshot({
        path: path.join(reportDir, target.name),
        fullPage: false,
      });
      await context.close();
    }
  } finally {
    await browser.close();
  }
}

const latest = await readJson(LATEST_JSON, {});
const state = await readJson(STATE_JSON, {});
const hits = [];
const sites = [];
for (const month of MONTHS) {
  const monthReportDir = path.join(REPORTS_DIR, month);
  const [hitsText, sitesText] = await Promise.all([
    fs.readFile(path.join(monthReportDir, "hits.csv"), "utf8"),
    fs.readFile(path.join(monthReportDir, "sites.csv"), "utf8"),
  ]);
  for (const hit of parseCsv(hitsText)) {
    hits.push({ ...hit, source_month: month });
  }
  for (const site of parseCsv(sitesText)) {
    if (!site.month_candidates && site.june_candidates) site.month_candidates = site.june_candidates;
    sites.push({ ...site, source_month: month });
  }
}
const siteMap = new Map();
for (const site of sites) {
  siteMap.set(`${site.source_month}|${site.domain}`, site);
  if (!siteMap.has(site.domain)) siteMap.set(site.domain, site);
}

console.log(`Building dashboard for ${hits.length} single-page products | months=${MONTHS.join(",")}`);
const browser = await chromium.launch({ headless: true, executablePath: CHROME_PATH });
const context = await browser.newContext({ userAgent: USER_AGENT });
const pages = await Promise.all(Array.from({ length: WORKERS }, () => context.newPage()));
await Promise.all(
  pages.map((page) =>
    page.route("**/*", (route) =>
      route.request().isNavigationRequest() ? route.continue() : route.abort()
    )
  )
);
const products = [];
let cursor = 0;
let completed = 0;

async function worker(page) {
  const fetchState = { forceBrowser: false, directFailures: 0 };
  while (cursor < hits.length) {
    const hit = hits[cursor++];
    const product = await enrichHit(context, page, fetchState, hit, siteMap).catch((error) => ({
      ...hit,
      rank_index: Number(hit.rank_index || 0),
      monthly_visits: Number(hit.monthly_visits || 0),
      hit_count: Number((siteMap.get(`${hit.source_month}|${hit.domain}`) || siteMap.get(hit.domain))?.hit_count || 0),
      image_url: "",
      image_urls: [],
      price: "",
      compare_at_price: "",
      currency: "",
      vendor: "",
      product_type: "",
      tags: [],
      description: "",
      display_title: hit.product_title || hit.page_title || hit.handle,
      source_detail: `error: ${error.name}`,
    }));
    products.push(product);
    completed += 1;
    if (completed % 10 === 0 || completed === hits.length) {
      console.log(`${completed}/${hits.length} enriched`);
    }
  }
}

await Promise.all(pages.map((page) => worker(page)));
await context.close();
await browser.close();

attachStateMeta(products, state);
const duplicateGroups = attachRankingMeta(products);
products.sort(
  (a, b) =>
    productDateValue(b).localeCompare(productDateValue(a)) ||
    signalDateValue(b).localeCompare(signalDateValue(a)) ||
    Number(b.freshness_weight || 0) - Number(a.freshness_weight || 0) ||
    Number(b.hit_count || 0) - Number(a.hit_count || 0) ||
    Number(b.monthly_visits || 0) - Number(a.monthly_visits || 0) ||
    Number(a.rank_index || 0) - Number(b.rank_index || 0)
);

const uniqueDomains = (rows) => new Set(rows.map((item) => item.domain).filter(Boolean)).size;
const needsRescanSites = sites.filter(
  (site) =>
    site.status === "scan_error" ||
    ["error", "blocked", "incomplete", "partial"].includes(site.scan_quality) ||
    (site.status !== "has_month_single_page" &&
      Number(site.month_candidates || site.june_candidates || 0) > 0 &&
      Number(site.sampled_products || 0) === 0)
).length;
const payload = {
  generated_at: new Date().toLocaleString("zh-CN", { hour12: false }),
  month: MONTH,
  months: MONTHS,
  latest_month: LATEST_MONTH,
  label: DASHBOARD_LABEL,
  summary: {
    hit_sites: uniqueDomains(products),
    hit_pages: products.length,
    top20_flagship_sites: uniqueDomains(products.filter((item) => item.tier === "top20_flagship")),
    core_candidate_sites: uniqueDomains(products.filter((item) => item.tier === "core_candidate")),
    needs_rescan_sites: needsRescanSites,
    duplicate_groups: duplicateGroups.length,
    duplicate_items: duplicateGroups.reduce((sum, group) => sum + group.count, 0),
  },
  products,
};

await fs.mkdir(REPORT_DIR, { recursive: true });
await atomicWriteFile(OUT_JSON, JSON.stringify(payload, null, 2) + "\n", "utf8");
await atomicWriteFile(OUT_DUPLICATES, JSON.stringify({ generated_at: payload.generated_at, month: MONTH, groups: duplicateGroups }, null, 2) + "\n", "utf8");
await atomicWriteFile(OUT_HTML, buildHtml(payload), "utf8");
await renderDashboardScreenshots(OUT_HTML, REPORT_DIR);
console.log(`Dashboard written: ${OUT_HTML}`);
