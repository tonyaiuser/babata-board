#!/usr/bin/env node

import fs from "node:fs/promises";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  coveragePercent,
  dedupeAndMergeProducts,
  detectAccessIssue,
  exponentialBackoffMs,
  isClassificationCacheFresh,
  parseRetryAfter,
  pruneClassificationCache,
  scanQuality,
  shouldTryBrowserFallback,
  updateCircuitBreakerState,
  validateScanOptions,
} from "./single-page-monitor/lib/scan_helpers.mjs";
import { atomicWriteFile } from "./single-page-monitor/lib/file_utils.mjs";

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

const WORKSPACE = "/Users/tonyaiuser/.openclaw/workspace";
const TOP200_PATH = path.join(WORKSPACE, "sp_top200.csv");
const VALIDATION_PATH = path.join(WORKSPACE, "sp_flagship_validation_2026-07.json");
const CHROME_PATH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  args.set(process.argv[i], process.argv[i + 1]);
}

const LIMIT = Number(args.get("--limit") || 200);
const WORKERS = Number(args.get("--workers") || 6);
const TIMEOUT = Number(args.get("--timeout") || 30000);
const PAGE_TIMEOUT = Number(args.get("--page-timeout") || 12000);
const MIN_REQUEST_INTERVAL_MS = Number(args.get("--min-request-interval-ms") || 900);
const REQUEST_JITTER_MS = Number(args.get("--request-jitter-ms") || 500);
const BACKOFF_BASE_MS = Number(args.get("--backoff-base-ms") || 2000);
const BACKOFF_MAX_MS = Number(args.get("--backoff-max-ms") || 60000);
const MAX_CONSECUTIVE_FAILURES = Number(args.get("--max-consecutive-failures") || 3);
const CACHE_TTL_HOURS = Number(args.get("--cache-ttl-hours") || 18);
const CACHE_MAX_ENTRIES = Number(args.get("--cache-max-entries") || 50000);
const CACHE_JSON = args.get("--cache-json") || "";
const MAX_CREATED = Number(args.get("--max-created") || 80);
const MAX_UPDATED = Number(args.get("--max-updated") || 35);
const MAX_JSON_PAGES = Number(args.get("--max-json-pages") || 6);
const CHECKPOINT_EVERY = Math.max(1, Number(args.get("--checkpoint-every") || 10));
const FETCH_MODE = args.get("--fetch-mode") || "auto";
const WRITE_WORKSPACE = args.get("--write-workspace") !== "no";
const MONTH = args.get("--month") || "2026-06";
const OUT_HITS = args.get("--hits-csv") || "top200_single_page_june_hits.csv";
const OUT_SITES = args.get("--sites-csv") || "top200_single_page_june_sites.csv";
const OUT_MD = args.get("--md") || "top200_single_page_june_sites.md";
const PROGRESS_JSON = args.get("--progress-json") || "";
const UPDATE_VALIDATION = args.get("--update-validation") === "yes";
const MONTH_FILE = MONTH.replace(/[^\d-]/g, "");
const CLASSIFIER_VERSION = "2026-07-14-v3";

validateScanOptions({
  month: MONTH,
  limit: LIMIT,
  workers: WORKERS,
  max_json_pages: MAX_JSON_PAGES,
  max_created: MAX_CREATED,
  max_updated: MAX_UPDATED,
  checkpoint_every: CHECKPOINT_EVERY,
  timeout: TIMEOUT,
  page_timeout: PAGE_TIMEOUT,
  min_request_interval_ms: MIN_REQUEST_INTERVAL_MS,
  request_jitter_ms: REQUEST_JITTER_MS,
  backoff_base_ms: BACKOFF_BASE_MS,
  backoff_max_ms: BACKOFF_MAX_MS,
  max_consecutive_failures: MAX_CONSECUTIVE_FAILURES,
  cache_ttl_hours: CACHE_TTL_HOURS,
  cache_max_entries: CACHE_MAX_ENTRIES,
  fetch_mode: FETCH_MODE,
});

const CURRENT_FLAGSHIPS = new Set([
  "shimmer07.com",
  "charm-cart.com",
  "bebuyby.com",
  "britneed.com",
  "rouvenor.com",
  "copensunny.com",
  "loungon.com",
  "boniss.com",
  "londonnk.com",
]);
let TOP20_FLAGSHIPS = new Set();

const USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const leanRouteHandlers = new WeakMap();

async function enableLeanNavigation(page) {
  const handler = (route) =>
    route.request().isNavigationRequest() ? route.continue() : route.abort();
  leanRouteHandlers.set(page, handler);
  await page.route("**/*", handler);
}

async function withFullNavigation(page, callback) {
  const handler = leanRouteHandlers.get(page);
  if (handler) await page.unroute("**/*", handler).catch(() => {});
  try {
    return await callback();
  } finally {
    if (handler) await page.route("**/*", handler).catch(() => {});
  }
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

function csvEscape(value) {
  const text = String(value ?? "");
  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function toCsv(rows, fieldnames) {
  return [
    fieldnames.join(","),
    ...rows.map((row) => fieldnames.map((field) => csvEscape(row[field])).join(",")),
  ].join("\n") + "\n";
}

function xmlUnescape(text) {
  return text.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim();
}

function sitemapEntries(xml) {
  const entries = [];
  for (const match of xml.matchAll(/<url>([\s\S]*?)<\/url>/gi)) {
    const body = match[1];
    const loc = body.match(/<loc>([\s\S]*?)<\/loc>/i)?.[1];
    if (!loc) continue;
    const lastmod = body.match(/<lastmod>([\s\S]*?)<\/lastmod>/i)?.[1] || "";
    entries.push({ url: xmlUnescape(loc), lastmod: xmlUnescape(lastmod) });
  }
  return entries;
}

function locsFromXml(xml) {
  return [...xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)].map((match) => xmlUnescape(match[1]));
}

function decodeHtml(text) {
  return text
    .replace(/&ndash;/g, "-")
    .replace(/&mdash;/g, "-")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function extractTitle(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match) return "";
  return decodeHtml(match[1])
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\s+[–|-]\s+[^–|-]+$/, "")
    .trim();
}

function count(text, pattern) {
  return (text.match(pattern) || []).length;
}

function classifyHtml(url, html) {
  const lower = html.toLowerCase();
  const productClassCount = count(html, /product__/g);
  const mainProductCount = count(html, /MainProduct-/g);
  const productInfoCount = count(html, /ProductInfo-/g);
  const productFormComponentCount = count(lower, /product-form-component/g);
  const shopifyProductFormCount = count(lower, /shopify-product-form/g);
  const addToCartFormCount = count(lower, /add-to-cart-form/g);
  const quickAddCount = count(lower, /quick-add/g);
  const buyNowCount = count(lower, /buy now/g);
  const addToCartCount = count(lower, /add to cart/g);
  const specialOfferCount = count(lower, /special offer/g);
  const guaranteeCount = count(lower, /guarantee/g);
  const faqCount = count(lower, /faq/g);

  let standardScore = 0;
  if (html.includes("section-main-product.css")) standardScore += 5;
  if (mainProductCount) standardScore += 5;
  if (productInfoCount) standardScore += 4;
  if (html.includes("product__media-wrapper")) standardScore += 4;
  if (lower.includes("product-single")) standardScore += 3;
  if (lower.includes("productview")) standardScore += 3;
  if (html.includes("shopify-payment-button")) standardScore += 2;
  if (html.includes("product-form")) standardScore += 2;
  if (productFormComponentCount) standardScore += 4;
  if (shopifyProductFormCount) standardScore += 4;
  if (addToCartFormCount && productFormComponentCount) standardScore += 2;
  if (quickAddCount >= 3 && productFormComponentCount) standardScore += 2;
  standardScore += Math.min(5, Math.floor(productClassCount / 40));

  let landingScore = 0;
  if (specialOfferCount) landingScore += 3;
  if (guaranteeCount >= 2) landingScore += 2;
  if (faqCount >= 2) landingScore += 2;
  if (buyNowCount >= 5) landingScore += 2;
  if (lower.includes("limited time offer")) landingScore += 2;
  if (lower.includes("30-day free returns") || lower.includes("30 day free returns")) landingScore += 2;
  if (lower.includes("landing page")) landingScore += 2;
  if (["special offer", "guarantees", "faq"].every((term) => lower.includes(term))) landingScore += 2;
  if (lower.includes("buy more") && lower.includes("save")) landingScore += 1;

  let classification = "uncertain";
  let reason = `standard=${standardScore}, landing=${landingScore}`;
  if (standardScore >= 8) {
    classification = "default_product_template";
    reason = "standard Shopify product module markers";
  } else if (standardScore <= 4 && landingScore >= 7) {
    classification = "custom_single_page";
    reason = "landing markers without standard product module";
  } else if (standardScore <= 3 && productClassCount === 0 && landingScore >= 5) {
    classification = "custom_single_page";
    reason = "no product classes plus landing signals";
  }

  return {
    url,
    title: extractTitle(html),
    classification,
    reason,
    standard_score: standardScore,
    landing_score: landingScore,
    product_class_count: productClassCount,
    main_product_count: mainProductCount,
    product_info_count: productInfoCount,
    product_form_component_count: productFormComponentCount,
    shopify_product_form_count: shopifyProductFormCount,
    add_to_cart_form_count: addToCartFormCount,
    quick_add_count: quickAddCount,
    buy_now_count: buyNowCount,
    add_to_cart_count: addToCartCount,
    special_offer_count: specialOfferCount,
    guarantee_count: guaranteeCount,
    faq_count: faqCount,
    html_bytes: Buffer.byteLength(html),
  };
}

function monthMatch(value) {
  return String(value || "").startsWith(MONTH);
}

function dateBasis(product) {
  const created = product.created_at || "";
  const published = product.published_at || "";
  const updated = product.updated_at || "";
  const lastmod = product.lastmod || "";
  const strong = monthMatch(created) || monthMatch(published);
  if (strong) return "created_or_published_month";
  if (monthMatch(updated)) return "updated_month";
  if (monthMatch(lastmod)) return "sitemap_lastmod_month";
  return "";
}

function signalDate(product) {
  if (product.date_basis === "created_or_published_month") {
    return [product.created_at || "", product.published_at || ""].sort().pop() || "";
  }
  if (product.date_basis === "updated_month") return product.updated_at || "";
  if (product.date_basis === "sitemap_lastmod_month") return product.lastmod || "";
  return product.created_at || product.published_at || product.updated_at || product.lastmod || "";
}

function tierFor(site, basis) {
  if (TOP20_FLAGSHIPS.has(site.domain)) return "top20_flagship";
  if (!TOP20_FLAGSHIPS.size && CURRENT_FLAGSHIPS.has(site.domain)) return "fallback_flagship";
  return "core_candidate";
}

async function loadTop20Flagships() {
  try {
    const [similarwebCsv, domainsText] = await Promise.all([
      fs.readFile(path.join(WORKSPACE, "sp_similarweb_full.csv"), "utf8"),
      fs.readFile(path.join(WORKSPACE, "sp_domains.txt"), "utf8"),
    ]);
    const spSet = new Set(domainsText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean));
    const sites = parseCsv(similarwebCsv)
      .map((row) => ({
        domain: String(row.domain || "").replace(/^www\./, ""),
        visits: Number(row.monthly_visits || 0),
      }))
      .filter((site) => site.domain && spSet.has(site.domain) && site.visits > 0)
      .sort((a, b) => b.visits - a.visits)
      .slice(0, 20);
    TOP20_FLAGSHIPS = new Set(sites.map((site) => site.domain));
  } catch {
    TOP20_FLAGSHIPS = new Set();
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

async function responseHeaders(response) {
  try {
    if (typeof response.allHeaders === "function") return await response.allHeaders();
    if (typeof response.headers === "function") return await response.headers();
  } catch {}
  return {};
}

async function waitForRequestSlot(state) {
  const now = Date.now();
  const waitUntil = Math.max(Number(state.nextRequestAt || 0), Number(state.backoffUntil || 0));
  if (waitUntil > now) await sleep(waitUntil - now);
  state.requestCount = Number(state.requestCount || 0) + 1;
  state.nextRequestAt = Date.now() + MIN_REQUEST_INTERVAL_MS + Math.round(Math.random() * REQUEST_JITTER_MS);
}

function applyThrottleBackoff(state, result) {
  const issue = result.access_issue || detectAccessIssue(result);
  if (!["forbidden", "rate_limited", "bot_challenge", "server_error"].includes(issue)) return;
  state.throttleEvents = Number(state.throttleEvents || 0) + 1;
  state.throttleAttempts = Number(state.throttleAttempts || 0) + 1;
  const retryAfterMs = Number(result.retry_after_ms || 0);
  if (retryAfterMs > BACKOFF_MAX_MS) {
    state.circuitOpen = true;
    state.circuitReason = `${issue}:retry_after_${Math.round(retryAfterMs / 1000)}s`;
    return;
  }
  const delay = Math.max(
    retryAfterMs,
    exponentialBackoffMs(state.throttleAttempts, BACKOFF_BASE_MS, BACKOFF_MAX_MS)
  );
  state.backoffUntil = Math.max(Number(state.backoffUntil || 0), Date.now() + delay);
}

function recordFinalOutcome(state, result) {
  const issue = result.access_issue || detectAccessIssue(result);
  if (["forbidden", "rate_limited", "bot_challenge", "server_error", "network_error", "empty_response"].includes(issue)) {
    applyThrottleBackoff(state, result);
  }
  Object.assign(state, updateCircuitBreakerState(state, { ...result, access_issue: issue }, {
    maxConsecutiveFailures: MAX_CONSECUTIVE_FAILURES,
    maxRetryAfterMs: BACKOFF_MAX_MS,
  }));
}

function cacheKey(site, product) {
  return `${site.domain}|${String(product.handle || product.url || "").toLowerCase()}`;
}

function timeoutIssue(error, skipOnTimeout = false) {
  const text = `${error?.name || ""} ${error?.message || ""}`;
  return skipOnTimeout && /timeout/i.test(text) ? "page_timeout" : "network_error";
}

function accessIssue(result) {
  return result?.access_issue || detectAccessIssue(result);
}

async function loadClassificationCache() {
  const empty = { version: 1, classifier_version: CLASSIFIER_VERSION, entries: {} };
  if (!CACHE_JSON) return empty;
  try {
    const parsed = JSON.parse(await fs.readFile(CACHE_JSON, "utf8"));
    return {
      version: 1,
      classifier_version: CLASSIFIER_VERSION,
      entries: parsed?.entries && typeof parsed.entries === "object" ? parsed.entries : {},
    };
  } catch (error) {
    if (error?.code !== "ENOENT") console.warn(`Classification cache ignored: ${error.message}`);
    return empty;
  }
}

async function writeClassificationCache(cache) {
  if (!CACHE_JSON) return;
  cache.entries = pruneClassificationCache(cache.entries, CACHE_MAX_ENTRIES);
  cache.updated_at = new Date().toISOString();
  cache.classifier_version = CLASSIFIER_VERSION;
  await atomicWriteFile(CACHE_JSON, JSON.stringify(cache, null, 2) + "\n", "utf8");
}

function hitRow(site, product, evidence) {
  const tier = tierFor(site, product.date_basis);
  return {
    rank_index: site.rank_index,
    domain: site.domain,
    monthly_visits: site.monthly_visits,
    top_country: site.top_country,
    tier,
    url: product.url || evidence.url,
    handle: product.handle,
    product_title: product.product_title,
    page_title: evidence.title,
    date_basis: product.date_basis,
    signal_date: product.signal_date,
    created_at: product.created_at,
    published_at: product.published_at,
    updated_at: product.updated_at,
    lastmod: product.lastmod || "",
    classification: evidence.classification,
    reason: evidence.reason,
    standard_score: evidence.standard_score,
    landing_score: evidence.landing_score,
    product_class_count: evidence.product_class_count,
    product_form_component_count: evidence.product_form_component_count,
    shopify_product_form_count: evidence.shopify_product_form_count,
    add_to_cart_form_count: evidence.add_to_cart_form_count,
    quick_add_count: evidence.quick_add_count,
    buy_now_count: evidence.buy_now_count,
    add_to_cart_count: evidence.add_to_cart_count,
    special_offer_count: evidence.special_offer_count,
    guarantee_count: evidence.guarantee_count,
    faq_count: evidence.faq_count,
    html_bytes: evidence.html_bytes,
  };
}

async function fetchViaRequest(context, url, state, timeout = TIMEOUT, { skipOnTimeout = false } = {}) {
  try {
    await waitForRequestSlot(state);
    const response = await context.request.get(url, {
      timeout,
      failOnStatusCode: false,
    });
    const headers = await responseHeaders(response);
    const result = {
      status: response.status(),
      text: await response.text(),
      finalUrl: response.url(),
      transport: "request",
      error: "",
      retry_after_ms: parseRetryAfter(headers["retry-after"]),
    };
    await response.dispose().catch(() => {});
    return result;
  } catch (error) {
    return {
      status: 0,
      text: "",
      finalUrl: url,
      transport: "request",
      error: `${error.name}: ${error.message}`,
      access_issue: timeoutIssue(error, skipOnTimeout),
    };
  }
}

async function fetchViaPage(page, url, timeout = TIMEOUT, state, { skipOnTimeout = false } = {}) {
  await waitForRequestSlot(state);
  let navigationError = null;
  let response = await page.goto(url, { waitUntil: "domcontentloaded", timeout }).catch((error) => {
    navigationError = error;
    return null;
  });
  if (!response) {
    return {
      status: 0,
      text: "",
      finalUrl: url,
      transport: "browser",
      error: navigationError ? `${navigationError.name}: ${navigationError.message}` : "navigation_failed",
      access_issue: timeoutIssue(navigationError, skipOnTimeout),
    };
  }
  let text = "";
  try {
    text = await response.text();
  } catch {
    text = await page.content();
  }
  let headers = await responseHeaders(response);
  let result = {
    status: response.status(),
    text,
    finalUrl: page.url(),
    transport: "browser",
    error: "",
    retry_after_ms: parseRetryAfter(headers["retry-after"]),
  };
  if (detectAccessIssue(result) === "bot_challenge") {
    result = await withFullNavigation(page, async () => {
      await waitForRequestSlot(state);
      let challengeError = null;
      response = await page.goto(url, { waitUntil: "domcontentloaded", timeout }).catch((error) => {
        challengeError = error;
        return null;
      });
      await page.waitForTimeout(2500).catch(() => {});
      headers = response ? await responseHeaders(response) : {};
      return {
        status: response?.status() || 0,
        text: await page.content().catch(() => text),
        finalUrl: page.url(),
        transport: "browser",
        error: response ? "" : challengeError ? `${challengeError.name}: ${challengeError.message}` : "challenge_retry_failed",
        access_issue: response ? "" : timeoutIssue(challengeError, skipOnTimeout),
        retry_after_ms: parseRetryAfter(headers["retry-after"]),
      };
    });
  }
  return result;
}

async function fetchResource(
  context,
  page,
  url,
  state,
  { pageTimeout = TIMEOUT, requestTimeout = TIMEOUT, skipOnTimeout = false } = {}
) {
  if (FETCH_MODE === "page") {
    const result = await fetchViaPage(page, url, pageTimeout, state, { skipOnTimeout });
    return { ...result, access_issue: accessIssue(result), browser_fallback: false };
  }

  if (state.forceBrowser) {
    const result = await fetchViaPage(page, url, pageTimeout, state, { skipOnTimeout });
    return { ...result, access_issue: accessIssue(result), browser_fallback: true };
  }

  const direct = await fetchViaRequest(context, url, state, requestTimeout, { skipOnTimeout });
  const directIssue = accessIssue(direct);
  if (FETCH_MODE === "request" || !shouldTryBrowserFallback(directIssue)) {
    return { ...direct, access_issue: directIssue, browser_fallback: false };
  }

  state.directFailures = Number(state.directFailures || 0) + 1;
  applyThrottleBackoff(state, { ...direct, access_issue: directIssue });
  if (state.circuitOpen) {
    return { ...direct, access_issue: directIssue, browser_fallback: false };
  }
  if (["forbidden", "rate_limited", "bot_challenge"].includes(directIssue) || state.directFailures >= 2) {
    state.forceBrowser = true;
  }

  const fallback = await fetchViaPage(page, url, pageTimeout, state, { skipOnTimeout });
  return {
    ...fallback,
    access_issue: accessIssue(fallback),
    browser_fallback: true,
    request_error: direct.error || directIssue,
  };
}

async function discoverJuneProducts(context, page, site, fetchState) {
  const domain = site.domain;
  const products = [];
  const discoveryIssues = new Set();
  let browserFallbacks = 0;
  for (let pageNo = 1; pageNo <= MAX_JSON_PAGES; pageNo += 1) {
    const productsJson = await fetchResource(context, page, `https://${domain}/products.json?limit=250&page=${pageNo}`, fetchState);
    recordFinalOutcome(fetchState, productsJson);
    if (productsJson.browser_fallback) browserFallbacks += 1;
    if (productsJson.status !== 200 || productsJson.access_issue) {
      discoveryIssues.add(productsJson.access_issue || `products_json_http_${productsJson.status}`);
      break;
    }
    try {
      const data = JSON.parse(productsJson.text);
      const items = data.products || [];
      for (const product of items) {
        if (!product.handle) continue;
        products.push({
          url: `https://${domain}/products/${product.handle}`,
          handle: product.handle,
          product_title: product.title || "",
          created_at: product.created_at || "",
          published_at: product.published_at || "",
          updated_at: product.updated_at || "",
          source: "products_json",
        });
      }
      if (items.length < 250) break;
    } catch {
      // Some protected sites return an HTML challenge to JSON endpoints.
      discoveryIssues.add("invalid_products_json");
      break;
    }
    if (fetchState.circuitOpen) break;
  }

  const sitemapIndex = fetchState.circuitOpen
    ? null
    : await fetchResource(context, page, `https://${domain}/sitemap.xml`, fetchState);
  if (sitemapIndex) recordFinalOutcome(fetchState, sitemapIndex);
  if (sitemapIndex?.browser_fallback) browserFallbacks += 1;
  if (sitemapIndex?.status === 200 && !sitemapIndex.access_issue) {
    const locs = locsFromXml(sitemapIndex.text);
    const productSitemaps = locs.filter((url) => url.includes("sitemap_products")).slice(0, 3);
    for (const sitemapUrl of productSitemaps) {
      const productSitemap = await fetchResource(context, page, sitemapUrl, fetchState);
      recordFinalOutcome(fetchState, productSitemap);
      if (productSitemap.browser_fallback) browserFallbacks += 1;
      if (productSitemap.status !== 200 || productSitemap.access_issue) {
        discoveryIssues.add(productSitemap.access_issue || `product_sitemap_http_${productSitemap.status}`);
        continue;
      }
      for (const entry of sitemapEntries(productSitemap.text)) {
        if (!entry.url.includes("/products/")) continue;
        products.push({
          url: entry.url,
          handle: entry.url.split("/products/")[1]?.split(/[/?#]/)[0] || "",
          product_title: "",
          created_at: "",
          published_at: "",
          updated_at: "",
          lastmod: entry.lastmod,
          source: "sitemap",
        });
      }
      if (fetchState.circuitOpen) break;
    }
  } else if (sitemapIndex) {
    discoveryIssues.add(sitemapIndex.access_issue || `sitemap_http_${sitemapIndex.status}`);
  }

  const deduped = dedupeAndMergeProducts(products).map((product) => ({ ...product, date_basis: dateBasis(product) }));
  const byDateDesc = (a, b) =>
    String(signalDate(b)).localeCompare(String(signalDate(a)));
  const strongDiscovered = deduped
    .filter((product) => product.date_basis === "created_or_published_month")
    .sort(byDateDesc);
  const weakDiscovered = deduped
    .filter((product) => product.date_basis && product.date_basis !== "created_or_published_month")
    .sort(byDateDesc);
  const strong = strongDiscovered.slice(0, MAX_CREATED);
  const weak = weakDiscovered.slice(0, MAX_UPDATED);
  return {
    discovered_products: deduped.length,
    strong_candidates_discovered: strongDiscovered.length,
    weak_candidates_discovered: weakDiscovered.length,
    selected_strong_candidates: strong.length,
    selected_weak_candidates: weak.length,
    month_candidates: dedupeAndMergeProducts([...strong, ...weak]).map((product) => ({
      ...product,
      signal_date: signalDate(product),
    })),
    discovery_issue: deduped.length ? "" : [...discoveryIssues].filter(Boolean).join("+"),
    discovery_browser_fallbacks: browserFallbacks,
  };
}

async function scanSite(browser, site, classificationCache) {
  const context = await browser.newContext({ userAgent: USER_AGENT });
  const page = await context.newPage();
  try {
    await enableLeanNavigation(page);
    const fetchState = {
      forceBrowser: FETCH_MODE === "page",
      directFailures: 0,
      nextRequestAt: 0,
      backoffUntil: 0,
      requestCount: 0,
      throttleEvents: 0,
      throttleAttempts: 0,
      consecutiveFailures: 0,
      circuitOpen: false,
      circuitReason: "",
    };
    const {
      discovered_products,
      strong_candidates_discovered,
      weak_candidates_discovered,
      selected_strong_candidates,
      selected_weak_candidates,
      month_candidates,
      discovery_issue,
      discovery_browser_fallbacks,
    } =
      await discoverJuneProducts(context, page, site, fetchState);
    const hits = [];
    let sampled = 0;
    let sampledStrongCandidates = 0;
    let sampledWeakCandidates = 0;
    let cachedProducts = 0;
    let fetchFailures = 0;
    let blockedProducts = 0;
    let pageTimeouts = 0;
    let skippedProducts = 0;
    let browserFallbacks = discovery_browser_fallbacks;
    const failureReasons = new Map();
    for (let productIndex = 0; productIndex < month_candidates.length; productIndex += 1) {
      const product = month_candidates[productIndex];
      if (fetchState.circuitOpen) {
        skippedProducts = month_candidates.length - productIndex;
        break;
      }

      const key = cacheKey(site, product);
      const cached = classificationCache.entries[key];
      if (isClassificationCacheFresh(cached, product, {
        ttlHours: CACHE_TTL_HOURS,
        classifierVersion: CLASSIFIER_VERSION,
      })) {
        sampled += 1;
        if (product.date_basis === "created_or_published_month") sampledStrongCandidates += 1;
        else sampledWeakCandidates += 1;
        cachedProducts += 1;
        const evidence = { ...cached.evidence, url: product.url };
        if (evidence.classification === "custom_single_page") hits.push(hitRow(site, product, evidence));
        continue;
      }

      const response = await fetchResource(context, page, product.url, fetchState, {
        pageTimeout: PAGE_TIMEOUT,
        requestTimeout: PAGE_TIMEOUT,
        skipOnTimeout: true,
      });
      recordFinalOutcome(fetchState, response);
      if (response.browser_fallback) browserFallbacks += 1;
      if (response.status !== 200 || response.access_issue) {
        fetchFailures += 1;
        const reason = response.access_issue || `http_${response.status}`;
        failureReasons.set(reason, (failureReasons.get(reason) || 0) + 1);
        if (reason === "page_timeout") pageTimeouts += 1;
        if (["password_page", "login_required", "member_login", "forbidden", "rate_limited", "bot_challenge"].includes(reason)) {
          blockedProducts += 1;
        }
        continue;
      }
      sampled += 1;
      if (product.date_basis === "created_or_published_month") sampledStrongCandidates += 1;
      else sampledWeakCandidates += 1;
      const evidence = classifyHtml(response.finalUrl, response.text);
      classificationCache.entries[key] = {
        fetched_at: new Date().toISOString(),
        signal_date: product.signal_date || "",
        classifier_version: CLASSIFIER_VERSION,
        url: product.url,
        evidence,
      };
      if (evidence.classification === "custom_single_page") hits.push(hitRow(site, product, evidence));
    }
    const quality = scanQuality({
      candidates: month_candidates.length,
      sampled,
      blocked: (blockedProducts || fetchState.circuitOpen) ? 1 : 0,
      discoveryIssue: discovery_issue || (fetchState.circuitOpen ? fetchState.circuitReason : ""),
    });
    const status = hits.length
      ? "has_month_single_page"
      : quality === "blocked"
        ? "access_blocked"
        : ["partial", "incomplete"].includes(quality)
          ? "scan_incomplete"
          : "no_month_single_page_hit";
    return {
      rank_index: site.rank_index,
      domain: site.domain,
      monthly_visits: site.monthly_visits,
      top_country: site.top_country,
      status,
      scan_quality: quality,
      coverage_pct: coveragePercent(sampled, month_candidates.length),
      discovery_issue: discovery_issue || (fetchState.circuitOpen && !month_candidates.length ? fetchState.circuitReason : ""),
      discovered_products,
      strong_candidates_discovered,
      weak_candidates_discovered,
      selected_strong_candidates,
      selected_weak_candidates,
      sampled_strong_candidates: sampledStrongCandidates,
      sampled_weak_candidates: sampledWeakCandidates,
      month_candidates: month_candidates.length,
      sampled_products: sampled,
      cached_products: cachedProducts,
      fetch_failures: fetchFailures,
      blocked_products: blockedProducts,
      page_timeouts: pageTimeouts,
      skipped_products: skippedProducts,
      browser_fallbacks: browserFallbacks,
      network_requests: fetchState.requestCount,
      throttle_events: fetchState.throttleEvents,
      circuit_open: fetchState.circuitOpen ? "yes" : "no",
      circuit_reason: fetchState.circuitReason,
      failure_reasons: [...failureReasons].map(([reason, count]) => `${reason}:${count}`).join(";"),
      hit_count: hits.length,
      strong_hit_count: hits.filter((hit) => hit.date_basis === "created_or_published_month").length,
      weak_hit_count: hits.filter((hit) => hit.date_basis !== "created_or_published_month").length,
      first_hit_url: hits[0]?.url || "",
      first_hit_title: hits[0]?.page_title || "",
      strongest_basis: hits.some((h) => h.date_basis === "created_or_published_month")
        ? "created_or_published_month"
        : hits[0]?.date_basis || "",
      tier:
        hits.find((h) => h.tier === "top20_flagship")?.tier ||
        hits.find((h) => h.tier === "fallback_flagship")?.tier ||
        hits[0]?.tier ||
        "",
      hits,
    };
  } finally {
    await context.close().catch(() => {});
  }
}

async function writeOutputs(siteResults, hitRows) {
  const sortedSites = [...siteResults].sort((a, b) => Number(a.rank_index) - Number(b.rank_index));
  const sortedHits = [...hitRows].sort((a, b) => Number(a.rank_index) - Number(b.rank_index));

  const hitFields = [
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
    "classification",
    "reason",
    "standard_score",
    "landing_score",
    "product_class_count",
    "product_form_component_count",
    "shopify_product_form_count",
    "add_to_cart_form_count",
    "quick_add_count",
    "buy_now_count",
    "add_to_cart_count",
    "special_offer_count",
    "guarantee_count",
    "faq_count",
    "html_bytes",
  ];
  await atomicWriteFile(OUT_HITS, toCsv(sortedHits, hitFields), "utf8");

  const siteFields = [
    "rank_index",
    "domain",
    "monthly_visits",
    "top_country",
    "status",
    "scan_quality",
    "coverage_pct",
    "discovery_issue",
    "tier",
    "discovered_products",
    "strong_candidates_discovered",
    "weak_candidates_discovered",
    "selected_strong_candidates",
    "selected_weak_candidates",
    "sampled_strong_candidates",
    "sampled_weak_candidates",
    "month_candidates",
    "sampled_products",
    "cached_products",
    "fetch_failures",
    "blocked_products",
    "page_timeouts",
    "skipped_products",
    "browser_fallbacks",
    "network_requests",
    "throttle_events",
    "circuit_open",
    "circuit_reason",
    "failure_reasons",
    "hit_count",
    "strong_hit_count",
    "weak_hit_count",
    "strongest_basis",
    "first_hit_url",
    "first_hit_title",
  ];
  await atomicWriteFile(
    OUT_SITES,
    toCsv(
      sortedSites.map((site) => {
        const { hits, ...rest } = site;
        return rest;
      }),
      siteFields
    ),
    "utf8"
  );

  const hitSites = sortedSites.filter((site) => site.status === "has_month_single_page");
  const top20FlagshipSites = hitSites.filter((site) => site.tier === "top20_flagship");
  const fallbackFlagshipSites = hitSites.filter((site) => site.tier === "fallback_flagship");
  const coreCandidates = hitSites.filter((site) => site.tier === "core_candidate");

  const lines = [
    "# Top 200 SP Sites With Monthly Custom Single-Page Products",
    "",
    `Scanned at: ${new Date().toISOString()}`,
    `Month filter: ${MONTH}`,
    "",
    "## Summary",
    "",
    `- Sites scanned: ${sortedSites.length}`,
    `- Sites with ${MONTH} single-page evidence: ${hitSites.length}`,
    `- In dynamic SimilarWeb Top20 flagships: ${top20FlagshipSites.length}`,
    `- In fallback flagship list only: ${fallbackFlagshipSites.length}`,
    `- Core single-page candidates: ${coreCandidates.length}`,
    `- Hit pages: ${sortedHits.length}`,
    "",
    "## Sites",
    "",
    "| Top | Domain | Visits/mo | Tier | Basis | Hits | First LP |",
    "|---:|---|---:|---|---|---:|---|",
    ...hitSites.map((site) =>
      `| ${site.rank_index} | \`${site.domain}\` | ${site.monthly_visits} | ${site.tier} | ${site.strongest_basis} | ${site.hit_count} | ${site.first_hit_url} |`
    ),
  ];
  await atomicWriteFile(OUT_MD, `${lines.join("\n")}\n`, "utf8");

  if (WRITE_WORKSPACE) {
    const workspaceJson = path.join(WORKSPACE, `sp_single_page_core_candidates_${MONTH_FILE}.json`);
    const workspacePayload = {
    generated_at: new Date().toISOString(),
    source: "top200_june_single_page_scan.mjs",
    month: MONTH,
    rule: {
      single_page: "custom single-page classifier from landing markers after excluding standard Shopify product module and product-form-component templates",
      strong_month: `created_at or published_at starts with ${MONTH}`,
      weak_month: `updated_at or sitemap lastmod starts with ${MONTH}`,
      top20_flagship: "site is in the current dynamic SimilarWeb Top20 SP flagship set",
      core_candidate: "site has monthly custom single-page evidence but is not in the dynamic Top20 flagship set",
    },
    summary: {
      sites_scanned: sortedSites.length,
      hit_sites: hitSites.length,
      top20_flagship_sites: top20FlagshipSites.length,
      fallback_flagship_sites: fallbackFlagshipSites.length,
      core_candidates: coreCandidates.length,
      hit_pages: sortedHits.length,
    },
    sites: hitSites.map((site) => ({
      rank_index: Number(site.rank_index),
      domain: site.domain,
      monthly_visits: Number(site.monthly_visits || 0),
      top_country: site.top_country,
      tier: site.tier,
      strongest_basis: site.strongest_basis,
      hit_count: site.hit_count,
      first_hit_url: site.first_hit_url,
      first_hit_title: site.first_hit_title,
      hits: sortedHits
        .filter((hit) => hit.domain === site.domain)
        .map((hit) => ({
          url: hit.url,
          handle: hit.handle,
          product_title: hit.product_title,
          page_title: hit.page_title,
          date_basis: hit.date_basis,
          signal_date: hit.signal_date,
          created_at: hit.created_at,
          published_at: hit.published_at,
          updated_at: hit.updated_at,
          lastmod: hit.lastmod,
          standard_score: hit.standard_score,
          landing_score: hit.landing_score,
          product_form_component_count: hit.product_form_component_count,
          shopify_product_form_count: hit.shopify_product_form_count,
          add_to_cart_form_count: hit.add_to_cart_form_count,
          quick_add_count: hit.quick_add_count,
          buy_now_count: hit.buy_now_count,
          add_to_cart_count: hit.add_to_cart_count,
        })),
    })),
    };
    await atomicWriteFile(workspaceJson, JSON.stringify(workspacePayload, null, 2) + "\n", "utf8");

    await atomicWriteFile(
      path.join(WORKSPACE, `sp_top20_single_page_sites_${MONTH_FILE}.txt`),
      top20FlagshipSites.map((site) => site.domain).join("\n") + (top20FlagshipSites.length ? "\n" : ""),
      "utf8"
    );
    await atomicWriteFile(
      path.join(WORKSPACE, `sp_core_sites_single_page_${MONTH_FILE}.txt`),
      coreCandidates.map((site) => site.domain).join("\n") + (coreCandidates.length ? "\n" : ""),
      "utf8"
    );
  }

  if (UPDATE_VALIDATION) {
    await updateValidationJson(coreCandidates, sortedHits);
  }
}

async function updateValidationJson(coreCandidates, sortedHits) {
  let raw;
  try {
    raw = JSON.parse(await fs.readFile(VALIDATION_PATH, "utf8"));
  } catch {
    return;
  }
  const backup = `${VALIDATION_PATH}.bak_single_page_${new Date().toISOString().replace(/[-:T.Z]/g, "").slice(0, 14)}`;
  await atomicWriteFile(backup, JSON.stringify(raw, null, 2) + "\n", "utf8");
  const existingDomains = new Set((raw.candidate_results || []).map((row) => row.domain));
  const additions = coreCandidates
    .filter((site) => !existingDomains.has(site.domain))
    .map((site) => {
      const firstHit = sortedHits.find((hit) => hit.domain === site.domain) || {};
      return {
        domain: site.domain,
        country: site.top_country,
        visits: Number(site.monthly_visits || 0),
        fb_count: -1,
        candidate_type: site.tier,
        candidate_reason: `${MONTH} custom single-page product evidence`,
        single_page_signal: {
          month: MONTH,
          strongest_basis: site.strongest_basis,
          hit_count: site.hit_count,
          url: firstHit.url || site.first_hit_url,
          title: firstHit.page_title || site.first_hit_title,
          signal_date: firstHit.signal_date || "",
          created_at: firstHit.created_at || "",
          published_at: firstHit.published_at || "",
          updated_at: firstHit.updated_at || "",
          lastmod: firstHit.lastmod || "",
        },
        source: "top200_june_single_page_scan.mjs",
      };
    });
  raw.candidate_results = [...(raw.candidate_results || []), ...additions].sort(
    (a, b) => Number(b.visits || 0) - Number(a.visits || 0)
  );
  raw.single_page_candidate_source = {
    updated_at: new Date().toISOString(),
    month: MONTH,
    added_candidates: additions.length,
    backup,
  };
  await atomicWriteFile(VALIDATION_PATH, JSON.stringify(raw, null, 2) + "\n", "utf8");
}

await loadTop20Flagships();
console.log(
  `Dynamic Top20 flagships: ${TOP20_FLAGSHIPS.size ? [...TOP20_FLAGSHIPS].slice(0, 5).join(", ") + "..." : "fallback list only"}`
);

const topCsv = await fs.readFile(TOP200_PATH, "utf8");
const sites = parseCsv(topCsv)
  .slice(0, LIMIT)
  .map((row, index) => ({
    ...row,
    rank_index: index + 1,
    domain: row.domain.replace(/^www\./, ""),
  }));
const classificationCache = await loadClassificationCache();

console.log(
  `Scanning ${sites.length} sites for ${MONTH} custom single pages | workers=${WORKERS} pace=${MIN_REQUEST_INTERVAL_MS}+0-${REQUEST_JITTER_MS}ms cache=${CACHE_JSON ? `${CACHE_TTL_HOURS}h` : "off"}`
);
const browser = await chromium.launch({ headless: true, executablePath: CHROME_PATH });
const siteResults = [];
const hitRows = [];
let cursor = 0;
let completed = 0;
let checkpointQueue = Promise.resolve();
let progressQueue = Promise.resolve();
const scanStartedAt = new Date().toISOString();

function queueCheckpoint() {
  const siteSnapshot = [...siteResults];
  const hitSnapshot = [...hitRows];
  checkpointQueue = checkpointQueue.then(async () => {
    await writeOutputs(siteSnapshot, hitSnapshot);
    await writeClassificationCache(classificationCache);
  });
  return checkpointQueue;
}

function queueProgress(lastResult) {
  if (!PROGRESS_JSON) return Promise.resolve();
  const payload = {
    started_at: scanStartedAt,
    updated_at: new Date().toISOString(),
    month: MONTH,
    total_sites: sites.length,
    completed_sites: completed,
    hit_pages: hitRows.length,
    last_domain: lastResult.domain,
    last_status: lastResult.status,
  };
  progressQueue = progressQueue.then(() =>
    atomicWriteFile(PROGRESS_JSON, JSON.stringify(payload, null, 2) + "\n", "utf8")
  );
  return progressQueue;
}

async function worker() {
  while (cursor < sites.length) {
    const site = sites[cursor++];
    const result = await scanSite(browser, site, classificationCache).catch((error) => ({
      rank_index: site.rank_index,
      domain: site.domain,
      monthly_visits: site.monthly_visits,
      top_country: site.top_country,
      status: "scan_error",
      tier: "",
      discovered_products: 0,
      strong_candidates_discovered: 0,
      weak_candidates_discovered: 0,
      selected_strong_candidates: 0,
      selected_weak_candidates: 0,
      sampled_strong_candidates: 0,
      sampled_weak_candidates: 0,
      month_candidates: 0,
      sampled_products: 0,
      cached_products: 0,
      scan_quality: "error",
      coverage_pct: 0,
      discovery_issue: "",
      fetch_failures: 0,
      blocked_products: 0,
      page_timeouts: 0,
      skipped_products: 0,
      browser_fallbacks: 0,
      network_requests: 0,
      throttle_events: 0,
      circuit_open: "no",
      circuit_reason: "",
      failure_reasons: "",
      hit_count: 0,
      strong_hit_count: 0,
      weak_hit_count: 0,
      strongest_basis: "",
      first_hit_url: "",
      first_hit_title: "",
      error: `${error.name}: ${error.message}`,
      hits: [],
    }));
    siteResults.push(result);
    for (const hit of result.hits || []) hitRows.push(hit);
    completed += 1;
    console.log(
      `${completed}/${sites.length} #${result.rank_index} ${result.domain} ${result.status} quality=${result.scan_quality} month=${result.month_candidates} sampled=${result.sampled_products} cached=${result.cached_products} requests=${result.network_requests} throttle=${result.throttle_events} circuit=${result.circuit_open} failures=${result.fetch_failures} hits=${result.hit_count}`
    );
    await queueProgress(result);
    if (completed % CHECKPOINT_EVERY === 0) await queueCheckpoint();
  }
}

try {
  await Promise.all(Array.from({ length: WORKERS }, () => worker()));
  await progressQueue;
  await checkpointQueue;
  await writeOutputs(siteResults, hitRows);
  await writeClassificationCache(classificationCache);
} finally {
  await browser.close().catch(() => {});
}
console.log(`Done. Hit sites=${new Set(hitRows.map((row) => row.domain)).size} hit pages=${hitRows.length}`);
