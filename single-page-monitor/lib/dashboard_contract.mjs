import crypto from "node:crypto";
import { constants as FS_CONSTANTS } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";

export const DATA_CONTRACT_VERSION = 1;
export const REQUIRED_HIT_COLUMNS = ["domain", "url", "handle"];
export const REQUIRED_SITE_COLUMNS = [
  "domain", "status", "hit_count", "scan_quality", "coverage_pct", "month_candidates", "sampled_products",
];
export const SOURCE_MIN_PLANNED_COVERAGE_PCT = 95;
export const SOURCE_MIN_USABLE_COVERAGE_PCT = 90;
export const SOURCE_MIN_PLANNED_SITES = 200;
export const SOURCE_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
export const SOURCE_MAX_LATEST_AGE_MS = 36 * 60 * 60 * 1000;
export const SOURCE_MAX_AGE_MONTHS = 24;

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const USABLE_QUALITIES = new Set(["complete", "no_candidates"]);
const KNOWN_QUALITIES = new Set(["complete", "no_candidates", "partial", "incomplete", "blocked", "error"]);

export function isMonth(value) {
  return /^\d{4}-(0[1-9]|1[0-2])$/.test(String(value || ""));
}

export function assertMonth(value, label = "month") {
  if (!isMonth(value)) throw new Error(`${label} must use YYYY-MM`);
  return String(value);
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sameStatIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.uid === right.uid && left.nlink === right.nlink && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function assertSafeRegularStat(stat, file) {
  if (!stat.isFile()) throw new Error(`${file} is not a regular file`);
  if (stat.isSymbolicLink()) throw new Error(`${file} must not be a symbolic link`);
  if (stat.nlink !== 1n) throw new Error(`${file} has unsafe hard-link count ${stat.nlink}`);
  if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) {
    throw new Error(`${file} is not owned by the current uid`);
  }
}

export async function readSafeFileSnapshot(file, { testAfterOpen = null } = {}) {
  let beforePath;
  try {
    beforePath = await fs.lstat(file, { bigint: true });
  } catch (error) {
    const wrapped = new Error(`${file} is missing or unreadable: ${error.message}`);
    wrapped.code = error?.code;
    throw wrapped;
  }
  assertSafeRegularStat(beforePath, file);
  const noFollow = FS_CONSTANTS.O_NOFOLLOW || 0;
  let handle;
  try {
    handle = await fs.open(file, FS_CONSTANTS.O_RDONLY | noFollow);
  } catch (error) {
    throw new Error(`${file} cannot be opened safely: ${error.message}`);
  }
  try {
    const beforeRead = await handle.stat({ bigint: true });
    assertSafeRegularStat(beforeRead, file);
    if (!sameStatIdentity(beforePath, beforeRead)) throw new Error(`${file} changed while it was opened`);
    if (testAfterOpen) await testAfterOpen({ file, handle, stat: beforeRead });
    const buffer = await handle.readFile();
    const afterRead = await handle.stat({ bigint: true });
    const afterPath = await fs.lstat(file, { bigint: true });
    assertSafeRegularStat(afterRead, file);
    assertSafeRegularStat(afterPath, file);
    if (!sameStatIdentity(beforeRead, afterRead) || !sameStatIdentity(beforeRead, afterPath)) {
      throw new Error(`${file} changed while it was read`);
    }
    if (BigInt(buffer.length) !== beforeRead.size) throw new Error(`${file} size changed while it was read`);
    return Object.freeze({
      file,
      buffer,
      sha256: sha256(buffer),
      bytes: buffer.length,
      identity: Object.freeze({
        dev: String(beforeRead.dev), ino: String(beforeRead.ino), mode: String(beforeRead.mode),
        uid: String(beforeRead.uid), nlink: String(beforeRead.nlink), size: String(beforeRead.size),
        mtimeNs: String(beforeRead.mtimeNs), ctimeNs: String(beforeRead.ctimeNs),
      }),
    });
  } finally {
    await handle.close();
  }
}

export async function assertSnapshotPathIdentity(snapshot) {
  const stat = await fs.lstat(snapshot.file, { bigint: true });
  assertSafeRegularStat(stat, snapshot.file);
  const current = {
    dev: String(stat.dev), ino: String(stat.ino), mode: String(stat.mode), uid: String(stat.uid),
    nlink: String(stat.nlink), size: String(stat.size), mtimeNs: String(stat.mtimeNs), ctimeNs: String(stat.ctimeNs),
  };
  if (!sameJson(current, snapshot.identity)) throw new Error(`${snapshot.file} no longer matches its consumed snapshot`);
}

export function decodeUtf8Fatal(buffer, label) {
  try {
    return UTF8_DECODER.decode(buffer);
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8: ${error.message}`);
  }
}

// JSON.parse silently accepts duplicate keys. This parser implements the JSON
// grammar while rejecting duplicates at every object depth.
export function parseJsonStrict(text, label = "JSON") {
  let index = 0;
  const fail = (message) => { throw new Error(`${label} ${message} at character ${index + 1}`); };
  const whitespace = () => { while (/[ \t\r\n]/.test(text[index] || "")) index += 1; };
  const string = () => {
    if (text[index] !== '"') fail("expected a string");
    const start = index++;
    let escaped = false;
    while (index < text.length) {
      const ch = text[index++];
      if (!escaped && ch === '"') {
        try { return JSON.parse(text.slice(start, index)); }
        catch { fail("contains an invalid string"); }
      }
      if (!escaped && ch.charCodeAt(0) < 0x20) fail("contains a control character");
      if (!escaped && ch === "\\") escaped = true;
      else escaped = false;
    }
    fail("has an unterminated string");
  };
  const value = () => {
    whitespace();
    const ch = text[index];
    if (ch === '"') return string();
    if (ch === "{") {
      index += 1;
      const object = {};
      const keys = new Set();
      whitespace();
      if (text[index] === "}") { index += 1; return object; }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) fail(`contains duplicate key ${JSON.stringify(key)}`);
        keys.add(key);
        whitespace();
        if (text[index++] !== ":") fail("expected ':'");
        Object.defineProperty(object, key, { value: value(), enumerable: true, writable: true, configurable: true });
        whitespace();
        const delimiter = text[index++];
        if (delimiter === "}") return object;
        if (delimiter !== ",") fail("expected ',' or '}'");
      }
    }
    if (ch === "[") {
      index += 1;
      const array = [];
      whitespace();
      if (text[index] === "]") { index += 1; return array; }
      while (true) {
        array.push(value());
        whitespace();
        const delimiter = text[index++];
        if (delimiter === "]") return array;
        if (delimiter !== ",") fail("expected ',' or ']'");
      }
    }
    for (const [token, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(token, index)) { index += token.length; return parsed; }
    }
    const number = text.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (number) {
      index += number[0].length;
      const parsed = Number(number[0]);
      if (!Number.isFinite(parsed)) fail("contains a non-finite number");
      return parsed;
    }
    fail("contains an invalid value");
  };
  const parsed = value();
  whitespace();
  if (index !== text.length) fail("has trailing content");
  return parsed;
}

export async function readJsonSnapshot(file, label = path.basename(file), options = {}) {
  const snapshot = await readSafeFileSnapshot(file, options);
  const text = decodeUtf8Fatal(snapshot.buffer, label);
  return Object.freeze({ ...snapshot, text, value: parseJsonStrict(text, label) });
}

export function parseCsvStrict(text, label = "CSV") {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;
  let afterQuote = false;
  let fieldStarted = false;
  const pushField = () => { row.push(value); value = ""; fieldStarted = false; afterQuote = false; };
  const pushRow = () => { pushField(); rows.push(row); row = []; };
  for (let index = 0; index < text.length; index += 1) {
    const ch = text[index];
    const next = text[index + 1];
    if (quoted) {
      if (ch === '"' && next === '"') { value += '"'; index += 1; }
      else if (ch === '"') { quoted = false; afterQuote = true; }
      else value += ch;
    } else if (afterQuote) {
      if (ch === ",") pushField();
      else if (ch === "\n") pushRow();
      else if (ch === "\r" && next === "\n") continue;
      else throw new Error(`${label} has content after a closing quote at character ${index + 1}`);
    } else if (ch === '"') {
      if (fieldStarted) throw new Error(`${label} has an unexpected quote at character ${index + 1}`);
      quoted = true;
      fieldStarted = true;
    } else if (ch === ",") pushField();
    else if (ch === "\n") pushRow();
    else if (ch === "\r" && next === "\n") continue;
    else if (ch === "\r") throw new Error(`${label} has a stray carriage return at character ${index + 1}`);
    else { value += ch; fieldStarted = true; }
  }
  if (quoted) throw new Error(`${label} has an unterminated quoted field`);
  if (value.length || row.length || fieldStarted || afterQuote) pushRow();
  const headers = rows.shift();
  if (!headers?.length || headers.every((header) => !header)) throw new Error(`${label} has no header row`);
  if (headers.some((header, index) => !header || headers.indexOf(header) !== index)) {
    throw new Error(`${label} has duplicate or empty headers`);
  }
  const records = [];
  for (const [rowIndex, columns] of rows.entries()) {
    if (columns.every((column) => column === "")) continue;
    if (columns.length !== headers.length) {
      throw new Error(`${label} row ${rowIndex + 2} has ${columns.length} columns; expected ${headers.length}`);
    }
    records.push(Object.fromEntries(headers.map((header, columnIndex) => [header, columns[columnIndex]])));
  }
  return Object.freeze({ headers: Object.freeze(headers), records: Object.freeze(records) });
}

export async function readCsvSnapshot(file, requiredColumns, options = {}) {
  const snapshot = await readSafeFileSnapshot(file, options);
  const text = decodeUtf8Fatal(snapshot.buffer, path.basename(file));
  const parsed = parseCsvStrict(text, path.basename(file));
  for (const column of requiredColumns) {
    if (!parsed.headers.includes(column)) throw new Error(`${path.basename(file)} is missing required column ${column}`);
  }
  return Object.freeze({ ...snapshot, text, headers: parsed.headers, records: parsed.records, rows: parsed.records.length });
}

function shanghaiParts(date) {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit" })
    .formatToParts(date);
  return Object.fromEntries(parts.map((part) => [part.type, part.value]));
}

function shanghaiMonth(date) {
  const map = shanghaiParts(date);
  return `${map.year}-${map.month}`;
}

export function shanghaiYmd(date = new Date()) {
  if (!(date instanceof Date) || !Number.isFinite(date.getTime())) throw new Error("Shanghai date is invalid");
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(date);
  const map = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${map.year}-${map.month}-${map.day}`;
}

function monthIndex(month) {
  const [year, value] = month.split("-").map(Number);
  return year * 12 + value - 1;
}

export function assertSourceTime(sourceMonth, value, { now = new Date() } = {}) {
  assertMonth(sourceMonth, "source_month");
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error("source_generated_at must be a complete UTC ISO timestamp");
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) throw new Error("source_generated_at is invalid");
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("contract validation clock is invalid");
  if (parsed.getTime() > now.getTime() + SOURCE_MAX_FUTURE_SKEW_MS) throw new Error("source_generated_at is in the future");
  const asOfMonth = shanghaiMonth(parsed);
  const age = monthIndex(asOfMonth) - monthIndex(sourceMonth);
  if (age < 0) throw new Error("source_month is after source_generated_at in Asia/Shanghai");
  if (age > SOURCE_MAX_AGE_MONTHS) throw new Error(`source_month is more than ${SOURCE_MAX_AGE_MONTHS} months older than source_generated_at`);
  return value;
}

export function latestSourceAgeSeconds(sourceMonth, value, { now = new Date() } = {}) {
  assertSourceTime(sourceMonth, value, { now });
  const ageMs = now.getTime() - new Date(value).getTime();
  if (ageMs > SOURCE_MAX_LATEST_AGE_MS) throw new Error("latest source_generated_at is older than 36 hours");
  return Math.floor(Math.max(0, ageMs) / 1000);
}

export function assertLatestBuildSourceFresh(sourceMonth, value, { now = new Date() } = {}) {
  if (assertMonth(sourceMonth, "latest source_month") !== shanghaiMonth(now)) {
    throw new Error("latest dashboard source_month must be the current Asia/Shanghai month");
  }
  return latestSourceAgeSeconds(sourceMonth, value, { now });
}

export function sourceAgeAtGeneratedAtSeconds(sourceMonth, sourceGeneratedAt, generatedAt) {
  if (typeof generatedAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(generatedAt)) {
    throw new Error("dashboard manifest generated_at must be a complete UTC ISO timestamp");
  }
  const generated = new Date(generatedAt);
  if (!Number.isFinite(generated.getTime()) || generated.toISOString() !== generatedAt) {
    throw new Error("dashboard manifest generated_at is invalid");
  }
  assertSourceTime(sourceMonth, sourceGeneratedAt, { now: generated });
  const ageMs = generated.getTime() - new Date(sourceGeneratedAt).getTime();
  if (ageMs < 0) throw new Error("dashboard manifest generated_at is before its trusted source");
  const seconds = Math.floor(ageMs / 1000);
  if (!Number.isSafeInteger(seconds) || seconds < 0) throw new Error("dashboard source age is invalid");
  return seconds;
}

function strictNonNegativeInteger(value, label, { positive = false } = {}) {
  if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    throw new Error(`${label} must be a ${positive ? "positive" : "non-negative"} safe integer`);
  }
  return value;
}

export function canonicalDomain(value, label = "domain") {
  const raw = String(value ?? "");
  const normalized = raw.trim().toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  if (!normalized || /[\s/?#@]/.test(normalized) || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(normalized)) {
    throw new Error(`${label} must be a canonical hostname`);
  }
  return normalized;
}

export function canonicalProductHandle(value, label = "product handle") {
  const raw = String(value ?? "");
  if (!raw || /[\\/?#:[\]@!$&'()*+,;=|\s\u0000-\u001f\u007f]/.test(raw)) {
    throw new Error(`${label} is invalid`);
  }
  let decoded;
  try { decoded = decodeURIComponent(raw); }
  catch { throw new Error(`${label} has invalid encoding`); }
  if (!decoded || /[%\\/?#:[\]@!$&'()*+,;=|\s\u0000-\u001f\u007f]/.test(decoded)) {
    throw new Error(`${label} is invalid`);
  }
  return decoded.normalize("NFC").toLowerCase();
}

export function canonicalProductKey({ domain, handle }) {
  return `${canonicalDomain(domain, "product domain")}|${canonicalProductHandle(handle)}`;
}

export function canonicalProductJsonUrl({ domain, handle }) {
  const canonicalDomainValue = canonicalDomain(domain, "product domain");
  const canonicalHandle = canonicalProductHandle(handle);
  return `https://${canonicalDomainValue}/products/${encodeURIComponent(canonicalHandle)}.json`;
}

export function canonicalizeStateProducts(products) {
  if (!products || typeof products !== "object" || Array.isArray(products)) {
    throw new Error("state.json products must be an object");
  }
  const canonical = {};
  for (const [legacyKey, product] of Object.entries(products)) {
    if (!product || typeof product !== "object" || Array.isArray(product)) {
      throw new Error(`state product ${JSON.stringify(legacyKey)} must be an object`);
    }
    const separator = legacyKey.indexOf("|");
    if (separator <= 0 || !product.domain || !product.handle) {
      throw new Error(`legacy state product ${JSON.stringify(legacyKey)} has no provable domain/handle identity`);
    }
    const fallbackDomain = legacyKey.slice(0, separator);
    const fallbackHandle = legacyKey.slice(separator + 1);
    const domain = canonicalDomain(product.domain, "state product domain");
    const handle = canonicalProductHandle(product.handle, "state product handle");
    const key = canonicalProductKey({ domain, handle });
    const legacyIdentity = canonicalProductKey({ domain: fallbackDomain, handle: fallbackHandle });
    if (legacyIdentity !== key) {
      throw new Error(`legacy state product key ${JSON.stringify(legacyKey)} does not match its record identity`);
    }
    if (Object.hasOwn(canonical, key)) {
      throw new Error(`legacy state product identities collide at ${key}`);
    }
    canonical[key] = { ...product, domain, handle };
  }
  return canonical;
}

function strictCoverage(value, site) {
  if (typeof value === "string" && !value.trim()) {
    throw new Error(`site ${site} coverage_pct must be finite and in [0, 100]`);
  }
  const coverage = Number(value);
  if (!Number.isFinite(coverage) || coverage < 0 || coverage > 100) {
    throw new Error(`site ${site} coverage_pct must be finite and in [0, 100]`);
  }
  return coverage;
}

function strictSiteInteger(value, label) {
  if (typeof value === "string" && !value.trim()) throw new Error(`${label} must be a non-negative safe integer`);
  return strictNonNegativeInteger(Number(value), label);
}

function expectedScanQuality({ candidates, sampled, blocked }) {
  if (!candidates) return blocked ? "blocked" : "no_candidates";
  if (!sampled) return blocked ? "blocked" : "incomplete";
  return sampled / candidates >= 0.9 ? "complete" : "partial";
}

function canonicalPlan(plan) {
  if (!plan || typeof plan !== "object" || !Array.isArray(plan.domains)) throw new Error("scan plan is missing canonical domains");
  if (plan.domains.length !== SOURCE_MIN_PLANNED_SITES) {
    throw new Error(`scan plan must contain exactly canonical ${SOURCE_MIN_PLANNED_SITES} domains`);
  }
  const domains = plan.domains.map((domain, index) => canonicalDomain(domain, `scan plan domain ${index + 1}`));
  if (new Set(domains).size !== domains.length) throw new Error("scan plan has duplicate canonical domains");
  const canonicalSha = sha256(`${domains.join("\n")}\n`);
  if (plan.domains_sha256 !== canonicalSha) throw new Error("scan plan canonical domain hash does not match");
  if (!plan.input || typeof plan.input !== "object" || typeof plan.input.sha256 !== "string") {
    throw new Error("scan plan is missing its input snapshot");
  }
  return { domains, domains_sha256: canonicalSha, input: plan.input };
}

export function scanPlanFromSnapshot(snapshot) {
  const domains = snapshot.records.slice(0, SOURCE_MIN_PLANNED_SITES)
    .map((row, index) => canonicalDomain(row.domain, `scan plan domain ${index + 1}`));
  if (domains.length !== SOURCE_MIN_PLANNED_SITES) {
    throw new Error(`scan plan input must contain at least canonical ${SOURCE_MIN_PLANNED_SITES} domains`);
  }
  if (new Set(domains).size !== domains.length) throw new Error("scan plan input has duplicate canonical domains");
  return Object.freeze({
    version: 1,
    domains: Object.freeze(domains),
    domains_sha256: sha256(`${domains.join("\n")}\n`),
    input: Object.freeze(inputMetadata(snapshot)),
  });
}

function validateHitsAgainstSites(hits, siteDomains) {
  if (!Array.isArray(hits)) throw new Error("hits must be an array");
  const hitCounts = new Map();
  const hitUrls = new Set();
  const products = new Set();
  for (const hit of hits) {
    if (!hit || typeof hit !== "object") throw new Error("each hit must be an object");
    const domain = canonicalDomain(hit.domain, "hit domain");
    if (!siteDomains.has(domain)) throw new Error(`hit domain ${domain} is not in sites.csv`);
    const rawUrl = String(hit.url || "");
    if (!rawUrl || /[\\\u0000-\u001f\u007f]/.test(rawUrl)) throw new Error(`hit URL for ${domain} is invalid`);
    let url;
    try { url = new URL(rawUrl); } catch { throw new Error(`hit URL for ${domain} is invalid`); }
    if (!/^https?:$/.test(url.protocol) || canonicalDomain(url.hostname, "hit URL hostname") !== domain) {
      throw new Error(`hit URL domain does not match ${domain}`);
    }
    const pathname = url.pathname;
    const pathSegments = pathname.split("/").slice(1);
    if (pathSegments.at(-1) === "") pathSegments.pop();
    if (!pathSegments.length || pathSegments.some((segment) => !segment)) {
      throw new Error(`hit URL for ${domain} must contain one non-empty /products/<handle> path`);
    }
    const productIndexes = pathSegments
      .map((segment, index) => segment.toLowerCase() === "products" ? index : -1)
      .filter((index) => index >= 0);
    if (productIndexes.length !== 1 || productIndexes[0] !== pathSegments.length - 2) {
      throw new Error(`hit URL for ${domain} must contain one non-empty /products/<handle> path with no suffix`);
    }
    const rawPathHandle = pathSegments.at(-1);
    const rawDeclaredHandle = String(hit.handle ?? "");
    if (!rawDeclaredHandle) throw new Error(`hit handle for ${domain} is required`);
    const pathHandle = canonicalProductHandle(rawPathHandle, `hit URL product handle for ${domain}`);
    const declaredHandle = canonicalProductHandle(rawDeclaredHandle, `hit handle for ${domain}`);
    if (declaredHandle !== pathHandle) throw new Error(`hit handle does not match its URL for ${domain}`);
    const canonicalPath = [...pathSegments.slice(0, -1), pathHandle].join("/");
    const canonicalUrl = `${url.protocol.toLowerCase()}//${domain}/${canonicalPath}`;
    if (hitUrls.has(canonicalUrl)) throw new Error(`duplicate hit URL ${canonicalUrl}`);
    hitUrls.add(canonicalUrl);
    const productKey = canonicalProductKey({ domain, handle: declaredHandle });
    if (products.has(productKey)) throw new Error(`duplicate hit product ${productKey}`);
    products.add(productKey);
    hitCounts.set(domain, (hitCounts.get(domain) || 0) + 1);
  }
  return hitCounts;
}

function expectedSiteStatus(quality, hitCount) {
  if (hitCount > 0) return "has_month_single_page";
  if (quality === "blocked") return "access_blocked";
  if (["partial", "incomplete"].includes(quality)) return "scan_incomplete";
  if (quality === "error") return "scan_error";
  return "no_month_single_page_hit";
}

export function canonicalSourceHealth({ plannedSites, sites, hits = [], scanPlan = null }) {
  strictNonNegativeInteger(plannedSites, "planned_sites", { positive: true });
  if (plannedSites !== SOURCE_MIN_PLANNED_SITES) {
    throw new Error(`planned_sites must equal canonical ${SOURCE_MIN_PLANNED_SITES}`);
  }
  if (!Array.isArray(sites)) throw new Error("sites must be an array");
  const totalSites = sites.length;
  if (totalSites !== plannedSites) throw new Error("total_sites must equal planned_sites");
  const plan = scanPlan ? canonicalPlan(scanPlan) : null;
  const qualityCounts = Object.fromEntries([...KNOWN_QUALITIES].map((quality) => [quality, 0]));
  const domains = new Set();
  const sitesByDomain = new Map();
  for (const [index, site] of sites.entries()) {
    if (!site || typeof site !== "object") throw new Error("each site must have a domain");
    const domain = canonicalDomain(site.domain, "site domain");
    if (domains.has(domain)) throw new Error(`duplicate site domain ${domain}`);
    domains.add(domain);
    if (plan && domain !== plan.domains[index]) throw new Error(`site domain at rank ${index + 1} does not match the scan plan`);
    const quality = String(site.scan_quality || "");
    if (!KNOWN_QUALITIES.has(quality)) throw new Error(`unknown scan_quality ${JSON.stringify(quality)}`);
    const candidates = strictSiteInteger(site.month_candidates, `site ${domain} month_candidates`);
    const sampled = strictSiteInteger(site.sampled_products, `site ${domain} sampled_products`);
    if (sampled > candidates) throw new Error(`site ${domain} sampled_products cannot exceed month_candidates`);
    const coverage = strictCoverage(site.coverage_pct, domain);
    const expectedCoverage = candidates === 0 ? 100 : Math.round((sampled / candidates) * 1000) / 10;
    if (coverage !== expectedCoverage) throw new Error(`site ${domain} coverage_pct does not match sampled_products/month_candidates`);
    const discoveryBlocked = String(site.circuit_open || "").toLowerCase() === "yes" || Boolean(String(site.discovery_issue || "").trim());
    const blocked = candidates === 0 ? discoveryBlocked :
      (Number(site.blocked_products || 0) > 0 || discoveryBlocked);
    if (quality !== expectedScanQuality({ candidates, sampled, blocked })) {
      throw new Error(`site ${domain} scan_quality does not match scan evidence`);
    }
    const declaredHitCount = strictSiteInteger(site.hit_count, `site ${domain} hit_count`);
    const status = String(site.status || "");
    if (!status) throw new Error(`site ${domain} status is required`);
    sitesByDomain.set(domain, { status, quality, declaredHitCount });
    qualityCounts[quality] += 1;
  }
  const hitCounts = validateHitsAgainstSites(hits, domains);
  for (const [domain, site] of sitesByDomain) {
    const actualHitCount = hitCounts.get(domain) || 0;
    if (site.declaredHitCount !== actualHitCount) {
      throw new Error(`site ${domain} hit_count does not match hits.csv`);
    }
    if (site.status !== expectedSiteStatus(site.quality, actualHitCount)) {
      throw new Error(`site ${domain} status does not match hits.csv and scan_quality`);
    }
  }
  const hitSites = hitCounts.size;
  const usableSites = [...USABLE_QUALITIES].reduce((sum, quality) => sum + qualityCounts[quality], 0);
  const plannedCoveragePct = Math.round((totalSites / plannedSites) * 10000) / 100;
  const usableCoveragePct = totalSites === 0 ? 0 : Math.round((usableSites / totalSites) * 10000) / 100;
  const accepted = plannedCoveragePct >= SOURCE_MIN_PLANNED_COVERAGE_PCT &&
    usableCoveragePct >= SOURCE_MIN_USABLE_COVERAGE_PCT;
  return Object.freeze({
    status: accepted ? "accepted" : "rejected",
    scan_status: accepted && usableSites === totalSites ? "healthy" : "degraded",
    planned_sites: plannedSites,
    total_sites: totalSites,
    usable_sites: usableSites,
    hit_pages: hits.length,
    hit_sites: hitSites,
    planned_coverage_pct: plannedCoveragePct,
    usable_coverage_pct: usableCoveragePct,
    thresholds: Object.freeze({
      planned_coverage_pct: SOURCE_MIN_PLANNED_COVERAGE_PCT,
      usable_coverage_pct: SOURCE_MIN_USABLE_COVERAGE_PCT,
    }),
    scan_quality_counts: Object.freeze(qualityCounts),
  });
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function inputMetadata(snapshot) {
  return { sha256: snapshot.sha256, bytes: snapshot.bytes, rows: snapshot.rows };
}

export function sourceManifestFromSnapshots({ month, sourceGeneratedAt, runId, plannedSites, hits, sites, scanPlan, now = new Date() }) {
  assertSourceTime(month, sourceGeneratedAt, { now });
  if (typeof runId !== "string" || !runId) throw new Error("run_id is required");
  const plan = canonicalPlan(scanPlan);
  for (const column of REQUIRED_HIT_COLUMNS) {
    if (!hits.headers?.includes(column)) throw new Error(`hits.csv is missing required column ${column}`);
  }
  for (const column of REQUIRED_SITE_COLUMNS) {
    if (!sites.headers?.includes(column)) throw new Error(`sites.csv is missing required column ${column}`);
  }
  if (plannedSites !== plan.domains.length) throw new Error("planned_sites does not match the scan plan");
  const health = canonicalSourceHealth({ plannedSites, sites: sites.records, hits: hits.records, scanPlan: plan });
  if (health.status !== "accepted") {
    throw new Error(
      `scan source health rejected: planned=${health.total_sites}/${health.planned_sites}, usable=${health.usable_sites}/${health.total_sites}`,
    );
  }
  return {
    version: DATA_CONTRACT_VERSION,
    source_month: month,
    source_generated_at: sourceGeneratedAt,
    run_id: runId,
    health,
    inputs: { hits_csv: inputMetadata(hits), sites_csv: inputMetadata(sites), scan_plan: plan },
  };
}

function assertInputMetadata(expected, snapshot, label) {
  if (!expected || typeof expected !== "object") throw new Error(`manifest is missing ${label} metadata`);
  const actual = inputMetadata(snapshot);
  for (const field of ["sha256", "bytes", "rows"]) {
    if (expected[field] !== actual[field]) throw new Error(`${label} ${field} does not match its manifest`);
  }
}

function validateAttestation(attestation, manifest, manifestSha, month) {
  if (!attestation || typeof attestation !== "object") throw new Error(`state.json has no current attestation for ${month}`);
  if (
    attestation.version !== DATA_CONTRACT_VERSION || attestation.run_id !== manifest.run_id ||
    attestation.source_month !== month || attestation.source_generated_at !== manifest.source_generated_at ||
    attestation.manifest_sha256 !== manifestSha || !sameJson(attestation.health, manifest.health)
  ) {
    throw new Error(`state.json current attestation does not match source manifest for ${month}`);
  }
}

async function loadMonthlySource({ reportsDir, month, state, now, testHooks = {} }) {
  const reportDir = path.join(reportsDir, month);
  const manifestFile = path.join(reportDir, "source_manifest.json");
  const manifestSnapshot = await readJsonSnapshot(manifestFile, `source_manifest.json for ${month}`, {
    testAfterOpen: testHooks.afterManifestOpen,
  });
  const manifest = manifestSnapshot.value;
  if (manifest.version !== DATA_CONTRACT_VERSION) throw new Error(`source manifest for ${month} has unsupported version`);
  if (manifest.source_month !== month) throw new Error(`source manifest month does not match ${month}`);
  assertSourceTime(month, manifest.source_generated_at, { now });
  const [hits, sites] = await Promise.all([
    readCsvSnapshot(path.join(reportDir, "hits.csv"), REQUIRED_HIT_COLUMNS, { testAfterOpen: testHooks.afterHitsOpen }),
    readCsvSnapshot(path.join(reportDir, "sites.csv"), REQUIRED_SITE_COLUMNS, { testAfterOpen: testHooks.afterSitesOpen }),
  ]);
  assertInputMetadata(manifest.inputs?.hits_csv, hits, `hits.csv for ${month}`);
  assertInputMetadata(manifest.inputs?.sites_csv, sites, `sites.csv for ${month}`);
  const plan = canonicalPlan(manifest.inputs?.scan_plan);
  const recomputedHealth = canonicalSourceHealth({
    plannedSites: manifest.health?.planned_sites, sites: sites.records, hits: hits.records, scanPlan: plan,
  });
  if (!sameJson(manifest.health, recomputedHealth) || recomputedHealth.status !== "accepted") {
    throw new Error(`source health for ${month} is not canonical and accepted`);
  }
  validateAttestation(state.source_manifests?.[month], manifest, manifestSnapshot.sha256, month);
  return Object.freeze({
    month,
    as_of: manifest.source_generated_at,
    run_id: manifest.run_id,
    manifest_sha256: manifestSnapshot.sha256,
    health: recomputedHealth,
    hits: Object.freeze({ ...inputMetadata(hits), records: hits.records }),
    sites: Object.freeze({ ...inputMetadata(sites), records: sites.records }),
  });
}

function assertLatestMatches(latest, source) {
  const contract = latest.data_contract;
  if (!contract || contract.version !== DATA_CONTRACT_VERSION) throw new Error("latest.json has no supported data contract");
  if (
    contract.source_month !== source.month || contract.source_generated_at !== source.as_of ||
    contract.manifest_sha256 !== source.manifest_sha256 || !sameJson(contract.health, source.health)
  ) {
    throw new Error("latest.json does not attest to its current source manifest");
  }
}

function assertLatestMonthIsCurrent(latestMonth, state) {
  const attestedMonths = Object.keys(state.source_manifests || {}).map((month) => assertMonth(month, "state.json source manifest month"));
  if (!attestedMonths.length) throw new Error("state.json has no current monthly attestations");
  const newest = attestedMonths.sort().at(-1);
  if (latestMonth !== newest) throw new Error(`latest.json source_month ${latestMonth} is superseded by ${newest}`);
}

async function loadRootSnapshots({ dataDir, testHooks = {} }) {
  const [latestSnapshot, stateSnapshot] = await Promise.all([
    readJsonSnapshot(path.join(dataDir, "latest.json"), "latest.json", { testAfterOpen: testHooks.afterLatestOpen }),
    readJsonSnapshot(path.join(dataDir, "state.json"), "state.json", { testAfterOpen: testHooks.afterStateOpen }),
  ]);
  const latest = latestSnapshot.value;
  const state = stateSnapshot.value;
  if (!state.source_manifests || typeof state.source_manifests !== "object" || Array.isArray(state.source_manifests)) {
    throw new Error("state.json has no source_manifests object");
  }
  canonicalizeStateProducts(state.products || {});
  return { latest, state, latestSnapshot, stateSnapshot };
}

export async function validateLatestSource({ dataDir, reportsDir, now = new Date(), testHooks = {}, rootSnapshots = null }) {
  const roots = rootSnapshots || await loadRootSnapshots({ dataDir, testHooks });
  const { latest, state } = roots;
  const month = assertMonth(latest?.data_contract?.source_month, "latest.json source_month");
  assertLatestMonthIsCurrent(month, state);
  const source = await loadMonthlySource({ reportsDir, month, state, now, testHooks });
  assertLatestMatches(latest, source);
  return Object.freeze({ latest, state, source, latestSnapshot: roots.latestSnapshot, stateSnapshot: roots.stateSnapshot });
}

function assertDashboardSource(payload, source, expectedMonth) {
  if (!payload || typeof payload !== "object") throw new Error("dashboard_data.json is not an object");
  if (payload.latest_month !== expectedMonth || !Array.isArray(payload.months) || !payload.months.includes(expectedMonth)) {
    throw new Error("dashboard_data.json is not bound to the expected current month");
  }
  const entry = payload.source?.manifests?.find((item) => item?.month === source.month);
  if (!entry || entry.as_of !== source.as_of || entry.run_id !== source.run_id ||
      entry.manifest_sha256 !== source.manifest_sha256 || !sameJson(entry.health, source.health)) {
    throw new Error("dashboard_data.json does not attest to the latest source manifest");
  }
}

export async function validateLatestDashboardArtifact({ reportsDir, source, expectedMonth, now = new Date() }) {
  assertMonth(expectedMonth, "expected dashboard month");
  if (!source || source.month !== expectedMonth) throw new Error("latest source is not the expected dashboard month");
  const reportDir = path.join(reportsDir, "latest");
  const [commit, data, html] = await Promise.all([
    readJsonSnapshot(path.join(reportDir, "dashboard_manifest.json"), "latest dashboard manifest"),
    readJsonSnapshot(path.join(reportDir, "dashboard_data.json"), "latest dashboard data"),
    readSafeFileSnapshot(path.join(reportDir, "dashboard.html")),
  ]);
  const manifest = commit.value;
  // Hard freshness is evaluated against the health-check clock, independently
  // from the stable age proof recorded when the dashboard was generated.
  latestSourceAgeSeconds(source.month, source.as_of, { now });
  if (manifest.version !== 1 || manifest.kind !== "single-page-dashboard" || manifest.out_key !== "latest" ||
      manifest.latest_month !== expectedMonth || !manifest.inputs ||
      manifest.inputs.dashboard_data?.sha256 !== data.sha256 || manifest.inputs.dashboard_data?.bytes !== data.bytes ||
      manifest.inputs.dashboard_html?.sha256 !== html.sha256 || manifest.inputs.dashboard_html?.bytes !== html.bytes ||
      !sameJson(manifest.source_manifests, data.value?.source?.manifests)) {
    throw new Error("latest dashboard artifact commit does not match its files");
  }
  if (manifest.generated_at !== data.value?.generated_at) {
    throw new Error("latest dashboard manifest generated_at does not match dashboard data");
  }
  if (!Number.isSafeInteger(manifest.source_age_seconds) || manifest.source_age_seconds < 0) {
    throw new Error("latest dashboard manifest source_age_seconds must be a non-negative safe integer");
  }
  const sourceAgeSeconds = sourceAgeAtGeneratedAtSeconds(
    source.month, source.as_of, manifest.generated_at,
  );
  if (manifest.source_age_seconds !== sourceAgeSeconds) {
    throw new Error("latest dashboard manifest source_age_seconds does not match the trusted source time");
  }
  assertDashboardSource(data.value, source, expectedMonth);
  const htmlText = decodeUtf8Fatal(html.buffer, "latest dashboard HTML");
  if (!/^<!doctype html>/i.test(htmlText) || !htmlText.includes("const DATA =") || !htmlText.includes(source.manifest_sha256)) {
    throw new Error("latest dashboard HTML is not bound to its dashboard data");
  }
  return Object.freeze({ manifest, data: data.value, commit, dataSnapshot: data, htmlSnapshot: html });
}

export async function validateDashboardSources({ dataDir, reportsDir, months, now = new Date(), testHooks = {} }) {
  if (!Array.isArray(months)) throw new Error("months must be an array");
  const { latest, state } = await loadRootSnapshots({ dataDir, testHooks });
  const latestMonth = assertMonth(latest?.data_contract?.source_month, "latest.json source_month");
  assertLatestMonthIsCurrent(latestMonth, state);
  const selectedMonths = months.length ? [...new Set(months.map((month) => assertMonth(month)))] : [latestMonth];
  const monthsToLoad = [...new Set([...selectedMonths, latestMonth])];
  const sourceByMonth = new Map();
  for (const month of monthsToLoad) {
    sourceByMonth.set(month, await loadMonthlySource({ reportsDir, month, state, now, testHooks }));
  }
  assertLatestMatches(latest, sourceByMonth.get(latestMonth));
  return Object.freeze({ latest, state, sources: Object.freeze(selectedMonths.map((month) => sourceByMonth.get(month))) });
}

export function assertEnrichmentCoverage({ total, succeeded, thresholdPct }) {
  strictNonNegativeInteger(total, "enrichment total");
  strictNonNegativeInteger(succeeded, "enrichment succeeded");
  if (succeeded > total) throw new Error("enrichment succeeded cannot exceed total");
  if (typeof thresholdPct !== "number" || !Number.isFinite(thresholdPct) || thresholdPct <= 0 || thresholdPct > 100) {
    throw new Error("enrichment coverage threshold must be a finite number in (0, 100]");
  }
  const failed = total - succeeded;
  const emptyInput = total === 0;
  const coveragePct = emptyInput ? 100 : Math.round((succeeded / total) * 10000) / 100;
  if (!emptyInput && coveragePct < thresholdPct) {
    throw new Error(`enrichment coverage ${coveragePct}% (${succeeded}/${total}) is below required ${thresholdPct}%`);
  }
  return Object.freeze({
    total,
    succeeded,
    failed,
    coverage_pct: coveragePct,
    threshold_pct: thresholdPct,
    empty_input: emptyInput,
    status: "accepted",
  });
}

export function hasMeaningfulEnrichment(product) {
  if (!product || typeof product !== "object") return false;
  return Boolean(
    String(product.image_url || "").trim() ||
    String(product.price || "").trim() ||
    String(product.description || "").trim() ||
    String(product.vendor || "").trim() ||
    String(product.product_type || "").trim() ||
    (Array.isArray(product.tags) && product.tags.some((tag) => String(tag || "").trim())),
  );
}
