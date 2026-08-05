import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import {
  DATA_CONTRACT_VERSION,
  assertLatestBuildSourceFresh,
  assertEnrichmentCoverage,
  assertSourceTime,
  canonicalProductHandle,
  canonicalProductJsonUrl,
  canonicalProductKey,
  canonicalSourceHealth,
  canonicalizeStateProducts,
  hasMeaningfulEnrichment,
  parseJsonStrict,
  readCsvSnapshot,
  readJsonSnapshot,
  readSafeFileSnapshot,
  scanPlanFromSnapshot,
  sha256,
  sourceManifestFromSnapshots,
  validateDashboardSources,
  validateLatestDashboardArtifact,
  validateLatestSource,
} from "../lib/dashboard_contract.mjs";

function runNode(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("exit", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

async function waitFor(file) {
  for (let index = 0; index < 300; index += 1) {
    try { await fs.access(file); return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`timed out waiting for ${file}`);
}

async function writeFakeEngine(root, {
  qualities = Array.from({ length: 200 }, () => "complete"), hitMarker = "engine", sitesText = "", planDomains = null,
} = {}) {
  const file = path.join(root, "fake_scan_engine.mjs");
  const source = `import fs from "node:fs/promises";
import path from "node:path";
const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) args.set(process.argv[index], process.argv[index + 1]);
const hits = args.get("--hits-csv");
const sites = args.get("--sites-csv");
await fs.mkdir(path.dirname(hits), { recursive: true });
await fs.writeFile(hits, ${JSON.stringify(`domain,url,handle\nsite-0.example,https://site-0.example/products/${hitMarker},${hitMarker}\n`)});
await fs.writeFile(sites, ${JSON.stringify(sitesText || sitesCsv(qualities))});
await fs.writeFile(args.get("--md"), ${JSON.stringify("fake scan\n")});
await fs.writeFile(args.get("--progress-json"), ${JSON.stringify("{}\n")});
`;
  await fs.writeFile(file, source);
  await fs.writeFile(path.join(root, "top200-plan.csv"), "domain\n" + (planDomains || qualities.map((_, index) => `site-${index}.example`)).join("\n") + "\n");
  return file;
}

function shanghaiMonth(date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit" })
    .formatToParts(date);
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${values.year}-${values.month}`;
}

function previousMonth(month) {
  const [year, value] = month.split("-").map(Number);
  const date = new Date(Date.UTC(year, value - 2, 1));
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
}

function sitesCsv(qualities) {
  return "domain,status,hit_count,scan_quality,coverage_pct,month_candidates,sampled_products\n" + qualities
    .map((quality, index) => {
      const evidence = {
        complete: [100, 10, 10], no_candidates: [100, 0, 0], partial: [20, 10, 2],
        incomplete: [0, 10, 0], blocked: [0, 10, 0], error: [0, 10, 0],
      }[quality] || [0, 10, 0];
      const hitCount = index === 0 ? 1 : 0;
      const status = hitCount ? "has_month_single_page" : quality === "blocked" ? "access_blocked" :
        ["partial", "incomplete"].includes(quality) ? "scan_incomplete" :
          quality === "error" ? "scan_error" : "no_month_single_page_hit";
      return `site-${index}.example,${status},${hitCount},${quality},${evidence[0]},${evidence[1]},${evidence[2]}`;
    })
    .join("\n") + "\n";
}

async function writeSource({ reportsDir, state, month, at, qualities = Array.from({ length: 200 }, () => "complete"), hitMarker = "widget" }) {
  const reportDir = path.join(reportsDir, month);
  await fs.mkdir(reportDir, { recursive: true });
  await fs.writeFile(
    path.join(reportDir, "hits.csv"),
    `domain,url,handle\nsite-0.example,https://site-0.example/products/${hitMarker},${hitMarker}\n`,
  );
  await fs.writeFile(path.join(reportDir, "sites.csv"), sitesCsv(qualities));
  const [hits, sites] = await Promise.all([
    readCsvSnapshot(path.join(reportDir, "hits.csv"), ["domain", "url"]),
    readCsvSnapshot(path.join(reportDir, "sites.csv"), ["domain", "scan_quality", "coverage_pct"]),
  ]);
  const planFile = path.join(path.dirname(reportsDir), "top200-plan.csv");
  await fs.writeFile(planFile, "domain\n" + qualities.map((_, index) => `site-${index}.example`).join("\n") + "\n");
  const scanPlan = scanPlanFromSnapshot(await readCsvSnapshot(planFile, ["domain"]));
  const runId = `${month}-${at}-${hitMarker}`;
  const manifest = sourceManifestFromSnapshots({
    month,
    sourceGeneratedAt: at,
    runId,
    plannedSites: qualities.length,
    hits,
    sites,
    scanPlan,
    now: new Date(Date.parse(at) + 1000),
  });
  const text = JSON.stringify(manifest, null, 2) + "\n";
  await fs.writeFile(path.join(reportDir, "source_manifest.json"), text);
  const manifestSha256 = sha256(Buffer.from(text));
  state.source_manifests[month] = {
    version: DATA_CONTRACT_VERSION,
    run_id: runId,
    source_month: month,
    source_generated_at: at,
    manifest_sha256: manifestSha256,
    health: manifest.health,
  };
  return { manifest, text, manifestSha256, hitsText: hits.text, sitesText: sites.text };
}

async function writeLatestDashboardArtifact(reportsDir, source, month) {
  const reportDir = path.join(reportsDir, "latest");
  await fs.mkdir(reportDir, { recursive: true });
  const generatedAt = new Date(Date.parse(source.manifest.source_generated_at) + 1000).toISOString();
  const payload = {
    generated_at: generatedAt,
    month,
    months: [month],
    latest_month: month,
    source: { manifests: [{
      month, as_of: source.manifest.source_generated_at, run_id: source.manifest.run_id,
      manifest_sha256: source.manifestSha256, health: source.manifest.health,
    }] },
  };
  const dataText = JSON.stringify(payload, null, 2) + "\n";
  const htmlText = `<!doctype html><script>const DATA = ${JSON.stringify(payload)};</script>${source.manifestSha256}`;
  await fs.writeFile(path.join(reportDir, "dashboard_data.json"), dataText);
  await fs.writeFile(path.join(reportDir, "dashboard.html"), htmlText);
  await fs.writeFile(path.join(reportDir, "dashboard_manifest.json"), JSON.stringify({
    version: 1, kind: "single-page-dashboard", out_key: "latest", latest_month: month,
    generated_at: generatedAt, source_age_seconds: 1,
    source_manifests: payload.source.manifests,
    inputs: {
      dashboard_data: { sha256: sha256(Buffer.from(dataText)), bytes: Buffer.byteLength(dataText) },
      dashboard_html: { sha256: sha256(Buffer.from(htmlText)), bytes: Buffer.byteLength(htmlText) },
    },
  }, null, 2) + "\n");
}

async function setupFixture({ multi = true, sourceMonth = "", sourceAt = "" } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-dashboard-contract-"));
  const dataDir = path.join(root, "data");
  const reportsDir = path.join(root, "reports");
  await fs.mkdir(dataDir, { recursive: true });
  const state = { version: 2, products: {}, runs: [], source_manifests: {} };
  const currentMonth = sourceMonth || shanghaiMonth();
  const priorMonth = previousMonth(currentMonth);
  const currentAt = sourceAt || new Date(Date.now() - 60_000).toISOString();
  const priorAt = new Date(Date.now() - 120_000).toISOString();
  const sources = {};
  if (multi) sources[priorMonth] = await writeSource({ reportsDir, state, month: priorMonth, at: priorAt, hitMarker: "prior" });
  sources[currentMonth] = await writeSource({ reportsDir, state, month: currentMonth, at: currentAt, hitMarker: "current" });
  await fs.writeFile(path.join(dataDir, "state.json"), JSON.stringify(state, null, 2) + "\n");
  const current = sources[currentMonth];
  await fs.writeFile(path.join(dataDir, "latest.json"), JSON.stringify({
    month: currentMonth,
    data_contract: {
      version: DATA_CONTRACT_VERSION,
      source_month: currentMonth,
      source_generated_at: current.manifest.source_generated_at,
      manifest_sha256: current.manifestSha256,
      health: current.manifest.health,
    },
  }, null, 2) + "\n");
  await writeLatestDashboardArtifact(reportsDir, current, currentMonth);
  return { root, dataDir, reportsDir, state, currentMonth, priorMonth, sources };
}

test("validates multi-month sources and derives the default from one latest snapshot", async () => {
  const fixture = await setupFixture();
  try {
    const multi = await validateDashboardSources({
      dataDir: fixture.dataDir,
      reportsDir: fixture.reportsDir,
      months: [fixture.priorMonth, fixture.currentMonth],
    });
    assert.deepEqual(multi.sources.map((source) => source.month), [fixture.priorMonth, fixture.currentMonth]);
    assert.equal(multi.sources[0].hits.records[0].handle, "prior");
    const inferred = await validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [] });
    assert.deepEqual(inferred.sources.map((source) => source.month), [fixture.currentMonth]);
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("canonical source health rejects one complete site among 199 partial sites", () => {
  const sites = Array.from({ length: 200 }, (_, index) => ({
    domain: `site-${index}.example`,
    scan_quality: index === 0 ? "complete" : "partial",
    coverage_pct: index === 0 ? 100 : 20,
    month_candidates: 10,
    sampled_products: index === 0 ? 10 : 2,
    status: index === 0 ? "no_month_single_page_hit" : "scan_incomplete",
    hit_count: 0,
  }));
  const health = canonicalSourceHealth({ plannedSites: 200, sites });
  assert.equal(health.status, "rejected");
  assert.equal(health.planned_sites, 200);
  assert.equal(health.total_sites, 200);
  assert.equal(health.usable_sites, 1);
  assert.equal(health.usable_coverage_pct, 0.5);
  assert.equal(health.scan_quality_counts.partial, 199);
  assert.throws(() => canonicalSourceHealth({ plannedSites: "200", sites }), /positive safe integer/);
  assert.throws(() => canonicalSourceHealth({ plannedSites: 1, sites: sites.slice(0, 1) }), /canonical 200/);
  assert.throws(() => canonicalSourceHealth({ plannedSites: 199, sites: sites.slice(0, 199) }), /canonical 200/);
  assert.equal(
    canonicalSourceHealth({
      plannedSites: 200,
      sites: sites.map((site) => ({
        ...site, scan_quality: "complete", coverage_pct: 100, sampled_products: 10,
        status: "no_month_single_page_hit",
      })),
    }).status,
    "accepted",
  );
});

test("canonical source health rejects forged coverage, normalized duplicates, bad hit linkage, and non-200 plans", () => {
  const sites = Array.from({ length: 200 }, (_, index) => ({
    domain: `site-${index}.example`, scan_quality: "complete", coverage_pct: 100,
    month_candidates: 10, sampled_products: 10, status: "no_month_single_page_hit", hit_count: 0,
  }));
  assert.throws(() => canonicalSourceHealth({
    plannedSites: 200, sites: sites.map((site, index) => index ? site : { ...site, coverage_pct: 0 }),
  }), /coverage_pct does not match/);
  assert.throws(() => canonicalSourceHealth({
    plannedSites: 200, sites: sites.map((site, index) => index === 1 ? { ...site, domain: "  SITE-0.EXAMPLE  " } : site),
  }), /duplicate site domain/);
  assert.throws(() => canonicalSourceHealth({
    plannedSites: 201, sites,
  }), /must equal canonical 200/);
  assert.throws(() => canonicalSourceHealth({
    plannedSites: 200, sites, hits: [{ domain: "outside.example", url: "https://outside.example/products/x" }],
  }), /not in sites.csv/);
});

test("source health binds site status and hit_count bidirectionally and rejects duplicate hits", () => {
  const sites = Array.from({ length: 200 }, (_, index) => ({
    domain: `site-${index}.example`, status: "no_month_single_page_hit", hit_count: 0,
    scan_quality: "complete", coverage_pct: 100, month_candidates: 10, sampled_products: 10,
  }));
  const hit = { domain: "site-0.example", url: "https://site-0.example/products/widget", handle: "widget" };
  assert.throws(() => canonicalSourceHealth({
    plannedSites: 200,
    sites: sites.map((site, index) => index ? site : { ...site, status: "has_month_single_page", hit_count: 999 }),
    hits: [],
  }), /hit_count does not match/);
  assert.throws(() => canonicalSourceHealth({ plannedSites: 200, sites, hits: [hit] }), /hit_count does not match/);
  assert.throws(() => canonicalSourceHealth({
    plannedSites: 200,
    sites: sites.map((site, index) => index ? site : { ...site, hit_count: 1 }),
    hits: [hit],
  }), /status does not match/);
  assert.throws(() => canonicalSourceHealth({
    plannedSites: 200,
    sites: sites.map((site, index) => index ? site : { ...site, status: "has_month_single_page", hit_count: 500 }),
    hits: Array.from({ length: 500 }, () => ({ ...hit })),
  }), /duplicate hit URL/);
  assert.throws(() => canonicalSourceHealth({
    plannedSites: 200,
    sites: sites.map((site, index) => index ? site : { ...site, status: "has_month_single_page", hit_count: 2 }),
    hits: [
      { ...hit, url: "https://site-0.example/en/products/widget" },
      { ...hit, url: "https://site-0.example/fr/products/widget" },
    ],
  }), /duplicate hit product/);
});

test("hit URL and declared handle require one strict canonical product identity", () => {
  const sites = Array.from({ length: 200 }, (_, index) => ({
    domain: `site-${index}.example`,
    status: index === 0 ? "has_month_single_page" : "no_month_single_page_hit",
    hit_count: index === 0 ? 1 : 0,
    scan_quality: "complete", coverage_pct: 100, month_candidates: 10, sampled_products: 10,
  }));
  const rejected = [
    { name: "account URL", hit: { url: "https://site-0.example/account/login", handle: "login" } },
    { name: "bare products URL", hit: { url: "https://site-0.example/products", handle: "products" } },
    { name: "empty declared handle", hit: { url: "https://site-0.example/products/widget", handle: "" } },
    { name: "encoded slash", hit: { url: "https://site-0.example/products/foo%2Fbar", handle: "foo/bar" } },
    { name: "encoded backslash", hit: { url: "https://site-0.example/products/foo%5Cbar", handle: "foo\\bar" } },
    { name: "encoded control", hit: { url: "https://site-0.example/products/foo%00bar", handle: "foo" } },
    { name: "encoded separator in declared handle", hit: { url: "https://site-0.example/products/widget", handle: "wid%2Fget" } },
    { name: "literal control", hit: { url: "https://site-0.example/products/foo\nbar", handle: "foobar" } },
    { name: "mismatch", hit: { url: "https://site-0.example/products/widget", handle: "other" } },
    { name: "encoded query delimiter", hit: { url: "https://site-0.example/products/foo%3Fbar", handle: "foo?bar" } },
    { name: "encoded fragment delimiter", hit: { url: "https://site-0.example/products/foo%23bar", handle: "foo#bar" } },
    { name: "literal query delimiter", hit: { url: "https://site-0.example/products/foo", handle: "foo?bar" } },
    { name: "literal fragment delimiter", hit: { url: "https://site-0.example/products/foo", handle: "foo#bar" } },
    { name: "extra path", hit: { url: "https://site-0.example/products/widget/reviews", handle: "widget" } },
    { name: "multiple product segments", hit: { url: "https://site-0.example/products/a/products/b", handle: "b" } },
  ];
  for (const attack of rejected) {
    assert.throws(
      () => canonicalSourceHealth({
        plannedSites: 200,
        sites,
        hits: [{ domain: "site-0.example", ...attack.hit }],
      }),
      undefined,
      attack.name,
    );
  }
  const accepted = canonicalSourceHealth({
    plannedSites: 200,
    sites,
    hits: [{ domain: "site-0.example", url: "https://site-0.example/en/products/WidGet/", handle: "widget" }],
  });
  assert.equal(accepted.hit_pages, 1);
  assert.equal(accepted.hit_sites, 1);
});

test("raw and percent-encoded Unicode handles share one state identity and JSON URL encoding", () => {
  const raw = "🧸";
  const encoded = "%F0%9F%A7%B8";
  assert.equal(canonicalProductHandle(raw), raw);
  assert.equal(canonicalProductHandle(encoded), raw);
  assert.equal(
    canonicalProductKey({ domain: "Example.COM", handle: raw }),
    canonicalProductKey({ domain: "example.com", handle: encoded }),
  );
  assert.equal(
    canonicalProductJsonUrl({ domain: "Example.COM", handle: raw }),
    "https://example.com/products/%F0%9F%A7%B8.json",
  );

  const migrated = canonicalizeStateProducts({
    "example.com|%F0%9F%A7%B8": { domain: "Example.COM", handle: encoded, first_seen_at: "2026-08-01" },
  });
  assert.deepEqual(Object.keys(migrated), [`example.com|${raw}`]);
  assert.equal(migrated[`example.com|${raw}`].handle, raw);
  assert.throws(() => canonicalizeStateProducts({
    [`example.com|${raw}`]: { domain: "example.com", handle: raw },
    "example.com|%F0%9F%A7%B8": { domain: "example.com", handle: encoded },
  }), /legacy state product identities collide/);

  const sites = Array.from({ length: 200 }, (_, index) => ({
    domain: `site-${index}.example`,
    status: index === 0 ? "has_month_single_page" : "no_month_single_page_hit",
    hit_count: index === 0 ? 1 : 0,
    scan_quality: "complete", coverage_pct: 100, month_candidates: 10, sampled_products: 10,
  }));
  assert.equal(canonicalSourceHealth({
    plannedSites: 200,
    sites,
    hits: [{ domain: "site-0.example", url: `https://site-0.example/products/${encoded}`, handle: raw }],
  }).hit_pages, 1);
});

test("fails closed for tampering, a missing manifest, and corrupt or duplicate-key JSON", async () => {
  const fixture = await setupFixture();
  try {
    const hits = path.join(fixture.reportsDir, fixture.currentMonth, "hits.csv");
    await fs.appendFile(hits, "bad.example,https://bad.example/products/x,x\n");
    await assert.rejects(
      validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [] }),
      /hits\.csv .* sha256 does not match/,
    );
    await fs.writeFile(hits, fixture.sources[fixture.currentMonth].hitsText);
    await fs.rm(path.join(fixture.reportsDir, fixture.currentMonth, "source_manifest.json"));
    await assert.rejects(
      validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [] }),
      /source_manifest\.json.*missing or unreadable/,
    );
    assert.throws(() => parseJsonStrict('{"x":1,"x":2}', "duplicate.json"), /duplicate key/);
    await fs.writeFile(path.join(fixture.dataDir, "latest.json"), '{"data_contract":{},"data_contract":{}}\n');
    await assert.rejects(
      validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [] }),
      /duplicate key/,
    );
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("hashes raw bytes and rejects distinct invalid UTF-8 byte sequences", async () => {
  assert.notEqual(sha256(Buffer.from([0x80])), sha256(Buffer.from([0x81])));
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-invalid-utf8-"));
  try {
    const file = path.join(root, "latest.json");
    await fs.writeFile(file, Buffer.from([0x80]));
    await assert.rejects(readJsonSnapshot(file, "latest.json"), /not valid UTF-8/);
    await fs.writeFile(file, Buffer.from([0x81]));
    await assert.rejects(readJsonSnapshot(file, "latest.json"), /not valid UTF-8/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("rejects symlink, non-regular, and hard-linked contract inputs", async () => {
  const fixture = await setupFixture({ multi: false });
  const hits = path.join(fixture.reportsDir, fixture.currentMonth, "hits.csv");
  const saved = path.join(fixture.root, "saved-hits.csv");
  try {
    await fs.rename(hits, saved);
    await fs.symlink(saved, hits);
    await assert.rejects(validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [] }), /symbolic link|opened safely|not a regular file/);
    await fs.rm(hits);
    await fs.link(saved, hits);
    await assert.rejects(validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [] }), /unsafe hard-link count/);
    await fs.rm(hits);
    await fs.mkdir(hits);
    await assert.rejects(validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [] }), /not a regular file/);
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("rejects superseded monthly manifest replay even if it still appears in runs", async () => {
  const fixture = await setupFixture({ multi: false });
  try {
    const month = fixture.currentMonth;
    const old = fixture.sources[month];
    const newerAt = new Date(Date.now() - 30_000).toISOString();
    const newer = await writeSource({ reportsDir: fixture.reportsDir, state: fixture.state, month, at: newerAt, hitMarker: "newer" });
    fixture.state.runs.push({ run_id: old.manifest.run_id, data_contract: fixture.state.source_manifests[month] });
    await fs.writeFile(path.join(fixture.dataDir, "state.json"), JSON.stringify(fixture.state, null, 2) + "\n");
    await fs.writeFile(path.join(fixture.dataDir, "latest.json"), JSON.stringify({ data_contract: {
      version: 1, source_month: month, source_generated_at: newerAt,
      manifest_sha256: newer.manifestSha256, health: newer.manifest.health,
    } }, null, 2) + "\n");
    await fs.writeFile(path.join(fixture.reportsDir, month, "hits.csv"), old.hitsText);
    await fs.writeFile(path.join(fixture.reportsDir, month, "sites.csv"), old.sitesText);
    await fs.writeFile(path.join(fixture.reportsDir, month, "source_manifest.json"), old.text);
    await assert.rejects(
      validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [month] }),
      /current attestation does not match/,
    );
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("latest.json cannot replay an older attested month", async () => {
  const fixture = await setupFixture();
  try {
    const prior = fixture.sources[fixture.priorMonth];
    await fs.writeFile(path.join(fixture.dataDir, "latest.json"), JSON.stringify({ data_contract: {
      version: 1,
      source_month: fixture.priorMonth,
      source_generated_at: prior.manifest.source_generated_at,
      manifest_sha256: prior.manifestSha256,
      health: prior.manifest.health,
    } }, null, 2) + "\n");
    await assert.rejects(
      validateDashboardSources({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir, months: [] }),
      /is superseded by/,
    );
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("requires complete bounded source timestamps", () => {
  assert.throws(() => assertSourceTime("2040-01", "2040-01-01T00:00:00.000Z", { now: new Date("2026-08-01T00:00:00.000Z") }), /future/);
  assert.throws(() => assertSourceTime("2026-08", "2026-08-01T00:00:00Z", { now: new Date("2026-08-02T00:00:00.000Z") }), /complete UTC ISO/);
  assert.throws(() => assertSourceTime("2026-09", "2026-08-02T00:00:00.000Z", { now: new Date("2026-08-03T00:00:00.000Z") }), /source_month is after/);
  assert.throws(() => assertSourceTime("2020-01", "2026-08-02T00:00:00.000Z", { now: new Date("2026-08-03T00:00:00.000Z") }), /more than 24 months/);
});

test("latest build freshness requires the current Shanghai month and a source no older than 36 hours", () => {
  const now = new Date("2026-08-03T00:00:00.000Z");
  assert.equal(assertLatestBuildSourceFresh("2026-08", "2026-08-02T00:00:00.000Z", { now }), 86400);
  assert.throws(() => assertLatestBuildSourceFresh("2026-07", "2026-07-31T16:00:00.000Z", { now }), /current Asia\/Shanghai month/);
  assert.throws(() => assertLatestBuildSourceFresh("2026-08", "2026-08-01T11:59:59.000Z", { now }), /older than 36 hours/);
});

test("latest dashboard manifest binds stable generated-time age and rejects malformed proofs", async () => {
  const fixture = await setupFixture({ multi: false });
  try {
    const source = (await validateLatestSource({ dataDir: fixture.dataDir, reportsDir: fixture.reportsDir })).source;
    const manifestFile = path.join(fixture.reportsDir, "latest", "dashboard_manifest.json");
    const original = JSON.parse(await fs.readFile(manifestFile, "utf8"));
    const oneHourLater = new Date(Date.parse(source.as_of) + 60 * 60 * 1000);
    await validateLatestDashboardArtifact({
      reportsDir: fixture.reportsDir, source, expectedMonth: source.month, now: oneHourLater,
    });
    for (const [label, mutate, expected] of [
      ["missing", (value) => { delete value.source_age_seconds; }, /non-negative safe integer/],
      ["negative", (value) => { value.source_age_seconds = -1; }, /non-negative safe integer/],
      ["fractional", (value) => { value.source_age_seconds = 1.5; }, /non-negative safe integer/],
      ["tampered", (value) => { value.source_age_seconds = 2; }, /does not match the trusted source time/],
      ["unbound generated_at", (value) => { value.generated_at = new Date(Date.parse(value.generated_at) + 1000).toISOString(); }, /generated_at does not match dashboard data/],
    ]) {
      const manifest = structuredClone(original);
      mutate(manifest);
      await fs.writeFile(manifestFile, JSON.stringify(manifest, null, 2) + "\n");
      await assert.rejects(
        validateLatestDashboardArtifact({ reportsDir: fixture.reportsDir, source, expectedMonth: source.month, now: oneHourLater }),
        expected,
        label,
      );
    }
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("health marks a weeks-old latest source invalid even during grace and a live run", async () => {
  const fixture = await setupFixture({
    multi: false, sourceMonth: "2026-07", sourceAt: "2026-07-01T00:00:00.000Z",
  });
  const script = new URL("../check_health.mjs", import.meta.url);
  try {
    await fs.writeFile(path.join(fixture.dataDir, "run_status.json"), JSON.stringify({
      state: "running", stage: "scan_current_month", pid: process.pid,
      started_at: "2026-08-01T01:00:00.000Z", heartbeat_at: "2026-08-01T01:01:00.000Z",
    }));
    const result = await runNode([script.pathname, "--json", "yes", "--grace-minutes", "100000"], {
      ...process.env,
      SP_SINGLE_PAGE_DATA_DIR: fixture.dataDir,
      SP_SINGLE_PAGE_REPORTS_DIR: fixture.reportsDir,
      SP_SINGLE_PAGE_TEST_MODE: "1",
      SP_SINGLE_PAGE_TEST_NOW: "2026-08-01T01:02:00.000Z",
    });
    assert.equal(result.code, 2, result.stdout);
    assert.ok(JSON.parse(result.stdout).issue_codes.includes("data_contract_invalid"));
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("safe snapshot detects path replacement during its single read", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-snapshot-race-"));
  const file = path.join(root, "hits.csv");
  try {
    await fs.writeFile(file, "domain,url\na.example,https://a.example/x\n");
    await assert.rejects(
      readSafeFileSnapshot(file, { testAfterOpen: async () => {
        const replacement = path.join(root, "replacement.csv");
        await fs.writeFile(replacement, "domain,url\nb.example,https://b.example/x\n");
        await fs.rename(replacement, file);
      } }),
      /changed while it was read|unsafe hard-link count 0/,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("builder uses its validated CSV snapshot even if the path changes afterward", async () => {
  const fixture = await setupFixture({ multi: false });
  const ready = path.join(fixture.root, "builder-ready");
  const proceed = path.join(fixture.root, "builder-proceed");
  const script = new URL("../build_dashboard.mjs", import.meta.url);
  try {
    const originalHash = fixture.sources[fixture.currentMonth].manifest.inputs.hits_csv.sha256;
    const running = runNode([script.pathname, "--verify-inputs-only"], {
      ...process.env,
      SP_SINGLE_PAGE_DATA_DIR: fixture.dataDir,
      SP_SINGLE_PAGE_REPORTS_DIR: fixture.reportsDir,
      SP_SINGLE_PAGE_TEST_MODE: "1",
      SP_SINGLE_PAGE_TEST_CONTRACT_PAUSE_AT: "after_contract_snapshot",
      SP_SINGLE_PAGE_TEST_CONTRACT_READY_FILE: ready,
      SP_SINGLE_PAGE_TEST_CONTRACT_CONTINUE_FILE: proceed,
    });
    await waitFor(ready);
    await fs.writeFile(path.join(fixture.reportsDir, fixture.currentMonth, "hits.csv"), "domain,url,handle\nchanged.example,https://changed.example/x,x\n");
    await fs.writeFile(proceed, "go\n");
    const result = await running;
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, new RegExp(originalHash));
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("skip-scan never promotes legacy CSV and does not refresh trusted mtimes", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-skip-readonly-"));
  const dataDir = path.join(root, "data");
  const reportsDir = path.join(root, "reports");
  const month = shanghaiMonth();
  const reportDir = path.join(reportsDir, month);
  const script = new URL("../monitor.mjs", import.meta.url);
  try {
    await fs.mkdir(reportDir, { recursive: true });
    const hits = path.join(reportDir, "hits.csv");
    const sites = path.join(reportDir, "sites.csv");
    await fs.writeFile(hits, "domain,url\nlegacy.example,https://legacy.example/x\n");
    await fs.writeFile(sites, "domain,scan_quality,coverage_pct\nlegacy.example,complete,100\n");
    const before = await Promise.all([fs.stat(hits), fs.stat(sites)]);
    const legacy = await runNode([script.pathname, "--month", month, "--skip-scan", "yes", "--limit", "1"], {
      ...process.env, SP_SINGLE_PAGE_DATA_DIR: dataDir, SP_SINGLE_PAGE_REPORTS_DIR: reportsDir,
    });
    assert.notEqual(legacy.code, 0);
    await assert.rejects(fs.access(path.join(reportDir, "source_manifest.json")));
    const after = await Promise.all([fs.stat(hits), fs.stat(sites)]);
    assert.equal(after[0].mtimeMs, before[0].mtimeMs);
    assert.equal(after[1].mtimeMs, before[1].mtimeMs);

    const trusted = await setupFixture({ multi: false });
    try {
      const watched = [
        path.join(trusted.dataDir, "latest.json"), path.join(trusted.dataDir, "state.json"),
        path.join(trusted.reportsDir, trusted.currentMonth, "source_manifest.json"),
      ];
      const mtimes = await Promise.all(watched.map((file) => fs.stat(file)));
      const valid = await runNode([script.pathname, "--month", trusted.currentMonth, "--skip-scan", "yes", "--limit", "2"], {
        ...process.env, SP_SINGLE_PAGE_DATA_DIR: trusted.dataDir, SP_SINGLE_PAGE_REPORTS_DIR: trusted.reportsDir,
      });
      assert.equal(valid.code, 0, valid.stderr);
      const afterMtimes = await Promise.all(watched.map((file) => fs.stat(file)));
      assert.deepEqual(afterMtimes.map((item) => item.mtimeMs), mtimes.map((item) => item.mtimeMs));
    } finally {
      await fs.rm(trusted.root, { recursive: true, force: true });
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("monitor rejects input TOCTOU before publishing a manifest", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-monitor-toctou-"));
  const dataDir = path.join(root, "data");
  const reportsDir = path.join(root, "reports");
  const ready = path.join(root, "ready");
  const proceed = path.join(root, "proceed");
  const month = shanghaiMonth();
  const engine = await writeFakeEngine(root);
  const script = new URL("../monitor.mjs", import.meta.url);
  try {
    const running = runNode([script.pathname, "--month", month, "--limit", "200"], {
      ...process.env,
      SP_SINGLE_PAGE_DATA_DIR: dataDir,
      SP_SINGLE_PAGE_REPORTS_DIR: reportsDir,
      SP_SINGLE_PAGE_TEST_MODE: "1",
      SP_SINGLE_PAGE_TEST_ENGINE: engine,
      SP_SINGLE_PAGE_TEST_CONTRACT_PAUSE_AT: "after_input_snapshot",
      SP_SINGLE_PAGE_TEST_CONTRACT_READY_FILE: ready,
      SP_SINGLE_PAGE_TEST_CONTRACT_CONTINUE_FILE: proceed,
    });
    await waitFor(ready);
    await fs.writeFile(path.join(reportsDir, month, "hits.csv"), "domain,url,handle\nchanged.example,https://changed.example/x,x\n");
    await fs.writeFile(proceed, "go\n");
    const result = await running;
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /no longer matches its consumed snapshot/);
    await assert.rejects(fs.access(path.join(reportsDir, month, "source_manifest.json")));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("monitor cannot lower the production planned-site profile with --limit", async () => {
  const script = new URL("../monitor.mjs", import.meta.url);
  const month = shanghaiMonth();
  for (const limit of [1, 199]) {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), `sp-monitor-limit-${limit}-`));
    const dataDir = path.join(root, "data");
    const reportsDir = path.join(root, "reports");
    const engine = await writeFakeEngine(root);
    try {
      const result = await runNode([script.pathname, "--month", month, "--limit", String(limit)], {
        ...process.env,
        SP_SINGLE_PAGE_DATA_DIR: dataDir,
        SP_SINGLE_PAGE_REPORTS_DIR: reportsDir,
        SP_SINGLE_PAGE_TEST_MODE: "1",
        SP_SINGLE_PAGE_TEST_ENGINE: engine,
      });
      assert.notEqual(result.code, 0);
      assert.match(result.stderr, /canonical production profile of 200 sites/);
      await assert.rejects(fs.access(path.join(reportsDir, month, "source_manifest.json")));
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }
});

test("monitor accepts the canonical 200-site healthy production profile", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-monitor-limit-200-"));
  const dataDir = path.join(root, "data");
  const reportsDir = path.join(root, "reports");
  const month = shanghaiMonth();
  const engine = await writeFakeEngine(root);
  const script = new URL("../monitor.mjs", import.meta.url);
  try {
    const result = await runNode([script.pathname, "--month", month, "--limit", "200"], {
      ...process.env,
      SP_SINGLE_PAGE_DATA_DIR: dataDir,
      SP_SINGLE_PAGE_REPORTS_DIR: reportsDir,
      SP_SINGLE_PAGE_TEST_MODE: "1",
      SP_SINGLE_PAGE_TEST_ENGINE: engine,
    });
    assert.equal(result.code, 0, result.stderr);
    const validated = await validateDashboardSources({ dataDir, reportsDir, months: [month] });
    assert.equal(validated.sources[0].health.planned_sites, 200);
    assert.equal(validated.sources[0].health.status, "accepted");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("monitor writes percent-encoded Unicode hits under one canonical state product key", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-monitor-canonical-product-"));
  const dataDir = path.join(root, "data");
  const reportsDir = path.join(root, "reports");
  const month = shanghaiMonth();
  const engine = await writeFakeEngine(root, { hitMarker: "%F0%9F%A7%B8" });
  const script = new URL("../monitor.mjs", import.meta.url);
  try {
    const result = await runNode([script.pathname, "--month", month, "--limit", "200"], {
      ...process.env,
      SP_SINGLE_PAGE_DATA_DIR: dataDir,
      SP_SINGLE_PAGE_REPORTS_DIR: reportsDir,
      SP_SINGLE_PAGE_TEST_MODE: "1",
      SP_SINGLE_PAGE_TEST_ENGINE: engine,
    });
    assert.equal(result.code, 0, result.stderr);
    const state = JSON.parse(await fs.readFile(path.join(dataDir, "state.json"), "utf8"));
    assert.ok(state.products["site-0.example|🧸"]);
    assert.equal(state.products["site-0.example|🧸"].handle, "🧸");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("monitor fails closed when a fake 200-row engine forges zero coverage or a different Top200 plan", async () => {
  const script = new URL("../monitor.mjs", import.meta.url);
  const month = shanghaiMonth();
  const cases = [
    {
      name: "zero-coverage",
      sitesText: sitesCsv(Array.from({ length: 200 }, () => "complete"))
        .replaceAll(",complete,100,10,10", ",complete,0,10,10"),
    },
    {
      name: "plan-mismatch",
      planDomains: Array.from({ length: 200 }, (_, index) => `other-${index}.example`),
    },
  ];
  for (const attack of cases) {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), `sp-monitor-${attack.name}-`));
    try {
      const engine = await writeFakeEngine(root, attack);
      const result = await runNode([script.pathname, "--month", month, "--limit", "200"], {
        ...process.env, SP_SINGLE_PAGE_DATA_DIR: path.join(root, "data"), SP_SINGLE_PAGE_REPORTS_DIR: path.join(root, "reports"),
        SP_SINGLE_PAGE_TEST_MODE: "1", SP_SINGLE_PAGE_TEST_ENGINE: engine,
      });
      assert.notEqual(result.code, 0, `${attack.name}: ${result.stderr}`);
      await assert.rejects(fs.access(path.join(root, "reports", month, "source_manifest.json")));
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }
});

test("monitor authentication commit remains fail-closed at every crash prefix", async () => {
  const script = new URL("../monitor.mjs", import.meta.url);
  const month = shanghaiMonth();
  for (const point of ["after_manifest", "after_state", "after_latest"]) {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), `sp-monitor-crash-${point}-`));
    const dataDir = path.join(root, "data");
    const reportsDir = path.join(root, "reports");
    const engine = await writeFakeEngine(root, { hitMarker: point });
    try {
      const result = await runNode([script.pathname, "--month", month, "--limit", "200"], {
        ...process.env,
        SP_SINGLE_PAGE_DATA_DIR: dataDir,
        SP_SINGLE_PAGE_REPORTS_DIR: reportsDir,
        SP_SINGLE_PAGE_TEST_MODE: "1",
        SP_SINGLE_PAGE_TEST_ENGINE: engine,
        SP_SINGLE_PAGE_TEST_CONTRACT_FAIL_AT: point,
        SP_SINGLE_PAGE_TEST_CONTRACT_CRASH: "1",
      });
      assert.equal(result.signal, "SIGKILL", `${point}: ${result.stderr}`);
      const validation = validateDashboardSources({ dataDir, reportsDir, months: [month] });
      if (point === "after_latest") await validation;
      else await assert.rejects(validation);
      const recovered = await runNode([script.pathname, "--month", month, "--limit", "200"], {
        ...process.env,
        SP_SINGLE_PAGE_DATA_DIR: dataDir,
        SP_SINGLE_PAGE_REPORTS_DIR: reportsDir,
        SP_SINGLE_PAGE_TEST_MODE: "1",
        SP_SINGLE_PAGE_TEST_ENGINE: engine,
      });
      assert.equal(recovered.code, 0, `${point} recovery: ${recovered.stderr}`);
      await validateDashboardSources({ dataDir, reportsDir, months: [month] });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }
});

test("health checker uses the authoritative contract validator", async () => {
  const fixture = await setupFixture({ multi: false });
  const script = new URL("../check_health.mjs", import.meta.url);
  const env = {
    ...process.env,
    SP_SINGLE_PAGE_DATA_DIR: fixture.dataDir,
    SP_SINGLE_PAGE_REPORTS_DIR: fixture.reportsDir,
  };
  try {
    const valid = await runNode([script.pathname, "--json", "yes", "--grace-minutes", "100000"], env);
    assert.equal(valid.code, 0, valid.stderr);
    assert.equal(JSON.parse(valid.stdout).source_month, fixture.currentMonth);
    const hits = path.join(fixture.reportsDir, fixture.currentMonth, "hits.csv");
    const saved = path.join(fixture.root, "health-hits.csv");
    await fs.rename(hits, saved);
    await fs.symlink(saved, hits);
    const invalid = await runNode([script.pathname, "--json", "yes", "--grace-minutes", "100000"], env);
    assert.equal(invalid.code, 2);
    assert.match(invalid.stdout, /data_contract_invalid/);
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("health checker rejects a same-day non-dashboard artifact instead of trusting mtimes", async () => {
  const fixture = await setupFixture({ multi: false });
  const script = new URL("../check_health.mjs", import.meta.url);
  try {
    await fs.writeFile(path.join(fixture.reportsDir, "latest", "dashboard.html"), "THIS IS NOT A DASHBOARD");
    const result = await runNode([script.pathname, "--json", "yes", "--grace-minutes", "100000"], {
      ...process.env, SP_SINGLE_PAGE_DATA_DIR: fixture.dataDir, SP_SINGLE_PAGE_REPORTS_DIR: fixture.reportsDir,
    });
    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stdout, /data_contract_invalid/);
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("health freshness waits through midnight/grace and while running, but rejects a succeeded run bound to yesterday", async () => {
  const fixture = await setupFixture({
    multi: false,
    sourceMonth: "2026-07",
    sourceAt: "2026-07-31T15:30:00.000Z",
  });
  const script = new URL("../check_health.mjs", import.meta.url);
  const runHealth = (now) => runNode([script.pathname, "--json", "yes"], {
    ...process.env,
    SP_SINGLE_PAGE_DATA_DIR: fixture.dataDir,
    SP_SINGLE_PAGE_REPORTS_DIR: fixture.reportsDir,
    SP_SINGLE_PAGE_TEST_MODE: "1",
    SP_SINGLE_PAGE_TEST_NOW: now,
  });
  const writeStatus = (payload) => fs.writeFile(
    path.join(fixture.dataDir, "run_status.json"), JSON.stringify(payload, null, 2) + "\n",
  );
  try {
    for (const now of ["2026-07-31T16:30:00.000Z", "2026-08-01T03:00:00.000Z"]) {
      const result = await runHealth(now);
      assert.equal(result.code, 0, `${now}: ${result.stdout}\n${result.stderr}`);
      assert.equal(JSON.parse(result.stdout).source_fresh_today, false);
    }

    const afterGrace = await runHealth("2026-08-01T06:00:00.000Z");
    assert.equal(afterGrace.code, 2);
    assert.deepEqual(JSON.parse(afterGrace.stdout).issue_codes, ["not_completed"]);

    await writeStatus({
      state: "running", stage: "scan_current_month", pid: process.pid,
      started_at: "2026-08-01T05:55:00.000Z", heartbeat_at: "2026-08-01T06:00:00.000Z",
    });
    const running = await runHealth("2026-08-01T06:00:00.000Z");
    assert.equal(running.code, 0, running.stdout);

    await writeStatus({
      state: "succeeded", stage: "completed", pid: process.pid,
      started_at: "2026-08-01T05:00:00.000Z", finished_at: "2026-08-01T06:00:00.000Z",
    });
    const wronglyBound = await runHealth("2026-08-01T06:01:00.000Z");
    assert.equal(wronglyBound.code, 2);
    assert.deepEqual(JSON.parse(wronglyBound.stdout).issue_codes, ["data_contract_invalid"]);
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("enrichment coverage has strict integer bounds and explicit empty-input semantics", () => {
  assert.deepEqual(
    assertEnrichmentCoverage({ total: 0, succeeded: 0, thresholdPct: 60 }),
    { total: 0, succeeded: 0, failed: 0, coverage_pct: 100, threshold_pct: 60, empty_input: true, status: "accepted" },
  );
  assert.equal(assertEnrichmentCoverage({ total: 10, succeeded: 7, thresholdPct: 60 }).coverage_pct, 70);
  for (const invalid of [
    { total: NaN, succeeded: 0, thresholdPct: 60 },
    { total: -1, succeeded: 0, thresholdPct: 60 },
    { total: 1.5, succeeded: 1, thresholdPct: 60 },
    { total: 1, succeeded: 2, thresholdPct: 60 },
    { total: 1, succeeded: 1, thresholdPct: "60" },
    { total: 1, succeeded: 1, thresholdPct: NaN },
  ]) assert.throws(() => assertEnrichmentCoverage(invalid));
});

test("HTTP 200 with empty product/page metadata is not successful enrichment", () => {
  const emptyHttp200 = {
    source_detail: "html_meta",
    image_url: "",
    price: "",
    description: "",
    vendor: "",
    product_type: "",
    tags: [],
  };
  assert.equal(hasMeaningfulEnrichment(emptyHttp200), false);
  assert.equal(hasMeaningfulEnrichment({ ...emptyHttp200, source_detail: "product_json" }), false);
  assert.equal(hasMeaningfulEnrichment({ ...emptyHttp200, image_url: "https://example.com/product.jpg" }), true);
  assert.throws(
    () => assertEnrichmentCoverage({
      total: 10,
      succeeded: Array.from({ length: 10 }, () => emptyHttp200).filter(hasMeaningfulEnrichment).length,
      thresholdPct: 60,
    }),
    /enrichment coverage 0%/,
  );
});

test("builder refuses attempts to lower its canonical enrichment gate", async () => {
  const fixture = await setupFixture({ multi: false });
  const script = new URL("../build_dashboard.mjs", import.meta.url);
  try {
    const result = await runNode([script.pathname, "--verify-inputs-only", "--enrichment-min-coverage-pct", "1"], {
      ...process.env,
      SP_SINGLE_PAGE_DATA_DIR: fixture.dataDir,
      SP_SINGLE_PAGE_REPORTS_DIR: fixture.reportsDir,
    });
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /cannot be lower than canonical 60%/);
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});

test("builder refuses to overwrite latest with an explicitly selected older month", async () => {
  const fixture = await setupFixture({ multi: true });
  const script = new URL("../build_dashboard.mjs", import.meta.url);
  try {
    const result = await runNode([
      script.pathname, "--month", fixture.priorMonth, "--out", "latest", "--verify-inputs-only",
    ], {
      ...process.env,
      SP_SINGLE_PAGE_DATA_DIR: fixture.dataDir,
      SP_SINGLE_PAGE_REPORTS_DIR: fixture.reportsDir,
    });
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /latest dashboard output must include and bind authenticated latest month/);
  } finally {
    await fs.rm(fixture.root, { recursive: true, force: true });
  }
});
