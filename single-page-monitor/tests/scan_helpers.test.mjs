import test from "node:test";
import assert from "node:assert/strict";
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
} from "../lib/scan_helpers.mjs";

test("merges products.json dates with sitemap lastmod for the same handle", () => {
  const products = dedupeAndMergeProducts([
    {
      url: "https://example.com/products/widget",
      handle: "widget",
      product_title: "Widget",
      created_at: "2026-06-01T00:00:00Z",
      updated_at: "2026-06-20T00:00:00Z",
      source: "products_json",
    },
    {
      url: "https://example.com/fr/products/widget?variant=1",
      handle: "widget",
      lastmod: "2026-07-14T00:00:00Z",
      source: "sitemap",
    },
  ]);

  assert.equal(products.length, 1);
  assert.equal(products[0].url, "https://example.com/products/widget");
  assert.equal(products[0].product_title, "Widget");
  assert.equal(products[0].lastmod, "2026-07-14T00:00:00Z");
  assert.equal(products[0].source, "products_json+sitemap");
});

test("recognizes Shopify password, member login, and bot challenge pages", () => {
  assert.equal(
    detectAccessIssue({ status: 200, finalUrl: "https://example.com/password", text: "<html></html>" }),
    "password_page"
  );
  assert.equal(
    detectAccessIssue({
      status: 200,
      finalUrl: "https://example.com/products/widget",
      text: '<body class="template-password"><div class="shopify-section-password"></div></body>',
    }),
    "password_page"
  );
  assert.equal(
    detectAccessIssue({
      status: 200,
      finalUrl: "https://example.com/products/widget",
      text: "<title>Members only login</title><p>Sign in to view this product</p>",
    }),
    "member_login"
  );
  assert.equal(
    detectAccessIssue({ status: 200, finalUrl: "https://example.com", text: '<title>Just a moment</title><p>Verify you are human</p><script src="/cdn-cgi/challenge-platform/x"></script>' }),
    "bot_challenge"
  );
});

test("does not flag ordinary product copy as a member gate", () => {
  assert.equal(
    detectAccessIssue({
      status: 200,
      finalUrl: "https://example.com/products/widget",
      text: "<title>Widget</title><p>Members only receive an extra coupon.</p>",
    }),
    ""
  );
  assert.equal(
    detectAccessIssue({
      status: 200,
      finalUrl: "https://example.com/products/widget",
      text: '<title>Widget</title><script src="/cdn-cgi/challenge-platform/widget.js"></script><div class="g-recaptcha"></div>',
    }),
    ""
  );
});

test("reports coverage and scan quality consistently", () => {
  assert.equal(scanQuality({ candidates: 10, sampled: 10 }), "complete");
  assert.equal(scanQuality({ candidates: 10, sampled: 8 }), "partial");
  assert.equal(scanQuality({ candidates: 10, sampled: 0, blocked: 10 }), "blocked");
  assert.equal(scanQuality({ candidates: 0, discoveryIssue: "password_page" }), "blocked");
  assert.equal(scanQuality({ candidates: 0 }), "no_candidates");
  assert.equal(coveragePercent(8, 10), 80);
  assert.equal(coveragePercent(0, 0), 100);
});

test("only retries browser-solvable failures", () => {
  assert.equal(shouldTryBrowserFallback("bot_challenge"), true);
  assert.equal(shouldTryBrowserFallback("network_error"), true);
  assert.equal(shouldTryBrowserFallback("page_timeout"), false);
  assert.equal(shouldTryBrowserFallback("password_page"), false);
  assert.equal(shouldTryBrowserFallback("login_required"), false);
});

test("rejects scan settings that would silently produce an empty or stale run", () => {
  const valid = {
    month: "2026-07",
    limit: 200,
    workers: 6,
    max_json_pages: 6,
    max_created: 80,
    max_updated: 35,
    checkpoint_every: 10,
    timeout: 30000,
    page_timeout: 12000,
    min_request_interval_ms: 900,
    request_jitter_ms: 500,
    backoff_base_ms: 2000,
    backoff_max_ms: 60000,
    max_consecutive_failures: 3,
    cache_ttl_hours: 18,
    cache_max_entries: 50000,
    fetch_mode: "auto",
  };
  assert.equal(validateScanOptions(valid), valid);
  assert.throws(() => validateScanOptions({ ...valid, month: "2026-13" }), /month must use YYYY-MM/);
  assert.throws(() => validateScanOptions({ ...valid, workers: 0 }), /workers must be a positive integer/);
  assert.throws(() => validateScanOptions({ ...valid, fetch_mode: "fast" }), /fetch_mode must be auto/);
  assert.throws(() => validateScanOptions({ ...valid, cache_max_entries: 0 }), /cache_max_entries must be a positive integer/);
  assert.throws(() => validateScanOptions({ ...valid, backoff_max_ms: 1000 }), /greater than or equal/);
});

test("parses Retry-After and applies capped exponential backoff", () => {
  assert.equal(parseRetryAfter("3"), 3000);
  assert.equal(parseRetryAfter("Wed, 15 Jul 2026 00:00:10 GMT", Date.parse("2026-07-15T00:00:00Z")), 10000);
  assert.equal(parseRetryAfter("invalid"), 0);
  assert.equal(exponentialBackoffMs(1, 2000, 60000, 0.5), 2000);
  assert.equal(exponentialBackoffMs(6, 2000, 30000, 0.5), 30000);
});

test("classification cache requires matching signal, classifier, and TTL", () => {
  const nowMs = Date.parse("2026-07-14T12:00:00Z");
  const entry = {
    fetched_at: "2026-07-14T02:00:00Z",
    signal_date: "2026-07-14T01:00:00Z",
    classifier_version: "v3",
    evidence: { classification: "custom_single_page" },
  };
  const product = { signal_date: "2026-07-14T01:00:00Z" };
  assert.equal(isClassificationCacheFresh(entry, product, { nowMs, ttlHours: 18, classifierVersion: "v3" }), true);
  assert.equal(isClassificationCacheFresh(entry, product, { nowMs, ttlHours: 8, classifierVersion: "v3" }), false);
  assert.equal(isClassificationCacheFresh(entry, { signal_date: "changed" }, { nowMs, ttlHours: 18, classifierVersion: "v3" }), false);
  assert.equal(isClassificationCacheFresh(entry, product, { nowMs, ttlHours: 18, classifierVersion: "v4" }), false);
});

test("prunes cache by newest fetch time", () => {
  const pruned = pruneClassificationCache({
    old: { fetched_at: "2026-07-13T00:00:00Z" },
    newest: { fetched_at: "2026-07-14T02:00:00Z" },
    middle: { fetched_at: "2026-07-14T01:00:00Z" },
  }, 2);
  assert.deepEqual(Object.keys(pruned), ["newest", "middle"]);
});

test("opens the circuit after repeated throttles or a long Retry-After", () => {
  let state = { consecutiveFailures: 0, circuitOpen: false, circuitReason: "" };
  for (let index = 0; index < 2; index += 1) {
    state = updateCircuitBreakerState(state, { status: 429, access_issue: "rate_limited" }, {
      maxConsecutiveFailures: 3,
      maxRetryAfterMs: 60000,
    });
    assert.equal(state.circuitOpen, false);
  }
  state = updateCircuitBreakerState(state, { status: 429, access_issue: "rate_limited" }, {
    maxConsecutiveFailures: 3,
    maxRetryAfterMs: 60000,
  });
  assert.equal(state.circuitOpen, true);
  assert.equal(state.circuitReason, "rate_limited:3");

  const longRetry = updateCircuitBreakerState(
    { consecutiveFailures: 0, circuitOpen: false, circuitReason: "" },
    { status: 429, access_issue: "rate_limited", retry_after_ms: 120000 },
    { maxConsecutiveFailures: 3, maxRetryAfterMs: 60000 }
  );
  assert.equal(longRetry.circuitOpen, true);
  assert.equal(longRetry.circuitReason, "rate_limited:retry_after_120s");
});

test("resets transient failure streak after a successful response", () => {
  const state = updateCircuitBreakerState(
    { consecutiveFailures: 2, circuitOpen: false, circuitReason: "" },
    { status: 200, access_issue: "", text: "ok" }
  );
  assert.equal(state.consecutiveFailures, 0);
  assert.equal(state.circuitOpen, false);
});

test("a single page timeout is skipped without opening the site circuit", () => {
  const state = updateCircuitBreakerState(
    { consecutiveFailures: 2, circuitOpen: false, circuitReason: "" },
    { status: 0, access_issue: "page_timeout", error: "TimeoutError" }
  );
  assert.equal(state.consecutiveFailures, 0);
  assert.equal(state.circuitOpen, false);
});
