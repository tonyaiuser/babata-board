function cleanUrl(value) {
  return String(value || "").split("?")[0].replace(/\/$/, "");
}

function handleFromUrl(value) {
  try {
    const url = new URL(value);
    const match = url.pathname.match(/\/products\/([^/?#]+)/i);
    return match ? decodeURIComponent(match[1]).toLowerCase() : "";
  } catch {
    return "";
  }
}

function latestValue(a, b) {
  return [String(a || ""), String(b || "")].sort().at(-1) || "";
}

function sourceParts(value) {
  return String(value || "").split("+").map((item) => item.trim()).filter(Boolean);
}

export function productIdentity(product) {
  const handle = String(product?.handle || "").trim().toLowerCase() || handleFromUrl(product?.url);
  if (handle) return `handle:${handle}`;
  return `url:${cleanUrl(product?.url)}`;
}

export function mergeProducts(existing, incoming) {
  const sources = [...new Set([...sourceParts(existing.source), ...sourceParts(incoming.source)])];
  const existingIsJson = sourceParts(existing.source).includes("products_json");
  const incomingIsJson = sourceParts(incoming.source).includes("products_json");
  const preferredUrl = incomingIsJson && !existingIsJson ? incoming.url : existing.url || incoming.url;
  return {
    ...existing,
    ...Object.fromEntries(
      Object.entries(incoming).filter(([, value]) => value !== "" && value !== null && value !== undefined)
    ),
    url: cleanUrl(preferredUrl),
    handle: existing.handle || incoming.handle || handleFromUrl(preferredUrl),
    product_title: existing.product_title || incoming.product_title || "",
    created_at: existing.created_at || incoming.created_at || "",
    published_at: existing.published_at || incoming.published_at || "",
    updated_at: latestValue(existing.updated_at, incoming.updated_at),
    lastmod: latestValue(existing.lastmod, incoming.lastmod),
    source: sources.join("+"),
  };
}

// Shopify product sitemaps often repeat the same handle under locale-prefixed URLs.
// Merge those records so their lastmod evidence is retained without rescanning the
// same product several times.
export function dedupeAndMergeProducts(products) {
  const merged = new Map();
  for (const raw of products) {
    const product = { ...raw, url: cleanUrl(raw.url) };
    const key = productIdentity(product);
    if (!product.url || key === "url:") continue;
    merged.set(key, merged.has(key) ? mergeProducts(merged.get(key), product) : product);
  }
  return [...merged.values()];
}

function normalizedPath(value) {
  try {
    return new URL(value).pathname.replace(/\/+$/, "") || "/";
  } catch {
    return "";
  }
}

export function detectAccessIssue({ status = 0, finalUrl = "", text = "" } = {}) {
  const code = Number(status || 0);
  if (!code) return "network_error";
  if (code === 401) return "login_required";
  if (code === 402) return "payment_required";
  if (code === 403) return "forbidden";
  if (code === 429) return "rate_limited";
  if (code >= 500) return "server_error";

  const path = normalizedPath(finalUrl).toLowerCase();
  if (path === "/password" || path.endsWith("/password")) return "password_page";
  if (/\/(account\/login|auth\/login|users\/sign_in|member\/login)$/.test(path)) return "login_required";
  if (/\/(challenge|checkpoint)(\/|$)/.test(path)) return "bot_challenge";

  const lower = String(text || "").slice(0, 350000).toLowerCase();
  if (!lower.trim()) return "empty_response";
  if (
    lower.includes("shopify-section-password") ||
    lower.includes("template-password") ||
    lower.includes("password-modal__content") ||
    (lower.includes("/password") && lower.includes("enter using password"))
  ) {
    return "password_page";
  }
  const challengeCopy =
    lower.includes("verify you are human") ||
    lower.includes("checking your browser") ||
    lower.includes("performing security verification") ||
    /<title[^>]*>[^<]*(just a moment|attention required|security check|human verification)[^<]*<\/title>/i.test(text);
  const challengeRuntime =
    lower.includes("cf-chl-") ||
    lower.includes("challenge-platform") ||
    lower.includes("/cdn-cgi/challenge-platform") ||
    lower.includes("g-recaptcha") ||
    lower.includes("hcaptcha");
  if (challengeCopy && challengeRuntime) {
    return "bot_challenge";
  }
  if (
    /<title[^>]*>[^<]*(members? only|sign in|log in|login)[^<]*<\/title>/i.test(text) &&
    /(sign in to (view|continue)|log in to (view|continue)|members? only|wholesale login)/i.test(text)
  ) {
    return "member_login";
  }
  return "";
}

export function shouldTryBrowserFallback(issue) {
  return ["network_error", "forbidden", "rate_limited", "server_error", "bot_challenge", "empty_response"].includes(issue);
}

export function scanQuality({ candidates = 0, sampled = 0, blocked = 0, discoveryIssue = "" } = {}) {
  const total = Number(candidates || 0);
  const ok = Number(sampled || 0);
  if (!total) return discoveryIssue ? "blocked" : "no_candidates";
  if (!ok) return blocked ? "blocked" : "incomplete";
  return ok / total >= 0.9 ? "complete" : "partial";
}

export function coveragePercent(sampled, candidates) {
  const total = Number(candidates || 0);
  if (!total) return 100;
  return Math.round((Number(sampled || 0) / total) * 1000) / 10;
}

export function validateScanOptions(options) {
  const errors = [];
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(String(options.month || ""))) {
    errors.push("month must use YYYY-MM");
  }
  for (const key of ["limit", "workers", "max_json_pages", "checkpoint_every"]) {
    if (!Number.isInteger(Number(options[key])) || Number(options[key]) < 1) {
      errors.push(`${key} must be a positive integer`);
    }
  }
  for (const key of ["max_created", "max_updated"]) {
    if (!Number.isInteger(Number(options[key])) || Number(options[key]) < 0) {
      errors.push(`${key} must be a non-negative integer`);
    }
  }
  for (const key of ["timeout", "page_timeout"]) {
    if (!Number.isFinite(Number(options[key])) || Number(options[key]) < 1000) {
      errors.push(`${key} must be at least 1000 ms`);
    }
  }
  for (const key of ["min_request_interval_ms", "request_jitter_ms", "backoff_base_ms", "backoff_max_ms"]) {
    if (!Number.isFinite(Number(options[key])) || Number(options[key]) < 0) {
      errors.push(`${key} must be a non-negative number`);
    }
  }
  if (!Number.isInteger(Number(options.max_consecutive_failures)) || Number(options.max_consecutive_failures) < 1) {
    errors.push("max_consecutive_failures must be a positive integer");
  }
  if (!Number.isFinite(Number(options.cache_ttl_hours)) || Number(options.cache_ttl_hours) < 0) {
    errors.push("cache_ttl_hours must be a non-negative number");
  }
  if (!Number.isInteger(Number(options.cache_max_entries)) || Number(options.cache_max_entries) < 1) {
    errors.push("cache_max_entries must be a positive integer");
  }
  if (Number(options.backoff_max_ms) < Number(options.backoff_base_ms)) {
    errors.push("backoff_max_ms must be greater than or equal to backoff_base_ms");
  }
  if (!new Set(["auto", "request", "page"]).has(options.fetch_mode)) {
    errors.push("fetch_mode must be auto, request, or page");
  }
  if (errors.length) throw new Error(`Invalid scan options: ${errors.join("; ")}`);
  return options;
}

export function parseRetryAfter(value, nowMs = Date.now()) {
  const text = String(value || "").trim();
  if (!text) return 0;
  if (/^\d+(\.\d+)?$/.test(text)) return Math.max(0, Math.round(Number(text) * 1000));
  const dateMs = Date.parse(text);
  return Number.isFinite(dateMs) ? Math.max(0, dateMs - nowMs) : 0;
}

export function exponentialBackoffMs(attempt, baseMs, maxMs, randomValue = Math.random()) {
  const exponent = Math.max(0, Number(attempt || 1) - 1);
  const raw = Math.min(Number(maxMs), Number(baseMs) * (2 ** exponent));
  const jitter = 0.75 + Math.max(0, Math.min(1, Number(randomValue))) * 0.5;
  return Math.max(0, Math.round(raw * jitter));
}

export function updateCircuitBreakerState(
  state,
  result,
  { maxConsecutiveFailures = 3, maxRetryAfterMs = 60000 } = {}
) {
  const next = { ...state };
  const issue = result?.access_issue || detectAccessIssue(result);
  if (Number(result?.status) === 200 && !issue) {
    next.consecutiveFailures = 0;
    return next;
  }
  if (["password_page", "login_required", "member_login", "payment_required"].includes(issue)) {
    next.circuitOpen = true;
    next.circuitReason = issue;
    return next;
  }
  if (["forbidden", "rate_limited", "bot_challenge", "server_error", "network_error", "empty_response"].includes(issue)) {
    next.consecutiveFailures = Number(next.consecutiveFailures || 0) + 1;
    const retryAfterMs = Number(result?.retry_after_ms || 0);
    if (retryAfterMs > Number(maxRetryAfterMs)) {
      next.circuitOpen = true;
      next.circuitReason = `${issue}:retry_after_${Math.round(retryAfterMs / 1000)}s`;
    } else if (next.consecutiveFailures >= Number(maxConsecutiveFailures)) {
      next.circuitOpen = true;
      next.circuitReason = `${issue}:${next.consecutiveFailures}`;
    }
    return next;
  }

  // Missing or removed product pages should not trip a site-wide breaker.
  next.consecutiveFailures = 0;
  return next;
}

export function isClassificationCacheFresh(
  entry,
  product,
  { nowMs = Date.now(), ttlHours = 18, classifierVersion = "" } = {}
) {
  if (!entry?.fetched_at || !entry?.evidence) return false;
  if (classifierVersion && entry.classifier_version !== classifierVersion) return false;
  if (String(entry.signal_date || "") !== String(product?.signal_date || "")) return false;
  const fetchedMs = Date.parse(entry.fetched_at);
  if (!Number.isFinite(fetchedMs)) return false;
  return nowMs - fetchedMs >= 0 && nowMs - fetchedMs <= Number(ttlHours) * 3600000;
}

export function pruneClassificationCache(entries, maxEntries = 50000) {
  return Object.fromEntries(
    Object.entries(entries || {})
      .sort(([, a], [, b]) => String(b?.fetched_at || "").localeCompare(String(a?.fetched_at || "")))
      .slice(0, Math.max(0, Number(maxEntries || 0)))
  );
}
