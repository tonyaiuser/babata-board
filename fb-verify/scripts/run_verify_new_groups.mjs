// 每日增量 FB 广告库验证 runner。
//
// 从一次性脚本 run_full_verify.mjs 迁移而来，改动点：
//   - 所有路径通过 CLI 参数传入（--unique-json / --checkpoint-json / --verify-script / --log-file）
//   - 单日查询上限（--max-groups，默认 40），超出的截断到明天（明天的 todo 列表会重新算，
//     被截断的组仍然是 already_verified=false 且没有 checkpoint 记录，会在下一次运行时补上）
//   - 连续 N 组空结果（--blank-streak，默认 5）直接终止退出（不像一次性脚本那样等 10 分钟
//     重试一次），因为这是每日定时任务，明天会自愈，没必要在 launchd 里挂起整个任务
//
// 用法:
//   node run_verify_new_groups.mjs \
//     --unique-json data/2026-07/unique_products.json \
//     --checkpoint-json data/2026-07/product_verify_full.json \
//     --verify-script scripts/fb_product_verify.mjs \
//     --log-file /path/to/fb_verify.log \
//     [--max-groups 40] [--blank-streak 5]

import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = (i + 1 < argv.length && !argv[i + 1].startsWith('--')) ? argv[++i] : true;
      out[key] = val;
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const UNIQUE_JSON = args['unique-json'];
const CHECKPOINT_JSON = args['checkpoint-json'];
const VERIFY_SCRIPT = args['verify-script'];
const LOG_FILE = args['log-file'];
const MAX_GROUPS = parseInt(args['max-groups'] || '40', 10);
const BLANK_STREAK_LIMIT = parseInt(args['blank-streak'] || '5', 10);
const RECORD_SCHEMA_VERSION = 2;
const CHECKPOINT_SCHEMA_VERSION = 2;
const RUNNER_PRODUCER = 'fb-verify-runner';

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

function sleep(ms) { return new Promise(res => setTimeout(res, ms)); }
function randSleepMs() {
  if (process.env.FB_VERIFY_TEST_NO_SLEEP === '1') return 0;
  return 8000 + Math.floor(Math.random() * 6000);
} // 8-14s

function fsyncDirectory(directory) {
  let fd;
  try {
    fd = fs.openSync(directory, 'r');
    fs.fsyncSync(fd);
  } catch {}
  finally { if (fd !== undefined) fs.closeSync(fd); }
}

function atomicWriteFileSync(target, contents) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temporary = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );
  let fd;
  try {
    fd = fs.openSync(temporary, 'wx');
    fs.writeFileSync(fd, contents, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporary, target);
    fsyncDirectory(path.dirname(target));
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
}

function loadCheckpoint() {
  if (!fs.existsSync(CHECKPOINT_JSON)) {
    return {
      schema_version: CHECKPOINT_SCHEMA_VERSION,
      producer: RUNNER_PRODUCER,
      generated_at: new Date().toISOString(),
      groups: {},
    };
  }
  let data;
  try {
    data = JSON.parse(fs.readFileSync(CHECKPOINT_JSON, 'utf8'));
  } catch (e) {
    throw new Error(`checkpoint is unreadable; refusing to overwrite ${CHECKPOINT_JSON}: ${e.message}`);
  }
  try {
    return migrateCheckpoint(data);
  } catch (error) {
    throw new Error(`checkpoint has an invalid schema; refusing to overwrite ${CHECKPOINT_JSON}: ${error.message}`);
  }
}

function saveCheckpoint(state) {
  state.schema_version = CHECKPOINT_SCHEMA_VERSION;
  state.producer = RUNNER_PRODUCER;
  state.updated_at = new Date().toISOString();
  atomicWriteFileSync(CHECKPOINT_JSON, JSON.stringify(state, null, 2) + '\n');
}

function coreStems(query) {
  const stop = new Set(['with', 'for', 'and', 'the', 'to', 'of', 'a', 'an', 'in', 'on', 'at', '1', 'pro']);
  return query
    .toLowerCase()
    .replace(/[^a-z0-9\s\-]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length >= 3 && !stop.has(w));
}

function countStemHits(text, stems) {
  if (!text) return 0;
  const low = text.toLowerCase();
  let n = 0;
  for (const s of stems) if (low.includes(s)) n++;
  return n;
}

function stripUrls(text) {
  return (text || '').replace(/https?:\/\/\S+/gi, ' ');
}

function isInconclusiveResponse(apiResult) {
  return classifyVerificationState({
    response_http_status: apiResult?.http_status ?? null,
    fb_total_reported: apiResult?.total_reported ?? null,
    harvested: apiResult?.harvested ?? 0,
    sample: apiResult?.sample || [],
    relevant_ads_count: 0,
  }) === 'inconclusive';
}

function isSuccessfulHttpStatus(value) {
  const status = Number(value);
  return Number.isInteger(status) && status >= 200 && status <= 299;
}

function isFiniteZero(value) {
  if (value === null || value === undefined || typeof value === 'boolean'
      || (typeof value === 'string' && !value.trim())) return false;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric === 0;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normalizeLegacyInteger(value, field, nullable = true) {
  if ((value === null || value === undefined) && nullable) return null;
  if (typeof value === 'boolean') throw new Error(`invalid ${field}`);
  if (typeof value === 'string') {
    const stripped = value.trim();
    let parsed;
    if (/^[0-9]+$/.test(stripped)) parsed = Number(stripped);
    if (/^[0-9]{1,3}(?:,[0-9]{3})+$/.test(stripped)) {
      parsed = Number(stripped.replaceAll(',', ''));
    }
    if (Number.isSafeInteger(parsed) && parsed >= 0) return parsed;
    throw new Error(`invalid ${field}`);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  throw new Error(`invalid ${field}`);
}

function canonicalAlias(record, canonical, alias) {
  const canonicalPresent = record[canonical] !== undefined;
  const aliasPresent = record[alias] !== undefined;
  if (canonicalPresent && aliasPresent) {
    const left = normalizeLegacyInteger(record[canonical], canonical);
    const right = normalizeLegacyInteger(record[alias], alias);
    if (left !== right) {
      throw new Error(`conflicting ${canonical}/${alias} fields`);
    }
  }
  return canonicalPresent ? record[canonical] : (aliasPresent ? record[alias] : null);
}

// Core classification accepts canonical persisted field names only. API aliases
// are normalized by analyze(), and legacy aliases only by migrateLegacyRecord().
function classifyVerificationState(record, relevantAdsCount = undefined) {
  if (!record) return 'inconclusive';
  const relevant = relevantAdsCount === undefined
    ? Number(record.relevant_ads_count || 0)
    : Number(relevantAdsCount || 0);
  const sampled = Math.max(
    Number(record.harvested || 0),
    Array.isArray(record.sample) ? record.sample.length : 0,
    Array.isArray(record.relevant_ads) ? record.relevant_ads.length : 0,
  );
  if (sampled > 0) return relevant > 0 ? 'positive' : 'sample_negative';
  if (relevant > 0) return 'inconclusive';
  if (isSuccessfulHttpStatus(record.response_http_status)
      && Number(record.harvested) === 0
      && isFiniteZero(record.fb_total_reported)) return 'explicit_zero';
  return 'inconclusive';
}

function validateCanonicalRecord(record) {
  if (!isPlainObject(record)) throw new Error('verification record must be an object');
  if (record.http_status !== undefined || record.total_reported !== undefined) {
    throw new Error('schema2 record contains legacy response aliases');
  }
  if (record.response_http_status !== null && record.response_http_status !== undefined
      && (typeof record.response_http_status !== 'number'
          || !Number.isInteger(record.response_http_status)
          || record.response_http_status < 100
          || record.response_http_status > 599)) {
    throw new Error('invalid response_http_status');
  }
  for (const field of ['fb_total_reported', 'harvested', 'relevant_ads_count']) {
    if (record[field] !== null && record[field] !== undefined) {
      if (typeof record[field] !== 'number'
          || !Number.isSafeInteger(record[field]) || record[field] < 0) {
        throw new Error(`invalid ${field}`);
      }
    }
  }
  if (record.sample !== undefined && !Array.isArray(record.sample)) {
    throw new Error('sample must be an array');
  }
  if (record.relevant_ads !== undefined && !Array.isArray(record.relevant_ads)) {
    throw new Error('relevant_ads must be an array');
  }
  const inferred = classifyVerificationState(record);
  const stated = record.verification_state || inferred;
  if (!['positive', 'sample_negative', 'explicit_zero', 'inconclusive'].includes(stated)) {
    throw new Error(`unknown verification_state: ${stated}`);
  }
  if (stated !== inferred) {
    throw new Error(`verification_state ${stated} contradicts evidence (${inferred})`);
  }
  return stated;
}

function migrateLegacyRecord(record) {
  if (!isPlainObject(record)) throw new Error('legacy verification record must be an object');
  const migrated = { ...record };
  migrated.response_http_status = normalizeLegacyInteger(
    canonicalAlias(record, 'response_http_status', 'http_status'), 'response_http_status',
  );
  migrated.fb_total_reported = normalizeLegacyInteger(
    canonicalAlias(record, 'fb_total_reported', 'total_reported'), 'fb_total_reported',
  );
  for (const field of ['harvested', 'relevant_ads_count']) {
    if (migrated[field] !== undefined) {
      migrated[field] = normalizeLegacyInteger(migrated[field], field);
    }
  }
  delete migrated.http_status;
  delete migrated.total_reported;
  migrated.verification_state = record.verification_state
    || classifyVerificationState(migrated);
  migrated.schema_version = RECORD_SCHEMA_VERSION;
  migrated.producer = RUNNER_PRODUCER;
  migrated.migrated_from_schema = 1;
  validateCanonicalRecord(migrated);
  return migrated;
}

function migrateVerificationRecord(record) {
  if (!isPlainObject(record)) throw new Error('verification record must be an object');
  const legacy = record.schema_version === undefined || record.schema_version === 1;
  if (legacy) {
    if (record.producer !== undefined && record.producer !== RUNNER_PRODUCER) {
      throw new Error(`unsupported legacy verification producer: ${record.producer}`);
    }
    return migrateLegacyRecord(record);
  }
  if (record.schema_version !== RECORD_SCHEMA_VERSION || record.producer !== RUNNER_PRODUCER) {
    throw new Error(`unsupported verification record schema/producer: ${record.schema_version}/${record.producer}`);
  }
  validateCanonicalRecord(record);
  return { ...record };
}

function migrateCheckpoint(data) {
  if (!isPlainObject(data) || !isPlainObject(data.groups)
      || (data.retry_errors !== undefined && !isPlainObject(data.retry_errors))) {
    throw new Error('checkpoint containers are invalid');
  }
  const legacy = data.schema_version === undefined || data.schema_version === 1;
  if (legacy && data.producer !== undefined && data.producer !== RUNNER_PRODUCER) {
    throw new Error(`unsupported legacy checkpoint producer: ${data.producer}`);
  }
  if (!legacy && (data.schema_version !== CHECKPOINT_SCHEMA_VERSION
      || data.producer !== RUNNER_PRODUCER)) {
    throw new Error(`unsupported checkpoint schema/producer: ${data.schema_version}/${data.producer}`);
  }
  const migrated = { ...data, groups: {} };
  for (const [gid, record] of Object.entries(data.groups)) {
    migrated.groups[gid] = migrateVerificationRecord(record);
  }
  migrated.schema_version = CHECKPOINT_SCHEMA_VERSION;
  migrated.producer = RUNNER_PRODUCER;
  if (legacy) migrated.migrated_from_schema = 1;
  return migrated;
}

function isCompletedRecord(record) {
  if (!isPlainObject(record)
      || record.schema_version !== RECORD_SCHEMA_VERSION
      || record.producer !== RUNNER_PRODUCER) return false;
  try {
    const state = validateCanonicalRecord(record);
    return ['positive', 'sample_negative', 'explicit_zero'].includes(state);
  } catch {
    return false;
  }
}

function extractDomainFromCaptionOrLink(caption, linkUrl) {
  if (caption) {
    const m = caption.match(/([a-z0-9-]+\.[a-z]{2,})/i);
    if (m) return m[1].toLowerCase();
  }
  if (linkUrl) {
    try {
      const u = new URL(linkUrl);
      return u.hostname.replace(/^www\./, '').toLowerCase();
    } catch {}
  }
  return null;
}

function analyze(group, query, apiResult) {
  const stems = coreStems(query);
  const sample = (apiResult && apiResult.sample) || [];
  const totalReported = apiResult
    ? normalizeLegacyInteger(apiResult.total_reported, 'fb_total_reported')
    : null;

  const relevant = [];
  let contentMatchedCount = 0;
  let landingOnlyMatchedCount = 0;
  for (const ad of sample) {
    const contentText = stripUrls([ad.title, ad.body].filter(Boolean).join(' '));
    const landingText = [ad.link_url, ad.caption].filter(Boolean).join(' ');
    const contentHits = countStemHits(contentText, stems);
    const landingHits = countStemHits(landingText, stems);
    if (contentHits < 2 && landingHits < 2) continue;
    const relevanceBasis = contentHits >= 2 ? 'content' : 'landing_url';
    if (relevanceBasis === 'content') contentMatchedCount++;
    else landingOnlyMatchedCount++;
    relevant.push({ ...ad, relevance_basis: relevanceBasis });
  }

  const domainSet = new Set();
  for (const ad of relevant) {
    const d = extractDomainFromCaptionOrLink(ad.caption, ad.link_url);
    if (d) domainSet.add(d);
  }
  const crossSiteDomains = [...domainSet];

  const memberDomains = group.members.map(m => m.domain.replace(/^www\./, ''));
  const ownDomainHit = crossSiteDomains.some(d => memberDomains.some(md => d.includes(md) || md.includes(d)));

  const now = Date.now() / 1000;
  const startDates = relevant.map(a => a.start_date).filter(v => typeof v === 'number' && v > 0);
  let maxRunDays = null;
  if (startDates.length > 0) maxRunDays = Math.round((now - Math.min(...startDates)) / 86400);

  const formatCounts = {};
  for (const ad of relevant) {
    const f = ad.display_format || 'UNKNOWN';
    formatCounts[f] = (formatCounts[f] || 0) + 1;
  }

  const record = {
    schema_version: RECORD_SCHEMA_VERSION,
    producer: RUNNER_PRODUCER,
    group_id: group.group_id,
    query,
    fb_total_reported: totalReported,
    harvested: apiResult
      ? normalizeLegacyInteger(apiResult.harvested ?? 0, 'harvested', false)
      : 0,
    response_http_status: apiResult
      ? normalizeLegacyInteger(apiResult.http_status, 'response_http_status')
      : null,
    sample_scope: apiResult?.sample_scope || 'first_page',
    sample_limited: Boolean(apiResult?.sample_limited || ((apiResult?.harvested || 0) >= 30 && !apiResult?.total_reported)),
    relevant_ads_count: relevant.length,
    content_matched_ads_count: contentMatchedCount,
    landing_only_matched_ads_count: landingOnlyMatchedCount,
    cross_site_domains: crossSiteDomains,
    cross_site_domains_count: crossSiteDomains.length,
    own_domain_hit: ownDomainHit,
    max_run_days: maxRunDays,
    formats: formatCounts,
    relevant_ads: relevant,
    error: null,
    verified_at: new Date().toISOString(),
  };
  record.verification_state = classifyVerificationState(record);
  validateCanonicalRecord(record);
  return record;
}

async function main() {
  if (!UNIQUE_JSON || !CHECKPOINT_JSON || !VERIFY_SCRIPT || !LOG_FILE) {
    console.error('missing required args: --unique-json --checkpoint-json --verify-script --log-file');
    process.exit(2);
  }
  if (!fs.existsSync(UNIQUE_JSON)) {
    log(`unique-json not found: ${UNIQUE_JSON} — nothing to verify, exiting.`);
    console.log('VERIFY_SUMMARY_JSON ' + JSON.stringify({
      todo: 0,
      verified: 0,
      verified_group_ids: [],
      failed: 0,
      failed_group_ids: [],
      truncated: 0,
      terminated_early: false,
      pending: 0,
    }));
    return;
  }
  let unique;
  try {
    unique = JSON.parse(fs.readFileSync(UNIQUE_JSON, 'utf8'));
  } catch (e) {
    throw new Error(`unique groups file is unreadable; refusing to continue: ${UNIQUE_JSON}: ${e.message}`);
  }
  if (!unique || typeof unique !== 'object' || !Array.isArray(unique.groups)) {
    throw new Error(`unique groups file has an invalid schema; refusing to continue: ${UNIQUE_JSON}`);
  }
  const allGroups = (unique.groups || []).filter(group => !group.quarantined);
  const seenGroupIds = new Set();
  const reusableResults = new Map();
  for (const group of allGroups) {
    if (!isPlainObject(group) || typeof group.group_id !== 'string' || !group.group_id
        || typeof group.query !== 'string' || !Array.isArray(group.members)) {
      throw new Error(`unique groups file has an invalid group schema; refusing to continue: ${UNIQUE_JSON}`);
    }
    if (seenGroupIds.has(group.group_id)) {
      throw new Error(`duplicate active group_id ${group.group_id}; refusing to continue`);
    }
    seenGroupIds.add(group.group_id);
    if (group.already_verified) {
      if (!isPlainObject(group.verify_result)) {
        throw new Error(`reused result is missing for ${group.group_id}; refusing to continue`);
      }
      // Validate every reusable result before any checkpoint mutation. Unknown
      // schemas and contradictory evidence fail closed; strict schema1 data is
      // migrated in memory and may be reused only when terminal.
      reusableResults.set(group.group_id, migrateVerificationRecord(group.verify_result));
    }
  }
  log(`Loaded ${allGroups.length} active groups from ${UNIQUE_JSON}`);

  const state = loadCheckpoint();
  const monthPattern = /^\d{4}-(0[1-9]|1[0-2])$/;
  if (unique.month !== undefined && !monthPattern.test(unique.month)) {
    throw new Error(`unique state has an invalid month: ${unique.month}`);
  }
  if (state.month !== undefined && !monthPattern.test(state.month)) {
    throw new Error(`checkpoint state has an invalid month: ${state.month}`);
  }
  if (unique.month && state.month && unique.month !== state.month) {
    throw new Error(`unique/checkpoint month mismatch: ${unique.month}/${state.month}`);
  }
  const stateMonth = state.month || unique.month || null;
  if (stateMonth) state.month = stateMonth;
  for (const [gid, record] of Object.entries(state.groups || {})) {
    if (stateMonth && record.state_month && record.state_month !== stateMonth) {
      throw new Error(`checkpoint record ${gid} belongs to ${record.state_month}, expected ${stateMonth}`);
    }
    if (stateMonth && !record.state_month) record.state_month = stateMonth;
  }
  state.retry_errors ||= {};
  const activeGroupIds = new Set(allGroups.map(group => group.group_id));
  state.quarantined_groups ||= {};
  state.quarantined_retry_errors ||= {};
  let quarantinedOrphans = 0;
  for (const gid of Object.keys(state.groups || {})) {
    if (!activeGroupIds.has(gid)) {
      state.groups[gid].quarantined = true;
      state.groups[gid].quarantine_reason ||= 'not_in_active_groups';
      state.quarantined_groups[gid] = {
        reason: state.groups[gid].quarantine_reason,
        quarantined_at: new Date().toISOString(),
      };
      quarantinedOrphans++;
    }
  }
  for (const gid of Object.keys(state.retry_errors || {})) {
    if (!activeGroupIds.has(gid)) {
      state.retry_errors[gid].quarantined = true;
      state.retry_errors[gid].quarantine_reason ||= 'not_in_active_groups';
      state.quarantined_retry_errors[gid] = {
        reason: state.retry_errors[gid].quarantine_reason,
        quarantined_at: new Date().toISOString(),
      };
    }
  }
  if (quarantinedOrphans > 0) {
    saveCheckpoint(state);
    log(`Quarantined ${quarantinedOrphans} inactive checkpoint groups; no persisted result was deleted.`);
  }

  // 种子：已标记 already_verified 且带 verify_result 的组（历史复用），直接写入 checkpoint，不查询。
  let seeded = 0;
  for (const g of allGroups) {
    if (isCompletedRecord(state.groups[g.group_id])) continue;
    if (g.already_verified && reusableResults.has(g.group_id)) {
      const r = reusableResults.get(g.group_id);
      const seededRecord = {
        ...r,
        schema_version: RECORD_SCHEMA_VERSION,
        producer: RUNNER_PRODUCER,
        group_id: g.group_id,
        query: g.query,
        error: null,
        reused: true,
        reused_from: g.reused_from,
        verified_at: r.verified_at || r.generated_at || null,
        ...(stateMonth ? { state_month: stateMonth } : {}),
      };
      seededRecord.verification_state = classifyVerificationState(seededRecord);
      if (isCompletedRecord(seededRecord)) {
        state.groups[g.group_id] = seededRecord;
        seeded++;
      } else {
        state.retry_errors[g.group_id] ||= {
          group_id: g.group_id,
          query: g.query,
          error: 'reused result is inconclusive and requires a fresh verification',
          attempts: 0,
          failed_at: new Date().toISOString(),
          verification_state: 'inconclusive',
        };
      }
    }
  }
  if (seeded > 0) {
    saveCheckpoint(state);
    log(`Seeded ${seeded} reused groups into checkpoint (no query needed).`);
  }

  const allTodo = allGroups.filter(g => !isCompletedRecord(state.groups[g.group_id]));
  const todo = allTodo.slice(0, MAX_GROUPS);
  const truncated = allTodo.length - todo.length;
  log(`To query: ${allTodo.length}. Running today: ${todo.length}${truncated > 0 ? ` (truncated ${truncated}, will pick up next run)` : ''}.`);

  let consecutiveBlank = 0;
  let terminated = false;
  let verifiedCount = 0;
  const verifiedGroupIds = [];
  let failedCount = 0;
  const failedGroupIds = [];
  for (let i = 0; i < todo.length; i++) {
    const g = todo[i];
    const query = g.query;
    log(`\n=== [${i + 1}/${todo.length}] ${g.group_id} (${g.members.length} members: ${g.members.map(m => m.domain).join(', ')}) -> "${query}" ===`);

    let apiResult = null;
    let error = null;
    try {
      const stdout = execFileSync('node', [VERIFY_SCRIPT, query, 'ALL', '0', 'keyword_exact_phrase'], {
        encoding: 'utf8',
        maxBuffer: 50 * 1024 * 1024,
        timeout: 60000,
        stdio: ['ignore', 'pipe', 'inherit'],
      });
      apiResult = JSON.parse(stdout);
    } catch (e) {
      error = e.message ? e.message.slice(0, 500) : String(e);
      log(`[${g.group_id}] ERROR: ${error}`);
    }

    if (error) {
      const previousAttempts = Number(state.retry_errors[g.group_id]?.attempts || 0);
      state.retry_errors[g.group_id] = {
        group_id: g.group_id,
        query,
        error,
        attempts: previousAttempts + 1,
        failed_at: new Date().toISOString(),
        ...(stateMonth ? { state_month: stateMonth } : {}),
      };
      saveCheckpoint(state);
      failedCount++;
      failedGroupIds.push(g.group_id);
      consecutiveBlank++;
      log(`[${g.group_id}] query failed; left pending for the next incremental run (attempts=${previousAttempts + 1}).`);
    } else {
      const record = analyze(g, query, apiResult);
      record.reused = false;
      if (stateMonth) record.state_month = stateMonth;
      if (record.verification_state === 'inconclusive') {
        const previousAttempts = Number(state.retry_errors[g.group_id]?.attempts || 0);
        // Keep the canonical response evidence for diagnosis and cross-month
        // conservation. isCompletedRecord() remains false, so the next run
        // still queries this group again.
        state.groups[g.group_id] = record;
        state.retry_errors[g.group_id] = {
          group_id: g.group_id,
          query,
          error: `inconclusive Facebook response: HTTP ${apiResult.http_status ?? 'missing'}, total=${apiResult.total_reported ?? 'missing'}, harvested=${record.harvested}`,
          attempts: previousAttempts + 1,
          failed_at: new Date().toISOString(),
          verification_state: 'inconclusive',
          ...(stateMonth ? { state_month: stateMonth } : {}),
        };
        saveCheckpoint(state);
        failedCount++;
        failedGroupIds.push(g.group_id);
        consecutiveBlank++;
        log(`[${g.group_id}] response is inconclusive; no completed checkpoint written (attempts=${previousAttempts + 1}).`);
        if (consecutiveBlank >= BLANK_STREAK_LIMIT) {
          log(`\n!!! 连续 ${BLANK_STREAK_LIMIT} 组无有效结果，疑似被限速。终止本次剩余查询，明天自动续跑。!!!`);
          terminated = true;
          break;
        }
        if (i < todo.length - 1) {
          const ms = randSleepMs();
          log(`Sleeping ${Math.round(ms / 1000)}s...`);
          await sleep(ms);
        }
        continue;
      }
      // explicit_zero is conclusive API evidence, not a rate-limit symptom.
      // Only failed/inconclusive attempts contribute to the breaker streak.
      consecutiveBlank = 0;
      log(`[${g.group_id}] total=${record.fb_total_reported} harvested=${record.harvested} relevant=${record.relevant_ads_count} cross_domains=${record.cross_site_domains_count} own_hit=${record.own_domain_hit} max_days=${record.max_run_days}`);
      state.groups[g.group_id] = record;
      if (state.retry_errors[g.group_id]) {
        state.retry_errors[g.group_id].resolved_at = new Date().toISOString();
        state.retry_errors[g.group_id].resolved_by = record.verification_state;
      }
      saveCheckpoint(state); // 每个成功组查完立刻落盘，中途被杀最多丢一组
      verifiedCount++;
      verifiedGroupIds.push(g.group_id);
    }

    if (consecutiveBlank >= BLANK_STREAK_LIMIT) {
      log(`\n!!! 连续 ${BLANK_STREAK_LIMIT} 组空结果，疑似被限速。终止本次剩余查询，明天自动续跑。!!!`);
      terminated = true;
      break;
    }

    if (i < todo.length - 1) {
      const ms = randSleepMs();
      log(`Sleeping ${Math.round(ms / 1000)}s...`);
      await sleep(ms);
    }
  }

  const doneCount = allGroups.filter(g => isCompletedRecord(state.groups[g.group_id])).length;
  const pendingCount = allGroups.length - doneCount;
  log(`\nDone. completed checkpoints=${doneCount}/${allGroups.length} verified_this_run=${verifiedCount} failed_this_run=${failedCount} pending=${pendingCount} truncated=${truncated} terminated_early=${terminated}`);
  state.terminated_early = terminated;
  state.total_unique_groups = allGroups.length;
  saveCheckpoint(state);

  console.log('VERIFY_SUMMARY_JSON ' + JSON.stringify({
    todo: allTodo.length,
    verified: verifiedCount,
    verified_group_ids: verifiedGroupIds,
    failed: failedCount,
    failed_group_ids: failedGroupIds,
    truncated,
    terminated_early: terminated,
    pending: pendingCount,
  }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(e => {
    console.error('FATAL:', e);
    process.exit(1);
  });
}

export {
  analyze,
  classifyVerificationState,
  coreStems,
  countStemHits,
  isCompletedRecord,
  isInconclusiveResponse,
  migrateCheckpoint,
  migrateVerificationRecord,
  stripUrls,
};
