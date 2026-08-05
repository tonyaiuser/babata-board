import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

import {
  analyze,
  classifyVerificationState,
  isInconclusiveResponse,
  migrateVerificationRecord,
} from '../scripts/run_verify_new_groups.mjs';


test('403 with no harvested ads remains inconclusive', () => {
  assert.equal(isInconclusiveResponse({ http_status: 403, harvested: 0 }), true);
  assert.equal(isInconclusiveResponse({ http_status: 403, harvested: 3 }), false);
  assert.equal(isInconclusiveResponse({ http_status: 200, harvested: 0 }), true);
});


test('verification classification has four terminal/evidence states', () => {
  assert.equal(classifyVerificationState({ response_http_status: 200, harvested: 1, sample: [{}] }, 1), 'positive');
  assert.equal(classifyVerificationState({ response_http_status: 200, harvested: 1, sample: [{}] }, 0), 'sample_negative');
  assert.equal(classifyVerificationState({ response_http_status: 200, fb_total_reported: '0', harvested: 0 }, 0), 'explicit_zero');
  assert.equal(classifyVerificationState({ response_http_status: 403, fb_total_reported: '0', harvested: 0 }, 0), 'inconclusive');
  assert.equal(classifyVerificationState({ response_http_status: 482, fb_total_reported: 0, harvested: 0 }, 0), 'inconclusive');
  assert.equal(classifyVerificationState({ response_http_status: 200, fb_total_reported: 'NaN', harvested: 0 }, 0), 'inconclusive');
  assert.equal(classifyVerificationState({ response_http_status: 200, fb_total_reported: '', harvested: 0 }, 0), 'inconclusive');
  assert.equal(classifyVerificationState({ harvested: 0, fb_total_reported: null }, 0), 'inconclusive');
  assert.equal(classifyVerificationState({ response_http_status: null, fb_total_reported: '0', harvested: 0 }, 0), 'inconclusive');
  assert.equal(classifyVerificationState({
    response_http_status: 200, fb_total_reported: 0,
    relevant_ads_count: 9, harvested: 0, relevant_ads: [],
  }), 'inconclusive');
});


test('strict schema1 migration canonicalizes aliases and only terminal evidence is reusable', () => {
  const positive = migrateVerificationRecord({
    http_status: 200, total_reported: 4, harvested: 1,
    relevant_ads_count: 1, sample: [{}],
  });
  assert.equal(positive.schema_version, 2);
  assert.equal(positive.migrated_from_schema, 1);
  assert.equal(positive.verification_state, 'positive');
  assert.equal(positive.response_http_status, 200);
  assert.equal(positive.fb_total_reported, 4);
  assert.equal(positive.http_status, undefined);

  const explicitV1 = migrateVerificationRecord({
    schema_version: 1, http_status: 200, total_reported: 0,
    harvested: 0, relevant_ads_count: 0,
  });
  assert.equal(explicitV1.verification_state, 'explicit_zero');
  assert.equal(explicitV1.schema_version, 2);

  const groupedV1 = migrateVerificationRecord({
    schema_version: 1, total_reported: '33,000', harvested: '30',
    relevant_ads_count: '0',
  });
  assert.equal(groupedV1.fb_total_reported, 33000);
  assert.equal(groupedV1.harvested, 30);
  assert.equal(groupedV1.verification_state, 'sample_negative');
  assert.throws(
    () => migrateVerificationRecord({ schema_version: 1, total_reported: '1,40' }),
    /invalid fb_total_reported/,
  );
  assert.throws(
    () => migrateVerificationRecord({
      schema_version: 2, producer: 'fb-verify-runner',
      fb_total_reported: '1400', verification_state: 'inconclusive',
    }),
    /invalid fb_total_reported/,
  );

  const inconclusive = migrateVerificationRecord({
    http_status: 403, total_reported: 0, harvested: 0, relevant_ads_count: 0,
  });
  assert.equal(inconclusive.verification_state, 'inconclusive');
  assert.throws(
    () => migrateVerificationRecord({ schema_version: 99, producer: 'other' }),
    /unsupported verification record schema/,
  );
  assert.throws(
    () => migrateVerificationRecord({
      verification_state: 'positive', relevant_ads_count: 3, harvested: 0,
    }),
    /contradicts evidence/,
  );
});


test('corrupt existing checkpoint fails closed without altering its bytes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-verify-corrupt-'));
  try {
    const uniquePath = path.join(dir, 'unique.json');
    const checkpointPath = path.join(dir, 'checkpoint.json');
    const fakeVerifier = path.join(dir, 'fake-verifier.mjs');
    const logPath = path.join(dir, 'runner.log');
    const corrupt = '{definitely not json';
    fs.writeFileSync(uniquePath, JSON.stringify({ groups: [] }));
    fs.writeFileSync(checkpointPath, corrupt);
    fs.writeFileSync(fakeVerifier, "console.log('{}');\n");
    const result = execFileSync('node', [
      path.resolve('fb-verify/scripts/run_verify_new_groups.mjs'), '--unique-json', uniquePath,
      '--checkpoint-json', checkpointPath, '--verify-script', fakeVerifier, '--log-file', logPath,
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.fail(`runner unexpectedly succeeded: ${result}`);
  } catch (error) {
    assert.match(String(error.stderr), /refusing to overwrite/);
  } finally {
    const checkpointPath = path.join(dir, 'checkpoint.json');
    assert.equal(fs.readFileSync(checkpointPath, 'utf8'), '{definitely not json');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test('missing unique file emits the complete zero-summary contract', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-verify-missing-unique-'));
  try {
    const output = execFileSync('node', [
      path.resolve('fb-verify/scripts/run_verify_new_groups.mjs'),
      '--unique-json', path.join(dir, 'missing.json'),
      '--checkpoint-json', path.join(dir, 'checkpoint.json'),
      '--verify-script', path.join(dir, 'unused.mjs'),
      '--log-file', path.join(dir, 'runner.log'),
    ], { encoding: 'utf8' });
    const summary = JSON.parse(output.match(/VERIFY_SUMMARY_JSON (.+)/)[1]);
    assert.deepEqual(summary, {
      todo: 0,
      verified: 0,
      verified_group_ids: [],
      failed: 0,
      failed_group_ids: [],
      truncated: 0,
      terminated_early: false,
      pending: 0,
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test('empty unknown response preserves evidence, remains pending, and is queried again', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-verify-test-'));
  try {
    const uniquePath = path.join(dir, 'unique.json');
    const checkpointPath = path.join(dir, 'checkpoint.json');
    const fakeVerifier = path.join(dir, 'fake-verifier.mjs');
    const logPath = path.join(dir, 'runner.log');
    fs.writeFileSync(uniquePath, JSON.stringify({ groups: [{
      group_id: 'G0001', query: 'Unknown Widget', members: [{ domain: 'shop.example', handle: 'widget' }],
    }] }));
    fs.writeFileSync(fakeVerifier, "console.log(JSON.stringify({harvested:0,total_reported:null,http_status:null,sample:[]}));\n");
    const output = execFileSync('node', [
      path.resolve('fb-verify/scripts/run_verify_new_groups.mjs'),
      '--unique-json', uniquePath,
      '--checkpoint-json', checkpointPath,
      '--verify-script', fakeVerifier,
      '--log-file', logPath,
      '--max-groups', '1',
      '--blank-streak', '5',
    ], { encoding: 'utf8' });
    const summary = JSON.parse(output.match(/VERIFY_SUMMARY_JSON (.+)/)[1]);
    const checkpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
    assert.equal(summary.verified, 0);
    assert.equal(summary.failed, 1);
    assert.equal(summary.pending, 1);
    assert.equal(checkpoint.groups.G0001.verification_state, 'inconclusive');
    assert.equal(checkpoint.groups.G0001.response_http_status, null);
    assert.equal(checkpoint.retry_errors.G0001.verification_state, 'inconclusive');
    const secondOutput = execFileSync('node', [
      path.resolve('fb-verify/scripts/run_verify_new_groups.mjs'),
      '--unique-json', uniquePath,
      '--checkpoint-json', checkpointPath,
      '--verify-script', fakeVerifier,
      '--log-file', logPath,
      '--max-groups', '1',
      '--blank-streak', '5',
    ], { encoding: 'utf8' });
    const secondSummary = JSON.parse(secondOutput.match(/VERIFY_SUMMARY_JSON (.+)/)[1]);
    const secondCheckpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
    assert.equal(secondSummary.failed, 1);
    assert.equal(secondCheckpoint.retry_errors.G0001.attempts, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test('explicit zero is terminal evidence and never advances the blank breaker', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-verify-zero-'));
  try {
    const uniquePath = path.join(dir, 'unique.json');
    const checkpointPath = path.join(dir, 'checkpoint.json');
    const fakeVerifier = path.join(dir, 'fake-verifier.mjs');
    const logPath = path.join(dir, 'runner.log');
    fs.writeFileSync(uniquePath, JSON.stringify({ groups: [1, 2].map(number => ({
      group_id: `G000${number}`,
      query: `Zero Widget ${number}`,
      members: [{ domain: `shop${number}.example`, handle: `widget-${number}` }],
    })) }));
    fs.writeFileSync(fakeVerifier, "console.log(JSON.stringify({harvested:0,total_reported:0,http_status:200,sample:[]}));\n");
    const output = execFileSync('node', [
      path.resolve('fb-verify/scripts/run_verify_new_groups.mjs'),
      '--unique-json', uniquePath,
      '--checkpoint-json', checkpointPath,
      '--verify-script', fakeVerifier,
      '--log-file', logPath,
      '--max-groups', '2',
      '--blank-streak', '1',
    ], { encoding: 'utf8', env: { ...process.env, FB_VERIFY_TEST_NO_SLEEP: '1' } });
    const summary = JSON.parse(output.match(/VERIFY_SUMMARY_JSON (.+)/)[1]);
    const checkpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
    assert.equal(summary.verified, 2);
    assert.equal(summary.failed, 0);
    assert.equal(summary.terminated_early, false);
    assert.equal(checkpoint.groups.G0001.verification_state, 'explicit_zero');
    assert.equal(checkpoint.groups.G0002.verification_state, 'explicit_zero');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test('legacy inconclusive reused result is queried fresh rather than seeded', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-verify-legacy-retry-'));
  try {
    const uniquePath = path.join(dir, 'unique.json');
    const checkpointPath = path.join(dir, 'checkpoint.json');
    const fakeVerifier = path.join(dir, 'fake-verifier.mjs');
    const logPath = path.join(dir, 'runner.log');
    fs.writeFileSync(uniquePath, JSON.stringify({ groups: [{
      group_id: 'G0001', query: 'Retry Widget', already_verified: true,
      reused_from: 'previous_month:G0042',
      verify_result: { http_status: 403, total_reported: 0, harvested: 0, relevant_ads_count: 0 },
      members: [{ domain: 'shop.example', handle: 'widget' }],
    }] }));
    fs.writeFileSync(fakeVerifier, "console.log(JSON.stringify({harvested:0,total_reported:0,http_status:200,sample:[]}));\n");
    const output = execFileSync('node', [
      path.resolve('fb-verify/scripts/run_verify_new_groups.mjs'), '--unique-json', uniquePath,
      '--checkpoint-json', checkpointPath, '--verify-script', fakeVerifier, '--log-file', logPath,
      '--max-groups', '1', '--blank-streak', '5',
    ], { encoding: 'utf8' });
    const summary = JSON.parse(output.match(/VERIFY_SUMMARY_JSON (.+)/)[1]);
    const checkpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
    assert.equal(summary.verified, 1);
    assert.equal(checkpoint.groups.G0001.reused, false);
    assert.equal(checkpoint.groups.G0001.verification_state, 'explicit_zero');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test('unknown reused schema fails closed without changing checkpoint bytes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-verify-bad-reuse-'));
  try {
    const uniquePath = path.join(dir, 'unique.json');
    const checkpointPath = path.join(dir, 'checkpoint.json');
    const fakeVerifier = path.join(dir, 'fake-verifier.mjs');
    const logPath = path.join(dir, 'runner.log');
    const originalCheckpoint = JSON.stringify({ groups: {} });
    fs.writeFileSync(checkpointPath, originalCheckpoint);
    fs.writeFileSync(uniquePath, JSON.stringify({ groups: [{
      group_id: 'G0001', query: 'Bad Schema Widget', already_verified: true,
      verify_result: { schema_version: 99, producer: 'unknown', verification_state: 'positive' },
      members: [{ domain: 'shop.example', handle: 'widget' }],
    }] }));
    fs.writeFileSync(fakeVerifier, "console.log('{}');\n");
    const result = spawnSync('node', [
      path.resolve('fb-verify/scripts/run_verify_new_groups.mjs'), '--unique-json', uniquePath,
      '--checkpoint-json', checkpointPath, '--verify-script', fakeVerifier, '--log-file', logPath,
    ], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unsupported verification record schema/);
    assert.equal(fs.readFileSync(checkpointPath, 'utf8'), originalCheckpoint);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test('analysis separates content matches from landing-url-only matches', () => {
  const group = {
    group_id: 'G0001',
    members: [{ domain: 'source.example' }],
  };
  const apiResult = {
    http_status: 403,
    total_reported: null,
    harvested: 30,
    sample_scope: 'first_page',
    sample_limited: true,
    sample: [
      {
        ad_archive_id: '1',
        body: 'Electric aquarium gravel cleaner makes water changes easy',
        link_url: 'https://one.example/products/item',
      },
      {
        ad_archive_id: '2',
        body: 'Unrelated creative copy',
        link_url: 'https://two.example/products/electric-aquarium-gravel-cleaner',
      },
      {
        ad_archive_id: '3',
        body: 'Completely unrelated',
        link_url: 'https://three.example/products/other',
      },
    ],
  };
  const result = analyze(group, 'Electric Aquarium Gravel Cleaner', apiResult);
  assert.equal(result.relevant_ads_count, 2);
  assert.equal(result.content_matched_ads_count, 1);
  assert.equal(result.landing_only_matched_ads_count, 1);
  assert.equal(result.relevant_ads[0].relevance_basis, 'content');
  assert.equal(result.relevant_ads[1].relevance_basis, 'landing_url');
  assert.equal(result.sample_limited, true);
  assert.equal(result.response_http_status, 403);
});
