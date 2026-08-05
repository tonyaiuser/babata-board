import { chromium } from '/opt/homebrew/lib/node_modules/playwright/index.mjs';

const QUERY = process.argv[2] || 'sakerplus.com';
const COUNTRY = process.argv[3] || 'ALL';
const SCROLLS = parseInt(process.argv[4] || '0', 10);
const SEARCH_TYPE = process.argv[5] || 'keyword_exact_phrase';
const URL = `https://www.facebook.com/ads/library/?active_status=active&ad_type=all&country=${COUNTRY}&q=${encodeURIComponent(QUERY)}&search_type=${SEARCH_TYPE}&media_type=all`;

function harvestAds(node, out, depth = 0) {
  if (!node || depth > 45) return;
  if (Array.isArray(node)) { for (const v of node) harvestAds(v, out, depth + 1); return; }
  if (typeof node === 'object') {
    if ('ad_archive_id' in node && 'snapshot' in node) out.push(node);
    for (const k of Object.keys(node)) harvestAds(node[k], out, depth + 1);
  }
}

// Try to JSON.parse anything ad-bearing: script blocks in HTML, or raw graphql JSON.
function extractFromText(text, ads, seen) {
  const candidates = [];
  if (text.includes('<script')) {
    const re = /<script[^>]*type="application\/json"[^>]*>([\s\S]*?)<\/script>/g;
    let m;
    while ((m = re.exec(text)) !== null) candidates.push(m[1]);
  } else {
    for (const line of text.split('\n')) { const t = line.trim(); if (t.startsWith('{')) candidates.push(t); }
  }
  for (const c of candidates) {
    let json;
    try { json = JSON.parse(c); } catch { continue; }
    const found = [];
    harvestAds(json, found);
    for (const ad of found) {
      const id = ad.ad_archive_id;
      if (id && !seen.has(id)) { seen.add(id); ads.push(ad); }
    }
  }
}

const ads = [];
const seen = new Set();

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  locale: 'en-US', viewport: { width: 1440, height: 900 },
});
const page = await ctx.newPage();

page.on('response', async (resp) => {
  const url = resp.url();
  if (!/graphql|async\/search_ads|q=/.test(url)) return;
  const ct = resp.headers()['content-type'] || '';
  if (!/json|javascript|text|html/.test(ct)) return;
  let body; try { body = await resp.text(); } catch { return; }
  if (!body.includes('ad_archive_id')) return;
  extractFromText(body.replace(/^for \(;;\);/, ''), ads, seen);
});

console.error('Navigating:', URL);
let httpStatus = null;
try {
  const resp = await page.goto(URL, { waitUntil: 'domcontentloaded', timeout: 45000 });
  httpStatus = resp ? resp.status() : null;
} catch (e) { console.error('goto warning:', e.message); }
await page.waitForTimeout(5000);

let total = null;
try {
  const t = await page.evaluate(() => {
    const m = document.body.innerText.match(/~?([\d,]+)\s+results/);
    return m ? m[1] : null;
  });
  total = t;
} catch {}

const before = ads.length;
for (let i = 0; i < SCROLLS; i++) {
  await page.mouse.wheel(0, 6000);
  await page.waitForTimeout(2600);
}
await page.waitForTimeout(1500);

console.error(`http_status: ${httpStatus}, total reported: ${total}, ads harvested: ${ads.length} (page1 ~${before})`);

const rows = ads.map(a => {
  const s = a.snapshot || {};
  const bc = s.branded_content || {};
  return {
    ad_archive_id: a.ad_archive_id,
    page_id: a.page_id,
    advertiser: s.page_name || bc.page_name,
    branded_content_page: bc.page_name,
    profile: s.page_profile_uri || bc.page_profile_uri,
    is_active: a.is_active,
    uses_this_creative: a.collation_count,
    start_date: a.start_date,
    end_date: a.end_date,
    cta: s.cta_text,
    caption: s.caption,
    title: s.title,
    body: s.body && (typeof s.body === 'object' ? (s.body.text || '') : s.body),
    link_url: s.link_url,
    display_format: s.display_format,
    image_url: (s.images && s.images[0] && (s.images[0].original_image_url || s.images[0].resized_image_url)) ||
               (s.cards && s.cards[0] && s.cards[0].original_image_url) ||
               (s.videos && s.videos[0] && (s.videos[0].video_preview_image_url || s.videos[0].preview_image_url)) || null,
    video_url: (s.videos && s.videos[0] && (s.videos[0].video_hd_url || s.videos[0].video_sd_url)) || null,
  };
});

console.log(JSON.stringify({
  query: QUERY,
  search_type: SEARCH_TYPE,
  http_status: httpStatus,
  total_reported: total,
  harvested: rows.length,
  sample_scope: SCROLLS === 0 ? 'first_page' : `first_page_plus_${SCROLLS}_scrolls`,
  sample_limited: SCROLLS === 0 && rows.length >= 30,
  sample: rows,
}, null, 2));

await browser.close();
