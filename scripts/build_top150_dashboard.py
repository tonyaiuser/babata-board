#!/usr/bin/env python3
"""
Build a public dashboard for the latest SP Top150 near-3-day candidates.

This page is intentionally narrower than the main picker dashboard: it mirrors
the DingTalk change-report scope so the "full dashboard" link does not land on
old historical hot products.
"""

import csv
import json
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENCLAW_DIR = os.path.expanduser("~/.openclaw/workspace")
DATA_DIR = os.path.join(BASE_DIR, "data")
TEMPLATE_PATH = os.path.join(BASE_DIR, "templates", "dashboard_template.html")
OUTPUT_PATHS = [
    os.path.join(BASE_DIR, "sp_top150_dashboard.html"),
    # Existing DingTalk messages already point here, so keep it aligned too.
    os.path.join(BASE_DIR, "sp_picker_dashboard.html"),
]
IMAGES_PATH = os.path.join(DATA_DIR, "images.json")
TOP_N = int(os.environ.get("SP_REPORT_SCAN_TOP_N", "150"))
REQUEST_DELAY = float(os.environ.get("SP_TOP150_IMAGE_DELAY", "0.6"))
REQUEST_TIMEOUT = int(os.environ.get("SP_TOP150_IMAGE_TIMEOUT", "8"))
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


def as_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def age_hours(pub_str):
    if not pub_str:
        return 999.0
    try:
        dt = datetime.fromisoformat(str(pub_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600)
    except Exception:
        try:
            dt = datetime.strptime(str(pub_str)[:10], "%Y-%m-%d")
            return max(0.0, (datetime.now() - dt).total_seconds() / 3600)
        except Exception:
            return 999.0


def latest_hotlist_path():
    paths = []
    for name in os.listdir(OPENCLAW_DIR):
        if name.startswith("sp_hotlist_") and name.endswith(".json"):
            day = name.replace("sp_hotlist_", "").replace(".json", "")
            if len(day) == 10:
                paths.append((day, os.path.join(OPENCLAW_DIR, name)))
    if not paths:
        raise RuntimeError("no sp_hotlist files found")
    return max(paths)[0], max(paths)[1]


def load_rank_map():
    active_path = os.path.join(OPENCLAW_DIR, "sp_domains.txt")
    full_path = os.path.join(OPENCLAW_DIR, "sp_similarweb_full.csv")
    with open(active_path, encoding="utf-8") as f:
        active = {line.strip() for line in f if line.strip()}

    sites = []
    with open(full_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            domain = row["domain"].replace("www.", "")
            if domain not in active:
                continue
            sites.append((domain, as_int(row.get("monthly_visits"))))
    sites.sort(key=lambda item: -item[1])
    return {domain: index + 1 for index, (domain, _) in enumerate(sites)}


def load_images():
    if not os.path.exists(IMAGES_PATH):
        return {}
    with open(IMAGES_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_images(images):
    os.makedirs(os.path.dirname(IMAGES_PATH), exist_ok=True)
    with open(IMAGES_PATH, "w", encoding="utf-8") as f:
        json.dump(images, f, indent=2, ensure_ascii=False)


def normalize_https(url):
    if url and url.startswith("http://"):
        return "https://" + url[len("http://") :]
    return url or ""


def fetch_shopify_image(sample_url, handle):
    parsed = urlparse(sample_url or "")
    if not parsed.scheme or not parsed.netloc or not handle:
        return ""
    api_url = f"{parsed.scheme}://{parsed.netloc}/products/{handle}.json"
    req = Request(api_url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read())
        images = data.get("product", {}).get("images", [])
        if images:
            return normalize_https(images[0].get("src"))
    except Exception:
        pass

    req = Request(sample_url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            html = resp.read().decode("utf-8", "ignore")
        for pattern in (
            r'<meta[^>]+(?:property|name)=["\'](?:og:image|twitter:image)["\'][^>]+content=["\']([^"\']+)',
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\'](?:og:image|twitter:image)["\']',
        ):
            match = re.search(pattern, html, re.I)
            if match:
                return normalize_https(match.group(1))
    except Exception:
        return ""
    return ""


def candidate_product_urls(product):
    handle = product.get("handle", "")
    urls = []
    sample_url = product.get("sample_url")
    if sample_url:
        urls.append(sample_url)
    for site in product.get("sites", []):
        url = f"https://{site}/products/{handle}"
        if url not in urls:
            urls.append(url)
    return urls


def fetch_product_image(product):
    handle = product.get("handle", "")
    for url in candidate_product_urls(product):
        image_url = fetch_shopify_image(url, handle)
        if image_url:
            return image_url
    return ""


def ensure_candidate_images(products, images):
    changed = False
    today = datetime.now().strftime("%Y-%m-%d")
    missing = []
    for product in products:
        handle = product.get("handle")
        if not handle or image_url_for(handle, images):
            continue
        if product.get("image_url"):
            images[handle] = {
                "url": normalize_https(product.get("image_url")),
                "fetched_at": today,
                "source": "hotlist_products_json",
                "error_type": None,
                "error": None,
            }
            changed = True
            continue
        missing.append(product)

    for index, product in enumerate(missing, 1):
        handle = product["handle"]
        img_url = fetch_product_image(product)
        images[handle] = {
            "url": img_url or None,
            "fetched_at": today,
            "source": "top150_dashboard",
            "error_type": None if img_url else "not_found",
            "error": None if img_url else "image not found via Shopify product API or product page",
        }
        product["image_url"] = img_url
        changed = True
        print(f"  image {index}/{len(missing)} {handle}: {'ok' if img_url else 'missing'}")
        if REQUEST_DELAY:
            time.sleep(REQUEST_DELAY)
    if changed:
        save_images(images)


def image_url_for(handle, images):
    entry = images.get(handle) or {}
    url = entry.get("url") or ""
    if url.startswith("http://"):
        url = "https://" + url[len("http://") :]
    return url


def fetch_site_currency(domain):
    """货币是站点级别的，查询一次 Shopify cart.js 即可（与 backfill_currency.py 同口径）"""
    req = Request(
        f"https://{domain}/cart.js",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read())
        code = str(data.get("currency") or "").strip().upper()
        if len(code) == 3:
            return code
    except Exception:
        pass
    return ""


def product_domain(product):
    domain = urlparse(product.get("sample_url") or "").netloc
    if domain:
        return domain
    sites = product.get("sites") or []
    return sites[0] if sites else ""


def ensure_candidate_currencies(products, images):
    """为候选注入货币代码：优先读缓存，缺失时按域名查 cart.js 并回写缓存"""
    changed = False
    domain_cache = {}
    for product in products:
        handle = product.get("handle")
        if not handle:
            continue
        currency = (images.get(handle) or {}).get("currency")
        if not currency:
            domain = product_domain(product)
            if domain:
                if domain not in domain_cache:
                    domain_cache[domain] = fetch_site_currency(domain)
                    if REQUEST_DELAY:
                        time.sleep(REQUEST_DELAY)
                currency = domain_cache[domain]
            if currency:
                images.setdefault(handle, {})["currency"] = currency
                changed = True
        product["currency"] = currency or None
    if changed:
        save_images(images)


def build_products(day, hotlist, rank_map, images):
    scored = {
        row.get("handle"): row
        for row in hotlist.get("scored_results", [])
        if row.get("handle")
    }
    products = []
    for row in hotlist.get("results", []):
        handle = row.get("handle")
        if not handle:
            continue
        top_sites = [
            domain
            for domain in row.get("sites", [])
            if rank_map.get(domain, 999999) <= TOP_N
        ]
        if len(top_sites) < 3:
            continue

        score_row = scored.get(handle, {})
        item = dict(row)
        item["date"] = day
        item["score"] = score_row.get("score", row.get("score", 0))
        item["top150_count"] = len(top_sites)
        item["image_url"] = image_url_for(handle, images) or normalize_https(row.get("image_url"))
        item["age_hours"] = round(age_hours(item.get("published_at")), 1)
        item["is_new"] = item["age_hours"] <= 24 * 7
        item["dashboard_priority"] = 3
        item["change_label"] = f"Top{TOP_N}候选"
        item["fb_hit_count"] = len(item.get("fb_hits", [])) if isinstance(item.get("fb_hits"), list) else 0
        item["delta_1d"] = item.get("spread_delta", 0)
        item["trend"] = None
        products.append(item)

    products.sort(
        key=lambda item: (
            -float(item.get("score") or 0),
            -as_int(item.get("flagship_count")),
            -as_int(item.get("top150_count")),
            item.get("age_hours", 999.0),
        )
    )
    return products


def generate_html(day, products):
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        template = f.read()

    safe_products = []
    for item in products:
        safe = {k: v for k, v in item.items() if k not in ("sites", "flagship_hits", "fb_hits")}
        safe_products.append(safe)

    html = template.replace("/*__DATA__*/[]", json.dumps(safe_products, indent=2, ensure_ascii=False))
    html = html.replace("巴巴塔AdSpy自动化选品工具", "SP Top150 今日候选看板")
    html = html.replace("数据来源：热榜 · 最近 3 天汇总", f"数据来源：{day} · Top{TOP_N}内≥3站重复候选")
    html = html.replace("Top 产品列表", f"Top{TOP_N} 候选列表")

    for output_path in OUTPUT_PATHS:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    print(f"Top{TOP_N} dashboard generated: {', '.join(OUTPUT_PATHS)}")
    print(f"  Date: {day}")
    print(f"  Products: {len(products)}")
    print(f"  With images: {sum(1 for p in products if p.get('image_url'))}")
    print(f"  With currency: {sum(1 for p in products if p.get('currency'))}")


def main():
    day, path = latest_hotlist_path()
    with open(path, encoding="utf-8") as f:
        hotlist = json.load(f)
    rank_map = load_rank_map()
    images = load_images()
    products = build_products(day, hotlist, rank_map, images)
    ensure_candidate_images(products, images)
    ensure_candidate_currencies(products, images)
    generate_html(day, products)


if __name__ == "__main__":
    main()
