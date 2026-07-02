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
from datetime import datetime, timezone


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


def image_url_for(handle, images):
    entry = images.get(handle) or {}
    url = entry.get("url") or ""
    if url.startswith("http://"):
        url = "https://" + url[len("http://") :]
    return url


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
        item["image_url"] = image_url_for(handle, images)
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


def main():
    day, path = latest_hotlist_path()
    with open(path, encoding="utf-8") as f:
        hotlist = json.load(f)
    rank_map = load_rank_map()
    images = load_images()
    products = build_products(day, hotlist, rank_map, images)
    generate_html(day, products)


if __name__ == "__main__":
    main()
