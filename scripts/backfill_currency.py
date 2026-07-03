#!/usr/bin/env python3
"""
backfill_currency.py - 为 images.json 中已有的缓存条目补充货币代码
货币是站点级别的，按域名调用一次 Shopify cart.js 即可，无需逐商品请求
"""

import json
import glob
import os
import time
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAILY_DIR = os.path.join(BASE_DIR, "data", "daily")
IMAGES_PATH = os.path.join(BASE_DIR, "data", "images.json")

REQUEST_TIMEOUT = 10
REQUEST_DELAY = 0.5

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def handle_domains():
    """handle -> 域名，来自每日热榜的 sample_url"""
    mapping = {}
    for fp in sorted(glob.glob(os.path.join(DAILY_DIR, "sp_hotlist_*.json"))):
        with open(fp, "r", encoding="utf-8") as f:
            for p in json.load(f):
                domain = urlparse(p.get("sample_url", "")).netloc
                if domain:
                    mapping[p["handle"]] = domain
    return mapping


def main():
    import requests

    with open(IMAGES_PATH, "r", encoding="utf-8") as f:
        cache = json.load(f)

    domains = handle_domains()

    # 缺货币的条目：优先用热榜里的 sample_url 域名，退回图片 URL 域名
    pending = {}
    for handle, entry in cache.items():
        if entry.get("currency"):
            continue
        domain = domains.get(handle)
        if not domain and entry.get("url"):
            domain = urlparse(entry["url"]).netloc
        if domain:
            pending.setdefault(domain, []).append(handle)

    print(f"缺货币条目: {sum(len(v) for v in pending.values())}, 涉及域名: {len(pending)}")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    for i, (domain, handles) in enumerate(sorted(pending.items())):
        currency = None
        try:
            resp = session.get(f"https://{domain}/cart.js", timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                currency = (resp.json().get("currency") or "").strip().upper() or None
        except Exception as e:
            print(f"  [{i+1}/{len(pending)}] {domain}: 请求失败 {e}")
        if currency:
            for h in handles:
                cache[h]["currency"] = currency
            print(f"  [{i+1}/{len(pending)}] {domain}: {currency} ({len(handles)} 条)")
        else:
            print(f"  [{i+1}/{len(pending)}] {domain}: 未获取到货币")
        time.sleep(REQUEST_DELAY)

    with open(IMAGES_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

    done = sum(1 for v in cache.values() if v.get("currency"))
    print(f"完成: {done}/{len(cache)} 条已有货币代码")


if __name__ == "__main__":
    main()
