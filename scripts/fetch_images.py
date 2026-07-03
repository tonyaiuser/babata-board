#!/usr/bin/env python3
"""
fetch_images.py - 抓取商品 OG 图片 URL 和货币代码并缓存
从最新的热榜数据中读取 sample_url，提取 og:image / og:price:currency 元标签
"""

import json
import glob
import os
import time
import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAILY_DIR = os.path.join(BASE_DIR, "data", "daily")
IMAGES_PATH = os.path.join(BASE_DIR, "data", "images.json")

# 失败后重试间隔（天）
RETRY_AFTER_DAYS = 1
# 404 / 明确无效链接的重试间隔（天）
RETRY_404_AFTER_DAYS = 7
# 请求间隔（秒）
REQUEST_DELAY = 1.5
# 请求超时（秒）
REQUEST_TIMEOUT = 10
# 单个商品最多尝试的站点数
MAX_URLS_PER_HANDLE = 4

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def load_cache():
    """加载图片缓存"""
    if os.path.exists(IMAGES_PATH):
        with open(IMAGES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    """保存图片缓存"""
    with open(IMAGES_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)


def should_fetch(cache_entry):
    """判断是否需要（重新）抓取"""
    if not cache_entry:
        return True
    if cache_entry.get("url"):
        return False

    fetched_at = cache_entry.get("fetched_at", "")
    if not fetched_at:
        return True

    error_type = cache_entry.get("error_type", "unknown")
    retry_days = RETRY_404_AFTER_DAYS if error_type == "not_found" else RETRY_AFTER_DAYS
    cutoff = (datetime.now() - timedelta(days=retry_days)).strftime("%Y-%m-%d")
    return fetched_at < cutoff


def normalize_https(url):
    """图片 URL 统一使用 https，避免看板托管在 HTTPS 页面时被混合内容拦截"""
    if url and url.startswith("http://"):
        return "https://" + url[len("http://"):]
    return url


def fetch_og_image(url, session):
    """从页面提取 og:image / og:price:currency 元标签"""
    from bs4 import BeautifulSoup
    import requests

    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        currency = None
        cur_meta = soup.find("meta", property="og:price:currency")
        if cur_meta and cur_meta.get("content"):
            currency = cur_meta["content"].strip().upper()

        og = soup.find("meta", property="og:image")
        if og and og.get("content"):
            img_url = og["content"]
            if img_url.startswith("//"):
                img_url = "https:" + img_url
            return {"url": normalize_https(img_url), "currency": currency}

        return {"url": None, "currency": currency, "error_type": "no_og_image", "error": "og:image not found"}
    except requests.HTTPError as e:
        status = getattr(e.response, "status_code", None)
        error_type = "not_found" if status == 404 else f"http_{status or 'error'}"
        return {"url": None, "error_type": error_type, "error": str(e)}
    except Exception as e:
        return {"url": None, "error_type": "request_error", "error": str(e)}


def fetch_site_currency(domain, session, cache={}):
    """通过 Shopify cart.js 获取站点货币（按域名缓存）"""
    if domain in cache:
        return cache[domain]
    currency = None
    try:
        resp = session.get(f"https://{domain}/cart.js", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            currency = (resp.json().get("currency") or "").strip().upper() or None
    except Exception:
        pass
    cache[domain] = currency
    return currency


def fetch_shopify_api(sample_url, handle, session):
    """备选方案：通过 Shopify products API 获取图片"""
    try:
        parsed = urlparse(sample_url)
        api_url = f"{parsed.scheme}://{parsed.netloc}/products/{handle}.json"
        resp = session.get(api_url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            images = data.get("product", {}).get("images", [])
            if images:
                return {"url": normalize_https(images[0].get("src"))}
        if resp.status_code == 404:
            return {"url": None, "error_type": "not_found", "error": f"404 on {api_url}"}
        return {"url": None, "error_type": f"http_{resp.status_code}", "error": f"HTTP {resp.status_code} on {api_url}"}
    except Exception as e:
        return {"url": None, "error_type": "api_error", "error": str(e)}


def get_products_to_fetch():
    """从最新的热榜数据中获取需要抓取图片的产品列表"""
    pattern = os.path.join(DAILY_DIR, "sp_hotlist_*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        return []

    # 合并所有文件，按 handle 去重
    seen = {}
    for fp in files:
        with open(fp, "r", encoding="utf-8") as f:
            products = json.load(f)
        for p in products:
            handle = p["handle"]
            if handle not in seen:
                seen[handle] = p

    return list(seen.values())


def main():
    try:
        import requests
        from bs4 import BeautifulSoup  # noqa: F401
    except ImportError:
        print("ERROR: Missing dependencies. Run:")
        print("  pip3 install requests beautifulsoup4")
        sys.exit(1)

    cache = load_cache()
    products = get_products_to_fetch()

    if not products:
        print("No products found in daily data.")
        return

    to_fetch = []
    for p in products:
        handle = p["handle"]
        if should_fetch(cache.get(handle)):
            to_fetch.append(p)

    print(f"Total products: {len(products)}")
    print(f"Already cached: {len(products) - len(to_fetch)}")
    print(f"To fetch: {len(to_fetch)}")

    if not to_fetch:
        print("All images already cached.")
        return

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    today = datetime.now().strftime("%Y-%m-%d")
    success = 0
    fail = 0

    for i, p in enumerate(to_fetch):
        handle = p["handle"]
        sample_url = p.get("sample_url", "")
        print(f"[{i+1}/{len(to_fetch)}] {handle}")

        img_url = None
        currency = None
        sites = p.get("sites", [])

        # 构建候选 URL 列表：sample_url 优先，然后从其他站点生成
        urls = []
        if sample_url:
            urls.append(sample_url)
        for site in sites:
            alt = f"https://{site}/products/{handle}"
            if alt != sample_url:
                urls.append(alt)

        last_error = None

        # 依次尝试每个 URL
        for try_url in urls[:MAX_URLS_PER_HANDLE]:
            og_result = fetch_og_image(try_url, session)
            currency = currency or og_result.get("currency")
            if og_result.get("url"):
                img_url = og_result["url"]
                break
            last_error = og_result
            if og_result.get("error"):
                print(f"    OG miss: {og_result['error']}")

            api_result = fetch_shopify_api(try_url, handle, session)
            if api_result.get("url"):
                img_url = api_result["url"]
                break
            last_error = api_result or last_error
            if api_result.get("error"):
                print(f"    API miss: {api_result['error']}")
            time.sleep(0.5)

        # og 标签没拿到货币时，退回到 sample_url 站点的 cart.js
        if not currency and sample_url:
            domain = urlparse(sample_url).netloc
            if domain:
                currency = fetch_site_currency(domain, session)

        if img_url:
            cache[handle] = {"url": img_url, "currency": currency, "fetched_at": today, "error_type": None, "error": None}
            success += 1
            print(f"    OK: {img_url[:80]}...")
        else:
            cache[handle] = {
                "url": None,
                "currency": currency,
                "fetched_at": today,
                "error_type": (last_error or {}).get("error_type", "unknown"),
                "error": (last_error or {}).get("error", "unknown error"),
            }
            fail += 1
            print(f"    FAILED: {cache[handle]['error_type']}")

        # 每次抓取后保存（防止中断丢失）
        save_cache(cache)

        # 礼貌延迟
        if i < len(to_fetch) - 1:
            time.sleep(REQUEST_DELAY)

    print(f"\nDone! Success: {success}, Failed: {fail}")


if __name__ == "__main__":
    main()
