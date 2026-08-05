#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
为看板抓取产品主图，写入 product_images.json（可重跑、幂等，按 domain|handle 缓存）。

从一次性脚本 fetch_all_images.py / fetch_product_images.py 迁移而来，改动点：
  - 不再直接读某份 hits.csv，而是遍历 unique_products.json 里全部组的全部成员
    （已缓存的 key 会被跳过，天然只对"新成员"发请求，不需要单独维护一份"新增名单"）
  - 路径全部通过 CLI 参数传入

策略（对每个 domain|handle）：
  1. 首选 https://<domain>/products/<handle>.json 取 product.images[0].src
  2. 失败（非200 / 无图）则抓单页 HTML，解析 <meta property="og:image">
  3. 两者都失败记 None，继续下一个，不中断整个流程；单站失败不重试轰炸

礼貌抓取：浏览器 UA；请求间隔 2~4 秒随机；每完成一个立即保存，可断点续传。

用法:
  python3 fetch_new_images.py \
      --unique-json data/2026-07/unique_products.json \
      --images-json data/2026-07/product_images.json
"""

import argparse
import base64
import html
import json
import math
import os
import random
import re
import subprocess
import sys
import time
import signal
import threading
import urllib.parse
import urllib.request
import urllib.error
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from state_io import atomic_write_json
from verification_schema import migrate_checkpoint

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

REQUEST_TIMEOUT = 15
SLEEP_MIN = 2.0
SLEEP_MAX = 4.0
HTTP_RETRIES = 2
VIDEO_FRAME_TIMEOUT = 30
# A single broken origin must not hold the whole image-cache checkpoint hostage.
# Keep this below the daily watchdog so the outer runner has time to persist its
# terminal status and release its lock cleanly.
PRODUCT_TIMEOUT_SECONDS = 90
PRODUCT_TIMEOUT_MIN_SECONDS = 1
PRODUCT_TIMEOUT_MAX_SECONDS = 300
PREVIOUS_CACHE_CHECKPOINT_SIZE = 1000
HEARTBEAT_SECONDS = 30

_network_requests = 0

OG_IMAGE_RE = re.compile(
    r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
OG_IMAGE_RE_ALT = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']',
    re.IGNORECASE,
)


def polite_sleep():
    time.sleep(random.uniform(SLEEP_MIN, SLEEP_MAX))


def wait_before_network_request():
    """Rate-limit real HTTP attempts, never local cache hydration."""
    global _network_requests
    if _network_requests:
        polite_sleep()
    _network_requests += 1


class ProductTimeout(RuntimeError):
    """The current product exceeded its bounded image-resolution budget."""


@contextmanager
def product_timeout(seconds):
    """Interrupt a stuck product fetch without terminating the whole batch.

    The fetcher is a single-process CLI and runs this context in its main
    thread, so SIGALRM can interrupt a blocking urllib call as well as a slow
    fallback.  Existing alarms are restored exactly on exit.
    """
    if not math.isfinite(seconds) or not PRODUCT_TIMEOUT_MIN_SECONDS <= seconds <= PRODUCT_TIMEOUT_MAX_SECONDS:
        raise ValueError(
            f"product timeout must be finite and in "
            f"[{PRODUCT_TIMEOUT_MIN_SECONDS}, {PRODUCT_TIMEOUT_MAX_SECONDS}] seconds"
        )
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("product timeout must run in the main thread")

    def on_timeout(_signum, _frame):
        raise ProductTimeout(f"image resolution exceeded {seconds:.0f}s")

    old_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, on_timeout)
    old_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *old_timer)
        signal.signal(signal.SIGALRM, old_handler)


class Heartbeat:
    """Emit progress to stderr even while one product is blocked."""

    def __init__(self, interval):
        if not math.isfinite(interval) or not 0 < interval <= 60:
            raise ValueError("heartbeat interval must be finite, >0 and <=60 seconds")
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        print("[images] heartbeat: image fetch worker started", file=sys.stderr, flush=True)
        self.thread.start()

    def _run(self):
        while not self.stop_event.wait(self.interval):
            print("[images] heartbeat: image fetch worker still running", file=sys.stderr, flush=True)

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=1)


def normalize_image_url(value):
    """将站点返回的协议相对/HTTP 图片统一成 Pages 可加载的 HTTPS URL。"""
    if not value or not isinstance(value, str):
        return None
    value = html.unescape(value.strip())
    if value.startswith("//"):
        return "https:" + value
    if value.startswith("http://"):
        return "https://" + value[len("http://"):]
    return value


def fetch_url(url, retries=HTTP_RETRIES):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    for attempt in range(retries + 1):
        wait_before_network_request()
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status = e.code
            if status not in {403, 429, 500, 502, 503, 504} or attempt >= retries:
                return status, None
        except ProductTimeout:
            # The outer per-product budget is a control-flow boundary, never
            # an ordinary retryable transport failure.
            raise
        except Exception:
            if attempt >= retries:
                return None, None
    return None, None


def try_shopify_json(domain, handle):
    # 某些 Shopify 站封锁 .json 但允许产品 .js；两个端点都尝试。
    for suffix in (".js", ".json"):
        url = f"https://{domain}/products/{handle}{suffix}"
        status, body = fetch_url(url)
        if status != 200 or not body:
            continue
        try:
            data = json.loads(body)
            product = data.get("product") if isinstance(data, dict) and "product" in data else data
            images = (product or {}).get("images") or []
            if images:
                first = images[0]
                src = first.get("src") if isinstance(first, dict) else first
                if src:
                    return normalize_image_url(src)
            featured = (product or {}).get("featured_image")
            if isinstance(featured, str) and featured:
                return normalize_image_url(featured)
        except (ValueError, AttributeError, TypeError):
            pass
    return None


def try_og_image(domain, handle, product_url):
    url = product_url or f"https://{domain}/products/{handle}"
    status, body = fetch_url(url)
    if status == 200 and body:
        try:
            text = body.decode("utf-8", errors="ignore")
        except Exception:
            return None
        m = OG_IMAGE_RE.search(text) or OG_IMAGE_RE_ALT.search(text)
        if m:
            img = m.group(1)
            return normalize_image_url(img)
    return None


def product_parts_from_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        match = re.search(r"/products/([^/?#]+)", parsed.path)
        if not parsed.hostname or not match:
            return None
        return parsed.hostname.lower().removeprefix("www."), urllib.parse.unquote(match.group(1))
    except (TypeError, ValueError):
        return None


def try_cross_site_images(urls, original_key):
    """从 FB 已确认广告的同款落地页补图，最多尝试 4 个不同商品链接。"""
    tried = set()
    for url in urls:
        parts = product_parts_from_url(url)
        if not parts:
            continue
        domain, handle = parts
        key = f"{domain}|{handle}"
        if key == original_key or key in tried:
            continue
        tried.add(key)
        image = try_shopify_json(domain, handle)
        if not image:
            image = try_og_image(domain, handle, url)
        if image:
            return image
        if len(tried) >= 4:
            break
    return None


def try_video_frame(video_url):
    """最后兜底：用广告视频首帧生成小尺寸 JPEG data URL（ffmpeg 可用时）。"""
    if not video_url:
        return None
    try:
        proc = subprocess.run(
            [
                "ffmpeg", "-hide_banner", "-loglevel", "error", "-ss", "0.5",
                "-i", video_url, "-frames:v", "1", "-vf", "scale=480:-2",
                "-q:v", "6", "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=VIDEO_FRAME_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout or len(proc.stdout) > 600_000:
        return None
    return "data:image/jpeg;base64," + base64.b64encode(proc.stdout).decode("ascii")


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"persistent state unreadable; refusing to overwrite {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"persistent state has invalid schema; refusing to overwrite {path}")
    return data


def save_images(images, path):
    atomic_write_json(path, images)


def resolve_network_image(domain, handle, product_url, cross_urls, ad_images, video_urls, key):
    """Resolve one cache miss; callers turn a timeout into a retryable None."""
    source = None
    img = try_shopify_json(domain, handle)
    if img:
        return img, "shopify-json"
    # At least one Shopify endpoint was attempted above; an OG fallback is a
    # real HTTP request too and fetch_url will apply the polite interval.
    img = try_og_image(domain, handle, product_url)
    if img:
        return img, "og-image"
    if cross_urls:
        img = try_cross_site_images(cross_urls, key)
        if img:
            return img, "cross-site-product"
    if ad_images:
        return ad_images[0], "fb-ad-preview"
    if video_urls:
        img = try_video_frame(video_urls[0])
        if img:
            return img, "fb-video-frame"
    return None, "failed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unique-json", required=True)
    ap.add_argument("--images-json", required=True)
    ap.add_argument("--previous-images-json", default="")
    ap.add_argument("--full-verify-json", default="")
    ap.add_argument("--group-ids", default="", help="可选，逗号分隔；只补指定组图片")
    ap.add_argument("--product-timeout-seconds", type=float,
                    default=PRODUCT_TIMEOUT_SECONDS)
    ap.add_argument("--heartbeat-seconds", type=float,
                    default=float(os.environ.get("FB_VERIFY_IMAGE_HEARTBEAT_SECONDS", HEARTBEAT_SECONDS)))
    args = ap.parse_args()
    if (
        not math.isfinite(args.product_timeout_seconds)
        or not PRODUCT_TIMEOUT_MIN_SECONDS
        <= args.product_timeout_seconds
        <= PRODUCT_TIMEOUT_MAX_SECONDS
    ):
        ap.error(
            f"product timeout must be finite and in "
            f"[{PRODUCT_TIMEOUT_MIN_SECONDS}, {PRODUCT_TIMEOUT_MAX_SECONDS}] seconds"
        )
    if not math.isfinite(args.heartbeat_seconds) or not 0 < args.heartbeat_seconds <= 60:
        ap.error("heartbeat interval must be finite, >0 and <=60 seconds")

    unique = load_json(args.unique_json, {"groups": []})
    images = load_json(args.images_json, {})
    previous_images = load_json(args.previous_images_json, {}) if args.previous_images_json else {}
    full_verify = load_json(args.full_verify_json, {"groups": {}}) if args.full_verify_json else {"groups": {}}
    if not isinstance(unique.get("groups"), list) or not isinstance(images, dict) or not isinstance(previous_images, dict):
        raise SystemExit("persistent state has invalid schema; refusing to overwrite image cache")
    try:
        full_verify = migrate_checkpoint(full_verify)
    except ValueError as exc:
        raise SystemExit(
            f"persistent state has invalid verification schema; refusing to overwrite image cache: {exc}"
        ) from exc
    verify_groups = full_verify["groups"]
    selected_group_ids = {gid for gid in args.group_ids.split(",") if gid}

    seen_keys = set()
    todo = []
    for g in unique.get("groups", []):
        if selected_group_ids and g.get("group_id") not in selected_group_ids:
            continue
        verify = verify_groups.get(g.get("group_id"), {})
        relevant_ads = verify.get("relevant_ads") or []
        cross_urls = [ad.get("link_url") for ad in relevant_ads if ad.get("link_url")]
        ad_images = [
            image
            for ad in relevant_ads
            if (image := normalize_image_url(ad.get("image_url")))
        ]
        video_urls = [ad.get("video_url") for ad in relevant_ads if ad.get("video_url")]
        for m in g.get("members", []):
            domain = m["domain"]
            handle = m["handle"]
            key = f"{domain}|{handle}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            todo.append((key, domain, handle, m.get("url") or "", cross_urls, ad_images, video_urls))

    new_count = sum(1 for key, *_ in todo if not normalize_image_url(images.get(key)))
    print(f"[images] 全量 domain|handle 去重后: {len(todo)}，已缓存: {len(todo) - new_count}，待抓取: {new_count}")

    global _network_requests
    _network_requests = 0
    try:
        heartbeat = Heartbeat(args.heartbeat_seconds)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    results = []
    shopify_ok = 0
    og_ok = 0
    failed = 0
    cached = 0
    previous_cache_ok = 0
    cross_site_ok = 0
    ad_preview_ok = 0
    video_frame_ok = 0

    hydrated_since_checkpoint = 0
    # A missing cache is itself state that must be checkpointed, while an
    # already-normalized all-cache run should not rewrite it pointlessly.
    dirty = not os.path.exists(args.images_json)
    heartbeat.start()
    try:
        for key, domain, handle, product_url, cross_urls, ad_images, video_urls in todo:
            cached_image = normalize_image_url(images.get(key))
            if cached_image:
                if images.get(key) != cached_image:
                    dirty = True
                images[key] = cached_image
                results.append((key, domain, handle, "already-cached", cached_image))
                cached += 1
                continue

            img = normalize_image_url(previous_images.get(key))
            if img:
                # This is local data only.  Batch the durable checkpoint so a
                # month boundary with hundreds of reusable images does not
                # spend tens of minutes on writes/sleeps.
                images[key] = img
                dirty = True
                results.append((key, domain, handle, "previous-month-cache", img))
                previous_cache_ok += 1
                hydrated_since_checkpoint += 1
                if hydrated_since_checkpoint >= PREVIOUS_CACHE_CHECKPOINT_SIZE:
                    save_images(images, args.images_json)
                    hydrated_since_checkpoint = 0
                    dirty = False
                continue

            try:
                with product_timeout(args.product_timeout_seconds):
                    img, source = resolve_network_image(
                        domain, handle, product_url, cross_urls, ad_images, video_urls, key
                    )
            except ProductTimeout as exc:
                print(f"[images] product timeout {key}: {exc}; recording retryable None", file=sys.stderr, flush=True)
                img, source = None, "failed"

            if source == "shopify-json":
                shopify_ok += 1
            elif source == "og-image":
                og_ok += 1
            elif source == "cross-site-product":
                cross_site_ok += 1
            elif source == "fb-ad-preview":
                ad_preview_ok += 1
            elif source == "fb-video-frame":
                video_frame_ok += 1
            else:
                failed += 1

            images[key] = normalize_image_url(img)
            dirty = True
            results.append((key, domain, handle, source, img))
            # Network-backed misses checkpoint individually: a watchdog or a
            # later site hang must preserve every completed result.
            save_images(images, args.images_json)
            dirty = False
    finally:
        heartbeat.stop()

    # Flush an incomplete local-cache batch (or a missing empty cache).
    if dirty:
        save_images(images, args.images_json)
    ok_count = sum(1 for _, _, _, _, img in results if img)
    print(
        f"[images] 总计 {len(todo)} 个产品；已缓存跳过 {cached}；"
        f"上月缓存复用={previous_cache_ok} shopify-json={shopify_ok} og-image={og_ok} "
        f"跨站补图={cross_site_ok} 广告预览={ad_preview_ok} 视频首帧={video_frame_ok}；失败 {failed}"
    )
    print(f"[images] 图片非空总数: {ok_count}/{len(todo)}")
    print("IMAGES_SUMMARY_JSON " + json.dumps({
        "total": len(todo),
        "cached_skipped": cached,
        "new_shopify_ok": shopify_ok,
        "new_og_ok": og_ok,
        "previous_cache_ok": previous_cache_ok,
        "cross_site_ok": cross_site_ok,
        "ad_preview_ok": ad_preview_ok,
        "video_frame_ok": video_frame_ok,
        "new_failed": failed,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
