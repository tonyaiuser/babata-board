#!/usr/bin/env python3
"""
sync_openclaw.py - 从 openclaw workspace 同步 SP 热榜数据
openclaw 格式: {scored_results: [...], results: [...], ...}
spspy 格式: [{handle, title, price, ...}, ...]  (纯列表, Top 100)
"""

import json
import glob
import os

OPENCLAW_DIR = os.path.expanduser("~/.openclaw/workspace")
DAILY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "daily")

# 需要保留的字段
FIELDS = [
    "handle", "title", "price", "published_at",
    "sites", "sites_count", "flagship_hits", "flagship_count",
    "sample_url", "score",
    "freshness", "days_old", "base_score", "spread_delta", "aging_penalty",
    "fb_hits", "fb_total", "is_lp", "countries", "flagship_days",
]


def default_value(field):
    if field in ("title", "handle", "price", "published_at", "sample_url"):
        return ""
    if field in ("sites", "flagship_hits", "fb_hits", "countries"):
        return []
    if field == "is_lp":
        return False
    return 0


def convert_file(src_path, date_str):
    """将 openclaw 格式转换为 spspy 格式"""
    with open(src_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # 已经是列表格式（旧格式），直接跳过
    if isinstance(raw, list):
        return raw[:100]

    # openclaw 格式: 看板主口径必须用当天 results，避免历史 scored_results 老品回流。
    items = raw.get("results") or raw.get("scored_results", [])
    if not items:
        return None

    scored_by_handle = {
        item.get("handle"): item
        for item in raw.get("scored_results", [])
        if item.get("handle")
    }

    for item in items:
        handle = item.get("handle")
        score_row = scored_by_handle.get(handle, {})
        if score_row and not item.get("score"):
            item["score"] = score_row.get("score", 0)

    # 按 score 降序取 Top 100；score 只用于排序，不改变当天 results 的站点口径。
    items.sort(key=lambda x: x.get("score", 0), reverse=True)

    output = []
    for p in items[:100]:
        entry = {k: p.get(k, default_value(k)) for k in FIELDS}
        entry["date"] = date_str
        # 确保列表字段类型稳定，方便看板直接消费
        for field in ("sites", "flagship_hits", "fb_hits", "countries"):
            if not isinstance(entry.get(field), list):
                entry[field] = []
        entry["is_lp"] = bool(entry.get("is_lp"))
        output.append(entry)

    return output


def main():
    if not os.path.isdir(OPENCLAW_DIR):
        print("openclaw workspace not found, skipping sync")
        return

    # 找 openclaw 中所有 sp_hotlist 文件
    pattern = os.path.join(OPENCLAW_DIR, "sp_hotlist_*.json")
    src_files = sorted(glob.glob(pattern))

    synced = 0
    skipped = 0

    import re
    date_pattern = re.compile(r"^sp_hotlist_(\d{4}-\d{2}-\d{2})\.json$")

    for src in src_files:
        fname = os.path.basename(src)
        m = date_pattern.match(fname)
        if not m:
            continue
        date_str = m.group(1)
        dst = os.path.join(DAILY_DIR, fname)

        # 目标已存在且比源文件新，跳过
        if os.path.exists(dst) and os.path.getmtime(dst) >= os.path.getmtime(src):
            skipped += 1
            continue

        products = convert_file(src, date_str)
        if not products:
            print(f"  {date_str}: SKIP (no data)")
            continue

        with open(dst, "w", encoding="utf-8") as f:
            json.dump(products, f, indent=2, ensure_ascii=False)

        print(f"  {date_str}: synced {len(products)} products")
        synced += 1

    print(f"Sync done: {synced} new, {skipped} up-to-date")


if __name__ == "__main__":
    main()
