#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 product_verify_full.json 里取出"本轮验证过的一批 group_id"的统计：
确认有相关投放、🔥新起投(<=3天)、多站跨投(>=3站)数量，并生成钉钉所需的
产品标题、来源站、主图、单页链接和起投日期摘要。

用法:
  python3 compute_verify_stats.py --full-verify-json path --unique-json path \
      --images-json path --group-ids G0107,G0108
"""

import argparse
import json
import os
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verification_schema import migrate_checkpoint  # noqa: E402


DISPLAY_TZ = ZoneInfo("Asia/Shanghai")


def to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_json(path, fallback):
    if not os.path.exists(path):
        return fallback
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"persistent state unreadable; refusing to continue {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"persistent state has invalid schema; refusing to continue {path}")
    return data


def start_date_text(value):
    try:
        timestamp = float(value)
        if timestamp <= 0:
            return ""
        return datetime.fromtimestamp(timestamp, DISPLAY_TZ).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def representative_member(group, images):
    members = group.get("members") or []
    for member in members:
        key = f"{member.get('domain', '')}|{member.get('handle', '')}"
        if images.get(key):
            return member, images[key]
    if members:
        member = members[0]
        key = f"{member.get('domain', '')}|{member.get('handle', '')}"
        return member, images.get(key) or ""
    return {}, ""


def normalize_image_url(value):
    if not value or not isinstance(value, str):
        return ""
    if value.startswith("//"):
        return "https:" + value
    if value.startswith("http://"):
        return "https://" + value[len("http://"):]
    return value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full-verify-json", required=True)
    ap.add_argument("--unique-json", required=True)
    ap.add_argument("--images-json", required=True)
    ap.add_argument("--group-ids", default="", help="逗号分隔的 group_id 列表，空则输出全 0")
    args = ap.parse_args()

    gids = [g for g in args.group_ids.split(",") if g]
    matched = 0
    fresh = 0
    multi_site = 0
    matched_products = []

    if gids:
        data = load_json(args.full_verify_json, {"groups": {}})
        unique = load_json(args.unique_json, {"groups": []})
        images = load_json(args.images_json, {})
        if not isinstance(unique.get("groups"), list) or not isinstance(images, dict):
            raise SystemExit("persistent state has invalid schema; refusing to continue")
        try:
            data = migrate_checkpoint(data)
        except ValueError as exc:
            raise SystemExit(
                f"persistent state has invalid verification schema; refusing to continue: {exc}"
            ) from exc
        groups = data["groups"]
        unique_groups = {group.get("group_id"): group for group in unique.get("groups", [])}
        for gid in gids:
            rec = groups.get(gid)
            if not rec:
                continue
            relevant = to_int(rec.get("relevant_ads_count"))
            if rec.get("verification_state") != "positive" or relevant <= 0:
                continue
            matched += 1
            days = rec.get("max_run_days")
            if isinstance(days, (int, float)) and days <= 3:
                fresh += 1
            cross = to_int(rec.get("cross_site_domains_count"))
            if cross >= 3:
                multi_site += 1

            group = unique_groups.get(gid) or {}
            member, image_url = representative_member(group, images)
            image_url = normalize_image_url(image_url)
            dates = sorted({
                date
                for ad in (rec.get("relevant_ads") or [])
                if (date := start_date_text(ad.get("start_date")))
            })
            matched_products.append({
                "group_id": gid,
                "title": (
                    member.get("title")
                    or member.get("page_title")
                    or group.get("query")
                    or rec.get("query")
                    or gid
                ),
                "source_domain": member.get("domain") or "",
                "product_url": member.get("url") or "",
                "image_url": image_url,
                "first_start_date": dates[0] if dates else "",
                "latest_start_date": dates[-1] if dates else "",
                "relevant_ads_count": relevant,
                "sample_limited": bool(
                    rec.get("sample_limited")
                    or ((rec.get("harvested") or 0) >= 30 and not rec.get("fb_total_reported"))
                ),
                "sample_scope": rec.get("sample_scope") or "first_page",
                "content_matched_ads_count": rec.get("content_matched_ads_count"),
                "landing_only_matched_ads_count": rec.get("landing_only_matched_ads_count"),
                "cross_site_domains_count": cross,
                "own_domain_hit": bool(rec.get("own_domain_hit")),
            })

    print("STATS_JSON " + json.dumps(
        {
            "matched": matched,
            "fresh": fresh,
            "multi_site": multi_site,
            "matched_group_ids": [product["group_id"] for product in matched_products],
            "matched_products": matched_products,
        },
        ensure_ascii=False,
    ))


if __name__ == "__main__":
    main()
