#!/usr/bin/env python3
"""
build_dashboard.py - 合并每日热榜数据，注入图片/趋势/新品标记，生成看板 HTML
"""

import json
import glob
import os
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAILY_DIR = os.path.join(BASE_DIR, "data", "daily")
DATA_DIR = os.path.join(BASE_DIR, "data")
TEMPLATE_PATH = os.path.join(BASE_DIR, "templates", "dashboard_template.html")
OUTPUT_PATH = os.path.join(BASE_DIR, "sp_picker_dashboard.html")
IMAGES_PATH = os.path.join(DATA_DIR, "images.json")
HISTORY_PATH = os.path.join(DATA_DIR, "history.json")

# 取最近 N 天的数据
MERGE_DAYS = 3
# 历史保留天数
HISTORY_RETAIN_DAYS = 14


def load_daily_files():
    """加载所有每日热榜 JSON 文件，按日期排序"""
    pattern = os.path.join(DAILY_DIR, "sp_hotlist_*.json")
    files = sorted(glob.glob(pattern))
    all_data = []
    for fp in files:
        fname = os.path.basename(fp)
        # 从文件名提取日期: sp_hotlist_2026-04-02.json
        date_str = fname.replace("sp_hotlist_", "").replace(".json", "")
        with open(fp, "r", encoding="utf-8") as f:
            products = json.load(f)
        for p in products:
            p.setdefault("date", date_str)
        all_data.append((date_str, products))
    return all_data


def merge_products(all_data, merge_days=MERGE_DAYS):
    """取最近 N 天的数据，按 handle 去重，保留最新版本并记录峰值分"""
    # 取最近 N 天
    recent = all_data[-merge_days:] if len(all_data) > merge_days else all_data
    best = {}
    for date_str, products in recent:
        for p in products:
            handle = p["handle"]
            current = best.get(handle)
            peak_score = p.get("score", 0)
            if current:
                peak_score = max(peak_score, current.get("peak_score", current.get("score", 0)))
            if not current or date_str >= current.get("date", ""):
                best[handle] = dict(p)
                best[handle]["peak_score"] = peak_score
            else:
                current["peak_score"] = peak_score
    return list(best.values())


def _age_hours(pub_str):
    """计算 published_at 距当前的小时数"""
    if not pub_str:
        return 999.0
    try:
        dt = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600)
    except Exception:
        try:
            dt = datetime.strptime(pub_str[:10], "%Y-%m-%d")
            return max(0.0, (datetime.now() - dt).total_seconds() / 3600)
        except Exception:
            return 999.0


def _freshness_bonus(age_hours):
    if age_hours <= 12:
        return 14
    if age_hours <= 24:
        return 12
    if age_hours <= 48:
        return 9
    if age_hours <= 72:
        return 7
    if age_hours <= 24 * 5:
        return 5
    if age_hours <= 24 * 7:
        return 3
    if age_hours <= 24 * 10:
        return 1
    if age_hours <= 24 * 14:
        return 0
    if age_hours <= 24 * 21:
        return -2
    return -4


def _as_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _date_age_days(date_str):
    if not date_str:
        return 999
    try:
        dt = datetime.strptime(date_str[:10], "%Y-%m-%d")
        return max(0, (datetime.now() - dt).days)
    except Exception:
        return 999


def attach_history_metrics(products, history):
    """根据历史站点数补充首次出现、增量、重复天数等变化指标"""
    for p in products:
        handle = p["handle"]
        trend = history.get(handle, {})
        dates = sorted(trend)
        current_date = p.get("date") or (dates[-1] if dates else "")
        current_sites = p.get("sites_count", 0)

        if dates:
            current_date = max(current_date, dates[-1])
            current_sites = trend.get(current_date, current_sites)
            prev_dates = [d for d in dates if d < current_date]
            prev_sites = trend[prev_dates[-1]] if prev_dates else 0
            base_3d_date = prev_dates[-3] if len(prev_dates) >= 3 else (prev_dates[0] if prev_dates else None)
            base_3d_sites = trend[base_3d_date] if base_3d_date else 0
            first_seen = dates[0]
        else:
            prev_sites = 0
            base_3d_sites = 0
            first_seen = current_date

        p["first_seen"] = first_seen
        p["first_seen_age_days"] = _date_age_days(first_seen)
        p["last_seen"] = current_date
        p["repeat_days"] = len(dates)
        p["delta_1d"] = current_sites - prev_sites
        p["delta_3d"] = current_sites - base_3d_sites


def recompute_scores(products, history):
    """按变化价值重算看板排序分：新品/增速/投放信号优先，稳定老品降权"""
    for p in products:
        sc = p.get("sites_count", 0)
        fs = p.get("flagship_count", 0)
        age = _age_hours(p.get("published_at", ""))
        days_span = len(history.get(p["handle"], {}))
        source_score = _as_float(p.get("score"), sc + fs * 4)
        if not p.get("base_score"):
            source_score = sc + fs * 4 + _freshness_bonus(age)

        delta_1d = max(0, _as_float(p.get("delta_1d")))
        raw_delta_1d = _as_float(p.get("delta_1d"))
        spread_delta = max(0, _as_float(p.get("spread_delta")))
        first_seen_age = p.get("first_seen_age_days", 999)
        fb_hit_count = len(p.get("fb_hits", [])) if isinstance(p.get("fb_hits"), list) else 0
        has_fb_signal = fb_hit_count > 0 or _as_float(p.get("fb_total")) > 0
        has_lp_signal = bool(p.get("is_lp"))
        recent_drop = first_seen_age <= 3 and raw_delta_1d < -max(3, sc * 0.3)

        if recent_drop:
            first_seen_bonus = 0
        elif first_seen_age <= 1:
            first_seen_bonus = 6
        elif first_seen_age <= 3:
            first_seen_bonus = 4
        elif first_seen_age <= 7:
            first_seen_bonus = 2
        else:
            first_seen_bonus = 0

        change_bonus = delta_1d * 1.5 + spread_delta + first_seen_bonus
        signal_bonus = (2 if has_fb_signal else 0) + (3 if has_lp_signal else 0)
        stable_penalty = 0
        if delta_1d <= 0 and spread_delta <= 0 and not has_fb_signal and not has_lp_signal:
            stable_penalty = min(max(days_span - 7, 0) * 0.8, 8)

        score = max(0, source_score + change_bonus + signal_bonus - stable_penalty)
        p["raw_score"] = round(source_score, 1)
        p["score"] = round(score, 1)
        p["freshness_bonus"] = first_seen_bonus
        p["change_bonus"] = round(change_bonus, 1)
        p["signal_bonus"] = signal_bonus
        p["stable_penalty"] = round(stable_penalty, 1)
        p["fb_hit_count"] = fb_hit_count
        p["days_span"] = days_span
        p["age_hours"] = round(age, 1)

        if recent_drop:
            p["change_label"] = "回落观察"
            p["dashboard_priority"] = 1
        elif first_seen_age <= 3:
            p["change_label"] = "新发现"
            p["dashboard_priority"] = 3
        elif delta_1d > 0 or spread_delta > 0:
            p["change_label"] = "扩散中"
            p["dashboard_priority"] = 2
        elif has_fb_signal or has_lp_signal:
            p["change_label"] = "投放信号"
            p["dashboard_priority"] = 2
        elif stable_penalty:
            p["change_label"] = "稳定老品"
            p["dashboard_priority"] = 0
        else:
            p["change_label"] = "观察"
            p["dashboard_priority"] = 1


def build_history(all_data):
    """构建/更新历史趋势数据"""
    # 加载已有历史
    history = {}
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            history = json.load(f)

    # 合并所有日期的数据
    for date_str, products in all_data:
        for p in products:
            handle = p["handle"]
            if handle not in history:
                history[handle] = {}
            history[handle][date_str] = p.get("sites_count", 0)

    # 裁剪到最近 N 天
    cutoff = (datetime.now() - timedelta(days=HISTORY_RETAIN_DAYS)).strftime("%Y-%m-%d")
    for handle in list(history.keys()):
        history[handle] = {
            d: v for d, v in history[handle].items() if d >= cutoff
        }
        if not history[handle]:
            del history[handle]

    # 保存
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)

    return history


NEW_THRESHOLD_HOURS = 24 * 7  # 上架 7 天内算 NEW


def detect_new_products(products, history):
    """检测新品：上架 7 天内或近 3 天首次进入监控"""
    for p in products:
        p["is_new"] = (
            p.get("age_hours", 999.0) <= NEW_THRESHOLD_HOURS
            or p.get("first_seen_age_days", 999) <= 3
        )


def attach_images(products):
    """从缓存中附加图片 URL 和货币代码"""
    images = {}
    if os.path.exists(IMAGES_PATH):
        with open(IMAGES_PATH, "r", encoding="utf-8") as f:
            images = json.load(f)

    for p in products:
        handle = p["handle"]
        img_entry = images.get(handle, {})
        url = img_entry.get("url")
        # 旧缓存中的 http 图片统一转 https，避免 HTTPS 页面混合内容拦截
        if url and url.startswith("http://"):
            url = "https://" + url[len("http://"):]
        p["image_url"] = url
        p["currency"] = img_entry.get("currency")


def attach_trends(products, history):
    """附加趋势数据"""
    for p in products:
        handle = p["handle"]
        trend = history.get(handle, {})
        if len(trend) >= 2:
            p["trend"] = dict(sorted(trend.items()))
        else:
            p["trend"] = None


def generate_html(products):
    """将数据注入 HTML 模板"""
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = f.read()

    # 去除敏感字段（公开仓库不暴露站点明细）
    safe_products = []
    for p in products:
        sp = {k: v for k, v in p.items() if k not in ("sites", "flagship_hits", "fb_hits")}
        safe_products.append(sp)
    data_json = json.dumps(safe_products, indent=2, ensure_ascii=False)
    html = template.replace("/*__DATA__*/[]", data_json)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Dashboard generated: {OUTPUT_PATH}")
    print(f"  Products: {len(products)}")
    new_count = sum(1 for p in products if p.get("is_new"))
    img_count = sum(1 for p in products if p.get("image_url"))
    trend_count = sum(1 for p in products if p.get("trend"))
    changing_count = sum(1 for p in products if p.get("dashboard_priority", 0) > 0)
    print(f"  With images: {img_count}")
    print(f"  With trends: {trend_count}")
    print(f"  New products: {new_count}")
    print(f"  Change-priority products: {changing_count}")


def main():
    all_data = load_daily_files()
    if not all_data:
        print("ERROR: No daily data files found in", DAILY_DIR)
        return

    print(f"Found {len(all_data)} daily files")
    dates = [d for d, _ in all_data]
    print(f"  Date range: {dates[0]} ~ {dates[-1]}")

    # 构建历史（用所有数据）
    history = build_history(all_data)
    print(f"  History entries: {len(history)}")

    # 合并最近 N 天
    products = merge_products(all_data)

    # 计算历史变化指标，按变化价值重算评分并排序
    attach_history_metrics(products, history)
    recompute_scores(products, history)
    detect_new_products(products, history)
    products.sort(
        key=lambda x: (
            x.get("dashboard_priority", 0),
            x.get("is_new", False),
            x.get("score", 0),
            max(x.get("delta_1d", 0), x.get("spread_delta", 0)),
        ),
        reverse=True,
    )
    products = products[:100]

    # 附加各维度数据
    attach_images(products)
    attach_trends(products, history)

    # 生成 HTML
    generate_html(products)


if __name__ == "__main__":
    main()
