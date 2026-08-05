#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FB 广告库验证 —— 独立钉钉推送。

只读复用单页监控 run_daily.sh 里同一套凭证获取方式：从
~/.openclaw/workspace/skills/sp-monitor/run.py 里用 ast 静态解析出
DINGTALK_WEBHOOK / DINGTALK_SECRET 两个常量（不 import、不执行该文件，也不修改它），
用同一套 HMAC-SHA256 签名逻辑直接调用钉钉自定义机器人 webhook。

不硬编码、不打印 webhook/secret 到 stdout/stderr/日志。

用法:
  python3 notify_dingtalk.py \
      --verified-count 3 --matched-count 2 --fresh-count 1 --multi-site-count 0 \
      --matched-products-json '[{"title":"Example"}]' \
      --dashboard-url https://tonyaiuser.github.io/babata-board/fb_verify_dashboard.html \
      [--dry-run]

--dry-run: 只打印将要发送的消息正文（标题+markdown文本），不读取凭证、不发起任何网络请求。
"""

import argparse
import ast
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_CONFIG = "/Users/tonyaiuser/.openclaw/workspace/skills/sp-monitor/run.py"
MAX_PRODUCT_DETAILS = 10


def clean_inline(value, limit=72):
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    for char in ("\\", "*", "_", "[", "]"):
        text = text.replace(char, f"\\{char}")
    return text


def product_markdown(index, product):
    title = clean_inline(product.get("title") or product.get("group_id") or "未命名产品")
    domain = clean_inline(product.get("source_domain") or "未知来源", limit=80)
    first_date = product.get("first_start_date") or "未知"
    latest_date = product.get("latest_start_date") or ""
    if latest_date and latest_date != first_date:
        date_text = f"首次：{first_date}｜最近：{latest_date}"
    else:
        date_text = f"起投：{first_date}"

    ad_count = int(product.get("relevant_ads_count") or 0)
    domain_count = int(product.get("cross_site_domains_count") or 0)
    own_hit = "｜原站在投" if product.get("own_domain_hit") else ""
    sample_suffix = "+" if product.get("sample_limited") else ""
    return (
        f"{index}. **{title}**（{domain}）\n\n"
        f"{date_text}｜首屏相关样本 {ad_count}{sample_suffix} 条 / {domain_count} 个落地域名{own_hit}"
    )


def build_message(
    verified_count,
    matched_count,
    fresh_count,
    multi_site_count,
    dashboard_url,
    matched_products=None,
    batch_url="",
):
    title = "FB 投放验证已更新"
    products = list(matched_products or [])
    detail_products = products[:MAX_PRODUCT_DETAILS]
    detail_text = ""
    if detail_products:
        blocks = [product_markdown(index, product) for index, product in enumerate(detail_products, 1)]
        detail_text = "\n\n#### 本轮确认产品\n\n" + "\n\n".join(blocks) + "\n"
        if len(products) > len(detail_products):
            detail_text += f"\n另有 {len(products) - len(detail_products)} 个确认产品，请在看板查看。\n"

    batch_link = ""
    if batch_url:
        batch_link = f"[查看本轮 {matched_count} 个产品图文看板]({batch_url})\n\n"

    text = f"""### {title}

- 本轮完成 FB 查询：{verified_count}
- ✅ 确认相关投放：{matched_count}
- 🔥 新起投（首次起投 ≤3 天）：{fresh_count}
- 首屏样本多落地域名（≥3）：{multi_site_count}
{detail_text}
> 广告条数为本次抓到的首屏相关样本，不等于 Facebook 广告总量。

{batch_link}[查看完整月度看板]({dashboard_url})
"""
    return title, text


def load_credentials(config_path):
    source = Path(config_path).read_text(encoding="utf-8")
    module = ast.parse(source)
    values = {}
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in {"DINGTALK_WEBHOOK", "DINGTALK_SECRET"}:
                values[target.id] = ast.literal_eval(node.value)
    webhook = values.get("DINGTALK_WEBHOOK")
    secret = values.get("DINGTALK_SECRET")
    if not webhook or not secret:
        raise SystemExit("missing DingTalk webhook or secret in config")
    return webhook, secret


def send(webhook, secret, title, text):
    payload = {
        "msgtype": "markdown",
        "markdown": {"title": title, "text": text},
    }
    timestamp = str(round(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
    sign = urllib.parse.quote_plus(
        base64.b64encode(hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).digest()).decode("utf-8")
    )
    separator = "&" if "?" in webhook else "?"
    url = f"{webhook}{separator}timestamp={timestamp}&sign={sign}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verified-count", type=int, required=True)
    ap.add_argument("--matched-count", type=int, required=True)
    ap.add_argument("--fresh-count", type=int, default=0)
    ap.add_argument("--multi-site-count", type=int, default=0)
    ap.add_argument("--matched-products-json", default="[]")
    ap.add_argument("--batch-url", default="")
    ap.add_argument("--dashboard-url", required=True)
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    try:
        matched_products = json.loads(args.matched_products_json)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid --matched-products-json: {exc}") from exc
    if not isinstance(matched_products, list):
        raise SystemExit("--matched-products-json must be a JSON array")

    title, text = build_message(
        args.verified_count,
        args.matched_count,
        args.fresh_count,
        args.multi_site_count,
        args.dashboard_url,
        matched_products,
        args.batch_url,
    )

    if args.dry_run:
        print("[notify_dingtalk] DRY RUN — 不读取凭证，不发送，仅打印消息体：")
        print(f"--- title ---\n{title}")
        print(f"--- markdown text ---\n{text}")
        print("NOTIFY_SUMMARY_JSON " + json.dumps({"sent": False, "dry_run": True}, ensure_ascii=False))
        return

    webhook, secret = load_credentials(args.config)
    try:
        resp = send(webhook, secret, title, text)
    except Exception as e:  # noqa: BLE001 - best-effort notify, caller treats failure as non-fatal
        print(f"[notify_dingtalk] send failed: {e}", file=sys.stderr)
        print("NOTIFY_SUMMARY_JSON " + json.dumps({"sent": False, "error": str(e)}, ensure_ascii=False))
        sys.exit(1)

    # 钉钉返回体里没有敏感信息（只有 errcode/errmsg），可以正常打印用于排障。
    print(f"[notify_dingtalk] sent. response={resp}")
    print("NOTIFY_SUMMARY_JSON " + json.dumps({"sent": True}, ensure_ascii=False))


if __name__ == "__main__":
    main()
