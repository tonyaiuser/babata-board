#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
共享的 FB 广告库查询词构造规则。

从一次性脚本 build_unique_products.py 原样搬过来，供每日增量脚本
(ingest_new_hits.py) 复用，保证查询词构造规则与 7 月初始状态一致。
"""

import re

EMOJI_PATTERN = re.compile(
    "["
    "\U0001F000-\U0001FFFF"
    "\U00002600-\U000027BF"
    "\U0001F1E6-\U0001F1FF"
    "←-⇿⌀-⏿■-◿⬀-⯿"
    "️‍"
    "]+",
    flags=re.UNICODE,
)

PROMO_PHRASES = re.compile(
    r"\b("
    r"LAST\s+DAY(\s+SALE)?(\s+ONLY)?|FINAL\s+\d+\s+HOURS?|"
    r"SUMMER\s+HOT\s+SALE|HOT\s+SALE(S)?|KITCHEN\s+HOT\s+SALE|"
    r"LIMITED[- ]TIME(\s+SPECIAL)?|LIMITED\s+TIME|"
    r"PROMO\s+LIMIT[EÉ]E?|"
    r"\d+K\+?\s*SOLD|SOLD!?|"
    r"NEW\s+HOT\s+SELLING|"
    r"BUY\s+\d+\s+GET\s+\d+\s+FREE|"
    r"EARLY\s+BLACK\s+FRIDAY(\s+SALE)?|BLACK\s+FRIDAY|"
    r"FESTIVE\s+FEAST\s+DEAL|CHRISTMAS\s+SALE|NEW\s+YEAR\s+SALE|"
    r"BEST\s+SELLER|RECOMMENDED\s+BY[^\]\n]*|"
    r"TIME[- ]LIMITED|TIME[- ]LIMITED\s+SPECIAL|"
    r"NEW\s+UPGRADE(D)?|2026\s+NEW|"
    r"DIRECT\s+FROM\s+THE\s+MANUFACTURER|"
    r"NICE\s+GIFT\*?|PERFECT\s+FOR\s+ALL\s+AGES|"
    r"FLASH\s+SALE|CLEARANCE|"
    r"WAS\s+[\d.]+\s*\$?,?\s*NOW\s+[\d.]+\s*\$?|"
    r"ONLY\s+\d+\s*(PLACES)?|ONLY!*|NOW!*|"
    r"ALERT"
    r")\b",
    flags=re.IGNORECASE,
)

TRAILING_CONNECTOR_RE = re.compile(
    r"(\s+(&|and|for|with|of|to|in|on|at|from|by|is|are|no|a|an|the|\d{1,2}|"
    r"[-–—]))+$",
    flags=re.IGNORECASE,
)

BRACKET_RE = re.compile(r"\[[^\]]*\]")
PRICE_RE = re.compile(r"[£$€￡]\s?[\d,]+(\.\d+)?")
PERCENT_OFF_RE = re.compile(r"\d+\s*%\s*(OFF|DE\s*R[ÉE]DUCTION)?", flags=re.IGNORECASE)
YEAR_RE = re.compile(r"\b20(2[4-9]|3[0-5])\b")
PUNCT_LEAD_RE = re.compile(r"^[\s:：\-–—|✅✨💥🔥⏳⏰🎁🌟💎!！,.，。*]+")
MULTI_SPACE_RE = re.compile(r"\s{2,}")
PAGE_TITLE_SUFFIX_RE = re.compile(r"\s*-\s*[a-z0-9\-]+\s*$", flags=re.IGNORECASE)


def strip_emoji(t):
    return EMOJI_PATTERN.sub(" ", t)


def clean_query(raw_title, fallback_page_title=""):
    """把原始标题清洗成一个 3-6 词左右的独特产品名短语，用作 FB exact_phrase 查询词。"""
    title = (raw_title or "").strip() or (fallback_page_title or "").strip()
    if not title:
        return ""

    if not raw_title and fallback_page_title:
        title = PAGE_TITLE_SUFFIX_RE.sub("", title)

    t = strip_emoji(title)
    t = BRACKET_RE.sub(" ", t)
    t = PRICE_RE.sub(" ", t)
    t = PERCENT_OFF_RE.sub(" ", t)
    t = PROMO_PHRASES.sub(" ", t)
    t = YEAR_RE.sub(" ", t)
    t = re.sub(r"[!！]+", " ", t)

    if "|" in t:
        first_seg = t.split("|", 1)[0].strip()
        if len(first_seg.split()) >= 2:
            t = first_seg

    t = PUNCT_LEAD_RE.sub("", t)
    t = re.sub(r"[*✅💥]", " ", t)
    t = re.sub(r"\s*,\s*", " ", t)
    t = MULTI_SPACE_RE.sub(" ", t).strip(" .:-–—|,")

    words = t.split()
    if len(words) > 6:
        words = words[:6]
    out = " ".join(words).strip(" .:-–—|,")
    prev = None
    while prev != out:
        prev = out
        out = TRAILING_CONNECTOR_RE.sub("", out).strip()
    return out


def norm_query(q):
    return " ".join((q or "").strip().lower().split())
