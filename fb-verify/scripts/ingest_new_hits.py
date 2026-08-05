#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
每日增量摄入：把单页监控持久事件流中尚未处理的新命中，构造查询词后并入本月
unique_products.json。

只负责"新增分组"，不做同款合并（合并交给 merge_duplicate_query_groups.py 处理，
它会在整份 unique_products.json 范围内按归一化查询词把新组并入老组，或把当天
多条新行并成一组）。

用法:
  python3 ingest_new_hits.py \
      --monitor-events-jsonl /path/to/data/events.jsonl \
      --new-hits-csv /path/to/reports/2026-07/new_hits.csv \
      --month 2026-07 \
      --unique-json /path/to/data/2026-07/unique_products.json \
      [--date 2026-07-10]   # 仅补跑某天时使用

正常情况下读单页监控的 append-only `events.jsonl`：即使晚上有一次完整单页扫描、
第二天早晨的 `new_hits.csv` 被覆盖，`single_page_first_detected` 事件仍会留在这里，
下一次 FB 验证会补上。`new_hits.csv` 只保留为 events 文件缺失时的兼容兜底。

退出码恒为 0（找不到数据源或当月 0 行都不是错误，属正常场景）。
摘要以单行 JSON 打印到 stdout 的最后一行，供上层 shell 脚本解析。
"""

import argparse
import copy
import csv
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from query_utils import clean_query, norm_query  # noqa: E402
from state_io import atomic_write_json, recoverable_json_transaction  # noqa: E402
from verification_schema import is_completed, migrate_checkpoint  # noqa: E402

SHANGHAI = ZoneInfo("Asia/Shanghai")


def today_shanghai():
    return datetime.now(SHANGHAI).strftime("%Y-%m-%d")


def parse_calendar_month(value, field):
    if not isinstance(value, str):
        raise SystemExit(f"{field} must use YYYY-MM")
    try:
        parsed = datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise SystemExit(f"{field} must be a valid calendar month in YYYY-MM") from exc
    if parsed.strftime("%Y-%m") != value:
        raise SystemExit(f"{field} must be a canonical calendar month in YYYY-MM")
    return value


def previous_calendar_month(value):
    parsed = datetime.strptime(value, "%Y-%m")
    year = parsed.year - (1 if parsed.month == 1 else 0)
    month = 12 if parsed.month == 1 else parsed.month - 1
    return f"{year:04d}-{month:02d}"


def bind_unique_month(state, expected_month, label):
    stated = state.get("month")
    if stated is None:
        state["month"] = expected_month
    elif parse_calendar_month(stated, f"{label} month") != expected_month:
        raise SystemExit(f"{label} month disagrees with expected month {expected_month}")
    for group in state.get("groups", []):
        if not isinstance(group, dict):
            raise SystemExit(f"{label} groups must contain objects")
        group_month = group.get("state_month")
        if group_month is None:
            group["state_month"] = expected_month
        elif parse_calendar_month(group_month, f"{label} group state_month") != expected_month:
            raise SystemExit(
                f"{label} group {group.get('group_id')} belongs to {group_month}, expected {expected_month}"
            )


def bind_verify_month(state, expected_month, label):
    stated = state.get("month")
    if stated is None:
        state["month"] = expected_month
    elif parse_calendar_month(stated, f"{label} month") != expected_month:
        raise SystemExit(f"{label} month disagrees with expected month {expected_month}")
    for container_name in (
        "groups", "checkpoint_archive", "retry_errors", "retry_archive",
        "carryover_evidence_archive",
    ):
        container = state.get(container_name, {})
        if not isinstance(container, dict):
            raise SystemExit(f"{label} {container_name} must be an object")
        for gid, record in container.items():
            if not isinstance(record, dict):
                raise SystemExit(f"{label} {container_name} record {gid} must be an object")
            record_month = record.get("state_month")
            if record_month is None:
                record["state_month"] = expected_month
            elif parse_calendar_month(
                record_month, f"{label} {container_name} state_month"
            ) != expected_month:
                raise SystemExit(
                    f"{label} {container_name} record {gid} belongs to {record_month}, "
                    f"expected {expected_month}"
                )


def validate_previous_state_paths(unique_path, verify_path, expected_month):
    for label, raw_path in (
        ("previous unique", unique_path), ("previous verify", verify_path),
    ):
        if not raw_path:
            continue
        parent_month = Path(raw_path).resolve().parent.name
        if parent_month != expected_month:
            raise SystemExit(
                f"{label} path must be inside the expected {expected_month} monthly directory"
            )


def parse_seen_datetime_shanghai(value):
    """把 ISO8601 时间转成 Asia/Shanghai datetime。解析失败返回 None。"""
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=SHANGHAI)
    return dt.astimezone(SHANGHAI)


def parse_first_seen_date_shanghai(value):
    dt = parse_seen_datetime_shanghai(value)
    return dt.strftime("%Y-%m-%d") if dt else None


def row_from_event(event):
    """把单页监控的 single_page_first_detected 事件对齐到 new_hits.csv 字段。"""
    seen_at = event.get("run_at") or ""
    return {
        "first_seen_at": seen_at,
        "first_seen_month": event.get("month") or "",
        "domain": event.get("domain") or "",
        "handle": event.get("handle") or "",
        "url": event.get("url") or "",
        "product_title": event.get("title") or "",
        "page_title": event.get("title") or "",
        "created_at": event.get("created_at") or "",
        "published_at": event.get("published_at") or "",
        "updated_at": event.get("updated_at") or "",
        "lastmod": event.get("lastmod") or "",
        "signal_date": event.get("signal_date") or "",
        "tier": event.get("tier") or "",
    }


def matches_scope(seen_date, target_month, target_date, carryover_date):
    """正常运行收当月事件；月初同时接住前一天夜间事件，避免跨月丢失。"""
    if target_date:
        return seen_date == target_date
    return seen_date.startswith(target_month + "-") or seen_date == carryover_date


def load_event_rows(path, target_month, target_date=None, carryover_date=None, not_before=None):
    """读取 append-only 事件流；只保留首次发现的单页事件。"""
    stats = {
        "found": bool(path and os.path.exists(path)), "lines": 0, "invalid": 0,
        "matching": 0, "before_cutoff": 0,
    }
    rows = []
    if not stats["found"]:
        return rows, stats
    cutoff_dt = parse_seen_datetime_shanghai(not_before) if not_before else None

    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            stats["lines"] += 1
            try:
                event = json.loads(line)
            except ValueError:
                stats["invalid"] += 1
                continue
            if event.get("type") != "single_page_first_detected":
                continue
            row = row_from_event(event)
            if not row["domain"] or not row["handle"]:
                stats["invalid"] += 1
                continue
            seen_dt = parse_seen_datetime_shanghai(row["first_seen_at"])
            if not seen_dt:
                stats["invalid"] += 1
                continue
            if cutoff_dt and seen_dt <= cutoff_dt:
                stats["before_cutoff"] += 1
                continue
            seen_date = seen_dt.strftime("%Y-%m-%d")
            if not matches_scope(seen_date, target_month, target_date, carryover_date):
                continue
            rows.append(row)
            stats["matching"] += 1
    return rows, stats


def load_csv_rows(path, target_month, target_date=None, carryover_date=None, not_before=None):
    """events.jsonl 不存在时的兼容兜底（CSV 仅保存最近一次扫描的新命中）。"""
    stats = {"found": bool(path and os.path.exists(path)), "total_rows": 0, "matching": 0, "before_cutoff": 0}
    rows = []
    if not stats["found"]:
        return rows, stats
    cutoff_dt = parse_seen_datetime_shanghai(not_before) if not_before else None
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            stats["total_rows"] += 1
            seen_dt = parse_seen_datetime_shanghai(row.get("first_seen_at"))
            if not seen_dt:
                continue
            if cutoff_dt and seen_dt <= cutoff_dt:
                stats["before_cutoff"] += 1
                continue
            seen_date = seen_dt.strftime("%Y-%m-%d")
            if not matches_scope(seen_date, target_month, target_date, carryover_date):
                continue
            rows.append(row)
            stats["matching"] += 1
    return rows, stats


def load_unique(path):
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"unique state unreadable; refusing to overwrite {path}: {exc}")
        if not isinstance(data, dict) or not isinstance(data.get("groups"), list):
            raise SystemExit(f"unique state has invalid schema; refusing to overwrite {path}")
        return data
    # 月度初始状态（新月份第一次跑 / 文件缺失）
    return {
        "generated_at": datetime.now(SHANGHAI).isoformat(),
        "total_groups": 0,
        "groups": [],
    }


def load_json(path, default):
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"persistent state unreadable; refusing to overwrite {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"persistent state has invalid schema; refusing to overwrite {path}")
    return data


def verification_is_completed(record):
    try:
        return is_completed(record)
    except ValueError:
        return False


def load_previous_context(unique_path, verify_path, expected_month):
    """读取上月成员与验证结果，用于月初去重和同款结果复用。"""
    validate_previous_state_paths(unique_path, verify_path, expected_month)
    previous_unique = load_unique(unique_path) if unique_path else {"groups": []}
    bind_unique_month(previous_unique, expected_month, "previous unique")
    previous_verify = load_json(verify_path, {"groups": {}})
    if (not isinstance(previous_verify.get("groups"), dict)
            or ("retry_errors" in previous_verify and not isinstance(previous_verify["retry_errors"], dict))):
        raise SystemExit(f"persistent state has invalid schema; refusing to overwrite {verify_path}")

    completed_member_keys = set()
    query_groups = {}
    try:
        previous_verify = migrate_checkpoint(previous_verify)
    except ValueError as exc:
        raise SystemExit(
            f"persistent state has invalid verification schema; refusing to overwrite "
            f"{verify_path}: {exc}"
        ) from exc
    bind_verify_month(previous_verify, expected_month, "previous verify")
    verify_groups = previous_verify["groups"]
    for group in previous_unique.get("groups", []):
        verify_result = verify_groups.get(group.get("group_id"))
        if verification_is_completed(verify_result):
            for member in group.get("members", []):
                domain = member.get("domain")
                handle = member.get("handle")
                if domain and handle:
                    completed_member_keys.add((domain, handle))
        normalized = norm_query(group.get("query"))
        if not normalized:
            continue
        candidate = {
            "group_id": group.get("group_id") or "",
            "verify_result": verify_result if verification_is_completed(verify_result) else None,
        }
        existing = query_groups.get(normalized)
        # 同查询词多组时，优先选择已有验证结果的组。
        if existing is None or (not existing.get("verify_result") and candidate.get("verify_result")):
            query_groups[normalized] = candidate
    return previous_unique, previous_verify, completed_member_keys, query_groups


def group_identity(group):
    members = {
        (member.get("domain"), member.get("handle"))
        for member in group.get("members", [])
        if isinstance(member, dict) and member.get("domain") and member.get("handle")
    }
    return norm_query(group.get("query")), frozenset(members)


def migrate_unresolved(previous_unique, previous_verify, current_unique, current_verify):
    """Carry every unresolved group and retry state into the new month.

    IDs are preserved so the retry ledger continues to point at the same
    product group.  Existing current-month records win only as containers; no
    persisted group or checkpoint is removed.
    """
    current_groups = current_unique.setdefault("groups", [])
    by_gid = {group.get("group_id"): group for group in current_groups}
    reserved_gids = {
        group.get("group_id")
        for group in [*current_groups, *previous_unique.get("groups", [])]
        if group.get("group_id")
    }
    next_counter = next_gid_counter([*current_groups, *previous_unique.get("groups", [])])
    gid_remap = {}
    migrated_groups = 0
    migrated_retry = 0
    migrated_inconclusive = 0
    for group in previous_unique.get("groups", []):
        gid = group.get("group_id")
        if not gid or group.get("quarantined"):
            continue
        previous_record = previous_verify.get("groups", {}).get(gid)
        if verification_is_completed(previous_record):
            continue
        target_gid = gid
        if gid in by_gid and group_identity(by_gid[gid]) != group_identity(group):
            while f"G{next_counter:04d}" in reserved_gids:
                next_counter += 1
            target_gid = f"G{next_counter:04d}"
            next_counter += 1
            reserved_gids.add(target_gid)
        gid_remap[gid] = target_gid
        if target_gid not in by_gid:
            carried = copy.deepcopy(group)
            carried["group_id"] = target_gid
            carried["already_verified"] = False
            carried["verify_result"] = None
            carried["carried_from"] = f"previous_month:{gid}"
            carried["carried_from_month"] = previous_unique.get("month")
            carried["state_month"] = current_unique["month"]
            if target_gid != gid:
                carried["original_group_id"] = gid
                carried["carry_id_remap"] = {"from": gid, "to": target_gid}
                current_unique.setdefault("carryover_group_id_remaps", {})[
                    f"{previous_unique.get('month') or 'previous'}:{gid}"
                ] = target_gid
            current_groups.append(carried)
            by_gid[target_gid] = carried
            migrated_groups += 1
    current_records = current_verify.setdefault("groups", {})
    evidence_archive = current_verify.setdefault("carryover_evidence_archive", {})
    for old_gid, target_gid in gid_remap.items():
        previous_record = previous_verify.get("groups", {}).get(old_gid)
        if not isinstance(previous_record, dict) or verification_is_completed(previous_record):
            continue
        carried_record = copy.deepcopy(previous_record)
        carried_record["group_id"] = target_gid
        carried_record["evidence_group_id"] = old_gid
        carried_record["carried_from"] = f"previous_month:{old_gid}"
        carried_record["state_month"] = current_unique["month"]
        if target_gid != old_gid:
            carried_record["original_group_id"] = old_gid
        existing_record = current_records.get(target_gid)
        if existing_record is None:
            current_records[target_gid] = carried_record
        elif not verification_is_completed(existing_record):
            evidence_archive[f"{previous_unique.get('month') or 'previous'}:{old_gid}"] = carried_record
            merged_record = copy.deepcopy(existing_record)
            for key, value in carried_record.items():
                if merged_record.get(key) in (None, "", [], {}) and value not in (None, "", [], {}):
                    merged_record[key] = value
            current_records[target_gid] = merged_record
        # A terminal current-month record is more authoritative; archive the
        # older inconclusive evidence without replacing it.
        else:
            evidence_archive[f"{previous_unique.get('month') or 'previous'}:{old_gid}"] = carried_record
        migrated_inconclusive += 1
    current_retries = current_verify.setdefault("retry_errors", {})
    for gid, retry in previous_verify.get("retry_errors", {}).items():
        target_gid = gid_remap.get(gid)
        if target_gid in by_gid and target_gid not in current_retries:
            carried_retry = copy.deepcopy(retry)
            carried_retry["migrated_from"] = "previous_month"
            carried_retry["group_id"] = target_gid
            carried_retry["state_month"] = current_unique["month"]
            if target_gid != gid:
                carried_retry["original_group_id"] = gid
                carried_retry["migrated_from_group_id"] = gid
            current_retries[target_gid] = carried_retry
            migrated_retry += 1
    return migrated_groups, migrated_retry, migrated_inconclusive


def member_from_row(row):
    return {
        "domain": row["domain"],
        "handle": row["handle"],
        "url": row.get("url") or "",
        "title": row.get("product_title") or row.get("page_title") or "",
        "page_title": row.get("page_title") or "",
        "created_at": row.get("created_at") or "",
        "signal_date": row.get("signal_date") or "",
        "tier": row.get("tier") or "",
        "first_seen_at": row.get("first_seen_at") or "",
    }


def next_gid_counter(groups):
    max_n = 0
    for g in groups:
        gid = g.get("group_id") or ""
        if gid.startswith("G") and gid[1:].isdigit():
            max_n = max(max_n, int(gid[1:]))
    return max_n + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-hits-csv", default="", help="兼容兜底：最近一次扫描的 new_hits.csv")
    ap.add_argument("--monitor-events-jsonl", default="", help="首选：单页监控 append-only events.jsonl")
    ap.add_argument("--unique-json", required=True)
    ap.add_argument("--month", default=None, help="YYYY-MM (Asia/Shanghai)，默认当前月")
    ap.add_argument("--date", default=None, help="YYYY-MM-DD (Asia/Shanghai)，仅补跑某天时使用")
    ap.add_argument("--not-before", default=None, help="仅常规运行使用：忽略不晚于该 ISO8601 水位线的历史事件")
    ap.add_argument("--previous-unique-json", default="", help="上月产品组；用于跨月精确成员去重")
    ap.add_argument("--previous-full-verify-json", default="", help="上月验证结果；用于新站同款免查询复用")
    ap.add_argument("--full-verify-json", default="", help="本月 checkpoint；月初迁移未解决 retry 状态")
    args = ap.parse_args()

    target_month = parse_calendar_month(
        args.month or today_shanghai()[:7], "target month"
    )
    target_date = args.date
    if target_date:
        try:
            parsed_target_date = datetime.strptime(target_date, "%Y-%m-%d")
        except ValueError as exc:
            raise SystemExit("target date must be a valid calendar date in YYYY-MM-DD") from exc
        if parsed_target_date.strftime("%Y-%m-%d") != target_date or target_date[:7] != target_month:
            raise SystemExit("target date must be canonical and belong to target month")
    carryover_date = (datetime.now(SHANGHAI) - timedelta(days=1)).strftime("%Y-%m-%d")
    # 显式补跑应能处理水位线之前的历史事件；常规每日任务才启用水位线。
    not_before = None if target_date else args.not_before
    rows, event_stats = load_event_rows(
        args.monitor_events_jsonl, target_month, target_date, carryover_date, not_before
    )
    source = "monitor_events_jsonl"
    csv_stats = {"found": False, "total_rows": 0, "matching": 0, "before_cutoff": 0}
    if not event_stats["found"]:
        rows, csv_stats = load_csv_rows(
            args.new_hits_csv, target_month, target_date, carryover_date, not_before
        )
        source = "new_hits_csv_fallback"

    unique = load_unique(args.unique_json)
    bind_unique_month(unique, target_month, "current unique")
    previous_unique, previous_verify, previous_member_keys, previous_query_groups = load_previous_context(
        args.previous_unique_json, args.previous_full_verify_json,
        previous_calendar_month(target_month),
    )
    current_verify = load_json(args.full_verify_json, {"groups": {}}) if args.full_verify_json else {"groups": {}}
    if (not isinstance(current_verify.get("groups"), dict)
            or ("retry_errors" in current_verify and not isinstance(current_verify["retry_errors"], dict))):
        raise SystemExit(f"persistent state has invalid schema; refusing to overwrite {args.full_verify_json}")
    try:
        current_verify = migrate_checkpoint(current_verify)
    except ValueError as exc:
        raise SystemExit(
            f"persistent state has invalid verification schema; refusing to overwrite "
            f"{args.full_verify_json}: {exc}"
        ) from exc
    bind_verify_month(current_verify, target_month, "current verify")
    groups = unique["groups"]
    migrated_unresolved_groups, migrated_retry_states, migrated_inconclusive_records = migrate_unresolved(
        previous_unique, previous_verify, unique, current_verify
    )

    existing_keys = set()
    for g in groups:
        for m in g.get("members", []):
            existing_keys.add((m["domain"], m["handle"]))

    seen_today = set()
    gid_counter = next_gid_counter(groups)
    added_groups = 0
    skipped_existing = 0
    skipped_previous_member = 0
    skipped_dup_in_batch = 0
    reused_previous_query = 0

    for row in rows:
        key = (row["domain"], row["handle"])
        if key in previous_member_keys:
            skipped_previous_member += 1
            continue
        if key in existing_keys:
            skipped_existing += 1
            continue
        if key in seen_today:
            skipped_dup_in_batch += 1
            continue
        seen_today.add(key)

        member = member_from_row(row)
        query = clean_query(member["title"], member["page_title"])
        gid = f"G{gid_counter:04d}"
        gid_counter += 1
        previous_match = previous_query_groups.get(norm_query(query))
        previous_result = previous_match.get("verify_result") if previous_match else None
        reused_from = previous_match.get("group_id") if previous_match else None
        already_verified = bool(previous_result)
        groups.append({
            "group_id": gid,
            "source": "daily_new",
            "duplicate_key": None,
            "query": query,
            "members": [member],
            "already_verified": already_verified,
            "verify_result": previous_result if already_verified else None,
            "reused_from": f"previous_month:{reused_from}" if already_verified else None,
            "added_on": parse_first_seen_date_shanghai(member["first_seen_at"]) or target_date or target_month,
            "state_month": target_month,
        })
        if already_verified:
            reused_previous_query += 1
        existing_keys.add(key)
        added_groups += 1

    unique["groups"] = groups
    unique["total_groups"] = len(groups)
    unique["updated_at"] = datetime.now(SHANGHAI).isoformat()
    bind_unique_month(unique, target_month, "current unique")
    bind_verify_month(current_verify, target_month, "current verify")

    if args.full_verify_json:
        current_verify["updated_at"] = datetime.now(SHANGHAI).isoformat()
        recoverable_json_transaction(
            [(args.unique_json, unique), (args.full_verify_json, current_verify)]
        )
    else:
        atomic_write_json(args.unique_json, unique)

    summary = {
        "source": source,
        "target_month": target_month,
        "target_date": target_date,
        "carryover_date": carryover_date if not target_date else None,
        "not_before": not_before,
        "monitor_events_found": event_stats["found"],
        "monitor_events_lines": event_stats["lines"],
        "monitor_events_matching": event_stats["matching"],
        "monitor_events_invalid": event_stats["invalid"],
        "monitor_events_before_cutoff": event_stats["before_cutoff"],
        "new_hits_csv_found": csv_stats["found"],
        "new_hits_csv_total_rows": csv_stats["total_rows"],
        "new_hits_csv_before_cutoff": csv_stats["before_cutoff"],
        "rows_matching_scope": len(rows),
        "skipped_already_known": skipped_existing,
        "skipped_previous_member": skipped_previous_member,
        "skipped_dup_in_batch": skipped_dup_in_batch,
        "pruned_previous_members": 0,
        "pruned_previous_groups": 0,
        "migrated_unresolved_groups": migrated_unresolved_groups,
        "migrated_retry_states": migrated_retry_states,
        "migrated_inconclusive_records": migrated_inconclusive_records,
        "reused_previous_query": reused_previous_query,
        "groups_added": added_groups,
        "total_groups_after": len(groups),
    }
    print(f"[ingest] source={source} target_month={target_month} target_date={target_date or '-'} "
          f"carryover_date={carryover_date if not target_date else '-'} not_before={not_before or '-'} "
          f"rows_matching_scope={len(rows)} events_found={event_stats['found']} "
          f"events_lines={event_stats['lines']} events_matching={event_stats['matching']} "
          f"events_before_cutoff={event_stats['before_cutoff']} "
          f"skipped_already_known={skipped_existing} skipped_previous_member={skipped_previous_member} "
          f"skipped_dup_in_batch={skipped_dup_in_batch} pruned_previous_members=0 "
          f"pruned_previous_groups=0 migrated_unresolved_groups={migrated_unresolved_groups} "
          f"migrated_retry_states={migrated_retry_states} reused_previous_query={reused_previous_query} "
          f"migrated_inconclusive_records={migrated_inconclusive_records} "
          f"groups_added={added_groups} total_groups_after={len(groups)}")
    print("SUMMARY_JSON " + json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
