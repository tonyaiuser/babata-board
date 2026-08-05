#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
合并 unique_products.json 里"归一化查询词相同"但被拆成多组的产品组（同款合组）。

这是从一次性脚本原样迁移过来的通用逻辑，每日增量流程复用它：
ingest_new_hits.py 只管把持久事件流中新命中的行各自建一个新组，同款合并统一交给这里，
不管新组是跟老组重复（并入老的、已验证过的 group_id，从而不触发重新 FB 查询），
还是当天多条新命中彼此重复（并成一组，只需要查一次）。

处理逻辑：
  1. 按 query 归一化（lower + 折叠空白）分桶。
  2. 桶内 group 数 > 1 的，合并为一组：
     - 保留数组中最靠前（group_id 数字最小）的那个 group_id 作为合并后的 id
     - members 取所有子组成员的并集（按 domain+handle 去重）
     - 其它字段（source / duplicate_key / query 原文等）取第一组的值，并记录 merged_from
  3. 同步更新 product_verify_full.json：
     - 每个被合并的查询词，只保留 relevant_ads_count 最大的那份验证结果（并列取 group_id
       最小的），键改写为合并后保留的 group_id；其余子组的 key 从文件中删除。

用法:
  python3 merge_duplicate_query_groups.py \
      --unique-json /path/to/data/2026-07/unique_products.json \
      --full-verify-json /path/to/data/2026-07/product_verify_full.json
"""

import argparse
import json
import os
import math
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_fb_verify_page import validate_alias_contract as validate_dashboard_alias_contract
from state_io import recoverable_json_transaction
from verification_schema import migrate_checkpoint, migrate_verification_record


CHECKPOINT_QUARANTINE_FIELDS = (
    "quarantined",
    "quarantine_reason",
    "merged_into",
    "quarantined_at",
    "quarantine_source_state",
)


def norm_query(q):
    return " ".join((q or "").strip().lower().split())


def gid_selection_key(gid):
    """Choose the numerically smallest canonical group while retaining a fallback."""
    if isinstance(gid, str) and gid.startswith("G") and gid[1:].isdigit():
        return (0, int(gid[1:]), gid)
    return (1, gid)


def member_identity(member, group_id, member_index):
    """Return the durable member key, rejecting incomplete state."""
    if not isinstance(member, dict):
        raise SystemExit(
            f"group {group_id} member {member_index} is not an object; refusing to overwrite"
        )
    domain = member.get("domain")
    handle = member.get("handle")
    if not isinstance(domain, str) or not domain or not isinstance(handle, str) or not handle:
        raise SystemExit(
            f"group {group_id} member {member_index} has an incomplete identity; "
            "refusing to overwrite"
        )
    return domain, handle


def canonical_member_payload(member, group_id, member_index):
    """Serialize a member deterministically so every field is compared."""
    try:
        return json.dumps(
            member,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SystemExit(
            f"group {group_id} member {member_index} is not canonical JSON; "
            f"refusing to overwrite: {exc}"
        ) from exc


def active_member_key_set(groups):
    keys = set()
    for group in groups:
        group_id = group.get("group_id")
        members = group.get("members")
        if not isinstance(members, list):
            raise SystemExit(
                f"group {group_id} members is not an array; refusing to overwrite"
            )
        for member_index, member in enumerate(members):
            keys.add(member_identity(member, group_id, member_index))
    return keys


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


def evidence_rank(record):
    """Terminal evidence always outranks an inconclusive attempt."""
    if not isinstance(record, dict):
        return 0
    state = record.get("verification_state")
    if state == "positive":
        return 3
    if state == "sample_negative":
        return 2
    if state == "explicit_zero":
        try:
            status = float(record.get("response_http_status", record.get("http_status")))
            total = float(record.get("fb_total_reported", record.get("total_reported")))
            harvested = float(record.get("harvested"))
            if (math.isfinite(status) and status.is_integer() and 200 <= status <= 299
                    and math.isfinite(total) and math.isfinite(harvested)
                    and total == 0 and harvested == 0):
                return 2
        except (TypeError, ValueError):
            pass
        return 0
    if state:
        return 0
    if (record.get("relevant_ads_count") or 0) > 0:
        return 3
    if (record.get("harvested") or 0) > 0 or record.get("sample"):
        return 2
    return 0


def source_state(record):
    return record.get("verification_state") if isinstance(record, dict) else "missing"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def fail_closed(message):
    raise SystemExit(f"{message}; refusing to overwrite")


def mapping_container(state, key, field, *, entry_objects=False):
    """Create only absent mappings; explicit null/scalar containers are corrupt."""
    if key not in state:
        state[key] = {}
    value = state[key]
    if not isinstance(value, dict):
        fail_closed(f"{field} must be an object")
    if any(not isinstance(gid, str) or not gid.strip() for gid in value):
        fail_closed(f"{field} keys must be non-empty strings")
    if entry_objects and any(not isinstance(record, dict) for record in value.values()):
        fail_closed(f"{field} entries must be objects")
    return value


def alias_entries(value, field):
    """Validate alias metadata without discarding its durable audit fields."""
    if not isinstance(value, dict):
        fail_closed(f"{field} must be an object")
    targets = {}
    for source, entry in value.items():
        if not isinstance(source, str) or not source.strip() or not isinstance(entry, dict):
            fail_closed(f"{field} entries must be keyed objects")
        target = entry.get("canonical_group_id")
        if (
            not isinstance(target, str)
            or not target.strip()
            or target == source
            or entry.get("reason") != "duplicate_merged_into"
        ):
            fail_closed(f"{field} has invalid alias metadata for {source}")
        for metadata_field in ("at", "source_state"):
            if metadata_field in entry and (
                not isinstance(entry[metadata_field], str)
                or not entry[metadata_field].strip()
            ):
                fail_closed(
                    f"{field} {source} has invalid {metadata_field} metadata"
                )
        targets[source] = target
    return value, targets


def resolve_alias(source, aliases, field):
    seen = set()
    current = source
    while current in aliases:
        if current in seen:
            fail_closed(f"{field} contains an alias cycle at {current}")
        seen.add(current)
        current = aliases[current]
    return current


def alias_reaches_target(source, target, aliases, field):
    current = source
    seen = set()
    while current in aliases:
        if current in seen:
            fail_closed(f"{field} contains an alias cycle at {current}")
        seen.add(current)
        current = aliases[current]
        if current == target:
            return True
    return False


def provenance_list(record, field, *, target=None, include_target=None):
    raw = record.get("merged_from", [])
    if not isinstance(raw, list) or any(
        not isinstance(source, str) or not source.strip() for source in raw
    ):
        fail_closed(f"{field} must be a string array")
    if len(raw) != len(set(raw)):
        fail_closed(f"{field} contains duplicate sources")
    # Persisted provenance must use the unchanged dashboard builder's exact
    # canonical form: ordinary Python string ordering, not numeric G-id order.
    canonical = sorted(raw)
    if raw != canonical:
        fail_closed(f"{field} must already be in canonical group-id order")
    if target is not None and include_target is True and target not in raw:
        fail_closed(f"{field} must include canonical target {target}")
    if target is not None and include_target is False and target in raw:
        fail_closed(f"{field} must contain sources only, not target {target}")
    return list(raw)


def validate_audit_declaration(record, source, target, field):
    """Validate every audit field a source/archive already declares."""
    if record is None:
        return
    if not isinstance(record, dict):
        fail_closed(f"{field} for {source} must be an object")
    if "quarantined" in record and record["quarantined"] is not True:
        fail_closed(f"{field} {source} has conflicting quarantined metadata")
    for key, expected in (
        ("quarantine_reason", "duplicate_merged_into"),
        ("merged_into", target),
    ):
        if key in record and record[key] != expected:
            fail_closed(f"{field} {source} has conflicting {key}")
    for key in ("quarantined_at", "quarantine_source_state"):
        if key in record and (
            not isinstance(record[key], str) or not record[key].strip()
        ):
            fail_closed(f"{field} {source} has invalid {key} metadata")


def canonical_evidence_payload(record, source, field):
    """Return immutable evidence separately from mutable merge/quarantine audit."""
    if not isinstance(record, dict):
        fail_closed(f"{field} for {source} must be an object")
    payload = dict(record)
    for key in CHECKPOINT_QUARANTINE_FIELDS:
        payload.pop(key, None)
    payload.pop("merged_from", None)
    if not payload:
        fail_closed(f"{field} for {source} has no auditable evidence")
    stated_gid = payload.get("group_id")
    if stated_gid is not None and stated_gid != source:
        fail_closed(f"{field} for {source} has conflicting group_id {stated_gid}")
    try:
        migrated = migrate_verification_record(payload)
        comparable = dict(migrated)
        comparable.setdefault("group_id", source)
        comparable.setdefault("evidence_group_id", source)
        encoded = json.dumps(
            comparable,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        fail_closed(f"{field} for {source} is invalid checkpoint evidence: {exc}")
    return payload, migrated, encoded


def audit_provenance(record, source, field):
    """Return a declared source-only provenance list without normalizing it."""
    if record is None or "merged_from" not in record:
        return None
    return provenance_list(
        record,
        f"{field} {source} merged_from",
        target=source,
        include_target=False,
    )


def preflight_unique_containers(unique):
    """Validate every unique-state mapping that this script may read or mutate."""
    group_aliases = mapping_container(unique, "group_aliases", "group_aliases")
    quarantined_groups = mapping_container(
        unique,
        "quarantined_groups",
        "quarantined_groups",
        entry_objects=True,
    )
    alias_entries(group_aliases, "group_aliases")
    return group_aliases, quarantined_groups


def preflight_checkpoint_containers(full_verify):
    """Validate all checkpoint containers before planning any in-memory merge."""
    verify_groups = mapping_container(
        full_verify, "groups", "checkpoint groups", entry_objects=True
    )
    checkpoint_aliases = mapping_container(
        full_verify, "checkpoint_aliases", "checkpoint_aliases"
    )
    checkpoint_archive = mapping_container(
        full_verify,
        "checkpoint_archive",
        "checkpoint_archive",
        entry_objects=True,
    )
    retry_errors = mapping_container(
        full_verify, "retry_errors", "retry_errors", entry_objects=True
    )
    retry_archive = mapping_container(
        full_verify, "retry_archive", "retry_archive", entry_objects=True
    )
    retry_aliases = mapping_container(
        full_verify, "retry_aliases", "retry_aliases"
    )
    _, checkpoint_targets = alias_entries(
        checkpoint_aliases, "checkpoint_aliases"
    )
    alias_entries(retry_aliases, "retry_aliases")
    for gid, record in verify_groups.items():
        if "quarantined" in record and not isinstance(record["quarantined"], bool):
            fail_closed(f"checkpoint {gid} quarantined flag must be boolean")
        provenance_list(
            record,
            f"checkpoint {gid} merged_from",
            target=gid,
            include_target=False,
        )
    for source, target in checkpoint_targets.items():
        validate_audit_declaration(
            verify_groups.get(source), source, target, "checkpoint source"
        )
        validate_audit_declaration(
            checkpoint_archive.get(source), source, target, "checkpoint archive"
        )
    return {
        "groups": verify_groups,
        "checkpoint_aliases": checkpoint_aliases,
        "checkpoint_archive": checkpoint_archive,
        "retry_errors": retry_errors,
        "retry_archive": retry_archive,
        "retry_aliases": retry_aliases,
    }


def validate_unique_alias_state(unique):
    """Validate the complete historical group-alias graph before committing."""
    groups = unique.get("groups")
    if not isinstance(groups, list):
        fail_closed("unique groups must be an array")
    by_gid = {}
    member_keys = {}
    for group in groups:
        if not isinstance(group, dict):
            fail_closed("unique groups must contain objects")
        gid = group.get("group_id")
        if not isinstance(gid, str) or not gid.strip() or gid in by_gid:
            fail_closed(f"unique groups contain an invalid or duplicate group_id {gid}")
        by_gid[gid] = group
        if "quarantined" in group and not isinstance(group["quarantined"], bool):
            fail_closed(f"group {gid} quarantined flag must be boolean")
        members = group.get("members")
        if not isinstance(members, list):
            fail_closed(f"group {gid} members must be an array")
        member_keys[gid] = {
            member_identity(member, gid, index)
            for index, member in enumerate(members)
        }

    entries, aliases = alias_entries(unique["group_aliases"], "group_aliases")
    quarantine_entries = unique["quarantined_groups"]
    quarantined = {
        gid for gid, group in by_gid.items() if group.get("quarantined") is True
    }
    if quarantined != set(aliases) or set(quarantine_entries) != set(aliases):
        fail_closed(
            "quarantined groups, quarantined_groups, and group_aliases must match exactly"
        )
    for source, target in aliases.items():
        source_group = by_gid.get(source)
        target_group = by_gid.get(target)
        if source_group is None or target_group is None:
            fail_closed(f"group alias {source}->{target} references a missing group")
        if (
            source_group.get("quarantined") is not True
            or source_group.get("quarantine_reason") != "duplicate_merged_into"
            or source_group.get("merged_into") != target
        ):
            fail_closed(f"group alias {source}->{target} conflicts with quarantine state")
        if not member_keys[source].issubset(member_keys[target]):
            fail_closed(f"group alias {source}->{target} loses product members")
        entry = entries[source]
        quarantine_entry = quarantine_entries[source]
        if (
            quarantine_entry.get("reason") != "duplicate_merged_into"
            or quarantine_entry.get("merged_into") != target
        ):
            fail_closed(
                f"quarantined_groups {source}->{target} conflicts with group alias"
            )
        for metadata_field, group_field in (
            ("at", "quarantined_at"),
            ("source_state", "quarantine_source_state"),
        ):
            values = []
            for label, mapping, key in (
                ("group alias", entry, metadata_field),
                ("quarantined group", source_group, group_field),
                ("quarantined_groups", quarantine_entry, metadata_field),
            ):
                if key in mapping:
                    value = mapping[key]
                    if not isinstance(value, str) or not value.strip():
                        fail_closed(
                            f"{label} {source} has invalid {metadata_field} metadata"
                        )
                    values.append((label, value))
            if any(value != values[0][1] for _, value in values[1:]):
                fail_closed(
                    f"group alias {source}->{target} has conflicting "
                    f"{metadata_field} metadata"
                )
        terminal = resolve_alias(source, aliases, "group_aliases")
        terminal_group = by_gid.get(terminal)
        if terminal_group is None or terminal_group.get("quarantined") is True:
            fail_closed(f"group alias {source} does not converge to an active group")

    alias_targets = set(aliases.values())
    for target in sorted(alias_targets):
        target_group = by_gid.get(target)
        if target_group is None:
            fail_closed(f"group alias target {target} is missing")
        expected = sorted(
            {
                target,
                *(
                    source
                    for source in aliases
                    if alias_reaches_target(
                        source, target, aliases, "group_aliases"
                    )
                ),
            },
        )
        actual = provenance_list(
            target_group,
            f"group {target} merged_from",
            target=target,
            include_target=True,
        )
        if actual != expected:
            fail_closed(
                f"group {target} merged_from provenance does not exactly match aliases"
            )
    for gid, group in by_gid.items():
        if gid not in alias_targets and "merged_from" in group:
            actual = provenance_list(
                group,
                f"group {gid} merged_from",
                target=gid,
                include_target=True,
            )
            if actual != [gid]:
                fail_closed(
                    f"group {gid} merged_from provenance has no matching aliases"
                )
    return entries, aliases, by_gid


def _metadata_value(
    checkpoint_entry,
    unique_entry,
    unique_group,
    quarantine_entry,
    source_record,
    archived_record,
    key,
    record_key,
):
    values = []
    for label, mapping, field in (
        ("checkpoint alias", checkpoint_entry, key),
        ("group alias", unique_entry, key),
        ("quarantined group", unique_group, record_key),
        ("quarantined_groups", quarantine_entry, key),
        ("checkpoint source", source_record, record_key),
        ("checkpoint archive", archived_record, record_key),
    ):
        if mapping is not None and field in mapping:
            values.append((label, mapping[field]))
    for label, value in values:
        if not isinstance(value, str) or not value.strip():
            fail_closed(f"historical alias {label} has invalid {key} metadata")
    if any(value != values[0][1] for _, value in values[1:]):
        labels = ", ".join(label for label, _ in values)
        fail_closed(f"historical alias metadata conflict for {key} across {labels}")
    return values[0][1] if values else None


def reconcile_checkpoint_provenance(unique, full_verify, verify_groups):
    """Close every live/archive provenance claim over provable direct aliases."""
    unique_entries, unique_aliases, unique_groups = validate_unique_alias_state(unique)
    raw_aliases = full_verify["checkpoint_aliases"]
    checkpoint_entries, checkpoint_aliases = alias_entries(
        raw_aliases, "checkpoint_aliases"
    )
    checkpoint_archive = full_verify["checkpoint_archive"]
    quarantine_entries = unique["quarantined_groups"]

    def ensure_source(source, target):
        """Materialize one proven direct alias and return its child claims."""
        if source not in unique_aliases:
            fail_closed(
                f"checkpoint provenance source {source} has no unique group alias"
            )
        if unique_aliases[source] != target:
            fail_closed(
                f"checkpoint provenance source {source} points to {unique_aliases[source]}, "
                f"not {target}"
            )
        source_terminal = resolve_alias(source, unique_aliases, "group_aliases")
        target_terminal = resolve_alias(target, unique_aliases, "group_aliases")
        if source_terminal != target_terminal:
            fail_closed(
                f"checkpoint provenance source {source} does not converge with {target}"
            )
        target_record = verify_groups.get(target)
        if not isinstance(target_record, dict):
            fail_closed(f"checkpoint alias {source}->{target} has no target record")

        checkpoint_entry = checkpoint_entries.get(source)
        if checkpoint_entry is None:
            unique_entry = unique_entries[source]
            checkpoint_entry = {
                "canonical_group_id": target,
                "reason": "duplicate_merged_into",
            }
            for key in ("at", "source_state"):
                if key in unique_entry:
                    checkpoint_entry[key] = unique_entry[key]
            checkpoint_entries[source] = checkpoint_entry
            checkpoint_aliases[source] = target
        elif checkpoint_aliases[source] != target:
            fail_closed(
                f"existing checkpoint alias {source}->{checkpoint_aliases[source]} "
                f"conflicts with {target}"
            )

        unique_entry = unique_entries[source]
        for key in ("at", "source_state"):
            if key in checkpoint_entry and key in unique_entry and (
                checkpoint_entry[key] != unique_entry[key]
            ):
                fail_closed(f"checkpoint alias {source} conflicts with group alias {key}")

        source_record = verify_groups.get(source)
        archived_record = checkpoint_archive.get(source)
        validate_audit_declaration(
            source_record, source, target, "checkpoint source"
        )
        validate_audit_declaration(
            archived_record, source, target, "checkpoint archive"
        )
        source_provenance = audit_provenance(
            source_record, source, "checkpoint source"
        )
        archive_provenance = audit_provenance(
            archived_record, source, "checkpoint archive"
        )
        if (
            source_provenance is not None
            and archive_provenance is not None
            and source_provenance != archive_provenance
        ):
            fail_closed(
                f"checkpoint source/archive merged_from conflict for {source}"
            )
        declared_provenance = (
            source_provenance
            if source_provenance is not None
            else archive_provenance
        )
        if source_record is None and archived_record is None:
            fail_closed(
                f"checkpoint provenance source {source} has no source/archive evidence"
            )
        source_payload = source_migrated = source_encoded = None
        if source_record is not None:
            source_payload, source_migrated, source_encoded = canonical_evidence_payload(
                source_record, source, "checkpoint source"
            )
        archive_payload = archive_migrated = archive_encoded = None
        if archived_record is not None:
            archive_payload, archive_migrated, archive_encoded = canonical_evidence_payload(
                archived_record, source, "checkpoint archive"
            )
        if source_encoded is not None and archive_encoded is not None:
            if source_encoded != archive_encoded:
                fail_closed(
                    f"checkpoint source/archive payload conflict for {source}"
                )
        elif source_record is None:
            source_record = dict(archive_migrated)
            if declared_provenance is not None:
                source_record["merged_from"] = list(declared_provenance)
            verify_groups[source] = source_record
            source_payload, source_migrated, source_encoded = canonical_evidence_payload(
                source_record, source, "reconstructed checkpoint source"
            )
        else:
            checkpoint_archive[source] = dict(source_payload)
            archived_record = checkpoint_archive[source]

        validate_audit_declaration(
            source_record, source, target, "checkpoint source"
        )
        if "quarantined" not in source_record:
            source_record["quarantined"] = True
        expected_fields = {
            "quarantine_reason": "duplicate_merged_into",
            "merged_into": target,
        }
        for field, expected in expected_fields.items():
            if field in source_record and source_record[field] != expected:
                fail_closed(f"checkpoint source {source} has conflicting {field}")
            if field not in source_record:
                source_record[field] = expected

        for key, record_key in (
            ("at", "quarantined_at"),
            ("source_state", "quarantine_source_state"),
        ):
            metadata = _metadata_value(
                checkpoint_entry,
                unique_entry,
                unique_groups[source],
                quarantine_entries[source],
                source_record,
                archived_record,
                key,
                record_key,
            )
            if metadata is None and key == "source_state":
                metadata = source_migrated.get("verification_state")
            if metadata is not None:
                if key not in checkpoint_entry:
                    checkpoint_entry[key] = metadata
                if record_key not in source_record:
                    source_record[record_key] = metadata

        # A hybrid live record may omit mutable provenance while its immutable
        # archive carries the historical claim. Missing fields can be filled;
        # explicit live/archive disagreement was rejected above.
        if "merged_from" not in source_record and declared_provenance is not None:
            source_record["merged_from"] = list(declared_provenance)

        if source not in checkpoint_archive:
            checkpoint_archive[source] = dict(source_payload)
        validate_audit_declaration(
            source_record, source, target, "checkpoint source"
        )
        validate_audit_declaration(
            checkpoint_archive[source], source, target, "checkpoint archive"
        )
        return list(declared_provenance or [])

    # Seed the closure from durable checkpoint aliases and every live claim.
    # Archive claims become roots only after their record is proven to be an
    # alias source. This deliberately ignores an active target's old archive
    # when the current run adds new direct aliases to that target.
    pending = set(checkpoint_aliases.items())
    for target in sorted(verify_groups):
        record = verify_groups[target]
        if not isinstance(record, dict):
            fail_closed(f"checkpoint {target} must be an object")
        for source in provenance_list(
            record,
            f"checkpoint {target} merged_from",
            target=target,
            include_target=False,
        ):
            pending.add((source, target))

    processed = set()
    while pending:
        ready = sorted(
            pair
            for pair in pending
            if isinstance(verify_groups.get(pair[1]), dict)
        )
        # Existing aliases may be listed child-first even though an ancestor
        # archive must reconstruct their target. Process any ready ancestor
        # first; if none is ready, ensure_source emits the precise missing-
        # target failure instead of making traversal order affect the result.
        source, target = ready[0] if ready else min(pending)
        pending.remove((source, target))
        if (source, target) in processed:
            continue
        child_claims = ensure_source(source, target)
        processed.add((source, target))
        for child in child_claims:
            pending.add((child, source))

    # Revalidate the complete checkpoint alias graph and derive its exact
    # direct-child mapping in lexical order, matching the unchanged builder.
    _, checkpoint_aliases = alias_entries(
        full_verify["checkpoint_aliases"], "checkpoint_aliases"
    )
    aliases_by_target = {}
    for source in sorted(checkpoint_aliases):
        target = checkpoint_aliases[source]
        if unique_aliases.get(source) != target:
            fail_closed(
                f"checkpoint alias {source}->{target} disagrees with group alias"
            )
        checkpoint_terminal = resolve_alias(
            source, checkpoint_aliases, "checkpoint_aliases"
        )
        group_terminal = resolve_alias(source, unique_aliases, "group_aliases")
        if checkpoint_terminal != group_terminal or checkpoint_terminal not in verify_groups:
            fail_closed(
                f"checkpoint alias {source} does not converge with its group alias"
            )
        source_record = verify_groups.get(source)
        archived_record = checkpoint_archive.get(source)
        validate_audit_declaration(
            source_record, source, target, "checkpoint source"
        )
        validate_audit_declaration(
            archived_record, source, target, "checkpoint archive"
        )
        if (
            not isinstance(source_record, dict)
            or source_record.get("quarantined") is not True
            or source_record.get("quarantine_reason") != "duplicate_merged_into"
            or source_record.get("merged_into") != target
            or source not in checkpoint_archive
        ):
            fail_closed(f"checkpoint alias {source}->{target} lacks complete audit state")
        aliases_by_target.setdefault(target, []).append(source)

    quarantined_checkpoints = {
        gid for gid, record in verify_groups.items()
        if isinstance(record, dict) and record.get("quarantined") is True
    }
    if quarantined_checkpoints != set(checkpoint_aliases):
        fail_closed("quarantined checkpoints and checkpoint_aliases must match exactly")

    # An archive claim belonging to an alias source is an auditable assertion,
    # not a hint. If present, it must exactly equal the final direct children.
    # Missing archive provenance remains valid. Active-target archives are not
    # checked unless that target is itself an alias source in a longer chain.
    for source in sorted(checkpoint_aliases):
        archive_claim = audit_provenance(
            checkpoint_archive[source], source, "checkpoint archive"
        )
        expected_children = sorted(aliases_by_target.get(source, []))
        if archive_claim is not None and archive_claim != expected_children:
            fail_closed(
                f"checkpoint archive {source} merged_from does not exactly match "
                "direct child aliases"
            )

    # A missing live field can be completed from the proven closure. Explicit
    # live provenance is immutable audit and must already match exactly.
    for gid in sorted(verify_groups):
        record = verify_groups[gid]
        expected = sorted(aliases_by_target.get(gid, []))
        if "merged_from" not in record:
            if expected:
                record["merged_from"] = expected
            continue
        current = provenance_list(
            record,
            f"checkpoint {gid} merged_from",
            target=gid,
            include_target=False,
        )
        if current != expected:
            fail_closed(
                f"checkpoint {gid} merged_from provenance does not exactly match aliases"
            )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unique-json", required=True)
    ap.add_argument("--full-verify-json", required=True)
    args = ap.parse_args()

    unique = load_json(args.unique_json, None)
    if unique is None:
        raise SystemExit(f"缺少 {args.unique_json}")
    if not isinstance(unique.get("groups"), list):
        raise SystemExit(f"unique state has invalid schema; refusing to overwrite {args.unique_json}")
    preflight_unique_containers(unique)

    # Every mapping the merge may read or mutate is validated together before
    # any merge planning. Missing mappings can be materialized; explicit null,
    # arrays, and scalars are persistent-state corruption and fail closed.
    full_verify = load_json(args.full_verify_json, {})
    preflight_checkpoint_containers(full_verify)
    try:
        full_verify = migrate_checkpoint(full_verify)
    except ValueError as exc:
        raise SystemExit(
            f"checkpoint state has invalid verification schema; refusing to overwrite "
            f"{args.full_verify_json}: {exc}"
        ) from exc
    preflight_checkpoint_containers(full_verify)

    groups = unique["groups"]
    # Reject and reconcile historical state before planning a new duplicate
    # merge, so a later evidence selection cannot erase a prior provenance
    # claim. Final validation below covers aliases introduced by this run.
    validate_unique_alias_state(unique)
    verify_groups = full_verify["groups"]
    reconcile_checkpoint_provenance(unique, full_verify, verify_groups)

    active_groups = [g for g in groups if g.get("quarantined") is not True]
    orig_count = len(active_groups)
    orig_member_keys = active_member_key_set(active_groups)
    orig_member_occurrences = sum(len(g["members"]) for g in active_groups)
    print(
        f"[merge] 合并前：{orig_count} 组，成员记录 {orig_member_occurrences}，"
        f"唯一成员 {len(orig_member_keys)}"
    )

    buckets = {}
    by_gid = {g["group_id"]: g for g in active_groups}
    for g in active_groups:
        nk = norm_query(g.get("query"))
        buckets.setdefault(nk, []).append(g["group_id"])

    dup_buckets = {nk: gids for nk, gids in buckets.items() if len(gids) > 1 and nk}
    print(f"[merge] 发现 {len(dup_buckets)} 个查询词对应多组，涉及 {sum(len(v) for v in dup_buckets.values())} 组")
    for nk, gids in dup_buckets.items():
        print(f"  - \"{nk}\" -> {gids}")

    # Validate every bucket before mutating any in-memory state.  Duplicate
    # identities may be deduplicated only when their complete JSON payloads
    # (including provenance fields) are identical.  This keeps a conflict on
    # a later bucket from reaching the transaction writer at all.
    merge_plans = {}
    for nk in sorted(dup_buckets):
        gids_sorted = sorted(dup_buckets[nk], key=gid_selection_key)
        payload_by_key = {}
        origin_by_key = {}
        merged_members = []
        merged_provenance = list(gids_sorted)
        for gid in gids_sorted:
            group = by_gid[gid]
            prior_provenance = (
                provenance_list(
                    group,
                    f"group {gid} merged_from",
                    target=gid,
                    include_target=True,
                )
                if "merged_from" in group
                else []
            )
            merged_provenance.extend(prior_provenance)
            members = group.get("members")
            if not isinstance(members, list):
                raise SystemExit(f"group {gid} members is not an array; refusing to overwrite")
            for member_index, member in enumerate(members):
                key = member_identity(member, gid, member_index)
                payload = canonical_member_payload(member, gid, member_index)
                if key in payload_by_key:
                    if payload != payload_by_key[key]:
                        prior_gid, prior_index = origin_by_key[key]
                        raise SystemExit(
                            "conflicting duplicate member payload for "
                            f"{key[0]}/{key[1]} between group {prior_gid} member "
                            f"{prior_index} and group {gid} member {member_index}; "
                            "refusing to overwrite"
                        )
                    continue
                payload_by_key[key] = payload
                origin_by_key[key] = (gid, member_index)
                merged_members.append(member)
        merge_plans[nk] = {
            "gids": gids_sorted,
            "members": merged_members,
            "merged_from": sorted(set(merged_provenance)),
        }

    dropped_gids = set()
    merged_info = {}
    merged_at = utc_now()

    for nk in sorted(merge_plans):
        plan = merge_plans[nk]
        gids_sorted = plan["gids"]
        kept_gid = gids_sorted[0]
        drop_gids = gids_sorted[1:]
        kept_group = by_gid[kept_gid]
        kept_group["members"] = plan["members"]
        for dg in drop_gids:
            dropped_gids.add(dg)
            other = by_gid[dg]
            # Keep the historical group in place for audit/retry safety.  The
            # runner and dashboard ignore quarantined groups, but no durable
            # group is silently cropped during a same-month incremental run.
            other["quarantined"] = True
            other["quarantine_reason"] = "duplicate_merged_into"
            other["merged_into"] = kept_gid
            other["quarantined_at"] = merged_at
            other["quarantine_source_state"] = source_state(verify_groups.get(dg))
            # 合并进来的新组如果本身已标记 already_verified（理论上不会，daily_new 组
            # 恒为 False），保留 kept_group 原值，不覆盖。

        kept_group["merged_from"] = plan["merged_from"]
        merged_info[kept_gid] = gids_sorted
        print(f"[merge] 合并 \"{nk}\": 保留 {kept_gid}，丢弃 {drop_gids}")

    ordered_dropped_gids = sorted(dropped_gids)
    new_groups = groups
    new_active_groups = [g for g in new_groups if not g.get("quarantined")]
    new_count = len(new_active_groups)
    new_member_occurrences = sum(len(g["members"]) for g in new_active_groups)
    new_member_keys = active_member_key_set(new_active_groups)
    print(
        f"[merge] 合并后：{new_count} 组，成员记录 {new_member_occurrences}，"
        f"唯一成员 {len(new_member_keys)}"
    )

    if new_member_keys != orig_member_keys:
        raise SystemExit(
            "active member-key set changed during merge; refusing to overwrite "
            f"(missing={len(orig_member_keys - new_member_keys)}, "
            f"added={len(new_member_keys - orig_member_keys)})"
        )

    unique["groups"] = new_groups
    unique["total_groups"] = new_count
    for gid in ordered_dropped_gids:
        unique["quarantined_groups"][gid] = {
            "reason": by_gid[gid].get("quarantine_reason"),
            "merged_into": by_gid[gid].get("merged_into"),
            "at": by_gid[gid].get("quarantined_at"),
            "source_state": by_gid[gid].get("quarantine_source_state"),
        }
    for gid in ordered_dropped_gids:
        unique["group_aliases"][gid] = {
            "canonical_group_id": by_gid[gid].get("merged_into"),
            "reason": "duplicate_merged_into",
            "at": by_gid[gid].get("quarantined_at"),
            "source_state": by_gid[gid].get("quarantine_source_state"),
        }
    def relevant_count(gid):
        v = verify_groups.get(gid)
        if v is None:
            return -1
        rc = v.get("relevant_ads_count")
        return rc if isinstance(rc, int) else -1

    for kept_gid, gids_sorted in merged_info.items():
        present = [g for g in gids_sorted if g in verify_groups]
        if not present:
            continue
        # A terminal sample/zero/positive result is usable evidence; an
        # inconclusive attempt is never allowed to displace it merely because
        # a malformed record reported a larger relevance counter.
        best_gid = min(
            present,
            key=lambda g: (
                -evidence_rank(verify_groups[g]),
                -relevant_count(g),
                gid_selection_key(g),
            ),
        )
        checkpoint_archive = full_verify["checkpoint_archive"]
        for gid in present:
            checkpoint_archive.setdefault(gid, dict(verify_groups[gid]))
        best_result = dict(verify_groups[best_gid])
        for field in CHECKPOINT_QUARANTINE_FIELDS:
            best_result.pop(field, None)
        best_result["group_id"] = kept_gid
        best_result["evidence_group_id"] = best_gid
        _, current_group_aliases = alias_entries(
            unique["group_aliases"], "group_aliases"
        )
        best_result["merged_from"] = sorted(
            (
                source
                for source, target in current_group_aliases.items()
                if target == kept_gid
            ),
        )
        verify_groups[kept_gid] = best_result
        print(f"[merge] 验证结果合并 -> {kept_gid}: 从 {present} 中选中 {best_gid}")

    retry_errors = full_verify["retry_errors"]
    retry_archive = full_verify["retry_archive"]
    retry_aliases = full_verify["retry_aliases"]
    for kept_gid, gids_sorted in merged_info.items():
        if kept_gid not in retry_errors:
            for gid in gids_sorted:
                if gid in retry_errors:
                    retry_archive.setdefault(gid, dict(retry_errors[gid]))
                    retry_errors[kept_gid] = dict(
                        retry_errors[gid], group_id=kept_gid, evidence_group_id=gid, merged_from=gid
                    )
                    break
        for gid in gids_sorted:
            if gid != kept_gid and gid in retry_errors:
                retry_archive.setdefault(gid, dict(retry_errors[gid]))
                retry_errors[gid]["quarantined"] = True
                retry_errors[gid]["quarantine_reason"] = "duplicate_merged_into"
                retry_errors[gid]["merged_into"] = kept_gid
                retry_errors[gid]["quarantined_at"] = merged_at
                retry_errors[gid]["quarantine_source_state"] = source_state(verify_groups.get(gid))
                retry_aliases[gid] = {
                    "canonical_group_id": kept_gid,
                    "reason": "duplicate_merged_into",
                    "at": merged_at,
                    "source_state": source_state(verify_groups.get(gid)),
                }

    reconcile_checkpoint_provenance(unique, full_verify, verify_groups)
    full_verify["groups"] = verify_groups
    try:
        validate_dashboard_alias_contract(unique, full_verify)
    except ValueError as exc:
        fail_closed(f"dashboard alias contract invalid: {exc}")
    recoverable_json_transaction(
        [(args.unique_json, unique), (args.full_verify_json, full_verify)]
    )
    print(f"[merge] 已写回 {args.unique_json}")
    print(f"[merge] 已写回 {args.full_verify_json}")

    print(f"MERGE_SUMMARY_JSON " + json.dumps({
        "buckets_merged": len(dup_buckets),
        "groups_dropped": len(dropped_gids),
        "total_groups_after": new_count,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
