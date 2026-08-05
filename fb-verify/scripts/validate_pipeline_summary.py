#!/usr/bin/env python3
"""Strictly extract and validate one pipeline summary marker from stdin."""

import argparse
import json
import sys


MARKERS = {
    "ingest": "SUMMARY_JSON",
    "merge": "MERGE_SUMMARY_JSON",
    "verify": "VERIFY_SUMMARY_JSON",
    "images": "IMAGES_SUMMARY_JSON",
    "build": "BUILD_SUMMARY_JSON",
    "stats": "STATS_JSON",
}


def reject_constant(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def nonnegative_int(payload, key):
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


def boolean(payload, key):
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def id_list(payload, key):
    value = payload.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be an array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{key} must contain non-empty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{key} must contain unique ids")
    return value


def require_keys(payload, keys):
    missing = sorted(set(keys) - set(payload))
    if missing:
        raise ValueError("missing required keys: " + ", ".join(missing))


def validate_verify(payload):
    require_keys(payload, {
        "todo", "verified", "verified_group_ids", "failed",
        "failed_group_ids", "pending", "truncated", "terminated_early",
    })
    todo = nonnegative_int(payload, "todo")
    verified = nonnegative_int(payload, "verified")
    failed = nonnegative_int(payload, "failed")
    pending = nonnegative_int(payload, "pending")
    truncated = nonnegative_int(payload, "truncated")
    terminated = boolean(payload, "terminated_early")
    verified_ids = id_list(payload, "verified_group_ids")
    failed_ids = id_list(payload, "failed_group_ids")
    if len(verified_ids) != verified or len(failed_ids) != failed:
        raise ValueError("group id list lengths must equal their counters")
    if set(verified_ids) & set(failed_ids):
        raise ValueError("verified and failed group ids must be disjoint")
    if verified + pending != todo:
        raise ValueError("verify conservation failed: verified + pending must equal todo")
    if failed > pending or truncated > pending:
        raise ValueError("failed/truncated cannot exceed pending")
    if not terminated and verified + failed + truncated != todo:
        raise ValueError(
            "verify conservation failed without early termination: "
            "verified + failed + truncated must equal todo"
        )


def validate_ingest(payload):
    keys = {
        "rows_matching_scope", "groups_added", "total_groups_after",
        "skipped_already_known", "skipped_previous_member",
        "skipped_dup_in_batch", "migrated_unresolved_groups",
        "migrated_retry_states", "migrated_inconclusive_records",
        "reused_previous_query",
    }
    require_keys(payload, keys)
    values = {key: nonnegative_int(payload, key) for key in keys}
    if values["groups_added"] > values["rows_matching_scope"]:
        raise ValueError("groups_added cannot exceed rows_matching_scope")
    if values["groups_added"] > values["total_groups_after"]:
        raise ValueError("groups_added cannot exceed total_groups_after")


def validate_merge(payload):
    keys = {"buckets_merged", "groups_dropped", "total_groups_after"}
    require_keys(payload, keys)
    for key in keys:
        nonnegative_int(payload, key)


def validate_images(payload):
    keys = {
        "total", "cached_skipped", "new_shopify_ok", "new_og_ok",
        "previous_cache_ok", "cross_site_ok", "ad_preview_ok",
        "video_frame_ok", "new_failed",
    }
    require_keys(payload, keys)
    values = {key: nonnegative_int(payload, key) for key in keys}
    classified = sum(value for key, value in values.items() if key != "total")
    if classified != values["total"]:
        raise ValueError("image summary counters must sum to total")


def parse_expected_group_ids(raw):
    if not isinstance(raw, str):
        raise ValueError("--expected-group-ids is required for batch builds")
    values = [value.strip() for value in raw.split(",")]
    if any(not value for value in values):
        raise ValueError("--expected-group-ids must not contain empty ids")
    if len(values) != len(set(values)):
        raise ValueError("--expected-group-ids must not contain duplicate ids")
    return values


def validate_build(payload, *, build_view_kind, expected_group_ids):
    keys = {"total_groups", "found", "unverified"}
    require_keys(payload, keys)
    values = {key: nonnegative_int(payload, key) for key in keys}
    if values["found"] > values["total_groups"]:
        raise ValueError("found cannot exceed total_groups")
    if values["unverified"] > values["total_groups"]:
        raise ValueError("unverified cannot exceed total_groups")
    batch_keys = {"requested", "resolved", "missing"}
    present_batch_keys = batch_keys & set(payload)
    if build_view_kind == "monthly":
        if expected_group_ids is not None:
            raise ValueError("monthly build validation forbids --expected-group-ids")
        if present_batch_keys:
            raise ValueError("monthly build summary must not contain batch resolution fields")
        return
    if build_view_kind != "batch":
        raise ValueError("--build-view-kind is required for build summaries")
    if expected_group_ids is None:
        raise ValueError("--expected-group-ids is required for batch builds")
    require_keys(payload, batch_keys)
    requested = id_list(payload, "requested")
    resolved = id_list(payload, "resolved")
    missing = id_list(payload, "missing")
    if requested != expected_group_ids or resolved != expected_group_ids or missing:
        raise ValueError(
            "batch requested and resolved must exactly equal --expected-group-ids "
            "and missing must be empty"
        )
    if values["total_groups"] != len(expected_group_ids):
        raise ValueError("batch total_groups must equal expected group id count")


def validate_stats(payload):
    keys = {"matched", "fresh", "multi_site", "matched_group_ids", "matched_products"}
    require_keys(payload, keys)
    matched = nonnegative_int(payload, "matched")
    fresh = nonnegative_int(payload, "fresh")
    multi_site = nonnegative_int(payload, "multi_site")
    ids = id_list(payload, "matched_group_ids")
    products = payload["matched_products"]
    if not isinstance(products, list) or any(not isinstance(item, dict) for item in products):
        raise ValueError("matched_products must be an array of objects")
    if len(ids) != matched or len(products) != matched:
        raise ValueError("matched ids/products lengths must equal matched")
    if fresh > matched or multi_site > matched:
        raise ValueError("fresh/multi_site cannot exceed matched")


VALIDATORS = {
    "ingest": validate_ingest,
    "merge": validate_merge,
    "verify": validate_verify,
    "images": validate_images,
    "build": validate_build,
    "stats": validate_stats,
}


def extract_and_validate(
    kind, text, *, build_view_kind=None, expected_group_ids=None
):
    if kind != "build" and (build_view_kind is not None or expected_group_ids is not None):
        raise ValueError("build validation options are valid only with --kind build")
    if kind == "build" and build_view_kind is None:
        raise ValueError("--build-view-kind is required for build summaries")
    marker = MARKERS[kind]
    prefix = marker + " "
    matches = [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {marker} marker, found {len(matches)}")
    payload = json.loads(
        matches[0], object_pairs_hook=unique_object, parse_constant=reject_constant
    )
    if not isinstance(payload, dict):
        raise ValueError(f"{marker} payload must be an object")
    if kind == "build":
        VALIDATORS[kind](
            payload,
            build_view_kind=build_view_kind,
            expected_group_ids=expected_group_ids,
        )
    else:
        VALIDATORS[kind](payload)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=sorted(MARKERS), required=True)
    parser.add_argument("--build-view-kind", choices=("monthly", "batch"))
    parser.add_argument("--expected-group-ids")
    args = parser.parse_args(argv)
    try:
        expected_group_ids = None
        if args.expected_group_ids is not None:
            expected_group_ids = parse_expected_group_ids(args.expected_group_ids)
        payload = extract_and_validate(
            args.kind,
            sys.stdin.read(),
            build_view_kind=args.build_view_kind,
            expected_group_ids=expected_group_ids,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"invalid {MARKERS[args.kind]}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
