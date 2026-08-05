#!/usr/bin/env python3
"""Versioned verification-record validation and strict schema1 migration."""

import math
import re


SCHEMA_VERSION = 2
PRODUCER = "fb-verify-runner"
TERMINAL_STATES = {"positive", "sample_negative", "explicit_zero"}
ALL_STATES = TERMINAL_STATES | {"inconclusive"}
PLAIN_INTEGER = re.compile(r"^[0-9]+$")
GROUPED_INTEGER = re.compile(r"^[0-9]{1,3}(?:,[0-9]{3})+$")


def _number(value, field, *, nullable=True):
    if value is None and nullable:
        return None
    if isinstance(value, bool):
        raise ValueError(f"invalid {field}")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field}") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"invalid {field}")
    return number


def _legacy_integer(value, field, *, nullable=True):
    """Normalize only strict legacy integer spellings into canonical numbers."""
    if value is None and nullable:
        return None
    if isinstance(value, bool):
        raise ValueError(f"invalid {field}")
    if isinstance(value, str):
        stripped = value.strip()
        if PLAIN_INTEGER.fullmatch(stripped):
            return int(stripped)
        if GROUPED_INTEGER.fullmatch(stripped):
            return int(stripped.replace(",", ""))
        raise ValueError(f"invalid {field}")
    if isinstance(value, (int, float)) and math.isfinite(value) and value >= 0:
        if float(value).is_integer():
            return int(value)
    raise ValueError(f"invalid {field}")


def _canonical_integer(value, field, *, nullable=True):
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"invalid {field}")
    if not math.isfinite(value) or value < 0 or not float(value).is_integer():
        raise ValueError(f"invalid {field}")
    return int(value)


def _alias(record, canonical, legacy):
    has_canonical = canonical in record
    has_legacy = legacy in record
    if has_canonical and has_legacy:
        canonical_value = record[canonical]
        legacy_value = record[legacy]
        if canonical_value is None or legacy_value is None:
            equivalent = canonical_value is None and legacy_value is None
        else:
            try:
                equivalent = _legacy_integer(canonical_value, canonical, nullable=False) == _legacy_integer(
                    legacy_value, legacy, nullable=False
                )
            except ValueError:
                equivalent = str(canonical_value) == str(legacy_value)
        if not equivalent:
            raise ValueError(f"conflicting {canonical}/{legacy} fields")
    if has_canonical:
        return record[canonical]
    return record.get(legacy) if has_legacy else None


def classify(record):
    relevant = _number(record.get("relevant_ads_count", 0), "relevant_ads_count") or 0
    harvested = _number(record.get("harvested", 0), "harvested") or 0
    sample = record.get("sample", [])
    relevant_ads = record.get("relevant_ads", [])
    if not isinstance(sample, list) or not isinstance(relevant_ads, list):
        raise ValueError("sample and relevant_ads must be lists")
    if max(harvested, len(sample), len(relevant_ads)) > 0:
        return "positive" if relevant > 0 else "sample_negative"
    # A relevance counter without any sampled response evidence is not proof of
    # a match and also contradicts an explicit-zero interpretation.
    if relevant > 0:
        return "inconclusive"
    status = _number(record.get("response_http_status"), "response_http_status")
    total = _number(record.get("fb_total_reported"), "fb_total_reported")
    if status is not None and status.is_integer() and 200 <= status <= 299 and total == 0 and harvested == 0:
        return "explicit_zero"
    return "inconclusive"


def _validate_v2(record):
    if "http_status" in record or "total_reported" in record:
        raise ValueError("schema2 record contains legacy aliases")
    status = _canonical_integer(record.get("response_http_status"), "response_http_status")
    if status is not None and not 100 <= status <= 599:
        raise ValueError("invalid response_http_status")
    for field in ("fb_total_reported", "harvested", "relevant_ads_count"):
        _canonical_integer(record.get(field), field)
    state = record.get("verification_state") or classify(record)
    if state not in ALL_STATES:
        raise ValueError(f"unknown verification_state: {state}")
    inferred = classify(record)
    if state != inferred:
        raise ValueError(f"verification_state {state} contradicts evidence ({inferred})")
    return state


def migrate_verification_record(record):
    if not isinstance(record, dict):
        raise ValueError("verification record must be an object")
    version = record.get("schema_version")
    producer = record.get("producer")
    legacy = "schema_version" not in record or (
        not isinstance(version, bool) and version == 1
    )
    if legacy and producer not in (None, PRODUCER):
        raise ValueError(f"unsupported legacy verification producer: {producer}")
    if legacy:
        migrated = dict(record)
        migrated["response_http_status"] = _legacy_integer(
            _alias(record, "response_http_status", "http_status"),
            "response_http_status",
        )
        migrated["fb_total_reported"] = _legacy_integer(
            _alias(record, "fb_total_reported", "total_reported"),
            "fb_total_reported",
        )
        for field in ("harvested", "relevant_ads_count"):
            if field in migrated:
                migrated[field] = _legacy_integer(migrated[field], field)
        migrated.pop("http_status", None)
        migrated.pop("total_reported", None)
        migrated["verification_state"] = record.get("verification_state") or classify(migrated)
        migrated["schema_version"] = SCHEMA_VERSION
        migrated["producer"] = PRODUCER
        migrated["migrated_from_schema"] = 1
    elif record.get("schema_version") == SCHEMA_VERSION and record.get("producer") == PRODUCER:
        migrated = dict(record)
    else:
        raise ValueError(
            f"unsupported verification schema/producer: "
            f"{record.get('schema_version')}/{record.get('producer')}"
        )
    _validate_v2(migrated)
    return migrated


def is_completed(record):
    return migrate_verification_record(record).get("verification_state") in TERMINAL_STATES


def migrate_checkpoint(state):
    if not isinstance(state, dict) or not isinstance(state.get("groups"), dict):
        raise ValueError("checkpoint groups must be an object")
    if "retry_errors" in state and not isinstance(state["retry_errors"], dict):
        raise ValueError("checkpoint retry_errors must be an object")
    version = state.get("schema_version")
    producer = state.get("producer")
    legacy = "schema_version" not in state or (
        not isinstance(version, bool) and version == 1
    )
    if legacy and producer not in (None, PRODUCER):
        raise ValueError(f"unsupported legacy checkpoint producer: {producer}")
    if not legacy and (
        state.get("schema_version") != SCHEMA_VERSION
        or state.get("producer") != PRODUCER
    ):
        raise ValueError(
            f"unsupported checkpoint schema/producer: "
            f"{state.get('schema_version')}/{state.get('producer')}"
        )
    migrated = dict(state)
    migrated["groups"] = {
        gid: migrate_verification_record(record)
        for gid, record in state["groups"].items()
    }
    migrated["schema_version"] = SCHEMA_VERSION
    migrated["producer"] = PRODUCER
    if legacy:
        migrated["migrated_from_schema"] = 1
    return migrated
