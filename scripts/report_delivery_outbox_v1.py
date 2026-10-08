"""Pure, deterministic report-delivery outbox state machine (v1).

This module deliberately has no I/O.  Callers persist ``canonical_bytes`` and
later restore it with ``parse_canonical_bytes``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace
from enum import Enum
from collections.abc import Iterable as IterableABC, Mapping
from typing import Any, Iterable, Optional

SCHEMA = "report-delivery-outbox/v1"


class OutboxError(Exception):
    """Base class for all public outbox failures."""


class ValidationError(OutboxError):
    pass


class ResourceLimitError(OutboxError):
    pass


class CanonicalEncodingError(OutboxError):
    pass


class SchemaVersionError(OutboxError):
    pass


class IntegrityError(OutboxError):
    pass


class InvalidTransitionError(OutboxError):
    pass


class CasOutcome(str, Enum):
    NOT_SENT = "not_sent"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"
    PUBLISHED = "published"


class DeliveryOutcome(str, Enum):
    NOT_SENT = "not_sent"
    UNKNOWN = "unknown"
    SENT = "sent"


class DeliveryChannel(str, Enum):
    PRIMARY = "primary"
    FALLBACK = "fallback"


class DedupeOutcome(str, Enum):
    NOT_APPLIED = "not_applied"
    APPLIED = "applied"


class ResumeAction(str, Enum):
    PREPARE_PUBLICATION = "prepare_publication"
    START_PUBLICATION = "start_publication"
    RECONCILE_PUBLICATION = "reconcile_publication"
    START_PRIMARY_DELIVERY = "start_primary_delivery"
    START_FALLBACK_DELIVERY = "start_fallback_delivery"
    RECONCILE_DELIVERY = "reconcile_delivery"
    APPLY_DEDUPE = "apply_dedupe"
    TERMINAL_CONFLICT = "terminal_conflict"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class Target:
    repository: str
    ref: str
    path: str


@dataclass(frozen=True, slots=True)
class Payload:
    handles: tuple[str, ...]
    payload: bytes


@dataclass(frozen=True, slots=True)
class Intent:
    changed_handles: tuple[str, ...]
    fallback: Optional[Payload]
    image: bytes
    primary: Payload
    target: Target


@dataclass(frozen=True, slots=True)
class Publication:
    outcome: CasOutcome
    remote_base: Optional[str]
    remote_blob: Optional[str]
    remote_commit: Optional[str]


@dataclass(frozen=True, slots=True)
class Delivery:
    channel: Optional[DeliveryChannel]
    delivered_handles: tuple[str, ...]
    outcome: DeliveryOutcome


@dataclass(frozen=True, slots=True)
class Dedupe:
    outcome: DedupeOutcome


@dataclass(frozen=True, slots=True)
class OutboxRecord:
    dedupe: Dedupe
    delivery: Delivery
    intent: Intent
    outbox_id: str
    publication: Publication
    schema: str = SCHEMA


_MAX_IMAGE = 16 * 1024 * 1024
_MAX_PAYLOAD = 1024 * 1024
_MAX_RECORD = 32 * 1024 * 1024
_MAX_HANDLES_BYTES = 2 * 1024 * 1024
_RE_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_RE_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _fail(message: str, cls: type[OutboxError] = ValidationError) -> None:
    raise cls(message)


def _string(value: Any, name: str, cls: type[OutboxError] = ValidationError) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string", cls)
    return value


def _bytes(value: Any, name: str, cls: type[OutboxError] = ValidationError) -> bytes:
    if type(value) is not bytes:
        _fail(f"{name} must be bytes", cls)
    return value


def _has_control(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


def _utf8_size(value: str, name: str, cls: type[OutboxError]) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise cls(f"{name} must be valid Unicode") from error


def _handles(value: Any, name: str, *, allow_empty: bool = False,
             cls: type[OutboxError] = ValidationError) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, bytearray, memoryview, Mapping)) or not isinstance(value, IterableABC):
        _fail(f"{name} must be an iterable of strings", cls)
    result: list[str] = []
    try:
        iterator = iter(value)
        for index in range(10_001):
            try:
                item = next(iterator)
            except StopIteration:
                break
            if index == 10_000:
                _fail(f"{name} exceeds resource limits", ResourceLimitError)
            item = _string(item, name, cls)
            normalized = unicodedata.normalize("NFC", item)
            size = _utf8_size(normalized, name, cls)
            if not normalized or size > 255 or _has_control(normalized):
                _fail(f"invalid handle in {name}", cls)
            result.append(normalized)
    except OutboxError:
        raise
    except MemoryError:
        raise
    except Exception as error:
        raise cls(f"{name} iterator failed") from error
    result.sort()
    if len(set(result)) != len(result):
        _fail(f"{name} must have unique handles", cls)
    if not allow_empty and not result:
        _fail(f"{name} must not be empty", cls)
    return tuple(result)


def _intent_handles_size(intent: Intent, cls: type[OutboxError]) -> int:
    groups = (intent.changed_handles, intent.primary.handles,
              () if intent.fallback is None else intent.fallback.handles)
    total = sum(_utf8_size(handle, "handle", cls) for group in groups for handle in group)
    if total > _MAX_HANDLES_BYTES:
        _fail("intent handles exceed resource limits", ResourceLimitError)
    return total


def _repository(value: Any, cls: type[OutboxError] = ValidationError) -> str:
    value = _string(value, "repository", cls)
    if _utf8_size(value, "repository", cls) > 255 or not _RE_REPOSITORY.fullmatch(value):
        _fail("invalid repository", cls)
    return value


def _ref(value: Any, cls: type[OutboxError] = ValidationError) -> str:
    value = _string(value, "ref", cls)
    tail = value[len("refs/heads/"):] if value.startswith("refs/heads/") else ""
    components = tail.split("/") if tail else ()
    bad = (not tail or _utf8_size(value, "ref", cls) > 255 or ".." in value or "//" in value
           or value.endswith(".") or value.endswith("/") or "@{" in value
           or value == "@" or any(c in value for c in " ~^:?*[\\") or _has_control(value)
           or any(not component or component.startswith(".") or component.endswith(".lock")
                  for component in components))
    if bad:
        _fail("invalid ref", cls)
    return value


def _path(value: Any, cls: type[OutboxError] = ValidationError) -> str:
    value = _string(value, "path", cls)
    normalized = unicodedata.normalize("NFC", value)
    segments = normalized.split("/")
    if (not normalized or normalized.startswith("/") or "\\" in normalized
            or _utf8_size(normalized, "path", cls) > 1024 or _has_control(normalized)
            or any(not s or s in (".", "..") for s in segments)):
        _fail("invalid path", cls)
    return normalized


def _payload(handles: Any, payload: Any, name: str,
             cls: type[OutboxError] = ValidationError) -> Payload:
    normalized = _handles(handles, f"{name}_handles", cls=cls)
    data = _bytes(payload, f"{name}_payload_bytes", cls)
    if not data:
        _fail(f"{name} payload must not be empty", cls)
    if len(data) > _MAX_PAYLOAD:
        _fail(f"{name} payload exceeds resource limit", ResourceLimitError)
    return Payload(normalized, data)


def _envelope(data: bytes) -> dict[str, Any]:
    return {"b64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _intent_object(intent: Intent) -> dict[str, Any]:
    return {
        "changed_handles": list(intent.changed_handles),
        "fallback": None if intent.fallback is None else {
            "handles": list(intent.fallback.handles), "payload": _envelope(intent.fallback.payload)},
        "image": _envelope(intent.image),
        "primary": {"handles": list(intent.primary.handles), "payload": _envelope(intent.primary.payload)},
        "target": {"path": intent.target.path, "ref": intent.target.ref,
                   "repository": intent.target.repository},
    }


def _intent_id(intent: Intent) -> str:
    content = _dump({"intent": _intent_object(intent), "schema": SCHEMA})
    return "rdo1-" + hashlib.sha256(content).hexdigest()


def _dump(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise CanonicalEncodingError("could not encode canonical JSON") from error


def _publication(pub: Publication, cls: type[OutboxError] = ValidationError) -> None:
    if not isinstance(pub.outcome, CasOutcome):
        _fail("invalid publication outcome", cls)
    fields = (pub.remote_base, pub.remote_blob, pub.remote_commit)
    if any(x is None for x in fields) and any(x is not None for x in fields):
        _fail("publication OIDs must be all null or all present", cls)
    if pub.outcome in (CasOutcome.UNKNOWN, CasOutcome.PUBLISHED, CasOutcome.CONFLICT) and any(x is None for x in fields):
        _fail("publication state requires OIDs", cls)
    if all(x is not None for x in fields):
        lengths: set[int] = set()
        for oid in fields:
            oid = _string(oid, "remote OID", cls)
            if not _RE_OID.fullmatch(oid):
                _fail("invalid remote OID", cls)
            lengths.add(len(oid))
        if len(lengths) != 1:
            _fail("remote OIDs must have one hash length", cls)


def _validate_record(record: Any, cls: type[OutboxError] = ValidationError) -> OutboxRecord:
    if not isinstance(record, OutboxRecord):
        _fail("record must be an OutboxRecord", cls)
    if record.schema != SCHEMA:
        _fail("unsupported schema", SchemaVersionError)
    intent = record.intent
    if not isinstance(intent, Intent) or not isinstance(intent.target, Target) or not isinstance(intent.primary, Payload):
        _fail("invalid intent structure", cls)
    _repository(intent.target.repository, cls); _ref(intent.target.ref, cls)
    if _path(intent.target.path, cls) != intent.target.path:
        _fail("path must be NFC canonical", cls)
    changed = _handles(intent.changed_handles, "changed_handles", cls=cls)
    if changed != intent.changed_handles:
        _fail("handles must be canonical", cls)
    image = _bytes(intent.image, "image", cls)
    if len(image) < 1:
        _fail("image must not be empty", cls)
    if len(image) > _MAX_IMAGE:
        _fail("image exceeds resource limit", ResourceLimitError)
    primary = _payload(intent.primary.handles, intent.primary.payload, "primary", cls)
    if primary != intent.primary or not set(primary.handles).issubset(changed):
        _fail("invalid primary payload", cls)
    if intent.fallback is not None:
        if not isinstance(intent.fallback, Payload):
            _fail("invalid fallback payload", cls)
        fallback = _payload(intent.fallback.handles, intent.fallback.payload, "fallback", cls)
        if fallback != intent.fallback or not set(fallback.handles).issubset(changed):
            _fail("invalid fallback payload", cls)
    _intent_handles_size(intent, cls)
    if not isinstance(record.publication, Publication) or not isinstance(record.delivery, Delivery) or not isinstance(record.dedupe, Dedupe):
        _fail("invalid state structure", cls)
    _publication(record.publication, cls)
    delivery = record.delivery
    if not isinstance(delivery.outcome, DeliveryOutcome) or not isinstance(record.dedupe.outcome, DedupeOutcome):
        _fail("invalid delivery or dedupe outcome", cls)
    delivered = _handles(delivery.delivered_handles, "delivered_handles", allow_empty=True, cls=cls)
    if delivered != delivery.delivered_handles:
        _fail("delivered handles must be canonical", cls)
    if delivery.outcome is DeliveryOutcome.NOT_SENT:
        if delivery.channel is not None or delivered:
            _fail("not_sent delivery must be empty", cls)
    elif delivery.outcome is DeliveryOutcome.UNKNOWN:
        if delivery.channel not in (DeliveryChannel.PRIMARY, DeliveryChannel.FALLBACK) or delivered:
            _fail("unknown delivery must have a channel and no handles", cls)
    else:
        expected = intent.primary.handles if delivery.channel is DeliveryChannel.PRIMARY else (
            intent.fallback.handles if delivery.channel is DeliveryChannel.FALLBACK and intent.fallback else None)
        if expected is None or delivered != expected:
            _fail("sent delivery handles do not match channel", cls)
    if record.dedupe.outcome is DedupeOutcome.APPLIED and delivery.outcome is not DeliveryOutcome.SENT:
        _fail("dedupe cannot precede delivery", cls)
    if delivery.channel is DeliveryChannel.PRIMARY and record.publication.outcome is not CasOutcome.PUBLISHED:
        _fail("primary delivery requires publication", cls)
    if delivery.channel is DeliveryChannel.FALLBACK and record.publication.outcome is not CasOutcome.CONFLICT:
        _fail("fallback delivery requires conflict", cls)
    expected_id = _intent_id(intent)
    if record.outbox_id != expected_id:
        _fail("outbox ID does not match intent", IntegrityError)
    return record


def create_record(*, repository: str, ref: str, path: str, image_bytes: bytes,
                  primary_payload_bytes: bytes, changed_handles: Iterable[str],
                  primary_handles: Iterable[str], fallback_payload_bytes: Optional[bytes] = None,
                  fallback_handles: Iterable[str] = ()) -> OutboxRecord:
    target = Target(_repository(repository), _ref(ref), _path(path))
    changed = _handles(changed_handles, "changed_handles")
    image = _bytes(image_bytes, "image_bytes")
    if not image:
        _fail("image must not be empty")
    if len(image) > _MAX_IMAGE:
        _fail("image exceeds resource limit", ResourceLimitError)
    primary = _payload(primary_handles, primary_payload_bytes, "primary")
    if not set(primary.handles).issubset(changed):
        _fail("primary handles must be a subset of changed_handles")
    fallback_handles_tuple = _handles(fallback_handles, "fallback_handles", allow_empty=True)
    if fallback_payload_bytes is None:
        if fallback_handles_tuple:
            _fail("fallback payload is required when fallback handles are present")
        fallback = None
    else:
        if not fallback_handles_tuple:
            _fail("fallback handles are required when fallback payload is present")
        fallback = _payload(fallback_handles_tuple, fallback_payload_bytes, "fallback")
        if not set(fallback.handles).issubset(changed):
            _fail("fallback handles must be a subset of changed_handles")
    intent = Intent(changed, fallback, image, primary, target)
    record = OutboxRecord(Dedupe(DedupeOutcome.NOT_APPLIED),
                          Delivery(None, (), DeliveryOutcome.NOT_SENT), intent,
                          _intent_id(intent), Publication(CasOutcome.NOT_SENT, None, None, None))
    record = _validate_record(record)
    canonical_bytes(record)
    return record


def _oids(remote_base: str, remote_blob: str, remote_commit: str) -> tuple[str, str, str]:
    pub = Publication(CasOutcome.UNKNOWN, remote_base, remote_blob, remote_commit)
    _publication(pub)
    return remote_base, remote_blob, remote_commit


def prepare_publication(record: OutboxRecord, *, remote_base: str, remote_blob: str,
                        remote_commit: str) -> OutboxRecord:
    _validate_record(record)
    if record.publication != Publication(CasOutcome.NOT_SENT, None, None, None):
        _fail("publication is already prepared", InvalidTransitionError)
    oids = _oids(remote_base, remote_blob, remote_commit)
    return replace(record, publication=Publication(CasOutcome.NOT_SENT, *oids))


def begin_publication(record: OutboxRecord) -> OutboxRecord:
    _validate_record(record)
    pub = record.publication
    if pub.outcome is not CasOutcome.NOT_SENT or pub.remote_base is None:
        _fail("publication is not prepared", InvalidTransitionError)
    return replace(record, publication=replace(pub, outcome=CasOutcome.UNKNOWN))


def mark_publication_published(record: OutboxRecord) -> OutboxRecord:
    _validate_record(record)
    if record.publication.outcome is not CasOutcome.UNKNOWN:
        _fail("publication is not unknown", InvalidTransitionError)
    return replace(record, publication=replace(record.publication, outcome=CasOutcome.PUBLISHED))


def mark_publication_conflict(record: OutboxRecord) -> OutboxRecord:
    _validate_record(record)
    if record.publication.outcome is not CasOutcome.UNKNOWN:
        _fail("publication is not unknown", InvalidTransitionError)
    return replace(record, publication=replace(record.publication, outcome=CasOutcome.CONFLICT))


def confirm_existing_publication(record: OutboxRecord, *, remote_base: str, remote_blob: str,
                                 remote_commit: str) -> OutboxRecord:
    _validate_record(record)
    if record.publication != Publication(CasOutcome.NOT_SENT, None, None, None):
        _fail("existing publication can only confirm an unprepared record", InvalidTransitionError)
    oids = _oids(remote_base, remote_blob, remote_commit)
    return replace(record, publication=Publication(CasOutcome.PUBLISHED, *oids))


def fallback_eligible(record: OutboxRecord) -> bool:
    _validate_record(record)
    return (record.publication.outcome is CasOutcome.CONFLICT and
            record.delivery.outcome is DeliveryOutcome.NOT_SENT and record.delivery.channel is None and
            record.intent.fallback is not None)


def begin_delivery(record: OutboxRecord, channel: DeliveryChannel) -> OutboxRecord:
    _validate_record(record)
    if not isinstance(channel, DeliveryChannel):
        _fail("channel must be a DeliveryChannel")
    if channel is DeliveryChannel.PRIMARY:
        okay = (record.publication.outcome is CasOutcome.PUBLISHED and
                record.delivery.outcome is DeliveryOutcome.NOT_SENT and record.delivery.channel is None)
    else:
        okay = fallback_eligible(record)
    if not okay:
        _fail("delivery cannot begin in this state", InvalidTransitionError)
    return replace(record, delivery=Delivery(channel, (), DeliveryOutcome.UNKNOWN))


def confirm_delivery_sent(record: OutboxRecord) -> OutboxRecord:
    _validate_record(record)
    delivery = record.delivery
    if delivery.outcome is not DeliveryOutcome.UNKNOWN or delivery.channel is None:
        _fail("delivery is not unknown", InvalidTransitionError)
    handles = (record.intent.primary.handles if delivery.channel is DeliveryChannel.PRIMARY
               else record.intent.fallback.handles if record.intent.fallback else None)
    if handles is None:
        _fail("missing fallback intent", InvalidTransitionError)
    return replace(record, delivery=Delivery(delivery.channel, handles, DeliveryOutcome.SENT))


def dedupe_eligible_handles(record: OutboxRecord) -> tuple[str, ...]:
    _validate_record(record)
    return record.delivery.delivered_handles if record.delivery.outcome is DeliveryOutcome.SENT else ()


def mark_dedupe_applied(record: OutboxRecord, *, applied_handles: Iterable[str]) -> OutboxRecord:
    _validate_record(record)
    if record.delivery.outcome is not DeliveryOutcome.SENT or record.dedupe.outcome is not DedupeOutcome.NOT_APPLIED:
        _fail("dedupe cannot be applied in this state", InvalidTransitionError)
    applied = _handles(applied_handles, "applied_handles")
    if applied != dedupe_eligible_handles(record):
        _fail("applied handles must exactly match eligible handles", ValidationError)
    return replace(record, dedupe=Dedupe(DedupeOutcome.APPLIED))


def resume_action(record: OutboxRecord) -> ResumeAction:
    _validate_record(record)
    pub, delivery, dedupe = record.publication, record.delivery, record.dedupe
    if delivery.outcome is DeliveryOutcome.UNKNOWN:
        return ResumeAction.RECONCILE_DELIVERY
    if delivery.outcome is DeliveryOutcome.SENT:
        return ResumeAction.COMPLETE if dedupe.outcome is DedupeOutcome.APPLIED else ResumeAction.APPLY_DEDUPE
    if pub.outcome is CasOutcome.NOT_SENT:
        return ResumeAction.PREPARE_PUBLICATION if pub.remote_base is None else ResumeAction.START_PUBLICATION
    if pub.outcome is CasOutcome.UNKNOWN:
        return ResumeAction.RECONCILE_PUBLICATION
    if pub.outcome is CasOutcome.PUBLISHED:
        return ResumeAction.START_PRIMARY_DELIVERY
    return ResumeAction.START_FALLBACK_DELIVERY if fallback_eligible(record) else ResumeAction.TERMINAL_CONFLICT


def canonical_bytes(record: OutboxRecord) -> bytes:
    _validate_record(record)
    obj = {
        "dedupe": {"outcome": record.dedupe.outcome.value},
        "delivery": {"channel": None if record.delivery.channel is None else record.delivery.channel.value,
                     "delivered_handles": list(record.delivery.delivered_handles),
                     "outcome": record.delivery.outcome.value},
        "intent": _intent_object(record.intent),
        "outbox_id": record.outbox_id,
        "publication": {"outcome": record.publication.outcome.value,
                        "remote_base": record.publication.remote_base,
                        "remote_blob": record.publication.remote_blob,
                        "remote_commit": record.publication.remote_commit},
        "schema": SCHEMA,
    }
    encoded = _dump(obj)
    if len(encoded) > _MAX_RECORD:
        _fail("canonical record exceeds resource limit", ResourceLimitError)
    return encoded


def record_sha256(record: OutboxRecord) -> str:
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def record_size(record: OutboxRecord) -> int:
    return len(canonical_bytes(record))


def _object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(f"invalid {name} object", CanonicalEncodingError)
    return value


def _decoded_envelope(value: Any, name: str) -> bytes:
    value = _object(value, {"b64", "sha256", "size"}, name)
    b64, digest, size = value["b64"], value["sha256"], value["size"]
    if not isinstance(b64, str) or not isinstance(digest, str) or type(size) is not int or size < 0:
        _fail(f"invalid {name} envelope", CanonicalEncodingError)
    try:
        data = base64.b64decode(b64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise CanonicalEncodingError(f"invalid {name} base64") from error
    if base64.b64encode(data).decode("ascii") != b64:
        _fail(f"noncanonical {name} base64", CanonicalEncodingError)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        _fail(f"invalid {name} integrity", IntegrityError)
    return data


def _parse_payload(value: Any, name: str) -> Payload:
    value = _object(value, {"handles", "payload"}, name)
    handles = _handles(value["handles"], f"{name}_handles", cls=CanonicalEncodingError)
    payload = _decoded_envelope(value["payload"], f"{name}.payload")
    try:
        parsed = _payload(handles, payload, name)
    except ResourceLimitError:
        raise
    except OutboxError as error:
        raise CanonicalEncodingError(str(error)) from error
    if parsed.handles != tuple(value["handles"]):
        _fail(f"noncanonical {name} handles", CanonicalEncodingError)
    return parsed


def parse_canonical_bytes(value: bytes) -> OutboxRecord:
    """Strictly parse exactly one canonical record; no compatibility decoding."""
    if type(value) is not bytes:
        _fail("canonical input must be bytes", CanonicalEncodingError)
    if len(value) > _MAX_RECORD:
        _fail("canonical record exceeds resource limit", ResourceLimitError)
    if value.startswith(b"\xef\xbb\xbf"):
        _fail("BOM is not allowed", CanonicalEncodingError)
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CanonicalEncodingError("canonical input must be UTF-8") from error
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, val in pairs:
            if key in result:
                _fail("duplicate JSON key", CanonicalEncodingError)
            result[key] = val
        return result
    try:
        raw = json.loads(text, object_pairs_hook=no_duplicates,
                         parse_constant=lambda _: _fail("nonfinite JSON", CanonicalEncodingError))
    except OutboxError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise CanonicalEncodingError("invalid JSON") from error
    root = _object(raw, {"dedupe", "delivery", "intent", "outbox_id", "publication", "schema"}, "record")
    if root["schema"] != SCHEMA:
        _fail("unsupported schema", SchemaVersionError)
    intent_raw = _object(root["intent"], {"changed_handles", "fallback", "image", "primary", "target"}, "intent")
    target_raw = _object(intent_raw["target"], {"path", "ref", "repository"}, "target")
    try:
        path_raw = _string(target_raw["path"], "path")
        path = _path(path_raw)
        if path != path_raw:
            _fail("noncanonical path", CanonicalEncodingError)
        target = Target(_repository(target_raw["repository"]), _ref(target_raw["ref"]), path)
        changed = _handles(intent_raw["changed_handles"], "changed_handles")
        if changed != tuple(intent_raw["changed_handles"]):
            _fail("noncanonical changed handles", CanonicalEncodingError)
        image = _decoded_envelope(intent_raw["image"], "image")
        primary = _parse_payload(intent_raw["primary"], "primary")
        fallback = None if intent_raw["fallback"] is None else _parse_payload(intent_raw["fallback"], "fallback")
        if len(image) > _MAX_IMAGE:
            _fail("image exceeds resource limit", ResourceLimitError)
        if not image or not set(primary.handles).issubset(changed):
            _fail("invalid immutable intent")
        if fallback is not None and not set(fallback.handles).issubset(changed):
            _fail("invalid fallback intent")
    except (CanonicalEncodingError, ResourceLimitError, IntegrityError):
        raise
    except (OutboxError, TypeError) as error:
        raise CanonicalEncodingError("invalid intent") from error
    pub_raw = _object(root["publication"], {"outcome", "remote_base", "remote_blob", "remote_commit"}, "publication")
    delivery_raw = _object(root["delivery"], {"channel", "delivered_handles", "outcome"}, "delivery")
    dedupe_raw = _object(root["dedupe"], {"outcome"}, "dedupe")
    try:
        pub = Publication(CasOutcome(pub_raw["outcome"]), pub_raw["remote_base"], pub_raw["remote_blob"], pub_raw["remote_commit"])
        channel = None if delivery_raw["channel"] is None else DeliveryChannel(delivery_raw["channel"])
        delivery = Delivery(channel, _handles(delivery_raw["delivered_handles"], "delivered_handles", allow_empty=True),
                            DeliveryOutcome(delivery_raw["outcome"]))
        if delivery.delivered_handles != tuple(delivery_raw["delivered_handles"]):
            _fail("noncanonical delivered handles", CanonicalEncodingError)
        dedupe = Dedupe(DedupeOutcome(dedupe_raw["outcome"]))
        record = OutboxRecord(dedupe, delivery, Intent(changed, fallback, image, primary, target),
                              _string(root["outbox_id"], "outbox_id"), pub, _string(root["schema"], "schema"))
        _validate_record(record, CanonicalEncodingError)
    except (CanonicalEncodingError, ResourceLimitError, IntegrityError):
        raise
    except (OutboxError, ValueError, TypeError) as error:
        raise CanonicalEncodingError("invalid state") from error
    if canonical_bytes(record) != value:
        _fail("input is not canonical", CanonicalEncodingError)
    return record


__all__ = [
    "SCHEMA", "CasOutcome", "DeliveryOutcome", "DeliveryChannel", "DedupeOutcome", "ResumeAction",
    "OutboxError", "ValidationError", "ResourceLimitError", "CanonicalEncodingError", "SchemaVersionError",
    "IntegrityError", "InvalidTransitionError", "OutboxRecord", "create_record", "prepare_publication",
    "begin_publication",
    "mark_publication_published", "mark_publication_conflict", "confirm_existing_publication", "begin_delivery",
    "confirm_delivery_sent", "mark_dedupe_applied", "fallback_eligible", "dedupe_eligible_handles",
    "resume_action", "canonical_bytes", "parse_canonical_bytes", "record_sha256", "record_size",
]
