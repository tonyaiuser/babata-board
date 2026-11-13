import base64
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from unittest import mock

import scripts.report_delivery_outbox_v1 as outbox


def fixture(**extra):
    args = dict(repository="owner/repo", ref="refs/heads/main", path="reports/a.png",
                image_bytes=b"image", primary_payload_bytes=b"primary",
                changed_handles=("zoe", "alice"), primary_handles=("alice",))
    args.update(extra)
    return outbox.create_record(**args)


def prepared(record, width=40):
    return outbox.prepare_publication(record, remote_base="a" * width,
                                      remote_blob="b" * width, remote_commit="c" * width)


def changed_json(record, modify):
    value = json.loads(outbox.canonical_bytes(record))
    modify(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8") + b"\n"


class ReportDeliveryOutboxTests(unittest.TestCase):
    def test_golden_numeric_size_hash_and_identity(self):
        record = fixture()
        encoded = outbox.canonical_bytes(record)
        self.assertEqual(encoded, b'{"dedupe":{"outcome":"not_applied"},"delivery":{"channel":null,"delivered_handles":[],"outcome":"not_sent"},"intent":{"changed_handles":["alice","zoe"],"fallback":null,"image":{"b64":"aW1hZ2U=","sha256":"6105d6cc76af400325e94d588ce511be5bfdbb73b437dc51eca43917d7a43e3d","size":5},"primary":{"handles":["alice"],"payload":{"b64":"cHJpbWFyeQ==","sha256":"986a1b7135f4986150aa5fa0028feeaa66cdaf3ed6a00a355dd86e042f7fb494","size":7}},"target":{"path":"reports/a.png","ref":"refs/heads/main","repository":"owner/repo"}},"outbox_id":"rdo1-e57b1422d8ad4db96ae871b55ddd36123e0cdff936854ed0fa2453a11d9e3344","publication":{"outcome":"not_sent","remote_base":null,"remote_blob":null,"remote_commit":null},"schema":"report-delivery-outbox/v1"}\n')
        self.assertEqual(record.outbox_id, "rdo1-e57b1422d8ad4db96ae871b55ddd36123e0cdff936854ed0fa2453a11d9e3344")
        self.assertEqual(outbox.record_sha256(record), "48cfc312382053316ace321d4dde4a63af7632fcfe3338a9a64f500a374b8318")
        self.assertEqual(outbox.record_size(record), 733)
        self.assertEqual(outbox.parse_canonical_bytes(encoded), record)
        self.assertNotEqual(fixture(image_bytes=b"Image").outbox_id, record.outbox_id)
        self.assertNotEqual(outbox.record_sha256(fixture(image_bytes=b"Image")), outbox.record_sha256(record))

    def test_nfc_permutation_and_generator_are_deterministic(self):
        first = fixture(changed_handles=("zoe", "e\u0301"), primary_handles=("e\u0301",))
        second = fixture(changed_handles=(x for x in ("é", "zoe")), primary_handles=(x for x in ("é",)))
        self.assertEqual(first.intent.changed_handles, ("zoe", "é"))
        self.assertEqual(outbox.canonical_bytes(first), outbox.canonical_bytes(second))
        self.assertEqual(first.outbox_id, second.outbox_id)
        for bad in ("abc", b"abc", {"a": 1}):
            with self.subTest(bad=type(bad).__name__), self.assertRaises(outbox.ValidationError):
                fixture(changed_handles=bad)

    def test_strict_parser_matrix(self):
        canonical = outbox.canonical_bytes(fixture())
        corruptions = [
            (b" " + canonical, outbox.CanonicalEncodingError),
            (canonical + b" ", outbox.CanonicalEncodingError),
            (b"\xef\xbb\xbf" + canonical, outbox.CanonicalEncodingError),
            (b"\xff", outbox.CanonicalEncodingError),
            (canonical.replace(b'"schema":', b'"schema":"x","schema":', 1), outbox.CanonicalEncodingError),
            (canonical.replace(b'"schema":"report-delivery-outbox/v1"', b'"schema":"x"'), outbox.SchemaVersionError),
            (canonical.replace(b'"outbox_id":', b'"extra":1,"outbox_id":', 1), outbox.CanonicalEncodingError),
            (canonical.replace(b'"size":5', b'"size":6', 1), outbox.IntegrityError),
            (canonical.replace(b'aW1hZ2U=', b'aW1hZ2U!', 1), outbox.CanonicalEncodingError),
            (canonical.replace(b'rdo1-', b'rdo1-x', 1), outbox.IntegrityError),
            (canonical.replace(b'"outcome":"not_sent"', b'"outcome":"bad"', 1), outbox.CanonicalEncodingError),
            (b"[" * 1100 + b"]" * 1100, outbox.CanonicalEncodingError),
        ]
        for value, expected in corruptions:
            with self.subTest(expected=expected.__name__), self.assertRaises(expected):
                outbox.parse_canonical_bytes(value)
        missing = canonical.replace(b',"schema":"report-delivery-outbox/v1"', b"")
        with self.assertRaises(outbox.CanonicalEncodingError):
            outbox.parse_canonical_bytes(missing)
        unordered = canonical.replace(b'["alice","zoe"]', b'["zoe","alice"]', 1)
        with self.assertRaises(outbox.CanonicalEncodingError):
            outbox.parse_canonical_bytes(unordered)

    def test_parser_resource_errors_are_not_reclassified(self):
        payload = b"x" * (1024 * 1024 + 1)
        def too_big_payload(value):
            env = value["intent"]["primary"]["payload"]
            env.update(b64=base64.b64encode(payload).decode("ascii"), size=len(payload),
                       sha256=hashlib.sha256(payload).hexdigest())
        with self.assertRaises(outbox.ResourceLimitError):
            outbox.parse_canonical_bytes(changed_json(fixture(), too_big_payload))
        def many_handles(value):
            value["intent"]["changed_handles"] = ["h" + str(i) for i in range(10001)]
        with self.assertRaises(outbox.ResourceLimitError):
            outbox.parse_canonical_bytes(changed_json(fixture(), many_handles))

    def test_resource_iterator_early_stop_and_target_rules(self):
        consumed = []
        def many():
            for index in range(10002):
                consumed.append(index)
                yield "h" + str(index)
        with self.assertRaises(outbox.ResourceLimitError):
            fixture(changed_handles=many())
        self.assertEqual(len(consumed), 10001)
        with self.assertRaises(outbox.ResourceLimitError):
            fixture(image_bytes=b"x" * (16 * 1024 * 1024 + 1))
        with self.assertRaises(outbox.ResourceLimitError):
            fixture(primary_payload_bytes=b"x" * (1024 * 1024 + 1))
        for bad in ("refs/heads/.hidden", "refs/heads/topic.lock", "refs/heads/a..b", "refs/heads/a/b/", "refs/heads/a b"):
            with self.subTest(ref=bad), self.assertRaises(outbox.ValidationError):
                fixture(ref=bad)
        for width in (40, 64):
            self.assertEqual(prepared(fixture(), width).publication.remote_base, "a" * width)
        with self.assertRaises(outbox.ValidationError):
            outbox.prepare_publication(fixture(), remote_base="A" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
        with self.assertRaises(outbox.ValidationError):
            outbox.prepare_publication(fixture(), remote_base="a" * 40, remote_blob="b" * 64, remote_commit="c" * 40)

    def test_exact_resource_boundaries_and_create_parse_size_precheck(self):
        image_limit = b"i" * (16 * 1024 * 1024)
        self.assertEqual(fixture(image_bytes=image_limit).intent.image, image_limit)
        payload_limit = b"p" * (1024 * 1024)
        self.assertEqual(fixture(primary_payload_bytes=payload_limit).intent.primary.payload, payload_limit)
        handle_255 = "é" * 127 + "a"  # 255 UTF-8 bytes
        self.assertEqual(fixture(changed_handles=(handle_255,), primary_handles=(handle_255,)).intent.changed_handles, (handle_255,))
        with self.assertRaises(outbox.ValidationError):
            fixture(changed_handles=("é" * 128,), primary_handles=("é" * 128,))
        handles = tuple("h" + str(index) for index in range(10000))
        self.assertEqual(len(fixture(changed_handles=handles, primary_handles=(handles[0],)).intent.changed_handles), 10000)
        aggregate_args = dict(changed_handles=("a", "b"), primary_handles=("a",),
                              fallback_payload_bytes=b"f", fallback_handles=("b",))
        with mock.patch.object(outbox, "_MAX_HANDLES_BYTES", 4):
            self.assertEqual(fixture(**aggregate_args).intent.changed_handles, ("a", "b"))
        with mock.patch.object(outbox, "_MAX_HANDLES_BYTES", 3), self.assertRaises(outbox.ResourceLimitError):
            fixture(**aggregate_args)
        encoded = outbox.canonical_bytes(fixture())
        with mock.patch.object(outbox, "_MAX_RECORD", len(encoded) - 1):
            with self.assertRaises(outbox.ResourceLimitError):
                fixture()
            with self.assertRaises(outbox.ResourceLimitError):
                outbox.parse_canonical_bytes(encoded)

    def test_record_invariants_and_frozen_dataclasses(self):
        record = fixture()
        with self.assertRaises(FrozenInstanceError):
            record.outbox_id = "changed"
        nfd = replace(record.intent.target, path="e\u0301.png")
        forged = replace(record, intent=replace(record.intent, target=nfd))
        with self.assertRaises(outbox.ValidationError):
            outbox.canonical_bytes(forged)
        expected = {"SCHEMA", "CasOutcome", "DeliveryOutcome", "DeliveryChannel", "DedupeOutcome", "ResumeAction", "OutboxError", "ValidationError", "ResourceLimitError", "CanonicalEncodingError", "SchemaVersionError", "IntegrityError", "InvalidTransitionError", "OutboxRecord", "create_record", "prepare_publication", "begin_publication", "mark_publication_published", "mark_publication_conflict", "confirm_existing_publication", "begin_delivery", "confirm_delivery_sent", "mark_dedupe_applied", "fallback_eligible", "dedupe_eligible_handles", "resume_action", "canonical_bytes", "parse_canonical_bytes", "record_sha256", "record_size"}
        self.assertTrue(expected.issubset(set(outbox.__all__)))
        self.assertEqual(set(outbox.__all__), {
            "SCHEMA", "CasOutcome", "DeliveryOutcome", "DeliveryChannel", "DedupeOutcome", "ResumeAction",
            "OutboxError", "ValidationError", "ResourceLimitError", "CanonicalEncodingError", "SchemaVersionError",
            "IntegrityError", "InvalidTransitionError", "OutboxRecord", "create_record", "prepare_publication",
            "begin_publication",
            "mark_publication_published", "mark_publication_conflict", "confirm_existing_publication", "begin_delivery",
            "confirm_delivery_sent", "mark_dedupe_applied", "fallback_eligible", "dedupe_eligible_handles",
            "resume_action", "canonical_bytes", "parse_canonical_bytes", "record_sha256", "record_size",
        })
        self.assertTrue({"Target", "Payload", "Intent", "Publication", "Delivery", "Dedupe"}.isdisjoint(outbox.__all__))
        for enum, expected_members in (
            (outbox.CasOutcome, {"NOT_SENT": "not_sent", "CONFLICT": "conflict", "UNKNOWN": "unknown", "PUBLISHED": "published"}),
            (outbox.DeliveryOutcome, {"NOT_SENT": "not_sent", "UNKNOWN": "unknown", "SENT": "sent"}),
            (outbox.DeliveryChannel, {"PRIMARY": "primary", "FALLBACK": "fallback"}),
            (outbox.DedupeOutcome, {"NOT_APPLIED": "not_applied", "APPLIED": "applied"}),
            (outbox.ResumeAction, {"PREPARE_PUBLICATION": "prepare_publication", "START_PUBLICATION": "start_publication", "RECONCILE_PUBLICATION": "reconcile_publication", "START_PRIMARY_DELIVERY": "start_primary_delivery", "START_FALLBACK_DELIVERY": "start_fallback_delivery", "RECONCILE_DELIVERY": "reconcile_delivery", "APPLY_DEDUPE": "apply_dedupe", "TERMINAL_CONFLICT": "terminal_conflict", "COMPLETE": "complete"}),
        ):
            self.assertEqual({name: member.value for name, member in enum.__members__.items()}, expected_members)

    def test_strict_integrity_and_illegal_state_json(self):
        def wrong_sha(value):
            value["intent"]["image"]["sha256"] = "0" * 64
        with self.assertRaises(outbox.IntegrityError):
            outbox.parse_canonical_bytes(changed_json(fixture(), wrong_sha))
        cases = []
        def published_without_oids(value):
            value["publication"]["outcome"] = "published"
        cases.append(published_without_oids)
        def unknown_without_channel(value):
            value["delivery"]["outcome"] = "unknown"
        cases.append(unknown_without_channel)
        def sent_wrong_handles(value):
            value["publication"].update(outcome="published", remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40)
            value["delivery"].update(outcome="sent", channel="primary", delivered_handles=["zoe"])
        cases.append(sent_wrong_handles)
        def dedupe_before_sent(value):
            value["dedupe"]["outcome"] = "applied"
        cases.append(dedupe_before_sent)
        for change in cases:
            with self.subTest(change=change.__name__), self.assertRaises(outbox.CanonicalEncodingError):
                outbox.parse_canonical_bytes(changed_json(fixture(), change))

    def test_resume_table_and_primary_unknown_safety(self):
        record = fixture()
        checkpoints = [(record, outbox.ResumeAction.PREPARE_PUBLICATION)]
        record = prepared(record); checkpoints.append((record, outbox.ResumeAction.START_PUBLICATION))
        record = outbox.begin_publication(record); checkpoints.append((record, outbox.ResumeAction.RECONCILE_PUBLICATION))
        for current, action in checkpoints:
            self.assertIs(outbox.resume_action(current), action)
        with self.assertRaises(outbox.InvalidTransitionError):
            outbox.begin_delivery(record, outbox.DeliveryChannel.PRIMARY)
        with self.assertRaises(outbox.InvalidTransitionError):
            outbox.mark_dedupe_applied(record, applied_handles=("alice",))
        published = outbox.mark_publication_published(record)
        self.assertIs(outbox.resume_action(published), outbox.ResumeAction.START_PRIMARY_DELIVERY)
        unknown = outbox.begin_delivery(published, outbox.DeliveryChannel.PRIMARY)
        self.assertIs(outbox.resume_action(unknown), outbox.ResumeAction.RECONCILE_DELIVERY)
        with self.assertRaises(outbox.InvalidTransitionError):
            outbox.begin_delivery(unknown, outbox.DeliveryChannel.FALLBACK)
        sent = outbox.confirm_delivery_sent(unknown)
        self.assertEqual(outbox.dedupe_eligible_handles(sent), ("alice",))
        self.assertIs(outbox.resume_action(sent), outbox.ResumeAction.APPLY_DEDUPE)
        with self.assertRaises(outbox.ValidationError):
            outbox.mark_dedupe_applied(sent, applied_handles=("zoe",))
        complete = outbox.mark_dedupe_applied(sent, applied_handles=("alice",))
        self.assertIs(outbox.resume_action(complete), outbox.ResumeAction.COMPLETE)
        with self.assertRaises(outbox.InvalidTransitionError):
            outbox.confirm_delivery_sent(sent)

    def test_unknown_states_cannot_retry_switch_or_send(self):
        publication_unknown = outbox.begin_publication(prepared(fixture()))
        self.assertFalse(outbox.fallback_eligible(publication_unknown))
        for call in (
            lambda: outbox.begin_publication(publication_unknown),
            lambda: outbox.confirm_existing_publication(publication_unknown, remote_base="a" * 40, remote_blob="b" * 40, remote_commit="c" * 40),
            lambda: outbox.begin_delivery(publication_unknown, outbox.DeliveryChannel.PRIMARY),
            lambda: outbox.begin_delivery(publication_unknown, outbox.DeliveryChannel.FALLBACK),
            lambda: outbox.mark_dedupe_applied(publication_unknown, applied_handles=("alice",)),
        ):
            with self.subTest(call=call), self.assertRaises(outbox.InvalidTransitionError):
                call()
        delivery_unknown = outbox.begin_delivery(outbox.mark_publication_published(publication_unknown), outbox.DeliveryChannel.PRIMARY)
        for call in (
            lambda: outbox.begin_delivery(delivery_unknown, outbox.DeliveryChannel.PRIMARY),
            lambda: outbox.begin_delivery(delivery_unknown, outbox.DeliveryChannel.FALLBACK),
            lambda: outbox.mark_dedupe_applied(delivery_unknown, applied_handles=("alice",)),
        ):
            with self.subTest(call=call), self.assertRaises(outbox.InvalidTransitionError):
                call()

    def test_conflict_fallback_no_fallback_and_existing_publication(self):
        fall = fixture(fallback_payload_bytes=b"fallback", fallback_handles=("zoe",))
        conflict = outbox.mark_publication_conflict(outbox.begin_publication(prepared(fall)))
        self.assertTrue(outbox.fallback_eligible(conflict))
        self.assertIs(outbox.resume_action(conflict), outbox.ResumeAction.START_FALLBACK_DELIVERY)
        unknown = outbox.begin_delivery(conflict, outbox.DeliveryChannel.FALLBACK)
        self.assertIs(outbox.resume_action(unknown), outbox.ResumeAction.RECONCILE_DELIVERY)
        sent = outbox.confirm_delivery_sent(unknown)
        self.assertEqual(outbox.dedupe_eligible_handles(sent), ("zoe",))
        self.assertIs(outbox.resume_action(sent), outbox.ResumeAction.APPLY_DEDUPE)
        complete = outbox.mark_dedupe_applied(sent, applied_handles=("zoe",))
        self.assertIs(outbox.resume_action(complete), outbox.ResumeAction.COMPLETE)
        terminal = outbox.mark_publication_conflict(outbox.begin_publication(prepared(fixture())))
        self.assertFalse(outbox.fallback_eligible(terminal))
        self.assertIs(outbox.resume_action(terminal), outbox.ResumeAction.TERMINAL_CONFLICT)
        existing = outbox.confirm_existing_publication(fixture(), remote_base="a" * 64,
                                                       remote_blob="b" * 64, remote_commit="c" * 64)
        self.assertIs(existing.publication.outcome, outbox.CasOutcome.PUBLISHED)
        with self.assertRaises(outbox.InvalidTransitionError):
            outbox.confirm_existing_publication(existing, remote_base="a" * 64, remote_blob="b" * 64, remote_commit="c" * 64)

    def test_repeated_calls_are_deterministic_or_rejected(self):
        record = fixture()
        first = prepared(record)
        self.assertEqual(first, prepared(record))
        self.assertEqual(outbox.canonical_bytes(first), outbox.canonical_bytes(prepared(record)))
        started = outbox.begin_publication(first)
        with self.assertRaises(outbox.InvalidTransitionError):
            outbox.begin_publication(started)
        published = outbox.mark_publication_published(started)
        with self.assertRaises(outbox.InvalidTransitionError):
            outbox.mark_publication_published(published)
        sent = outbox.confirm_delivery_sent(outbox.begin_delivery(published, outbox.DeliveryChannel.PRIMARY))
        applied = outbox.mark_dedupe_applied(sent, applied_handles=("alice",))
        with self.assertRaises(outbox.InvalidTransitionError):
            outbox.mark_dedupe_applied(applied, applied_handles=("alice",))

    def test_hostile_iterable_memory_errors_propagate(self):
        class IterMemoryError:
            def __iter__(self):
                raise MemoryError("iter")
        class NextMemoryError:
            def __iter__(self):
                return self
            def __next__(self):
                raise MemoryError("next")
        for hostile in (IterMemoryError(), NextMemoryError()):
            with self.subTest(hostile=type(hostile).__name__), self.assertRaises(MemoryError):
                fixture(changed_handles=hostile)


if __name__ == "__main__":
    unittest.main()
