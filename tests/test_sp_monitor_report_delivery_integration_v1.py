import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import unicodedata
import zlib
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "skills" / "sp-monitor" / "run.py"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_monitor_module():
    spec = importlib.util.spec_from_file_location(
        "sp_monitor_report_delivery_integration_v1", SOURCE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


MONITOR = load_monitor_module()
TEST_OUTBOX = importlib.import_module("scripts.report_delivery_outbox_v1")
TEST_ADAPTERS = importlib.import_module("scripts.report_delivery_adapters_v1")


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8") + b"\n"


def product_state(day="2026-08-04", *, reported=True, sites=3, score=10.0):
    value = {
        "first_seen": day,
        "last_seen": day,
        "last_rank": 1,
        "last_sites_count": sites,
        "last_score": score,
        "last_fb_hits": [],
        "last_is_lp": False,
        "last_flagship_count": 0,
    }
    if reported:
        value["last_reported_at"] = day
    return value


def prior_state():
    return {
        "version": 1,
        "created_at": "2026-08-04T08:00:00+08:00",
        "last_run": "2026-08-04T11:30:00+08:00",
        "last_result_count": 1,
        "last_reported_count": 1,
        "products": {"alpha": product_state()},
    }


def next_state():
    value = copy.deepcopy(prior_state())
    value["last_run"] = "2026-08-05T11:30:00+08:00"
    value["last_result_count"] = 2
    value["last_reported_count"] = 1
    value["products"]["alpha"].update(
        last_seen="2026-08-05",
        last_sites_count=4,
        last_score=12.0,
        last_reported_at="2026-08-05",
    )
    value["products"]["beta"] = product_state(
        "2026-08-05", reported=False, sites=2, score=8.0
    )
    return value


def primary_wire():
    return {
        "msgtype": "markdown",
        "markdown": {
            "title": "SP report 2026-08-05",
            "text": "![report](https://example.invalid/report.png)",
        },
    }


def fallback_wire():
    return {"msgtype": "text", "text": {"content": "SP fallback report"}}


def report_row(handle="alpha", *, score=12.0, sites=4):
    return {
        "handle": handle,
        "title": handle.title() + " product",
        "sample_url": f"https://shop.example/products/{handle}",
        "sites_count": sites,
        "score": score,
        "fb_hits": [],
        "is_lp": False,
        "flagship_count": 0,
        "flagship_hits": [],
        "countries": ["US"],
    }


def report_inputs():
    alpha = report_row("alpha")
    beta = report_row("beta", score=8.0, sites=2)
    return {
        "state": prior_state(),
        "results": [alpha, beta],
        "change_groups": {
            "new": [{"row": alpha, "rank": 1, "reasons": ["首次发现"]}],
            "signal": [],
            "growth": [],
        },
        "today": "2026-08-05",
        "text_message": "SP frozen fallback",
        "text_delivered_handles": ["alpha"],
        "dashboard_receipt": {
            "source_date": "2026-08-05",
            "source_hash": "f" * 64,
        },
        "frozen_last_run": "2026-08-05T11:30:00+08:00",
    }


def make_plan(channel="primary", *, existed=True, before=None, after=None,
              changed=("alpha", "beta"), delivered=("alpha",)):
    before = prior_state() if before is None else before
    after = next_state() if after is None else after
    return MONITOR.build_report_delivery_plan(
        channel=channel,
        prior_exists=existed,
        prior_state=before,
        next_state=after,
        changed_handles=changed,
        delivered_handles=delivered,
        frozen_last_run=after["last_run"],
    )


def make_envelope(channel="primary", **plan_overrides):
    wire = primary_wire() if channel == "primary" else fallback_wire()
    return MONITOR.build_report_delivery_envelope(
        channel, wire, make_plan(channel, **plan_overrides)
    )


class StrictEnvelopeIntegrationTest(unittest.TestCase):
    def test_round_trip_is_canonical_strict_and_has_no_hidden_outer_fields(self):
        envelope = make_envelope()
        decoded = MONITOR.decode_report_delivery_envelope(
            envelope, expected_channel="primary", expected_handles=("alpha",)
        )
        outer = json.loads(envelope)
        self.assertEqual(set(outer), {"schema", "channel", "wire", "plan"})
        self.assertEqual(envelope, canonical(outer))
        self.assertEqual(decoded["wire"], primary_wire())
        self.assertEqual(decoded["wire_bytes"], canonical(primary_wire()))
        self.assertEqual(decoded["wire_sha256"], hashlib.sha256(canonical(primary_wire())).hexdigest())
        self.assertEqual(decoded["plan"], make_plan())
        self.assertEqual(decoded["plan_bytes"], canonical(make_plan()))
        self.assertEqual(decoded["plan_sha256"], hashlib.sha256(canonical(make_plan())).hexdigest())

    def test_noncanonical_duplicate_extra_missing_and_mismatched_bindings_fail_closed(self):
        envelope = make_envelope()
        outer = json.loads(envelope)
        cases = []
        cases.append(b" " + envelope)
        cases.append(envelope + b" ")
        cases.append(envelope.replace(b'"schema":', b'"schema":"duplicate","schema":', 1))
        extra = copy.deepcopy(outer)
        extra["extra"] = None
        cases.append(canonical(extra))
        missing = copy.deepcopy(outer)
        del missing["wire"]
        cases.append(canonical(missing))
        wrong_wire_sha = copy.deepcopy(outer)
        wrong_wire_sha["wire"]["sha256"] = "0" * 64
        cases.append(canonical(wrong_wire_sha))
        wrong_wire_size = copy.deepcopy(outer)
        wrong_wire_size["wire"]["size"] += 1
        cases.append(canonical(wrong_wire_size))
        wrong_plan_sha = copy.deepcopy(outer)
        wrong_plan_sha["plan"]["sha256"] = "0" * 64
        cases.append(canonical(wrong_plan_sha))
        wrong_channel = copy.deepcopy(outer)
        wrong_channel["channel"] = "fallback"
        cases.append(canonical(wrong_channel))
        for index, value in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(
                MONITOR.ReportDeliveryIntegrityError
            ):
                MONITOR.decode_report_delivery_envelope(value)
        with self.assertRaises(MONITOR.ReportDeliveryIntegrityError):
            MONITOR.decode_report_delivery_envelope(
                envelope, expected_channel="fallback"
            )
        with self.assertRaises(MONITOR.ReportDeliveryIntegrityError):
            MONITOR.decode_report_delivery_envelope(
                envelope, expected_handles=("beta",)
            )

    def test_real_zlib_bomb_is_bounded_before_json_or_hash_acceptance(self):
        outer = json.loads(make_envelope())
        expanded = b"x" * (MONITOR._REPORT_DELIVERY_PLAN_MAX_BYTES + 1)
        compressed = zlib.compress(expanded, level=9)
        self.assertLess(len(compressed), MONITOR._REPORT_DELIVERY_PLAN_MAX_BYTES)
        outer["plan"] = {
            "encoding": "zlib+base64",
            "b64": base64.b64encode(compressed).decode("ascii"),
            "size": MONITOR._REPORT_DELIVERY_PLAN_MAX_BYTES,
            "compressed_size": len(compressed),
            "sha256": hashlib.sha256(expanded).hexdigest(),
        }
        bomb = canonical(outer)
        self.assertLess(len(bomb), MONITOR._REPORT_DELIVERY_ENVELOPE_MAX_BYTES)
        with self.assertRaises(MONITOR.ReportDeliveryIntegrityError):
            MONITOR.decode_report_delivery_envelope(bomb)

    def test_one_mebibyte_envelope_limit_is_enforced_before_parsing(self):
        oversized = b"{" + b" " * MONITOR._REPORT_DELIVERY_ENVELOPE_MAX_BYTES + b"}"
        self.assertGreater(len(oversized), 1024 * 1024)
        with self.assertRaises(MONITOR.ReportDeliveryIntegrityError):
            MONITOR.decode_report_delivery_envelope(oversized)

    def test_next_state_cannot_embed_receipt_or_self_reference(self):
        after = next_state()
        after["delivery_receipt"] = {
            "schema": MONITOR.REPORT_DELIVERY_RECEIPT_SCHEMA,
            "outbox_id": "rdo1-" + "a" * 64,
            "digest": "b" * 64,
            "handles": ["alpha"],
            "plan_sha256": "c" * 64,
            "next_state_sha256": "d" * 64,
        }
        MONITOR.validate_report_state(after)
        with self.assertRaises(MONITOR.ReportDeliveryInputError):
            make_plan(after=after)

    def test_plan_canonicalizes_order_and_rejects_duplicate_or_out_of_intent_handles(self):
        ordered = make_plan(delivered=("beta", "alpha"))
        self.assertEqual(ordered["delivered_handles"], ["alpha", "beta"])
        for delivered in (("alpha", "alpha"), ("outside",)):
            with self.subTest(delivered=delivered), self.assertRaises(
                (MONITOR.ReportDeliveryInputError, MONITOR.ReportDeliveryIntegrityError)
            ):
                make_plan(delivered=delivered)


class ReportStateDedupeIntegrationTest(unittest.TestCase):
    OUTBOX_ID = "rdo1-" + "a" * 64
    DIGEST = "b" * 64

    def test_ack_loss_replay_returns_unchanged_and_preserves_exact_state_bytes(self):
        payload = make_envelope()
        with tempfile.TemporaryDirectory() as temp:
            state_path = Path(temp) / "state.json"
            state_path.write_bytes(canonical(prior_state()))
            adapter = MONITOR.ReportStateDedupeAdapter(payload, state_path=state_path)
            first = adapter.apply(self.OUTBOX_ID, self.DIGEST, ("alpha",))
            self.assertEqual(first["outcome"], "applied")
            applied_bytes = state_path.read_bytes()
            applied = json.loads(applied_bytes)
            self.assertEqual(applied["delivery_receipt"]["outbox_id"], self.OUTBOX_ID)
            replay = MONITOR.ReportStateDedupeAdapter(payload, state_path=state_path)
            second = replay.apply(self.OUTBOX_ID, self.DIGEST, ("alpha",))
            self.assertEqual(second, {
                "outbox_id": self.OUTBOX_ID,
                "digest": self.DIGEST,
                "outcome": "unchanged",
            })
            self.assertEqual(state_path.read_bytes(), applied_bytes)

    def test_prior_content_or_existence_divergence_fails_without_overwrite(self):
        payload = make_envelope()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            divergent = prior_state()
            divergent["last_result_count"] = 99
            state_path = root / "state.json"
            state_path.write_bytes(canonical(divergent))
            before = state_path.read_bytes()
            adapter = MONITOR.ReportStateDedupeAdapter(payload, state_path=state_path)
            with self.assertRaises(MONITOR.ReportDeliveryIntegrityError):
                adapter.apply(self.OUTBOX_ID, self.DIGEST, ("alpha",))
            self.assertEqual(state_path.read_bytes(), before)

            state_path.unlink()
            with self.assertRaises(MONITOR.ReportDeliveryIntegrityError):
                adapter.apply(self.OUTBOX_ID, self.DIGEST, ("alpha",))
            self.assertFalse(state_path.exists())

    def test_wrong_replay_binding_or_handle_order_is_never_acknowledged(self):
        payload = make_envelope(delivered=("alpha", "beta"))
        with tempfile.TemporaryDirectory() as temp:
            state_path = Path(temp) / "state.json"
            state_path.write_bytes(canonical(prior_state()))
            adapter = MONITOR.ReportStateDedupeAdapter(payload, state_path=state_path)
            before = state_path.read_bytes()
            cases = (
                ("rdo1-" + "x" * 64, self.DIGEST, ("alpha", "beta")),
                (self.OUTBOX_ID, "x" * 64, ("alpha", "beta")),
                (self.OUTBOX_ID, self.DIGEST, ("beta", "alpha")),
                (self.OUTBOX_ID, self.DIGEST, ("alpha",)),
            )
            for index, args in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(
                    MONITOR.ReportDeliveryIntegrityError
                ):
                    adapter.apply(*args)
                self.assertEqual(state_path.read_bytes(), before)


class FixedGithubTransportIntegrationTest(unittest.TestCase):
    PREFIX = "/repos/tonyaiuser/babata-board"

    @staticmethod
    def completed(status=200, body=None, *, returncode=0, headers=()):
        body = {} if body is None else body
        header_lines = [f"HTTP/2.0 {status} synthetic".encode("ascii")]
        header_lines.extend(headers)
        stdout = b"\r\n".join(header_lines) + b"\r\n\r\n" + canonical(body)
        return SimpleNamespace(stdout=stdout, stderr=b"sensitive-stderr-marker", returncode=returncode)

    def test_request_uses_exact_argv_canonical_stdin_no_shell_and_allowlisted_environment(self):
        transport = MONITOR.ReportGithubTransport()
        response = self.completed(201, {"sha": "a" * 40})
        with mock.patch.dict(
            MONITOR.os.environ,
            {"HOME": "/tmp/synthetic-home", "SECRET_MARKER": "must-not-forward"},
            clear=True,
        ), mock.patch.object(MONITOR.subprocess, "run", return_value=response) as runner:
            result = transport.request(
                "POST", self.PREFIX + "/git/blobs", {"z": 1, "a": "value"}
            )
        self.assertEqual(result, {"status": 201, "body": {"sha": "a" * 40}})
        runner.assert_called_once()
        args, kwargs = runner.call_args
        self.assertEqual(args[0], [
            MONITOR.REPORT_DELIVERY_GH_EXECUTABLE,
            "api",
            "--include",
            "--method",
            "POST",
            self.PREFIX + "/git/blobs",
            "--input",
            "-",
        ])
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["input"], b'{"a":"value","z":1}\n')
        self.assertEqual(kwargs["env"], {"HOME": "/tmp/synthetic-home", "NO_COLOR": "1"})
        self.assertNotIn("SECRET_MARKER", kwargs["env"])

    def test_patch_409_and_422_are_structured_once_without_retry(self):
        transport = MONITOR.ReportGithubTransport()
        path = self.PREFIX + "/git/refs/heads/main"
        for status in (409, 422):
            with self.subTest(status=status), mock.patch.object(
                MONITOR.subprocess,
                "run",
                return_value=self.completed(status, {"message": "conflict"}, returncode=1),
            ) as runner:
                result = transport.request("PATCH", path, {"sha": "a" * 40, "force": False})
            self.assertEqual(result["status"], status)
            self.assertEqual(runner.call_count, 1)

    def test_malicious_endpoint_executable_and_include_framing_fail_without_process_retry(self):
        with self.assertRaises(MONITOR.ReportGithubTransportError):
            MONITOR.ReportGithubTransport(executable="/tmp/fake-gh")
        transport = MONITOR.ReportGithubTransport()
        malicious_paths = (
            self.PREFIX + "/git/ref/heads/main;touch /tmp/no",
            self.PREFIX + "/git/ref/heads/main\n--hostname=evil.invalid",
            "--hostname=evil.invalid",
        )
        for path in malicious_paths:
            with self.subTest(path=path), mock.patch.object(MONITOR.subprocess, "run") as runner:
                with self.assertRaises(MONITOR.ReportGithubTransportError):
                    transport.request("GET", path)
                runner.assert_not_called()

        outputs = (
            b"HTTP/2.0 200 OK\r\nX-A: 1\r\nX-A: 2\r\n\r\n{}\n",
            b"HTTP/2.0 200 OK\r\n\r\n{}\nHTTP/2.0 500 injected\n",
            b"HTTP/2.0 200 OK\r\n\r\n[]\n",
            b"HTTP/2.0 200 OK\r\n\r\n" + b"x" * MONITOR._REPORT_DELIVERY_GH_OUTPUT_MAX_BYTES,
        )
        for index, stdout in enumerate(outputs):
            completed = SimpleNamespace(stdout=stdout, stderr=b"private", returncode=0)
            with self.subTest(index=index), mock.patch.object(
                MONITOR.subprocess, "run", return_value=completed
            ) as runner, self.assertRaises(MONITOR.ReportGithubTransportError):
                transport.request("GET", self.PREFIX + "/git/ref/heads/main")
            self.assertEqual(runner.call_count, 1)

    def test_non_conflict_nonzero_exit_is_redacted_and_never_retried(self):
        completed = self.completed(500, {"message": "private"}, returncode=1)
        with mock.patch.object(MONITOR.subprocess, "run", return_value=completed) as runner:
            with self.assertRaises(MONITOR.ReportGithubTransportError) as caught:
                MONITOR.ReportGithubTransport().request(
                    "GET", self.PREFIX + "/git/ref/heads/main"
                )
        self.assertEqual(runner.call_count, 1)
        rendered = f"{caught.exception!s} {caught.exception!r}"
        self.assertNotIn("private", rendered)
        self.assertNotIn("sensitive-stderr-marker", rendered)


class DingTalkTransportIntegrationTest(unittest.TestCase):
    OUTBOX_ID = "rdo1-" + "a" * 64

    def test_exact_binding_decodes_then_sends_wire_once_with_one_attempt(self):
        payload = make_envelope()
        transport = MONITOR.ReportDingTalkTransport(
            self.OUTBOX_ID,
            "primary",
            hashlib.sha256(payload).hexdigest(),
            ("alpha",),
        )
        with mock.patch.object(
            MONITOR, "send_dingtalk_payload", return_value={"errcode": 0}
        ) as sender:
            result = transport.send("primary", payload, idempotency_key=self.OUTBOX_ID)
        self.assertEqual(result, {"status": 200, "ack": 1})
        sender.assert_called_once_with(canonical(primary_wire()), max_attempts=1)

    def test_binding_mismatch_or_remote_failure_never_retries(self):
        payload = make_envelope()
        transport = MONITOR.ReportDingTalkTransport(
            self.OUTBOX_ID,
            "primary",
            hashlib.sha256(payload).hexdigest(),
            ("alpha",),
        )
        cases = (
            ("fallback", payload, self.OUTBOX_ID),
            ("primary", payload, "rdo1-" + "b" * 64),
            ("primary", payload + b" ", self.OUTBOX_ID),
        )
        for index, (channel, value, key) in enumerate(cases):
            with self.subTest(index=index), mock.patch.object(
                MONITOR, "send_dingtalk_payload"
            ) as sender, self.assertRaises(MONITOR.DingTalkDeliveryError):
                transport.send(channel, value, idempotency_key=key)
            sender.assert_not_called()

        with mock.patch.object(
            MONITOR, "send_dingtalk_payload", return_value={"errcode": 17}
        ) as sender, self.assertRaises(MONITOR.DingTalkDeliveryError):
            transport.send("primary", payload, idempotency_key=self.OUTBOX_ID)
        self.assertEqual(sender.call_count, 1)


class ReportRecordBuilderIntegrationTest(unittest.TestCase):
    def test_record_freezes_remote_url_dashboard_and_non_self_referential_plans(self):
        outbox, _adapters = TEST_OUTBOX, TEST_ADAPTERS
        inputs = report_inputs()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state_path = root / "state.json"
            state_path.write_bytes(canonical(inputs["state"]))
            image_path = root / "report.png"
            image_path.write_bytes(b"synthetic-image")

            def image_factory(groups, today, results_count, changed_count, publish=True):
                self.assertIs(groups, inputs["change_groups"])
                self.assertEqual((today, results_count, changed_count), ("2026-08-05", 2, 1))
                self.assertIs(publish, False)
                return {
                    "path": image_path,
                    "items": inputs["change_groups"]["new"],
                }

            record = MONITOR.build_report_delivery_record_v1(
                outbox_module=outbox,
                state_path=state_path,
                image_factory=image_factory,
                **inputs,
            )
        self.assertEqual(record.intent.target.repository, MONITOR.REPORT_DELIVERY_GITHUB_REPOSITORY)
        self.assertEqual(record.intent.target.ref, MONITOR.REPORT_DELIVERY_GITHUB_REF)
        self.assertEqual(record.intent.target.path, "reports/dingtalk/sp_report_2026-08-05.png")
        primary = MONITOR.decode_report_delivery_envelope(
            record.intent.primary.payload,
            expected_channel="primary",
            expected_handles=("alpha",),
        )
        remote_url = (
            MONITOR.REPORT_DELIVERY_RAW_BASE_URL
            + "/reports/dingtalk/sp_report_2026-08-05.png"
        )
        self.assertIn(remote_url, primary["wire"]["markdown"]["text"])
        self.assertIn("看板已核验", primary["wire"]["markdown"]["text"])
        self.assertNotIn(record.outbox_id.encode("ascii"), record.intent.primary.payload)
        self.assertNotIn(record.outbox_id.encode("ascii"), record.intent.fallback.payload)
        self.assertNotIn("delivery_receipt", primary["plan"]["next_state"])

    def test_remote_url_policy_rejects_ref_repository_and_path_injection(self):
        cases = (
            ("attacker/repo", MONITOR.REPORT_DELIVERY_GITHUB_REF,
             "reports/dingtalk/sp_report_2026-08-05.png"),
            (MONITOR.REPORT_DELIVERY_GITHUB_REPOSITORY, "refs/heads/other",
             "reports/dingtalk/sp_report_2026-08-05.png"),
            (MONITOR.REPORT_DELIVERY_GITHUB_REPOSITORY, MONITOR.REPORT_DELIVERY_GITHUB_REF,
             "reports/dingtalk/../private.png"),
        )
        for args in cases:
            with self.subTest(args=args), self.assertRaises(MONITOR.ReportDeliveryInputError):
                MONITOR._report_delivery_raw_url(*args)

    def test_decomposed_unicode_handle_is_frozen_as_exact_nfc_intent_and_plan(self):
        outbox, _adapters = TEST_OUTBOX, TEST_ADAPTERS
        decomposed = "cafe\u0301"
        composed = unicodedata.normalize("NFC", decomposed)
        self.assertNotEqual(decomposed, composed)
        row = report_row(decomposed)
        change_groups = {
            "new": [{"row": row, "rank": 1, "reasons": ["首次发现"]}],
            "signal": [],
            "growth": [],
        }
        unicode_state = prior_state()
        unicode_state["products"] = {decomposed: product_state()}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state_path = root / "state.json"
            state_path.write_bytes(canonical(unicode_state))
            image_path = root / "report.png"
            image_path.write_bytes(b"unicode-image")

            def image_factory(groups, today, results_count, changed_count, publish=True):
                self.assertIs(groups, change_groups)
                self.assertEqual((results_count, changed_count), (1, 1))
                self.assertIs(publish, False)
                return {"path": image_path, "items": groups["new"]}

            record = MONITOR.build_report_delivery_record_v1(
                outbox_module=outbox,
                state=unicode_state,
                results=[row],
                change_groups=change_groups,
                today="2026-08-05",
                text_message="unicode fallback",
                text_delivered_handles=[decomposed],
                dashboard_receipt=None,
                image_factory=image_factory,
                frozen_last_run="2026-08-05T11:30:00+08:00",
                state_path=state_path,
            )

        self.assertEqual(record.intent.changed_handles, (composed,))
        self.assertEqual(record.intent.primary.handles, (composed,))
        self.assertEqual(record.intent.fallback.handles, (composed,))
        for channel, payload in (
            ("primary", record.intent.primary),
            ("fallback", record.intent.fallback),
        ):
            decoded = MONITOR.decode_report_delivery_envelope(
                payload.payload,
                expected_channel=channel,
                expected_handles=payload.handles,
            )
            self.assertEqual(tuple(decoded["plan"]["changed_handles"]),
                             record.intent.changed_handles)
            self.assertEqual(tuple(decoded["plan"]["delivered_handles"]),
                             payload.handles)
            self.assertIn(composed, decoded["plan"]["next_state"]["products"])
            self.assertNotIn(decomposed, decoded["plan"]["next_state"]["products"])
            self.assertEqual(list(decoded["plan"]["next_state"]["products"]), [composed])


class ReportDeliveryLazyLoadIntegrationTest(unittest.TestCase):
    MODULE_NAMES = (
        "scripts.report_delivery_outbox_v1",
        "scripts.report_delivery_adapters_v1",
    )

    @staticmethod
    def _write_deployment_layout(root, outbox_bytes, adapters_bytes):
        live = Path(root) / "live"
        scripts = live / "scripts"
        scripts.mkdir(parents=True)
        run_file = live / "run.py"
        run_file.write_bytes(b"# synthetic deployed entrypoint\n")
        (scripts / "report_delivery_outbox_v1.py").write_bytes(outbox_bytes)
        (scripts / "report_delivery_adapters_v1.py").write_bytes(adapters_bytes)
        return run_file, scripts

    def _without_report_modules(self):
        for name in ("scripts",) + self.MODULE_NAMES:
            sys.modules.pop(name, None)

    def test_direct_deployment_scripts_load_is_exact_and_ignores_cwd_and_fallback(self):
        outbox_source = (ROOT / "scripts" / "report_delivery_outbox_v1.py").read_bytes()
        adapters_source = (ROOT / "scripts" / "report_delivery_adapters_v1.py").read_bytes()
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
            sys.modules, {}, clear=False
        ):
            run_file, scripts = self._write_deployment_layout(
                temp, outbox_source, adapters_source
            )
            unrelated = Path(temp) / "unrelated-cwd"
            unrelated.mkdir()
            self._without_report_modules()
            try:
                os.chdir(unrelated)
                with mock.patch.object(MONITOR, "__file__", str(run_file)), \
                     mock.patch.object(MONITOR, "_REPORT_DELIVERY_MODULE_CACHE", None), \
                     mock.patch.object(
                         MONITOR.importlib,
                         "import_module",
                         side_effect=AssertionError("namespace fallback must not run"),
                     ) as fallback:
                    outbox, adapters = MONITOR._load_report_delivery_modules()
                    cached = MONITOR._load_report_delivery_modules()
            finally:
                os.chdir(original_cwd)

            fallback.assert_not_called()
            self.assertIs(cached[0], outbox)
            self.assertIs(cached[1], adapters)
            self.assertEqual(Path(outbox.__file__).resolve(),
                             (scripts / "report_delivery_outbox_v1.py").resolve())
            self.assertEqual(Path(adapters.__file__).resolve(),
                             (scripts / "report_delivery_adapters_v1.py").resolve())
            self.assertIs(adapters.outbox, outbox)
            self.assertEqual(len(sys.modules["scripts"].__path__), 1)
            self.assertEqual(Path(sys.modules["scripts"].__path__[0]).resolve(), scripts.resolve())

    def test_helper_syntax_and_runtime_failures_are_redacted_and_leave_no_partial_modules(self):
        real_outbox = (ROOT / "scripts" / "report_delivery_outbox_v1.py").read_bytes()
        cases = (
            (
                "syntax",
                b"PRIVATE_INNER_SYNTAX =\n",
                b"raise AssertionError('adapter must not execute')\n",
                "PRIVATE_INNER_SYNTAX",
            ),
            (
                "runtime",
                real_outbox,
                b"raise RuntimeError('PRIVATE_INNER_RUNTIME')\n",
                "PRIVATE_INNER_RUNTIME",
            ),
        )
        for label, outbox_source, adapters_source, marker in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp, \
                 mock.patch.dict(sys.modules, {}, clear=False):
                run_file, _scripts = self._write_deployment_layout(
                    temp, outbox_source, adapters_source
                )
                self._without_report_modules()
                with mock.patch.object(MONITOR, "__file__", str(run_file)), \
                     mock.patch.object(MONITOR, "_REPORT_DELIVERY_MODULE_CACHE", None), \
                     mock.patch.object(
                         MONITOR.importlib,
                         "import_module",
                         side_effect=AssertionError("namespace fallback must not run"),
                     ):
                    with self.assertRaises(MONITOR.ReportDeliveryInputError) as caught:
                        MONITOR._load_report_delivery_modules()
                    self.assertEqual(
                        str(caught.exception), "report delivery modules are unavailable"
                    )
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertIsNone(caught.exception.__context__)
                    rendered = f"{caught.exception!s} {caught.exception!r}"
                    self.assertNotIn(marker, rendered)
                    self.assertNotIn(str(run_file), rendered)
                    self.assertIsNone(MONITOR._REPORT_DELIVERY_MODULE_CACHE)
                    for name in self.MODULE_NAMES:
                        self.assertNotIn(name, sys.modules)
                    package = sys.modules.get("scripts")
                    if package is not None:
                        self.assertFalse(hasattr(package, "report_delivery_outbox_v1"))
                        self.assertFalse(hasattr(package, "report_delivery_adapters_v1"))

    def test_failed_load_restores_preexisting_module_attributes_and_path_by_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            run_file, _scripts = self._write_deployment_layout(
                temp,
                b"PRIVATE_BROKEN =\n",
                b"raise AssertionError('must not execute')\n",
            )
            package = ModuleType("scripts")
            old_path = ["/synthetic/original/scripts"]
            old_outbox = ModuleType("scripts.report_delivery_outbox_v1")
            old_adapters = ModuleType("scripts.report_delivery_adapters_v1")
            package.__path__ = old_path
            package.__package__ = "original_scripts"
            package.report_delivery_outbox_v1 = old_outbox
            package.report_delivery_adapters_v1 = old_adapters
            existing = {
                "scripts": package,
                self.MODULE_NAMES[0]: old_outbox,
                self.MODULE_NAMES[1]: old_adapters,
            }
            with mock.patch.dict(sys.modules, existing, clear=False), \
                 mock.patch.object(MONITOR, "__file__", str(run_file)), \
                 mock.patch.object(MONITOR, "_REPORT_DELIVERY_MODULE_CACHE", None):
                with self.assertRaises(MONITOR.ReportDeliveryInputError):
                    MONITOR._load_report_delivery_modules()
                self.assertIs(sys.modules["scripts"], package)
                self.assertIs(sys.modules[self.MODULE_NAMES[0]], old_outbox)
                self.assertIs(sys.modules[self.MODULE_NAMES[1]], old_adapters)
                self.assertIs(package.__path__, old_path)
                self.assertEqual(package.__package__, "original_scripts")
                self.assertIs(package.report_delivery_outbox_v1, old_outbox)
                self.assertIs(package.report_delivery_adapters_v1, old_adapters)
                self.assertIsNone(MONITOR._REPORT_DELIVERY_MODULE_CACHE)


class MainActiveFirstIntegrationTest(unittest.TestCase):
    TODAY = "2026-08-05"

    @staticmethod
    def _healthy_scan():
        return {
            "healthy": True,
            "success_total": MONITOR.REPORT_SCAN_TOP_N,
            "overall_success_ratio": 1.0,
            "flagship_success": min(MONITOR.FLAGSHIP_TOP_N, MONITOR.REPORT_SCAN_TOP_N),
            "flagship_success_ratio": 1.0,
        }

    def _run_main(self, arguments, recovery_result):
        clock = MONITOR.datetime(
            2026, 8, 5, 11, 30, tzinfo=MONITOR.SHANGHAI_TIMEZONE
        )
        dashboard_receipt = {
            "source_date": self.TODAY,
            "source_hash": "a" * 64,
            "html_hash": "b" * 64,
            "manifest_hash": "c" * 64,
        }
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(sys, "argv", ["run.py", "--quick", *arguments]), \
             mock.patch.object(MONITOR, "WORKSPACE", Path(temp)), \
             mock.patch.object(MONITOR, "REPORT_STATE_FILE", Path(temp) / "state.json"), \
             mock.patch.object(
                 MONITOR,
                 "shanghai_run_clock",
                 return_value=(clock, self.TODAY, "2026-08-04", clock),
             ), \
             mock.patch.object(MONITOR, "load_top_sites", return_value=[]), \
             mock.patch.object(MONITOR, "build_flagship_config", return_value=[]), \
             mock.patch.object(
                 MONITOR,
                 "scan_sites_bounded",
                 return_value=([], {"state": "closed"}),
             ), \
             mock.patch.object(
                 MONITOR, "evaluate_scan_health", return_value=self._healthy_scan()
             ), \
             mock.patch.object(MONITOR, "atomic_write_json"), \
             mock.patch.object(MONITOR, "write_run_status") as status_writer, \
             mock.patch.object(MONITOR, "rescore", return_value=[]), \
             mock.patch.object(MONITOR, "load_report_state", return_value=prior_state()), \
             mock.patch.object(
                 MONITOR,
                 "classify_report_changes",
                 return_value={"new": [], "signal": [], "growth": []},
             ), \
             mock.patch.object(
                 MONITOR, "refresh_product_dashboard", return_value=dashboard_receipt
             ) as dashboard, \
             mock.patch.object(
                 MONITOR, "run_report_delivery_v1", return_value=recovery_result
             ) as delivery, \
             mock.patch.object(MONITOR, "create_dingtalk_report_image") as image_renderer, \
             mock.patch.object(MONITOR, "build_report_delivery_record_v1") as record_builder, \
             mock.patch.object(MONITOR, "send_change_notification") as legacy_sender, \
             mock.patch.object(MONITOR, "save_report_state") as legacy_state, \
             mock.patch("builtins.print"):
            exit_code = MONITOR.main()
        return {
            "exit_code": exit_code,
            "dashboard": dashboard,
            "delivery": delivery,
            "image_renderer": image_renderer,
            "record_builder": record_builder,
            "legacy_sender": legacy_sender,
            "legacy_state": legacy_state,
            "status_writer": status_writer,
        }

    def test_old_active_recovers_and_returns_before_current_dashboard_or_new_intent(self):
        outcome = self._run_main(
            ["--send"],
            {
                "exit_code": 0,
                "report": {"state": "succeeded", "projection": {"outbox_id": "old"}},
                "created": False,
                "had_active": True,
            },
        )
        self.assertEqual(outcome["exit_code"], 0)
        outcome["delivery"].assert_called_once_with(
            today=self.TODAY, recover_only=True
        )
        outcome["dashboard"].assert_not_called()
        outcome["image_renderer"].assert_not_called()
        outcome["record_builder"].assert_not_called()
        outcome["legacy_sender"].assert_not_called()
        outcome["legacy_state"].assert_not_called()

    def test_send_empty_with_no_changes_has_no_publish_send_render_or_new_intent(self):
        outcome = self._run_main(
            ["--send", "--send-empty"],
            {
                "exit_code": None,
                "report": {"state": "no_active"},
                "created": False,
                "had_active": False,
            },
        )
        self.assertEqual(outcome["exit_code"], 2)
        outcome["delivery"].assert_called_once_with(
            today=self.TODAY, recover_only=True
        )
        outcome["dashboard"].assert_not_called()
        outcome["image_renderer"].assert_not_called()
        outcome["record_builder"].assert_not_called()
        outcome["legacy_sender"].assert_not_called()
        outcome["legacy_state"].assert_not_called()
        final_status = outcome["status_writer"].call_args.args[1]
        self.assertEqual(final_status["report"]["state"],
                         "unsupported_empty_notification")


class LegacyReportPathDecommissionIntegrationTest(unittest.TestCase):
    def test_legacy_entrypoints_fail_before_git_dingtalk_or_state_side_effects(self):
        state = prior_state()
        original = copy.deepcopy(state)
        groups = {"new": [{"row": report_row(), "rank": 1, "reasons": ["x"]}],
                  "signal": [], "growth": []}
        with mock.patch.object(MONITOR.subprocess, "run") as process, \
             mock.patch.object(MONITOR, "send_dingtalk_payload") as payload_sender, \
             mock.patch.object(MONITOR, "send_dingtalk") as text_sender, \
             mock.patch.object(MONITOR, "send_dingtalk_markdown") as markdown_sender, \
             mock.patch.object(MONITOR, "select_visual_report_items") as selector, \
             mock.patch.object(MONITOR, "atomic_write_json") as state_writer:
            calls = (
                lambda: MONITOR.ensure_repo_git_identity(),
                lambda: MONITOR.publish_report_image(Path("report.png"), "2026-08-05"),
                lambda: MONITOR.create_dingtalk_report_image(
                    groups, "2026-08-05", 1, 1, publish=True
                ),
                lambda: MONITOR.send_change_notification(
                    groups, "2026-08-05", 1, 1, "fallback", ["alpha"], None
                ),
                lambda: MONITOR.save_report_state(
                    state, [report_row()], ["alpha"], "2026-08-05",
                    changed_handles=["alpha"],
                ),
            )
            for call in calls:
                with self.assertRaises(MONITOR.ReportDeliveryInputError):
                    call()
        process.assert_not_called()
        payload_sender.assert_not_called()
        text_sender.assert_not_called()
        markdown_sender.assert_not_called()
        selector.assert_not_called()
        state_writer.assert_not_called()
        self.assertEqual(state, original)

    def test_private_publish_false_renderer_remains_and_legacy_ast_has_no_side_effect_calls(self):
        item = {"row": report_row()}
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(MONITOR, "DINGTALK_REPORT_DIR", Path(temp)), \
             mock.patch.object(MONITOR, "select_visual_report_items", return_value=[item]), \
             mock.patch.object(MONITOR, "ensure_visual_item_images") as image_loader, \
             mock.patch.object(MONITOR, "build_visual_report_html", return_value="<html/>") as html_builder, \
             mock.patch.object(MONITOR, "render_html_to_png") as renderer, \
             mock.patch.object(MONITOR, "publish_report_image") as publisher:
            result = MONITOR.create_dingtalk_report_image(
                {"new": [item], "signal": [], "growth": []},
                "2026-08-05", 1, 1, publish=False,
            )
        self.assertEqual(result["url"], str(result["path"]))
        image_loader.assert_called_once()
        html_builder.assert_called_once()
        renderer.assert_called_once()
        publisher.assert_not_called()

        tree = ast.parse(SOURCE_PATH.read_text(encoding="utf-8"))
        functions = {
            node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
        }
        forbidden_names = {
            "send_dingtalk", "send_dingtalk_markdown", "send_change_notification",
            "save_report_state", "publish_report_image", "ensure_repo_git_identity",
        }
        for name in ("ensure_repo_git_identity", "publish_report_image",
                     "send_change_notification", "save_report_state"):
            called = [
                node.func.id for node in ast.walk(functions[name])
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            ]
            self.assertEqual(called, ["ReportDeliveryInputError"])
        main_called = {
            node.func.id for node in ast.walk(functions["main"])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(main_called.isdisjoint(forbidden_names))


class DriverGithubTransport:
    """Deterministic in-memory GitHub boundary for the real R1/B adapters."""

    base = "a" * 40
    base_tree = "b" * 40
    blob = "c" * 40
    candidate_tree = "d" * 40
    candidate = "e" * 40
    old_blob = "f" * 40

    def __init__(self, image, target_path, *, existing_same=False, patch_loses_ack=False):
        self.image = image
        self.target_path = target_path
        self.existing_same = existing_same
        self.patch_loses_ack = patch_loses_ack
        self.tip = self.base
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        prefix = "/repos/tonyaiuser/babata-board/git"
        if method == "GET" and path == prefix + "/ref/heads/main":
            return {"status": 200, "body": {"object": {"sha": self.tip}}}
        if method == "GET" and path == prefix + "/commits/" + self.base:
            return {
                "status": 200,
                "body": {"tree": {"sha": self.base_tree}, "parents": []},
            }
        if method == "GET" and path == prefix + "/commits/" + self.candidate:
            return {
                "status": 200,
                "body": {
                    "tree": {"sha": self.candidate_tree},
                    "parents": [{"sha": self.base}],
                },
            }
        if method == "GET" and path == prefix + "/trees/" + self.base_tree + "?recursive=1":
            entries = []
            if self.existing_same:
                entries.append({"path": self.target_path, "sha": self.old_blob})
            return {"status": 200, "body": {"tree": entries}}
        if method == "GET" and path == prefix + "/trees/" + self.candidate_tree + "?recursive=1":
            return {
                "status": 200,
                "body": {"tree": [{"path": self.target_path, "sha": self.blob}]},
            }
        if method == "GET" and path in (
            prefix + "/blobs/" + self.old_blob,
            prefix + "/blobs/" + self.blob,
        ):
            return {
                "status": 200,
                "body": {
                    "encoding": "base64",
                    "content": base64.b64encode(self.image).decode("ascii"),
                },
            }
        if method == "POST" and path == prefix + "/blobs":
            return {"status": 201, "body": {"sha": self.blob}}
        if method == "POST" and path == prefix + "/trees":
            return {"status": 201, "body": {"sha": self.candidate_tree}}
        if method == "POST" and path == prefix + "/commits":
            return {"status": 201, "body": {"sha": self.candidate}}
        if method == "PATCH" and path == prefix + "/refs/heads/main":
            if self.patch_loses_ack:
                raise TimeoutError("synthetic PATCH acknowledgement loss")
            self.tip = self.candidate
            return {"status": 200, "body": {}}
        raise AssertionError(f"unexpected GitHub boundary call: {method} {path}")

    def ancestry(self, ancestor, tip):
        self.calls.append(("ANCESTRY", ancestor, tip))
        return ancestor == self.candidate and tip == self.candidate

    @property
    def patch_calls(self):
        return [call for call in self.calls if call[0] == "PATCH"]


class ReportDeliveryDriverIntegrationTest(unittest.TestCase):
    IMAGE = b"synthetic-report-image"

    def _paths(self, temp):
        root = Path(temp)
        return root / "outbox", root / "state.json", root / "report.png"

    def _image_factory(self, image_path, calls):
        def create(groups, today, results_count, changed_count, publish=True):
            calls.append((groups, today, results_count, changed_count, publish))
            image_path.write_bytes(self.IMAGE)
            return {"path": image_path, "items": groups["new"]}

        return create

    def _run(self, *, store_root, state_path, image_factory, github, recover_only=False,
             today="2026-08-05"):
        outbox, adapters = TEST_OUTBOX, TEST_ADAPTERS
        inputs = report_inputs()
        kwargs = {
            "today": today,
            "recover_only": recover_only,
            "store_root": store_root,
            "state_path": state_path,
            "outbox_module": outbox,
            "adapters_module": adapters,
            "github_transport": github,
            "image_factory": image_factory,
        }
        if not recover_only:
            kwargs.update({
                "state": inputs["state"],
                "results": inputs["results"],
                "change_groups": inputs["change_groups"],
                "text_message": inputs["text_message"],
                "text_delivered_handles": inputs["text_delivered_handles"],
                "dashboard_receipt": inputs["dashboard_receipt"],
                "frozen_last_run": inputs["frozen_last_run"],
            })
        return MONITOR.run_report_delivery_v1(**kwargs)

    def test_same_blob_primary_runs_real_outbox_and_adapters_to_both_receipts(self):
        _outbox, adapters = TEST_OUTBOX, TEST_ADAPTERS
        with tempfile.TemporaryDirectory() as temp:
            store_root, state_path, image_path = self._paths(temp)
            state_path.write_bytes(canonical(prior_state()))
            image_calls = []
            github = DriverGithubTransport(
                self.IMAGE,
                "reports/dingtalk/sp_report_2026-08-05.png",
                existing_same=True,
            )
            with mock.patch.object(
                MONITOR, "send_dingtalk_payload", return_value={"errcode": 0}
            ) as sender:
                result = self._run(
                    store_root=store_root,
                    state_path=state_path,
                    image_factory=self._image_factory(image_path, image_calls),
                    github=github,
                )

            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["report"]["state"], "succeeded")
            projection = result["report"]["projection"]
            self.assertEqual(projection["state"], "complete")
            self.assertEqual(projection["channel"], "primary")
            self.assertEqual(projection["publication_outcome"], "published")
            self.assertEqual(projection["delivery_outcome"], "sent")
            self.assertEqual(projection["dedupe_outcome"], "applied")
            self.assertEqual(len(image_calls), 1)
            self.assertIs(image_calls[0][-1], False)
            self.assertEqual(len(github.patch_calls), 0)
            self.assertEqual(sender.call_count, 1)

            state = json.loads(state_path.read_bytes())
            receipt = state["delivery_receipt"]
            self.assertEqual(receipt["outbox_id"], projection["outbox_id"])
            self.assertEqual(receipt["handles"], ["alpha"])
            self.assertFalse((store_root / "active.json").exists())
            receipt_files = list((store_root / "receipts").glob("*.json"))
            self.assertEqual(len(receipt_files), 1)
            private_receipt = json.loads(receipt_files[0].read_bytes())
            self.assertEqual(private_receipt["outbox_id"], projection["outbox_id"])
            self.assertEqual(private_receipt["terminal_action"], "complete")
            self.assertEqual(private_receipt["channel"], "primary")
            self.assertEqual(private_receipt["dedupe_outcome"], "applied")
            adapters.initialize_store(store_root)
            with adapters.open_transaction(store_root) as transaction:
                self.assertIsNone(transaction.load_active())

    def test_cross_day_unknown_active_is_recovered_without_rendering_or_second_intent(self):
        _outbox, adapters = TEST_OUTBOX, TEST_ADAPTERS
        with tempfile.TemporaryDirectory() as temp:
            store_root, state_path, image_path = self._paths(temp)
            state_path.write_bytes(canonical(prior_state()))
            image_calls = []
            github = DriverGithubTransport(
                self.IMAGE,
                "reports/dingtalk/sp_report_2026-08-05.png",
                patch_loses_ack=True,
            )
            factory = self._image_factory(image_path, image_calls)
            with mock.patch.object(MONITOR, "send_dingtalk_payload") as sender:
                first = self._run(
                    store_root=store_root,
                    state_path=state_path,
                    image_factory=factory,
                    github=github,
                )
            self.assertEqual(first["exit_code"], 3)
            self.assertEqual(first["report"]["state"], "blocked")
            self.assertEqual(first["report"]["projection"]["publication_outcome"], "unknown")
            self.assertEqual(first["report"]["projection"]["error_class"], "no_progress")
            self.assertEqual(len(github.patch_calls), 1)
            sender.assert_not_called()

            with adapters.open_transaction(store_root) as transaction:
                before = transaction.load_active()
            self.assertIsNotNone(before)
            before_id = before.record.outbox_id
            before_sha = before.record_sha256
            self.assertEqual(before.record.intent.target.path,
                             "reports/dingtalk/sp_report_2026-08-05.png")

            day_two_factory = mock.Mock(side_effect=AssertionError("must not render day two"))
            with mock.patch.object(MONITOR, "send_dingtalk_payload") as sender:
                second = self._run(
                    store_root=store_root,
                    state_path=state_path,
                    image_factory=day_two_factory,
                    github=github,
                    recover_only=True,
                    today="2026-08-06",
                )
            self.assertEqual(second["exit_code"], 3)
            self.assertTrue(second["had_active"])
            self.assertFalse(second["created"])
            self.assertEqual(second["report"]["state"], "blocked")
            self.assertEqual(second["report"]["projection"]["error_class"], "no_progress")
            day_two_factory.assert_not_called()
            sender.assert_not_called()
            self.assertEqual(len(image_calls), 1)
            self.assertEqual(len(github.patch_calls), 1)

            with adapters.open_transaction(store_root) as transaction:
                after = transaction.load_active()
            self.assertIsNotNone(after)
            self.assertEqual(after.record.outbox_id, before_id)
            self.assertEqual(after.record_sha256, before_sha)
            self.assertEqual(after.record.intent.target.path,
                             "reports/dingtalk/sp_report_2026-08-05.png")
            self.assertEqual(list((store_root / "receipts").glob("*.json")), [])
            self.assertEqual(state_path.read_bytes(), canonical(prior_state()))


if __name__ == "__main__":
    unittest.main()
