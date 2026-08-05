import importlib.util
import io
import fcntl
import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from datetime import datetime
from zoneinfo import ZoneInfo
from contextlib import redirect_stderr


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


FETCH_IMAGES = load_module("fb_fetch_images", SCRIPTS / "fetch_new_images.py")
BUILD_PAGE = load_module("fb_build_page", SCRIPTS / "build_fb_verify_page.py")
STATE_IO = load_module("fb_state_io", SCRIPTS / "state_io.py")
PIPELINE_STATUS = load_module("fb_pipeline_status", SCRIPTS / "pipeline_status.py")
LOCKED_EXEC = load_module("fb_locked_exec", SCRIPTS / "locked_exec.py")
VERIFY_SCHEMA = load_module("fb_verification_schema", SCRIPTS / "verification_schema.py")
SUMMARY_VALIDATOR = load_module(
    "fb_summary_validator", SCRIPTS / "validate_pipeline_summary.py"
)
DRAIN_LEGACY = load_module(
    "fb_drain_legacy", SCRIPTS / "wait_for_legacy_entrypoints.py"
)


def tree_digest(root):
    digest = hashlib.sha256()
    root = Path(root)
    if not root.exists():
        return digest.hexdigest()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def wait_for_path(path, process, timeout=10):
    deadline = time.monotonic() + timeout
    path = Path(path)
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"process exited before {path} appeared: rc={process.returncode}\n"
                f"stdout={stdout}\nstderr={stderr}"
            )
        time.sleep(0.02)
    process.terminate()
    stdout, stderr = process.communicate(timeout=5)
    raise AssertionError(
        f"timed out waiting for {path}\nstdout={stdout}\nstderr={stderr}"
    )


def wait_for_pid_gone(pid, timeout=5):
    """Wait for a real process to disappear without process-list inspection."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    raise AssertionError(f"process {pid} remained alive past the deadline")


class CrossMonthIngestTest(unittest.TestCase):
    def test_preserves_current_groups_and_reuses_verified_query(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            previous_dir = root / "2026-07"
            previous_dir.mkdir()
            previous_unique = previous_dir / "unique_products.json"
            previous_verify = previous_dir / "product_verify_full.json"
            current_unique = root / "current_unique.json"
            events = root / "events.jsonl"

            previous_unique.write_text(json.dumps({
                "groups": [{
                    "group_id": "G0042",
                    "query": "Rolling Low Stool with Backrest",
                    "members": [{"domain": "old.example", "handle": "rolling-stool"}],
                }],
            }), encoding="utf-8")
            previous_verify.write_text(json.dumps({
                "groups": {"G0042": {
                    "query": "Rolling Low Stool with Backrest",
                    "harvested": 3,
                    "relevant_ads_count": 3,
                    "relevant_ads": [],
                }},
            }), encoding="utf-8")
            current_unique.write_text(json.dumps({
                "groups": [{
                    "group_id": "G0001",
                    "query": "Rolling Low Stool with Backrest",
                    "members": [{"domain": "old.example", "handle": "rolling-stool"}],
                }],
            }), encoding="utf-8")
            rows = [
                {
                    "type": "single_page_first_detected",
                    "run_at": "2026-08-01T09:00:00+08:00",
                    "month": "2026-08",
                    "domain": "old.example",
                    "handle": "rolling-stool",
                    "url": "https://old.example/products/rolling-stool",
                    "title": "Rolling Low Stool with Backrest",
                },
                {
                    "type": "single_page_first_detected",
                    "run_at": "2026-08-01T09:01:00+08:00",
                    "month": "2026-08",
                    "domain": "new.example",
                    "handle": "rolling-stool-new",
                    "url": "https://new.example/products/rolling-stool-new",
                    "title": "Rolling Low Stool with Backrest",
                },
            ]
            events.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "ingest_new_hits.py"),
                    "--monitor-events-jsonl", str(events),
                    "--unique-json", str(current_unique),
                    "--month", "2026-08",
                    "--date", "2026-08-01",
                    "--previous-unique-json", str(previous_unique),
                    "--previous-full-verify-json", str(previous_verify),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            data = json.loads(current_unique.read_text(encoding="utf-8"))
            self.assertEqual(data["month"], "2026-08")
            self.assertEqual(len(data["groups"]), 2)
            self.assertEqual(data["groups"][0]["members"][0]["domain"], "old.example")
            group = data["groups"][1]
            self.assertEqual(group["members"][0]["domain"], "new.example")
            self.assertTrue(group["already_verified"])
            self.assertEqual(group["reused_from"], "previous_month:G0042")
            self.assertIn("pruned_previous_groups=0", completed.stdout)
            self.assertIn("skipped_previous_member=1", completed.stdout)
            self.assertIn("reused_previous_query=1", completed.stdout)

    def test_migrates_unresolved_groups_and_retry_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            previous_dir = root / "2026-07"
            previous_dir.mkdir()
            previous_unique = previous_dir / "unique_products.json"
            previous_verify = previous_dir / "product_verify_full.json"
            current_unique = root / "current_unique.json"
            current_verify = root / "current_verify.json"
            events = root / "events.jsonl"
            previous_unique.write_text(json.dumps({"month": "2026-07", "groups": [{
                "group_id": "G0042", "query": "Unresolved Widget", "members": [{
                    "domain": "old.example", "handle": "widget", "title": "Unresolved Widget"
                }], "already_verified": False,
            }]}), encoding="utf-8")
            previous_verify.write_text(json.dumps({"groups": {}, "retry_errors": {"G0042": {
                "group_id": "G0042", "attempts": 3, "error": "HTTP 403"
            }}}), encoding="utf-8")
            current_unique.write_text(json.dumps({"groups": []}), encoding="utf-8")
            events.write_text("", encoding="utf-8")
            subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(current_unique),
                "--full-verify-json", str(current_verify), "--month", "2026-08",
                "--previous-unique-json", str(previous_unique),
                "--previous-full-verify-json", str(previous_verify),
            ], check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(current_unique.read_text(encoding="utf-8"))["groups"][0]["group_id"], "G0042")
            retry = json.loads(current_verify.read_text(encoding="utf-8"))["retry_errors"]["G0042"]
            self.assertEqual(retry["attempts"], 3)
            self.assertEqual(retry["migrated_from"], "previous_month")

    def test_gid_collision_remaps_group_retry_and_inconclusive_evidence_without_loss(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            previous_dir = root / "2026-07"
            previous_dir.mkdir()
            previous_unique = previous_dir / "unique_products.json"
            previous_verify = previous_dir / "product_verify_full.json"
            current_unique = root / "current_unique.json"
            current_verify = root / "current_verify.json"
            events = root / "events.jsonl"
            previous_unique.write_text(json.dumps({"month": "2026-07", "groups": [{
                "group_id": "G0001", "query": "Previous Widget", "members": [{
                    "domain": "previous.example", "handle": "previous-widget"
                }]
            }]}))
            previous_verify.write_text(json.dumps({
                "groups": {"G0001": {
                    "group_id": "G0001", "http_status": 403, "total_reported": 0,
                    "harvested": 0, "relevant_ads_count": 0,
                    "error": "rate limited diagnostic",
                }},
                "retry_errors": {"G0001": {"group_id": "G0001", "attempts": 4}},
            }))
            current_unique.write_text(json.dumps({"groups": [{
                "group_id": "G0001", "query": "Current Different Widget", "members": [{
                    "domain": "current.example", "handle": "current-widget"
                }]
            }]}))
            current_verify.write_text(json.dumps({"groups": {}}))
            events.write_text("")

            subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(current_unique),
                "--full-verify-json", str(current_verify), "--month", "2026-08",
                "--previous-unique-json", str(previous_unique),
                "--previous-full-verify-json", str(previous_verify),
            ], check=True, capture_output=True, text=True)

            unique_data = json.loads(current_unique.read_text())
            verify_data = json.loads(current_verify.read_text())
            groups = {group["group_id"]: group for group in unique_data["groups"]}
            self.assertEqual(set(groups), {"G0001", "G0002"})
            self.assertEqual(groups["G0001"]["members"][0]["domain"], "current.example")
            self.assertEqual(groups["G0002"]["members"][0]["domain"], "previous.example")
            self.assertEqual(groups["G0002"]["original_group_id"], "G0001")
            self.assertEqual(verify_data["groups"]["G0002"]["verification_state"], "inconclusive")
            self.assertEqual(verify_data["groups"]["G0002"]["evidence_group_id"], "G0001")
            self.assertEqual(verify_data["groups"]["G0002"]["error"], "rate limited diagnostic")
            self.assertEqual(verify_data["retry_errors"]["G0002"]["attempts"], 4)
            self.assertEqual(verify_data["retry_errors"]["G0002"]["original_group_id"], "G0001")

    def test_unknown_current_checkpoint_schema_fails_without_rewriting_either_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify, events = root / "unique.json", root / "verify.json", root / "events.jsonl"
            unique_bytes = b'{"groups": []}'
            verify_bytes = b'{"schema_version":99,"producer":"unknown","groups":{}}'
            unique.write_bytes(unique_bytes)
            verify.write_bytes(verify_bytes)
            events.write_text("")
            completed = subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(unique),
                "--full-verify-json", str(verify), "--month", "2026-08",
            ], capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("invalid verification schema", completed.stderr)
            self.assertEqual(unique.read_bytes(), unique_bytes)
            self.assertEqual(verify.read_bytes(), verify_bytes)

    def test_ingest_rejects_invalid_or_mismatched_month_without_rewriting_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, events = root / "unique.json", root / "events.jsonl"
            original = b'{"month":"2026-07","groups":[]}'
            unique.write_bytes(original)
            events.write_text("", encoding="utf-8")
            mismatch = subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(unique),
                "--month", "2026-08",
            ], capture_output=True, text=True)
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("disagrees", mismatch.stderr)
            self.assertEqual(unique.read_bytes(), original)

            invalid = subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(unique),
                "--month", "2026-13",
            ], capture_output=True, text=True)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("valid calendar month", invalid.stderr)
            self.assertEqual(unique.read_bytes(), original)

    def test_previous_unique_verify_and_nested_evidence_are_month_bound(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            july, june = root / "2026-07", root / "2026-06"
            july.mkdir()
            june.mkdir()
            previous_unique = july / "unique_products.json"
            previous_unique.write_text(json.dumps({
                "month": "2026-07",
                "groups": [{
                    "group_id": "G0001", "query": "Same GID",
                    "state_month": "2026-07", "members": [],
                }],
            }), encoding="utf-8")
            june_verify = june / "product_verify_full.json"
            june_verify.write_text(json.dumps({
                "month": "2026-06", "groups": {"G0001": {
                    "state_month": "2026-06", "response_http_status": 200,
                    "fb_total_reported": 0, "harvested": 0, "relevant_ads_count": 0,
                }},
            }), encoding="utf-8")
            current, events = root / "current.json", root / "events.jsonl"
            original = b'{"groups":[]}'
            current.write_bytes(original)
            events.write_text("", encoding="utf-8")

            wrong_file = subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(current),
                "--month", "2026-08", "--previous-unique-json", str(previous_unique),
                "--previous-full-verify-json", str(june_verify),
            ], capture_output=True, text=True)
            self.assertNotEqual(wrong_file.returncode, 0)
            self.assertIn("expected 2026-07 monthly directory", wrong_file.stderr)
            self.assertEqual(current.read_bytes(), original)

            july_verify = july / "product_verify_full.json"
            for container_name in ("groups", "checkpoint_archive"):
                payload = {
                    "month": "2026-07", "groups": {}, "checkpoint_archive": {},
                }
                payload[container_name]["G0001"] = {
                    "state_month": "2026-06", "response_http_status": 200,
                    "fb_total_reported": 0, "harvested": 0, "relevant_ads_count": 0,
                }
                july_verify.write_text(json.dumps(payload), encoding="utf-8")
                nested = subprocess.run([
                    sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                    "--monitor-events-jsonl", str(events), "--unique-json", str(current),
                    "--month", "2026-08", "--previous-unique-json", str(previous_unique),
                    "--previous-full-verify-json", str(july_verify),
                ], capture_output=True, text=True)
                self.assertNotEqual(nested.returncode, 0)
                self.assertIn("belongs to 2026-06", nested.stderr)
                self.assertEqual(current.read_bytes(), original)


class ImageAndDashboardTest(unittest.TestCase):
    @staticmethod
    def run_dashboard_builder(unique, verify, images, output, *extra, view_kind="monthly"):
        return subprocess.run([
            sys.executable, str(SCRIPTS / "build_fb_verify_page.py"),
            "--unique-json", str(unique), "--full-verify-json", str(verify),
            "--images-json", str(images), "--out", str(output),
            "--view-kind", view_kind, *extra,
        ], capture_output=True, text=True)

    @staticmethod
    def write_monthly_dashboard_inputs(directory, groups, checkpoint_groups, *, month="2026-08"):
        directory.mkdir(parents=True, exist_ok=True)
        unique, verify, images = (
            directory / "unique_products.json",
            directory / "product_verify_full.json",
            directory / "product_images.json",
        )
        bound_groups = [{**group, "state_month": month} for group in groups]
        bound_checkpoints = {
            gid: {**record, "state_month": month} for gid, record in checkpoint_groups.items()
        }
        unique.write_text(json.dumps({"month": month, "groups": bound_groups}), encoding="utf-8")
        verify.write_text(json.dumps({"month": month, "groups": bound_checkpoints}), encoding="utf-8")
        images.write_text("{}", encoding="utf-8")
        return unique, verify, images

    def test_monthly_dashboard_rejects_empty_or_regressed_inputs_without_replacing_page(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [
                {"group_id": gid, "query": gid, "members": []}
                for gid in ("G0001", "G0002")
            ]
            zero = {
                "response_http_status": 200, "fb_total_reported": 0,
                "harvested": 0, "relevant_ads_count": 0,
            }
            unique, verify, images = self.write_monthly_dashboard_inputs(
                month_dir, groups, {"G0001": zero}
            )
            bound_groups = [{**group, "state_month": "2026-08"} for group in groups]
            bound_zero = {**zero, "state_month": "2026-08"}
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            healthy_bytes = output.read_bytes()
            self.assertIn(b"FB_VERIFY_DASHBOARD_GUARD", healthy_bytes)

            unique.write_text(json.dumps({"month": "2026-08", "groups": []}), encoding="utf-8")
            verify.write_text(json.dumps({"month": "2026-08", "groups": {}}), encoding="utf-8")
            empty = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(empty.returncode, 0)
            self.assertIn("empty monthly input", empty.stderr)
            self.assertEqual(output.read_bytes(), healthy_bytes)

            unique.write_text(json.dumps({"month": "2026-08", "groups": bound_groups[:1]}), encoding="utf-8")
            verify.write_text(json.dumps({
                "month": "2026-08", "groups": {"G0001": bound_zero},
            }), encoding="utf-8")
            group_regression = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(group_regression.returncode, 0)
            self.assertIn("durable group state regressed", group_regression.stderr)
            self.assertEqual(output.read_bytes(), healthy_bytes)

            unique.write_text(json.dumps({"month": "2026-08", "groups": bound_groups}), encoding="utf-8")
            verify.write_text(json.dumps({"month": "2026-08", "groups": {}}), encoding="utf-8")
            checkpoint_regression = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(checkpoint_regression.returncode, 0)
            self.assertIn("active checkpoint immutable evidence changed", checkpoint_regression.stderr)
            self.assertEqual(output.read_bytes(), healthy_bytes)

    def test_empty_month_bootstrap_fails_closed_and_does_not_create_dashboard(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-09"
            unique, verify, images = self.write_monthly_dashboard_inputs(month_dir, [], {}, month="2026-09")
            output = month_dir / "fb_verify_dashboard.html"
            completed = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("empty monthly bootstrap", completed.stderr)
            self.assertFalse(output.exists())

    def test_month_path_mismatch_fails_and_batch_view_skips_monthly_guard(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            input_dir, wrong_month_dir = root / "2026-08", root / "2026-07"
            batch_dir = input_dir / "batches"
            groups = [{"group_id": "G0001", "query": "One", "members": []}]
            unique, verify, images = self.write_monthly_dashboard_inputs(input_dir, groups, {})
            wrong_month_dir.mkdir()
            wrong_output = wrong_month_dir / "fb_verify_dashboard.html"
            mismatch = self.run_dashboard_builder(unique, verify, images, wrong_output)
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("monthly dashboard output", mismatch.stderr)
            self.assertFalse(wrong_output.exists())

            batch_dir.mkdir()
            batch_output = batch_dir / "current.html"
            batch_output.write_text("unrecognized old batch", encoding="utf-8")
            batch = self.run_dashboard_builder(
                unique, verify, images, batch_output, "--group-ids", "G0001",
                view_kind="batch",
            )
            self.assertEqual(batch.returncode, 0, batch.stderr)
            rendered = batch_output.read_text(encoding="utf-8")
            self.assertTrue(rendered.startswith("<!DOCTYPE html>"))
            self.assertNotIn("FB_VERIFY_DASHBOARD_GUARD", rendered)

    def test_batch_kind_cannot_overwrite_canonical_monthly_output(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [{"group_id": "G0001", "query": "One", "members": []}]
            unique, verify, images = self.write_monthly_dashboard_inputs(month_dir, groups, {})
            output = month_dir / "fb_verify_dashboard.html"
            monthly = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(monthly.returncode, 0, monthly.stderr)
            original = output.read_bytes()
            attack = self.run_dashboard_builder(
                unique, verify, images, output, "--group-ids", "G0001", view_kind="batch"
            )
            self.assertNotEqual(attack.returncode, 0)
            self.assertIn("batch output", attack.stderr)
            self.assertEqual(output.read_bytes(), original)

    def test_batch_group_ids_are_exact_and_summary_is_a_complete_resolution_contract(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [
                {"group_id": "G0001", "query": "One", "members": []},
                {"group_id": "G0002", "query": "Two", "members": []},
            ]
            unique, verify, images = self.write_monthly_dashboard_inputs(month_dir, groups, {})
            output = month_dir / "batches" / "current.html"
            output.parent.mkdir()
            original = b"existing batch output\n"
            output.write_bytes(original)
            for group_ids, expected in (
                ("G9999", "unknown or unavailable"),
                ("G0001,G9999", "unknown or unavailable"),
                ("G0001,G0001", "duplicate"),
                ("G0001,,G0002", "empty"),
                (" ,G0001", "empty"),
            ):
                with self.subTest(group_ids=group_ids):
                    rejected = self.run_dashboard_builder(
                        unique, verify, images, output, "--group-ids", group_ids,
                        view_kind="batch",
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(expected, rejected.stderr)
                    self.assertEqual(output.read_bytes(), original)

            completed = self.run_dashboard_builder(
                unique, verify, images, output, "--group-ids", " G0002 , G0001 ",
                view_kind="batch",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = SUMMARY_VALIDATOR.extract_and_validate(
                "build", completed.stdout,
                build_view_kind="batch", expected_group_ids=["G0002", "G0001"],
            )
            self.assertEqual(summary["requested"], ["G0002", "G0001"])
            self.assertEqual(summary["resolved"], ["G0002", "G0001"])
            self.assertEqual(summary["missing"], [])
            for invalid in (
                {"total_groups": 1, "found": 1, "unverified": 0,
                 "requested": ["G0001"], "resolved": ["G9999"], "missing": []},
                {"total_groups": 1, "found": 1, "unverified": 0,
                 "requested": ["G0001"], "resolved": ["G0001"], "missing": ["G9999"]},
                {"total_groups": 1, "found": 1, "unverified": 0, "requested": ["G0001"]},
            ):
                with self.subTest(summary=invalid):
                    with self.assertRaisesRegex(ValueError, "batch|missing required"):
                        SUMMARY_VALIDATOR.extract_and_validate(
                            "build", "BUILD_SUMMARY_JSON " + json.dumps(invalid),
                            build_view_kind="batch", expected_group_ids=["G0001"],
                        )

    def test_legacy_decoys_multiple_records_and_forged_guard_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [{"group_id": "G0001", "query": "One", "members": []}]
            unique, verify, images = self.write_monthly_dashboard_inputs(month_dir, groups, {})
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            legacy = output.read_text(encoding="utf-8").split("\n", 1)[1]
            minimal_tokens = (
                '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>'
                '<title>单页产品 × FB 投放验证</title></head>\n<body>\n'
                '<div class="generated-at">生成时间：</div>\n<script>\n'
                'const RECORDS = [{"group_id":"G0001"}];\n'
                'const SORT_DEFAULT_DIRECTIONS = {};\n</script>\n</body>\n</html>\n'
            )
            variants = (
                legacy.replace("<script>\n", "<!--\nconst RECORDS = [];\n-->\n<script>\n", 1),
                legacy.replace(
                    "const SORT_DEFAULT_DIRECTIONS = ",
                    "const RECORDS = [];\nconst SORT_DEFAULT_DIRECTIONS = ", 1,
                ),
                legacy.replace(
                    '<div class="generated-at">生成时间：</div>',
                    '<div class="generated-at">生成时间：'
                    '<img src=x onerror=alert(1)></div>',
                    1,
                ),
                "<!-- forged wrapper -->\n" + legacy,
                minimal_tokens,
            )
            for forged in variants:
                with self.subTest(prefix=forged[:40]):
                    output.write_text(forged, encoding="utf-8")
                    before = output.read_bytes()
                    completed = self.run_dashboard_builder(unique, verify, images, output)
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("refusing to overwrite", completed.stderr)
                    self.assertEqual(output.read_bytes(), before)

    def test_calendar_month_and_all_input_parent_bindings_are_strict(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            invalid_dir = root / "2026-13"
            groups = [{"group_id": "G0001", "query": "One", "members": []}]
            unique, verify, images = self.write_monthly_dashboard_inputs(
                invalid_dir, groups, {}, month="2026-13"
            )
            invalid_out = invalid_dir / "fb_verify_dashboard.html"
            invalid = self.run_dashboard_builder(unique, verify, images, invalid_out)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("calendar month", invalid.stderr)
            self.assertFalse(invalid_out.exists())

            good_dir, other_dir = root / "2026-08", root / "2026-07"
            unique, verify, images = self.write_monthly_dashboard_inputs(good_dir, groups, {})
            other_dir.mkdir()
            other_verify = other_dir / "product_verify_full.json"
            other_verify.write_text('{"groups":{}}', encoding="utf-8")
            output = good_dir / "fb_verify_dashboard.html"
            crossed = self.run_dashboard_builder(unique, other_verify, images, output)
            self.assertNotEqual(crossed.returncode, 0)
            self.assertIn("must share", crossed.stderr)
            self.assertFalse(output.exists())

    def test_auditable_alias_merge_conserves_evidence_and_normal_append_is_safe(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [
                {
                    "group_id": "G0001", "query": "Same Widget",
                    "members": [{
                        "domain": "one.example", "handle": "one", "title": "One",
                        "url": "https://one.example/products/one",
                    }],
                },
                {
                    "group_id": "G0002", "query": "same widget",
                    "members": [{
                        "domain": "two.example", "handle": "two", "title": "Two",
                        "url": "https://two.example/products/two",
                    }],
                },
            ]
            zero = {
                "response_http_status": 200, "fb_total_reported": 0,
                "harvested": 0, "relevant_ads_count": 0,
            }
            unique, verify, images = self.write_monthly_dashboard_inputs(
                month_dir, groups, {"G0001": zero, "G0002": zero}
            )
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)

            merged = subprocess.run([
                sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
                "--unique-json", str(unique), "--full-verify-json", str(verify),
            ], capture_output=True, text=True)
            self.assertEqual(merged.returncode, 0, merged.stderr)
            converged = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(converged.returncode, 0, converged.stderr)
            stable_second_round = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(stable_second_round.returncode, 0, stable_second_round.stderr)

            state = json.loads(unique.read_text(encoding="utf-8"))
            hostile = "</script><script>alert(1)</script>"
            state["groups"].append({
                "group_id": "G0003", "query": hostile,
                "state_month": "2026-08",
                "members": [{
                    "domain": "three.example", "handle": "three", "title": hostile,
                    "url": "https://three.example/products/three",
                }],
            })
            unique.write_text(json.dumps(state), encoding="utf-8")
            appended = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(appended.returncode, 0, appended.stderr)
            rendered = output.read_text(encoding="utf-8")
            self.assertNotIn("</script><script>alert(1)", rendered)
            self.assertIn("\\u003c/script>\\u003cscript>alert(1)\\u003c/script>", rendered)

            healthy = output.read_bytes()
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))
            checkpoint["checkpoint_archive"]["G0002"]["error"] = "tampered archive"
            verify.write_text(json.dumps(checkpoint), encoding="utf-8")
            tampered = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("archived checkpoint evidence changed", tampered.stderr)
            self.assertEqual(output.read_bytes(), healthy)

    def test_alias_merge_allows_only_exact_merged_from_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [
                {"group_id": "G0001", "query": "Same", "members": [{
                    "domain": "one.example", "handle": "one",
                    "url": "https://one.example/products/one", "title": "One",
                }]},
                {"group_id": "G0002", "query": "same", "members": [{
                    "domain": "two.example", "handle": "two",
                    "url": "https://two.example/products/two", "title": "Two",
                }]},
            ]
            zero = {
                "response_http_status": 200, "fb_total_reported": 0,
                "harvested": 0, "relevant_ads_count": 0,
            }
            unique, verify, images = self.write_monthly_dashboard_inputs(
                month_dir, groups, {"G0001": zero, "G0002": zero}
            )
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            baseline = output.read_bytes()

            merged = subprocess.run([
                sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
                "--unique-json", str(unique), "--full-verify-json", str(verify),
            ], capture_output=True, text=True)
            self.assertEqual(merged.returncode, 0, merged.stderr)
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))
            self.assertEqual(checkpoint["groups"]["G0001"]["merged_from"], ["G0002"])
            checkpoint["groups"]["G0001"]["error"] = "field smuggled during merge"
            verify.write_text(json.dumps(checkpoint), encoding="utf-8")

            rejected = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("immutable evidence changed", rejected.stderr)
            self.assertEqual(output.read_bytes(), baseline)

    def test_group_alias_target_rejects_missing_or_forged_merge_provenance(self):
        mutations = (
            ("missing canonical", ["G0002"]),
            ("missing source", ["G0001"]),
            ("forged source", ["G0001", "G0002", "G9999"]),
        )
        for label, merged_from in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                month_dir = Path(td) / "2026-08"
                groups = [
                    {"group_id": "G0001", "query": "Same", "members": [{
                        "domain": "one.example", "handle": "one",
                        "url": "https://one.example/products/one", "title": "One",
                    }]},
                    {"group_id": "G0002", "query": "same", "members": [{
                        "domain": "two.example", "handle": "two",
                        "url": "https://two.example/products/two", "title": "Two",
                    }]},
                ]
                zero = {
                    "response_http_status": 200, "fb_total_reported": 0,
                    "harvested": 0, "relevant_ads_count": 0,
                }
                unique, verify, images = self.write_monthly_dashboard_inputs(
                    month_dir, groups, {"G0001": zero, "G0002": zero}
                )
                output = month_dir / "fb_verify_dashboard.html"
                initial = self.run_dashboard_builder(unique, verify, images, output)
                self.assertEqual(initial.returncode, 0, initial.stderr)
                baseline = output.read_bytes()

                merged = subprocess.run([
                    sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
                    "--unique-json", str(unique), "--full-verify-json", str(verify),
                ], capture_output=True, text=True)
                self.assertEqual(merged.returncode, 0, merged.stderr)
                unique_state = json.loads(unique.read_text(encoding="utf-8"))
                canonical = next(
                    group for group in unique_state["groups"]
                    if group["group_id"] == "G0001"
                )
                self.assertEqual(canonical["merged_from"], ["G0001", "G0002"])
                canonical["merged_from"] = merged_from
                unique.write_text(json.dumps(unique_state), encoding="utf-8")

                rejected = self.run_dashboard_builder(unique, verify, images, output)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("group merge provenance", rejected.stderr)
                self.assertEqual(output.read_bytes(), baseline)

    def test_schema3_guard_requires_unchanged_full_digest_before_safe_upgrade(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [
                {"group_id": "G0001", "query": "Same", "members": []},
                {"group_id": "G0002", "query": "same", "members": []},
            ]
            zero = {
                "response_http_status": 200, "fb_total_reported": 0,
                "harvested": 0, "relevant_ads_count": 0,
            }
            unique, verify, images = self.write_monthly_dashboard_inputs(
                month_dir, groups, {"G0001": zero, "G0002": zero}
            )
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            first_line, page_body = output.read_text(encoding="utf-8").split("\n", 1)
            encoded = first_line[len(BUILD_PAGE.DASHBOARD_GUARD_PREFIX):-len(
                BUILD_PAGE.DASHBOARD_GUARD_SUFFIX
            )]
            legacy_guard = json.loads(encoded)
            legacy_guard["schema_version"] = BUILD_PAGE.LEGACY_DASHBOARD_GUARD_SCHEMA_VERSION
            legacy_guard.pop("checkpoint_immutable_evidence_sha256")
            legacy_guard.pop("checkpoint_merged_from")
            legacy_page = (
                BUILD_PAGE.DASHBOARD_GUARD_PREFIX
                + BUILD_PAGE.json_for_html_comment(legacy_guard)
                + BUILD_PAGE.DASHBOARD_GUARD_SUFFIX + "\n" + page_body
            )
            output.write_text(legacy_page, encoding="utf-8")

            safe_upgrade = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(safe_upgrade.returncode, 0, safe_upgrade.stderr)
            upgraded_guard = json.loads(
                output.read_text(encoding="utf-8").split("\n", 1)[0][
                    len(BUILD_PAGE.DASHBOARD_GUARD_PREFIX):-len(
                        BUILD_PAGE.DASHBOARD_GUARD_SUFFIX
                    )
                ]
            )
            self.assertEqual(
                upgraded_guard["schema_version"], BUILD_PAGE.DASHBOARD_GUARD_SCHEMA_VERSION
            )

            output.write_text(legacy_page, encoding="utf-8")
            merged = subprocess.run([
                sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
                "--unique-json", str(unique), "--full-verify-json", str(verify),
            ], capture_output=True, text=True)
            self.assertEqual(merged.returncode, 0, merged.stderr)
            before = output.read_bytes()
            unsafe_guess = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(unsafe_guess.returncode, 0)
            self.assertIn("safe baseline/migration required", unsafe_guess.stderr)
            self.assertEqual(output.read_bytes(), before)

    def test_forged_alias_without_quarantine_and_checkpoint_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [
                {"group_id": "G0001", "query": "One", "members": []},
                {"group_id": "G0002", "query": "Two", "members": []},
            ]
            zero = {
                "response_http_status": 200, "fb_total_reported": 0,
                "harvested": 0, "relevant_ads_count": 0,
            }
            unique, verify, images = self.write_monthly_dashboard_inputs(
                month_dir, groups, {"G0002": zero}
            )
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            healthy = output.read_bytes()

            forged = json.loads(unique.read_text(encoding="utf-8"))
            forged["groups"][1].update({
                "quarantined": True, "quarantine_reason": "duplicate_merged_into",
                "merged_into": "G0001",
            })
            forged["groups"][0]["merged_from"] = ["G0001", "G0002"]
            forged["group_aliases"] = {
                "G0002": {"canonical_group_id": "G0001", "reason": "duplicate_merged_into"}
            }
            unique.write_text(json.dumps(forged), encoding="utf-8")
            rejected = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("terminal negative verification regressed", rejected.stderr)
            self.assertEqual(output.read_bytes(), healthy)

    def test_checkpoint_semantics_reject_regressions_and_allow_updates_or_upgrades(self):
        positive = {
            "response_http_status": 200, "fb_total_reported": 1,
            "harvested": 1, "sample": [{"ad_archive_id": "ad-1"}],
            "relevant_ads_count": 1,
            "relevant_ads": [{"ad_archive_id": "ad-1", "link_url": "https://shop.example/p"}],
        }
        explicit_zero = {
            "response_http_status": 200, "fb_total_reported": 0,
            "harvested": 0, "relevant_ads_count": 0,
        }
        sample_negative = {
            "response_http_status": 200, "fb_total_reported": 1,
            "harvested": 1, "sample": [{"ad_archive_id": "sample-1"}],
            "relevant_ads_count": 0, "relevant_ads": [],
        }
        inconclusive = {
            "response_http_status": 403, "fb_total_reported": 0,
            "harvested": 0, "relevant_ads_count": 0, "error": "rate limited",
        }

        def scenario(initial_record, updates, expected_success):
            with tempfile.TemporaryDirectory() as td:
                month_dir = Path(td) / "2026-08"
                group = {"group_id": "G0001", "query": "One", "members": []}
                unique, verify, images = self.write_monthly_dashboard_inputs(
                    month_dir, [group], {"G0001": initial_record}
                )
                output = month_dir / "fb_verify_dashboard.html"
                initial = self.run_dashboard_builder(unique, verify, images, output)
                self.assertEqual(initial.returncode, 0, initial.stderr)
                for record, should_succeed in zip(updates, expected_success):
                    before = output.read_bytes()
                    verify.write_text(json.dumps({
                        "month": "2026-08",
                        "groups": {"G0001": {**record, "state_month": "2026-08"}},
                    }), encoding="utf-8")
                    completed = self.run_dashboard_builder(unique, verify, images, output)
                    if should_succeed:
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        self.assertNotEqual(output.read_bytes(), before)
                    else:
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertEqual(output.read_bytes(), before)
                return completed

        positive_to_zero = scenario(positive, [explicit_zero], [False])
        self.assertIn("active checkpoint immutable evidence changed", positive_to_zero.stderr)

        positive_without_relevant = {
            **positive, "relevant_ads": [], "error": "evidence accidentally dropped",
        }
        positive_loss = scenario(positive, [positive_without_relevant], [False])
        self.assertIn("lacks durable relevant_ads evidence", positive_loss.stderr)

        negative_to_inconclusive = scenario(sample_negative, [inconclusive], [False])
        self.assertIn("active checkpoint immutable evidence changed", negative_to_inconclusive.stderr)

        updated_inconclusive = {**inconclusive, "error": "second diagnostic", "attempt": 2}
        scenario(inconclusive, [updated_inconclusive, positive], [True, True])
        scenario(explicit_zero, [positive], [False])

    def test_active_checkpoint_digest_cannot_be_replaced_by_other_legal_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            group = {"group_id": "G0001", "query": "One", "members": []}
            explicit_zero = {
                "response_http_status": 200, "fb_total_reported": 0,
                "harvested": 0, "relevant_ads_count": 0,
            }
            unique, verify, images = self.write_monthly_dashboard_inputs(
                month_dir, [group], {"G0001": explicit_zero}
            )
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            healthy = output.read_bytes()

            sample_negative = {
                "response_http_status": 200, "fb_total_reported": 1,
                "harvested": 1, "sample": [{"ad_archive_id": "sample-1"}],
                "relevant_ads_count": 0, "relevant_ads": [],
            }
            verify.write_text(json.dumps({
                "month": "2026-08", "groups": {
                    "G0001": {**sample_negative, "state_month": "2026-08"},
                },
            }), encoding="utf-8")
            replaced = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(replaced.returncode, 0)
            self.assertIn("active checkpoint immutable evidence changed", replaced.stderr)
            self.assertEqual(output.read_bytes(), healthy)

    def test_same_canonical_group_cannot_drop_historical_members(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            members = [
                {
                    "domain": f"{name}.example", "handle": name,
                    "url": f"https://{name}.example/products/{name}", "title": name,
                }
                for name in ("one", "two")
            ]
            group = {"group_id": "G0001", "query": "One", "members": members}
            unique, verify, images = self.write_monthly_dashboard_inputs(month_dir, [group], {})
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            healthy = output.read_bytes()

            shrunk = {
                "month": "2026-08",
                "groups": [{**group, "state_month": "2026-08", "members": members[:1]}],
            }
            unique.write_text(json.dumps(shrunk), encoding="utf-8")
            rejected = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("group members regressed", rejected.stderr)
            self.assertEqual(output.read_bytes(), healthy)

    def test_legacy_monthly_page_upgrades_only_when_current_groups_cover_it(self):
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            groups = [{"group_id": "G0001", "query": "One", "members": []}]
            unique, verify, images = self.write_monthly_dashboard_inputs(month_dir, groups, {})
            output = month_dir / "fb_verify_dashboard.html"
            first = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(first.returncode, 0, first.stderr)
            guarded = output.read_text(encoding="utf-8")
            # Releases before the guard contain the exact same complete page,
            # just without the first durable guard line.
            output.write_text(guarded.split("\n", 1)[1], encoding="utf-8")
            completed = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("FB_VERIFY_DASHBOARD_GUARD", output.read_text(encoding="utf-8"))

    def test_legacy_first_guard_write_preserves_positive_evidence_and_members(self):
        """A complete pre-guard page is a baseline, not an untrusted bootstrap."""
        with tempfile.TemporaryDirectory() as td:
            month_dir = Path(td) / "2026-08"
            members = [
                {
                    "domain": f"{name}.example", "handle": name,
                    "url": f"https://{name}.example/products/{name}", "title": name,
                }
                for name in ("one", "two")
            ]
            group = {
                "group_id": "G0001", "query": "One", "members": members,
            }
            positive = {
                "response_http_status": 200, "fb_total_reported": 1,
                "harvested": 1, "sample": [{"ad_archive_id": "ad-1"}],
                "relevant_ads_count": 1,
                "relevant_ads": [{
                    "ad_archive_id": "ad-1", "link_url": "https://one.example/products/one",
                }],
            }
            unique, verify, images = self.write_monthly_dashboard_inputs(
                month_dir, [group], {"G0001": positive}
            )
            output = month_dir / "fb_verify_dashboard.html"
            initial = self.run_dashboard_builder(unique, verify, images, output)
            self.assertEqual(initial.returncode, 0, initial.stderr)

            # Releases before schema v3 emitted this exact complete artifact
            # without the first guard line. Exercise that real migration path.
            legacy_page = output.read_text(encoding="utf-8").split("\n", 1)[1]
            output.write_text(legacy_page, encoding="utf-8")
            legacy_bytes = output.read_bytes()

            explicit_zero = {
                "response_http_status": 200, "fb_total_reported": 0,
                "harvested": 0, "relevant_ads_count": 0,
            }
            verify.write_text(json.dumps({
                "month": "2026-08", "groups": {
                    "G0001": {**explicit_zero, "state_month": "2026-08"},
                },
            }), encoding="utf-8")
            zeroed = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(zeroed.returncode, 0)
            self.assertIn("positive verification evidence regressed", zeroed.stderr)
            self.assertEqual(output.read_bytes(), legacy_bytes)

            replacement_positive = {
                **positive,
                "sample": [{"ad_archive_id": "ad-2"}],
                "relevant_ads": [{
                    "ad_archive_id": "ad-2", "link_url": "https://one.example/products/one",
                }],
            }
            verify.write_text(json.dumps({
                "month": "2026-08", "groups": {
                    "G0001": {**replacement_positive, "state_month": "2026-08"},
                },
            }), encoding="utf-8")
            evidence_lost = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(evidence_lost.returncode, 0)
            self.assertIn("lost evidence archive:ad-1", evidence_lost.stderr)
            self.assertEqual(output.read_bytes(), legacy_bytes)

            unique.write_text(json.dumps({
                "month": "2026-08", "groups": [{
                    **group, "state_month": "2026-08", "members": members[:1],
                }],
            }), encoding="utf-8")
            members_lost = self.run_dashboard_builder(unique, verify, images, output)
            self.assertNotEqual(members_lost.returncode, 0)
            self.assertIn("legacy group members regressed", members_lost.stderr)
            self.assertEqual(output.read_bytes(), legacy_bytes)

    def test_pre_four_state_negative_inference_requires_a_numeric_fb_response(self):
        records = [
            {
                "group_id": "G0001", "members": [], "found": False,
                "verify_error": None, "fb_total": None,
            },
            {
                "group_id": "G0002", "members": [], "found": False,
                "verify_error": None, "fb_total": 2,
            },
        ]
        _, semantics = BUILD_PAGE._legacy_record_contract(records)
        self.assertEqual(semantics["G0001"]["state"], "unverified")
        self.assertEqual(semantics["G0002"]["state"], "terminal_negative_unknown")

        previous = {"checkpoint_semantics": semantics}
        current = {
            "active_group_ids": ["G0001", "G0002"],
            "group_aliases": {},
            "checkpoint_semantics": {
                "G0001": {
                    "state": "missing", "positive_relevant_floor": 0,
                    "positive_evidence_ids": [],
                },
                "G0002": {
                    "state": "inconclusive", "positive_relevant_floor": 0,
                    "positive_evidence_ids": [],
                },
            },
        }
        with self.assertRaisesRegex(SystemExit, "legacy terminal negative"):
            BUILD_PAGE.assert_checkpoint_semantics_monotonic(previous, current)
        current["checkpoint_semantics"]["G0002"]["state"] = "sample_negative"
        BUILD_PAGE.assert_checkpoint_semantics_monotonic(previous, current)

    def test_normalizes_http_images(self):
        self.assertEqual(
            FETCH_IMAGES.normalize_image_url("http://shop.example/cdn/product.jpg"),
            "https://shop.example/cdn/product.jpg",
        )
        self.assertIsNone(BUILD_PAGE.normalize_image_url("data:text/html,bad"))
        self.assertIsNone(BUILD_PAGE.normalize_image_url("javascript:alert(1)"))
        self.assertEqual(
            FETCH_IMAGES.normalize_image_url("//cdn.example/product.jpg"),
            "https://cdn.example/product.jpg",
        )

    def test_previous_month_cache_hydrates_1000_without_network_sleep_or_per_item_writes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, images, previous = root / "unique.json", root / "images.json", root / "previous.json"
            members = [
                {"domain": f"shop-{index}.example", "handle": f"product-{index}"}
                for index in range(1000)
            ]
            unique.write_text(json.dumps({"groups": [{"group_id": "G0001", "members": members}]}))
            images.write_text("{}", encoding="utf-8")
            previous.write_text(json.dumps({
                f"shop-{index}.example|product-{index}": f"https://cdn.example/{index}.jpg"
                for index in range(1000)
            }))
            with mock.patch.object(FETCH_IMAGES, "save_images") as save, \
                 mock.patch.object(FETCH_IMAGES.urllib.request, "urlopen") as urlopen, \
                 mock.patch.object(FETCH_IMAGES.time, "sleep") as sleep, \
                 mock.patch.object(sys, "argv", [
                     "fetch_new_images.py", "--unique-json", str(unique),
                     "--images-json", str(images), "--previous-images-json", str(previous),
                     "--heartbeat-seconds", "0.05",
                 ]):
                FETCH_IMAGES.main()
            self.assertEqual(save.call_count, 1)
            self.assertFalse(urlopen.called)
            self.assertFalse(sleep.called)
            hydrated = save.call_args.args[0]
            self.assertEqual(len(hydrated), 1000)
            self.assertEqual(hydrated["shop-999.example|product-999"], "https://cdn.example/999.jpg")

    def test_product_timeout_records_retryable_none_and_continues_to_next_product(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, images = root / "unique.json", root / "images.json"
            unique.write_text(json.dumps({"groups": [{"group_id": "G0001", "members": [
                {"domain": "stuck.example", "handle": "stuck"},
                {"domain": "healthy.example", "handle": "healthy"},
            ]}]}))
            images.write_text("{}", encoding="utf-8")

            def resolve(domain, *_args):
                if domain == "stuck.example":
                    time.sleep(2)
                return "https://cdn.example/healthy.jpg", "shopify-json"

            stderr = io.StringIO()
            with mock.patch.object(FETCH_IMAGES, "resolve_network_image", side_effect=resolve), \
                 mock.patch.object(sys, "argv", [
                     "fetch_new_images.py", "--unique-json", str(unique),
                     "--images-json", str(images), "--product-timeout-seconds", "1",
                     "--heartbeat-seconds", "0.02",
                 ]), redirect_stderr(stderr):
                FETCH_IMAGES.main()
            payload = json.loads(images.read_text())
            self.assertIsNone(payload["stuck.example|stuck"])
            self.assertEqual(payload["healthy.example|healthy"], "https://cdn.example/healthy.jpg")
            self.assertIn("product timeout stuck.example|stuck", stderr.getvalue())
            self.assertIn("heartbeat:", stderr.getvalue())

    def test_transport_retry_does_not_swallow_product_timeout(self):
        def blocked_urlopen(*_args, **_kwargs):
            time.sleep(1)

        with mock.patch.object(FETCH_IMAGES.urllib.request, "urlopen", side_effect=blocked_urlopen):
            with self.assertRaises(FETCH_IMAGES.ProductTimeout):
                with FETCH_IMAGES.product_timeout(1):
                    FETCH_IMAGES.fetch_url("https://stuck.example/products/item.js")

    def test_watchdog_relays_stderr_heartbeat_before_child_exits(self):
        with tempfile.TemporaryDirectory() as td:
            child = Path(td) / "child.py"
            child.write_text(
                "import sys, time\n"
                "print('child heartbeat', file=sys.stderr, flush=True)\n"
                "time.sleep(1.2)\n",
                encoding="utf-8",
            )
            started = time.monotonic()
            process = subprocess.Popen(
                [sys.executable, str(SCRIPTS / "run_with_watchdog.py"),
                 "--timeout-seconds", "2", "--", sys.executable, str(child)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                self.assertEqual(process.stderr.readline().strip(), "child heartbeat")
                self.assertLess(time.monotonic() - started, 0.5)
                self.assertIsNone(process.poll())
                self.assertEqual(process.wait(timeout=3), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()

    def test_invalid_watchdog_and_product_timeouts_fail_before_command_network_or_cache_write(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "command-started"
            command = [
                sys.executable, "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()", str(marker),
            ]
            for flag, value in (
                ("--timeout-seconds", "nan"),
                ("--timeout-seconds", "inf"),
                ("--timeout-seconds", "1e309"),
                ("--timeout-seconds", "0.001"),
                ("--timeout-seconds", "3601"),
                ("--grace-seconds", "nan"),
                ("--grace-seconds", "61"),
                ("--grace-seconds", "-0.1"),
            ):
                with self.subTest(flag=flag, value=value):
                    args = [
                        sys.executable, str(SCRIPTS / "run_with_watchdog.py"),
                        "--timeout-seconds", "2", "--grace-seconds", "1",
                    ]
                    option_index = args.index(flag) if flag in args else None
                    if option_index is None:
                        args.extend([flag, value])
                    else:
                        args[option_index + 1] = value
                    completed = subprocess.run(
                        [*args, "--", *command], capture_output=True, text=True,
                    )
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertIn("must be finite and in", completed.stderr)
                    self.assertFalse(marker.exists())

            unique, images = root / "unique.json", root / "images.json"
            unique.write_text(json.dumps({"groups": [{"group_id": "G1", "members": [
                {"domain": "must-not-fetch.example", "handle": "item"},
            ]}]}), encoding="utf-8")
            original = b'{"keep":"https://cdn.example/keep.jpg"}\n'
            images.write_bytes(original)
            for value in ("nan", "inf", "1e309", "0.5", "301"):
                with self.subTest(product_timeout=value), \
                     mock.patch.object(FETCH_IMAGES.urllib.request, "urlopen") as urlopen, \
                     mock.patch.object(sys, "argv", [
                         "fetch_new_images.py", "--unique-json", str(unique),
                         "--images-json", str(images), "--product-timeout-seconds", value,
                     ]), self.assertRaises(SystemExit) as raised, \
                     redirect_stderr(io.StringIO()):
                    FETCH_IMAGES.main()
                self.assertEqual(raised.exception.code, 2)
                self.assertFalse(urlopen.called)
                self.assertEqual(images.read_bytes(), original)

    def test_watchdog_sigterm_terminates_entire_child_group_without_orphans(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ready = root / "group.json"
            helper = root / "group_helper.py"
            helper.write_text(
                "import json, os, pathlib, signal, subprocess, sys, time\n"
                "grandchild = subprocess.Popen([sys.executable, '-c', "
                "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'])\n"
                "pathlib.Path(sys.argv[1]).write_text(json.dumps({"
                "'pgid': os.getpgrp(), 'child': os.getpid(), 'grandchild': grandchild.pid}))\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [sys.executable, str(SCRIPTS / "run_with_watchdog.py"),
                 "--timeout-seconds", "10", "--grace-seconds", "0.1", "--",
                 sys.executable, str(helper), str(ready)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            wait_for_path(ready, process)
            group = json.loads(ready.read_text())
            os.kill(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 128 + signal.SIGTERM, stdout + stderr)
            self.assertIn("received signal", stderr)
            self.assertIn("child process group only", stderr)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.killpg(group["pgid"], 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail(f"watchdog left child process group alive: {group}")

    def test_watchdog_timeout_124_terminates_entire_child_group_without_orphans(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ready = root / "group.json"
            helper = root / "group_helper.py"
            helper.write_text(
                "import json, os, pathlib, signal, subprocess, sys, time\n"
                "grandchild = subprocess.Popen([sys.executable, '-c', "
                "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'])\n"
                "pathlib.Path(sys.argv[1]).write_text(json.dumps({"
                "'pgid': os.getpgrp(), 'child': os.getpid(), 'grandchild': grandchild.pid}))\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "run_with_watchdog.py"),
                 "--timeout-seconds", "0.2", "--grace-seconds", "0.1", "--",
                 sys.executable, str(helper), str(ready)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(completed.returncode, 124, completed.stdout + completed.stderr)
            self.assertIn("terminating image child process group only", completed.stderr)
            group = json.loads(ready.read_text())
            with self.assertRaises(ProcessLookupError):
                os.killpg(group["pgid"], 0)

    def test_watchdog_recorded_signal_wins_over_simultaneous_natural_exit(self):
        class NaturalExitRace:
            pid = 987654

            def __init__(self):
                self.stdout = io.BytesIO()
                self.stderr = io.BytesIO()
                self.returncode = None
                self.poll_calls = 0
                self.wait_calls = 0

            def poll(self):
                self.poll_calls += 1
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                self.returncode = 0
                return 0

            def wait(self, *_args, **_kwargs):
                self.wait_calls += 1
                return self.returncode

        fake = NaturalExitRace()
        with mock.patch.object(subprocess, "Popen", return_value=fake):
            watchdog = load_module("fb_watchdog_signal_race", SCRIPTS / "run_with_watchdog.py")
            rc = watchdog.main([
                "--timeout-seconds", "2", "--grace-seconds", "1", "--",
                sys.executable, "never-started.py",
            ])
        self.assertEqual(rc, 128 + signal.SIGTERM)
        self.assertEqual(fake.poll_calls, 1)
        self.assertEqual(fake.wait_calls, 0)

    def test_group_cleanup_keeps_leader_unreaped_until_final_group_signal(self):
        watchdog = load_module("fb_watchdog_group_identity", SCRIPTS / "run_with_watchdog.py")

        class ExitedLeader:
            pid = 543210

            def __init__(self):
                self.poll_calls = 0
                self.wait_calls = 0

            def poll(self):
                self.poll_calls += 1
                return 0

            def wait(self, *_args, **_kwargs):
                self.wait_calls += 1
                return 0

        fake = ExitedLeader()
        signals = []

        def record_group_signal(pgid, signum):
            signals.append((pgid, signum, fake.poll_calls, fake.wait_calls))

        with mock.patch.object(watchdog.os, "killpg", side_effect=record_group_signal), \
             mock.patch.object(watchdog, "process_group_has_live_members", return_value=True), \
             mock.patch.object(watchdog.time, "monotonic", side_effect=[10.0, 10.2]):
            watchdog.terminate_process_group(fake, 0.1)
        self.assertEqual([row[1] for row in signals], [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(all(row[2:] == (0, 0) for row in signals))
        self.assertEqual(fake.poll_calls, 0)
        self.assertEqual(fake.wait_calls, 1)

    def test_group_cleanup_observes_grandchild_exit_near_grace_without_kill(self):
        watchdog = load_module("fb_watchdog_near_grace", SCRIPTS / "run_with_watchdog.py")

        class ExitedLeader:
            pid = 543211
            poll_calls = 0
            wait_calls = 0

            def poll(self):
                self.poll_calls += 1
                return 0

            def wait(self, *_args, **_kwargs):
                self.wait_calls += 1
                return 0

        fake = ExitedLeader()
        signals = []
        with mock.patch.object(
            watchdog.os, "killpg", side_effect=lambda pgid, sig: signals.append((pgid, sig))
        ), mock.patch.object(
            watchdog, "process_group_has_live_members", side_effect=[True, True, False]
        ), mock.patch.object(
            watchdog.time, "monotonic", side_effect=[10.0, 10.04, 10.09]
        ), mock.patch.object(watchdog.time, "sleep"):
            watchdog.terminate_process_group(fake, 0.1)
        self.assertEqual(signals, [(fake.pid, signal.SIGTERM)])
        self.assertEqual(fake.poll_calls, 0)
        self.assertEqual(fake.wait_calls, 1)

    def test_process_group_probe_is_fail_closed_except_observed_zombie_only_target(self):
        watchdog = load_module("fb_watchdog_probe_contract", SCRIPTS / "run_with_watchdog.py")
        pgid = 543212
        cases = (
            ("empty", 0, "", None, True),
            ("malformed", 0, f"{pgid}\n", None, True),
            ("malformed-pgid", 0, "not-a-pgid S\n", None, True),
            ("unrelated", 0, "999999 Ss+\n", None, True),
            ("target-zombie", 0, f"{pgid} Z+\n{pgid} Zs\n", None, False),
            ("target-live", 0, f"{pgid} Ss+\n", None, True),
            ("nonzero", 1, f"{pgid} Z\n", None, True),
            ("exception", 0, "", OSError("ps unavailable"), True),
        )
        for name, returncode, stdout, error, expected in cases:
            with self.subTest(name=name):
                if error is not None:
                    patcher = mock.patch.object(watchdog.subprocess, "run", side_effect=error)
                else:
                    result = subprocess.CompletedProcess(["ps"], returncode, stdout, "")
                    patcher = mock.patch.object(watchdog.subprocess, "run", return_value=result)
                with patcher:
                    self.assertEqual(
                        watchdog.process_group_has_live_members(pgid), expected
                    )

        with mock.patch.object(watchdog.os, "killpg", side_effect=PermissionError):
            self.assertTrue(watchdog.process_group_exists(pgid))

    def test_dashboard_labels_first_page_sample_and_https_image(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique = root / "unique.json"
            verify = root / "verify.json"
            images = root / "images.json"
            unique.write_text(json.dumps({
                "total_groups": 1,
                "groups": [{
                    "group_id": "G0001",
                    "query": "Electric Aquarium Gravel Cleaner",
                    "members": [{
                        "domain": "shop.example",
                        "handle": "cleaner",
                        "url": "https://shop.example/products/cleaner",
                        "title": "Electric Aquarium Gravel Cleaner",
                    }],
                }],
            }), encoding="utf-8")
            verify.write_text(json.dumps({
                "groups": {"G0001": {
                    "query": "Electric Aquarium Gravel Cleaner",
                    "harvested": 30,
                    "fb_total_reported": None,
                    "relevant_ads_count": 29,
                    "relevant_ads": [],
                }},
            }), encoding="utf-8")
            images.write_text(json.dumps({
                "shop.example|cleaner": "http://shop.example/cdn/cleaner.jpg",
            }), encoding="utf-8")
            BUILD_PAGE.UNIQUE_JSON = str(unique)
            BUILD_PAGE.FULL_VERIFY_JSON = str(verify)
            BUILD_PAGE.PRODUCT_IMAGES_JSON = str(images)
            records, meta = BUILD_PAGE.build_records()
            self.assertEqual(records[0]["image_url"], "https://shop.example/cdn/cleaner.jpg")
            self.assertEqual(records[0]["relevant_label"], "29+")
            self.assertTrue(records[0]["sample_limited"])

    def test_dashboard_inline_json_escapes_script_breakout_and_line_separators(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify, images, output = (root / name for name in ("unique.json", "verify.json", "images.json", "page.html"))
            hostile = "bad </script><img src=x onerror=alert(1)>\u2028\u2029"
            unique.write_text(json.dumps({"total_groups": 1, "groups": [{
                "group_id": "G0001", "query": hostile, "members": [{
                    "domain": "shop.example", "handle": "hostile", "url": "https://shop.example/p", "title": hostile
                }]
            }]}), encoding="utf-8")
            verify.write_text(json.dumps({
                "generated_at": hostile,
                "groups": {"G0001": {
                    "response_http_status": 200, "fb_total_reported": 1, "harvested": 1,
                    "relevant_ads_count": 1, "verification_state": "positive",
                    "max_run_days": hostile,
                    "formats": {hostile: hostile},
                    "relevant_ads": [{
                        "body": hostile, "start_date": hostile,
                        "display_format": hostile,
                    }],
                }},
            }), encoding="utf-8")
            images.write_text("{}", encoding="utf-8")
            BUILD_PAGE.UNIQUE_JSON, BUILD_PAGE.FULL_VERIFY_JSON = str(unique), str(verify)
            BUILD_PAGE.PRODUCT_IMAGES_JSON, BUILD_PAGE.OUTPUT_HTML = str(images), str(output)
            records, meta = BUILD_PAGE.build_records()
            self.assertIsNone(records[0]["max_run_days"])
            self.assertIsNone(records[0]["ad_samples"][0]["start_date"])
            output.write_text(BUILD_PAGE.render_html(records, meta, "test", "test"), encoding="utf-8")
            rendered = output.read_text(encoding="utf-8")
            self.assertNotIn("</script><img", rendered)
            self.assertIn("\\u003c/script>\\u003cimg", rendered)
            self.assertIn("生成时间：bad &lt;/script&gt;&lt;img", rendered)
            self.assertIn("\\u2028", rendered)
            self.assertIn("\\u2029", rendered)
            source = (SCRIPTS / "build_fb_verify_page.py").read_text(encoding="utf-8")
            self.assertIn("function safeHttpUrl", source)
            self.assertIn("function metricText", source)
            self.assertIn("${{metricText(r.max_run_days)}}", source)
            self.assertNotRegex(source, r"\sonerror\s*=")
            self.assertNotRegex(source, r"\sonclick\s*=")

    def test_to_int_handles_numeric_strings_and_invalid_values(self):
        self.assertEqual(BUILD_PAGE.to_int("42"), 42)
        self.assertEqual(BUILD_PAGE.to_int(3.0), 3)
        self.assertIsNone(BUILD_PAGE.to_int("not-a-number"))

    def test_dashboard_uses_verified_four_state_semantics_and_numeric_strings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify, images = root / "unique.json", root / "verify.json", root / "images.json"
            unique.write_text(json.dumps({"groups": [
                {"group_id": "G0001", "query": "Sample negative", "members": [{"domain": "one.example", "handle": "one", "url": "https://one.example/p", "title": "One"}]},
                {"group_id": "G0002", "query": "Explicit zero", "members": [{"domain": "two.example", "handle": "two", "url": "https://two.example/p", "title": "Two"}]},
                {"group_id": "G0003", "query": "Inconclusive", "members": [{"domain": "three.example", "handle": "three", "url": "https://three.example/p", "title": "Three"}]},
            ]}))
            verify.write_text(json.dumps({"groups": {
                "G0001": {"verification_state": "sample_negative", "harvested": "1", "relevant_ads_count": "0", "relevant_ads": [{}]},
                "G0002": {"verification_state": "explicit_zero", "response_http_status": "200", "fb_total_reported": "0", "harvested": "0", "relevant_ads_count": "0"},
                "G0003": {"verification_state": "inconclusive", "response_http_status": "403", "fb_total_reported": "0", "harvested": "0", "relevant_ads_count": "0"},
            }}))
            images.write_text("{}")
            BUILD_PAGE.UNIQUE_JSON, BUILD_PAGE.FULL_VERIFY_JSON = str(unique), str(verify)
            BUILD_PAGE.PRODUCT_IMAGES_JSON = str(images)
            records, meta = BUILD_PAGE.build_records()
            by_gid = {record["group_id"]: record for record in records}
            self.assertFalse(by_gid["G0001"]["found"])
            self.assertFalse(by_gid["G0002"]["found"])
            self.assertFalse(by_gid["G0003"]["found"])
            self.assertIsInstance(by_gid["G0001"]["harvested"], int)
            self.assertIn("尚未完成验证", by_gid["G0003"]["verify_error"])
            self.assertEqual(meta["unverified_count"], 1)


class QuarantineMergeTest(unittest.TestCase):
    def run_merge(self, unique, verify):
        return subprocess.run([
            sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
            "--unique-json", str(unique), "--full-verify-json", str(verify),
        ], capture_output=True, text=True)

    def test_disjoint_member_merge_conserves_active_member_keys(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = root / "unique.json", root / "verify.json"
            first_member = {
                "domain": "first.example", "handle": "first",
                "title": "Fixture One", "provenance": {"event_id": "evt-1"},
            }
            second_member = {
                "domain": "second.example", "handle": "second",
                "title": "Fixture Two", "provenance": {"event_id": "evt-2"},
            }
            original_groups = [
                {
                    "group_id": "G0001", "query": "Fixture Query",
                    "members": [first_member],
                },
                {
                    "group_id": "G0002", "query": " fixture   query ",
                    "members": [second_member],
                    "provenance": {"source_run": "fixture-run-2"},
                },
            ]
            expected_keys = {
                (member["domain"], member["handle"])
                for group in original_groups for member in group["members"]
            }
            unique.write_text(json.dumps({"groups": original_groups}), encoding="utf-8")
            verify.write_text(json.dumps({"groups": {}}), encoding="utf-8")

            completed = self.run_merge(unique, verify)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            state = json.loads(unique.read_text(encoding="utf-8"))
            by_gid = {group["group_id"]: group for group in state["groups"]}
            active = [group for group in state["groups"] if not group.get("quarantined")]
            active_keys = {
                (member["domain"], member["handle"])
                for group in active for member in group["members"]
            }
            self.assertEqual(active_keys, expected_keys)
            self.assertEqual(len(by_gid["G0001"]["members"]), 2)
            self.assertEqual(by_gid["G0001"]["merged_from"], ["G0001", "G0002"])
            self.assertTrue(by_gid["G0002"]["quarantined"])
            self.assertEqual(by_gid["G0002"]["members"], [second_member])
            self.assertEqual(
                by_gid["G0002"]["provenance"], {"source_run": "fixture-run-2"}
            )
            self.assertEqual(
                state["group_aliases"]["G0002"]["canonical_group_id"], "G0001"
            )

    def test_identical_payload_overlap_deduplicates_with_complete_quarantine_audit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = root / "unique.json", root / "verify.json"
            shared_first = {
                "domain": "shared.example", "handle": "shared",
                "title": "Shared Fixture", "url": "https://shared.example/products/shared",
                "provenance": {"event_ids": ["evt-shared"], "source": "fixture"},
            }
            # Same JSON payload with deliberately different object-key order.
            shared_second = {
                "provenance": {"source": "fixture", "event_ids": ["evt-shared"]},
                "url": "https://shared.example/products/shared", "title": "Shared Fixture",
                "handle": "shared", "domain": "shared.example",
            }
            distinct = {
                "domain": "distinct.example", "handle": "distinct",
                "title": "Distinct Fixture", "provenance": {"event_ids": ["evt-distinct"]},
            }
            original_dropped_members = [shared_second, distinct]
            groups = [
                {
                    "group_id": "G0002", "query": "same fixture",
                    "members": original_dropped_members,
                    "provenance": {"source_run": "fixture-run-2"},
                },
                {
                    "group_id": "G0001", "query": "Same Fixture",
                    "members": [shared_first],
                },
            ]
            expected_keys = {
                (member["domain"], member["handle"])
                for group in groups for member in group["members"]
            }
            zero = {
                "response_http_status": 200, "fb_total_reported": 0,
                "harvested": 0, "relevant_ads_count": 0,
            }
            unique.write_text(json.dumps({"groups": groups}), encoding="utf-8")
            verify.write_text(json.dumps({"groups": {
                "G0001": {"group_id": "G0001", **zero},
                "G0002": {"group_id": "G0002", **zero},
            }}), encoding="utf-8")

            completed = self.run_merge(unique, verify)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            state = json.loads(unique.read_text(encoding="utf-8"))
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))
            by_gid = {group["group_id"]: group for group in state["groups"]}
            active = [group for group in state["groups"] if not group.get("quarantined")]
            active_keys = {
                (member["domain"], member["handle"])
                for group in active for member in group["members"]
            }
            self.assertEqual(active_keys, expected_keys)
            self.assertEqual(len(by_gid["G0001"]["members"]), 2)
            self.assertEqual(
                [(member["domain"], member["handle"]) for member in by_gid["G0001"]["members"]],
                [("shared.example", "shared"), ("distinct.example", "distinct")],
            )
            self.assertEqual(by_gid["G0001"]["merged_from"], ["G0001", "G0002"])
            self.assertEqual(by_gid["G0002"]["members"], original_dropped_members)
            self.assertEqual(
                by_gid["G0002"]["provenance"], {"source_run": "fixture-run-2"}
            )
            self.assertTrue(by_gid["G0002"]["quarantined"])
            self.assertEqual(by_gid["G0002"]["merged_into"], "G0001")
            self.assertEqual(set(checkpoint["checkpoint_archive"]), {"G0001", "G0002"})
            self.assertTrue(checkpoint["groups"]["G0002"]["quarantined"])
            self.assertEqual(checkpoint["groups"]["G0001"]["merged_from"], ["G0002"])
            BUILD_PAGE.validate_alias_contract(state, checkpoint)

    def test_conflicting_duplicate_payload_fails_atomically_without_byte_changes(self):
        mutations = (
            ("field", {"title": "Conflicting Fixture"}),
            ("provenance", {"provenance": {"event_id": "evt-conflict"}}),
        )
        for label, mutation in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                unique, verify = root / "unique.json", root / "verify.json"
                first = {
                    "domain": "same.example", "handle": "same", "title": "Fixture",
                    "provenance": {"event_id": "evt-original"},
                }
                second = dict(first)
                second.update(mutation)
                original_unique = json.dumps({"groups": [
                    {"group_id": "G0001", "query": "Same", "members": [first]},
                    {"group_id": "G0002", "query": "same", "members": [second]},
                ]}, separators=(",", ":")).encode("utf-8")
                original_verify = b'{\n  "groups": {}\n}\n'
                unique.write_bytes(original_unique)
                verify.write_bytes(original_verify)

                completed = self.run_merge(unique, verify)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("conflicting duplicate member payload", completed.stderr)
                self.assertIn("refusing to overwrite", completed.stderr)
                self.assertEqual(unique.read_bytes(), original_unique)
                self.assertEqual(verify.read_bytes(), original_verify)
                self.assertFalse(list(root.glob(".fbverify-transaction-*.json")))

    def test_duplicate_merge_is_byte_idempotent_on_repeated_run(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = root / "unique.json", root / "verify.json"
            shared = {
                "domain": "same.example", "handle": "same", "title": "Fixture",
                "provenance": {"event_id": "evt-same"},
            }
            unique.write_text(json.dumps({"groups": [
                {"group_id": "G0002", "query": "same", "members": [shared]},
                {"group_id": "G0001", "query": "Same", "members": [shared]},
            ]}), encoding="utf-8")
            verify.write_text(json.dumps({"groups": {}}), encoding="utf-8")

            first = self.run_merge(unique, verify)
            self.assertEqual(first.returncode, 0, first.stderr)
            after_first = (unique.read_bytes(), verify.read_bytes())
            second = self.run_merge(unique, verify)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("发现 0 个查询词对应多组", second.stdout)
            self.assertEqual((unique.read_bytes(), verify.read_bytes()), after_first)

    def test_three_group_merge_is_byte_deterministic_across_hash_seeds(self):
        frozen_runner = """
import importlib.util
import sys

script, unique, verify = sys.argv[1:]
spec = importlib.util.spec_from_file_location("merge_hashseed_test", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.utc_now = lambda: "2026-08-04T12:00:00+00:00"
sys.argv = [script, "--unique-json", unique, "--full-verify-json", verify]
module.main()
"""
        groups = [
            {
                "group_id": "G0003", "query": "same fixture",
                "members": [{
                    "domain": "third.example", "handle": "third",
                    "provenance": {"event_id": "evt-3"},
                }],
            },
            {
                "group_id": "G0001", "query": "Same Fixture",
                "members": [{
                    "domain": "first.example", "handle": "first",
                    "provenance": {"event_id": "evt-1"},
                }],
            },
            {
                "group_id": "G0002", "query": " same   fixture ",
                "members": [{
                    "domain": "second.example", "handle": "second",
                    "provenance": {"event_id": "evt-2"},
                }],
            },
        ]
        zero = {
            "response_http_status": 200, "fb_total_reported": 0,
            "harvested": 0, "relevant_ads_count": 0,
        }
        initial_unique = json.dumps({"groups": groups}, separators=(",", ":")).encode()
        initial_verify = json.dumps({"groups": {
            gid: {"group_id": gid, **zero} for gid in ("G0001", "G0002", "G0003")
        }}, separators=(",", ":")).encode()
        outputs = []
        output_hashes = []
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for seed in range(1, 9):
                run_root = root / f"seed-{seed}"
                run_root.mkdir()
                unique, verify = run_root / "unique.json", run_root / "verify.json"
                unique.write_bytes(initial_unique)
                verify.write_bytes(initial_verify)
                env = dict(
                    os.environ,
                    PYTHONHASHSEED=str(seed),
                    PYTHONDONTWRITEBYTECODE="1",
                )
                completed = subprocess.run([
                    sys.executable, "-c", frozen_runner,
                    str(SCRIPTS / "merge_duplicate_query_groups.py"),
                    str(unique), str(verify),
                ], capture_output=True, text=True, env=env)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                output = (unique.read_bytes(), verify.read_bytes())
                outputs.append(output)
                output_hashes.append(hashlib.sha256(
                    output[0] + b"\0" + output[1]
                ).hexdigest())

                state = json.loads(output[0])
                checkpoint = json.loads(output[1])
                self.assertEqual(
                    list(state["quarantined_groups"]), ["G0002", "G0003"]
                )
                self.assertEqual(list(state["group_aliases"]), ["G0002", "G0003"])
                self.assertEqual(
                    list(checkpoint["checkpoint_aliases"]), ["G0002", "G0003"]
                )
                by_gid = {group["group_id"]: group for group in state["groups"]}
                self.assertEqual(
                    by_gid["G0001"]["merged_from"], ["G0001", "G0002", "G0003"]
                )
                for gid in ("G0002", "G0003"):
                    original = next(group for group in groups if group["group_id"] == gid)
                    self.assertEqual(by_gid[gid]["members"], original["members"])
                    self.assertTrue(by_gid[gid]["quarantined"])
                    self.assertEqual(by_gid[gid]["merged_into"], "G0001")
                BUILD_PAGE.validate_alias_contract(state, checkpoint)

        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(len(set(output_hashes)), 1)

    def test_duplicate_merge_keeps_an_auditable_single_alias_chain_and_best_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = root / "unique.json", root / "verify.json"
            unique.write_text(json.dumps({"groups": [
                {"group_id": "G0001", "query": "Same Widget", "members": [{"domain": "a.example", "handle": "a"}]},
                {"group_id": "G0002", "query": "same widget", "members": [{"domain": "b.example", "handle": "b"}]},
            ]}), encoding="utf-8")
            verify.write_text(json.dumps({"groups": {
                "G0001": {"group_id": "G0001", "verification_state": "inconclusive", "relevant_ads_count": 0},
                "G0002": {"group_id": "G0002", "verification_state": "sample_negative", "harvested": 1},
            }, "retry_errors": {"G0002": {"attempts": 2}}}), encoding="utf-8")
            subprocess.run([
                sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
                "--unique-json", str(unique), "--full-verify-json", str(verify),
            ], check=True, capture_output=True, text=True)
            groups = {g["group_id"]: g for g in json.loads(unique.read_text(encoding="utf-8"))["groups"]}
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))
            self.assertTrue(groups["G0002"]["quarantined"])
            self.assertIn("G0002", checkpoint["groups"])
            self.assertTrue(checkpoint["groups"]["G0002"]["quarantined"])
            self.assertEqual(checkpoint["groups"]["G0001"]["evidence_group_id"], "G0002")
            self.assertEqual(checkpoint["groups"]["G0001"]["merged_from"], ["G0002"])
            self.assertEqual(checkpoint["retry_errors"]["G0002"]["quarantine_reason"], "duplicate_merged_into")
            self.assertEqual(groups["G0002"]["merged_into"], "G0001")
            self.assertEqual(json.loads(unique.read_text(encoding="utf-8"))["group_aliases"]["G0002"]["canonical_group_id"], "G0001")
            self.assertEqual(checkpoint["checkpoint_aliases"]["G0002"]["canonical_group_id"], "G0001")
            self.assertIn("G0001", checkpoint["checkpoint_archive"])
            self.assertIn("G0002", checkpoint["checkpoint_archive"])
            self.assertEqual(len({checkpoint["checkpoint_aliases"]["G0002"]["canonical_group_id"]}), 1)


class FailClosedStateTest(unittest.TestCase):
    def test_ingest_rejects_corrupt_existing_state_without_rewriting_it(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, events = root / "unique.json", root / "events.jsonl"
            corrupt = b'{broken unique state'
            unique.write_bytes(corrupt)
            events.write_text("", encoding="utf-8")
            completed = subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(unique), "--month", "2026-08",
            ], capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("refusing to overwrite", completed.stderr)
            self.assertEqual(unique.read_bytes(), corrupt)

    def test_merge_rejects_corrupt_checkpoint_without_rewriting_any_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = root / "unique.json", root / "verify.json"
            original_unique = b'{"groups": []}'
            corrupt_verify = b'{broken checkpoint'
            unique.write_bytes(original_unique)
            verify.write_bytes(corrupt_verify)
            completed = subprocess.run([
                sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
                "--unique-json", str(unique), "--full-verify-json", str(verify),
            ], capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("refusing to overwrite", completed.stderr)
            self.assertEqual(unique.read_bytes(), original_unique)
            self.assertEqual(verify.read_bytes(), corrupt_verify)

    def test_ingest_rejects_corrupt_existing_checkpoint_without_rewriting_unique(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify, events = root / "unique.json", root / "verify.json", root / "events.jsonl"
            original_unique, corrupt_verify = b'{"groups": []}', b'{broken checkpoint'
            unique.write_bytes(original_unique)
            verify.write_bytes(corrupt_verify)
            events.write_text("", encoding="utf-8")
            completed = subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(unique),
                "--full-verify-json", str(verify), "--month", "2026-08",
            ], capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("refusing to overwrite", completed.stderr)
            self.assertEqual(unique.read_bytes(), original_unique)
            self.assertEqual(verify.read_bytes(), corrupt_verify)

    def test_merge_rejects_corrupt_unique_without_rewriting_checkpoint(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = root / "unique.json", root / "verify.json"
            corrupt_unique, original_verify = b'{broken unique', b'{"groups": {}}'
            unique.write_bytes(corrupt_unique)
            verify.write_bytes(original_verify)
            completed = subprocess.run([
                sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
                "--unique-json", str(unique), "--full-verify-json", str(verify),
            ], capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("refusing to overwrite", completed.stderr)
            self.assertEqual(unique.read_bytes(), corrupt_unique)
            self.assertEqual(verify.read_bytes(), original_verify)

    def test_ingest_transaction_failure_restores_both_original_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify, events = root / "unique.json", root / "verify.json", root / "events.jsonl"
            original_unique = b'{"groups": []}'
            original_verify = b'{"groups": {}}'
            unique.write_bytes(original_unique)
            verify.write_bytes(original_verify)
            events.write_text(json.dumps({
                "type": "single_page_first_detected",
                "run_at": "2026-08-01T09:00:00+08:00",
                "domain": "new.example", "handle": "new-widget",
                "url": "https://new.example/products/new-widget", "title": "New Widget",
            }) + "\n")
            env = dict(os.environ, FB_VERIFY_TEST_MODE="1", FB_VERIFY_TEST_FAIL_AFTER_REPLACE="1")
            completed = subprocess.run([
                sys.executable, str(SCRIPTS / "ingest_new_hits.py"),
                "--monitor-events-jsonl", str(events), "--unique-json", str(unique),
                "--full-verify-json", str(verify), "--month", "2026-08", "--date", "2026-08-01",
            ], capture_output=True, text=True, env=env)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("injected transaction failure", completed.stderr)
            self.assertEqual(unique.read_bytes(), original_unique)
            self.assertEqual(verify.read_bytes(), original_verify)
            self.assertFalse(list(root.glob(".fbverify-transaction-*.json")))

    def test_merge_transaction_failure_restores_both_original_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = root / "unique.json", root / "verify.json"
            original_unique = json.dumps({"groups": [
                {"group_id": "G0001", "query": "Same", "members": [{"domain": "a.example", "handle": "a"}]},
                {"group_id": "G0002", "query": "same", "members": [{"domain": "b.example", "handle": "b"}]},
            ]}).encode()
            original_verify = b'{"groups": {}}'
            unique.write_bytes(original_unique)
            verify.write_bytes(original_verify)
            env = dict(os.environ, FB_VERIFY_TEST_MODE="1", FB_VERIFY_TEST_FAIL_AFTER_REPLACE="1")
            completed = subprocess.run([
                sys.executable, str(SCRIPTS / "merge_duplicate_query_groups.py"),
                "--unique-json", str(unique), "--full-verify-json", str(verify),
            ], capture_output=True, text=True, env=env)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("injected transaction failure", completed.stderr)
            self.assertEqual(unique.read_bytes(), original_unique)
            self.assertEqual(verify.read_bytes(), original_verify)


class DurableTransactionTest(unittest.TestCase):
    def test_committed_journal_is_removed_before_backups(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first, second = root / "first.json", root / "second.json"
            first.write_text('{"value":"old-first"}\n')
            second.write_text('{"value":"old-second"}\n')
            txid, journal_path = STATE_IO._transaction_identity([first, second])
            first_backup = first.resolve().with_name(f".{first.name}.{txid}.backup")
            original_unlink = Path.unlink
            crash_injected = False

            def crash_on_first_post_commit_backup(path_obj, *args, **kwargs):
                nonlocal crash_injected
                if (
                    not crash_injected
                    and path_obj == first_backup
                    and path_obj.exists()
                    and not journal_path.exists()
                ):
                    crash_injected = True
                    raise RuntimeError("simulated crash after durable commit marker removal")
                return original_unlink(path_obj, *args, **kwargs)

            with mock.patch.object(type(first), "unlink", crash_on_first_post_commit_backup):
                with self.assertRaisesRegex(RuntimeError, "durable commit marker"):
                    STATE_IO.recoverable_json_transaction([
                        (first, {"value": "committed-first"}),
                        (second, {"value": "committed-second"}),
                    ])

            self.assertTrue(crash_injected)
            self.assertFalse(journal_path.exists())
            self.assertTrue(first_backup.exists())
            self.assertEqual(json.loads(first.read_text()), {"value": "committed-first"})
            self.assertEqual(json.loads(second.read_text()), {"value": "committed-second"})

            # No stale journal means the next run must retain the committed
            # state, clean orphan backups, and complete normally.
            STATE_IO.recoverable_json_transaction([
                (first, {"value": "next-first"}),
                (second, {"value": "next-second"}),
            ])
            self.assertFalse(first_backup.exists())
            self.assertEqual(json.loads(first.read_text()), {"value": "next-first"})
            self.assertEqual(json.loads(second.read_text()), {"value": "next-second"})

    def test_half_applied_legacy_journal_is_rolled_back_and_current_commit_aborts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first, second = root / "first.json", root / "second.json"
            first_old, second_old = b'{"value":"first-old"}\n', b'{"value":"second-old"}\n'
            first.write_bytes(first_old)
            second.write_bytes(second_old)
            txid, journal_path = STATE_IO._transaction_identity([first, second])
            entries = []
            for target, new_value in ((first, {"value": "half-new"}), (second, {"value": "half-new"})):
                data = STATE_IO.json_bytes(new_value)
                staged = STATE_IO._write_temp(target, data, suffix=f"{txid}.staged")
                backup = target.with_name(f".{target.name}.{txid}.backup")
                backup_tmp = STATE_IO._write_temp(target, target.read_bytes(), suffix=f"{txid}.backup-tmp")
                os.replace(backup_tmp, backup)
                entries.append({
                    "target": str(target.resolve()), "staged": str(staged),
                    "backup": str(backup), "existed": True,
                    "sha256": __import__("hashlib").sha256(data).hexdigest(),
                })
            STATE_IO.atomic_write_json(journal_path, {
                "schema_version": 1, "transaction_id": txid, "entries": entries,
            })
            os.replace(entries[0]["staged"], first)

            with self.assertRaisesRegex(RuntimeError, "rerun required"):
                STATE_IO.recoverable_json_transaction([
                    (first, {"value": "must-not-commit"}),
                    (second, {"value": "must-not-commit"}),
                ])
            self.assertEqual(first.read_bytes(), first_old)
            self.assertEqual(second.read_bytes(), second_old)
            self.assertFalse(journal_path.exists())

            STATE_IO.recoverable_json_transaction([
                (first, {"value": "clean-next-run"}),
                (second, {"value": "clean-next-run"}),
            ])
            self.assertEqual(json.loads(first.read_text()), {"value": "clean-next-run"})
            self.assertEqual(json.loads(second.read_text()), {"value": "clean-next-run"})


class DeploymentSafetyTest(unittest.TestCase):
    def test_relative_daily_nightly_and_sync_entrypoints_are_drained_except_ancestor(self):
        rows = [
            (11, 1, "bash -c cd /tmp/release && ./run_daily_fb_verify.sh"),
            (12, 1, "bash -c cd /tmp/release && ./run_nightly_single_page_fb_verify.sh"),
            (13, 1, "bash -c cd /tmp/source && ./sync_deploy.sh"),
        ]
        with mock.patch.object(DRAIN_LEGACY, "ancestor_pids", return_value={11}):
            found = DRAIN_LEGACY.legacy_candidates(rows, {"/tmp/release"}, {"/tmp/source"})
        self.assertEqual([pid for pid, _ in found], [12, 13])

    def test_temp_release_deploy_never_seeds_or_changes_data_and_failed_stage_does_not_switch(self):
        self.assertTrue(os.access(ROOT / "sync_deploy.sh", os.X_OK))
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            missing_data_deploy = temp_root / "missing-data" / "fb-verify"
            missing = subprocess.run(
                ["bash", str(ROOT / "sync_deploy.sh")],
                capture_output=True, text=True,
                env={**os.environ, "FB_VERIFY_DEPLOY_DIR": str(missing_data_deploy)},
            )
            self.assertEqual(missing.returncode, 66, missing.stderr)
            self.assertFalse((missing_data_deploy / "data").exists())

            deploy = temp_root / "deploy" / "fb-verify"
            data = deploy / "data"
            data.mkdir(parents=True)
            sentinel = data / "production-state.bin"
            sentinel.write_bytes(b"production-state-must-remain-byte-identical\x00\xff")
            nested = data / "2026-08"
            nested.mkdir()
            (nested / "checkpoint.json").write_bytes(b'{"live":true}\n')
            data_before = tree_digest(data)
            source_data_before = tree_digest(ROOT / "data")
            env = dict(os.environ, FB_VERIFY_DEPLOY_DIR=str(deploy))

            completed = subprocess.run(
                ["bash", str(ROOT / "sync_deploy.sh")],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(tree_digest(data), data_before)
            self.assertEqual(tree_digest(ROOT / "data"), source_data_before)
            self.assertTrue((deploy / "current").is_symlink())
            first_release = os.readlink(deploy / "current")
            release = (deploy / "current").resolve()
            self.assertTrue((release / "scripts" / "state_io.py").is_file())
            self.assertFalse((release / "data").exists())
            self.assertTrue(os.access(release / "sync_deploy.sh", os.X_OK))
            for name in (
                "run_daily_fb_verify.sh",
                "run_nightly_single_page_fb_verify.sh",
                "sync_deploy.sh",
            ):
                wrapper = deploy / name
                self.assertTrue(os.access(wrapper, os.X_OK))
                self.assertIn("Stable launchd entrypoint", wrapper.read_text(encoding="utf-8"))
            stable_names = (
                "run_daily_fb_verify.sh", "run_nightly_single_page_fb_verify.sh",
                "sync_deploy.sh", "README.md", "com.spspy.fb-verify.plist",
                "com.spspy.single-page-fb-nightly.plist",
            )
            stable_before = {name: (deploy / name).read_bytes() for name in stable_names}

            wrapper_failure = subprocess.run(
                ["bash", str(ROOT / "sync_deploy.sh")],
                capture_output=True, text=True,
                env={
                    **env,
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_FAIL_DURING_WRAPPER_INSTALL": "1",
                },
            )
            self.assertEqual(wrapper_failure.returncode, 98, wrapper_failure.stderr)
            self.assertEqual(os.readlink(deploy / "current"), first_release)
            self.assertTrue((deploy / first_release).is_dir())
            self.assertEqual(
                {
                    name: (deploy / name).read_bytes()
                    for name in stable_before
                },
                stable_before,
            )
            self.assertEqual(tree_digest(data), data_before)

            for flag, expected_code in (
                ("FB_VERIFY_TEST_FAIL_AFTER_CURRENT_REPLACE", 99),
                ("FB_VERIFY_TEST_FAIL_FINAL_FSYNC", 100),
            ):
                injected = subprocess.run(
                    [str(ROOT / "sync_deploy.sh")],
                    capture_output=True, text=True,
                    env={**env, "FB_VERIFY_TEST_MODE": "1", flag: "1"},
                )
                self.assertEqual(injected.returncode, expected_code, injected.stderr)
                self.assertEqual(os.readlink(deploy / "current"), first_release)
                self.assertEqual(
                    {name: (deploy / name).read_bytes() for name in stable_names},
                    stable_before,
                )
                self.assertFalse((deploy / ".deployment.gate").exists())
                self.assertEqual(tree_digest(data), data_before)

            failed = subprocess.run(
                ["bash", str(ROOT / "sync_deploy.sh")],
                capture_output=True, text=True,
                env={
                    **env,
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_FAIL_BEFORE_SWITCH": "1",
                },
            )
            self.assertEqual(failed.returncode, 97, failed.stderr)
            self.assertEqual(os.readlink(deploy / "current"), first_release)
            self.assertEqual(tree_digest(data), data_before)
            self.assertEqual(tree_digest(ROOT / "data"), source_data_before)
            self.assertFalse(list((deploy / "releases").glob(".*.stage")))

            second = subprocess.run(
                ["bash", str(ROOT / "sync_deploy.sh")],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertNotEqual(os.readlink(deploy / "current"), first_release)
            self.assertTrue((deploy / first_release).is_dir())
            self.assertEqual(tree_digest(data), data_before)

            rollback_failure = subprocess.run(
                [str(ROOT / "sync_deploy.sh")], capture_output=True, text=True,
                env={
                    **env, "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_FAIL_AFTER_CURRENT_REPLACE": "1",
                    "FB_VERIFY_TEST_FAIL_ROLLBACK_RESTORE": "1",
                },
            )
            self.assertEqual(rollback_failure.returncode, 70, rollback_failure.stderr)
            self.assertTrue((deploy / ".deployment.gate").exists())
            gated = subprocess.run(
                [str(deploy / "run_daily_fb_verify.sh")], capture_output=True,
                text=True, env={**os.environ, "FB_VERIFY_LOG_DIR": str(temp_root / "logs")},
            )
            self.assertEqual(gated.returncode, 75, gated.stderr)
            self.assertEqual(tree_digest(data), data_before)

    def test_partial_wrapper_rollback_failure_converges_all_entrypoints_to_gate(self):
        for inject_failclosed_copy in (False, True):
            with self.subTest(inject_failclosed_copy=inject_failclosed_copy), \
                 tempfile.TemporaryDirectory() as td:
                root = Path(td)
                deploy = root / "deploy"
                data = deploy / "data"
                data.mkdir(parents=True)
                (data / "production-state.bin").write_bytes(b"must-not-change\x00\xff")
                (data / "nested").mkdir()
                (data / "nested" / "checkpoint.json").write_text('{"live":true}\n')
                data_before = tree_digest(data)
                env = {**os.environ, "FB_VERIFY_DEPLOY_DIR": str(deploy)}
                initial = subprocess.run(
                    [str(ROOT / "sync_deploy.sh")], capture_output=True, text=True, env=env,
                )
                self.assertEqual(initial.returncode, 0, initial.stderr)

                legacy_body = root / "legacy-body"
                legacy_body.mkdir()
                for name in (
                    "run_daily_fb_verify.sh",
                    "run_nightly_single_page_fb_verify.sh",
                    "sync_deploy.sh",
                ):
                    path = deploy / name
                    path.write_text(
                        "#!/usr/bin/env bash\n"
                        ': > "$LEGACY_BODY_DIR/' + name + '"\n'
                        "exit 42\n",
                        encoding="utf-8",
                    )
                    path.chmod(0o755)

                failure_env = {
                    **env,
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_FAIL_DURING_WRAPPER_INSTALL": "1",
                    "FB_VERIFY_TEST_FAIL_ROLLBACK_RESTORE": "1",
                }
                if inject_failclosed_copy:
                    failure_env["FB_VERIFY_TEST_FAIL_FAILCLOSED_WRAPPER_INSTALL"] = "1"
                failed = subprocess.run(
                    [str(ROOT / "sync_deploy.sh")], capture_output=True,
                    text=True, env=failure_env,
                )
                self.assertEqual(failed.returncode, 70, failed.stderr)
                self.assertTrue((deploy / ".deployment.gate").is_file())
                self.assertIn("retaining deployment gate", failed.stderr)
                if inject_failclosed_copy:
                    self.assertIn("injected fail-closed regular-wrapper install failure", failed.stderr)
                    fallback = deploy / "run_nightly_single_page_fb_verify.sh"
                    self.assertTrue(fallback.is_symlink())
                    self.assertIn("/deployment_entrypoint.sh", os.readlink(fallback))

                for name in (
                    "run_daily_fb_verify.sh",
                    "run_nightly_single_page_fb_verify.sh",
                    "sync_deploy.sh",
                ):
                    blocked = subprocess.run(
                        [str(deploy / name)], capture_output=True, text=True,
                        env={**os.environ, "LEGACY_BODY_DIR": str(legacy_body)},
                    )
                    self.assertEqual(blocked.returncode, 75, blocked.stderr)
                    self.assertIn("deployment gate is active", blocked.stderr)
                self.assertEqual(list(legacy_body.iterdir()), [])
                self.assertEqual(tree_digest(data), data_before)
                self.assertTrue(list(deploy.glob(".deploy-rollback-*")))

    def test_deploy_fcntl_lock_is_exclusive_and_crash_remnant_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            deploy = root / "deploy"
            (deploy / "data").mkdir(parents=True)
            ready, proceed = root / "lock-ready", root / "lock-continue"
            base = {
                **os.environ,
                "FB_VERIFY_DEPLOY_DIR": str(deploy),
                "FB_VERIFY_TEST_MODE": "1",
                "FB_VERIFY_TEST_EXIT_AFTER_LOCK": "1",
            }
            owner = subprocess.Popen(
                [str(ROOT / "sync_deploy.sh")], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
                env={
                    **base,
                    "FB_VERIFY_TEST_LOCK_READY_FILE": str(ready),
                    "FB_VERIFY_TEST_LOCK_CONTINUE_FILE": str(proceed),
                },
            )
            wait_for_path(ready, owner)
            lock = deploy / ".deploy.lock"
            self.assertTrue(lock.is_symlink())
            self.assertTrue((lock / ".fcntl").is_file())
            self.assertEqual((lock / "pid").read_text().strip(), "0")

            legacy_late = subprocess.run(
                ["bash", "-c", """
if mkdir "$LOCK_PATH" 2>/dev/null; then
  exit 99
fi
old_pid="$(cat "$LOCK_PATH/pid" 2>/dev/null || true)"
if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
  exit 75
fi
rm -rf "$LOCK_PATH"
exit 98
"""],
                capture_output=True, text=True,
                env={**os.environ, "LOCK_PATH": str(lock)},
            )
            self.assertEqual(legacy_late.returncode, 75, legacy_late.stderr)
            self.assertTrue(lock.is_symlink())
            self.assertIsNone(owner.poll())

            for _ in range(2):
                contender = subprocess.run(
                    [str(ROOT / "sync_deploy.sh")], capture_output=True,
                    text=True, env=base,
                )
                self.assertEqual(contender.returncode, 75, contender.stderr)
                self.assertIsNone(owner.poll())
                self.assertTrue(lock.is_symlink())

            owner.terminate()
            owner.communicate(timeout=5)
            after_crash = subprocess.run(
                [str(ROOT / "sync_deploy.sh")], capture_output=True,
                text=True, env=base,
            )
            self.assertEqual(after_crash.returncode, 75, after_crash.stderr)
            self.assertTrue(lock.is_symlink())

    def test_lock_publication_never_replaces_empty_legacy_or_follows_owner_symlink(self):
        helper = SCRIPTS / "locked_exec.py"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lock = root / ".deploy.lock"
            lock.mkdir()
            args = [
                sys.executable, str(helper), "--lock", str(lock),
                "--fd-env", "TEST_LOCK_FD", "--active-env", "TEST_LOCK_ACTIVE",
                "--label", "test deploy", "--", "/usr/bin/true",
            ]
            blocked = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(blocked.returncode, 75, blocked.stderr)
            self.assertTrue(lock.is_dir())
            self.assertFalse(lock.is_symlink())
            self.assertEqual(list(lock.iterdir()), [])

            (lock / "pid").write_text("99999999\n", encoding="ascii")
            recovered = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(recovered.returncode, 75, recovered.stderr)
            self.assertTrue(lock.is_dir())

            bad = root / "malicious.lock"
            external = root / "external"
            external.mkdir()
            (external / ".fcntl-protocol-v2").write_text("2\n")
            (external / ".fcntl").write_text("")
            (external / "pid").write_text(str(os.getpid()))
            owner_name = f".{bad.name}.owner.attacker"
            (root / owner_name).symlink_to(external, target_is_directory=True)
            bad.symlink_to(owner_name, target_is_directory=True)
            malicious_args = [
                sys.executable, str(helper), "--lock", str(bad),
                "--fd-env", "BAD_LOCK_FD", "--active-env", "BAD_LOCK_ACTIVE",
                "--label", "test", "--", "/usr/bin/true",
            ]
            rejected = subprocess.run(malicious_args, capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 70, rejected.stderr)
            self.assertTrue(bad.is_symlink())

    def test_lock_dead_reader_interleave_and_owner_only_cleanup(self):
        helper = SCRIPTS / "locked_exec.py"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lock, ready, proceed = root / "run.lock", root / "legacy-ready", root / "legacy-go"
            lock.mkdir()
            (lock / "pid").write_text("99999999\n", encoding="ascii")
            legacy_body, v2_body = root / "legacy-body", root / "v2-body"
            legacy = subprocess.Popen(
                ["bash", "-c", """
pid="$(cat "$LOCK_PATH/pid")"
kill -0 "$pid" 2>/dev/null && exit 91
: > "$READY"
while [[ ! -e "$PROCEED" ]]; do sleep 0.02; done
rm -rf "$LOCK_PATH"
mkdir "$LOCK_PATH"
: > "$LEGACY_BODY"
"""], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={
                    **os.environ, "LOCK_PATH": str(lock), "READY": str(ready),
                    "PROCEED": str(proceed), "LEGACY_BODY": str(legacy_body),
                },
            )
            wait_for_path(ready, legacy)
            rejected = subprocess.run(
                [sys.executable, str(helper), "--lock", str(lock), "--fd-env", "T_FD",
                 "--active-env", "T_ACTIVE", "--label", "interleave", "--",
                 "bash", "-c", ': > "$V2_BODY"'],
                capture_output=True, text=True,
                env={**os.environ, "V2_BODY": str(v2_body)},
            )
            self.assertEqual(rejected.returncode, 75, rejected.stderr)
            self.assertFalse(v2_body.exists())
            self.assertTrue(lock.is_dir())
            proceed.touch()
            _, legacy_stderr = legacy.communicate(timeout=5)
            self.assertEqual(legacy.returncode, 0, legacy_stderr)
            self.assertTrue(legacy_body.exists())

            # The nested child has inherited metadata/fd but not the original
            # outer PID, so even an ``exec`` of the release helper is rejected.
            # Only the outer target may itself exec that helper at final
            # cleanup.  This is deliberately an exec regression: its parent
            # PID is the outer shell, which used to bypass a getppid check.
            owner = root / "owner.sh"
            owner.write_text("""#!/usr/bin/env bash
set -euo pipefail
release() {
  code=$?
  trap - EXIT
  exec "$PYTHON_BIN" "$LOCK_HELPER" --lock "$LOCK_PATH" --fd-env T_FD \\
    --active-env T_ACTIVE --label owner --release-owned --exit-code "$code"
}
trap release EXIT
set +e
bash -c 'exec "$PYTHON_BIN" "$LOCK_HELPER" --lock "$LOCK_PATH" --fd-env T_FD --active-env T_ACTIVE --label owner --release-owned --exit-code 0'
child_code=$?
bash -c 'FB_VERIFY_LOCK_OWNER_PID=$$ exec "$PYTHON_BIN" "$LOCK_HELPER" --lock "$LOCK_PATH" --fd-env T_FD --active-env T_ACTIVE --label owner --release-owned --exit-code 0'
spoofed_child_code=$?
"$PYTHON_BIN" "$LOCK_HELPER" --lock "$LOCK_PATH" --fd-env T_FD \\
  --active-env T_ACTIVE --label owner --busy-exit 75 -- /usr/bin/true
contender_code=$?
set -e
[[ "$child_code" == "70" ]]
[[ "$spoofed_child_code" == "70" ]]
[[ "$contender_code" == "75" ]]
[[ -L "$LOCK_PATH" ]]
: > "$OWNER_BODY"
exit "${OWNER_EXIT_CODE:-0}"
""", encoding="utf-8")
            owner.chmod(0o755)
            for body, expected_code in (
                (root / "owner-body", 0),
                (root / "owner-body-second", 47),
            ):
                completed = subprocess.run(
                    [sys.executable, str(helper), "--lock", str(root / "owner.lock"),
                     "--fd-env", "T_FD", "--active-env", "T_ACTIVE", "--label", "owner",
                     "--", str(owner)], capture_output=True, text=True,
                    env={**os.environ, "LOCK_HELPER": str(helper),
                         "LOCK_PATH": str(root / "owner.lock"), "OWNER_BODY": str(body),
                         "PYTHON_BIN": sys.executable,
                         "OWNER_EXIT_CODE": str(expected_code)},
                )
                self.assertEqual(completed.returncode, expected_code, completed.stderr)
                self.assertTrue(body.exists())
                self.assertFalse((root / "owner.lock").exists())

    def test_cached_v1_pid_zero_cannot_delete_next_normal_owner_generation(self):
        helper = SCRIPTS / "locked_exec.py"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lock = root / "run.lock"
            owner_script = root / "owner.sh"
            owner_script.write_text("""#!/usr/bin/env bash
set -euo pipefail
release() {
  code=$?
  trap - EXIT
  exec "$PYTHON_BIN" "$LOCK_HELPER" --lock "$LOCK_PATH" --fd-env T_FD \\
    --active-env T_ACTIVE --label owner --release-owned --exit-code "$code"
}
trap release EXIT
: > "$READY"
: > "$OWNER_BODY"
if [[ -n "${CONTINUE:-}" ]]; then
  while [[ ! -e "$CONTINUE" ]]; do sleep 0.02; done
fi
""", encoding="utf-8")
            owner_script.chmod(0o755)

            def start_owner(label):
                ready = root / f"{label}-ready"
                proceed = root / f"{label}-continue"
                body = root / f"{label}-body"
                process = subprocess.Popen(
                    [sys.executable, str(helper), "--lock", str(lock),
                     "--fd-env", "T_FD", "--active-env", "T_ACTIVE",
                     "--label", "owner", "--", str(owner_script)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env={**os.environ, "PYTHON_BIN": sys.executable,
                         "LOCK_HELPER": str(helper), "LOCK_PATH": str(lock),
                         "READY": str(ready), "CONTINUE": str(proceed),
                         "OWNER_BODY": str(body)},
                )
                wait_for_path(ready, process)
                self.assertEqual((lock / "pid").read_text().strip(), "0")
                return process, proceed, body

            owner_a, continue_a, body_a = start_owner("a")
            cached_ready, cached_continue = root / "cached-ready", root / "cached-continue"
            legacy_body = root / "legacy-body"
            cached_v1 = subprocess.Popen(
                ["bash", "-c", """
cached_pid="$(cat "$LOCK_PATH/pid")"
[[ "$cached_pid" == "0" ]] || exit 92
: > "$READY"
while [[ ! -e "$CONTINUE" ]]; do sleep 0.02; done
if [[ -n "$cached_pid" ]] && kill -0 "$cached_pid" 2>/dev/null; then
  exit 75
fi
rm -rf "$LOCK_PATH"
: > "$LEGACY_BODY"
"""], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={**os.environ, "LOCK_PATH": str(lock), "READY": str(cached_ready),
                     "CONTINUE": str(cached_continue), "LEGACY_BODY": str(legacy_body)},
            )
            wait_for_path(cached_ready, cached_v1)

            continue_a.touch()
            _, stderr_a = owner_a.communicate(timeout=5)
            self.assertEqual(owner_a.returncode, 0, stderr_a)
            self.assertTrue(body_a.exists())
            self.assertFalse(lock.exists())

            owner_b, continue_b, body_b = start_owner("b")
            owner_b_target = os.readlink(lock)
            cached_continue.touch()
            _, cached_stderr = cached_v1.communicate(timeout=5)
            self.assertEqual(cached_v1.returncode, 75, cached_stderr)
            self.assertFalse(legacy_body.exists())
            self.assertTrue(lock.is_symlink())
            self.assertEqual(os.readlink(lock), owner_b_target)
            self.assertIsNone(owner_b.poll())

            continue_b.touch()
            _, stderr_b = owner_b.communicate(timeout=5)
            self.assertEqual(owner_b.returncode, 0, stderr_b)
            self.assertTrue(body_b.exists())
            self.assertFalse(lock.exists())

            # A fresh generation can enter after B's owner-safe cleanup.
            ready_c, body_c = root / "c-ready", root / "c-body"
            completed = subprocess.run(
                [sys.executable, str(helper), "--lock", str(lock),
                 "--fd-env", "T_FD", "--active-env", "T_ACTIVE",
                 "--label", "owner", "--", str(owner_script)],
                capture_output=True, text=True,
                env={**os.environ, "PYTHON_BIN": sys.executable,
                     "LOCK_HELPER": str(helper), "LOCK_PATH": str(lock),
                     "READY": str(ready_c), "CONTINUE": "", "OWNER_BODY": str(body_c)},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(body_c.exists())
            self.assertFalse(lock.exists())

    def test_validated_stage_is_installed_even_if_mutable_source_changes_after_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source"
            shutil.copytree(ROOT, source)
            deploy = root / "deploy"
            (deploy / "data").mkdir(parents=True)
            ready, proceed = root / "validated", root / "continue"
            original_launcher = (source / "deployment_entrypoint.sh").read_bytes()
            original_readme = (source / "README.md").read_bytes()
            process = subprocess.Popen(
                [str(source / "sync_deploy.sh")], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DEPLOY_DIR": str(deploy),
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_VALIDATION_READY_FILE": str(ready),
                    "FB_VERIFY_TEST_VALIDATION_CONTINUE_FILE": str(proceed),
                },
            )
            wait_for_path(ready, process)
            (source / "deployment_entrypoint.sh").write_bytes(
                original_launcher + b"\n# MUTATED AFTER VALIDATION\n"
            )
            (source / "README.md").write_bytes(
                original_readme + b"\nMUTATED AFTER VALIDATION\n"
            )
            proceed.touch()
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stderr)
            release = (deploy / "current").resolve()
            self.assertEqual((release / "deployment_entrypoint.sh").read_bytes(), original_launcher)
            self.assertEqual((deploy / "run_daily_fb_verify.sh").read_bytes(), original_launcher)
            self.assertEqual((deploy / "README.md").read_bytes(), original_readme)
            self.assertNotIn("MUTATED AFTER VALIDATION", stdout)

            before_current = os.readlink(deploy / "current")
            stable_before = {
                name: (deploy / name).read_bytes()
                for name in (
                    "run_daily_fb_verify.sh", "run_nightly_single_page_fb_verify.sh",
                    "sync_deploy.sh", "README.md", "com.spspy.fb-verify.plist",
                    "com.spspy.single-page-fb-nightly.plist",
                )
            }
            (source / "com.spspy.fb-verify.plist").write_text("not a plist")
            malformed = subprocess.run(
                [str(source / "sync_deploy.sh")], capture_output=True, text=True,
                env={**os.environ, "FB_VERIFY_DEPLOY_DIR": str(deploy)},
            )
            self.assertNotEqual(malformed.returncode, 0)
            self.assertEqual(os.readlink(deploy / "current"), before_current)
            self.assertEqual(
                {name: (deploy / name).read_bytes() for name in stable_before},
                stable_before,
            )
            self.assertFalse((deploy / ".deployment.gate").exists())

    def test_deploy_gate_drains_old_release_started_before_legacy_run_lock(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            deploy = root / "deploy"
            data = deploy / "data"
            data.mkdir(parents=True)
            env = {**os.environ, "FB_VERIFY_DEPLOY_DIR": str(deploy)}
            first = subprocess.run(
                [str(ROOT / "sync_deploy.sh")], capture_output=True, text=True, env=env,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            old_current = os.readlink(deploy / "current")
            data_before = tree_digest(data)

            legacy_release = deploy / "releases" / "legacy-test"
            legacy_release.mkdir()
            legacy_script = legacy_release / "run_daily_fb_verify.sh"
            legacy_script.write_text(
                """#!/usr/bin/env bash
set -e
: > "$OLD_READY"
while [[ ! -e "$OLD_CONTINUE" ]]; do sleep 0.02; done
lock="$FB_VERIFY_DATA_ROOT/run_daily.lock"
if mkdir "$lock" 2>/dev/null; then
  printf '%s\n' "$$" > "$lock/pid"
  : > "$OLD_BODY"
  sleep 0.1
  rm -rf "$lock"
  exit 0
fi
exit 75
""",
                encoding="utf-8",
            )
            legacy_script.chmod(0o755)
            old_ready, old_continue = root / "old-ready", root / "old-continue"
            old_body = root / "old-body"
            old_process = subprocess.Popen(
                ["bash", "-c", 'cd "$1" && ./run_daily_fb_verify.sh', "bash", str(legacy_release)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "OLD_READY": str(old_ready),
                    "OLD_CONTINUE": str(old_continue),
                    "OLD_BODY": str(old_body),
                },
            )
            wait_for_path(old_ready, old_process)

            drain_ready = root / "drain-ready"
            deploying = subprocess.Popen(
                [str(ROOT / "sync_deploy.sh")], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
                env={
                    **env,
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_DRAIN_READY_FILE": str(drain_ready),
                },
            )
            wait_for_path(drain_ready, deploying)
            # The test-only rendezvous is emitted only after the drain helper
            # has observed this non-ancestor legacy process while the gate is
            # live.  It is therefore safe to exercise the fail-closed stable
            # entrypoint before allowing the old process to finish.
            self.assertIsNone(deploying.poll())
            self.assertTrue((deploy / ".deployment.gate").exists())
            self.assertEqual(os.readlink(deploy / "current"), old_current)
            gated = subprocess.run(
                [str(deploy / "run_daily_fb_verify.sh")], capture_output=True, text=True,
                env={**os.environ, "FB_VERIFY_LOG_DIR": str(root / "logs")},
            )
            self.assertEqual(gated.returncode, 75, gated.stderr)
            self.assertIn("deployment gate is active", gated.stderr)

            old_continue.touch()
            old_stdout, old_stderr = old_process.communicate(timeout=10)
            self.assertEqual(old_process.returncode, 0, old_stderr)
            self.assertTrue(old_body.exists())
            deploy_stdout, deploy_stderr = deploying.communicate(timeout=20)
            self.assertEqual(deploying.returncode, 0, deploy_stderr)
            self.assertNotEqual(os.readlink(deploy / "current"), old_current)
            self.assertFalse((deploy / ".deployment.gate").exists())
            self.assertEqual(tree_digest(data), data_before)


class PipelineStatusTest(unittest.TestCase):
    @staticmethod
    def seed_nonempty_month(data):
        """Keep pipeline-status tests focused on status, not empty bootstrap policy."""
        month = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m")
        month_dir = data / month
        month_dir.mkdir()
        (month_dir / "unique_products.json").write_text(json.dumps({
            "month": month,
            "groups": [{
                "group_id": "G0001", "query": "Existing dashboard evidence",
                "members": [],
            }],
        }), encoding="utf-8")

    @staticmethod
    def _supervisor_command(lock, target):
        return [
            sys.executable, str(SCRIPTS / "locked_exec.py"),
            "--lock", str(lock), "--fd-env", "T_FD",
            "--active-env", "T_ACTIVE", "--label", "round3 test",
            "--busy-exit", "75", "--supervise", "--", *map(str, target),
        ]

    def test_supervisor_drains_same_group_inherited_lease_before_release(self):
        for leader_exit in (0, 47):
            with self.subTest(leader_exit=leader_exit), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                lock = root / "run.lock"
                child_ready = root / "child-ready"
                child_pid_file = root / "child-pid"
                leader_go = root / "leader-go"
                target = root / "same_group_holder.py"
                target.write_text(
                    "import os, pathlib, signal, time\n"
                    "lock_fd = int(os.environ['T_FD'])\n"
                    "os.fstat(lock_fd)\n"
                    "child = os.fork()\n"
                    "if child == 0:\n"
                    "    os.fstat(lock_fd)\n"
                    "    for item in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):\n"
                    "        signal.signal(item, signal.SIG_IGN)\n"
                    "    pathlib.Path(os.environ['CHILD_PID']).write_text(str(os.getpid()))\n"
                    "    pathlib.Path(os.environ['CHILD_READY']).touch()\n"
                    "    while True:\n"
                    "        time.sleep(1)\n"
                    "while not pathlib.Path(os.environ['LEADER_GO']).exists():\n"
                    "    time.sleep(0.01)\n"
                    "raise SystemExit(int(os.environ['LEADER_EXIT']))\n",
                    encoding="utf-8",
                )
                environment = {
                    **os.environ,
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_SUPERVISOR_DRAIN_GRACE_SECONDS": "0.4",
                    "FB_VERIFY_TEST_SUPERVISOR_GROUP_GONE_GRACE_SECONDS": "0.4",
                    "FB_VERIFY_TEST_SUPERVISOR_LEASE_GRACE_SECONDS": "0.4",
                    "CHILD_READY": str(child_ready),
                    "CHILD_PID": str(child_pid_file),
                    "LEADER_GO": str(leader_go),
                    "LEADER_EXIT": str(leader_exit),
                }
                owner = subprocess.Popen(
                    self._supervisor_command(lock, (sys.executable, target)),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env=environment,
                )
                wait_for_path(child_ready, owner)
                child_pid = int(child_pid_file.read_text(encoding="ascii"))
                self.assertTrue(lock.is_symlink())

                contender_command = self._supervisor_command(
                    lock, ("/usr/bin/true",)
                )
                contender = subprocess.run(
                    contender_command, capture_output=True, text=True,
                    env={**os.environ, "FB_VERIFY_TEST_MODE": "1"},
                )
                self.assertEqual(contender.returncode, 75, contender.stderr)

                leader_go.touch()
                time.sleep(0.08)
                during_drain = subprocess.run(
                    contender_command, capture_output=True, text=True,
                    env={**os.environ, "FB_VERIFY_TEST_MODE": "1"},
                )
                self.assertEqual(during_drain.returncode, 75, during_drain.stderr)
                stdout, stderr = owner.communicate(timeout=5)
                self.assertEqual(owner.returncode, leader_exit, stdout + stderr)
                wait_for_pid_gone(child_pid)
                self.assertFalse(lock.exists())

                after_release = subprocess.run(
                    contender_command, capture_output=True, text=True,
                    env={**os.environ, "FB_VERIFY_TEST_MODE": "1"},
                )
                self.assertEqual(after_release.returncode, 0, after_release.stderr)
                self.assertFalse(lock.exists())

    def test_supervisor_first_signal_deadline_is_not_reset_by_mixed_repeats(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lock = root / "run.lock"
            ready = root / "ready"
            child_pid_file = root / "child-pid"
            target = root / "stubborn_group.py"
            target.write_text(
                "import os, pathlib, signal, time\n"
                "lock_fd = int(os.environ['T_FD'])\n"
                "os.fstat(lock_fd)\n"
                "for item in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):\n"
                "    signal.signal(item, signal.SIG_IGN)\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    os.fstat(lock_fd)\n"
                "    pathlib.Path(os.environ['CHILD_PID']).write_text(str(os.getpid()))\n"
                "    pathlib.Path(os.environ['READY']).touch()\n"
                "while True:\n"
                "    time.sleep(1)\n",
                encoding="utf-8",
            )
            owner = subprocess.Popen(
                self._supervisor_command(lock, (sys.executable, target)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_SUPERVISOR_SIGNAL_GRACE_SECONDS": "0.3",
                    "FB_VERIFY_TEST_SUPERVISOR_GROUP_GONE_GRACE_SECONDS": "0.4",
                    "FB_VERIFY_TEST_SUPERVISOR_LEASE_GRACE_SECONDS": "0.4",
                    "READY": str(ready),
                    "CHILD_PID": str(child_pid_file),
                },
            )
            wait_for_path(ready, owner)
            child_pid = int(child_pid_file.read_text(encoding="ascii"))
            started = time.monotonic()
            owner.send_signal(signal.SIGTERM)
            for repeated in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                time.sleep(0.04)
                self.assertIsNone(owner.poll())
                owner.send_signal(repeated)
            stdout, stderr = owner.communicate(timeout=5)
            elapsed = time.monotonic() - started
            self.assertEqual(owner.returncode, 143, stdout + stderr)
            self.assertGreaterEqual(elapsed, 0.20)
            self.assertLess(elapsed, 1.2)
            wait_for_pid_gone(child_pid)
            self.assertFalse(lock.exists())

    def test_supervisor_preserves_public_owner_for_setsid_lease_escape(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            lock = root / "run.lock"
            ready = root / "ready"
            child_pid_file = root / "child-pid"
            leader_go = root / "leader-go"
            child_stop = root / "child-stop"
            target = root / "setsid_holder.py"
            target.write_text(
                "import os, pathlib, signal, time\n"
                "lock_fd = int(os.environ['T_FD'])\n"
                "os.fstat(lock_fd)\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    os.setsid()\n"
                "    os.fstat(lock_fd)\n"
                "    for item in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):\n"
                "        signal.signal(item, signal.SIG_IGN)\n"
                "    null_fd = os.open(os.devnull, os.O_RDWR)\n"
                "    for item in (0, 1, 2):\n"
                "        os.dup2(null_fd, item)\n"
                "    if null_fd > 2:\n"
                "        os.close(null_fd)\n"
                "    pathlib.Path(os.environ['CHILD_PID']).write_text(str(os.getpid()))\n"
                "    pathlib.Path(os.environ['READY']).touch()\n"
                "    while not pathlib.Path(os.environ['CHILD_STOP']).exists():\n"
                "        time.sleep(0.02)\n"
                "    raise SystemExit(0)\n"
                "while not pathlib.Path(os.environ['LEADER_GO']).exists():\n"
                "    time.sleep(0.01)\n",
                encoding="utf-8",
            )
            test_environment = {
                **os.environ,
                "FB_VERIFY_TEST_MODE": "1",
                "FB_VERIFY_TEST_SUPERVISOR_DRAIN_GRACE_SECONDS": "0.1",
                "FB_VERIFY_TEST_SUPERVISOR_GROUP_GONE_GRACE_SECONDS": "0.2",
                "FB_VERIFY_TEST_SUPERVISOR_LEASE_GRACE_SECONDS": "0.2",
                "READY": str(ready),
                "CHILD_PID": str(child_pid_file),
                "CHILD_STOP": str(child_stop),
                "LEADER_GO": str(leader_go),
            }
            owner = subprocess.Popen(
                self._supervisor_command(lock, (sys.executable, target)),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=test_environment,
            )
            wait_for_path(ready, owner)
            child_pid = int(child_pid_file.read_text(encoding="ascii"))
            self.assertTrue(lock.is_symlink())
            public_target = os.readlink(lock)
            contender_command = self._supervisor_command(lock, ("/usr/bin/true",))

            while_live = subprocess.run(
                contender_command, capture_output=True, text=True,
                env={**os.environ, "FB_VERIFY_TEST_MODE": "1"},
            )
            self.assertEqual(while_live.returncode, 75, while_live.stderr)
            leader_go.touch()
            stdout, stderr = owner.communicate(timeout=5)
            self.assertEqual(owner.returncode, 70, stdout + stderr)
            self.assertTrue(lock.is_symlink())
            self.assertEqual(os.readlink(lock), public_target)
            self.assertTrue((lock / ".lease-recovery-v1").is_file())
            os.kill(child_pid, 0)

            after_supervisor = subprocess.run(
                contender_command, capture_output=True, text=True,
                env={**os.environ, "FB_VERIFY_TEST_MODE": "1"},
            )
            self.assertEqual(after_supervisor.returncode, 75, after_supervisor.stderr)
            child_stop.touch()
            wait_for_pid_gone(child_pid)
            self.assertTrue(lock.is_symlink())
            self.assertEqual(os.readlink(lock), public_target)

            after_descendant = subprocess.run(
                contender_command, capture_output=True, text=True,
                env={**os.environ, "FB_VERIFY_TEST_MODE": "1"},
            )
            self.assertEqual(after_descendant.returncode, 0, after_descendant.stderr)
            self.assertFalse(lock.exists())

    def test_daily_rejects_nonfinite_or_out_of_policy_image_watchdog_before_pipeline_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cases = (
                ("FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS", "nan"),
                ("FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS", "inf"),
                ("FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS", "1e309"),
                ("FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS", "59"),
                ("FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS", "1201"),
                ("FB_VERIFY_IMAGE_WATCHDOG_GRACE_SECONDS", "0"),
                ("FB_VERIFY_IMAGE_WATCHDOG_GRACE_SECONDS", "31"),
            )
            for index, (variable, value) in enumerate(cases):
                with self.subTest(variable=variable, value=value):
                    data = root / f"data-{index}"
                    logs = root / f"logs-{index}"
                    self.assertFalse(data.exists())
                    self.assertFalse(logs.exists())
                    completed = subprocess.run(
                        ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                        capture_output=True,
                        text=True,
                        env={
                            **os.environ,
                            "FB_VERIFY_DATA_ROOT": str(data),
                            "FB_VERIFY_LOG_DIR": str(logs),
                            "FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS": "1200",
                            "FB_VERIFY_IMAGE_WATCHDOG_GRACE_SECONDS": "10",
                            variable: value,
                        },
                    )
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertIn("must be finite and in", completed.stderr)
                    self.assertNotIn("run_daily_fb_verify.sh start", completed.stdout)
                    self.assertFalse(data.exists())
                    self.assertFalse(logs.exists())

    def test_daily_supervisor_blocks_contenders_then_term_cleans_and_releases(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            node_scripts.mkdir()
            (node_scripts / "run_verify_new_groups.mjs").write_text("", encoding="utf-8")
            (node_scripts / "fb_product_verify.mjs").write_text("", encoding="utf-8")
            ready, proceed = root / "ready", root / "continue"
            base = {
                **os.environ,
                "FB_VERIFY_DATA_ROOT": str(data),
                "FB_VERIFY_LOG_DIR": str(logs),
                "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                "FB_VERIFY_PUBLISH": "0", "FB_VERIFY_DINGTALK": "0",
                "FB_VERIFY_TEST_MODE": "1",
                "FB_VERIFY_TEST_EXIT_AFTER_LOCK": "1",
            }
            owner = subprocess.Popen(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={
                    **base,
                    "FB_VERIFY_TEST_LOCK_READY_FILE": str(ready),
                    "FB_VERIFY_TEST_LOCK_CONTINUE_FILE": str(proceed),
                },
            )
            wait_for_path(ready, owner)
            lock = data / "run_daily.lock"
            self.assertTrue(lock.is_symlink())
            self.assertEqual((lock / "pid").read_text().strip(), "0")

            legacy_late = subprocess.run(
                ["bash", "-c", """
if mkdir "$LOCK_PATH" 2>/dev/null; then exit 99; fi
old_pid="$(cat "$LOCK_PATH/pid" 2>/dev/null || true)"
if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then exit 75; fi
rm -rf "$LOCK_PATH"
exit 98
"""], capture_output=True, text=True,
                env={**os.environ, "LOCK_PATH": str(lock)},
            )
            self.assertEqual(legacy_late.returncode, 75, legacy_late.stderr)
            for _ in range(2):
                contender = subprocess.run(
                    [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                    capture_output=True, text=True, env=base,
                )
                self.assertEqual(contender.returncode, 75, contender.stderr)
                self.assertIsNone(owner.poll())
                self.assertTrue(lock.is_symlink())
            self.assertFalse((data / "pipeline_status.json").exists())

            owner.terminate()
            owner_stdout, owner_stderr = owner.communicate(timeout=5)
            self.assertEqual(owner.returncode, 143, owner_stdout + owner_stderr)
            records = list((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(records), 1)
            terminal = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(terminal["exit_code"], 143)
            self.assertEqual(terminal["signature"], "recoverable_interrupted")
            self.assertFalse(terminal["pause_recommended"])
            self.assertFalse(lock.exists())

            after_term = subprocess.run(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True, text=True, env=base,
            )
            self.assertEqual(after_term.returncode, 96, after_term.stderr)
            self.assertFalse(lock.exists())

    def test_term_queued_after_lock_publish_before_target_init_gets_terminal_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            node_scripts.mkdir()
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            ready, proceed = root / "supervisor-init-ready", root / "supervisor-init-go"
            process = subprocess.Popen(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_PUBLISH": "0",
                    "FB_VERIFY_DINGTALK": "0",
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_SUPERVISOR_INIT_READY_FILE": str(ready),
                    "FB_VERIFY_TEST_SUPERVISOR_INIT_CONTINUE_FILE": str(proceed),
                },
            )
            wait_for_path(ready, process)
            self.assertTrue((data / "run_daily.lock").is_symlink())
            process.terminate()
            proceed.touch()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            records = list((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(records), 1)
            terminal = json.loads(records[0].read_text())
            self.assertEqual(terminal["exit_code"], 143)
            self.assertEqual(terminal["signature"], "recoverable_interrupted")
            self.assertFalse((data / "run_daily.lock").exists())

    def test_nightly_reuses_inherited_daily_lock_without_deadlock(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            monitor = root / "monitor"
            data.mkdir()
            self.seed_nonempty_month(data)
            node_scripts.mkdir()
            monitor.mkdir()
            events = root / "events.jsonl"
            events.write_text("", encoding="utf-8")
            zero = {
                "todo": 0, "verified": 0, "verified_group_ids": [],
                "failed": 0, "failed_group_ids": [], "pending": 0,
                "truncated": 0, "terminated_early": False,
            }
            (node_scripts / "run_verify_new_groups.mjs").write_text(
                "console.log('VERIFY_SUMMARY_JSON ' + process.env.FAKE_VERIFY_JSON);\n"
            )
            (node_scripts / "fb_product_verify.mjs").write_text("")
            monitor_marker = root / "monitor-ran"
            monitor_script = monitor / "run_daily.sh"
            monitor_script.write_text(
                "#!/usr/bin/env bash\n: > \"$MONITOR_MARKER\"\n", encoding="utf-8"
            )
            monitor_script.chmod(0o755)
            completed = subprocess.run(
                [str(ROOT / "run_nightly_single_page_fb_verify.sh")],
                capture_output=True, text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                    "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                    "FB_VERIFY_PUBLISH": "0", "FB_VERIFY_DINGTALK": "0",
                    "SP_SINGLE_PAGE_MONITOR_DIR": str(monitor),
                    "MONITOR_MARKER": str(monitor_marker),
                    "FAKE_VERIFY_JSON": json.dumps(zero),
                },
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(monitor_marker.exists())
            self.assertNotIn("another FB verifier run is active", completed.stderr)
            self.assertFalse((data / "run_daily.lock").exists())

    def test_nightly_to_daily_nested_supervisor_cascades_term_without_deadlock(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            monitor = root / "monitor"
            data.mkdir()
            node_scripts.mkdir()
            monitor.mkdir()
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            monitor_script = monitor / "run_daily.sh"
            monitor_script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            monitor_script.chmod(0o755)
            ready, never = root / "daily-ready", root / "never"
            process = subprocess.Popen(
                [str(ROOT / "run_nightly_single_page_fb_verify.sh")],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_PUBLISH": "0",
                    "FB_VERIFY_DINGTALK": "0",
                    "SP_SINGLE_PAGE_MONITOR_DIR": str(monitor),
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_SIGNAL_READY_FILE": str(ready),
                    "FB_VERIFY_TEST_SIGNAL_CONTINUE_FILE": str(never),
                },
            )
            wait_for_path(ready, process)
            process.terminate()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            records = list((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(records), 1)
            terminal = json.loads(records[0].read_text())
            self.assertEqual(terminal["exit_code"], 143)
            self.assertEqual(terminal["signature"], "recoverable_interrupted")
            self.assertFalse((data / "run_daily.lock").exists())

    def test_nightly_to_daily_strong_kill_leaves_one_inner_fallback_record(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            monitor = root / "monitor"
            data.mkdir()
            node_scripts.mkdir()
            monitor.mkdir()
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            monitor_script = monitor / "run_daily.sh"
            monitor_script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            monitor_script.chmod(0o755)
            events = root / "events.jsonl"
            events.write_text("", encoding="utf-8")
            merge_ready, merge_pid_file = root / "merge-ready", root / "merge-pid"
            merge = root / "nested_stubborn_merge.py"
            merge.write_text(
                "import os, pathlib, signal, time\n"
                "for item in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):\n"
                "    signal.signal(item, signal.SIG_IGN)\n"
                "pathlib.Path(os.environ['MERGE_PID']).write_text(str(os.getpid()))\n"
                "pathlib.Path(os.environ['MERGE_READY']).touch()\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [str(ROOT / "run_nightly_single_page_fb_verify.sh")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                    "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                    "FB_VERIFY_MERGE_SCRIPT": str(merge),
                    "FB_VERIFY_PUBLISH": "0",
                    "FB_VERIFY_DINGTALK": "0",
                    "SP_SINGLE_PAGE_MONITOR_DIR": str(monitor),
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_SUPERVISOR_SIGNAL_GRACE_SECONDS": "0.4",
                    "FB_VERIFY_TEST_SUPERVISOR_DRAIN_GRACE_SECONDS": "0.1",
                    "FB_VERIFY_TEST_SUPERVISOR_GROUP_GONE_GRACE_SECONDS": "0.5",
                    "FB_VERIFY_TEST_SUPERVISOR_LEASE_GRACE_SECONDS": "0.5",
                    "MERGE_READY": str(merge_ready),
                    "MERGE_PID": str(merge_pid_file),
                },
            )
            wait_for_path(merge_ready, process)
            merge_pid = int(merge_pid_file.read_text(encoding="ascii"))
            process.terminate()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            wait_for_pid_gone(merge_pid)
            records = list((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(records), 1)
            terminal = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(terminal["phase"], "unknown")
            self.assertEqual(terminal["exit_code"], 143)
            self.assertEqual(terminal["signature"], "recoverable_interrupted")
            self.assertFalse(terminal["pause_recommended"])
            self.assertFalse((data / "last_published_success.txt").exists())
            self.assertFalse((data / "run_daily.lock").exists())

    def test_final_status_is_durable_while_run_lock_is_still_held(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            self.seed_nonempty_month(data)
            node_scripts.mkdir()
            events = root / "events.jsonl"
            events.write_text("")
            zero = {
                "todo": 0, "verified": 0, "verified_group_ids": [],
                "failed": 0, "failed_group_ids": [], "pending": 0,
                "truncated": 0, "terminated_early": False,
            }
            (node_scripts / "run_verify_new_groups.mjs").write_text(
                "console.log('VERIFY_SUMMARY_JSON ' + process.env.FAKE_VERIFY_JSON);\n"
            )
            (node_scripts / "fb_product_verify.mjs").write_text("")
            ready, proceed = root / "final-ready", root / "final-continue"
            base = {
                **os.environ,
                "FB_VERIFY_DATA_ROOT": str(data),
                "FB_VERIFY_LOG_DIR": str(logs),
                "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                "FB_VERIFY_PUBLISH": "0", "FB_VERIFY_DINGTALK": "0",
                "FAKE_VERIFY_JSON": json.dumps(zero),
            }
            owner = subprocess.Popen(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={
                    **base, "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_FINAL_STATE_READY_FILE": str(ready),
                    "FB_VERIFY_TEST_FINAL_STATE_CONTINUE_FILE": str(proceed),
                },
            )
            wait_for_path(ready, owner)
            status_before_release = json.loads(
                (data / "pipeline_status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(status_before_release["state"], "partial")
            self.assertTrue(status_before_release["body_complete"])
            contender = subprocess.run(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True, text=True, env=base,
            )
            self.assertEqual(contender.returncode, 75, contender.stderr)
            self.assertEqual(
                json.loads((data / "pipeline_status.json").read_text()),
                status_before_release,
            )
            proceed.touch()
            stdout, stderr = owner.communicate(timeout=10)
            self.assertEqual(owner.returncode, 0, stderr)

    def test_strict_verify_summary_cli_rejects_missing_duplicate_bad_type_and_negative(self):
        valid_payload = {
            "todo": 3,
            "verified": 1,
            "verified_group_ids": ["G0001"],
            "failed": 1,
            "failed_group_ids": ["G0002"],
            "pending": 2,
            "truncated": 1,
            "terminated_early": False,
        }
        valid_line = "VERIFY_SUMMARY_JSON " + json.dumps(valid_payload)
        self.assertEqual(
            SUMMARY_VALIDATOR.extract_and_validate("verify", valid_line), valid_payload
        )
        invalid_inputs = [
            "",
            valid_line + "\n" + valid_line,
            "VERIFY_SUMMARY_JSON " + json.dumps({**valid_payload, "failed": False}),
            "VERIFY_SUMMARY_JSON " + json.dumps({**valid_payload, "pending": -1}),
            "VERIFY_SUMMARY_JSON " + json.dumps({**valid_payload, "todo": 4}),
        ]
        for raw in invalid_inputs:
            completed = subprocess.run(
                [sys.executable, str(SCRIPTS / "validate_pipeline_summary.py"), "--kind", "verify"],
                input=raw, capture_output=True, text=True,
            )
            self.assertEqual(completed.returncode, 2, raw)
            self.assertIn("invalid VERIFY_SUMMARY_JSON", completed.stderr)

    def test_build_summary_cli_is_bound_to_view_kind_and_expected_group_ids(self):
        monthly_payload = {"total_groups": 2, "found": 1, "unverified": 1}
        batch_payload = {
            "total_groups": 2, "found": 2, "unverified": 0,
            "requested": ["G0002", "G0001"],
            "resolved": ["G0002", "G0001"], "missing": [],
        }

        def validate(payload, *args):
            return subprocess.run(
                [sys.executable, str(SCRIPTS / "validate_pipeline_summary.py"),
                 "--kind", "build", *args],
                input="BUILD_SUMMARY_JSON " + json.dumps(payload),
                capture_output=True, text=True,
            )

        monthly = validate(monthly_payload, "--build-view-kind", "monthly")
        self.assertEqual(monthly.returncode, 0, monthly.stderr)
        batch = validate(
            batch_payload, "--build-view-kind", "batch",
            "--expected-group-ids", " G0002, G0001 ",
        )
        self.assertEqual(batch.returncode, 0, batch.stderr)

        invalid_cases = (
            ({"total_groups": 2, "found": 2, "unverified": 0},
             ("--build-view-kind", "batch", "--expected-group-ids", "G0002,G0001")),
            (batch_payload, ("--build-view-kind", "monthly")),
            (batch_payload, ("--build-view-kind", "batch", "--expected-group-ids", "G0001,G0002")),
            (batch_payload, ("--build-view-kind", "batch", "--expected-group-ids", "G0001,G0001")),
            (batch_payload, ("--build-view-kind", "batch", "--expected-group-ids", "G0001,,G0002")),
            (monthly_payload, ()),
        )
        for payload, args in invalid_cases:
            with self.subTest(args=args):
                rejected = validate(payload, *args)
                self.assertEqual(rejected.returncode, 2)
                self.assertIn("invalid BUILD_SUMMARY_JSON", rejected.stderr)

        verify_payload = {
            "todo": 0, "verified": 0, "verified_group_ids": [],
            "failed": 0, "failed_group_ids": [], "pending": 0,
            "truncated": 0, "terminated_early": False,
        }
        nonbuild = subprocess.run(
            [sys.executable, str(SCRIPTS / "validate_pipeline_summary.py"),
             "--kind", "verify", "--build-view-kind", "monthly"],
            input="VERIFY_SUMMARY_JSON " + json.dumps(verify_payload),
            capture_output=True, text=True,
        )
        self.assertEqual(nonbuild.returncode, 2)
        self.assertIn("valid only with --kind build", nonbuild.stderr)

    def test_daily_shell_stops_before_images_on_invalid_verify_summary(self):
        valid = {
            "todo": 0, "verified": 0, "verified_group_ids": [],
            "failed": 0, "failed_group_ids": [], "pending": 0,
            "truncated": 0, "terminated_early": False,
        }
        bad_outputs = (
            "runner returned no marker",
            "VERIFY_SUMMARY_JSON " + json.dumps({**valid, "failed": False}),
            "VERIFY_SUMMARY_JSON " + json.dumps({**valid, "pending": -1}),
        )
        for fake_output in bad_outputs:
            with self.subTest(fake_output=fake_output), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                data, logs, node_scripts = root / "data", root / "logs", root / "node"
                data.mkdir()
                node_scripts.mkdir()
                events = root / "events.jsonl"
                events.write_text("", encoding="utf-8")
                (node_scripts / "run_verify_new_groups.mjs").write_text(
                    "console.log(process.env.FAKE_VERIFY_OUTPUT);\n", encoding="utf-8"
                )
                (node_scripts / "fb_product_verify.mjs").write_text("", encoding="utf-8")
                completed = subprocess.run(
                    ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                    capture_output=True, text=True,
                    env={
                        **os.environ,
                        "FB_VERIFY_DATA_ROOT": str(data),
                        "FB_VERIFY_LOG_DIR": str(logs),
                        "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                        "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                        "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                        "FB_VERIFY_PUBLISH": "0",
                        "FB_VERIFY_DINGTALK": "0",
                        "FAKE_VERIFY_OUTPUT": fake_output,
                    },
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertIn("invalid VERIFY_SUMMARY_JSON", completed.stderr)
                self.assertNotIn("step 4/7", completed.stdout)
                status = json.loads((data / "pipeline_status.json").read_text())
                self.assertEqual(status["state"], "failed")
                self.assertFalse(status["stamp_eligible"])
                self.assertFalse((data / "last_published_success.txt").exists())

    def test_daily_shell_accepts_complete_zero_summary_but_publish_disabled_never_stamps(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            self.seed_nonempty_month(data)
            node_scripts.mkdir()
            events = root / "events.jsonl"
            events.write_text("", encoding="utf-8")
            zero = {
                "todo": 0, "verified": 0, "verified_group_ids": [],
                "failed": 0, "failed_group_ids": [], "pending": 0,
                "truncated": 0, "terminated_early": False,
            }
            (node_scripts / "run_verify_new_groups.mjs").write_text(
                "console.log('VERIFY_SUMMARY_JSON ' + process.env.FAKE_VERIFY_JSON);\n",
                encoding="utf-8",
            )
            (node_scripts / "fb_product_verify.mjs").write_text("", encoding="utf-8")
            completed = subprocess.run(
                ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True, text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                    "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                    "FB_VERIFY_PUBLISH": "0",
                    "FB_VERIFY_DINGTALK": "0",
                    "FAKE_VERIFY_JSON": json.dumps(zero),
                },
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            status = json.loads((data / "pipeline_status.json").read_text())
            self.assertEqual(status["state"], "partial")
            self.assertTrue(status["body_complete"])
            self.assertFalse(status["stamp_eligible"])
            self.assertFalse((data / "last_published_success.txt").exists())

    def test_image_step_124_preserves_cache_and_pipeline_fail_closed_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            self.seed_nonempty_month(data)
            month = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m")
            month_dir = data / month
            cache = month_dir / "product_images.json"
            cache_bytes = b'{"already":"https://cdn.example/already.jpg"}\n'
            cache.write_bytes(cache_bytes)
            node_scripts.mkdir()
            events = root / "events.jsonl"
            events.write_text("", encoding="utf-8")
            zero = {
                "todo": 0, "verified": 0, "verified_group_ids": [],
                "failed": 0, "failed_group_ids": [], "pending": 0,
                "truncated": 0, "terminated_early": False,
            }
            (node_scripts / "run_verify_new_groups.mjs").write_text(
                "console.log('VERIFY_SUMMARY_JSON ' + process.env.FAKE_VERIFY_JSON);\n",
                encoding="utf-8",
            )
            (node_scripts / "fb_product_verify.mjs").write_text("", encoding="utf-8")
            image_ready = root / "image-step-ready"
            image_fetch = root / "hanging_fetch.py"
            image_fetch.write_text(
                "import os, pathlib, sys, time\n"
                "pathlib.Path(os.environ['IMAGE_READY']).write_text(str(os.getpid()))\n"
                "print('[images] heartbeat: fake fetch started', file=sys.stderr, flush=True)\n"
                "time.sleep(1)\n"
                "raise SystemExit(124)\n",
                encoding="utf-8",
            )
            build_marker = root / "builder-called"
            builder = root / "builder.py"
            builder.write_text(
                "import os, pathlib\npathlib.Path(os.environ['BUILD_MARKER']).touch()\n",
                encoding="utf-8",
            )
            stamp = data / "last_published_success.txt"
            stamp.write_text(datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d") + "\n")
            env = {
                **os.environ,
                "FB_VERIFY_DATA_ROOT": str(data),
                "FB_VERIFY_LOG_DIR": str(logs),
                "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                "FB_VERIFY_PUBLISH": "1", "FB_VERIFY_DINGTALK": "0",
                "FB_VERIFY_IMAGE_FETCH_SCRIPT": str(image_fetch),
                "FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS": "60",
                "FB_VERIFY_IMAGE_WATCHDOG_GRACE_SECONDS": "1",
                "FB_VERIFY_BUILD_PAGE_SCRIPT": str(builder),
                "BUILD_MARKER": str(build_marker),
                "FAKE_VERIFY_JSON": json.dumps(zero),
                "IMAGE_READY": str(image_ready),
            }
            owner = subprocess.Popen(
                ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            wait_for_path(image_ready, owner)
            contender = subprocess.run(
                ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(contender.returncode, 75, contender.stderr)
            stdout, stderr = owner.communicate(timeout=10)
            self.assertEqual(owner.returncode, 124, stdout + stderr)
            self.assertIn("heartbeat: fake fetch started", stderr)
            self.assertNotIn("step 5/7", stdout)
            self.assertFalse(build_marker.exists())
            self.assertEqual(cache.read_bytes(), cache_bytes)
            status = json.loads((data / "pipeline_status.json").read_text())
            self.assertEqual(status["state"], "failed")
            self.assertFalse(status["stamp_eligible"])
            self.assertNotEqual(stamp.read_text().strip(), datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d"))
            self.assertFalse((data / "run_daily.lock").exists())

    def test_batch_builder_malformed_or_mismatched_summary_stops_before_publisher(self):
        bad_batch_outputs = (
            "batch builder exited zero without a marker",
            "BUILD_SUMMARY_JSON " + json.dumps({
                "total_groups": 1, "found": 1, "unverified": 0,
            }),
        )
        for fake_batch_output in bad_batch_outputs:
            with self.subTest(output=fake_batch_output), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                data, logs, node_scripts = root / "data", root / "logs", root / "node"
                fake_bin = root / "bin"
                data.mkdir()
                node_scripts.mkdir()
                fake_bin.mkdir()
                month = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m")
                month_dir = data / month
                month_dir.mkdir()
                (month_dir / "unique_products.json").write_text(json.dumps({
                    "month": month,
                    "total_groups": 1,
                    "groups": [{
                        "group_id": "G0001", "query": "Matched test product",
                        "members": [], "already_verified": False,
                    }],
                }), encoding="utf-8")
                events = root / "events.jsonl"
                events.write_text("")
                (node_scripts / "run_verify_new_groups.mjs").write_text(
                    """import fs from 'node:fs';
const args = process.argv.slice(2);
const value = (name) => args[args.indexOf(name) + 1];
const checkpoint = value('--checkpoint-json');
const record = {
  schema_version: 2, producer: 'fb-verify-runner', query: 'Matched test product',
  response_http_status: 200, fb_total_reported: 1, harvested: 1,
  sample: [{id:'ad1'}], relevant_ads_count: 1,
  relevant_ads: [{id:'ad1', start_date: 1770000000}],
  verification_state: 'positive', max_run_days: 1,
  cross_site_domains_count: 1, own_domain_hit: true
};
fs.writeFileSync(checkpoint, JSON.stringify({
  schema_version:2, producer:'fb-verify-runner', groups:{G0001:record}, retry_errors:{}
}));
console.log('VERIFY_SUMMARY_JSON ' + JSON.stringify({
  todo:1, verified:1, verified_group_ids:['G0001'], failed:0,
  failed_group_ids:[], pending:0, truncated:0, terminated_early:false
}));
""",
                    encoding="utf-8",
                )
                (node_scripts / "fb_product_verify.mjs").write_text("")
                fake_builder = root / "fake_builder.py"
                fake_builder.write_text(
                    """import json, os, pathlib, sys
args = sys.argv[1:]
out = pathlib.Path(args[args.index('--out') + 1])
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text('<!doctype html>fake')
if '--group-ids' in args:
    print(os.environ['FAKE_BATCH_OUTPUT'])
else:
    print('BUILD_SUMMARY_JSON ' + json.dumps({
        'total_groups': 1, 'found': 1, 'unverified': 0
    }))
""",
                    encoding="utf-8",
                )
                git_marker = root / "git-called"
                fake_git = fake_bin / "git"
                fake_git.write_text(
                    "#!/usr/bin/env bash\n: > \"$FAKE_GIT_MARKER\"\nexit 99\n",
                    encoding="utf-8",
                )
                fake_git.chmod(0o755)
                completed = subprocess.run(
                    [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                    capture_output=True, text=True,
                    env={
                        **os.environ,
                        "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
                        "FB_VERIFY_DATA_ROOT": str(data),
                        "FB_VERIFY_LOG_DIR": str(logs),
                        "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                        "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                        "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                        "FB_VERIFY_BUILD_PAGE_SCRIPT": str(fake_builder),
                        "FB_VERIFY_PAGES_DIR": str(root / "pages"),
                        "FB_VERIFY_PUBLISH": "1", "FB_VERIFY_DINGTALK": "0",
                        "FAKE_BATCH_OUTPUT": fake_batch_output,
                        "FAKE_GIT_MARKER": str(git_marker),
                    },
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("step 5b/7", completed.stdout)
                self.assertNotIn("step 6/7", completed.stdout)
                self.assertFalse(git_marker.exists(), completed.stdout + completed.stderr)
                status = json.loads((data / "pipeline_status.json").read_text())
                self.assertEqual(status["state"], "failed")
                self.assertFalse(status["stamp_eligible"])
                self.assertFalse((data / "last_published_success.txt").exists())

    def test_truth_table_requires_zero_failures_for_success_stamp(self):
        base = dict(
            exit_code=0, publish_ok=True, terminated_early=False,
            truncated=0, pending=0, failed=0, skipped=False,
        )
        self.assertEqual(PIPELINE_STATUS.evaluate_status(**base)["state"], "succeeded")
        self.assertTrue(PIPELINE_STATUS.evaluate_status(**base)["stamp_eligible"])
        for override, expected in (
            ({"failed": 1}, "partial"),
            ({"pending": 1}, "partial"),
            ({"truncated": 1}, "partial"),
            ({"terminated_early": True}, "partial"),
            ({"publish_ok": False}, "partial"),
            ({"body_complete": False}, "partial"),
            ({"exit_code": 2}, "failed"),
            ({"skipped": True}, "skipped"),
        ):
            row = {**base, **override}
            result = PIPELINE_STATUS.evaluate_status(**row)
            self.assertEqual(result["state"], expected)
            self.assertFalse(result["stamp_eligible"])

    def test_pipeline_status_is_atomic_and_cleanup_persists_before_unlock(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "status.json"
            self.assertEqual(PIPELINE_STATUS.main([
                "--out", str(output), "--date", "2026-08-01", "--exit-code", "0",
                "--run-id", "run-123", "--body-complete", "1",
                "--publish-ok", "1", "--terminated-early", "0",
                "--truncated", "0", "--pending", "0", "--failed", "0",
            ]), 0)
            payload = json.loads(output.read_text())
            self.assertEqual(payload["state"], "succeeded")
            self.assertEqual(payload["run_id"], "run-123")
            self.assertTrue(payload["gates"]["failed_zero"])
            self.assertFalse(list(output.parent.glob(".*.tmp")))

        shell = (ROOT / "run_daily_fb_verify.sh").read_text(encoding="utf-8")
        cleanup = shell[shell.index("cleanup() {"):shell.index("trap cleanup EXIT")]
        self.assertLess(cleanup.index("pipeline_status.py"), cleanup.index('exit "$code"'))
        self.assertIn('[[ "$FAILED_COUNT" == "0" ]]', cleanup)
        self.assertLess(cleanup.index("pipeline_status.py"), cleanup.index('atomic_write_text "$PUBLISHED_SUCCESS_FILE"'))
        self.assertNotIn('rm -rf "$LOCK', cleanup)
        self.assertIn("supervisor is the sole lock owner", cleanup)
        self.assertIn("trap '' HUP INT TERM", cleanup)
        self.assertNotIn("--release-owned", cleanup)
        body = shell[shell.index("trap cleanup EXIT"):]
        self.assertEqual(cleanup.count('atomic_write_text "$PUBLISHED_SUCCESS_FILE"'), 1)
        self.assertEqual(body.count('atomic_write_text "$PUBLISHED_SUCCESS_FILE"'), 1)
        invalidation = body.index('"invalidated:${TODAY}:${RUN_SLUG}"')
        first_step = body.index("# --- 1. 摄入本月")
        self.assertLess(invalidation, first_step)
        self.assertLess(body.index("# --- 汇总一行 ---"), body.rindex("PIPELINE_BODY_COMPLETE=1"))
        self.assertIn("validate_pipeline_summary.py\" --kind verify", shell)
        self.assertEqual(shell.count("--build-view-kind"), 2)
        self.assertRegex(
            shell,
            r'--kind build \\\n\s+--build-view-kind monthly',
        )
        self.assertRegex(
            shell,
            r'--kind build \\\n\s+--build-view-kind batch --expected-group-ids "\$MATCHED_GIDS"',
        )
        self.assertNotIn("d.get('failed',0)", shell)
        self.assertIn('PAGES_PUBLISH_SCRIPT="${FB_VERIFY_PAGES_PUBLISH_SCRIPT:', shell)
        self.assertIn('"$PYTHON_BIN" "$PAGES_PUBLISH_SCRIPT"', shell)
        self.assertNotIn('git -C "$PAGES_DIR" push origin main', shell)
        self.assertLess(
            shell.index("--kind verify"), shell.index("# --- 4. 只抓新增产品的主图")
        )

    def test_forced_same_day_failure_invalidates_old_success_tuple_and_next_skip_requires_final_tuple(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs = root / "data", root / "logs"
            data.mkdir()
            today = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d")
            stamp = data / "last_published_success.txt"
            attempt = data / "last_attempt_id.txt"
            status = data / "pipeline_status.json"
            stamp.write_text(today + "\n", encoding="utf-8")
            attempt.write_text("old-success-run\n", encoding="utf-8")
            status.write_text(json.dumps({
                "date": today, "run_id": "old-success-run", "state": "succeeded",
                "stamp_eligible": True,
            }), encoding="utf-8")
            env = {
                **os.environ,
                "FB_VERIFY_DATA_ROOT": str(data),
                "FB_VERIFY_LOG_DIR": str(logs),
                "FB_VERIFY_NODE_SCRIPTS_DIR": str(SCRIPTS),
                "FB_VERIFY_ALLOW_SAME_DAY": "1",
                "FB_VERIFY_PUBLISH": "0",
                "FB_VERIFY_DINGTALK": "0",
                "FB_VERIFY_TEST_MODE": "1",
                "FB_VERIFY_TEST_EXIT_AFTER_BEGIN": "1",
            }
            failed = subprocess.run(
                ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(failed.returncode, 91, failed.stderr)
            self.assertNotEqual(stamp.read_text(encoding="utf-8").strip(), today)
            new_attempt = attempt.read_text(encoding="utf-8").strip()
            self.assertNotEqual(new_attempt, "old-success-run")
            failed_status = json.loads(status.read_text(encoding="utf-8"))
            self.assertEqual(failed_status["run_id"], new_attempt)
            self.assertEqual(failed_status["state"], "failed")
            self.assertFalse(failed_status["body_complete"])

            # A fully matching final tuple is the only same-day skip state. A
            # skipped invocation must preserve it byte-for-byte.
            stamp.write_text(today + "\n", encoding="utf-8")
            attempt.write_text("restored-success-run\n", encoding="utf-8")
            success_payload = {
                "date": today, "run_id": "restored-success-run", "state": "succeeded",
                "stamp_eligible": True,
            }
            status.write_text(json.dumps(success_payload), encoding="utf-8")
            success_record = PIPELINE_STATUS.make_attempt_record(
                attempt_id="restored-success-run",
                run_id="restored-success-run",
                release_id="source_local",
                phase="complete",
                exit_code=0,
                publish_ok=True,
                terminated_early=False,
                truncated=0,
                pending=0,
                failed=0,
                body_complete=True,
                started_at="2026-08-04T10:00:00+08:00",
                finished_at="2026-08-04T10:00:01+08:00",
            )
            PIPELINE_STATUS.write_attempt_ledger(
                data / "attempt_ledger", success_record
            )
            before = (stamp.read_bytes(), attempt.read_bytes(), status.read_bytes())
            skipped = subprocess.run(
                ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True, text=True,
                env={**env, "FB_VERIFY_ALLOW_SAME_DAY": "0"},
            )
            self.assertEqual(skipped.returncode, 0, skipped.stderr)
            self.assertIn("skip (idempotent)", skipped.stdout)
            self.assertEqual(
                (stamp.read_bytes(), attempt.read_bytes(), status.read_bytes()), before
            )

    def test_same_day_skip_rejects_missing_malformed_uncertain_or_non_success_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            node_scripts = root / "node"
            node_scripts.mkdir()
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            today = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d")

            for case in ("missing", "malformed", "stale", "wrong_release", "failed"):
                with self.subTest(case=case):
                    data, logs = root / f"data-{case}", root / f"logs-{case}"
                    data.mkdir()
                    (data / "last_published_success.txt").write_text(
                        today + "\n", encoding="utf-8"
                    )
                    (data / "last_attempt_id.txt").write_text(
                        "old-success-run\n", encoding="utf-8"
                    )
                    (data / "pipeline_status.json").write_text(json.dumps({
                        "date": today,
                        "run_id": "old-success-run",
                        "state": "succeeded",
                        "stamp_eligible": True,
                    }), encoding="utf-8")
                    ledger = data / "attempt_ledger"
                    if case in {"malformed", "stale"}:
                        ledger.mkdir(mode=0o700)
                        ledger.chmod(0o700)
                    if case == "malformed":
                        bad = ledger / "bad.json"
                        bad.write_text("{}\n", encoding="utf-8")
                        bad.chmod(0o600)
                    elif case == "stale":
                        stale = ledger / ".old-success-run.123.1.tmp"
                        stale.write_text("{}\n", encoding="utf-8")
                        stale.chmod(0o600)
                    elif case in {"wrong_release", "failed"}:
                        if case == "wrong_release":
                            record = PIPELINE_STATUS.make_attempt_record(
                                attempt_id="old-success-run", run_id="old-success-run",
                                release_id="another-release", phase="complete", exit_code=0,
                                publish_ok=True, terminated_early=False, truncated=0,
                                pending=0, failed=0, body_complete=True,
                                started_at="2026-08-04T10:00:00+08:00",
                                finished_at="2026-08-04T10:00:01+08:00",
                            )
                        else:
                            record = self._attempt_record("old-success-run")
                        PIPELINE_STATUS.write_attempt_ledger(ledger, record)

                    completed = subprocess.run(
                        [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                        capture_output=True,
                        text=True,
                        env={
                            **os.environ,
                            "FB_VERIFY_DATA_ROOT": str(data),
                            "FB_VERIFY_LOG_DIR": str(logs),
                            "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                            "FB_VERIFY_PUBLISH": "0",
                            "FB_VERIFY_DINGTALK": "0",
                            "FB_VERIFY_TEST_MODE": "1",
                            "FB_VERIFY_TEST_EXIT_AFTER_BEGIN": "1",
                        },
                    )
                    expected_code = 70 if case in {"malformed", "stale"} else 91
                    self.assertEqual(
                        completed.returncode, expected_code, completed.stderr
                    )
                    self.assertNotIn("skip (idempotent)", completed.stdout)
                    self.assertNotEqual(
                        (data / "last_attempt_id.txt").read_text().strip(),
                        "old-success-run",
                    )

    def test_ledger_failure_still_forces_rerun_when_both_mutable_downgrades_fail(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            node_scripts.mkdir()
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            base = {
                **os.environ,
                "FB_VERIFY_DATA_ROOT": str(data),
                "FB_VERIFY_LOG_DIR": str(logs),
                "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                "FB_VERIFY_PUBLISH": "0",
                "FB_VERIFY_DINGTALK": "0",
                "FB_VERIFY_TEST_MODE": "1",
            }
            failed_commit = subprocess.run(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True,
                text=True,
                env={
                    **base,
                    "FB_VERIFY_TEST_FORCE_SUCCESS_AFTER_BEGIN": "1",
                    "FB_VERIFY_TEST_FAIL_ATTEMPT_LEDGER": "1",
                    "FB_VERIFY_TEST_FAIL_STAMP_INVALIDATION": "1",
                    "FB_VERIFY_TEST_FAIL_STATUS_DOWNGRADE": "1",
                },
            )
            self.assertEqual(failed_commit.returncode, 70, failed_commit.stderr)
            today = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d")
            self.assertEqual(
                (data / "last_published_success.txt").read_text().strip(), today
            )
            stale_status = json.loads((data / "pipeline_status.json").read_text())
            self.assertEqual(stale_status["state"], "succeeded")
            fallback_records = list((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(fallback_records), 1)
            fallback = json.loads(fallback_records[0].read_text(encoding="utf-8"))
            self.assertEqual(fallback["phase"], "unknown")
            self.assertEqual(fallback["exit_code"], 143)
            self.assertEqual(fallback["signature"], "recoverable_interrupted")
            self.assertFalse(fallback["pause_recommended"])

            rerun = subprocess.run(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True,
                text=True,
                env={**base, "FB_VERIFY_TEST_EXIT_AFTER_BEGIN": "1"},
            )
            self.assertEqual(rerun.returncode, 91, rerun.stderr)
            self.assertNotIn("skip (idempotent)", rerun.stdout)

    def test_repeated_term_during_cleanup_completes_once_without_double_record(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            node_scripts.mkdir()
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            ready, proceed = root / "cleanup-ready", root / "cleanup-continue"
            process = subprocess.Popen(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_PUBLISH": "0",
                    "FB_VERIFY_DINGTALK": "0",
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_EXIT_AFTER_BEGIN": "1",
                    "FB_VERIFY_TEST_FINAL_STATE_READY_FILE": str(ready),
                    "FB_VERIFY_TEST_FINAL_STATE_CONTINUE_FILE": str(proceed),
                },
            )
            wait_for_path(ready, process)
            for _ in range(3):
                process.send_signal(signal.SIGTERM)
                time.sleep(0.02)
            self.assertIsNone(process.poll())
            proceed.touch()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            records = list((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(records), 1)
            self.assertEqual(json.loads(records[0].read_text())["exit_code"], 91)
            self.assertFalse((data / "run_daily.lock").exists())

    def test_term_during_long_merge_kills_foreground_child_and_records_once(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            node_scripts.mkdir()
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            events = root / "events.jsonl"
            events.write_text("", encoding="utf-8")
            merge_ready, merge_pid = root / "merge-ready", root / "merge-pid"
            merge = root / "long_merge.py"
            merge.write_text(
                "import os, pathlib, signal, time\n"
                "for item in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):\n"
                "    signal.signal(item, signal.SIG_IGN)\n"
                "pathlib.Path(os.environ['MERGE_PID']).write_text(str(os.getpid()))\n"
                "pathlib.Path(os.environ['MERGE_READY']).touch()\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                    "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                    "FB_VERIFY_MERGE_SCRIPT": str(merge),
                    "FB_VERIFY_PUBLISH": "0",
                    "FB_VERIFY_DINGTALK": "0",
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_SUPERVISOR_SIGNAL_GRACE_SECONDS": "0.3",
                    "FB_VERIFY_TEST_SUPERVISOR_DRAIN_GRACE_SECONDS": "0.1",
                    "FB_VERIFY_TEST_SUPERVISOR_GROUP_GONE_GRACE_SECONDS": "0.4",
                    "FB_VERIFY_TEST_SUPERVISOR_LEASE_GRACE_SECONDS": "0.4",
                    "MERGE_READY": str(merge_ready),
                    "MERGE_PID": str(merge_pid),
                },
            )
            wait_for_path(merge_ready, process)
            child_pid = int(merge_pid.read_text())
            started = time.monotonic()
            process.terminate()
            for repeated in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                time.sleep(0.04)
                self.assertIsNone(process.poll())
                process.send_signal(repeated)
            stdout, stderr = process.communicate(timeout=10)
            elapsed = time.monotonic() - started
            self.assertEqual(process.returncode, 143, stdout + stderr)
            self.assertGreaterEqual(elapsed, 0.20)
            self.assertLess(elapsed, 1.5)
            wait_for_pid_gone(child_pid)
            records = list((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(records), 1)
            terminal = json.loads(records[0].read_text())
            self.assertEqual(terminal["phase"], "unknown")
            self.assertEqual(terminal["exit_code"], 143)
            self.assertEqual(terminal["signature"], "recoverable_interrupted")
            self.assertFalse(terminal["pause_recommended"])
            self.assertFalse((data / "last_published_success.txt").exists())
            self.assertFalse((data / "run_daily.lock").exists())

    @staticmethod
    def _attempt_record(
        attempt_id="attempt-1", release_id="release-test", phase="verify", exit_code=2,
        started_at="2026-08-04T10:00:00+08:00", finished_at="2026-08-04T10:00:01+08:00",
    ):
        return PIPELINE_STATUS.make_attempt_record(
            attempt_id=attempt_id,
            run_id=attempt_id,
            release_id=release_id,
            phase=phase,
            exit_code=exit_code,
            publish_ok=False,
            terminated_early=False,
            truncated=0,
            pending=0,
            failed=0,
            started_at=started_at,
            finished_at=finished_at,
        )

    def test_pre_summary_merge_failure_commits_one_immutable_attempt_record(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            node_scripts.mkdir()
            events = root / "events.jsonl"
            events.write_text("", encoding="utf-8")
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            merge_failure = root / "merge_failure.py"
            merge_failure.write_text("raise SystemExit(42)\n", encoding="utf-8")
            completed = subprocess.run(
                ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                    "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                    "FB_VERIFY_MERGE_SCRIPT": str(merge_failure),
                    "FB_VERIFY_PUBLISH": "0",
                    "FB_VERIFY_DINGTALK": "0",
                    "FB_VERIFY_RELEASE_ID": "release-merge-test",
                },
            )
            self.assertEqual(completed.returncode, 42, completed.stderr)
            records = sorted((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(record["release_id"], "release-merge-test")
            self.assertEqual(record["phase"], "merge")
            self.assertEqual(record["state"], "failed")
            self.assertEqual(record["exit_code"], 42)
            self.assertEqual(record["signature"], "local_merge_error")
            self.assertTrue(record["pause_recommended"])
            self.assertEqual(record["attempt_id"], record["run_id"])
            self.assertNotIn("stderr", record)
            self.assertNotIn("url", record)

    def test_signal_after_attempt_begin_commits_one_recoverable_terminal_record(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data, logs, node_scripts = root / "data", root / "logs", root / "node"
            data.mkdir()
            node_scripts.mkdir()
            events = root / "events.jsonl"
            events.write_text("", encoding="utf-8")
            for name in ("run_verify_new_groups.mjs", "fb_product_verify.mjs"):
                (node_scripts / name).write_text("", encoding="utf-8")
            ready, proceed = root / "signal-ready", root / "signal-proceed"
            process = subprocess.Popen(
                ["bash", str(ROOT / "run_daily_fb_verify.sh"), "--no-dingtalk"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={
                    **os.environ,
                    "FB_VERIFY_DATA_ROOT": str(data),
                    "FB_VERIFY_LOG_DIR": str(logs),
                    "FB_VERIFY_NODE_SCRIPTS_DIR": str(node_scripts),
                    "FB_VERIFY_MONITOR_EVENTS_JSONL": str(events),
                    "FB_VERIFY_EVENT_CUTOFF_FILE": str(root / "missing-cutoff"),
                    "FB_VERIFY_PUBLISH": "0",
                    "FB_VERIFY_DINGTALK": "0",
                    "FB_VERIFY_TEST_MODE": "1",
                    "FB_VERIFY_TEST_SIGNAL_READY_FILE": str(ready),
                    "FB_VERIFY_TEST_SIGNAL_CONTINUE_FILE": str(proceed),
                },
            )
            wait_for_path(ready, process)
            process.terminate()
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            records = sorted((data / "attempt_ledger").glob("*.json"))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(record["state"], "failed")
            self.assertEqual(record["exit_code"], 143)
            self.assertEqual(record["signature"], "recoverable_interrupted")
            self.assertFalse(record["pause_recommended"])
            self.assertFalse((data / "run_daily.lock").exists())

    def test_attempt_ledger_collision_never_overwrites_prior_record(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "ledger"
            first = self._attempt_record("collision-attempt", phase="verify")
            path = PIPELINE_STATUS.write_attempt_ledger(ledger, first)
            original = path.read_bytes()
            conflicting = self._attempt_record(
                "collision-attempt", phase="merge", exit_code=23,
                finished_at="2026-08-04T10:00:02+08:00",
            )
            with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                PIPELINE_STATUS.write_attempt_ledger(ledger, conflicting)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(sorted(item.name for item in ledger.iterdir()), [path.name])

    def test_fallback_accepts_only_exact_existing_terminal_without_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ledger = root / "ledger"
            metadata = {
                "schema_version": 1,
                "kind": "fb_attempt",
                "attempt_id": "fallback-exact",
                "run_id": "fallback-exact",
                "release_id": "release-test",
                "ledger_dir": str(ledger.resolve()),
                "started_at": "2026-08-04T10:00:00+08:00",
            }
            exact = self._attempt_record(
                "fallback-exact", phase="unknown", exit_code=143
            )
            exact_path = PIPELINE_STATUS.write_attempt_ledger(ledger, exact)
            exact_bytes = exact_path.read_bytes()
            self.assertTrue(LOCKED_EXEC.ensure_fallback_terminal(metadata, 143))
            self.assertEqual(exact_path.read_bytes(), exact_bytes)
            self.assertEqual(len(list(ledger.glob("*.json"))), 1)

            conflicting_metadata = {
                **metadata,
                "attempt_id": "fallback-conflict",
                "run_id": "fallback-conflict",
                "started_at": "2026-08-04T11:00:00+08:00",
            }
            conflicting = self._attempt_record(
                "fallback-conflict", phase="unknown", exit_code=143,
                started_at="2026-08-04T10:59:59+08:00",
                finished_at="2026-08-04T11:00:01+08:00",
            )
            conflict_path = PIPELINE_STATUS.write_attempt_ledger(
                ledger, conflicting
            )
            conflict_bytes = conflict_path.read_bytes()
            self.assertFalse(
                LOCKED_EXEC.ensure_fallback_terminal(conflicting_metadata, 143)
            )
            self.assertEqual(conflict_path.read_bytes(), conflict_bytes)
            self.assertEqual(len(list(ledger.glob("*.json"))), 2)

    def test_active_attempt_staging_hides_old_prefix_and_blocks_exact_success(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "ledger"
            for index in range(2):
                PIPELINE_STATUS.write_attempt_ledger(
                    ledger,
                    self._attempt_record(
                        f"old-failure-{index}", phase="verify", exit_code=2,
                        started_at=f"2026-08-0{index + 1}T10:00:00+08:00",
                        finished_at=f"2026-08-0{index + 1}T10:00:01+08:00",
                    ),
                )
            success = PIPELINE_STATUS.make_attempt_record(
                attempt_id="exact-success",
                run_id="exact-success",
                release_id="release-test",
                phase="complete",
                exit_code=0,
                publish_ok=True,
                terminated_early=False,
                truncated=0,
                pending=0,
                failed=0,
                body_complete=True,
                started_at="2026-08-04T10:00:00+08:00",
                finished_at="2026-08-04T10:00:01+08:00",
            )
            PIPELINE_STATUS.write_attempt_ledger(ledger, success)
            staging = ledger / f".active-attempt.{os.getpid()}.{time.time_ns()}.tmp"
            descriptor = os.open(
                str(staging), os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600
            )
            try:
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                snapshot = PIPELINE_STATUS.inspect_attempt_ledger(ledger)
                self.assertEqual(
                    snapshot,
                    {"available": False, "busy": True, "records": []},
                )
                with self.assertRaises(PIPELINE_STATUS.AttemptLedgerBusy):
                    PIPELINE_STATUS.read_attempt_ledger(ledger)
                with redirect_stderr(io.StringIO()):
                    check_code = PIPELINE_STATUS.main([
                        "--check-success-ledger",
                        "--ledger-dir", str(ledger),
                        "--attempt-id", "exact-success",
                        "--release-id", "release-test",
                    ])
                self.assertEqual(check_code, 1)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

            with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                PIPELINE_STATUS.inspect_attempt_ledger(ledger)
            staging.unlink()
            snapshot = PIPELINE_STATUS.inspect_attempt_ledger(ledger)
            self.assertTrue(snapshot["available"])
            self.assertFalse(snapshot["busy"])
            self.assertEqual(len(snapshot["records"]), 3)
            self.assertEqual(
                PIPELINE_STATUS.main([
                    "--check-success-ledger",
                    "--ledger-dir", str(ledger),
                    "--attempt-id", "exact-success",
                    "--release-id", "release-test",
                ]),
                0,
            )

    def test_attempt_ledger_atomic_fault_leaves_no_partial_record(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "ledger"
            record = self._attempt_record("atomic-fault")
            original_fsync = PIPELINE_STATUS.os.fsync
            calls = []

            def fail_first_fsync(descriptor):
                calls.append(descriptor)
                if len(calls) == 1:
                    raise OSError("injected fsync fault")
                return original_fsync(descriptor)

            with mock.patch.object(PIPELINE_STATUS.os, "fsync", side_effect=fail_first_fsync):
                with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                    PIPELINE_STATUS.write_attempt_ledger(ledger, record)
            self.assertFalse((ledger / "atomic-fault.json").exists())
            self.assertFalse(list(ledger.glob(".*.tmp")))

    def test_attempt_semantic_tuple_contract_rejects_all_cross_class_mutations(self):
        for exit_code in (129, 130, 143):
            for phase in sorted(PIPELINE_STATUS.PHASES):
                with self.subTest(exit_code=exit_code, phase=phase):
                    record = self._attempt_record(
                        f"signal-{exit_code}-{phase}", phase=phase, exit_code=exit_code
                    )
                    self.assertEqual(record["signature"], "recoverable_interrupted")
                    self.assertFalse(record["pause_recommended"])
                    for mutation in (
                        {"signature": f"recoverable_{phase}_error"},
                        {"pause_recommended": True},
                        {"state": "partial"},
                    ):
                        with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                            PIPELINE_STATUS.validate_attempt_record({**record, **mutation})

        valid_records = [
            PIPELINE_STATUS.make_attempt_record(
                attempt_id="semantic-success", run_id="semantic-success",
                release_id="release-test", phase="complete", exit_code=0,
                publish_ok=True, terminated_early=False, truncated=0, pending=0,
                failed=0, body_complete=True,
                started_at="2026-08-04T10:00:00+08:00",
                finished_at="2026-08-04T10:00:01+08:00",
            ),
            PIPELINE_STATUS.make_attempt_record(
                attempt_id="semantic-skip", run_id="semantic-skip",
                release_id="release-test", phase="complete", exit_code=0,
                publish_ok=False, terminated_early=False, truncated=0, pending=0,
                failed=0, skipped=True,
                started_at="2026-08-04T10:00:00+08:00",
                finished_at="2026-08-04T10:00:01+08:00",
            ),
            PIPELINE_STATUS.make_attempt_record(
                attempt_id="semantic-partial", run_id="semantic-partial",
                release_id="release-test", phase="verify", exit_code=0,
                publish_ok=False, terminated_early=False, truncated=1, pending=0,
                failed=0, body_complete=True,
                started_at="2026-08-04T10:00:00+08:00",
                finished_at="2026-08-04T10:00:01+08:00",
            ),
        ]
        for record in valid_records:
            for field, value in (
                ("exit_code", 2),
                ("signature", "recoverable_verify_error"),
                ("pause_recommended", True),
            ):
                with self.subTest(state=record["state"], field=field):
                    with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                        PIPELINE_STATUS.validate_attempt_record({**record, field: value})

    def test_attempt_ledger_faults_never_report_failure_with_readable_final(self):
        operations = (
            (PIPELINE_STATUS.os, "fsync"),
            (PIPELINE_STATUS.os, "stat"),
            (PIPELINE_STATUS.os, "fstat"),
            (PIPELINE_STATUS.os, "link"),
            (PIPELINE_STATUS.os, "unlink"),
            (PIPELINE_STATUS, "_close_fd"),
        )

        def count_clean_calls(owner, name):
            original = getattr(owner, name)
            calls = 0

            def counting(*args, **kwargs):
                nonlocal calls
                calls += 1
                return original(*args, **kwargs)

            with tempfile.TemporaryDirectory() as td, \
                 mock.patch.object(owner, name, side_effect=counting):
                PIPELINE_STATUS.write_attempt_ledger(
                    Path(td) / "ledger",
                    self._attempt_record(f"count-{name}"),
                )
            return calls

        for owner, name in operations:
            clean_count = count_clean_calls(owner, name)
            self.assertGreater(clean_count, 0, name)
            timings = ("before", "after")
            for timing in timings:
                for failing_call in range(1, clean_count + 1):
                    with self.subTest(operation=name, timing=timing, call=failing_call), \
                         tempfile.TemporaryDirectory() as td:
                        ledger = Path(td) / "ledger"
                        attempt_id = f"fault-{name}-{timing}-{failing_call}"
                        record = self._attempt_record(attempt_id)
                        original = getattr(owner, name)
                        calls = 0

                        def injected(*args, **kwargs):
                            nonlocal calls
                            calls += 1
                            if calls == failing_call:
                                if timing == "after":
                                    original(*args, **kwargs)
                                raise OSError(f"injected {name} {timing} fault")
                            return original(*args, **kwargs)

                        succeeded = False
                        with mock.patch.object(owner, name, side_effect=injected):
                            try:
                                PIPELINE_STATUS.write_attempt_ledger(ledger, record)
                                succeeded = True
                            except PIPELINE_STATUS.AttemptLedgerError:
                                pass

                        if succeeded:
                            self.assertTrue((ledger / f"{attempt_id}.json").exists())
                        else:
                            try:
                                parsed = PIPELINE_STATUS.read_attempt_ledger(ledger)
                            except PIPELINE_STATUS.AttemptLedgerError:
                                continue
                            self.assertNotIn(
                                attempt_id, {item["attempt_id"] for item in parsed},
                                "an API failure exposed a strictly readable final record",
                            )

    def test_attempt_ledger_unproven_rollback_leaves_detectable_uncertainty(self):
        def fail_commit_fsync_then(*, fail_rollback_fsync=False, unlink_call=None,
                                   unlink_after=False):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            ledger = Path(temporary.name) / "ledger"
            record = self._attempt_record(
                f"uncertain-{fail_rollback_fsync}-{unlink_call}-{unlink_after}"
            )
            original_fsync = PIPELINE_STATUS.os.fsync
            original_unlink = PIPELINE_STATUS.os.unlink
            fsync_calls = 0
            unlink_calls = 0

            def fsync_fault(*args, **kwargs):
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 2 or (fail_rollback_fsync and fsync_calls == 3):
                    raise OSError("injected directory fsync failure")
                return original_fsync(*args, **kwargs)

            def unlink_fault(*args, **kwargs):
                nonlocal unlink_calls
                unlink_calls += 1
                if unlink_call == unlink_calls:
                    if unlink_after:
                        original_unlink(*args, **kwargs)
                    raise OSError("injected rollback unlink failure")
                return original_unlink(*args, **kwargs)

            with mock.patch.object(PIPELINE_STATUS.os, "fsync", side_effect=fsync_fault), \
                 mock.patch.object(PIPELINE_STATUS.os, "unlink", side_effect=unlink_fault):
                with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                    PIPELINE_STATUS.write_attempt_ledger(ledger, record)
            return ledger

        # Final unlink did not happen: final+staging aliases remain and the
        # whole ledger is rejected rather than presenting a committed record.
        for ledger in (
            fail_commit_fsync_then(unlink_call=1),
            fail_commit_fsync_then(unlink_call=2),
            fail_commit_fsync_then(fail_rollback_fsync=True),
        ):
            with self.subTest(entries=sorted(item.name for item in ledger.iterdir())):
                with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                    PIPELINE_STATUS.read_attempt_ledger(ledger)

        # An unlink that completed and then raised is still provably rolled
        # back once the directory fsync and absence check succeed.
        proven = fail_commit_fsync_then(unlink_call=1, unlink_after=True)
        self.assertEqual(PIPELINE_STATUS.read_attempt_ledger(proven), [])

    def test_link_completed_then_link_and_probe_errors_leave_uncertain_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "ledger"
            record = self._attempt_record("link-probe-uncertain")
            original_link = PIPELINE_STATUS.os.link
            original_stat = PIPELINE_STATUS.os.stat
            stat_calls = 0

            def link_then_error(*args, **kwargs):
                original_link(*args, **kwargs)
                raise OSError("link completed then reported an error")

            def fail_probe_stat(*args, **kwargs):
                nonlocal stat_calls
                stat_calls += 1
                # pre-existing-final check, staging-name check, then the
                # post-link result probe from the exception path.
                if stat_calls == 3:
                    raise OSError("cannot determine link result")
                return original_stat(*args, **kwargs)

            with mock.patch.object(PIPELINE_STATUS.os, "link", side_effect=link_then_error), \
                 mock.patch.object(PIPELINE_STATUS.os, "stat", side_effect=fail_probe_stat):
                with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                    PIPELINE_STATUS.write_attempt_ledger(ledger, record)
            self.assertTrue((ledger / "link-probe-uncertain.json").exists())
            self.assertTrue(list(ledger.glob(".*.tmp")))
            with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                PIPELINE_STATUS.read_attempt_ledger(ledger)

    def test_post_durable_cleanup_faults_do_not_reverse_commit_success(self):
        cases = ("temp_unlink", "second_directory_fsync", "final_stat", "temp_close")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                ledger = Path(td) / "ledger"
                attempt_id = f"durable-{case}"
                record = self._attempt_record(attempt_id)
                if case == "temp_unlink":
                    original = PIPELINE_STATUS.os.unlink
                    calls = 0

                    def fault(*args, **kwargs):
                        nonlocal calls
                        calls += 1
                        if calls == 1:
                            raise OSError("cannot remove durable staging alias")
                        return original(*args, **kwargs)

                    patcher = mock.patch.object(PIPELINE_STATUS.os, "unlink", side_effect=fault)
                elif case == "second_directory_fsync":
                    original = PIPELINE_STATUS.os.fsync
                    calls = 0

                    def fault(*args, **kwargs):
                        nonlocal calls
                        calls += 1
                        if calls == 3:
                            raise OSError("second directory fsync failed")
                        return original(*args, **kwargs)

                    patcher = mock.patch.object(PIPELINE_STATUS.os, "fsync", side_effect=fault)
                elif case == "final_stat":
                    original = PIPELINE_STATUS.os.stat
                    calls = 0

                    def fault(*args, **kwargs):
                        nonlocal calls
                        calls += 1
                        if calls == 5:
                            raise OSError("post-cleanup final stat failed")
                        return original(*args, **kwargs)

                    patcher = mock.patch.object(PIPELINE_STATUS.os, "stat", side_effect=fault)
                else:
                    original = PIPELINE_STATUS._close_fd
                    calls = 0

                    def fault(*args, **kwargs):
                        nonlocal calls
                        calls += 1
                        result = original(*args, **kwargs)
                        if calls == 1:
                            raise OSError("close completed then failed")
                        return result

                    patcher = mock.patch.object(PIPELINE_STATUS, "_close_fd", side_effect=fault)

                with patcher:
                    committed = PIPELINE_STATUS.write_attempt_ledger(ledger, record)
                self.assertEqual(committed.name, f"{attempt_id}.json")
                self.assertTrue(committed.exists())
                if case == "temp_unlink":
                    with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                        PIPELINE_STATUS.read_attempt_ledger(ledger)
                else:
                    self.assertEqual(
                        PIPELINE_STATUS.read_attempt_ledger(ledger), [record]
                    )

    def test_attempt_ledger_rejects_raw_or_secret_like_values_before_writing(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "ledger"
            record = self._attempt_record("secret-reject")
            record["signature"] = "https://example.invalid/?access_token=secret-value"
            with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                PIPELINE_STATUS.write_attempt_ledger(ledger, record)
            raw_field = self._attempt_record("raw-field-reject")
            raw_field["stderr"] = "Authorization: Bearer definitely-not-a-ledger-field"
            with self.assertRaises(PIPELINE_STATUS.AttemptLedgerError):
                PIPELINE_STATUS.write_attempt_ledger(ledger, raw_field)
            self.assertFalse(ledger.exists())


class GitPagesPublisherTest(unittest.TestCase):
    MONTH = "2026-08"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote.git"
        self.seed = self.root / "seed"
        self.publish = self.root / "publish"
        self.month_dir = self.root / "data" / self.MONTH
        self.month_dir.mkdir(parents=True)
        self.dashboard = self.month_dir / "fb_verify_dashboard.html"
        self.dashboard.write_bytes(b"<html>GOOD verified dashboard</html>\n")
        self.replaceable_lock = self.root / ".publish.lock"
        self.git_env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }

        self.git("init", "--bare", "--initial-branch=main", str(self.remote))
        self.git("init", "--initial-branch=main", str(self.seed))
        self.git("-C", str(self.seed), "config", "user.name", "test")
        self.git("-C", str(self.seed), "config", "user.email", "test@example.invalid")
        (self.seed / "README.md").write_text("seed\n", encoding="utf-8")
        (self.seed / "fb_verify_dashboard.html").write_bytes(b"<html>old</html>\n")
        self.git("-C", str(self.seed), "add", "README.md", "fb_verify_dashboard.html")
        self.git("-C", str(self.seed), "commit", "--no-gpg-sign", "-m", "seed")
        self.git("-C", str(self.seed), "remote", "add", "origin", str(self.remote))
        self.git("-C", str(self.seed), "push", "origin", "main")
        self.git("clone", "--branch", "main", str(self.remote), str(self.publish))
        self.initial = self.remote_head()

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args, check=True, text=True):
        return subprocess.run(
            ["git", *args], check=check, capture_output=True, text=text,
            env=self.git_env,
        )

    def invoke(self, *extra, env=None):
        return subprocess.run([
            sys.executable, str(SCRIPTS / "publish_fb_pages.py"),
            "--repo", str(self.remote),
            "--worktree", str(self.publish),
            "--month", self.MONTH,
            "--dashboard-source", str(self.dashboard),
            *extra,
        ], capture_output=True, text=True, env={
            **self.git_env,
            "FB_VERIFY_TEST_MODE": "1",
            **(env or {}),
        })

    def journal_path(self):
        return self.root / ".publish.fb-pages-publish-journal.json"

    def remote_head(self):
        return self.git(
            "--git-dir", str(self.remote), "rev-parse", "refs/heads/main"
        ).stdout.strip()

    def remote_bytes(self, commit, path="fb_verify_dashboard.html"):
        return self.git(
            "--git-dir", str(self.remote), "show", f"{commit}:{path}",
            text=False,
        ).stdout

    def assert_publish_checkout_clean_at(self, commit):
        self.assertEqual(
            self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(),
            commit,
        )

    def assert_crash_recovers_to_one_good_commit(self, point, *extra):
        crashed = self.invoke(*extra, env={"FB_VERIFY_TEST_CRASH_AT": point})
        self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stderr)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertTrue(self.journal_path().exists())

        recovered = self.invoke(*extra)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        after = self.remote_head()
        self.assertEqual(
            self.git(
                "--git-dir", str(self.remote), "rev-list", "--count",
                f"{self.initial}..{after}",
            ).stdout.strip(),
            "1",
        )
        self.assertEqual(
            self.git("--git-dir", str(self.remote), "rev-parse", f"{after}^").stdout.strip(),
            self.initial,
        )
        self.assertEqual(self.remote_bytes(after), self.dashboard.read_bytes())
        self.assertFalse(self.journal_path().exists())
        self.assert_publish_checkout_clean_at(after)
        return after

    def assert_real_git_add_child_crash_recovers(self, *extra):
        """Kill the publisher from a PATH git wrapper after real `git add`.

        This is deliberately not the publisher's add fault hook: the real Git
        child has already updated the index while the durable journal still
        says staged_paths=None.
        """
        wrapper_dir = self.root / "git-wrapper"
        wrapper_dir.mkdir()
        ready = self.root / "real-add-complete"
        wrapper = wrapper_dir / "git"
        wrapper.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            '"${FB_REAL_GIT:?}" "$@"\n'
            "status=$?\n"
            "if [ \"$status\" -eq 0 ]; then\n"
            "  for argument in \"$@\"; do\n"
            "    if [ \"$argument\" = add ]; then\n"
            '      : > "${FB_REAL_ADD_READY:?}"\n'
            "      kill -KILL \"$PPID\"\n"
            "      break\n"
            "    fi\n"
            "  done\n"
            "fi\n"
            "exit \"$status\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        crashed = self.invoke(
            *extra,
            env={
                "PATH": f"{wrapper_dir}{os.pathsep}{os.environ['PATH']}",
                "FB_REAL_GIT": shutil.which("git"),
                "FB_REAL_ADD_READY": str(ready),
            },
        )
        self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stderr)
        self.assertTrue(ready.exists())
        self.assertEqual(self.remote_head(), self.initial)
        journal = json.loads(self.journal_path().read_text(encoding="utf-8"))
        self.assertIsNone(journal["staged_paths"])
        self.assertTrue(journal["planned_paths"])

        recovered = self.invoke(*extra)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        after = self.remote_head()
        self.assertEqual(
            self.git("--git-dir", str(self.remote), "rev-list", "--count", f"{self.initial}..{after}").stdout.strip(),
            "1",
        )
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", f"{after}^").stdout.strip(), self.initial)
        self.assertFalse(self.journal_path().exists())
        self.assert_publish_checkout_clean_at(after)
        return after

    def invoke_killed_after_real_rollback_clean(self, *, env=None):
        """Kill the publisher after real reset+clean, before journal clear."""
        wrapper_dir = self.root / "rollback-git-wrapper"
        wrapper_dir.mkdir(exist_ok=True)
        ready = self.root / "real-rollback-clean-complete"
        wrapper = wrapper_dir / "git"
        wrapper.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            '"${FB_REAL_GIT:?}" "$@"\n'
            "status=$?\n"
            "if [ \"$status\" -eq 0 ]; then\n"
            "  for argument in \"$@\"; do\n"
            "    if [ \"$argument\" = clean ] && [ ! -e \"${FB_ROLLBACK_CLEAN_READY:?}\" ]; then\n"
            '      : > "${FB_ROLLBACK_CLEAN_READY:?}"\n'
            "      kill -KILL \"$PPID\"\n"
            "      break\n"
            "    fi\n"
            "  done\n"
            "fi\n"
            "exit \"$status\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        result = self.invoke(env={
            "PATH": f"{wrapper_dir}{os.pathsep}{os.environ['PATH']}",
            "FB_REAL_GIT": shutil.which("git"),
            "FB_ROLLBACK_CLEAN_READY": str(ready),
            **(env or {}),
        })
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        self.assertTrue(ready.exists())
        self.assertEqual(self.remote_head(), self.initial)
        self.assert_publish_checkout_clean_at(self.initial)
        self.assertEqual(
            self.git(
                "-C", str(self.publish), "status", "--porcelain=v1",
                "--untracked-files=all",
            ).stdout,
            "",
        )
        self.assertTrue(self.journal_path().exists())
        return json.loads(self.journal_path().read_text(encoding="utf-8"))

    def test_sigkill_after_page_write_recovers_without_bad_ancestor(self):
        self.assert_crash_recovers_to_one_good_commit("write")

    def test_sigkill_after_temp_fsync_before_replace_recovers_without_orphan(self):
        self.assert_crash_recovers_to_one_good_commit("temp_after_fsync")

    def test_sigkill_after_git_add_recovers_without_bad_ancestor(self):
        self.assert_crash_recovers_to_one_good_commit("add")

    def test_real_git_add_completion_before_journal_update_recovers_one_good_commit(self):
        self.assert_real_git_add_child_crash_recovers()

    def test_real_git_add_completion_with_month_batch_recovers_one_good_commit(self):
        batch = self.month_dir / "batches" / "add-window.html"
        batch.parent.mkdir()
        batch.write_bytes(b"<html>batch add-window</html>\n")
        destination = f"fb_verify_batches/{self.MONTH}/{batch.name}"
        after = self.assert_real_git_add_child_crash_recovers(
            "--batch-source", str(batch), "--batch-destination", destination,
        )
        self.assertEqual(self.remote_bytes(after, destination), batch.read_bytes())

    def test_sigkill_after_commit_recovers_without_bad_ancestor(self):
        self.assert_crash_recovers_to_one_good_commit("commit")

    def test_sigkill_after_push_before_cleanup_converges_to_remote_commit(self):
        crashed = self.invoke(env={"FB_VERIFY_TEST_CRASH_AT": "push"})
        self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stderr)
        pushed = self.remote_head()
        self.assertNotEqual(pushed, self.initial)
        self.assertTrue(self.journal_path().exists())

        recovered = self.invoke()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(self.remote_head(), pushed)
        self.assertEqual(
            self.git(
                "--git-dir", str(self.remote), "rev-list", "--count",
                f"{self.initial}..{pushed}",
            ).stdout.strip(),
            "1",
        )
        self.assertFalse(self.journal_path().exists())
        self.assert_publish_checkout_clean_at(pushed)

    def test_push_reject_kill_after_completed_rollback_recovers_one_good_commit(self):
        reject_once = self.root / "rollback-reject-once"
        reject_once.write_text("reject\n", encoding="utf-8")
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            f"flag = pathlib.Path({str(reject_once)!r})\n"
            "reject = flag.exists()\n"
            "flag.unlink(missing_ok=True)\n"
            "raise SystemExit(1 if reject else 0)\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)

        journal = self.invoke_killed_after_real_rollback_clean()
        self.assertTrue(journal["staged_paths"])
        self.assertIsNotNone(journal["verified_commit"])
        recovered = self.invoke()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        after = self.remote_head()
        self.assertEqual(
            self.git("--git-dir", str(self.remote), "rev-list", "--count", f"{self.initial}..{after}").stdout.strip(),
            "1",
        )
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", f"{after}^").stdout.strip(), self.initial)
        self.assertFalse(self.journal_path().exists())

    def test_exception_kill_after_completed_rollback_recovers_one_good_commit(self):
        journal = self.invoke_killed_after_real_rollback_clean(
            env={"FB_VERIFY_TEST_FAIL_AT": "after_add_journal"},
        )
        self.assertTrue(journal["staged_paths"])
        self.assertIsNone(journal["verified_commit"])
        recovered = self.invoke()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        after = self.remote_head()
        self.assertEqual(
            self.git("--git-dir", str(self.remote), "rev-list", "--count", f"{self.initial}..{after}").stdout.strip(),
            "1",
        )
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", f"{after}^").stdout.strip(), self.initial)
        self.assertFalse(self.journal_path().exists())

    def test_journal_corruption_and_unknown_user_bytes_fail_closed_without_rewrite(self):
        crashed = self.invoke(env={"FB_VERIFY_TEST_CRASH_AT": "write"})
        self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stderr)
        journal = self.journal_path()
        target = self.publish / "fb_verify_dashboard.html"
        journal.write_bytes(b"{not-json\n")
        before = (journal.read_bytes(), target.read_bytes(), self.remote_head())
        rejected = self.invoke()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual((journal.read_bytes(), target.read_bytes(), self.remote_head()), before)

        # Restore a fresh journaled write, then replace a *permitted* path
        # with third-party bytes.  Path allowlisting alone must not authorize
        # a reset of that user content.
        journal.unlink()
        self.git("-C", str(self.publish), "reset", "--hard", self.initial)
        crashed = self.invoke(env={"FB_VERIFY_TEST_CRASH_AT": "write"})
        self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stderr)
        target.write_bytes(b"<html>USER THIRD PARTY BYTES</html>\n")
        before = (self.journal_path().read_bytes(), target.read_bytes(), self.remote_head())
        rejected = self.invoke()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("unknown page bytes", rejected.stderr)
        self.assertEqual((self.journal_path().read_bytes(), target.read_bytes(), self.remote_head()), before)

    def test_clean_local_ahead_is_rejected_before_journal_or_reset(self):
        README = self.publish / "README.md"
        README.write_text("user committed local-ahead state\n", encoding="utf-8")
        self.git("-C", str(self.publish), "add", "README.md")
        self.git(
            "-C", str(self.publish), "-c", "user.name=test", "-c",
            "user.email=test@example.invalid", "commit", "--no-gpg-sign", "-m", "user ahead",
        )
        before_head = self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip()
        before_bytes = README.read_bytes()
        rejected = self.invoke()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(), before_head)
        self.assertEqual(README.read_bytes(), before_bytes)
        self.assertFalse(self.journal_path().exists())

    def test_batch_only_commit_survives_sigkill_after_commit(self):
        # Make the canonical monthly page equal to its remote baseline, so
        # only the batch file is committed.  Recovery must use staged_paths,
        # not the full release allowlist, when validating the commit diff.
        (self.seed / "fb_verify_dashboard.html").write_bytes(self.dashboard.read_bytes())
        self.git("-C", str(self.seed), "add", "fb_verify_dashboard.html")
        self.git("-C", str(self.seed), "commit", "--no-gpg-sign", "-m", "align dashboard")
        self.git("-C", str(self.seed), "push", "origin", "main")
        self.git("-C", str(self.publish), "pull", "--ff-only")
        self.initial = self.remote_head()
        batch = self.month_dir / "batches" / "only-batch.html"
        batch.parent.mkdir()
        batch.write_bytes(b"<html>only changed batch</html>\n")
        destination = f"fb_verify_batches/{self.MONTH}/{batch.name}"
        self.assert_crash_recovers_to_one_good_commit(
            "commit", "--batch-source", str(batch), "--batch-destination", destination,
        )
        self.assertEqual(
            self.git(
                "-C", str(self.publish), "status", "--porcelain=v1",
                "--untracked-files=all",
            ).stdout,
            "",
        )

    def test_clean_filter_cannot_change_committed_bytes_or_claim_success(self):
        filter_script = self.root / "hostile_clean_filter.py"
        filter_script.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read().replace(b'GOOD', b'ATTACK'))\n",
            encoding="utf-8",
        )
        filter_script.chmod(0o755)
        self.git(
            "-C", str(self.publish), "config", "filter.hostile.clean", str(filter_script)
        )
        self.git("-C", str(self.publish), "config", "filter.hostile.smudge", "cat")
        self.git("-C", str(self.publish), "config", "filter.hostile.required", "true")
        (self.publish / ".git" / "info" / "attributes").write_text(
            "fb_verify_dashboard.html filter=hostile\n", encoding="utf-8"
        )

        rejected = self.invoke()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("cleanup refused", rejected.stderr)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertEqual(
            self.remote_bytes(self.initial), b"<html>old</html>\n"
        )
        self.assertTrue(self.journal_path().exists())

    def test_rejected_push_rolls_back_so_retry_has_one_good_commit(self):
        reject_once = self.root / "reject-once"
        reject_once.write_text("reject\n", encoding="utf-8")
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            f"flag = pathlib.Path({str(reject_once)!r})\n"
            "reject = flag.exists()\n"
            "flag.unlink(missing_ok=True)\n"
            "raise SystemExit(1 if reject else 0)\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)

        first = self.invoke()
        self.assertNotEqual(first.returncode, 0)
        self.assertEqual(self.remote_head(), self.initial)
        self.assert_publish_checkout_clean_at(self.initial)

        second = self.invoke()
        self.assertEqual(second.returncode, 0, second.stderr)
        after = self.remote_head()
        self.assertNotEqual(after, self.initial)
        self.assertEqual(
            self.git(
                "--git-dir", str(self.remote), "rev-list", "--count",
                f"{self.initial}..{after}",
            ).stdout.strip(),
            "1",
        )
        self.assertEqual(
            self.git("--git-dir", str(self.remote), "rev-parse", f"{after}^").stdout.strip(),
            self.initial,
        )
        self.assertEqual(self.remote_bytes(after), self.dashboard.read_bytes())
        self.assert_publish_checkout_clean_at(after)

    def test_pre_push_attacker_child_leaves_unknown_local_commit_fail_closed(self):
        hook = self.publish / ".git" / "hooks" / "pre-push"
        hook.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, subprocess\n"
            f"repo = pathlib.Path({str(self.publish)!r})\n"
            "(repo / 'fb_verify_dashboard.html').write_bytes(b'<html>ATTACK child</html>\\n')\n"
            "subprocess.run(['git','-C',str(repo),'add','--','fb_verify_dashboard.html'], check=True)\n"
            "subprocess.run(['git','-C',str(repo),'-c','user.name=attacker',"
            "'-c','user.email=attacker@example.invalid','commit','--no-gpg-sign',"
            "'-m','attacker child'], check=True, stdout=subprocess.DEVNULL)\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)

        completed = self.invoke()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("cleanup refused", completed.stderr)
        after = self.remote_head()
        self.assertEqual(self.remote_bytes(after), self.dashboard.read_bytes())
        self.assertNotIn(b"ATTACK", self.remote_bytes(after))
        self.assertEqual(
            self.git(
                "--git-dir", str(self.remote), "rev-list", "--count",
                f"{self.initial}..{after}",
            ).stdout.strip(),
            "1",
        )
        self.assertTrue(self.journal_path().exists())

    def test_remote_ref_race_is_rejected_by_the_exact_lease(self):
        hook = self.publish / ".git" / "hooks" / "pre-push"
        hook.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, subprocess\n"
            f"remote = pathlib.Path({str(self.remote)!r})\n"
            f"initial = {self.initial!r}\n"
            "base = ['git', '--git-dir', str(remote)]\n"
            "tree = subprocess.run(base + ['rev-parse', initial + '^{tree}'], "
            "check=True, capture_output=True, text=True).stdout.strip()\n"
            "env = {**os.environ, 'GIT_AUTHOR_NAME':'racer', "
            "'GIT_AUTHOR_EMAIL':'racer@example.invalid', "
            "'GIT_COMMITTER_NAME':'racer', "
            "'GIT_COMMITTER_EMAIL':'racer@example.invalid'}\n"
            "commit = subprocess.run(base + ['commit-tree', tree, '-p', initial], "
            "input='competing remote update\\n', check=True, capture_output=True, "
            "text=True, env=env).stdout.strip()\n"
            "subprocess.run(base + ['update-ref', 'refs/heads/main', commit, initial], "
            "check=True)\n"
            "pathlib.Path(__file__).unlink()\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)

        raced = self.invoke()
        self.assertNotEqual(raced.returncode, 0)
        competing = self.remote_head()
        self.assertNotEqual(competing, self.initial)
        self.assertEqual(self.remote_bytes(competing), b"<html>old</html>\n")
        self.assert_publish_checkout_clean_at(self.initial)

        retried = self.invoke()
        self.assertEqual(retried.returncode, 0, retried.stderr)
        published = self.remote_head()
        self.assertEqual(self.remote_bytes(published), self.dashboard.read_bytes())
        self.assertEqual(
            self.git(
                "--git-dir", str(self.remote), "rev-parse", f"{published}^"
            ).stdout.strip(),
            competing,
        )
        self.assert_publish_checkout_clean_at(published)

    def test_publish_lock_is_nonblocking_and_covers_the_transaction(self):
        self.replaceable_lock.write_text("old lock inode\n", encoding="utf-8")
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(self.root, directory_flags)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Replacing the legacy ordinary lock-file path cannot manufacture
            # another publisher lock: all publishers flock this directory.
            renamed = self.root / ".publish.lock.old"
            self.replaceable_lock.rename(renamed)
            self.replaceable_lock.write_text("new lock inode\n", encoding="utf-8")
            blocked = self.invoke()
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertEqual(blocked.returncode, 75, blocked.stderr)
        self.assertIn("lock is busy", blocked.stderr)
        self.assertEqual(self.remote_head(), self.initial)
        self.assert_publish_checkout_clean_at(self.initial)

    def test_dirty_worktree_is_rejected_without_overwriting_user_state(self):
        unrelated = self.publish / "unrelated-user-file.txt"
        unrelated.write_text("keep me\n", encoding="utf-8")
        rejected = self.invoke()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("worktree or index is not clean", rejected.stderr)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep me\n")
        self.assertEqual(
            self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(),
            self.initial,
        )
        unrelated.unlink()
        (self.publish / "README.md").write_text("staged user change\n", encoding="utf-8")
        self.git("-C", str(self.publish), "add", "README.md")
        staged_rejected = self.invoke()
        self.assertNotEqual(staged_rejected.returncode, 0)
        self.assertIn("worktree or index is not clean", staged_rejected.stderr)
        self.assertEqual(self.remote_head(), self.initial)
        self.assertEqual(
            self.git("-C", str(self.publish), "show", ":README.md").stdout,
            "staged user change\n",
        )

    def test_ignored_existing_batch_third_party_bytes_are_never_overwritten(self):
        batch = self.month_dir / "batches" / "ignored-existing.html"
        batch.parent.mkdir()
        batch.write_bytes(b"<html>publisher source</html>\n")
        destination = f"fb_verify_batches/{self.MONTH}/{batch.name}"
        target = self.publish / destination
        target.parent.mkdir(parents=True)
        target.write_bytes(b"<html>THIRD PARTY KEEP</html>\n")
        (self.publish / ".git" / "info" / "exclude").write_text(
            "fb_verify_batches/\n", encoding="utf-8"
        )
        before = (
            target.read_bytes(),
            self.git("-C", str(self.publish), "status", "--porcelain=v1", "--untracked-files=all").stdout,
            self.journal_path().exists(),
            self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(),
            self.remote_head(),
        )
        rejected = self.invoke(
            "--batch-source", str(batch), "--batch-destination", destination,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("ignored by Git", rejected.stderr)
        self.assertEqual(
            (
                target.read_bytes(),
                self.git("-C", str(self.publish), "status", "--porcelain=v1", "--untracked-files=all").stdout,
                self.journal_path().exists(),
                self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(),
                self.remote_head(),
            ),
            before,
        )

    def test_ignored_missing_batch_is_rejected_before_journal_or_write(self):
        batch = self.month_dir / "batches" / "ignored-missing.html"
        batch.parent.mkdir()
        batch.write_bytes(b"<html>publisher source</html>\n")
        destination = f"fb_verify_batches/{self.MONTH}/{batch.name}"
        target = self.publish / destination
        (self.publish / ".git" / "info" / "exclude").write_text(
            "fb_verify_batches/\n", encoding="utf-8"
        )
        before = (
            target.exists(), self.journal_path().exists(),
            self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(),
            self.remote_head(),
        )
        rejected = self.invoke(
            "--batch-source", str(batch), "--batch-destination", destination,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("ignored by Git", rejected.stderr)
        self.assertEqual(
            (
                target.exists(), self.journal_path().exists(),
                self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(),
                self.remote_head(),
            ),
            before,
        )

    def _assert_hidden_tracked_target_is_rejected(self, flag, clear_flag):
        target = self.publish / "fb_verify_dashboard.html"
        self.git("-C", str(self.publish), "update-index", flag, "--", target.name)
        target.write_bytes(b"<html>HIDDEN THIRD PARTY</html>\n")
        before = (target.read_bytes(), self.remote_head(), self.journal_path().exists())
        rejected = self.invoke()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertTrue(
            "differs from its tracked baseline" in rejected.stderr
            or "non-ordinary index flags" in rejected.stderr,
            rejected.stderr,
        )
        self.assertEqual((target.read_bytes(), self.remote_head(), self.journal_path().exists()), before)
        self.git("-C", str(self.publish), "update-index", clear_flag, "--", target.name)

    def test_assume_unchanged_tracked_target_is_preflighted_by_bytes(self):
        self._assert_hidden_tracked_target_is_rejected(
            "--assume-unchanged", "--no-assume-unchanged"
        )

    def test_skip_worktree_tracked_target_is_preflighted_by_bytes(self):
        self._assert_hidden_tracked_target_is_rejected(
            "--skip-worktree", "--no-skip-worktree"
        )

    def _assert_baseline_bytes_with_index_flag_are_rejected(self, flag, clear_flag):
        target = self.publish / "fb_verify_dashboard.html"
        baseline = target.read_bytes()
        self.git("-C", str(self.publish), "update-index", flag, "--", target.name)
        before = (
            target.read_bytes(),
            self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(),
            self.remote_head(),
            self.git("-C", str(self.publish), "status", "--porcelain=v1", "--untracked-files=all").stdout,
            self.git("-C", str(self.publish), "ls-files", "-v", "--", target.name).stdout,
            self.journal_path().exists(),
        )
        self.assertEqual(before[0], baseline)
        self.assertEqual(before[3], "")
        self.assertNotEqual(before[4][:1], "H")
        rejected = self.invoke()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("non-ordinary index flags", rejected.stderr)
        self.assertEqual(
            (
                target.read_bytes(),
                self.git("-C", str(self.publish), "rev-parse", "HEAD").stdout.strip(),
                self.remote_head(),
                self.git("-C", str(self.publish), "status", "--porcelain=v1", "--untracked-files=all").stdout,
                self.git("-C", str(self.publish), "ls-files", "-v", "--", target.name).stdout,
                self.journal_path().exists(),
            ),
            before,
        )
        self.git("-C", str(self.publish), "update-index", clear_flag, "--", target.name)

    def test_assume_unchanged_baseline_bytes_are_rejected_before_journal(self):
        self._assert_baseline_bytes_with_index_flag_are_rejected(
            "--assume-unchanged", "--no-assume-unchanged"
        )

    def test_skip_worktree_baseline_bytes_are_rejected_before_journal(self):
        self._assert_baseline_bytes_with_index_flag_are_rejected(
            "--skip-worktree", "--no-skip-worktree"
        )

    def test_recovery_exactly_removes_new_target_that_became_ignored(self):
        batch = self.month_dir / "batches" / "became-ignored.html"
        batch.parent.mkdir()
        batch.write_bytes(b"<html>journal-owned source</html>\n")
        destination = f"fb_verify_batches/{self.MONTH}/{batch.name}"
        target = self.publish / destination
        crashed = self.invoke(
            "--batch-source", str(batch), "--batch-destination", destination,
            env={"FB_VERIFY_TEST_CRASH_AT": "write"},
        )
        self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stderr)
        self.assertEqual(target.read_bytes(), batch.read_bytes())
        (self.publish / ".git" / "info" / "exclude").write_text(
            "fb_verify_batches/\n", encoding="utf-8"
        )
        self.git("-C", str(self.publish), "reset", "--hard", self.initial)
        self.git("-C", str(self.publish), "clean", "-f", "-d", "--", destination)
        self.assertTrue(target.exists(), "ignored target must survive ordinary git clean")
        self.assertEqual(
            self.git("-C", str(self.publish), "status", "--porcelain=v1", "--untracked-files=all").stdout,
            "",
        )

        recovered_then_rejected = self.invoke(
            "--batch-source", str(batch), "--batch-destination", destination,
        )
        self.assertNotEqual(recovered_then_rejected.returncode, 0)
        self.assertIn("ignored by Git", recovered_then_rejected.stderr)
        self.assertFalse(target.exists())
        self.assertFalse(self.journal_path().exists())
        self.assert_publish_checkout_clean_at(self.initial)
        (self.publish / ".git" / "info" / "exclude").write_text("", encoding="utf-8")
        retried = self.invoke(
            "--batch-source", str(batch), "--batch-destination", destination,
        )
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertEqual(self.remote_bytes(self.remote_head(), destination), batch.read_bytes())

    def test_missing_dedicated_checkout_is_cloned_inside_the_publish_lock(self):
        shutil.rmtree(self.publish)
        completed = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        after = self.remote_head()
        self.assertEqual(self.remote_bytes(after), self.dashboard.read_bytes())
        self.assert_publish_checkout_clean_at(after)
        unchanged = self.invoke()
        self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
        self.assertTrue(unchanged.stdout.startswith("no-changes:"), unchanged.stdout)
        self.assertEqual(self.remote_head(), after)

    def test_month_bound_batch_path_and_bytes_publish_in_same_commit(self):
        batch = self.month_dir / "batches" / "run-001.html"
        batch.parent.mkdir()
        batch.write_bytes(b"<html>GOOD batch</html>\n")
        destination = f"fb_verify_batches/{self.MONTH}/{batch.name}"
        completed = self.invoke(
            "--batch-source", str(batch),
            "--batch-destination", destination,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        after = self.remote_head()
        self.assertEqual(self.remote_bytes(after), self.dashboard.read_bytes())
        self.assertEqual(self.remote_bytes(after, destination), batch.read_bytes())
        changed = set(self.git(
            "--git-dir", str(self.remote), "diff-tree", "--no-commit-id",
            "--name-only", "--no-renames", "-r", after,
        ).stdout.splitlines())
        self.assertEqual(changed, {"fb_verify_dashboard.html", destination})
        self.assert_publish_checkout_clean_at(after)


class VerificationSchemaTest(unittest.TestCase):
    def test_phantom_positive_without_sample_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "contradicts evidence"):
            VERIFY_SCHEMA.migrate_verification_record({
                "verification_state": "positive",
                "relevant_ads_count": 4,
                "harvested": 0,
                "relevant_ads": [],
            })
        migrated = VERIFY_SCHEMA.migrate_verification_record({
            "schema_version": 1,
            "response_http_status": 200,
            "fb_total_reported": 0,
            "harvested": 0,
            "relevant_ads_count": 5,
            "relevant_ads": [],
        })
        self.assertEqual(migrated["verification_state"], "inconclusive")
        self.assertEqual(migrated["schema_version"], 2)

    def test_schema1_strict_thousands_are_canonicalized_but_schema2_strings_fail(self):
        migrated = VERIFY_SCHEMA.migrate_verification_record({
            "schema_version": 1,
            "fb_total_reported": "33,000",
            "harvested": "30",
            "relevant_ads_count": "0",
        })
        self.assertEqual(migrated["fb_total_reported"], 33000)
        self.assertEqual(migrated["harvested"], 30)
        self.assertEqual(migrated["verification_state"], "sample_negative")
        with self.assertRaisesRegex(ValueError, "invalid fb_total_reported"):
            VERIFY_SCHEMA.migrate_verification_record({
                "schema_version": 1, "fb_total_reported": "1,40",
            })
        with self.assertRaisesRegex(ValueError, "invalid fb_total_reported"):
            VERIFY_SCHEMA.migrate_verification_record({
                "schema_version": 2, "producer": "fb-verify-runner",
                "fb_total_reported": "1400", "verification_state": "inconclusive",
            })


if __name__ == "__main__":
    unittest.main()
