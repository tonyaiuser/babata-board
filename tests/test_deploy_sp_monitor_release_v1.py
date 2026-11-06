import copy
import datetime
import hashlib
import json
import os
import plistlib
import socket
import stat
import subprocess
import sys
import tempfile
import traceback
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts import deploy_sp_monitor_release_v1 as deploy
from scripts import sp_monitor_release_manifest_v1 as manifest


ROOT = Path(__file__).resolve().parents[1]
POLICY_BYTES = (ROOT / "config" / "sp_monitor_release_manifest_v1.json").read_bytes()


class FixedClock:
    def now(self): return datetime.datetime(2026, 8, 5, 3, 0, tzinfo=datetime.timezone.utc)  # 11:00 Shanghai


class FakeInspector(deploy.ProcessInspector):
    def __init__(self, policy, runtime, ops): self.policy, self.runtime, self.ops = policy, runtime, ops; self.active = False
    def repo_state(self, repo_root): return {"clean": True, "ref": "refs/heads/main", "commit": self.runtime["repository"]["commit"], "merge_proven": True}
    def main_state(self, plist):
        return {"loaded": True, "enabled": True, "pid": None, "argv": [self.ops.resolve(plist["interpreter"]), self.ops.resolve(plist["entrypoint"]), *plist["arguments"]]}
    def process_scan(self): return [["unrelated"]] if not self.active else [[self.ops.resolve(self.policy["deployment"]["plist"]["entrypoint"]), "--send"]]
    def dependent_state(self, item):
        return {"source_files": copy.deepcopy(item["source_files"]), "plist_sha256": item["plist_sha256"], "labels": {label: {"enabled": False, "loaded": False, "pid": None, "configured_argv": list(item["configured_argv"]), "runtime_argv": []} for label in item["labels"]}}


class DeploymentFixture:
    def __init__(self, testcase):
        self.case = testcase; self.temp = tempfile.TemporaryDirectory(dir="/private/tmp"); self.base = Path(self.temp.name); self.home = self.base / "home"; self.repo = self.base / "repo"
        self.home.mkdir(mode=0o700); self.repo.mkdir(mode=0o700)
        self.ops = deploy.Ops(lambda value: str(self.home) if value == "~" else str(self.home / value[2:]) if value.startswith("~/") else value)
        self.policy = manifest.parse_source_policy(POLICY_BYTES); self.policy = copy.deepcopy(self.policy)
        for index, item in enumerate(self.policy["deployment"]["dependent_consumers"], 1):
            item.update(plist_sha256=(str(index + 3) * 64), unresolved=False)
            for source_index, source in enumerate(item["source_files"], 1): source["sha256"] = hashlib.sha256(f"{index}:{source_index}".encode()).hexdigest()
        self.old_run = b'DINGTALK_WEBHOOK = "dummy-webhook"\nDINGTALK_SECRET = "dummy-secret"\n'
        self.policy["baseline"]["live_entrypoint_sha256"] = hashlib.sha256(self.old_run).hexdigest()
        self.new_run = b'def main():\n    return 0\n'
        self.blobs = {"scripts/report_delivery_outbox_v1.py": (ROOT / "scripts/report_delivery_outbox_v1.py").read_bytes(), "scripts/report_delivery_adapters_v1.py": (ROOT / "scripts/report_delivery_adapters_v1.py").read_bytes(), "skills/sp-monitor/run.py": self.new_run}
        for name, data in self.blobs.items():
            path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); os.chmod(path, 0o644)
        plist = self.policy["deployment"]["plist"]
        expected = {"EnvironmentVariables": {"HOME": str(self.home), "OPENCLAW_BIN": "/synthetic/openclaw", "PATH": "/usr/bin:/bin"}, "Label": plist["label"], "ProgramArguments": [self.ops.resolve(plist["interpreter"]), self.ops.resolve(plist["entrypoint"]), *plist["arguments"]], "RunAtLoad": False, "StandardErrorPath": str(self.home / "logs/sp-monitor.err.log"), "StandardOutPath": str(self.home / "logs/sp-monitor.out.log"), "StartCalendarInterval": plist["calendar"]}
        self.main_plist_bytes = plistlib.dumps(expected, fmt=plistlib.FMT_XML, sort_keys=True); plist["plist_sha256"] = hashlib.sha256(self.main_plist_bytes).hexdigest()
        self.runtime = manifest.build_runtime_release(self.policy, "a" * 40, self.blobs)
        live = Path(self.ops.resolve(self.policy["deployment"]["live_root"])); (live / "scripts").mkdir(parents=True, mode=0o700); (live / "run.py").write_bytes(self.old_run); os.chmod(live / "run.py", 0o644)
        secret_parent = Path(self.ops.resolve(self.policy["deployment"]["secret_path"])).parent; secret_parent.mkdir(parents=True, mode=0o700); os.chmod(secret_parent, 0o700)
        rollback_parent = Path(self.ops.resolve("~/.spspy-code-backups")); rollback_parent.mkdir(mode=0o700)
        plist_path = Path(self.ops.resolve(f"~/Library/LaunchAgents/{plist['label']}.plist")); plist_path.parent.mkdir(parents=True, mode=0o700)
        plist_path.write_bytes(self.main_plist_bytes); os.chmod(plist_path, 0o644)
        self.inspector = FakeInspector(self.policy, self.runtime, self.ops)
    def close(self): self.temp.cleanup()
    def tree(self):
        result = {}
        for path in self.base.rglob("*"):
            relative = str(path.relative_to(self.base)); mode = stat.S_IMODE(path.stat().st_mode)
            if path.is_file(): result[relative] = ("file", path.read_bytes(), mode)
            elif path.is_dir(): result[relative] = ("dir", mode)
        return result


class DeploySafetyTests(unittest.TestCase):
    def setUp(self): self.fx = DeploymentFixture(self)
    def tearDown(self): self.fx.close()
    def test_cli_help_works_direct_and_as_module_with_exact_sibling_manifest(self):
        expected_manifest = (ROOT / "scripts/sp_monitor_release_manifest_v1.py").resolve()
        self.assertEqual(Path(deploy.manifest.__file__).resolve(), expected_manifest)
        env = dict(os.environ); env["PYTHONDONTWRITEBYTECODE"] = "1"
        commands = ([sys.executable, str(ROOT / "scripts/deploy_sp_monitor_release_v1.py"), "--help"],
                    [sys.executable, "-m", "scripts.deploy_sp_monitor_release_v1", "--help"])
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr); self.assertIn("usage:", result.stdout)
    def test_verify_only_is_absolute_zero_write(self):
        before = self.fx.tree()
        result = deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["ok"]); self.assertEqual(before, self.fx.tree())
        self.assertFalse(Path(self.fx.ops.resolve(self.fx.policy["deployment"]["lock_path"])).exists())
    def test_unresolved_dependent_inventory_fails_closed_without_writes(self):
        item = self.fx.policy["deployment"]["dependent_consumers"][0]; item["unresolved"] = True; item["source_files"][0]["sha256"] = "REQUIRED_AT_DEPLOY"
        self.fx.runtime = manifest.build_runtime_release(self.fx.policy, "a" * 40, self.fx.blobs); self.fx.inspector.runtime = self.fx.runtime
        before = self.fx.tree()
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 78); self.assertEqual(before, self.fx.tree())
    def test_checked_in_unresolved_policy_blocks_deploy_and_rollback_before_writes(self):
        policy = manifest.parse_source_policy(POLICY_BYTES); before = self.fx.tree()
        lock = Path(self.fx.ops.resolve(policy["deployment"]["lock_path"])); guard = self.fx.home / (lock.name + ".guard")
        rollback_scope = Path(self.fx.ops.resolve(policy["deployment"]["rollback_root"])); secret = Path(self.fx.ops.resolve(policy["deployment"]["secret_path"]))
        self.assertFalse(lock.exists()); self.assertFalse(guard.exists()); self.assertFalse(rollback_scope.exists()); self.assertFalse(secret.exists())
        for method in ("repo_state", "main_state", "process_scan", "dependent_state"):
            setattr(self.fx.inspector, method, mock.Mock(side_effect=AssertionError("unresolved gate inspected external state")))
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT); self.assertEqual(before, self.fx.tree())
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.rollback_release(policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT); self.assertEqual(before, self.fx.tree())
        self.assertFalse(lock.exists()); self.assertFalse(guard.exists()); self.assertFalse(rollback_scope.exists()); self.assertFalse(secret.exists())
    def test_repo_process_window_plist_and_hash_gates(self):
        self.fx.inspector.active = True
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 75)
        self.fx.inspector.active = False
        bad_clock = type("BadClock", (), {"now": lambda self: datetime.datetime(2026, 8, 5, 7, 0, tzinfo=datetime.timezone.utc)})()
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=bad_clock, process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 75)
        source = self.fx.repo / "scripts/report_delivery_outbox_v1.py"; source.write_bytes(b"tampered"); os.chmod(source, 0o644)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 65)
    def test_naive_clock_and_plist_scan_race_fail_protocol(self):
        naive = type("NaiveClock", (), {"now": lambda self: datetime.datetime(2026, 8, 5, 11, 0)})()
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=naive, process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
        plist = self.fx.home / "Library/LaunchAgents" / f"{self.fx.policy['deployment']['plist']['label']}.plist"; original_scan = self.fx.inspector.process_scan
        def mutate_plist():
            plist.write_bytes(b"changed during scan"); os.chmod(plist, 0o644); return [["unrelated"]]
        self.fx.inspector.process_scan = mutate_plist
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL); plist.write_bytes(self.fx.main_plist_bytes); os.chmod(plist, 0o644); self.fx.inspector.process_scan = original_scan
    def test_process_scan_requires_exact_str_argv_and_detects_shell_wrappers(self):
        for invalid in ((["tuple-row"],), [[]], [[1]], [["ok", ""]]):
            self.fx.inspector.process_scan = lambda invalid=invalid: invalid
            with self.subTest(invalid=invalid), self.assertRaises(deploy.DeploymentError) as caught:
                deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
        plist = self.fx.policy["deployment"]["plist"]
        self.fx.inspector.process_scan = lambda: [[plist["interpreter"], "/synthetic/unrelated.py"]]
        self.assertTrue(deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)["ok"])
        main_executable = self.fx.ops.resolve(plist["entrypoint"])
        self.fx.inspector.process_scan = lambda: [["/bin/bash", "-lc", f"exec {main_executable} --send"]]
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_RETRY)
        dependent_executable = self.fx.policy["deployment"]["dependent_consumers"][0]["process_match_tokens"][0]
        self.fx.inspector.process_scan = lambda: [["/bin/sh", "-c", f"{dependent_executable} --daily"]]
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
    def test_ast_exact_two_names_and_secret_no_clobber(self):
        created = deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(created, {"created": True, "reused": False})
        secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600); self.assertEqual(secret.stat().st_nlink, 1)
        self.assertEqual(deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops), {"created": False, "reused": True})
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.migrate_credentials(self.fx.policy, b'DINGTALK_WEBHOOK="x"\nDINGTALK_SECRET="different"\n', ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 78)
        for bad in (b'DINGTALK_WEBHOOK="x"\n', b'DINGTALK_WEBHOOK="x"\nDINGTALK_WEBHOOK="y"\nDINGTALK_SECRET="z"\n', b'DINGTALK_WEBHOOK=DINGTALK_SECRET="x"\n'):
            with self.assertRaises(deploy.DeploymentError): deploy.migrate_credentials(self.fx.policy, bad, ops=self.fx.ops)
        secret.write_text('{ "webhook" : "dummy-webhook", "secret" : "dummy-secret" }', encoding="utf-8"); os.chmod(secret, 0o600)
        self.assertEqual(deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops), {"created": False, "reused": True})
    def test_same_value_secret_revalidates_parent_name_and_bytes_before_return(self):
        deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        original = deploy._revalidate_secret_binding
        with mock.patch.object(deploy, "_revalidate_secret_binding", wraps=original) as checked:
            self.assertEqual(deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops), {"created": False, "reused": True})
        self.assertEqual(checked.call_count, 1)
        secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); parent = secret.parent; held = parent.with_name(parent.name + "-held")
        original_parse = deploy._parse_secret_fields; changed = False
        def retarget(raw):
            nonlocal changed
            result = original_parse(raw)
            if not changed:
                changed = True; parent.rename(held); parent.mkdir(mode=0o700); secret.write_bytes(raw); os.chmod(secret, 0o600)
            return result
        try:
            with mock.patch.object(deploy, "_parse_secret_fields", side_effect=retarget):
                with self.assertRaises(deploy.DeploymentError) as caught: deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
        finally:
            secret.unlink(); parent.rmdir(); held.rename(parent)
        original_read = deploy._read_secret_at; reads = 0
        def retarget_after_reread(dfd, name):
            nonlocal reads
            raw = original_read(dfd, name); reads += 1
            if reads == 2:
                parent.rename(held); parent.mkdir(mode=0o700)
            return raw
        try:
            with mock.patch.object(deploy, "_read_secret_at", side_effect=retarget_after_reread):
                with self.assertRaises(deploy.DeploymentError) as caught: deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
        finally:
            parent.rmdir(); held.rename(parent)
    def test_secret_fifo_symlink_anchor_traceback_and_owned_temp(self):
        secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); os.mkfifo(secret, 0o600)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 77); secret.unlink()
        parent = secret.parent; real = parent.with_name("sp-monitor-real"); parent.rename(real); parent.symlink_to(real, target_is_directory=True)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 77); parent.unlink(); real.rename(parent)
        marker = "SENSITIVE_MARKER_9f2d"
        try: deploy.migrate_credentials(self.fx.policy, (f'DINGTALK_WEBHOOK="{marker}"\nDINGTALK_SECRET=\n').encode(), ops=self.fx.ops)
        except deploy.DeploymentError:
            self.assertNotIn(marker, traceback.format_exc())
        else: self.fail("invalid AST accepted")
        real_link = os.link
        def replace_owned_temp(source, destination, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):
            os.rename(source, source + ".old", src_dir_fd=src_dir_fd, dst_dir_fd=src_dir_fd)
            fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=src_dir_fd)
            try: os.write(fd, b"attacker")
            finally: os.close(fd)
            raise OSError("injected link loss")
        with mock.patch.object(deploy.os, "link", side_effect=replace_owned_temp):
            with self.assertRaises(deploy.DeploymentError) as caught: deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 73)
        leftovers = list(parent.glob(".report_delivery.tmp.*")); self.assertTrue(any(path.read_bytes() == b"attacker" for path in leftovers))
    def test_secret_hardlink_and_fault_fail_closed(self):
        secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); secret.write_bytes(b"{}\n"); os.chmod(secret, 0o600); os.link(secret, secret.parent / "copy")
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 77)
        secret.unlink(); (secret.parent / "copy").unlink()
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.migrate_credentials(self.fx.policy, self.fx.old_run, ops=self.fx.ops, fault=deploy.FaultInjector("secret.file.fsync"))
        self.assertEqual(caught.exception.exit_code, 73); self.assertFalse(secret.exists())
    def test_full_deploy_canary_and_rollback_order(self):
        result = deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["deployed"])
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); self.assertEqual((live / "run.py").read_bytes(), self.fx.new_run)
        runtime_path = live / self.fx.policy["deployment"]["runtime_manifest_target"]; self.assertEqual(manifest.parse_runtime_release(runtime_path.read_bytes()), self.fx.runtime)
        resumed = deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(resumed["recovered"])
        rollback_fault = deploy.FaultInjector(); rollback = deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=rollback_fault)
        self.assertTrue(rollback["rolled_back"]); self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        self.assertFalse((live / "scripts/report_delivery_outbox_v1.py").exists()); self.assertTrue(Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])).exists())
        self.assertLess(rollback_fault.events.index("rollback.3.open"), rollback_fault.events.index("rollback.2.unlink"))
    def test_rollback_repairs_exact_old_bytes_with_wrong_mode(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        live_entrypoint = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])) / "run.py"
        live_entrypoint.write_bytes(self.fx.old_run); os.chmod(live_entrypoint, 0o600)
        result = deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["rolled_back"]); self.assertEqual(live_entrypoint.read_bytes(), self.fx.old_run)
        self.assertEqual(stat.S_IMODE(live_entrypoint.stat().st_mode), 0o644)
        journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
        self.assertEqual(json.loads(journal.read_bytes())["status"], "rolled_back")
    def test_prepared_journal_and_orphan_backups_are_safely_reentrant(self):
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("journal.open"))
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_STAGING)
        release_root = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
        self.assertFalse((release_root / self.fx.policy["deployment"]["journal_name"]).exists()); self.assertTrue((release_root / "backup-3.bin").is_file())
        result = deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["deployed"])
    def test_prepared_resume_uses_digest_and_mode_jointly(self):
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.replace"))
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); first = live / "scripts/report_delivery_outbox_v1.py"
        self.assertTrue(first.exists()); os.chmod(first, 0o600)
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
    def test_prepared_resume_with_exact_old_new_hashes_and_modes_completes(self):
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.replace"))
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
        result = deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["recovered"])
    def test_compare_before_replace_rejects_fresh_and_resume_drift(self):
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); fresh_target = live / "scripts/report_delivery_outbox_v1.py"
        class MutateAtCompare(deploy.FaultInjector):
            def __init__(self, event, target): super().__init__(); self.event, self.target = event, target
            def hit(self, event):
                self.events.append(event)
                if event == self.event: self.target.write_bytes(b"external drift\n"); os.chmod(self.target, 0o644)
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=MutateAtCompare("install.0.compare", fresh_target))
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN); self.assertEqual(fresh_target.read_bytes(), b"external drift\n")
        self.fx.close(); self.fx = DeploymentFixture(self)
        with self.assertRaises(deploy.DeploymentError):
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.replace"))
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); resume_target = live / "scripts/report_delivery_adapters_v1.py"
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=MutateAtCompare("recover.install.1.compare", resume_target))
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN); self.assertEqual(resume_target.read_bytes(), b"external drift\n")
    def test_install_fault_rolls_back_and_lock_is_permanent(self):
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.file_fsync"))
        self.assertEqual(caught.exception.exit_code, 74)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        lock = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["lock_path"])); guard = self.fx.home / (lock.name + ".guard")
        self.assertTrue(lock.is_file()); self.assertTrue(guard.is_file()); self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
        self.assertEqual((lock.stat().st_dev, lock.stat().st_ino), (guard.stat().st_dev, guard.stat().st_ino))
        self.assertEqual(lock.stat().st_nlink, 2); self.assertEqual(guard.stat().st_nlink, 2)
    def test_helper_directory_is_safely_created(self):
        scripts = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])) / "scripts"; scripts.rmdir()
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(scripts.is_dir()); self.assertEqual(stat.S_IMODE(scripts.stat().st_mode), 0o700)
    def test_controlled_canary_rejects_wrong_bundle_and_protocol(self):
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]));
        for item in self.fx.runtime["bundle"]:
            target = live / item["target"]; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(self.fx.blobs[item["source"]]); os.chmod(target, 0o644)
        runtime_target = live / self.fx.policy["deployment"]["runtime_manifest_target"]; runtime_target.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_target, 0o644)
        original_run, original_socket = subprocess.run, socket.socket; before_env = dict(os.environ)
        before_temps = set(Path(tempfile.gettempdir()).glob("sp-monitor-controlled-canary-*"))
        with mock.patch.object(deploy.subprocess, "run", side_effect=AssertionError("process boundary")), mock.patch.object(socket, "socket", side_effect=AssertionError("network boundary")), mock.patch.object(os, "symlink", side_effect=AssertionError("symlink boundary")):
            self.assertEqual(deploy.run_fake_canary(self.fx.policy, self.fx.runtime, ops=self.fx.ops)["ok"], True)
        self.assertIs(subprocess.run, original_run); self.assertIs(socket.socket, original_socket); self.assertEqual(dict(os.environ), before_env)
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("sp-monitor-controlled-canary-*")), before_temps)
        runtime_target.unlink()
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.run_fake_canary(self.fx.policy, self.fx.runtime, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 66)
        runtime_target.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_target, 0o644)
        (live / "run.py").write_bytes(b"bad")
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.run_fake_canary(self.fx.policy, self.fx.runtime, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 65)
    def test_controlled_canary_executes_installed_helpers_with_same_live_outbox(self):
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]));
        for item in self.fx.runtime["bundle"]:
            target = live / item["target"]; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(self.fx.blobs[item["source"]]); os.chmod(target, 0o644)
        runtime_target = live / self.fx.policy["deployment"]["runtime_manifest_target"]; runtime_target.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_target, 0o644)
        fake = types.SimpleNamespace(create_record=mock.Mock(side_effect=AssertionError("repo outbox used")), controlled_canary=mock.Mock(side_effect=AssertionError("repo adapter used")))
        scripts_package = sys.modules["scripts"]; alias = "scripts.report_delivery_outbox_v1"; old_alias = sys.modules.get(alias); had_alias = alias in sys.modules; had_attr = hasattr(scripts_package, "report_delivery_outbox_v1"); old_attr = getattr(scripts_package, "report_delivery_outbox_v1", None)
        captured = {}; original_module_from_spec = deploy.importlib.util.module_from_spec
        def capture(spec):
            module = original_module_from_spec(spec); captured[spec.name] = module; return module
        try:
            sys.modules[alias] = fake; scripts_package.report_delivery_outbox_v1 = fake
            with mock.patch.object(deploy, "delivery_adapters", fake, create=True), mock.patch.object(deploy, "delivery_outbox", fake, create=True), mock.patch.object(deploy.importlib.util, "module_from_spec", side_effect=capture):
                self.assertTrue(deploy.run_fake_canary(self.fx.policy, self.fx.runtime, ops=self.fx.ops)["ok"])
            loaded_outbox = next(value for name, value in captured.items() if name.endswith(".report_delivery_outbox_v1"))
            loaded_adapter = next(value for name, value in captured.items() if name.endswith(".report_delivery_adapters_v1"))
            self.assertIs(loaded_adapter.outbox, loaded_outbox); fake.create_record.assert_not_called(); fake.controlled_canary.assert_not_called()
            self.assertIs(sys.modules[alias], fake); self.assertIs(scripts_package.report_delivery_outbox_v1, fake)
            self.assertFalse(any(name.startswith("_sp_monitor_installed_canary_") for name in sys.modules))
        finally:
            if had_alias: sys.modules[alias] = old_alias
            else: sys.modules.pop(alias, None)
            if had_attr: scripts_package.report_delivery_outbox_v1 = old_attr
            elif hasattr(scripts_package, "report_delivery_outbox_v1"): delattr(scripts_package, "report_delivery_outbox_v1")
    def test_controlled_canary_wrong_mode_and_exec_failure_clean_modules(self):
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]));
        for item in self.fx.runtime["bundle"]:
            target = live / item["target"]; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(self.fx.blobs[item["source"]]); os.chmod(target, 0o644)
        runtime_target = live / self.fx.policy["deployment"]["runtime_manifest_target"]; runtime_target.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_target, 0o644)
        adapter_path = live / "scripts/report_delivery_adapters_v1.py"; os.chmod(adapter_path, 0o600)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.run_fake_canary(self.fx.policy, self.fx.runtime, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE); os.chmod(adapter_path, 0o644)
        alias = "scripts.report_delivery_outbox_v1"; scripts_package = sys.modules["scripts"]; before_alias = sys.modules.get(alias); had_alias = alias in sys.modules; before_attr = getattr(scripts_package, "report_delivery_outbox_v1", None); had_attr = hasattr(scripts_package, "report_delivery_outbox_v1")
        original_get_code = deploy._ExactCanarySourceLoader.get_code
        def fail_adapter(loader, fullname):
            if fullname.endswith(".report_delivery_adapters_v1"): raise RuntimeError("SENSITIVE_IMPORT_FAILURE")
            return original_get_code(loader, fullname)
        with mock.patch.object(deploy._ExactCanarySourceLoader, "get_code", fail_adapter):
            with self.assertRaises(deploy.DeploymentError) as caught: deploy.run_fake_canary(self.fx.policy, self.fx.runtime, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL); self.assertIsNone(caught.exception.__cause__); self.assertIsNone(caught.exception.__context__)
        self.assertFalse(any(name.startswith("_sp_monitor_installed_canary_") for name in sys.modules))
        self.assertEqual(alias in sys.modules, had_alias); self.assertIs(sys.modules.get(alias), before_alias)
        self.assertEqual(hasattr(scripts_package, "report_delivery_outbox_v1"), had_attr)
        if had_attr: self.assertIs(scripts_package.report_delivery_outbox_v1, before_attr)
    def test_canary_policy_binding_and_direct_mode_scripts_package_cleanup(self):
        bad_policy = copy.deepcopy(self.fx.policy); bad_policy["baseline"]["live_entrypoint_sha256"] = "f" * 64
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.run_fake_canary(bad_policy, self.fx.runtime, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_INTEGRITY); self.assertIsNone(caught.exception.__cause__); self.assertIsNone(caught.exception.__context__)
        policy_path = self.fx.base / "bad-policy.json"; runtime_path = self.fx.base / "runtime.json"
        policy_path.write_bytes(manifest.canonical_source_policy_bytes(bad_policy)); runtime_path.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime))
        with mock.patch.object(deploy, "run_fake_canary") as called:
            code = deploy.main(["canary", "--policy", str(policy_path), "--runtime", str(runtime_path), "--repo-root", str(self.fx.repo)], ops=self.fx.ops, process_inspector=self.fx.inspector)
        self.assertEqual(code, deploy.EXIT_INTEGRITY); called.assert_not_called()
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
        for item in self.fx.runtime["bundle"]:
            target = live / item["target"]; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(self.fx.blobs[item["source"]]); os.chmod(target, 0o644)
        runtime_target = live / self.fx.policy["deployment"]["runtime_manifest_target"]
        runtime_target.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_target, 0o644)
        scripts_package = sys.modules.pop("scripts")
        try:
            self.assertTrue(deploy.run_fake_canary(self.fx.policy, self.fx.runtime, ops=self.fx.ops)["ok"])
            self.assertNotIn("scripts", sys.modules)
            self.assertFalse(any(name.startswith("_sp_monitor_installed_canary_") for name in sys.modules))
        finally:
            sys.modules["scripts"] = scripts_package
    def test_canary_implementation_has_no_exec_or_global_sandbox(self):
        source = (ROOT / "scripts/deploy_sp_monitor_release_v1.py").read_text(encoding="utf-8")
        self.assertNotIn("exec(compile", source); self.assertNotIn("invoke_canary", source); self.assertNotIn("builtins.open =", source)
    def test_lock_parent_retarget_blocks_second_coordinator(self):
        first = deploy._acquire_lock(self.fx.policy, self.fx.ops); root = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])); old = root.with_name("sp-monitor-held"); replacement = root
        root.rename(old); replacement.mkdir(mode=0o700)
        try:
            with self.assertRaises(deploy.DeploymentError) as caught: deploy._acquire_lock(self.fx.policy, self.fx.ops)
            self.assertIn(caught.exception.exit_code, (75, 77))
        finally:
            replacement.rmdir(); old.rename(root); first.close()
    def test_lock_dual_names_no_clobber_and_each_retarget_is_rejected(self):
        lock_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["lock_path"])); guard_path = self.fx.home / (lock_path.name + ".guard")
        guard_path.write_bytes(b"preexisting"); os.chmod(guard_path, 0o600); guard_fp = (guard_path.stat().st_dev, guard_path.stat().st_ino, guard_path.read_bytes())
        with self.assertRaises(deploy.DeploymentError) as caught: deploy._acquire_lock(self.fx.policy, self.fx.ops)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
        self.assertFalse(lock_path.exists()); self.assertEqual((guard_path.stat().st_dev, guard_path.stat().st_ino, guard_path.read_bytes()), guard_fp)
        guard_path.unlink(); Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])).rmdir()
        first = deploy._acquire_lock(self.fx.policy, self.fx.ops)
        for target in (lock_path, guard_path):
            moved = target.with_name(target.name + ".moved"); target.rename(moved); target.write_bytes(b"replacement"); os.chmod(target, 0o600)
            try:
                with self.subTest(target=target.name), self.assertRaises(deploy.DeploymentError) as caught:
                    deploy._acquire_lock(self.fx.policy, self.fx.ops)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
            finally:
                target.unlink(); moved.rename(target)
        first.close()
    def test_lock_parent_retarget_and_close_fence_fail_closed(self):
        first = deploy._acquire_lock(self.fx.policy, self.fx.ops); lock_parent = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["lock_path"])).parent
        held = lock_parent.with_name(lock_parent.name + "-held"); lock_parent.rename(held); lock_parent.mkdir(mode=0o700); (lock_parent / "sp-monitor").mkdir(mode=0o700)
        try:
            with self.assertRaises(deploy.DeploymentError) as caught: deploy._acquire_lock(self.fx.policy, self.fx.ops)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
        finally:
            (lock_parent / "sp-monitor").rmdir(); lock_parent.rmdir(); held.rename(lock_parent); first.close()
        second = deploy._acquire_lock(self.fx.policy, self.fx.ops); guard = self.fx.home / (Path(self.fx.ops.resolve(self.fx.policy["deployment"]["lock_path"])).name + ".guard"); moved = guard.with_name(guard.name + ".moved")
        guard.rename(moved); guard.write_bytes(b"replacement"); os.chmod(guard, 0o600)
        with self.assertRaises(deploy.DeploymentError) as caught: second.close()
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE); guard.unlink(); moved.rename(guard)
    def test_journal_traversal_and_delete_fault_are_third_state(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        release_root = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
        journal_path = release_root / self.fx.policy["deployment"]["journal_name"]
        journal = json.loads(journal_path.read_bytes()); journal["entries"][3]["backup"] = "../escape"; journal_path.write_bytes(deploy._canonical(journal)); os.chmod(journal_path, 0o600)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 80)
    def test_rollback_delete_after_unlink_fault_is_uncertain(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        fault = deploy.FaultInjector("rollback.2.dir_fsync")
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault)
        self.assertEqual(caught.exception.exit_code, 80)
    def test_dependent_exact_legacy_unloaded_source_and_process_contract(self):
        item = self.fx.policy["deployment"]["dependent_consumers"][0]; identity = item["process_match_tokens"][0]
        self.fx.inspector.process_scan = lambda: [["/bin/bash", "-lc", identity]]
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 78)
        self.fx.inspector.process_scan = lambda: [["/bin/bash", "-lc", "cd /Users/tonyaiuser/.spspy-single-page-monitor/single-page-monitor && echo unrelated"]]
        self.assertTrue(deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)["ok"])
        original = self.fx.inspector.dependent_state
        def drift(consumer):
            state = original(consumer)
            if consumer["name"] == item["name"]: state["source_files"][0]["sha256"] = "9" * 64
            return state
        self.fx.inspector.dependent_state = drift
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
        def loaded(consumer):
            state = original(consumer)
            if consumer["name"] == item["name"]:
                for value in state["labels"].values(): value.update(enabled=True, loaded=True)
            return state
        self.fx.inspector.dependent_state = loaded
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
    def test_production_inspector_uses_full_main_shape_and_policy_bound_dependent_sources(self):
        inspector = deploy.ProductionProcessInspector(); ps_output = ["401 /bin/bash -lc 'echo unrelated'"]
        def observed(argv, accepted=(0,), env=None):
            if argv[:2] == ["launchctl", "print"]:
                label = argv[-1].rsplit("/", 1)[-1]; code = 0 if label == self.fx.policy["deployment"]["plist"]["label"] else 113
                return subprocess.CompletedProcess(argv, code, stdout="", stderr="")
            if argv[:2] == ["launchctl", "print-disabled"]:
                values = [f'"{self.fx.policy["deployment"]["plist"]["label"]}" => false'] + [f'"{item["labels"][0]}" => true' for item in self.fx.policy["deployment"]["dependent_consumers"]]
                return subprocess.CompletedProcess(argv, 0, stdout="\n".join(values), stderr="")
            if argv[:3] == ["ps", "-axo", "pid=,command="]:
                return subprocess.CompletedProcess(argv, 0, stdout="\n".join(ps_output) + "\n", stderr="")
            raise AssertionError(argv)
        with mock.patch.object(deploy.Path, "home", return_value=self.fx.home), mock.patch.object(inspector, "_run", side_effect=observed):
            main = inspector.main_state(self.fx.policy["deployment"]["plist"])
            self.assertEqual(main["argv"][1], self.fx.ops.resolve(self.fx.policy["deployment"]["plist"]["entrypoint"])); self.assertTrue(main["loaded"] and main["enabled"])
            item = copy.deepcopy(self.fx.policy["deployment"]["dependent_consumers"][0]); source = self.fx.base / "policy-bound-dependent.sh"; source.write_bytes(b"exact dependent source\n"); os.chmod(source, 0o644)
            item["source_files"] = [{"path": str(source), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}]; item["unresolved"] = False
            dependent_plist = plistlib.dumps({"Label": item["labels"][0], "ProgramArguments": item["configured_argv"]}, fmt=plistlib.FMT_XML, sort_keys=True)
            dependent_path = self.fx.home / "Library/LaunchAgents" / f"{item['labels'][0]}.plist"; dependent_path.write_bytes(dependent_plist); os.chmod(dependent_path, 0o644); item["plist_sha256"] = hashlib.sha256(dependent_plist).hexdigest()
            state = inspector.dependent_state(item)
            self.assertEqual(state["source_files"], item["source_files"]); self.assertEqual(state["labels"][item["labels"][0]]["runtime_argv"], [])
            ps_output[:] = [f"402 /bin/bash -lc '{item['process_match_tokens'][0]}'"]
            active = inspector.dependent_state(item); self.assertEqual(active["labels"][item["labels"][0]]["runtime_argv"], item["configured_argv"])
            source.write_bytes(b"drift\n"); os.chmod(source, 0o644)
            self.assertNotEqual(inspector.dependent_state(item)["source_files"], item["source_files"])
            malformed = plistlib.loads(self.fx.main_plist_bytes); malformed["Unexpected"] = "x"
            main_path = self.fx.home / "Library/LaunchAgents" / f"{self.fx.policy['deployment']['plist']['label']}.plist"; main_path.write_bytes(plistlib.dumps(malformed, fmt=plistlib.FMT_XML, sort_keys=True)); os.chmod(main_path, 0o644)
            with self.assertRaises(deploy.DeploymentError) as caught: inspector.main_state(self.fx.policy["deployment"]["plist"])
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            main_path.write_bytes(self.fx.main_plist_bytes); os.chmod(main_path, 0o644)
    def test_public_oserror_kbi_and_process_inspector_argv_contract(self):
        with mock.patch.object(self.fx.ops, "read_bytes", side_effect=PermissionError("denied")):
            with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 70)
        with mock.patch.object(self.fx.inspector, "repo_state", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        marker = "SENSITIVE_PUBLIC_EXCEPTION_73bd"
        with mock.patch.object(self.fx.inspector, "repo_state", side_effect=RuntimeError(marker)):
            with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_INTERNAL); self.assertEqual(str(caught.exception), "public operation failed")
        self.assertIsNone(caught.exception.__cause__); self.assertIsNone(caught.exception.__context__); self.assertNotIn(marker, "".join(traceback.format_exception(caught.exception)))
        domain = deploy.DeploymentError("domain failure", deploy.EXIT_RETRY)
        with mock.patch.object(self.fx.inspector, "repo_state", side_effect=domain):
            with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertIs(caught.exception, domain)
        abrupt = SystemExit(23)
        with mock.patch.object(self.fx.inspector, "repo_state", side_effect=abrupt):
            with self.assertRaises(SystemExit) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertIs(caught.exception, abrupt)
        completed = subprocess.CompletedProcess(["tool", "arg"], 0, stdout="ok", stderr="")
        inspector = deploy.ProductionProcessInspector()
        with mock.patch.object(deploy.subprocess, "run", return_value=completed) as called: self.assertEqual(inspector._run(["tool", "arg"]).stdout, "ok")
        self.assertEqual(called.call_args.args[0], ["tool", "arg"]); self.assertIs(called.call_args.kwargs["shell"], False); self.assertEqual(called.call_args.kwargs["timeout"], 5)


if __name__ == "__main__": unittest.main()
