import copy
import datetime
import hashlib
import io
import json
import os
import plistlib
import signal
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
VALID_WEBHOOK = "https://oapi.dingtalk.com/robot/send?access_token=synthetic-token"
VALID_SECRET = "synthetic-secret"


def launchctl_print_output(label, argv):
    arguments = "".join(f"\t\t{value}\n" for value in argv)
    path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    by_label = {value["Label"]: value for value in manifest.EXACT_DEPENDENT_PLISTS.values()}
    contract = manifest.exact_main_plist_value(str(Path.home())) if label == manifest.EXACT_MAIN_PLIST["label"] else by_label.get(label)
    semantic = ""
    if contract is not None:
        environment = {"OSLogRateLimit": "64", **contract.get("EnvironmentVariables", {}), "XPC_SERVICE_NAME": label}
        env_lines = "".join(f"\t\t{key} => {value}\n" for key, value in environment.items())
        if "StartCalendarInterval" in contract:
            calendar = contract["StartCalendarInterval"]
            trigger = f'\tevent triggers = {{\n\t\t{label}.1 => {{\n\t\t\tdescriptor = {{\n\t\t\t\t"Minute" => {calendar["Minute"]}\n\t\t\t\t"Hour" => {calendar["Hour"]}\n\t\t\t}}\n\t\t}}\n\t}}\n'
            interval = ""
        else:
            trigger = ""; interval = f'\trun interval = {contract["StartInterval"]} seconds\n'
        properties = " | ".join(sorted(manifest.EXACT_LOADED_PROPERTIES[label]))
        semantic = (f'\tstdout path = {contract["StandardOutPath"]}\n\tstderr path = {contract["StandardErrorPath"]}\n'
                    f'\tenvironment = {{\n{env_lines}\t}}\n{trigger}{interval}\tproperties = {properties}\n')
    return f"gui/501/{label} = {{\n\tpath = {path}\n\tprogram = {argv[0]}\n\targuments = {{\n{arguments}\t}}\n{semantic}}}\n"


class FixedClock:
    def now(self): return datetime.datetime(2026, 8, 5, 3, 0, tzinfo=datetime.timezone.utc)  # 11:00 Shanghai


class AdvancingClock:
    def __init__(self, allowed_calls): self.allowed_calls, self.calls = allowed_calls, 0
    def now(self):
        self.calls += 1
        minute = 20 if self.calls <= self.allowed_calls else 21
        return datetime.datetime(2026, 8, 5, 3, minute, tzinfo=datetime.timezone.utc)


class FakeInspector(deploy.ProcessInspector):
    def __init__(self, policy, runtime, ops): self.policy, self.runtime, self.ops = policy, runtime, ops; self.active = False; self.commit_files = {}
    def repo_state(self, repo_root): return {"clean": True, "ref": "refs/heads/main", "commit": self.runtime["repository"]["commit"], "merge_proven": True}
    def repo_file_at_commit(self, repo_root, commit, relative_path):
        raw = self.commit_files[commit][relative_path]
        return {"present": True, "mode": "100644", "oid": hashlib.sha1(raw).hexdigest(), "bytes": raw}
    def repo_commit_proven(self, repo_root, commit): return True
    def main_state(self, plist):
        return {"loaded": True, "enabled": True, "pid": None, "argv": [self.ops.resolve(plist["interpreter"]), self.ops.resolve(plist["entrypoint"]), *plist["arguments"]]}
    def process_scan(self): return [["unrelated"]] if not self.active else [[self.ops.resolve(self.policy["deployment"]["plist"]["entrypoint"]), "--send"]]
    def dependent_state(self, item):
        required = item["required_launch_state"]
        binding = hashlib.sha256(deploy._canonical({"selected_release": item["selected_release"], "sources": item["source_files"]})).hexdigest()
        return {"source_files": copy.deepcopy(item["source_files"]), "selected_release": copy.deepcopy(item["selected_release"]), "plist_sha256": item["plist_sha256"], "credential_contract": item["credential_contract"], "binding": binding, "labels": {label: {"enabled": required["enabled"], "loaded": required["loaded"], "pid": None, "configured_argv": list(item["configured_argv"]), "runtime_argv": []} for label in item["labels"]}}
    def migration_dependent_state(self, item):
        required = item["required_launch_state"]
        return {"plist_sha256": item["plist_sha256"], "label": item["labels"][0], "launch": {"enabled": required["enabled"], "loaded": required["loaded"], "pid": None, "configured_argv": list(item["configured_argv"]), "runtime_argv": []}}


class DeploymentFixture:
    def __init__(self, testcase):
        self.case = testcase; self.temp = tempfile.TemporaryDirectory(dir="/private/tmp"); self.base = Path(self.temp.name); self.home = self.base / "home"; self.repo = self.base / "repo"
        self.home.mkdir(mode=0o700); self.repo.mkdir(mode=0o700)
        self.ops = deploy.Ops(lambda value: str(self.home) if value == "~" else str(self.home / value[2:]) if value.startswith("~/") else value)
        self.policy = manifest.parse_source_policy(POLICY_BYTES); self.policy = copy.deepcopy(self.policy)
        for index, item in enumerate(self.policy["deployment"]["dependent_consumers"], 1):
            item.update(plist_sha256=(str(index + 3) * 64), unresolved=False)
            chain = manifest.EXACT_DEPENDENT_CHAINS[item["name"]]; release_id = f"20260805T03000{index}Z-{index}"
            item["selected_release"].update(target=f"releases/{release_id}", release_id=release_id, release_path=f"{chain['root']}/releases/{release_id}")
            for source_index, source in enumerate(item["source_files"], 1):
                if source["role"] == "selected_entrypoint": source["path"] = item["selected_release"]["release_path"] + "/" + chain["entry"]
                if source["role"] == "notify_helper": source["path"] = item["selected_release"]["release_path"] + "/" + chain["helper"]
                source["sha256"] = hashlib.sha256(f"{index}:{source_index}".encode()).hexdigest()
            reviewed = manifest.EXACT_DEPENDENT_HELPER_SHA256[item["name"]]
            if reviewed is None: raise AssertionError(f"reviewed helper SHA-256 pending for {item['name']}")
            item["source_files"][2]["sha256"] = reviewed
            item["process_match_tokens"] = [item["configured_argv"][2], item["source_files"][1]["path"], item["source_files"][2]["path"]]
        self.old_run = f'DINGTALK_WEBHOOK = "{VALID_WEBHOOK}"\nDINGTALK_SECRET = "{VALID_SECRET}"\n'.encode()
        self.policy["baseline"]["live_entrypoint_sha256"] = hashlib.sha256(self.old_run).hexdigest()
        self.new_run = b'def main():\n    return 0\n'
        self.blobs = {"scripts/report_delivery_outbox_v1.py": (ROOT / "scripts/report_delivery_outbox_v1.py").read_bytes(), "scripts/report_delivery_adapters_v1.py": (ROOT / "scripts/report_delivery_adapters_v1.py").read_bytes(), "skills/sp-monitor/run.py": self.new_run}
        for name, data in self.blobs.items():
            path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); os.chmod(path, 0o644)
        plist = self.policy["deployment"]["plist"]
        expected = manifest.exact_main_plist_value(str(self.home))
        self.main_plist_bytes = plistlib.dumps(expected, fmt=plistlib.FMT_XML, sort_keys=True); plist["plist_sha256"] = hashlib.sha256(self.main_plist_bytes).hexdigest()
        self.runtime = manifest.build_runtime_release(self.policy, "a" * 40, self.blobs)
        policy_path = self.repo / self.policy["deployment"]["policy_path"]; policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(json.dumps(self.policy, indent=2, sort_keys=True) + "\n", encoding="utf-8"); os.chmod(policy_path, 0o644)
        live = Path(self.ops.resolve(self.policy["deployment"]["live_root"])); (live / "scripts").mkdir(parents=True, mode=0o700); (live / "run.py").write_bytes(self.old_run); os.chmod(live / "run.py", 0o644)
        secret_parent = Path(self.ops.resolve(self.policy["deployment"]["secret_path"])).parent; secret_parent.mkdir(parents=True, mode=0o700); os.chmod(secret_parent, 0o700)
        for directory in (self.home / ".openclaw", self.home / ".openclaw/secrets", secret_parent): os.chmod(directory, 0o700)
        rollback_parent = Path(self.ops.resolve("~/.spspy-code-backups")); rollback_parent.mkdir(mode=0o700)
        plist_path = Path(self.ops.resolve(f"~/Library/LaunchAgents/{plist['label']}.plist")); plist_path.parent.mkdir(parents=True, mode=0o700)
        plist_path.write_bytes(self.main_plist_bytes); os.chmod(plist_path, 0o600)
        self.inspector = FakeInspector(self.policy, self.runtime, self.ops)
        self.register_runtime(self.runtime, self.blobs)
    def register_runtime(self, runtime, blobs, policy=None):
        authority_policy = self.policy if policy is None else policy
        files = {authority_policy["deployment"]["policy_path"]: (self.repo / authority_policy["deployment"]["policy_path"]).read_bytes()}
        files.update({name: data for name, data in blobs.items()})
        self.inspector.commit_files[runtime["repository"]["commit"]] = files
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
    def test_manifest_cli_private_runtime_chains_into_deployer_cli_verify(self):
        runtime_path = self.fx.base / "runtime-cli.json"
        policy_path = self.fx.repo / self.fx.policy["deployment"]["policy_path"]
        code = manifest.main(["build-runtime", "--policy", str(policy_path), "--repo-root", str(self.fx.repo),
                "--repo-commit", self.fx.runtime["repository"]["commit"], "--output", str(runtime_path)])
        self.assertEqual(code, 0); self.assertEqual(stat.S_IMODE(runtime_path.stat().st_mode), 0o600)
        built = manifest.parse_runtime_release(runtime_path.read_bytes()); self.assertEqual(built, self.fx.runtime)
        argv = ["verify-only", "--policy", str(policy_path), "--runtime", str(runtime_path),
                "--repo-root", str(self.fx.repo), "--expected-release-id", self.fx.runtime["release_id"]]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(deploy.sys, "stdout", stdout), mock.patch.object(deploy.sys, "stderr", stderr):
            self.assertEqual(deploy.main(argv, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector), 0)
        self.assertEqual(stdout.getvalue(), ""); self.assertEqual(stderr.getvalue(), "")
        for mode in (0o644, 0o666):
            os.chmod(runtime_path, mode)
            with self.subTest(mode=oct(mode)):
                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch.object(deploy.sys, "stdout", stdout), mock.patch.object(deploy.sys, "stderr", stderr):
                    self.assertEqual(deploy.main(argv, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector), deploy.EXIT_UNSAFE)
                self.assertEqual(stdout.getvalue(), ""); self.assertTrue(stderr.getvalue().startswith("ERROR[77]:"))
        os.chmod(runtime_path, 0o600)
    def test_all_non_migration_successful_cli_commands_keep_stdout_empty(self):
        policy_path = self.fx.repo / self.fx.policy["deployment"]["policy_path"]
        runtime_path = self.fx.base / "runtime-cli-all.json"; runtime_path.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_path, 0o600)
        common = ["--policy", str(policy_path), "--runtime", str(runtime_path), "--repo-root", str(self.fx.repo),
                "--expected-release-id", self.fx.runtime["release_id"]]
        commands = (["verify-only", *common], ["deploy", *common], ["canary", *common],
                ["rollback", "--policy", str(policy_path), "--repo-root", str(self.fx.repo), "--expected-release-id", self.fx.runtime["release_id"]])
        for argv in commands:
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(command=argv[0]), mock.patch.object(deploy.sys, "stdout", stdout), mock.patch.object(deploy.sys, "stderr", stderr):
                code = deploy.main(argv, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
            self.assertEqual(code, 0); self.assertEqual(stdout.getvalue(), ""); self.assertEqual(stderr.getvalue(), "")
    def test_verify_only_is_absolute_zero_write(self):
        before = self.fx.tree()
        result = deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["ok"]); self.assertEqual(before, self.fx.tree())
        self.assertFalse(Path(self.fx.ops.resolve(self.fx.policy["deployment"]["lock_path"])).exists())
    def test_python_pre310_rejects_before_any_deploy_or_canary_write(self):
        before = self.fx.tree()
        for method in ("repo_state", "main_state", "process_scan", "dependent_state"):
            setattr(self.fx.inspector, method, mock.Mock(side_effect=AssertionError("old interpreter inspected external state")))
        with mock.patch.object(deploy.sys, "version_info", (3, 9, 99, "final", 0)):
            with self.assertRaises(deploy.DeploymentError) as caught:
                deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            with self.assertRaises(deploy.DeploymentError) as caught:
                deploy.run_fake_canary(self.fx.policy, self.fx.runtime, ops=self.fx.ops)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
        self.assertEqual(before, self.fx.tree())
    def test_unresolved_dependent_inventory_fails_closed_without_writes(self):
        item = self.fx.policy["deployment"]["dependent_consumers"][0]; item["unresolved"] = True
        item["selected_release"].update(target="REQUIRED_AT_DEPLOY", release_path="REQUIRED_AT_DEPLOY", release_id="REQUIRED_AT_DEPLOY")
        for source in item["source_files"]: source["sha256"] = "REQUIRED_AT_DEPLOY"
        item["source_files"][1]["path"] = "REQUIRED_AT_DEPLOY"; item["source_files"][2]["path"] = "REQUIRED_AT_DEPLOY"
        item["process_match_tokens"] = [item["configured_argv"][2], "REQUIRED_AT_DEPLOY", "REQUIRED_AT_DEPLOY"]
        self.fx.runtime = manifest.build_runtime_release(self.fx.policy, "a" * 40, self.fx.blobs); self.fx.inspector.runtime = self.fx.runtime
        before = self.fx.tree()
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 78); self.assertEqual(before, self.fx.tree())
    def test_checked_in_unresolved_policy_blocks_deploy_and_rollback_before_writes(self):
        policy = manifest.parse_source_policy(POLICY_BYTES)
        cli_runtime = manifest.build_runtime_release(policy, "a" * 40, self.fx.blobs)
        policy_path = self.fx.base / "unresolved-policy.json"; runtime_path = self.fx.base / "unresolved-runtime.json"
        policy_path.write_bytes(manifest.canonical_source_policy_bytes(policy)); runtime_path.write_bytes(manifest.canonical_runtime_release_bytes(cli_runtime)); os.chmod(runtime_path, 0o600)
        before = self.fx.tree()
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
        with mock.patch("sys.stderr"):
            self.assertEqual(deploy.main(["deploy", "--policy", str(policy_path), "--runtime", str(runtime_path), "--repo-root", str(self.fx.repo)], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector), deploy.EXIT_CONFLICT)
            self.assertEqual(deploy.main(["rollback", "--policy", str(policy_path), "--repo-root", str(self.fx.repo), "--expected-release-id", cli_runtime["release_id"]], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector), deploy.EXIT_CONFLICT)
        self.assertEqual(before, self.fx.tree())
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
    def test_repo_authority_rejects_skip_worktree_custom_policy_and_regenerated_runtime(self):
        policy_path = self.fx.repo / self.fx.policy["deployment"]["policy_path"]
        original_policy_raw = policy_path.read_bytes()
        policy_path.write_bytes(original_policy_raw + b" "); os.chmod(policy_path, 0o644)
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                    clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_INTEGRITY)
        policy_path.write_bytes(original_policy_raw); os.chmod(policy_path, 0o644)
        custom_policy = copy.deepcopy(self.fx.policy); custom_policy["baseline"]["live_entrypoint_sha256"] = "9" * 64
        custom_runtime = manifest.build_runtime_release(custom_policy, self.fx.runtime["repository"]["commit"], self.fx.blobs)
        self.fx.inspector.runtime = custom_runtime
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.verify_only(custom_policy, custom_runtime, self.fx.repo, ops=self.fx.ops,
                    clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_INTEGRITY)
        changed_blobs = dict(self.fx.blobs); changed_blobs["skills/sp-monitor/run.py"] = b"def main():\n    return 99\n"
        changed_source = self.fx.repo / "skills/sp-monitor/run.py"; changed_source.write_bytes(changed_blobs["skills/sp-monitor/run.py"]); os.chmod(changed_source, 0o644)
        regenerated = manifest.build_runtime_release(self.fx.policy, self.fx.runtime["repository"]["commit"], changed_blobs)
        self.fx.inspector.runtime = regenerated
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.verify_only(self.fx.policy, regenerated, self.fx.repo, ops=self.fx.ops,
                    clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_INTEGRITY)
    def test_real_git_replace_refs_are_ignored_with_exact_argv_and_environment(self):
        repo = self.fx.base / "replace-repo"; repo.mkdir(mode=0o700)
        construction_env = {"HOME": str(self.fx.home), "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", **deploy.GIT_ENVIRONMENT}
        def git(arguments, *, data=None, env=None, accepted=(0,)):
            result = subprocess.run([deploy.GIT_BIN, "-C", str(repo), *arguments], input=data, capture_output=True,
                    env=construction_env if env is None else env, check=False)
            self.assertIn(result.returncode, accepted, result.stderr.decode("utf-8", "replace")); return result
        git(["init", "-b", "main"])
        payload = repo / "payload.txt"; payload.write_bytes(b"parent-original\n"); git(["add", "payload.txt"])
        identity = ["-c", "user.name=Exact Test", "-c", "user.email=exact@example.invalid"]
        git([*identity, "commit", "-m", "parent"]); parent_commit = git(["rev-parse", "HEAD"]).stdout.decode().strip()
        payload.write_bytes(b"head-original\n"); git(["add", "payload.txt"]); git([*identity, "commit", "-m", "head"])
        head_commit = git(["rev-parse", "HEAD"]).stdout.decode().strip()
        original_blob = git(["rev-parse", f"{head_commit}:payload.txt"]).stdout.decode().strip()
        replacement_bytes = b"replacement-object-must-not-be-trusted\n"
        replacement_blob = git(["hash-object", "-w", "--stdin"], data=replacement_bytes).stdout.decode().strip()
        replacement_tree = git(["mktree"], data=f"100644 blob {replacement_blob}\tpayload.txt\n".encode()).stdout.decode().strip()
        unrelated = git([*identity, "commit-tree", replacement_tree, "-m", "unrelated"]).stdout.decode().strip()
        replacement_commit = git([*identity, "commit-tree", replacement_tree, "-p", unrelated, "-m", "replacement"]).stdout.decode().strip()
        git(["update-ref", f"refs/replace/{head_commit}", replacement_commit])
        git(["update-ref", f"refs/replace/{original_blob}", replacement_blob])
        git(["update-ref", "refs/remotes/origin/main", head_commit])
        ambient_env = dict(construction_env); ambient_env.pop("GIT_NO_REPLACE_OBJECTS")
        self.assertIn(replacement_blob.encode(), git(["ls-tree", head_commit, "--", "payload.txt"], env=ambient_env).stdout)
        self.assertEqual(git(["cat-file", "blob", original_blob], env=ambient_env).stdout, replacement_bytes)
        self.assertEqual(git(["merge-base", "--is-ancestor", parent_commit, "refs/remotes/origin/main"], env=ambient_env, accepted=(0, 1)).returncode, 1)
        inspector = deploy.ProductionProcessInspector(home=self.fx.home); real_run = subprocess.run; observed = []
        def capture(argv, **kwargs):
            observed.append((list(argv), dict(kwargs["env"]))); return real_run(argv, **kwargs)
        with mock.patch.object(deploy.subprocess, "run", side_effect=capture):
            state = inspector.repo_state(repo)
            committed = inspector.repo_file_at_commit(repo, head_commit, "payload.txt")
            proven = inspector.repo_commit_proven(repo, parent_commit)
        self.assertEqual(state, {"clean": True, "ref": "refs/heads/main", "commit": head_commit, "merge_proven": True})
        self.assertEqual(committed["bytes"], b"head-original\n"); self.assertEqual(committed["oid"], original_blob); self.assertTrue(proven)
        prefix = [deploy.GIT_BIN, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", str(repo)]
        self.assertEqual([argv for argv, _ in observed], [
            [*prefix, "status", "--porcelain=v1", "--untracked-files=all"],
            [*prefix, "symbolic-ref", "--quiet", "HEAD"],
            [*prefix, "rev-parse", "--verify", "HEAD^{commit}"],
            [*prefix, "merge-base", "--is-ancestor", head_commit, "refs/remotes/origin/main"],
            [*prefix, "ls-tree", head_commit, "--", "payload.txt"],
            [*prefix, "cat-file", "blob", original_blob],
            [*prefix, "merge-base", "--is-ancestor", parent_commit, "refs/remotes/origin/main"],
        ])
        expected_env = {"HOME": str(self.fx.home), "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", **deploy.GIT_ENVIRONMENT}
        self.assertTrue(observed); self.assertTrue(all(environment == expected_env for _, environment in observed))
        completed = subprocess.CompletedProcess([deploy.GIT_BIN, "--version"], 0, stdout="git version synthetic\n", stderr="")
        with mock.patch.object(deploy.subprocess, "run", return_value=completed) as called:
            inspector._run([deploy.GIT_BIN, "--version"], env={"HOME": "/tmp/shadow", "GIT_NO_REPLACE_OBJECTS": "0"})
        self.assertEqual(called.call_args.kwargs["env"], expected_env)
    def test_naive_clock_and_plist_scan_race_fail_protocol(self):
        naive = type("NaiveClock", (), {"now": lambda self: datetime.datetime(2026, 8, 5, 11, 0)})()
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=naive, process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
        plist = self.fx.home / "Library/LaunchAgents" / f"{self.fx.policy['deployment']['plist']['label']}.plist"; original_scan = self.fx.inspector.process_scan
        def mutate_plist():
            plist.write_bytes(b"changed during scan"); os.chmod(plist, 0o600); return [["unrelated"]]
        self.fx.inspector.process_scan = mutate_plist
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL); plist.write_bytes(self.fx.main_plist_bytes); os.chmod(plist, 0o600); self.fx.inspector.process_scan = original_scan
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
        item = self.fx.policy["deployment"]["dependent_consumers"][0]
        for identity in item["process_match_tokens"]:
            expanded = self.fx.ops.resolve(identity)
            self.fx.inspector.process_scan = lambda expanded=expanded: [["/bin/sh", "-c", f"exec {expanded} --synthetic"]]
            with mock.patch.object(deploy.os.path, "expanduser", side_effect=self.fx.ops.resolve):
                with self.subTest(identity=identity), self.assertRaises(deploy.DeploymentError) as caught:
                    deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
        production = deploy.ProductionProcessInspector(home=self.fx.home)
        raw_wrapper = f"402 /bin/bash -lc {item['configured_argv'][2]}\n"
        observed = subprocess.CompletedProcess([deploy.PS_BIN, "-axo", "pid=,command="], 0, stdout=raw_wrapper, stderr="")
        with mock.patch.object(production, "_run", return_value=observed): rows = production.process_scan()
        self.assertEqual(rows[0]["raw"], raw_wrapper.split(None, 1)[1].rstrip("\n"))
        self.fx.inspector.process_scan = lambda: rows
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
    def test_ast_exact_two_names_and_secret_no_clobber(self):
        created = deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(created, {"created": True, "reused": False})
        secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600); self.assertEqual(secret.stat().st_nlink, 1)
        self.assertEqual(deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops), {"created": False, "reused": True})
        different = b'DINGTALK_WEBHOOK="https://oapi.dingtalk.com/robot/send?access_token=different"\nDINGTALK_SECRET="different"\n'
        with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, different, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 78)
        for bad in (b'DINGTALK_WEBHOOK="x"\n', b'DINGTALK_WEBHOOK="x"\nDINGTALK_WEBHOOK="y"\nDINGTALK_SECRET="z"\n', b'DINGTALK_WEBHOOK=DINGTALK_SECRET="x"\n'):
            with self.assertRaises(deploy.DeploymentError): deploy._migrate_credentials_from_bytes(self.fx.policy, bad, ops=self.fx.ops)
        noncanonical = json.dumps({"webhook": VALID_WEBHOOK, "secret": VALID_SECRET}, indent=2).encode()
        secret.write_bytes(noncanonical); os.chmod(secret, 0o600)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT); self.assertEqual(secret.read_bytes(), noncanonical)

    def test_delivery_secret_v1_rejects_invalid_legacy_values_before_writing(self):
        invalid = {
            "blank-secret": (VALID_WEBHOOK, ""),
            "trimmed-secret": (VALID_WEBHOOK, " secret"),
            "control-secret": (VALID_WEBHOOK, "secret\x7f"),
            "unicode-control-secret": (VALID_WEBHOOK, "sec\x85ret"),
            "oversize-secret": (VALID_WEBHOOK, "s" * 4097),
            "http": (VALID_WEBHOOK.replace("https://", "http://"), VALID_SECRET),
            "wrong-host": (VALID_WEBHOOK.replace("oapi.dingtalk.com", "example.com"), VALID_SECRET),
            "userinfo": (VALID_WEBHOOK.replace("oapi.dingtalk.com", "user@oapi.dingtalk.com"), VALID_SECRET),
            "port": (VALID_WEBHOOK.replace("oapi.dingtalk.com", "oapi.dingtalk.com:443"), VALID_SECRET),
            "wrong-path": (VALID_WEBHOOK.replace("/robot/send", "/robot/other"), VALID_SECRET),
            "fragment": (VALID_WEBHOOK + "#fragment", VALID_SECRET),
            "missing-token": ("https://oapi.dingtalk.com/robot/send", VALID_SECRET),
            "blank-token": ("https://oapi.dingtalk.com/robot/send?access_token=", VALID_SECRET),
            "duplicate-token": (VALID_WEBHOOK + "&access_token=second", VALID_SECRET),
            "extra-query": (VALID_WEBHOOK + "&other=value", VALID_SECRET),
            "encoded-token-whitespace": ("https://oapi.dingtalk.com/robot/send?access_token=abc%20def", VALID_SECRET),
            "malformed-token-escape": ("https://oapi.dingtalk.com/robot/send?access_token=%ZZ", VALID_SECRET),
            "oversize-canonical": ("https://oapi.dingtalk.com/robot/send?access_token=t", "\U0001f642" * 4096),
        }
        secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); before = self.fx.tree()
        for name, (webhook, secret) in invalid.items():
            source = f"DINGTALK_WEBHOOK = {webhook!r}\nDINGTALK_SECRET = {secret!r}\n".encode("utf-8")
            with self.subTest(name=name), self.assertRaises(deploy.DeploymentError) as caught:
                deploy._migrate_credentials_from_bytes(self.fx.policy, source, ops=self.fx.ops)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_INTEGRITY); self.assertFalse(secret_path.exists()); self.assertEqual(before, self.fx.tree())

    def test_existing_secret_invalid_duplicate_or_noncanonical_never_clobbered(self):
        secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"]))
        cases = {
            "duplicate-key": ('{"secret":"synthetic-secret","secret":"synthetic-secret","webhook":' + json.dumps(VALID_WEBHOOK) + '}\n').encode(),
            "bom": b'\xef\xbb\xbf{"secret":"synthetic-secret","webhook":"x"}\n',
            "nul": b'{"secret":"synthetic-secret","webhook":"x"}\x00\n',
            "invalid-endpoint": deploy._canonical({"secret": VALID_SECRET, "webhook": "https://example.com/robot/send?access_token=x"}),
            "blank": deploy._canonical({"secret": "", "webhook": VALID_WEBHOOK}),
            "control": deploy._canonical({"secret": "bad\u007f", "webhook": VALID_WEBHOOK}),
            "oversize": deploy._canonical({"secret": "s" * 4097, "webhook": VALID_WEBHOOK}),
            "duplicate-token": deploy._canonical({"secret": VALID_SECRET, "webhook": VALID_WEBHOOK + "&access_token=again"}),
            "encoded-token-whitespace": deploy._canonical({"secret": VALID_SECRET, "webhook": "https://oapi.dingtalk.com/robot/send?access_token=abc%20def"}),
            "over-16k-raw": b"x" * (16 * 1024 + 1),
            "noncanonical-same-value": json.dumps({"webhook": VALID_WEBHOOK, "secret": VALID_SECRET}, indent=2).encode(),
        }
        for name, raw in cases.items():
            secret_path.write_bytes(raw); os.chmod(secret_path, 0o600)
            with self.subTest(name=name), self.assertRaises(deploy.DeploymentError) as caught:
                deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT); self.assertEqual(secret_path.read_bytes(), raw)
            secret_path.unlink()

    def test_supported_migrate_only_creates_then_reuses_exact_secret(self):
        created = deploy.migrate_credentials(self.fx.policy, self.fx.repo, ops=self.fx.ops,
                clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(created, {"created": True, "reused": False})
        secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"]))
        expected = deploy._canonical({"secret": VALID_SECRET, "webhook": VALID_WEBHOOK})
        self.assertEqual(secret.read_bytes(), expected); self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
        reused = deploy.migrate_credentials(self.fx.policy, self.fx.repo, ops=self.fx.ops,
                clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(reused, {"created": False, "reused": True}); self.assertEqual(secret.read_bytes(), expected)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
        self.assertFalse((live / self.fx.policy["deployment"]["runtime_manifest_target"]).exists())
        rollback = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"]))
        self.assertFalse(any(path.name == self.fx.policy["deployment"]["journal_name"] for path in rollback.rglob("*") if path.is_file()))

    def test_migrate_only_cli_outputs_exact_audit_json_and_errors_emit_no_stdout(self):
        policy_path = self.fx.repo / self.fx.policy["deployment"]["policy_path"]
        argv = ["migrate-only", "--policy", str(policy_path), "--repo-root", str(self.fx.repo)]
        outputs = []
        for expected in ('{"created":true,"reused":false}\n', '{"created":false,"reused":true}\n'):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(deploy.sys, "stdout", stdout), mock.patch.object(deploy.sys, "stderr", stderr):
                code = deploy.main(argv, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
            self.assertEqual(code, 0); self.assertEqual(stdout.getvalue(), expected); self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(set(json.loads(stdout.getvalue())), {"created", "reused"}); outputs.append(stdout.getvalue())
        audit = "".join(outputs)
        for forbidden in (VALID_SECRET, VALID_WEBHOOK, "sha256", "release_id", "secret_path", ".openclaw", str(self.fx.home)):
            self.assertNotIn(forbidden, audit)
        self.fx.inspector.active = True; stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(deploy.sys, "stdout", stdout), mock.patch.object(deploy.sys, "stderr", stderr):
            code = deploy.main(argv, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(code, deploy.EXIT_RETRY); self.assertEqual(stdout.getvalue(), ""); self.assertTrue(stderr.getvalue().startswith("ERROR[75]:"))
        self.assertNotIn(VALID_SECRET, stderr.getvalue()); self.assertNotIn(VALID_WEBHOOK, stderr.getvalue())
        self.fx.inspector.active = False; stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(deploy, "migrate_credentials", return_value={"created": True, "reused": True}), \
             mock.patch.object(deploy.sys, "stdout", stdout), mock.patch.object(deploy.sys, "stderr", stderr):
            code = deploy.main(argv, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(code, deploy.EXIT_PROTOCOL); self.assertEqual(stdout.getvalue(), ""); self.assertTrue(stderr.getvalue().startswith("ERROR[76]:"))

    def test_migrate_only_preflight_window_process_and_baseline_fail_with_zero_write(self):
        class ClosedClock:
            def now(self): return datetime.datetime(2026, 8, 5, 4, 0, tzinfo=datetime.timezone.utc)
        scenarios = ("window", "process", "baseline")
        for offset, scenario in enumerate(scenarios):
            with self.subTest(scenario=scenario):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                clock = FixedClock()
                if scenario == "window": clock = ClosedClock()
                elif scenario == "process": self.fx.inspector.active = True
                else:
                    live_run = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])) / "run.py"
                    live_run.write_bytes(b"drift\n"); os.chmod(live_run, 0o644)
                before = self.fx.tree()
                with self.assertRaises(deploy.DeploymentError) as caught:
                    deploy.migrate_credentials(self.fx.policy, self.fx.repo, ops=self.fx.ops,
                            clock=clock, process_inspector=self.fx.inspector)
                expected = deploy.EXIT_RETRY if scenario in ("window", "process") else deploy.EXIT_CONFLICT
                self.assertEqual(caught.exception.exit_code, expected); self.assertEqual(self.fx.tree(), before)

    def test_secret_exact_16k_read_boundary_and_private_ancestor_contract(self):
        secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); parent = secret_path.parent
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            secret_path.write_bytes(b"x" * (16 * 1024)); os.chmod(secret_path, 0o600)
            self.assertEqual(len(deploy._read_secret_at(dfd, secret_path.name)), 16 * 1024)
            secret_path.write_bytes(b"x" * (16 * 1024 + 1)); os.chmod(secret_path, 0o600)
            with self.assertRaises(deploy.DeploymentError) as caught: deploy._read_secret_at(dfd, secret_path.name)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
        finally:
            os.close(dfd); secret_path.unlink()
        for directory in (self.fx.home / ".openclaw", self.fx.home / ".openclaw/secrets"):
            for mode in (0o755, 0o711):
                os.chmod(directory, mode)
                try:
                    with self.subTest(directory=directory.name, mode=oct(mode)), self.assertRaises(deploy.DeploymentError) as caught:
                        deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
                    self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE); self.assertFalse(secret_path.exists())
                finally: os.chmod(directory, 0o700)

    def test_secret_ancestor_owner_and_open_faults_fail_without_fd_leaks(self):
        parent = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])).parent; home = self.fx.home
        baseline_fds = len(os.listdir("/dev/fd")); real_fstat = deploy.os.fstat; fstat_calls = 0
        def foreign_intermediate(fd):
            nonlocal fstat_calls
            value = real_fstat(fd); fstat_calls += 1
            if fstat_calls == 2:
                return types.SimpleNamespace(st_mode=value.st_mode, st_uid=os.getuid() + 1, st_dev=value.st_dev, st_ino=value.st_ino)
            return value
        with mock.patch.object(deploy.os, "fstat", side_effect=foreign_intermediate):
            with self.assertRaises(deploy.DeploymentError) as caught: deploy._open_stable_secret_parent(str(parent), str(home))
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE); self.assertEqual(len(os.listdir("/dev/fd")), baseline_fds)
        real_stat = deploy.os.stat
        def fail_child_named(path, *args, **kwargs):
            if kwargs.get("dir_fd") is not None: raise OSError("synthetic child stat failure")
            return real_stat(path, *args, **kwargs)
        for _ in range(8):
            with mock.patch.object(deploy.os, "stat", side_effect=fail_child_named):
                with self.assertRaises(deploy.DeploymentError): deploy._open_stable_secret_parent(str(parent), str(home))
        self.assertEqual(len(os.listdir("/dev/fd")), baseline_fds)

    def test_secret_file_mode_ctime_and_nlink_races_are_rejected(self):
        deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); real_read = deploy.os.read
        for scenario in ("mode", "ctime", "nlink"):
            changed = False; extra = secret_path.with_name("secret-race-link")
            def mutate_during_read(fd, size):
                nonlocal changed
                data = real_read(fd, size)
                if data and not changed:
                    changed = True
                    if scenario == "mode": os.chmod(secret_path, 0o644)
                    elif scenario == "ctime": os.chmod(secret_path, 0o400); os.chmod(secret_path, 0o600)
                    else: os.link(secret_path, extra)
                return data
            try:
                with mock.patch.object(deploy.os, "read", side_effect=mutate_during_read):
                    with self.subTest(scenario=scenario), self.assertRaises(deploy.DeploymentError) as caught:
                        deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
            finally:
                if extra.exists(): extra.unlink()
                os.chmod(secret_path, 0o600)
    def test_same_value_secret_revalidates_parent_name_and_bytes_before_return(self):
        deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        original = deploy._revalidate_secret_binding
        with mock.patch.object(deploy, "_revalidate_secret_binding", wraps=original) as checked:
            self.assertEqual(deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops), {"created": False, "reused": True})
        self.assertEqual(checked.call_count, 1)
        original_read = deploy._read_secret_at; reads = 0
        def change_revalidated_bytes(dfd, name, oversize_exit=deploy.EXIT_CONFLICT):
            nonlocal reads
            raw = original_read(dfd, name, oversize_exit); reads += 1
            return raw + b" " if reads == 2 else raw
        with mock.patch.object(deploy, "_read_secret_at", side_effect=change_revalidated_bytes):
            with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
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
                with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
        finally:
            secret.unlink(); parent.rmdir(); held.rename(parent)
        original_read = deploy._read_secret_at; reads = 0
        def retarget_after_reread(dfd, name, oversize_exit=deploy.EXIT_CONFLICT):
            nonlocal reads
            raw = original_read(dfd, name, oversize_exit); reads += 1
            if reads == 2:
                parent.rename(held); parent.mkdir(mode=0o700)
            return raw
        try:
            with mock.patch.object(deploy, "_read_secret_at", side_effect=retarget_after_reread):
                with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
        finally:
            parent.rmdir(); held.rename(parent)

    def test_new_secret_postverify_requires_exact_canonical_bytes(self):
        original_read = deploy._read_secret_at; successful_reads = 0
        def alter_postverify(dfd, name, oversize_exit=deploy.EXIT_CONFLICT):
            nonlocal successful_reads
            raw = original_read(dfd, name, oversize_exit); successful_reads += 1
            return raw + b" " if successful_reads == 1 else raw
        with mock.patch.object(deploy, "_read_secret_at", side_effect=alter_postverify):
            with self.assertRaises(deploy.DeploymentError) as caught:
                deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
    def test_secret_fifo_symlink_anchor_traceback_and_owned_temp(self):
        secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); os.mkfifo(secret, 0o600)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 77); secret.unlink()
        parent = secret.parent; real = parent.with_name("sp-monitor-real"); parent.rename(real); parent.symlink_to(real, target_is_directory=True)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 77); parent.unlink(); real.rename(parent)
        marker = "SENSITIVE_MARKER_9f2d"
        try: deploy._migrate_credentials_from_bytes(self.fx.policy, (f'DINGTALK_WEBHOOK="{marker}"\nDINGTALK_SECRET=\n').encode(), ops=self.fx.ops)
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
            with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 73)
        leftovers = list(parent.glob(".report_delivery.tmp.*")); self.assertTrue(any(path.read_bytes() == b"attacker" for path in leftovers))
    def test_secret_hardlink_and_fault_fail_closed(self):
        secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); secret.write_bytes(b"{}\n"); os.chmod(secret, 0o600); os.link(secret, secret.parent / "copy")
        with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
        self.assertEqual(caught.exception.exit_code, 77)
        secret.unlink(); (secret.parent / "copy").unlink()
        with self.assertRaises(deploy.DeploymentError) as caught: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops, fault=deploy.FaultInjector("secret.file.fsync"))
        self.assertEqual(caught.exception.exit_code, 73); self.assertFalse(secret.exists())
    @unittest.skipUnless(hasattr(os, "fork"), "requires a real crashable child process")
    def test_secret_sigkill_reconciles_prelink_linked_and_unlinked_states(self):
        for offset, watched in enumerate(("secret.hardlink", "secret.linked", "secret.unlinked")):
            with self.subTest(watched=watched):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                pid = os.fork()
                if pid == 0:
                    class KillAt(deploy.FaultInjector):
                        def hit(inner, event):
                            if event == watched: os.kill(os.getpid(), signal.SIGKILL)
                    try: deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops, fault=KillAt())
                    except BaseException: os._exit(111)
                    os._exit(0)
                _, status = os.waitpid(pid, 0)
                self.assertTrue(os.WIFSIGNALED(status)); self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); temps = list(secret.parent.glob(".report_delivery.tmp.*"))
                if watched == "secret.hardlink": self.assertFalse(secret.exists()); self.assertEqual(len(temps), 1); self.assertEqual(temps[0].stat().st_nlink, 1)
                elif watched == "secret.linked":
                    self.assertTrue(secret.exists()); self.assertEqual(len(temps), 1); self.assertEqual(secret.stat().st_nlink, 2)
                    self.assertEqual((secret.stat().st_dev, secret.stat().st_ino), (temps[0].stat().st_dev, temps[0].stat().st_ino))
                else: self.assertTrue(secret.exists()); self.assertEqual(temps, []); self.assertEqual(secret.stat().st_nlink, 1)
                recovered = deploy._migrate_credentials_from_bytes(self.fx.policy, self.fx.old_run, ops=self.fx.ops)
                self.assertEqual(recovered["reused"], watched != "secret.hardlink")
                self.assertEqual(list(secret.parent.glob(".report_delivery.tmp.*")), []); self.assertEqual(secret.stat().st_nlink, 1)
                self.assertEqual(secret.read_bytes(), deploy._canonical({"secret": VALID_SECRET, "webhook": VALID_WEBHOOK}))

    @unittest.skipUnless(hasattr(os, "fork"), "requires a real crashable child process")
    def test_backup_and_journal_sigkill_reconcile_private_publish_states(self):
        scenarios = [(kind, suffix) for kind in ("backup", "journal") for suffix in ("link", "linked", "unlinked")]
        for offset, (kind, suffix) in enumerate(scenarios):
            with self.subTest(kind=kind, suffix=suffix):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                release_root = deploy._join(self.fx.policy["deployment"]["rollback_root"], self.fx.runtime["release_id"])
                with deploy._acquire_lock(self.fx.policy, self.fx.ops) as lock: deploy._mkdir_private_locked(release_root, self.fx.ops, lock)
                name = "backup-0.bin" if kind == "backup" else self.fx.policy["deployment"]["journal_name"]
                data = b"exact backup bytes\n" if kind == "backup" else deploy._canonical({"crash_fixture": "journal"})
                event_base = f"crash.{kind}"; watched = event_base + "." + suffix
                pid = os.fork()
                if pid == 0:
                    class KillAt(deploy.FaultInjector):
                        def hit(inner, event):
                            if event == watched: os.kill(os.getpid(), signal.SIGKILL)
                    try:
                        with deploy._acquire_lock(self.fx.policy, self.fx.ops) as lock:
                            with deploy._open_release_scope(self.fx.policy, self.fx.runtime["release_id"], self.fx.ops, lock) as scope:
                                deploy._write_new_release_private(scope, name, data, KillAt(), event_base, lock)
                    except BaseException: os._exit(111)
                    os._exit(0)
                _, status = os.waitpid(pid, 0)
                self.assertTrue(os.WIFSIGNALED(status)); self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                release = Path(self.fx.ops.resolve(release_root)); final = release / name; temps = list(release.glob(f".{name}.release-tmp-*"))
                if suffix == "link": self.assertFalse(final.exists()); self.assertEqual(len(temps), 1); self.assertEqual(temps[0].stat().st_nlink, 1)
                elif suffix == "linked":
                    self.assertTrue(final.exists()); self.assertEqual(len(temps), 1); self.assertEqual(final.stat().st_nlink, 2)
                    self.assertEqual((final.stat().st_dev, final.stat().st_ino), (temps[0].stat().st_dev, temps[0].stat().st_ino))
                else: self.assertTrue(final.exists()); self.assertEqual(temps, []); self.assertEqual(final.stat().st_nlink, 1)
                with deploy._acquire_lock(self.fx.policy, self.fx.ops) as lock:
                    with deploy._open_release_scope(self.fx.policy, self.fx.runtime["release_id"], self.fx.ops, lock) as scope:
                        deploy._write_new_release_private(scope, name, data, deploy.FaultInjector(), event_base, lock)
                self.assertEqual(final.read_bytes(), data); self.assertEqual(stat.S_IMODE(final.stat().st_mode), 0o600); self.assertEqual(final.stat().st_nlink, 1)
                self.assertEqual(list(release.glob(f".{name}.release-tmp-*")), [])

    @unittest.skipUnless(hasattr(os, "fork"), "requires a real crashable child process")
    def test_full_deploy_initial_journal_sigkill_resumes_from_public_entrypoint(self):
        for offset, watched in enumerate(("journal.link", "journal.linked", "journal.unlinked")):
            with self.subTest(watched=watched):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                pid = os.fork()
                if pid == 0:
                    class KillAt(deploy.FaultInjector):
                        def hit(inner, event):
                            if event == watched: os.kill(os.getpid(), signal.SIGKILL)
                    try:
                        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                                clock=FixedClock(), process_inspector=self.fx.inspector, fault=KillAt(), canary=False)
                    except BaseException: os._exit(111)
                    os._exit(0)
                _, status = os.waitpid(pid, 0)
                self.assertTrue(os.WIFSIGNALED(status)); self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
                journal = release / self.fx.policy["deployment"]["journal_name"]
                temps = list(release.glob(f".{journal.name}.release-tmp-*"))
                if watched == "journal.link": self.assertFalse(journal.exists()); self.assertEqual(len(temps), 1); self.assertEqual(temps[0].stat().st_nlink, 1)
                elif watched == "journal.linked":
                    self.assertTrue(journal.exists()); self.assertEqual(len(temps), 1); self.assertEqual(journal.stat().st_nlink, 2)
                    self.assertEqual((journal.stat().st_dev, journal.stat().st_ino), (temps[0].stat().st_dev, temps[0].stat().st_ino))
                else: self.assertTrue(journal.exists()); self.assertEqual(temps, []); self.assertEqual(journal.stat().st_nlink, 1)
                result = deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                        clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
                self.assertTrue(result["recovered"]); self.assertEqual(result["release_id"], self.fx.runtime["release_id"])
                self.assertEqual(list(release.glob(f".{journal.name}.release-tmp-*")), [])
                self.assertEqual(json.loads(journal.read_bytes())["status"], "installed"); self.assertEqual(journal.stat().st_nlink, 1)
                live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
                self.assertEqual((live / "run.py").read_bytes(), self.fx.new_run)
                self.assertEqual(manifest.parse_runtime_release((live / self.fx.policy["deployment"]["runtime_manifest_target"]).read_bytes()), self.fx.runtime)

    @unittest.skipUnless(hasattr(os, "fork"), "requires a real crashable child process")
    def test_initial_journal_crash_residue_ambiguity_and_authority_drift_fail_closed(self):
        scenarios = ("noncanonical", "separate-linked", "bundle", "policy", "two-temps")
        for offset, scenario in enumerate(scenarios):
            with self.subTest(scenario=scenario):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                watched = "journal.linked" if scenario in ("separate-linked", "policy") else "journal.link"
                pid = os.fork()
                if pid == 0:
                    class KillAt(deploy.FaultInjector):
                        def hit(inner, event):
                            if event == watched: os.kill(os.getpid(), signal.SIGKILL)
                    try:
                        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                                clock=FixedClock(), process_inspector=self.fx.inspector, fault=KillAt(), canary=False)
                    except BaseException: os._exit(111)
                    os._exit(0)
                _, status = os.waitpid(pid, 0); self.assertTrue(os.WIFSIGNALED(status)); self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
                journal = release / self.fx.policy["deployment"]["journal_name"]; temps = list(release.glob(f".{journal.name}.release-tmp-*")); self.assertEqual(len(temps), 1)
                if scenario == "noncanonical": temps[0].write_bytes(b"{}\n"); os.chmod(temps[0], 0o600)
                elif scenario == "separate-linked":
                    raw = temps[0].read_bytes(); temps[0].unlink(); temps[0].write_bytes(raw); os.chmod(temps[0], 0o600)
                elif scenario == "bundle":
                    value = json.loads(temps[0].read_bytes()); value["bundle_digest"] = "0" * 64; temps[0].write_bytes(deploy._canonical(value)); os.chmod(temps[0], 0o600)
                elif scenario == "policy":
                    archived = release / deploy.POLICY_ARCHIVE_NAME; other = copy.deepcopy(self.fx.policy); other["baseline"]["live_entrypoint_sha256"] = "9" * 64
                    archived.write_bytes(manifest.canonical_source_policy_bytes(other)); os.chmod(archived, 0o600)
                else:
                    second = release / f".{journal.name}.release-tmp-{'f' * 24}"; second.write_bytes(temps[0].read_bytes()); os.chmod(second, 0o600)
                live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); before = (live / "run.py").read_bytes()
                with self.assertRaises(deploy.DeploymentError) as caught:
                    deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                            clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN); self.assertEqual((live / "run.py").read_bytes(), before)
                self.assertFalse((live / self.fx.policy["deployment"]["runtime_manifest_target"]).exists())
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

    def test_first_release_then_distinct_second_release_reuses_proven_canonical_secret(self):
        first = deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        self.assertTrue(first["deployed"])
        secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); exact_secret = secret_path.read_bytes()
        second_run = b"def main():\n    return 2\n"
        second_blobs = dict(self.fx.blobs); second_blobs["skills/sp-monitor/run.py"] = second_run
        source = self.fx.repo / "skills/sp-monitor/run.py"; source.write_bytes(second_run); os.chmod(source, 0o644)
        second_runtime = manifest.build_runtime_release(self.fx.policy, "b" * 40, second_blobs); self.fx.register_runtime(second_runtime, second_blobs)
        self.assertNotEqual(second_runtime["release_id"], self.fx.runtime["release_id"])
        self.fx.inspector.runtime = second_runtime
        second = deploy.deploy_release(self.fx.policy, second_runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        self.assertTrue(second["deployed"]); self.assertEqual(secret_path.read_bytes(), exact_secret)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); self.assertEqual((live / "run.py").read_bytes(), second_run)
        second_journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / second_runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
        value = json.loads(second_journal.read_bytes()); self.assertEqual(value["status"], "installed"); self.assertEqual(value["secret_sha256"], hashlib.sha256(exact_secret).hexdigest())
        self.assertNotIn(value["secret_sha256"], repr(second))

    def test_cross_policy_consumer_update_can_prepare_resume_and_rollback_to_prior_runtime(self):
        first_policy, first_runtime = copy.deepcopy(self.fx.policy), copy.deepcopy(self.fx.runtime)
        deploy.deploy_release(first_policy, first_runtime, self.fx.repo, ops=self.fx.ops,
                clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        second_policy = copy.deepcopy(first_policy)
        for index, item in enumerate(second_policy["deployment"]["dependent_consumers"], 1):
            chain = manifest.EXACT_DEPENDENT_CHAINS[item["name"]]
            release_id = f"20260806T03000{index}Z-{index + 10}"
            release_path = f"{chain['root']}/releases/{release_id}"
            item["selected_release"].update(target=f"releases/{release_id}", release_id=release_id, release_path=release_path)
            item["plist_sha256"] = hashlib.sha256(f"policy-2-plist:{index}".encode()).hexdigest()
            item["source_files"][0]["sha256"] = hashlib.sha256(f"policy-2-stable:{index}".encode()).hexdigest()
            item["source_files"][1].update(path=release_path + "/" + chain["entry"], sha256=hashlib.sha256(f"policy-2-entry:{index}".encode()).hexdigest())
            item["source_files"][2].update(path=release_path + "/" + chain["helper"], sha256=manifest.EXACT_DEPENDENT_HELPER_SHA256[item["name"]])
            item["process_match_tokens"] = [item["configured_argv"][2], item["source_files"][1]["path"], item["source_files"][2]["path"]]
        manifest.canonical_source_policy_bytes(second_policy)
        second_run = b"def main():\n    return 2\n"
        second_blobs = dict(self.fx.blobs); second_blobs["skills/sp-monitor/run.py"] = second_run
        source = self.fx.repo / "skills/sp-monitor/run.py"; source.write_bytes(second_run); os.chmod(source, 0o644)
        policy_path = self.fx.repo / second_policy["deployment"]["policy_path"]
        policy_path.write_text(json.dumps(second_policy, indent=2, sort_keys=True) + "\n", encoding="utf-8"); os.chmod(policy_path, 0o644)
        second_runtime = manifest.build_runtime_release(second_policy, "b" * 40, second_blobs)
        self.fx.register_runtime(second_runtime, second_blobs, second_policy)
        self.fx.inspector.policy, self.fx.inspector.runtime = second_policy, second_runtime
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(second_policy, second_runtime, self.fx.repo, ops=self.fx.ops,
                    clock=FixedClock(), process_inspector=self.fx.inspector,
                    fault=deploy.FaultInjector("install.1.replace"), canary=False)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
        resumed = deploy.deploy_release(second_policy, second_runtime, self.fx.repo, ops=self.fx.ops,
                clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        self.assertTrue(resumed["recovered"])
        live = Path(self.fx.ops.resolve(second_policy["deployment"]["live_root"]))
        self.assertEqual(manifest.parse_runtime_release((live / second_policy["deployment"]["runtime_manifest_target"]).read_bytes()), second_runtime)
        rolled_back = deploy.rollback_release(second_policy, second_runtime["release_id"], self.fx.repo,
                ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(rolled_back["rolled_back"])
        self.assertEqual(manifest.parse_runtime_release((live / second_policy["deployment"]["runtime_manifest_target"]).read_bytes()), first_runtime)
        self.assertEqual((live / "run.py").read_bytes(), self.fx.new_run)

    def test_installed_prior_journal_is_read_only_for_current_canary_and_distinct_second_verify(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        policy_path = self.fx.base / "installed-policy.json"; runtime_path = self.fx.base / "installed-runtime.json"
        policy_path.write_bytes(manifest.canonical_source_policy_bytes(self.fx.policy)); runtime_path.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_path, 0o600)
        before_canary = self.fx.tree()
        with mock.patch.object(deploy, "run_fake_canary", return_value={"ok": True}) as called:
            code = deploy.main(["canary", "--policy", str(policy_path), "--runtime", str(runtime_path), "--repo-root", str(self.fx.repo)], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(code, 0); called.assert_called_once(); self.assertEqual(before_canary, self.fx.tree())
        second_run = b"def main():\n    return 2\n"; second_blobs = dict(self.fx.blobs); second_blobs["skills/sp-monitor/run.py"] = second_run
        source = self.fx.repo / "skills/sp-monitor/run.py"; source.write_bytes(second_run); os.chmod(source, 0o644)
        second_runtime = manifest.build_runtime_release(self.fx.policy, "b" * 40, second_blobs); self.fx.register_runtime(second_runtime, second_blobs); self.fx.inspector.runtime = second_runtime
        before_verify = self.fx.tree()
        result = deploy.verify_only(self.fx.policy, second_runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["ok"]); self.assertEqual(result["release_id"], second_runtime["release_id"]); self.assertEqual(before_verify, self.fx.tree())

    def test_second_release_refuses_secret_reuse_without_exact_prior_bundle_provenance(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        second_run = b"def main():\n    return 2\n"; second_blobs = dict(self.fx.blobs); second_blobs["skills/sp-monitor/run.py"] = second_run
        source = self.fx.repo / "skills/sp-monitor/run.py"; source.write_bytes(second_run); os.chmod(source, 0o644)
        second_runtime = manifest.build_runtime_release(self.fx.policy, "b" * 40, second_blobs); self.fx.register_runtime(second_runtime, second_blobs); self.fx.inspector.runtime = second_runtime
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); prior_helper = live / "scripts/report_delivery_outbox_v1.py"; prior_helper.write_bytes(b"drift\n"); os.chmod(prior_helper, 0o644)
        before = self.fx.tree()
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, second_runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT); self.assertEqual(before, self.fx.tree())

    def test_second_release_binds_existing_secret_to_installed_prior_journal(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); drift = deploy._canonical({"secret": VALID_SECRET, "webhook": "https://oapi.dingtalk.com/robot/send?access_token=different"})
        secret_path.write_bytes(drift); os.chmod(secret_path, 0o600)
        second_run = b"def main():\n    return 2\n"; second_blobs = dict(self.fx.blobs); second_blobs["skills/sp-monitor/run.py"] = second_run
        source = self.fx.repo / "skills/sp-monitor/run.py"; source.write_bytes(second_run); os.chmod(source, 0o644)
        second_runtime = manifest.build_runtime_release(self.fx.policy, "b" * 40, second_blobs); self.fx.register_runtime(second_runtime, second_blobs); self.fx.inspector.runtime = second_runtime; before = self.fx.tree()
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, second_runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT); self.assertEqual(secret_path.read_bytes(), drift); self.assertEqual(before, self.fx.tree())

    def test_prepared_resume_rebuilds_missing_secret_and_rolls_back_on_secret_conflict(self):
        secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
        with self.assertRaises(deploy.DeploymentError):
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.replace"), canary=False)
        secret_path.unlink()
        result = deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        self.assertTrue(result["recovered"]); self.assertEqual(deploy._parse_secret_fields(secret_path.read_bytes()), (VALID_WEBHOOK, VALID_SECRET))
        for scenario in ("noncanonical", "different-canonical"):
            self.fx.close(); self.fx = DeploymentFixture(self); secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
            with self.assertRaises(deploy.DeploymentError):
                deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.replace"), canary=False)
            raw = (json.dumps({"secret": VALID_SECRET, "webhook": VALID_WEBHOOK}, indent=2).encode() if scenario == "noncanonical" else
                   deploy._canonical({"secret": VALID_SECRET, "webhook": "https://oapi.dingtalk.com/robot/send?access_token=different"}))
            secret_path.write_bytes(raw); os.chmod(secret_path, 0o600)
            with self.subTest(scenario=scenario), self.assertRaises(deploy.DeploymentError) as caught:
                deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_ROLLED_BACK); self.assertEqual(secret_path.read_bytes(), raw); self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
            journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
            self.assertEqual(json.loads(journal.read_bytes())["status"], "rolled_back")

    def test_installed_resume_secret_drift_is_zero_write_fail_closed(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        secret_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])); raw = json.dumps({"secret": VALID_SECRET, "webhook": VALID_WEBHOOK}, indent=2).encode()
        secret_path.write_bytes(raw); os.chmod(secret_path, 0o600); before = self.fx.tree()
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT); self.assertEqual(before, self.fx.tree())
        self.assertNotIn(hashlib.sha256(raw).hexdigest(), str(caught.exception))

    def test_window_rechecked_before_commit_and_rollback_ignores_closed_window(self):
        clock = AdvancingClock(8)
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=clock, process_inspector=self.fx.inspector, canary=False)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_ROLLED_BACK)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
        self.assertEqual(json.loads(journal.read_bytes())["status"], "rolled_back")
        # Explicit safety rollback is also not blocked merely because the
        # forward-deploy window has closed.
        self.fx.close(); self.fx = DeploymentFixture(self)
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        outside = type("OutsideClock", (), {"now": lambda self: datetime.datetime(2026, 8, 5, 3, 21, tzinfo=datetime.timezone.utc)})()
        self.assertTrue(deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=outside, process_inspector=self.fx.inspector)["rolled_back"])

    def test_resume_window_crossing_rolls_back_without_out_of_window_commit(self):
        with self.assertRaises(deploy.DeploymentError):
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.replace"), canary=False)
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=AdvancingClock(6), process_inspector=self.fx.inspector, canary=False)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_ROLLED_BACK)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
        self.assertEqual(json.loads(journal.read_bytes())["status"], "rolled_back")

    def test_dependent_gate_repeats_for_fresh_recover_canary_commits_and_rollback_steps(self):
        with mock.patch.object(deploy, "run_fake_canary", return_value={"ok": True}), mock.patch.object(deploy, "_check_dependents", wraps=deploy._check_dependents) as gated:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertGreaterEqual(gated.call_count, 11)
        with mock.patch.object(deploy, "run_fake_canary", return_value={"ok": True}), mock.patch.object(deploy, "_check_dependents", wraps=deploy._check_dependents) as gated:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertGreaterEqual(gated.call_count, 4)
        with mock.patch.object(deploy, "_check_dependents", wraps=deploy._check_dependents) as gated:
            deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertGreaterEqual(gated.call_count, 6)

        self.fx.close(); self.fx = DeploymentFixture(self)
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.replace"))
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
        with mock.patch.object(deploy, "run_fake_canary", return_value={"ok": True}), mock.patch.object(deploy, "_check_dependents", wraps=deploy._check_dependents) as gated:
            result = deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["recovered"]); self.assertGreaterEqual(gated.call_count, 8)

    def test_drift_at_pre_migration_gate_writes_no_secret_live_file_or_journal(self):
        original = self.fx.inspector.dependent_state; calls = 0; consumer_count = len(self.fx.policy["deployment"]["dependent_consumers"])
        def drift_on_second_gate(item):
            nonlocal calls
            calls += 1; state = original(item)
            if calls > consumer_count: state["credential_contract"] = "legacy_ast_v0"
            return state
        self.fx.inspector.dependent_state = drift_on_second_gate
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); secret = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"]))
        journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
        self.assertFalse(secret.exists()); self.assertFalse(journal.exists())
        self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        self.assertFalse((live / "scripts/report_delivery_outbox_v1.py").exists())

    def test_mid_install_consumer_start_or_source_drift_stops_before_next_install(self):
        for scenario in ("process", "source"):
            with self.subTest(scenario=scenario):
                if scenario != "process": self.fx.close(); self.fx = DeploymentFixture(self)
                inspector = self.fx.inspector; original = inspector.dependent_state
                identity = self.fx.policy["deployment"]["dependent_consumers"][0]["process_match_tokens"][0]
                class DriftAfterFirstInstall(deploy.FaultInjector):
                    def hit(inner, event):
                        inner.events.append(event)
                        if event == "install.0.dir_fsync":
                            if scenario == "process": inspector.process_scan = lambda: [["/bin/bash", "-lc", identity]]
                            else:
                                def drift(item):
                                    state = original(item)
                                    if item["name"] == "single-page-monitor": state["source_files"][0]["sha256"] = "9" * 64
                                    return state
                                inspector.dependent_state = drift
                with self.assertRaises(deploy.DeploymentError) as caught:
                    deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=inspector, fault=DriftAfterFirstInstall())
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
                live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
                self.assertTrue((live / "scripts/report_delivery_outbox_v1.py").exists())
                self.assertFalse((live / "scripts/report_delivery_adapters_v1.py").exists())
                self.assertEqual(json.loads(journal.read_bytes())["status"], "prepared")

    def test_fresh_and_resume_recheck_main_idle_after_final_install_before_canary_or_commit(self):
        for scenario in ("fresh", "resume"):
            with self.subTest(scenario=scenario):
                if scenario == "resume":
                    self.fx.close(); self.fx = DeploymentFixture(self)
                    with self.assertRaises(deploy.DeploymentError) as prepared:
                        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=deploy.FaultInjector("install.1.replace"), canary=False)
                    self.assertEqual(prepared.exception.exit_code, deploy.EXIT_UNCERTAIN)
                inspector = self.fx.inspector
                watched = "install.3.dir_fsync" if scenario == "fresh" else "recover.install.3.dir_fsync"
                class MainStartAfterFinalInstall(deploy.FaultInjector):
                    def hit(inner, event):
                        inner.events.append(event)
                        if event == watched: inspector.active = True
                fault = MainStartAfterFinalInstall()
                with mock.patch.object(deploy, "run_fake_canary") as canary, self.assertRaises(deploy.DeploymentError) as caught:
                    deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=inspector, fault=fault)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN); canary.assert_not_called()
                self.assertNotIn("journal.commit.open", fault.events); self.assertNotIn("recover.journal.commit.open", fault.events)
                journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
                self.assertEqual(json.loads(journal.read_bytes())["status"], "prepared")

    def test_mid_rollback_consumer_start_blocks_next_delete_and_journal_commit(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        inspector = self.fx.inspector; identity = self.fx.policy["deployment"]["dependent_consumers"][0]["process_match_tokens"][0]
        class StartAfterFirstRestore(deploy.FaultInjector):
            def hit(inner, event):
                inner.events.append(event)
                if event == "rollback.3.dir_fsync": inspector.process_scan = lambda: [["/bin/bash", "-lc", identity]]
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=inspector, fault=StartAfterFirstRestore())
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
        self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        self.assertTrue((live / self.fx.policy["deployment"]["runtime_manifest_target"]).exists())
        self.assertEqual(json.loads(journal.read_bytes())["status"], "installed")
    def test_mid_rollback_main_start_blocks_next_mutation_and_journal_commit(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        inspector = self.fx.inspector
        class MainStartAfterFirstRestore(deploy.FaultInjector):
            def hit(inner, event):
                inner.events.append(event)
                if event == "rollback.3.dir_fsync": inspector.active = True
        fault = MainStartAfterFirstRestore()
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=inspector, fault=fault)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_RETRY)
        self.assertNotIn("rollback.2.open", fault.events); self.assertNotIn("journal.rollback.open", fault.events)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
        self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        self.assertTrue((live / self.fx.policy["deployment"]["runtime_manifest_target"]).exists())
        self.assertEqual(json.loads(journal.read_bytes())["status"], "installed")
    def test_health_mid_install_helper_and_current_drift_fail_closed_before_next_write(self):
        health = self.fx.policy["deployment"]["dependent_consumers"][1]; original = self.fx.inspector.dependent_state
        class DriftAfterFirstInstall(deploy.FaultInjector):
            def hit(inner, event):
                inner.events.append(event)
                if event == "install.0.dir_fsync":
                    def drift(item):
                        state = original(item)
                        if item["name"] == health["name"]:
                            state["source_files"][2]["sha256"] = "9" * 64
                        return state
                    self.fx.inspector.dependent_state = drift
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=DriftAfterFirstInstall())
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
        self.assertTrue((live / "scripts/report_delivery_outbox_v1.py").exists())
        self.assertFalse((live / "scripts/report_delivery_adapters_v1.py").exists())
    def test_health_mid_rollback_current_switch_blocks_next_rollback_and_journal(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        health = self.fx.policy["deployment"]["dependent_consumers"][1]; original = self.fx.inspector.dependent_state
        class SwitchAfterFirstRollback(deploy.FaultInjector):
            def hit(inner, event):
                inner.events.append(event)
                if event == "rollback.3.dir_fsync":
                    def switched(item):
                        state = original(item)
                        if item["name"] == health["name"]: state["selected_release"]["target"] = "releases/20260805T030000Z-99"
                        return state
                    self.fx.inspector.dependent_state = switched
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=SwitchAfterFirstRollback())
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
        journal = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]
        self.assertEqual(json.loads(journal.read_bytes())["status"], "installed")
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
    def test_partial_prepared_release_has_private_runtime_authority_for_explicit_rollback(self):
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                    clock=FixedClock(), process_inspector=self.fx.inspector,
                    fault=deploy.FaultInjector("install.1.replace"), canary=False)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
        self.assertFalse((live / self.fx.policy["deployment"]["runtime_manifest_target"]).exists())
        release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
        authority = release / deploy.RUNTIME_ARCHIVE_NAME
        self.assertEqual(authority.read_bytes(), manifest.canonical_runtime_release_bytes(self.fx.runtime))
        self.assertEqual(stat.S_IMODE(authority.stat().st_mode), 0o600)
        self.assertEqual(json.loads((release / self.fx.policy["deployment"]["journal_name"]).read_bytes())["status"], "prepared")
        result = deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], self.fx.repo,
                ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertTrue(result["rolled_back"])
        self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        self.assertFalse((live / "scripts/report_delivery_outbox_v1.py").exists())
        self.assertFalse((live / "scripts/report_delivery_adapters_v1.py").exists())
        self.assertEqual(json.loads((release / self.fx.policy["deployment"]["journal_name"]).read_bytes())["status"], "rolled_back")
    def test_explicit_rollback_requires_exact_private_runtime_authority(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
        authority = release / deploy.RUNTIME_ARCHIVE_NAME; raw = authority.read_bytes(); alias = release / "runtime-authority-hardlink"
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
        live_before = {str(path.relative_to(live)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in live.rglob("*") if path.is_file()}
        for scenario in ("bytes", "mode", "nlink"):
            with self.subTest(scenario=scenario):
                if scenario == "bytes": authority.write_bytes(b"{}\n"); os.chmod(authority, 0o600)
                elif scenario == "mode": os.chmod(authority, 0o644)
                else: os.link(authority, alias)
                fault = deploy.FaultInjector()
                try:
                    with self.assertRaises(deploy.DeploymentError) as caught:
                        deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], self.fx.repo,
                                ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault)
                    self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN); self.assertEqual(fault.events, [])
                    live_after = {str(path.relative_to(live)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in live.rglob("*") if path.is_file()}
                    self.assertEqual(live_before, live_after)
                finally:
                    if alias.exists(): alias.unlink()
                    authority.write_bytes(raw); os.chmod(authority, 0o600)
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
    def test_missing_helper_directory_fails_without_unjournaled_live_creation(self):
        scripts = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])) / "scripts"; scripts.rmdir()
        with self.assertRaises(deploy.DeploymentError) as caught:
            deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_MISSING); self.assertFalse(scripts.exists())
        live = scripts.parent; self.assertEqual((live / "run.py").read_bytes(), self.fx.old_run)
        self.assertFalse(Path(self.fx.ops.resolve(self.fx.policy["deployment"]["secret_path"])).exists())
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
        policy_path.write_bytes(manifest.canonical_source_policy_bytes(bad_policy)); runtime_path.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_path, 0o600)
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
    def test_standalone_canary_runs_full_zero_write_gates_before_execution(self):
        policy_path = self.fx.base / "canary-policy.json"; runtime_path = self.fx.base / "canary-runtime.json"
        policy_path.write_bytes(manifest.canonical_source_policy_bytes(self.fx.policy)); runtime_path.write_bytes(manifest.canonical_runtime_release_bytes(self.fx.runtime)); os.chmod(runtime_path, 0o600)
        before = self.fx.tree(); outside = type("OutsideClock", (), {"now": lambda self: datetime.datetime(2026, 8, 5, 3, 21, tzinfo=datetime.timezone.utc)})()
        with mock.patch.object(deploy, "run_fake_canary") as called, mock.patch("sys.stderr"):
            code = deploy.main(["canary", "--policy", str(policy_path), "--runtime", str(runtime_path), "--repo-root", str(self.fx.repo)], ops=self.fx.ops, clock=outside, process_inspector=self.fx.inspector)
        self.assertEqual(code, deploy.EXIT_RETRY); called.assert_not_called(); self.assertEqual(before, self.fx.tree())
        identity = self.fx.policy["deployment"]["dependent_consumers"][0]["process_match_tokens"][0]
        self.fx.inspector.process_scan = lambda: [["/bin/bash", "-lc", identity]]
        with mock.patch.object(deploy, "run_fake_canary") as called, mock.patch("sys.stderr"):
            code = deploy.main(["canary", "--policy", str(policy_path), "--runtime", str(runtime_path), "--repo-root", str(self.fx.repo)], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(code, deploy.EXIT_CONFLICT); called.assert_not_called(); self.assertEqual(before, self.fx.tree())
        del self.fx.inspector.process_scan; original_verify = deploy.verify_only
        def verify_then_main_starts(*args, **kwargs):
            result = original_verify(*args, **kwargs); self.fx.inspector.active = True; return result
        with mock.patch.object(deploy, "verify_only", side_effect=verify_then_main_starts), mock.patch.object(deploy, "run_fake_canary") as called, mock.patch("sys.stderr"):
            code = deploy.main(["canary", "--policy", str(policy_path), "--runtime", str(runtime_path), "--repo-root", str(self.fx.repo)], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(code, deploy.EXIT_RETRY); called.assert_not_called(); self.assertEqual(before, self.fx.tree())
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
    def test_lock_context_exit_fence_failure_overrides_retry_body_for_every_retained_name(self):
        for offset, target_kind in enumerate(("primary", "guard", "scope")):
            with self.subTest(target_kind=target_kind):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                lock_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["lock_path"])); guard_path = self.fx.home / (lock_path.name + ".guard")
                scope_path = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])); target = {"primary": lock_path, "guard": guard_path, "scope": scope_path}[target_kind]
                moved = target.with_name(target.name + ".body-error-held")
                try:
                    with self.assertRaises(deploy.DeploymentError) as caught:
                        with deploy._acquire_lock(self.fx.policy, self.fx.ops):
                            target.rename(moved)
                            if target_kind == "scope": target.mkdir(mode=0o700)
                            else: target.write_bytes(b"replacement"); os.chmod(target, 0o600)
                            raise deploy.DeploymentError("ordinary retry body", deploy.EXIT_RETRY)
                    self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNSAFE)
                    self.assertIsInstance(caught.exception.__context__, deploy.DeploymentError)
                    self.assertEqual(caught.exception.__context__.exit_code, deploy.EXIT_RETRY)
                finally:
                    if target.exists():
                        if target.is_dir(): target.rmdir()
                        else: target.unlink()
                    if moved.exists(): moved.rename(target)
    def test_journal_traversal_and_delete_fault_are_third_state(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        release_root = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
        journal_path = release_root / self.fx.policy["deployment"]["journal_name"]
        journal = json.loads(journal_path.read_bytes()); journal["entries"][3]["backup"] = "../escape"; journal_path.write_bytes(deploy._canonical(journal)); os.chmod(journal_path, 0o600)
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        self.assertEqual(caught.exception.exit_code, 80)
    def test_explicit_rollback_release_scope_and_journal_metadata_are_fail_closed_zero_live_write(self):
        scenarios = {
            "release-symlink": deploy.EXIT_UNSAFE,
            "release-missing": deploy.EXIT_MISSING,
            "release-mode": deploy.EXIT_UNSAFE,
            "journal-mode": deploy.EXIT_UNCERTAIN,
            "journal-nlink": deploy.EXIT_UNCERTAIN,
        }
        for offset, (scenario, expected_exit) in enumerate(scenarios.items()):
            with self.subTest(scenario=scenario):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
                release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
                journal = release / self.fx.policy["deployment"]["journal_name"]; journal_raw = journal.read_bytes()
                live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"]))
                live_before = {str(path.relative_to(live)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in live.rglob("*") if path.is_file()}
                held = release.with_name(release.name + ".held"); alias = release / "journal-hardlink"
                try:
                    if scenario == "release-symlink": release.rename(held); release.symlink_to(held.name, target_is_directory=True)
                    elif scenario == "release-missing": release.rename(held)
                    elif scenario == "release-mode": os.chmod(release, 0o755)
                    elif scenario == "journal-mode": os.chmod(journal, 0o644)
                    else: os.link(journal, alias)
                    fault = deploy.FaultInjector()
                    with self.assertRaises(deploy.DeploymentError) as caught:
                        deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault)
                    self.assertEqual(caught.exception.exit_code, expected_exit); self.assertEqual(fault.events, [])
                    live_after = {str(path.relative_to(live)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in live.rglob("*") if path.is_file()}
                    self.assertEqual(live_before, live_after)
                finally:
                    if alias.exists(): alias.unlink()
                    if release.is_symlink(): release.unlink()
                    if held.exists(): held.rename(release)
                    if release.exists(): os.chmod(release, 0o700)
                    if journal.exists(): os.chmod(journal, 0o600)
                self.assertEqual(journal.read_bytes(), journal_raw)
    def test_release_private_read_rejects_named_metadata_change_after_same_fd_read(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        name = self.fx.policy["deployment"]["journal_name"]; real_stat = deploy.os.stat
        with deploy._acquire_lock(self.fx.policy, self.fx.ops) as lock:
            with deploy._open_release_scope(self.fx.policy, self.fx.runtime["release_id"], self.fx.ops, lock) as scope:
                calls = 0
                def change_named_mode(path, *args, **kwargs):
                    nonlocal calls
                    if path == name and kwargs.get("dir_fd") == scope.fd:
                        calls += 1
                        if calls == 2: os.chmod(name, 0o644, dir_fd=scope.fd, follow_symlinks=False)
                    return real_stat(path, *args, **kwargs)
                with mock.patch.object(deploy.os, "stat", side_effect=change_named_mode), self.assertRaises(deploy.DeploymentError) as caught:
                    scope.read_private(name)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
                os.chmod(name, 0o600, dir_fd=scope.fd, follow_symlinks=False)
    def test_journal_status_replacements_use_exact_compare_before_replace(self):
        for scenario in ("fresh-commit", "rollback-commit"):
            with self.subTest(scenario=scenario):
                if scenario == "rollback-commit":
                    self.fx.close(); self.fx = DeploymentFixture(self)
                    deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
                release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
                journal = release / self.fx.policy["deployment"]["journal_name"]
                watched = "journal.commit.compare" if scenario == "fresh-commit" else "journal.rollback.compare"
                class JournalDriftAtCompare(deploy.FaultInjector):
                    def hit(inner, event):
                        inner.events.append(event)
                        if event == watched:
                            journal.write_bytes(b"external journal drift\n"); os.chmod(journal, 0o600)
                fault = JournalDriftAtCompare()
                with self.assertRaises(deploy.DeploymentError) as caught:
                    if scenario == "fresh-commit":
                        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault, canary=False)
                    else:
                        deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_UNCERTAIN)
                self.assertEqual(journal.read_bytes(), b"external journal drift\n")
    def test_fresh_release_scope_retarget_is_detected_during_backup_journal_and_commit(self):
        for offset, watched in enumerate(("backup.3.open", "journal.open", "journal.commit.compare")):
            with self.subTest(watched=watched):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
                held = release.with_name(release.name + ".retarget-held")
                class RetargetReleaseScope(deploy.FaultInjector):
                    def hit(inner, event):
                        inner.events.append(event)
                        if event == watched:
                            release.rename(held); release.symlink_to(held.name, target_is_directory=True)
                fault = RetargetReleaseScope()
                try:
                    with self.assertRaises(deploy.DeploymentError) as caught:
                        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault, canary=False)
                    self.assertIn(caught.exception.exit_code, (deploy.EXIT_UNSAFE, deploy.EXIT_UNCERTAIN))
                finally:
                    if release.is_symlink(): release.unlink()
                    if held.exists(): held.rename(release)
                journal = release / self.fx.policy["deployment"]["journal_name"]
                if journal.exists(): self.assertEqual(json.loads(journal.read_bytes())["status"], "prepared")
    def test_live_root_and_scripts_retarget_are_detected_across_backup_install_canary_commit_and_rollback(self):
        fresh_scenarios = (
            ("backup", "backup.3.open", "root"),
            ("install", "install.0.compare", "scripts"),
            ("commit", "journal.commit.compare", "root"),
        )
        for offset, (scenario, watched, target_kind) in enumerate(fresh_scenarios):
            with self.subTest(scenario=scenario):
                if offset:
                    self.fx.close(); self.fx = DeploymentFixture(self)
                live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); target = live if target_kind == "root" else live / "scripts"
                held = target.with_name(target.name + ".retarget-held")
                class RetargetAtEvent(deploy.FaultInjector):
                    def hit(inner, event):
                        inner.events.append(event)
                        if event == watched:
                            target.rename(held); target.symlink_to(held.name, target_is_directory=True)
                fault = RetargetAtEvent()
                try:
                    with self.assertRaises(deploy.DeploymentError) as caught:
                        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                                clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault, canary=False)
                    self.assertIn(caught.exception.exit_code, (deploy.EXIT_UNSAFE, deploy.EXIT_UNCERTAIN)); self.assertIn(watched, fault.events)
                    if scenario == "install": self.assertNotIn("install.0.replace", fault.events)
                    if scenario == "commit": self.assertNotIn("journal.commit.replace", fault.events)
                finally:
                    if target.is_symlink(): target.unlink()
                    if held.exists(): held.rename(target)
                release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
                journal = release / self.fx.policy["deployment"]["journal_name"]
                if journal.exists(): self.assertEqual(json.loads(journal.read_bytes())["status"], "prepared")
        self.fx.close(); self.fx = DeploymentFixture(self)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); held = live.with_name(live.name + ".canary-held")
        def retarget_during_canary(*args, **kwargs):
            live.rename(held); live.symlink_to(held.name, target_is_directory=True); return {"ok": True}
        try:
            with mock.patch.object(deploy, "run_fake_canary", side_effect=retarget_during_canary) as called, self.assertRaises(deploy.DeploymentError) as caught:
                deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                        clock=FixedClock(), process_inspector=self.fx.inspector, canary=True)
            called.assert_called_once(); self.assertIn(caught.exception.exit_code, (deploy.EXIT_UNSAFE, deploy.EXIT_UNCERTAIN))
        finally:
            if live.is_symlink(): live.unlink()
            if held.exists(): held.rename(live)
        release = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"]
        self.assertEqual(json.loads((release / self.fx.policy["deployment"]["journal_name"]).read_bytes())["status"], "prepared")
        self.fx.close(); self.fx = DeploymentFixture(self)
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops,
                clock=FixedClock(), process_inspector=self.fx.inspector, canary=False)
        live = Path(self.fx.ops.resolve(self.fx.policy["deployment"]["live_root"])); held = live.with_name(live.name + ".rollback-held")
        expected_targets = [item["target"] for item in self.fx.policy["bundle"][:2]] + [self.fx.policy["deployment"]["runtime_manifest_target"], self.fx.policy["bundle"][2]["target"]]
        before = {target: ((live / target).read_bytes(), stat.S_IMODE((live / target).stat().st_mode)) for target in expected_targets}
        watched = "rollback.3.compare"
        class RetargetRollback(deploy.FaultInjector):
            def hit(inner, event):
                inner.events.append(event)
                if event == watched:
                    live.rename(held); live.symlink_to(held.name, target_is_directory=True)
        fault = RetargetRollback()
        try:
            with self.assertRaises(deploy.DeploymentError) as caught:
                deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops,
                        clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault)
            self.assertIn(caught.exception.exit_code, (deploy.EXIT_UNSAFE, deploy.EXIT_UNCERTAIN)); self.assertNotIn("rollback.3.replace", fault.events)
        finally:
            if live.is_symlink(): live.unlink()
            if held.exists(): held.rename(live)
        after = {target: ((live / target).read_bytes(), stat.S_IMODE((live / target).stat().st_mode)) for target in expected_targets}
        self.assertEqual(after, before)
        self.assertEqual(json.loads((Path(self.fx.ops.resolve(self.fx.policy["deployment"]["rollback_root"])) / self.fx.runtime["release_id"] / self.fx.policy["deployment"]["journal_name"]).read_bytes())["status"], "installed")
    def test_rollback_delete_after_unlink_fault_is_uncertain(self):
        deploy.deploy_release(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
        fault = deploy.FaultInjector("rollback.2.dir_fsync")
        with self.assertRaises(deploy.DeploymentError) as caught: deploy.rollback_release(self.fx.policy, self.fx.runtime["release_id"], ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector, fault=fault)
        self.assertEqual(caught.exception.exit_code, 80)
    def test_migrated_dependent_hash_contract_state_pid_and_process_gates(self):
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
        def assert_state_rejected(mutate):
            def changed(consumer):
                state = original(consumer)
                if consumer["name"] == item["name"]: mutate(state)
                return state
            self.fx.inspector.dependent_state = changed
            with self.assertRaises(deploy.DeploymentError) as caught:
                deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
        assert_state_rejected(lambda state: state.update(credential_contract="legacy_ast_v0"))
        assert_state_rejected(lambda state: state.update(plist_sha256="9" * 64))
        assert_state_rejected(lambda state: next(iter(state["labels"].values())).update(enabled=False))
        assert_state_rejected(lambda state: next(iter(state["labels"].values())).update(loaded=False))
        assert_state_rejected(lambda state: next(iter(state["labels"].values())).update(pid=4312))
        assert_state_rejected(lambda state: next(iter(state["labels"].values())).update(runtime_argv=list(item["configured_argv"])))
        self.fx.inspector.dependent_state = original
        self.assertTrue(deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)["ok"])
    def test_exact_single_loaded_and_fb_unloaded_launch_states_are_enforced(self):
        consumers = self.fx.policy["deployment"]["dependent_consumers"]
        self.assertEqual([item["required_launch_state"] for item in consumers], [
            {"enabled": True, "loaded": True},
            {"enabled": True, "loaded": True},
            {"enabled": False, "loaded": False},
            {"enabled": False, "loaded": False},
        ])
        self.assertTrue(deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)["ok"])
        original = self.fx.inspector.dependent_state
        def rejected_state(name, **changes):
            def changed(item):
                state = original(item)
                if item["name"] == name: next(iter(state["labels"].values())).update(changes)
                return state
            self.fx.inspector.dependent_state = changed
            try:
                with self.assertRaises(deploy.DeploymentError) as caught:
                    deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
            finally: self.fx.inspector.dependent_state = original
        for item in consumers[:2]:
            with self.subTest(name=item["name"], state="unloaded"): rejected_state(item["name"], loaded=False)
            with self.subTest(name=item["name"], state="disabled"): rejected_state(item["name"], enabled=False)
        for item in consumers[2:]:
            with self.subTest(name=item["name"], state="loaded"): rejected_state(item["name"], loaded=True)
            with self.subTest(name=item["name"], state="enabled"): rejected_state(item["name"], enabled=True)
            with self.subTest(name=item["name"], state="pid"): rejected_state(item["name"], pid=50123)
            self.fx.inspector.process_scan = lambda item=item: [["/bin/bash", "-lc", item["process_match_tokens"][0]]]
            with self.subTest(name=item["name"], state="matching-process"), self.assertRaises(deploy.DeploymentError) as caught:
                deploy.verify_only(self.fx.policy, self.fx.runtime, self.fx.repo, ops=self.fx.ops, clock=FixedClock(), process_inspector=self.fx.inspector)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
            self.fx.inspector.process_scan = lambda: [["unrelated"]]
    def test_loaded_launchctl_argv_is_exact_and_malformed_output_fails_closed(self):
        inspector = deploy.ProductionProcessInspector(home=self.fx.home); label = "synthetic.loaded"; configured = ["/bin/bash", "-lc", "echo reviewed"]
        outputs = {
            "empty": ("", deploy.EXIT_PROTOCOL),
            "unterminated": ("\tprogram = /bin/bash\n\targuments = {\n\t\t/bin/bash\n", deploy.EXIT_PROTOCOL),
            "program-mismatch": (launchctl_print_output(label, configured).replace("program = /bin/bash", "program = /usr/bin/env"), deploy.EXIT_PROTOCOL),
            "path-drift": (launchctl_print_output(label, configured).replace(str(Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"), "/tmp/unreviewed.plist"), deploy.EXIT_CONFLICT),
            "stale": (launchctl_print_output(label, ["/bin/bash", "-lc", "/tmp/unreviewed --unsafe"]), deploy.EXIT_CONFLICT),
        }
        for name, (printed, expected_exit) in outputs.items():
            def observed(argv, accepted=(0,), env=None, printed=printed):
                if argv[:2] == [deploy.LAUNCHCTL_BIN, "print"]: return subprocess.CompletedProcess(argv, 0, stdout=printed, stderr="")
                if argv[:2] == [deploy.LAUNCHCTL_BIN, "print-disabled"]: return subprocess.CompletedProcess(argv, 0, stdout=f'"{label}" => false\n', stderr="")
                if argv[:3] == [deploy.PS_BIN, "-axo", "pid=,command="]: return subprocess.CompletedProcess(argv, 0, stdout="401 /bin/echo unrelated\n", stderr="")
                raise AssertionError(argv)
            with self.subTest(name=name), mock.patch.object(inspector, "_run", side_effect=observed), self.assertRaises(deploy.DeploymentError) as caught:
                inspector._launch(label, configured, ["echo reviewed"])
            self.assertEqual(caught.exception.exit_code, expected_exit)
    def test_main_fb_plist_and_loaded_semantic_drift_are_rejected(self):
        inspector = deploy.ProductionProcessInspector(home=self.fx.home)
        main_path = self.fx.home / "Library/LaunchAgents" / f"{manifest.EXACT_MAIN_PLIST['label']}.plist"
        main_contract = manifest.exact_main_plist_value(str(self.fx.home)); main_raw = main_path.read_bytes()
        main_mutations = (
            lambda value: value.update(Label="ai.openclaw.sp.other"),
            lambda value: value.update(RunAtLoad=True),
            lambda value: value.update(StartCalendarInterval={"Hour": 11, "Minute": 31}),
            lambda value: value["EnvironmentVariables"].update(HOME="/tmp/shadow"),
            lambda value: value.update(KeepAlive=True),
        )
        for index, mutate in enumerate(main_mutations):
            value = plistlib.loads(main_raw); mutate(value)
            main_path.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)); os.chmod(main_path, 0o600)
            try:
                with self.subTest(main=index), self.assertRaises(deploy.DeploymentError) as caught:
                    inspector._plist(manifest.EXACT_MAIN_PLIST["label"], exact_value=main_contract)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally: main_path.write_bytes(main_raw); os.chmod(main_path, 0o600)
        fb_name = "fb-verify"; fb_contract = manifest.EXACT_DEPENDENT_PLISTS[fb_name]
        fb_path = self.fx.home / "Library/LaunchAgents" / f"{fb_contract['Label']}.plist"
        fb_raw = plistlib.dumps(fb_contract, fmt=plistlib.FMT_XML, sort_keys=True); fb_path.write_bytes(fb_raw); os.chmod(fb_path, 0o644)
        for index, mutate in enumerate((lambda value: value.update(Label="com.spspy.fb-other"), lambda value: value.update(RunAtLoad=True), lambda value: value.update(KeepAlive=True))):
            value = plistlib.loads(fb_raw); mutate(value); fb_path.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)); os.chmod(fb_path, 0o644)
            with self.subTest(fb=index), self.assertRaises(deploy.DeploymentError) as caught:
                inspector._plist(fb_contract["Label"], exact_value=fb_contract)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
        fb_path.write_bytes(fb_raw); os.chmod(fb_path, 0o644)
        argv = main_contract["ProgramArguments"]
        with mock.patch.object(deploy.Path, "home", return_value=self.fx.home): loaded = launchctl_print_output(main_contract["Label"], argv)
        loaded_mutations = (
            loaded.replace('"Hour" => 11', '"Hour" => 12'),
            loaded.replace("properties = inferred program", "properties = inferred program | keepalive"),
            loaded.replace(f"HOME => {self.fx.home}", "HOME => /tmp/shadow"),
            loaded.replace("properties = inferred program", "properties = inferred program | runatload"),
            loaded.replace("\tproperties =", "\trun interval = 60 seconds\n\tproperties ="),
        )
        for index, output in enumerate(loaded_mutations):
            with self.subTest(loaded=index), self.assertRaises(deploy.DeploymentError) as caught:
                inspector._loaded_launch_config(output, main_contract["Label"], main_contract)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_CONFLICT)
    def test_production_plist_final_component_is_nofollow_owned_single_link_exact_mode(self):
        inspector = deploy.ProductionProcessInspector(home=self.fx.home); plist = self.fx.policy["deployment"]["plist"]
        path = self.fx.home / "Library/LaunchAgents" / f"{plist['label']}.plist"; held = path.with_name(path.name + ".held")
        with mock.patch.object(deploy.Path, "home", return_value=self.fx.home):
            raw, argv = inspector._plist(plist["label"], plist["plist_keys"], plist["environment_variable_keys"])
            self.assertEqual(raw, self.fx.main_plist_bytes); self.assertEqual(argv[2:], plist["arguments"])
            os.chmod(path, 0o644)
            try:
                with self.assertRaises(deploy.DeploymentError) as caught: inspector._plist(plist["label"])
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally: os.chmod(path, 0o600)
            path.rename(held); path.symlink_to(held.name)
            try:
                with self.assertRaises(deploy.DeploymentError) as caught: inspector._plist(plist["label"])
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally:
                path.unlink(); held.rename(path)
    def test_production_inspector_uses_full_main_shape_and_policy_bound_dependent_sources(self):
        inspector = deploy.ProductionProcessInspector(home=self.fx.home); ps_output = ["401 /bin/bash -lc 'echo unrelated'"]
        def observed(argv, accepted=(0,), env=None):
            if argv[:2] == [deploy.LAUNCHCTL_BIN, "print"]:
                label = argv[-1].rsplit("/", 1)[-1]
                states = {item["labels"][0]: item["required_launch_state"] for item in self.fx.policy["deployment"]["dependent_consumers"]}
                code = 0 if label == self.fx.policy["deployment"]["plist"]["label"] or states.get(label, {}).get("loaded") is True else 113
                if label == self.fx.policy["deployment"]["plist"]["label"]:
                    plist = self.fx.policy["deployment"]["plist"]
                    configured = [self.fx.ops.resolve(plist["interpreter"]), self.fx.ops.resolve(plist["entrypoint"]), *plist["arguments"]]
                else:
                    configured = next((item["configured_argv"] for item in self.fx.policy["deployment"]["dependent_consumers"] if item["labels"][0] == label), [])
                stdout = launchctl_print_output(label, configured) if code == 0 else ""
                return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr="")
            if argv[:2] == [deploy.LAUNCHCTL_BIN, "print-disabled"]:
                values = [f'"{self.fx.policy["deployment"]["plist"]["label"]}" => false'] + [f'"{item["labels"][0]}" => {str(not item["required_launch_state"]["enabled"]).lower()}' for item in self.fx.policy["deployment"]["dependent_consumers"]]
                return subprocess.CompletedProcess(argv, 0, stdout="\n".join(values), stderr="")
            if argv[:3] == [deploy.PS_BIN, "-axo", "pid=,command="]:
                return subprocess.CompletedProcess(argv, 0, stdout="\n".join(ps_output) + "\n", stderr="")
            raise AssertionError(argv)
        with mock.patch.object(deploy.Path, "home", return_value=self.fx.home), mock.patch.object(inspector, "_run", side_effect=observed):
            main = inspector.main_state(self.fx.policy["deployment"]["plist"])
            self.assertEqual(main["argv"][1], self.fx.ops.resolve(self.fx.policy["deployment"]["plist"]["entrypoint"])); self.assertTrue(main["loaded"] and main["enabled"])
            for fb_item in self.fx.policy["deployment"]["dependent_consumers"][2:]:
                observed_fb = inspector._launch(fb_item["labels"][0], fb_item["configured_argv"], fb_item["process_match_tokens"])
                self.assertEqual(observed_fb, {"enabled": False, "loaded": False, "pid": None, "configured_argv": fb_item["configured_argv"], "runtime_argv": []})
            item = copy.deepcopy(self.fx.policy["deployment"]["dependent_consumers"][0]); source = self.fx.base / "policy-bound-dependent.sh"; source.write_bytes(b"exact dependent source\n"); os.chmod(source, 0o644)
            # Production observation is exercised with the policy's exact
            # three-role chain; materialize that topology under a synthetic home.
            release_id = "20260805T030001Z-1"; chain = manifest.EXACT_DEPENDENT_CHAINS[item["name"]]
            root = self.fx.home / ".spspy-single-page-monitor"; release = root / "releases" / release_id
            (release / "single-page-monitor/scripts").mkdir(parents=True); (root / "single-page-monitor").mkdir(parents=True, exist_ok=True)
            current = root / "current"; current.symlink_to(f"releases/{release_id}")
            stable = root / "single-page-monitor/run_daily.sh"; stable.write_bytes(b"stable wrapper current\n")
            entry = release / "single-page-monitor/run_daily.sh"; entry.write_bytes(b"selected entry\n")
            helper = release / "single-page-monitor/scripts/notify_dingtalk.py"
            reviewed_helper = (ROOT / "single-page-monitor/scripts/notify_dingtalk.py").read_bytes()
            self.assertEqual(hashlib.sha256(reviewed_helper).hexdigest(), deploy.manifest.EXACT_DEPENDENT_HELPER_SHA256[item["name"]])
            helper.write_bytes(reviewed_helper)
            expected_modes = {"stable_wrapper": 0o755, "selected_entrypoint": 0o555, "notify_helper": 0o555}
            for path, role in ((stable, "stable_wrapper"), (entry, "selected_entrypoint"), (helper, "notify_helper")): os.chmod(path, expected_modes[role])
            item["selected_release"].update(root="~/.spspy-single-page-monitor", current_path="~/.spspy-single-page-monitor/current", target=f"releases/{release_id}", release_id=release_id, release_path=f"~/.spspy-single-page-monitor/releases/{release_id}")
            item["source_files"] = [
                {"role": "stable_wrapper", "path": "~/.spspy-single-page-monitor/single-page-monitor/run_daily.sh", "mode": "0755", "sha256": hashlib.sha256(stable.read_bytes()).hexdigest()},
                {"role": "selected_entrypoint", "path": f"~/.spspy-single-page-monitor/releases/{release_id}/single-page-monitor/run_daily.sh", "mode": "0555", "sha256": hashlib.sha256(entry.read_bytes()).hexdigest()},
                {"role": "notify_helper", "path": f"~/.spspy-single-page-monitor/releases/{release_id}/single-page-monitor/scripts/notify_dingtalk.py", "mode": "0555", "sha256": hashlib.sha256(helper.read_bytes()).hexdigest()},
            ]; item["unresolved"] = False
            item["process_match_tokens"] = [item["configured_argv"][2], item["source_files"][1]["path"], item["source_files"][2]["path"]]
            dependent_plist = plistlib.dumps(manifest.EXACT_DEPENDENT_PLISTS[item["name"]], fmt=plistlib.FMT_XML, sort_keys=True)
            dependent_path = self.fx.home / "Library/LaunchAgents" / f"{item['labels'][0]}.plist"; dependent_path.write_bytes(dependent_plist); os.chmod(dependent_path, 0o644); item["plist_sha256"] = hashlib.sha256(dependent_plist).hexdigest()
            state = inspector.dependent_state(item)
            self.assertEqual(set(state), {"source_files", "selected_release", "plist_sha256", "credential_contract", "binding", "labels"})
            self.assertEqual(state["source_files"], item["source_files"]); self.assertEqual(state["credential_contract"], "report_delivery_secret_v1"); self.assertEqual(state["labels"][item["labels"][0]]["runtime_argv"], [])
            os.chmod(dependent_path, 0o600)
            try:
                with self.assertRaises(deploy.DeploymentError) as caught: inspector.dependent_state(item)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally: os.chmod(dependent_path, 0o644)
            releases_directory = root / "releases"; held_releases = root / "releases-real"
            releases_directory.rename(held_releases); releases_directory.symlink_to(held_releases.name, target_is_directory=True)
            try:
                with self.assertRaises(deploy.DeploymentError) as caught: inspector.dependent_state(item)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally:
                releases_directory.unlink(); held_releases.rename(releases_directory)
            os.chmod(releases_directory, 0o777)
            try:
                with self.assertRaises(deploy.DeploymentError) as caught: inspector.dependent_state(item)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally: os.chmod(releases_directory, 0o755)
            ps_output[:] = [f"402 /bin/bash -lc '{item['process_match_tokens'][0]}'"]
            active = inspector.dependent_state(item); self.assertEqual(active["labels"][item["labels"][0]]["runtime_argv"], item["configured_argv"])
            ps_output[:] = ["401 /bin/bash -lc 'echo unrelated'"]
            spoof = b"# report_delivery.json\nif False:\n    def load_credentials():\n        return None\n"
            os.chmod(helper, 0o644); helper.write_bytes(spoof); os.chmod(helper, expected_modes["notify_helper"])
            spoofed = inspector.dependent_state(item)
            self.assertIsNone(spoofed["credential_contract"]); self.assertNotEqual(spoofed["source_files"], item["source_files"])
            os.chmod(helper, 0o644); helper.write_bytes(reviewed_helper); os.chmod(helper, expected_modes["notify_helper"])
            for source_path, role in ((stable, "stable_wrapper"), (entry, "selected_entrypoint"), (helper, "notify_helper")):
                os.chmod(source_path, 0o666)
                with self.subTest(source=source_path.name), self.assertRaises(deploy.DeploymentError) as caught:
                    inspector.dependent_state(item)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL); os.chmod(source_path, expected_modes[role])
            original_plist = inspector._plist
            for source_path, role in ((stable, "stable_wrapper"), (entry, "selected_entrypoint"), (helper, "notify_helper")):
                plist_calls = 0
                def change_safe_source_mode_between_snapshots(*args, source_path=source_path, **kwargs):
                    nonlocal plist_calls
                    plist_calls += 1
                    if plist_calls == 2: os.chmod(source_path, 0o600)
                    return original_plist(*args, **kwargs)
                try:
                    with mock.patch.object(inspector, "_plist", side_effect=change_safe_source_mode_between_snapshots):
                        with self.subTest(mode_drift=source_path.name), self.assertRaises(deploy.DeploymentError) as caught:
                            inspector.dependent_state(item)
                    self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
                finally: os.chmod(source_path, expected_modes[role])
            os.chmod(release, 0o777)
            with self.assertRaises(deploy.DeploymentError) as caught: inspector.dependent_state(item)
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL); os.chmod(release, 0o755)
            alternate_id = "20260805T030009Z-9"; alternate = root / "releases" / alternate_id; alternate.mkdir(mode=0o755)
            held_current = root / "current.held"
            current.rename(held_current); current.symlink_to(f"releases/{alternate_id}")
            try:
                with self.assertRaises(deploy.DeploymentError) as caught: inspector.dependent_state(item)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally:
                current.unlink(); held_current.rename(current)
            original_plist = inspector._plist; plist_calls = 0
            def replace_current_between_snapshots(*args, **kwargs):
                nonlocal plist_calls
                plist_calls += 1
                if plist_calls == 2:
                    current.rename(held_current); current.symlink_to(f"releases/{release_id}")
                return original_plist(*args, **kwargs)
            try:
                with mock.patch.object(inspector, "_plist", side_effect=replace_current_between_snapshots):
                    with self.assertRaises(deploy.DeploymentError) as caught: inspector.dependent_state(item)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally:
                if held_current.exists() or held_current.is_symlink():
                    current.unlink(); held_current.rename(current)
            held_release = release.with_name(release.name + ".held"); plist_calls = 0
            def replace_release_inode_between_snapshots(*args, **kwargs):
                nonlocal plist_calls
                plist_calls += 1
                if plist_calls == 2:
                    release.rename(held_release); release.mkdir(mode=0o755)
                    (held_release / "single-page-monitor").rename(release / "single-page-monitor")
                return original_plist(*args, **kwargs)
            try:
                with mock.patch.object(inspector, "_plist", side_effect=replace_release_inode_between_snapshots):
                    with self.assertRaises(deploy.DeploymentError) as caught: inspector.dependent_state(item)
                self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            finally:
                if held_release.exists():
                    (release / "single-page-monitor").rename(held_release / "single-page-monitor")
                    release.rmdir(); held_release.rename(release)
            malformed = plistlib.loads(self.fx.main_plist_bytes); malformed["Unexpected"] = "x"
            main_path = self.fx.home / "Library/LaunchAgents" / f"{self.fx.policy['deployment']['plist']['label']}.plist"; main_path.write_bytes(plistlib.dumps(malformed, fmt=plistlib.FMT_XML, sort_keys=True)); os.chmod(main_path, 0o600)
            with self.assertRaises(deploy.DeploymentError) as caught: inspector.main_state(self.fx.policy["deployment"]["plist"])
            self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
            main_path.write_bytes(self.fx.main_plist_bytes); os.chmod(main_path, 0o600)
    def test_production_dependent_double_snapshot_rejects_helper_or_current_toctou(self):
        inspector = deploy.ProductionProcessInspector(home=self.fx.home); item = self.fx.policy["deployment"]["dependent_consumers"][1]
        sources = copy.deepcopy(item["source_files"]); binding = hashlib.sha256(deploy._canonical({"selected_release": item["selected_release"], "sources": sources})).hexdigest()
        fingerprint = ((1, 2, 3), (4, 5, 6))
        first = (sources, "report_delivery_secret_v1", binding, fingerprint)
        changed_helper = copy.deepcopy(sources); changed_helper[2]["sha256"] = "9" * 64
        changed_binding = hashlib.sha256(deploy._canonical({"selected_release": item["selected_release"], "sources": changed_helper})).hexdigest()
        with mock.patch.object(inspector, "_plist", side_effect=[(b"plist", item["configured_argv"]), (b"plist", item["configured_argv"])]), \
             mock.patch.object(inspector, "_dependent_snapshot", side_effect=[first, (changed_helper, "report_delivery_secret_v1", changed_binding, fingerprint)]):
            with self.assertRaises(deploy.DeploymentError) as caught: inspector.dependent_state(item)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
        switched = copy.deepcopy(item["selected_release"]); switched["target"] = "releases/20260805T030000Z-99"
        switched_binding = hashlib.sha256(deploy._canonical({"selected_release": switched, "sources": sources})).hexdigest()
        # The inspector uses the selected-release observation in its binding;
        # a real current-link switch is rejected by _selected_release before
        # this point, and a mismatching returned state is rejected by the gate.
        self.assertNotEqual(binding, switched_binding)
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
        completed = subprocess.CompletedProcess([deploy.PS_BIN, "-axo", "pid=,command="], 0, stdout="ok", stderr="")
        inspector = deploy.ProductionProcessInspector(home=self.fx.home)
        with mock.patch.object(deploy.subprocess, "run", return_value=completed) as called: self.assertEqual(inspector._run([deploy.PS_BIN, "-axo", "pid=,command="]).stdout, "ok")
        self.assertEqual(called.call_args.args[0], [deploy.PS_BIN, "-axo", "pid=,command="]); self.assertIs(called.call_args.kwargs["shell"], False); self.assertEqual(called.call_args.kwargs["timeout"], 5)
        self.assertEqual(called.call_args.kwargs["env"]["PATH"], "/usr/bin:/bin")
        with self.assertRaises(deploy.DeploymentError): inspector._run(["tool", "arg"])
    def test_home_path_git_shadow_and_production_python_contract_fail_closed(self):
        shadow = self.fx.base / "shadow-home"; shadow.mkdir(mode=0o700)
        passwd = types.SimpleNamespace(pw_dir=str(self.fx.home))
        with mock.patch.dict(deploy.os.environ, {"HOME": str(shadow), "PATH": str(shadow), "GIT_DIR": str(shadow), "GIT_WORK_TREE": str(shadow)}, clear=False), \
             mock.patch.object(deploy.pwd, "getpwuid", return_value=passwd):
            self.assertEqual(deploy.Ops().home, str(self.fx.home))
            inspector = deploy.ProductionProcessInspector(); self.assertEqual(inspector.home, str(self.fx.home))
            completed = subprocess.CompletedProcess([deploy.GIT_BIN, "--version"], 0, stdout="git version synthetic\n", stderr="")
            with mock.patch.object(deploy.subprocess, "run", return_value=completed) as called:
                inspector._run([deploy.GIT_BIN, "--version"], env={"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
            environment = called.call_args.kwargs["env"]
            self.assertEqual(environment["HOME"], str(self.fx.home)); self.assertEqual(environment["PATH"], "/usr/bin:/bin")
            self.assertNotIn("GIT_DIR", environment); self.assertNotIn("GIT_WORK_TREE", environment)
        inspector = deploy.ProductionProcessInspector(home=self.fx.home)
        clean_flags = types.SimpleNamespace(isolated=1, safe_path=True, no_user_site=1, no_site=1,
                dont_write_bytecode=1, ignore_environment=1)
        invalid_flags = copy.copy(clean_flags); invalid_flags.no_site = 0
        with mock.patch.object(deploy.sys, "flags", invalid_flags), self.assertRaises(deploy.DeploymentError) as caught:
            deploy._check_production_python(self.fx.policy, inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
        clean_env = {"HOME": str(self.fx.home), "LANG": "C", "LC_ALL": "C", "PATH": "/opt/homebrew/bin:/usr/bin:/bin",
                "TMPDIR": str(self.fx.home / ".spspy-code-backups/tmp")}
        with mock.patch.object(deploy.sys, "flags", clean_flags), mock.patch.dict(deploy.os.environ, {**clean_env, "PYTHONPATH": str(shadow)}, clear=True), \
             self.assertRaises(deploy.DeploymentError) as caught:
            deploy._check_production_python(self.fx.policy, inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)
        wrong_env = dict(clean_env); wrong_env["PATH"] = str(shadow)
        with mock.patch.object(deploy.sys, "flags", clean_flags), mock.patch.dict(deploy.os.environ, wrong_env, clear=True), \
             self.assertRaises(deploy.DeploymentError) as caught:
            deploy._check_production_python(self.fx.policy, inspector)
        self.assertEqual(caught.exception.exit_code, deploy.EXIT_PROTOCOL)


if __name__ == "__main__": unittest.main()
