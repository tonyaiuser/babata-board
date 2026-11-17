import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import sp_monitor_release_manifest_v1 as release


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "sp_monitor_release_manifest_v1.json"


def policy(): return release.parse_source_policy(POLICY_PATH.read_bytes())
def blobs():
    return {
        "scripts/report_delivery_outbox_v1.py": b"outbox\n",
        "scripts/report_delivery_adapters_v1.py": b"adapters\n",
        "skills/sp-monitor/run.py": b"entry\n",
    }


class SourcePolicyTests(unittest.TestCase):
    def test_checked_in_policy_exact_schema_and_stable_only(self):
        value = policy()
        self.assertEqual(set(value), {"schema", "policy_name", "runtime_schema", "repository", "baseline", "bundle", "deployment"})
        encoded = release.canonical_source_policy_bytes(value)
        self.assertNotIn(b'"release_id"', encoded)
        self.assertNotIn(b'"commit"', encoded)
        self.assertNotIn(b'"size"', encoded)
        self.assertEqual(release.source_policy_sha256(value), hashlib.sha256(encoded).hexdigest())
    def test_exact_three_mapping_and_order(self):
        self.assertEqual([(x["source"], x["target"], x["role"], x["mode"]) for x in policy()["bundle"]], [
            ("scripts/report_delivery_outbox_v1.py", "scripts/report_delivery_outbox_v1.py", "helper", "0644"),
            ("scripts/report_delivery_adapters_v1.py", "scripts/report_delivery_adapters_v1.py", "helper", "0644"),
            ("skills/sp-monitor/run.py", "run.py", "entrypoint", "0644"),
        ])
    def test_duplicate_unknown_dynamic_and_mapping_changes_rejected(self):
        raw = b'{"schema":"x","schema":"y"}'
        with self.assertRaises(release.ManifestSchemaError): release.parse_source_policy(raw)
        for mutate in (
            lambda x: x.update(release_id="bad"),
            lambda x: x["bundle"][0].update(target="run.py"),
            lambda x: x["repository"].update(required_ref="refs/heads/topic"),
            lambda x: x["deployment"].update(credential_names=["DINGTALK_WEBHOOK"]),
            lambda x: x["deployment"]["dependent_consumers"][0].update(configured_argv=["/bin/bash", "script.sh"]),
            lambda x: x["deployment"]["dependent_consumers"][0].update(process_match_tokens=["/bin/bash"]),
        ):
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(policy()); mutate(value)
                with self.assertRaises(release.ManifestSchemaError): release.canonical_source_policy_bytes(value)
    def test_unresolved_inventory_is_explicit_not_guessed(self):
        consumers = policy()["deployment"]["dependent_consumers"]
        self.assertEqual([x["name"] for x in consumers], ["single-page-monitor", "fb-verify", "single-page-fb-nightly"])
        self.assertTrue(all(x["unresolved"] and any(source["sha256"] == "REQUIRED_AT_DEPLOY" for source in x["source_files"]) for x in consumers))
        self.assertEqual([x["labels"][0] for x in consumers], ["com.spspy.single-page-monitor", "com.spspy.fb-verify", "com.spspy.single-page-fb-nightly"])
        self.assertTrue(all(x["configured_argv"][:2] == ["/bin/bash", "-lc"] and "/bin/bash" not in x["process_match_tokens"] for x in consumers))
        self.assertEqual([x["plist_sha256"] for x in consumers], ["bd2d7de333e4f82a7e6731dea31528edd51944bc0eb5eb9be9a29ef58cd84edc", "691bfbc444eb85835d572ab0182a2d942b78b98ef223d06f59a856fc0e5f8d56", "8648b05d65f29993e42be48453e252c3710c22af1f09767af74da2990d1108da"])
    def test_main_plist_raw_hash_exact_shape_and_entrypoint_identity_are_frozen(self):
        plist = policy()["deployment"]["plist"]
        self.assertEqual(plist["plist_sha256"], "52c1010edc38cdc17a0aa01081c0209e39f30edcb0905d868f384fb8ae37f525")
        self.assertEqual([plist["interpreter"], plist["entrypoint"], *plist["arguments"]], ["/opt/homebrew/bin/python3", "~/.openclaw/workspace/skills/sp-monitor/run.py", "--send"])
        self.assertEqual(plist["entrypoint_index"], 1)
        self.assertEqual(plist["environment_variable_keys"], ["HOME", "OPENCLAW_BIN", "PATH"])
        self.assertEqual(set(plist["plist_keys"]), {"EnvironmentVariables", "Label", "ProgramArguments", "RunAtLoad", "StandardErrorPath", "StandardOutPath", "StartCalendarInterval"})
        for key in ("plist_keys", "environment_variable_keys", "entrypoint_index"):
            bad = copy.deepcopy(policy()); bad["deployment"]["plist"][key] = [] if key != "entrypoint_index" else 0
            with self.subTest(key=key), self.assertRaises(release.ManifestSchemaError): release.canonical_source_policy_bytes(bad)
    def test_allow_window_is_strict_24_hour_clock(self):
        for key, value in (("start", "24:00"), ("end", "29:59"), ("start", "23:60"), ("end", "9:00")):
            bad = copy.deepcopy(policy()); bad["deployment"]["allow_window"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(release.ManifestSchemaError): release.canonical_source_policy_bytes(bad)
        valid = copy.deepcopy(policy()); valid["deployment"]["allow_window"].update(start="00:00", end="23:59")
        self.assertTrue(release.canonical_source_policy_bytes(valid))
    def test_main_plist_exact_types_reject_bool_int_aliases(self):
        mutations = (("entrypoint_index", True), ("run_at_load", 0), ("calendar", {"Hour": True, "Minute": 30}), ("arguments", ("--send",)))
        for key, value in mutations:
            bad = copy.deepcopy(policy()); bad["deployment"]["plist"][key] = value
            with self.subTest(key=key), self.assertRaises(release.ManifestSchemaError): release.canonical_source_policy_bytes(bad)
    def test_deployment_paths_and_four_targets_are_frozen(self):
        value = policy(); deployment = value["deployment"]
        self.assertEqual({key: deployment[key] for key in release.EXACT_DEPLOYMENT_PATHS}, release.EXACT_DEPLOYMENT_PATHS)
        for key, changed in (("live_root", "~/other"), ("runtime_manifest_target", "run.py"), ("lock_path", "~/.other-lock")):
            bad = copy.deepcopy(value); bad["deployment"][key] = changed
            with self.subTest(key=key), self.assertRaises(release.ManifestSchemaError): release.canonical_source_policy_bytes(bad)


class RuntimeManifestTests(unittest.TestCase):
    def test_build_is_deterministic_canonical_and_has_no_self_hash(self):
        runtime = release.build_runtime_release(policy(), "a" * 40, blobs())
        encoded = release.canonical_runtime_release_bytes(runtime)
        self.assertEqual(release.parse_runtime_release(encoded), runtime)
        self.assertEqual(runtime, release.build_runtime_release(policy(), "a" * 40, blobs()))
        self.assertRegex(runtime["release_id"], r"^spmrv1-[0-9a-f]{32}$")
        self.assertEqual(set(runtime), {"schema", "policy", "repository", "bundle", "bundle_digest", "release_id"})
        self.assertNotIn("runtime_sha256", runtime)
    def test_bundle_hash_size_digest_and_release_id_are_bound(self):
        runtime = release.build_runtime_release(policy(), "a" * 40, blobs())
        for item in runtime["bundle"]:
            self.assertEqual(item["sha256"], hashlib.sha256(blobs()[item["source"]]).hexdigest())
            self.assertEqual(item["size"], len(blobs()[item["source"]]))
        for field, value in (("bundle_digest", "0" * 64), ("release_id", "spmrv1-" + "0" * 32)):
            bad = copy.deepcopy(runtime); bad[field] = value
            with self.assertRaises(release.ManifestHashError): release.canonical_runtime_release_bytes(bad)
    def test_runtime_requires_canonical_exact_bytes(self):
        runtime = release.build_runtime_release(policy(), "a" * 40, blobs())
        pretty = json.dumps(runtime, indent=2).encode()
        with self.assertRaises(release.ManifestSchemaError): release.parse_runtime_release(pretty)
        with self.assertRaises(release.ManifestSchemaError): release.parse_runtime_release(b" " + release.canonical_runtime_release_bytes(runtime))
    def test_verify_binds_policy_commit_and_sources(self):
        runtime = release.build_runtime_release(policy(), "a" * 40, blobs())
        self.assertTrue(release.verify_runtime_release(policy(), runtime, blobs(), "a" * 40))
        changed = blobs(); changed["skills/sp-monitor/run.py"] = b"changed\n"
        with self.assertRaises(release.ManifestHashError): release.verify_runtime_release(policy(), runtime, changed)
        with self.assertRaises(release.ManifestHashError): release.verify_runtime_release(policy(), runtime, blobs(), "b" * 40)
    def test_build_cli_requires_outside_exclusive_output(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"; repo.mkdir()
            for name, data in blobs().items():
                path = repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            outside = Path(temp) / "runtime.json"
            args = ["build-runtime", "--policy", str(POLICY_PATH), "--repo-root", str(repo), "--repo-commit", "a" * 40, "--output", str(outside)]
            self.assertEqual(release.main(args), 0)
            self.assertEqual(release.parse_runtime_release(outside.read_bytes())["repository"]["commit"], "a" * 40)
            self.assertEqual(release.main(args), 70)
            inside = repo / "runtime.json"
            self.assertEqual(release.main(args[:-1] + [str(inside)]), 64)


if __name__ == "__main__": unittest.main()
