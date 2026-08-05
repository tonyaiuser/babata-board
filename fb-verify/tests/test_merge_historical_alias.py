import importlib.util
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MERGE_SCRIPT = SCRIPTS / "merge_duplicate_query_groups.py"
FROZEN_AT = "2026-08-04T14:29:27.087505+00:00"
HISTORICAL_AT = "2026-08-03T14:24:19.008804+00:00"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(SCRIPTS))
BUILD_PAGE = load_module("historical_alias_build_page", SCRIPTS / "build_fb_verify_page.py")


FROZEN_RUNNER = """
import importlib.util
import sys

script, unique, verify, frozen_at = sys.argv[1:]
spec = importlib.util.spec_from_file_location("merge_historical_alias_test", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.utc_now = lambda: frozen_at
sys.argv = [script, "--unique-json", unique, "--full-verify-json", verify]
module.main()
"""


def member(name):
    return {
        "domain": f"{name}.example",
        "handle": name,
        "title": f"Fixture {name}",
        "provenance": {"event_id": f"evt-{name}"},
    }


def zero_record(gid):
    return {
        "group_id": gid,
        "response_http_status": 200,
        "fb_total_reported": 0,
        "harvested": 0,
        "relevant_ads_count": 0,
    }


def historical_group(source, target, source_member, *, at=HISTORICAL_AT):
    return {
        "group_id": source,
        "query": "Historical Fixture",
        "members": [source_member],
        "quarantined": True,
        "quarantine_reason": "duplicate_merged_into",
        "merged_into": target,
        "quarantined_at": at,
        "quarantine_source_state": "missing",
    }


def historical_alias(target, *, at=HISTORICAL_AT):
    return {
        "canonical_group_id": target,
        "reason": "duplicate_merged_into",
        "at": at,
        "source_state": "missing",
    }


def quarantine_entry(target, *, at=HISTORICAL_AT):
    return {
        "reason": "duplicate_merged_into",
        "merged_into": target,
        "at": at,
        "source_state": "missing",
    }


class HistoricalCheckpointAliasReconciliationTest(unittest.TestCase):
    def run_merge(self, unique, verify, *, hash_seed=None):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        if hash_seed is not None:
            env["PYTHONHASHSEED"] = str(hash_seed)
        return subprocess.run(
            [
                sys.executable,
                "-c",
                FROZEN_RUNNER,
                str(MERGE_SCRIPT),
                str(unique),
                str(verify),
                FROZEN_AT,
            ],
            capture_output=True,
            text=True,
            env=env,
        )

    def write_states(self, root, unique_state, verify_state):
        unique = root / "unique.json"
        verify = root / "verify.json"
        unique.write_bytes(
            json.dumps(unique_state, ensure_ascii=False, separators=(",", ":")).encode()
        )
        verify.write_bytes(
            json.dumps(verify_state, ensure_ascii=False, separators=(",", ":")).encode()
        )
        return unique, verify

    def assert_fail_closed(self, unique_state, verify_state, expected):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = self.write_states(root, unique_state, verify_state)
            before = unique.read_bytes(), verify.read_bytes()
            completed = self.run_merge(unique, verify)
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn(expected, completed.stderr)
            self.assertIn("refusing to overwrite", completed.stderr)
            self.assertEqual((unique.read_bytes(), verify.read_bytes()), before)
            self.assertFalse(list(root.glob(".fbverify-transaction-*.json")))

    def historical_only_states(self):
        source_member = member("historical")
        unique_state = {
            "groups": [
                {
                    "group_id": "G0001",
                    "query": "Historical Fixture",
                    "members": [source_member],
                    "merged_from": ["G0001", "G0009"],
                },
                historical_group("G0009", "G0001", source_member),
            ],
            "total_groups": 1,
            "group_aliases": {"G0009": historical_alias("G0001")},
            "quarantined_groups": {"G0009": quarantine_entry("G0001")},
        }
        canonical = zero_record("G0001")
        canonical["merged_from"] = ["G0009"]
        verify_state = {
            "groups": {"G0001": canonical},
            # The historical source record was compacted, but its immutable
            # checkpoint evidence remains auditable and can reconstruct it.
            "checkpoint_archive": {"G0009": zero_record("G0009")},
        }
        return unique_state, verify_state

    def hybrid_multihop_states(self):
        root_member = member("hybrid-root")
        mid_member = member("hybrid-mid")
        leaf_member = member("hybrid-leaf")
        unique_state = {
            "groups": [
                {
                    "group_id": "G0001",
                    "query": "Hybrid Root",
                    "members": [root_member, mid_member, leaf_member],
                    "merged_from": ["G0001", "G0005", "G0009"],
                },
                {
                    **historical_group("G0005", "G0001", mid_member),
                    "members": [mid_member, leaf_member],
                    "merged_from": ["G0005", "G0009"],
                },
                historical_group("G0009", "G0005", leaf_member),
            ],
            "total_groups": 1,
            "group_aliases": {
                "G0005": historical_alias("G0001"),
                "G0009": historical_alias("G0005"),
            },
            "quarantined_groups": {
                "G0005": quarantine_entry("G0001"),
                "G0009": quarantine_entry("G0005"),
            },
        }
        canonical = zero_record("G0001")
        canonical["merged_from"] = ["G0005"]
        middle_archive = zero_record("G0005")
        middle_archive["merged_from"] = ["G0009"]
        active_target_archive = zero_record("G0001")
        active_target_archive["merged_from"] = []
        verify_state = {
            # Deliberately reverse the chain's insertion order. Closure must
            # derive from claims, not whichever group happens to be visited.
            "groups": {
                "G0009": zero_record("G0009"),
                "G0005": zero_record("G0005"),
                "G0001": canonical,
            },
            "checkpoint_archive": {
                # This source archive claim must be proven recursively.
                "G0005": middle_archive,
                # This active target's old archive is intentionally stale and
                # must not be compared with aliases added to its live record.
                "G0001": active_target_archive,
            },
        }
        return unique_state, verify_state

    def test_real_g1156_history_reconciles_with_new_g1163_g1164_merge(self):
        historical_member = member("old-umbrella")
        unique_state = {
            "groups": [
                {
                    "group_id": "G0095",
                    "query": "Reflective Safety Strip Ring Buckle Umbrella",
                    "members": [historical_member],
                    "merged_from": ["G0095", "G1156"],
                },
                historical_group("G1156", "G0095", historical_member),
                {
                    "group_id": "G1163",
                    "query": " reflective safety strip ring buckle umbrella ",
                    "members": [member("new-umbrella-one")],
                },
                {
                    "group_id": "G1164",
                    "query": "Reflective   Safety Strip Ring Buckle Umbrella",
                    "members": [member("new-umbrella-two")],
                },
            ],
            "total_groups": 3,
            "group_aliases": {"G1156": historical_alias("G0095")},
            "quarantined_groups": {"G1156": quarantine_entry("G0095")},
        }
        canonical = zero_record("G0095")
        canonical["merged_from"] = ["G1156"]
        verify_state = {
            "groups": {
                "G0095": canonical,
                "G1163": zero_record("G1163"),
                "G1164": zero_record("G1164"),
            },
            "checkpoint_archive": {"G1156": zero_record("G1156")},
        }

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = self.write_states(root, unique_state, verify_state)
            completed = self.run_merge(unique, verify)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn('"buckets_merged": 1', completed.stdout)
            state = json.loads(unique.read_text(encoding="utf-8"))
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))

            self.assertEqual(
                checkpoint["groups"]["G0095"]["merged_from"],
                ["G1156", "G1163", "G1164"],
            )
            self.assertEqual(
                list(checkpoint["checkpoint_aliases"]),
                ["G1156", "G1163", "G1164"],
            )
            self.assertEqual(
                checkpoint["checkpoint_aliases"]["G1156"]["at"], HISTORICAL_AT
            )
            for gid in ("G1163", "G1164"):
                self.assertEqual(checkpoint["checkpoint_aliases"][gid]["at"], FROZEN_AT)
            self.assertEqual(
                set(checkpoint["checkpoint_archive"]),
                {"G0095", "G1156", "G1163", "G1164"},
            )
            for gid in ("G1156", "G1163", "G1164"):
                self.assertTrue(checkpoint["groups"][gid]["quarantined"])
                self.assertEqual(checkpoint["groups"][gid]["merged_into"], "G0095")
            BUILD_PAGE.validate_alias_contract(state, checkpoint)

    def test_no_active_duplicate_repairs_from_archive_and_is_byte_idempotent(self):
        unique_state, verify_state = self.historical_only_states()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = self.write_states(root, unique_state, verify_state)
            first = self.run_merge(unique, verify)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("发现 0 个查询词对应多组", first.stdout)
            after_first = unique.read_bytes(), verify.read_bytes()
            state = json.loads(after_first[0])
            checkpoint = json.loads(after_first[1])
            self.assertEqual(
                checkpoint["checkpoint_aliases"]["G0009"],
                historical_alias("G0001"),
            )
            self.assertTrue(checkpoint["groups"]["G0009"]["quarantined"])
            self.assertEqual(checkpoint["groups"]["G0001"]["merged_from"], ["G0009"])
            BUILD_PAGE.validate_alias_contract(state, checkpoint)

            second = self.run_merge(unique, verify)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual((unique.read_bytes(), verify.read_bytes()), after_first)
            BUILD_PAGE.validate_alias_contract(
                json.loads(unique.read_text(encoding="utf-8")),
                json.loads(verify.read_text(encoding="utf-8")),
            )

    def test_source_only_history_is_archived_without_losing_audit(self):
        unique_state, verify_state = self.historical_only_states()
        verify_state.pop("checkpoint_archive")
        verify_state["groups"]["G0009"] = zero_record("G0009")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = self.write_states(root, unique_state, verify_state)
            completed = self.run_merge(unique, verify)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            state = json.loads(unique.read_text(encoding="utf-8"))
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))
            self.assertIn("G0009", checkpoint["checkpoint_archive"])
            self.assertNotIn(
                "quarantined", checkpoint["checkpoint_archive"]["G0009"]
            )
            self.assertTrue(checkpoint["groups"]["G0009"]["quarantined"])
            self.assertEqual(
                checkpoint["groups"]["G0009"]["quarantined_at"], HISTORICAL_AT
            )
            BUILD_PAGE.validate_alias_contract(state, checkpoint)

    def test_multihop_history_reconstructs_direct_alias_chain(self):
        root_member = member("root")
        mid_member = member("mid")
        leaf_member = member("leaf")
        unique_state = {
            "groups": [
                {
                    "group_id": "G0001",
                    "query": "Root",
                    "members": [root_member, mid_member, leaf_member],
                    "merged_from": ["G0001", "G0005", "G0009"],
                },
                {
                    **historical_group("G0005", "G0001", mid_member),
                    "members": [mid_member, leaf_member],
                    "merged_from": ["G0005", "G0009"],
                },
                historical_group("G0009", "G0005", leaf_member),
            ],
            "total_groups": 1,
            "group_aliases": {
                "G0005": historical_alias("G0001"),
                "G0009": historical_alias("G0005"),
            },
            "quarantined_groups": {
                "G0005": quarantine_entry("G0001"),
                "G0009": quarantine_entry("G0005"),
            },
        }
        canonical = zero_record("G0001")
        canonical["merged_from"] = ["G0005"]
        middle = zero_record("G0005")
        middle["merged_from"] = ["G0009"]
        verify_state = {
            "groups": {"G0001": canonical},
            "checkpoint_archive": {
                "G0005": middle,
                "G0009": zero_record("G0009"),
            },
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = self.write_states(root, unique_state, verify_state)
            completed = self.run_merge(unique, verify)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            state = json.loads(unique.read_text(encoding="utf-8"))
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    source: entry["canonical_group_id"]
                    for source, entry in checkpoint["checkpoint_aliases"].items()
                },
                {"G0005": "G0001", "G0009": "G0005"},
            )
            self.assertEqual(
                checkpoint["groups"]["G0001"]["merged_from"], ["G0005"]
            )
            self.assertEqual(
                checkpoint["groups"]["G0005"]["merged_from"], ["G0009"]
            )
            BUILD_PAGE.validate_alias_contract(state, checkpoint)

    def test_hybrid_archive_claim_closes_reverse_chain_and_is_byte_idempotent(self):
        unique_state, verify_state = self.hybrid_multihop_states()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = self.write_states(root, unique_state, verify_state)
            first = self.run_merge(unique, verify)
            self.assertEqual(first.returncode, 0, first.stderr)
            after_first = unique.read_bytes(), verify.read_bytes()
            state = json.loads(after_first[0])
            checkpoint = json.loads(after_first[1])

            self.assertEqual(
                {
                    source: entry["canonical_group_id"]
                    for source, entry in checkpoint["checkpoint_aliases"].items()
                },
                {"G0005": "G0001", "G0009": "G0005"},
            )
            self.assertEqual(
                checkpoint["groups"]["G0005"]["merged_from"], ["G0009"]
            )
            self.assertTrue(checkpoint["groups"]["G0009"]["quarantined"])
            self.assertEqual(
                checkpoint["checkpoint_archive"]["G0001"]["merged_from"], []
            )
            BUILD_PAGE.validate_alias_contract(state, checkpoint)

            second = self.run_merge(unique, verify)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual((unique.read_bytes(), verify.read_bytes()), after_first)

    def test_child_first_existing_aliases_reconstruct_parent_before_child(self):
        root_member = member("order-root")
        mid_member = member("order-mid")
        leaf_member = member("order-leaf")
        unique_state = {
            "groups": [
                {
                    "group_id": "G1",
                    "query": "Order Root",
                    "members": [root_member, mid_member, leaf_member],
                    "merged_from": ["G1", "G2", "G9"],
                },
                {
                    **historical_group("G9", "G1", mid_member),
                    "members": [mid_member, leaf_member],
                    "merged_from": ["G2", "G9"],
                },
                historical_group("G2", "G9", leaf_member),
            ],
            "total_groups": 1,
            "group_aliases": {
                "G2": historical_alias("G9"),
                "G9": historical_alias("G1"),
            },
            "quarantined_groups": {
                "G2": quarantine_entry("G9"),
                "G9": quarantine_entry("G1"),
            },
        }
        canonical = zero_record("G1")
        canonical["merged_from"] = ["G9"]
        middle = zero_record("G9")
        middle["merged_from"] = ["G2"]
        verify_state = {
            "groups": {"G1": canonical},
            "checkpoint_archive": {
                "G9": middle,
                "G2": zero_record("G2"),
            },
            # Child-first ordering must not try G2->G9 before G9 is rebuilt.
            "checkpoint_aliases": {
                "G2": historical_alias("G9"),
                "G9": historical_alias("G1"),
            },
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = self.write_states(root, unique_state, verify_state)
            completed = self.run_merge(unique, verify)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            state = json.loads(unique.read_text(encoding="utf-8"))
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))
            self.assertEqual(checkpoint["groups"]["G9"]["merged_from"], ["G2"])
            self.assertTrue(checkpoint["groups"]["G2"]["quarantined"])
            BUILD_PAGE.validate_alias_contract(state, checkpoint)

    def test_non_padded_group_ids_persist_builder_lexical_order(self):
        unique_state = {
            "groups": [
                {
                    "group_id": "G10",
                    "query": "Lexical Fixture",
                    "members": [member("lex-ten")],
                },
                {
                    "group_id": "G2",
                    "query": " lexical fixture ",
                    "members": [member("lex-two")],
                },
            ]
        }
        verify_state = {
            "groups": {
                "G10": zero_record("G10"),
                "G2": zero_record("G2"),
            }
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unique, verify = self.write_states(root, unique_state, verify_state)
            completed = self.run_merge(unique, verify)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            state = json.loads(unique.read_text(encoding="utf-8"))
            checkpoint = json.loads(verify.read_text(encoding="utf-8"))
            by_gid = {group["group_id"]: group for group in state["groups"]}

            # Numeric keeper selection remains G2, but persisted provenance
            # follows ordinary string sorting exactly like the builder.
            self.assertIsNot(by_gid["G2"].get("quarantined"), True)
            self.assertEqual(by_gid["G2"]["merged_from"], ["G10", "G2"])
            self.assertEqual(
                checkpoint["groups"]["G2"]["merged_from"], ["G10"]
            )
            BUILD_PAGE.validate_alias_contract(state, checkpoint)

    def test_new_duplicate_is_hashseed_stable_idempotent_and_conserves_members(self):
        groups = [
            {
                "group_id": gid,
                "query": query,
                "members": [member(name)],
            }
            for gid, query, name in (
                ("G0003", "same fixture", "third"),
                ("G0001", "Same Fixture", "first"),
                ("G0002", " same   fixture ", "second"),
            )
        ]
        unique_state = {"groups": groups}
        verify_state = {
            "groups": {
                gid: zero_record(gid) for gid in ("G0001", "G0002", "G0003")
            }
        }
        outputs = []
        for seed in (1, 777):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                unique, verify = self.write_states(
                    root, copy.deepcopy(unique_state), copy.deepcopy(verify_state)
                )
                completed = self.run_merge(unique, verify, hash_seed=seed)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                state = json.loads(unique.read_text(encoding="utf-8"))
                checkpoint = json.loads(verify.read_text(encoding="utf-8"))
                active = [
                    group for group in state["groups"]
                    if group.get("quarantined") is not True
                ]
                self.assertEqual(len(active), 1)
                self.assertEqual(
                    {
                        (item["domain"], item["handle"])
                        for item in active[0]["members"]
                    },
                    {
                        ("first.example", "first"),
                        ("second.example", "second"),
                        ("third.example", "third"),
                    },
                )
                for gid in ("G0002", "G0003"):
                    dropped = next(
                        group for group in state["groups"]
                        if group["group_id"] == gid
                    )
                    original = next(
                        group for group in groups if group["group_id"] == gid
                    )
                    self.assertEqual(dropped["members"], original["members"])
                BUILD_PAGE.validate_alias_contract(state, checkpoint)
                first_bytes = unique.read_bytes(), verify.read_bytes()
                second = self.run_merge(unique, verify, hash_seed=seed)
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertEqual((unique.read_bytes(), verify.read_bytes()), first_bytes)
                outputs.append(first_bytes)
        self.assertEqual(outputs[0], outputs[1])

    def test_unprovable_or_conflicting_history_fails_before_transaction(self):
        canonical = zero_record("G0001")
        canonical["merged_from"] = ["G0009"]
        source = zero_record("G0009")

        cases = []
        cases.append((
            "missing unique alias",
            {"groups": [{"group_id": "G0001", "query": "One", "members": []}]},
            {
                "groups": {"G0001": canonical, "G0009": source},
                "checkpoint_archive": {"G0009": source},
            },
            "has no unique group alias",
        ))

        endpoint_member = member("endpoint")
        cases.append((
            "different alias endpoint",
            {
                "groups": [
                    {"group_id": "G0001", "query": "One", "members": []},
                    {
                        "group_id": "G0002", "query": "Two", "members": [endpoint_member],
                        "merged_from": ["G0002", "G0009"],
                    },
                    historical_group("G0009", "G0002", endpoint_member),
                ],
                "group_aliases": {"G0009": historical_alias("G0002")},
                "quarantined_groups": {
                    "G0009": quarantine_entry("G0002")
                },
            },
            {
                "groups": {"G0001": canonical, "G0009": source},
                "checkpoint_archive": {"G0009": source},
            },
            "points to G0002, not G0001",
        ))

        cycle_member = member("cycle")
        cases.append((
            "unique alias cycle",
            {
                "groups": [
                    {"group_id": "G0001", "query": "One", "members": []},
                    historical_group("G0008", "G0009", cycle_member),
                    historical_group("G0009", "G0008", cycle_member),
                ],
                "group_aliases": {
                    "G0008": historical_alias("G0009"),
                    "G0009": historical_alias("G0008"),
                },
                "quarantined_groups": {
                    "G0008": quarantine_entry("G0009"),
                    "G0009": quarantine_entry("G0008"),
                },
            },
            {"groups": {"G0001": zero_record("G0001")}},
            "alias cycle",
        ))

        missing_evidence_unique, missing_evidence_verify = self.historical_only_states()
        missing_evidence_verify.pop("checkpoint_archive")
        cases.append((
            "missing source and archive evidence",
            missing_evidence_unique,
            missing_evidence_verify,
            "has no source/archive evidence",
        ))

        null_archive_unique, null_archive_verify = self.historical_only_states()
        null_archive_verify["checkpoint_archive"] = None
        cases.append((
            "explicit null archive container",
            null_archive_unique,
            null_archive_verify,
            "checkpoint_archive must be an object",
        ))

        conflict_unique, conflict_verify = self.historical_only_states()
        conflict_verify["groups"]["G0009"] = zero_record("G0009")
        conflict_verify["groups"]["G0009"]["error"] = "live evidence"
        conflict_verify["checkpoint_archive"]["G0009"]["error"] = "different archive"
        cases.append((
            "source archive payload conflict",
            conflict_unique,
            conflict_verify,
            "source/archive payload conflict",
        ))

        invalid_metadata_unique, invalid_metadata_verify = self.historical_only_states()
        invalid_metadata_unique["group_aliases"]["G0009"]["at"] = 7
        cases.append((
            "invalid historical metadata type",
            invalid_metadata_unique,
            invalid_metadata_verify,
            "invalid at metadata",
        ))

        for label, unique_state, verify_state, expected in cases:
            with self.subTest(label=label):
                self.assert_fail_closed(unique_state, verify_state, expected)

    def test_noncanonical_provenance_and_explicit_container_types_fail_closed(self):
        cases = []

        quarantined_null_unique, quarantined_null_verify = self.historical_only_states()
        quarantined_null_unique["groups"][1]["quarantined"] = None
        cases.append((
            "unique quarantined null",
            quarantined_null_unique,
            quarantined_null_verify,
            "quarantined flag must be boolean",
        ))

        unordered_unique, unordered_verify = self.historical_only_states()
        unordered_unique["groups"][0]["merged_from"] = ["G0009", "G0001"]
        cases.append((
            "unordered unique provenance",
            unordered_unique,
            unordered_verify,
            "must already be in canonical group-id order",
        ))

        cases.append((
            "unordered checkpoint provenance",
            {
                "groups": [
                    {"group_id": "G0001", "query": "One", "members": []}
                ]
            },
            {
                "groups": {
                    "G0001": {
                        **zero_record("G0001"),
                        "merged_from": ["G0010", "G0009"],
                    }
                }
            },
            "must already be in canonical group-id order",
        ))

        cases.append((
            "numeric rather than lexical checkpoint provenance",
            {
                "groups": [
                    {"group_id": "G1", "query": "One", "members": []}
                ]
            },
            {
                "groups": {
                    "G1": {
                        **zero_record("G1"),
                        "merged_from": ["G2", "G10"],
                    }
                }
            },
            "must already be in canonical group-id order",
        ))

        ordinary_unique = {
            "groups": [
                {"group_id": "G0001", "query": "One", "members": []}
            ]
        }
        ordinary_verify = {"groups": {"G0001": zero_record("G0001")}}
        for label, owner, field, bad_value in (
            ("group aliases null", "unique", "group_aliases", None),
            ("quarantine map list", "unique", "quarantined_groups", []),
            ("checkpoint groups null", "verify", "groups", None),
            ("checkpoint aliases null", "verify", "checkpoint_aliases", None),
            ("retry errors list", "verify", "retry_errors", []),
            ("retry archive null", "verify", "retry_archive", None),
            ("retry aliases scalar", "verify", "retry_aliases", 7),
        ):
            unique_state = copy.deepcopy(ordinary_unique)
            verify_state = copy.deepcopy(ordinary_verify)
            target = unique_state if owner == "unique" else verify_state
            target[field] = bad_value
            cases.append((
                label,
                unique_state,
                verify_state,
                f"{field} must be an object"
                if field != "groups"
                else "checkpoint groups must be an object",
            ))

        newdup_unique = {
            "groups": [
                {
                    "group_id": "G0001",
                    "query": "Same",
                    "members": [member("one")],
                },
                {
                    "group_id": "G0002",
                    "query": "same",
                    "members": [member("two")],
                },
            ]
        }
        newdup_verify = {
            "groups": {
                "G0001": zero_record("G0001"),
                "G0002": zero_record("G0002"),
            },
            "checkpoint_archive": None,
        }
        cases.append((
            "new duplicate with null archive",
            newdup_unique,
            newdup_verify,
            "checkpoint_archive must be an object",
        ))

        for label, unique_state, verify_state, expected in cases:
            with self.subTest(label=label):
                self.assert_fail_closed(unique_state, verify_state, expected)

    def test_archive_claim_closure_failures_are_atomic(self):
        cases = []

        no_alias_unique, no_alias_verify = self.hybrid_multihop_states()
        no_alias_verify["checkpoint_archive"]["G0005"]["merged_from"] = [
            "G0008"
        ]
        cases.append((
            "archive child lacks direct unique alias",
            no_alias_unique,
            no_alias_verify,
            "G0008 has no unique group alias",
        ))

        no_evidence_unique, no_evidence_verify = self.hybrid_multihop_states()
        no_evidence_verify["groups"].pop("G0009")
        cases.append((
            "archive child lacks checkpoint evidence",
            no_evidence_unique,
            no_evidence_verify,
            "G0009 has no source/archive evidence",
        ))

        omitted_unique, omitted_verify = self.hybrid_multihop_states()
        omitted_verify["checkpoint_archive"]["G0005"]["merged_from"] = []
        omitted_verify["checkpoint_aliases"] = {
            "G0009": historical_alias("G0005")
        }
        cases.append((
            "explicit empty archive omits proven direct child",
            omitted_unique,
            omitted_verify,
            "checkpoint archive G0005 merged_from does not exactly match direct child aliases",
        ))

        conflict_unique, conflict_verify = self.hybrid_multihop_states()
        conflict_verify["groups"]["G0005"]["merged_from"] = []
        cases.append((
            "hybrid live archive explicit conflict",
            conflict_unique,
            conflict_verify,
            "checkpoint source/archive merged_from conflict for G0005",
        ))

        for label, unique_state, verify_state, expected in cases:
            with self.subTest(label=label):
                self.assert_fail_closed(unique_state, verify_state, expected)

    def test_archive_and_source_audit_conflicts_fail_closed(self):
        cases = []
        archive_mutations = (
            ("wrong target", {"merged_into": "G9999"}, "conflicting merged_into"),
            ("wrong reason", {"quarantine_reason": "wrong"}, "conflicting quarantine_reason"),
            ("quarantined false", {"quarantined": False}, "conflicting quarantined metadata"),
            ("quarantined null", {"quarantined": None}, "conflicting quarantined metadata"),
            (
                "wrong timestamp",
                {"quarantined_at": "2026-08-01T00:00:00+00:00"},
                "metadata conflict for at",
            ),
            (
                "wrong source state",
                {"quarantine_source_state": "explicit_zero"},
                "metadata conflict for source_state",
            ),
        )
        for label, mutation, expected in archive_mutations:
            unique_state, verify_state = self.historical_only_states()
            verify_state["checkpoint_archive"]["G0009"].update(mutation)
            cases.append((f"archive {label}", unique_state, verify_state, expected))

        source_false_unique, source_false_verify = self.historical_only_states()
        source_false_verify.pop("checkpoint_archive")
        source_false_verify["groups"]["G0009"] = {
            **zero_record("G0009"),
            "quarantined": False,
        }
        cases.append((
            "source-only quarantined false",
            source_false_unique,
            source_false_verify,
            "checkpoint source G0009 has conflicting quarantined metadata",
        ))

        provenance_unique, provenance_verify = self.historical_only_states()
        provenance_verify["groups"]["G0009"] = {
            **zero_record("G0009"),
            "merged_from": [],
        }
        provenance_verify["checkpoint_archive"]["G0009"]["merged_from"] = [
            "G0008"
        ]
        cases.append((
            "source archive provenance conflict",
            provenance_unique,
            provenance_verify,
            "source/archive merged_from conflict",
        ))

        for label, unique_state, verify_state, expected in cases:
            with self.subTest(label=label):
                self.assert_fail_closed(unique_state, verify_state, expected)


if __name__ == "__main__":
    unittest.main()
