import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def _tool(name):
    path = Path(__file__).resolve().parents[1] / "tools" / name
    spec = importlib.util.spec_from_file_location("_" + name.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


candidate = _tool("reverse_candidate_build_v2.py")


class CandidateBuildTests(unittest.TestCase):
    def _config(self, root, blob="b" * 40, allowlist=None):
        if allowlist is None:
            allowlist = [{"path": "app", "kind": "directory"}, {"path": "keep.py", "kind": "file"}]
        value = {
            "schema": "spspy-reverse-producer/v2",
            "workflow": {"repository": "owner/repo", "path": ".github/workflows/trusted-reverse-producer-v2.yml",
                         "authority_ref": "refs/heads/main",
                         "signer_workflow_ref": "owner/repo/.github/workflows/trusted-reverse-producer-v2.yml@refs/heads/main",
                         "blob_oid": blob},
            "limits": {"max_file_bytes": 4096, "max_payload_bytes": 16384, "max_entries": 16, "max_path_bytes": 160},
            "allowlist": allowlist,
            "outputs": ["release-payload.tar", "release-receipt.json"],
        }
        (root / "config").mkdir(exist_ok=True)
        (root / "config" / "reverse_producer_v2.json").write_text(json.dumps(value), encoding="utf-8")

    def _build(self, root, output):
        return candidate.build_candidate(candidate_root=root, candidate_repository="owner/candidate",
                                         source_commit="a" * 40, source_tree="c" * 40,
                                         workflow_repository="owner/repo",
                                         workflow_path=".github/workflows/trusted-reverse-producer-v2.yml",
                                         workflow_ref="refs/heads/main",
                                         signer_workflow_ref="owner/repo/.github/workflows/trusted-reverse-producer-v2.yml@refs/heads/main",
                                         workflow_commit="d" * 40, workflow_blob="b" * 40,
                                         output_dir=output)

    def test_builds_exact_raw_ustar_and_non_authoritative_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "candidate"; root.mkdir()
            (root / "app").mkdir(); (root / "app" / "one.txt").write_bytes(b"one")
            (root / "keep.py").write_bytes(b"two")
            self._config(root)
            output = Path(temporary) / "out"; output.mkdir()
            result = self._build(root, output)
            raw = result["payload"].read_bytes()
            self.assertEqual(len(raw) % 512, 0)
            self.assertEqual(raw[-1024:], b"\0" * 1024)
            # Two headers, two one-block payloads, and exactly two EOA blocks.
            self.assertEqual(len(raw), 4 * 512 + 1024)
            receipt = json.loads(result["receipt"].read_text())
            self.assertEqual(receipt["schema"], "spspy.candidate-reverse-v2.receipt")
            self.assertEqual(receipt["checks"], [])
            self.assertEqual(receipt["candidate"]["repository"], "owner/candidate")
            self.assertEqual(receipt["candidate"]["input_tree_sha256"], candidate._inventory_sha256(receipt["entries"]))
            self.assertEqual(receipt["workflow"]["authority_ref"], "refs/heads/main")
            self.assertIn("@refs/heads/main", receipt["workflow"]["signer_workflow_ref"])
            # The producer accepts ASCII-zero regular typeflag only.
            self.assertEqual(raw[156:157], b"0")

    def test_fails_closed_for_unsealed_workflow_symlink_or_nonempty_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "candidate"; root.mkdir(); (root / "app").mkdir()
            (root / "app" / "link").symlink_to("/etc/passwd"); (root / "keep.py").write_bytes(b"b")
            self._config(root)
            output = Path(temporary) / "out"; output.mkdir()
            with self.assertRaises(candidate.CandidateError):
                self._build(root, output)
            (root / "app" / "link").unlink()
            (root / "app" / "a").write_bytes(b"a")
            (output / "not-empty").write_bytes(b"x")
            with self.assertRaises(candidate.CandidateError):
                self._build(root, output)
            (output / "not-empty").unlink()
            self._config(root, blob=None)
            with self.assertRaises(candidate.CandidateError):
                self._build(root, output)

    def test_rejects_symlink_in_explicit_file_parent_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "candidate"; root.mkdir()
            outside = Path(temporary) / "outside"; outside.mkdir()
            (outside / "secret.py").write_bytes(b"must-not-escape-root")
            (root / "linked").symlink_to(outside, target_is_directory=True)
            self._config(root, allowlist=[{"path": "linked/secret.py", "kind": "file"}])
            output = Path(temporary) / "out"; output.mkdir()
            with self.assertRaises(candidate.CandidateError):
                self._build(root, output)

    def test_rejects_parent_switched_to_symlink_during_openat_walk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "candidate"; root.mkdir()
            (root / "a" / "b").mkdir(parents=True)
            (root / "a" / "b" / "secret.py").write_bytes(b"candidate")
            outside = Path(temporary) / "outside"; outside.mkdir()
            (outside / "secret.py").write_bytes(b"must-not-escape-root")
            self._config(root, allowlist=[{"path": "a/b/secret.py", "kind": "file"}])
            output = Path(temporary) / "out"; output.mkdir()
            original_open = os.open
            switched = {"value": False}

            def racing_open(path, flags, mode=0o777, *, dir_fd=None):
                if path == "b" and dir_fd is not None and not switched["value"]:
                    (root / "a" / "b").rename(root / "a" / "original-b")
                    (root / "a" / "b").symlink_to(outside, target_is_directory=True)
                    switched["value"] = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(candidate.os, "open", side_effect=racing_open):
                with self.assertRaises(candidate.CandidateError):
                    self._build(root, output)
            self.assertTrue(switched["value"])
            self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
