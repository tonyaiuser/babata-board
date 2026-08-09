"""Local proof for the trusted reverse producer v2 finalizer and workflow fences."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / ".github" / "reverse_producer_v2" / "validate.py"
PREPARE_PATH = ROOT / ".github" / "reverse_producer_v2" / "prepare_candidate.py"
TRUSTED_POLICY_PATH = ROOT / ".github" / "reverse_producer_v2" / "policy.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "trusted-reverse-producer-v2.yml"
DISPATCH_PATH = ROOT / ".github" / "workflows" / "trusted-reverse-dispatch-v2.yml"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validator = _load_module("trusted_reverse_v2_validator", VALIDATOR_PATH)
prepare = _load_module("trusted_reverse_v2_prepare", PREPARE_PATH)


def binding() -> dict[str, Any]:
    return {
        "schema": validator.BINDING_SCHEMA,
        "source": {
            "id": "123456",
            "repository": "tonyaiuser/babata-board",
            "commit": "d" * 40,
            "ref": "refs/heads/main",
        },
        "candidate": {
            "commit": "a" * 40,
            "ref": "refs/heads/candidate",
            "tree": "b" * 40,
        },
        "signer": {
            "repository": "tonyaiuser/babata-board",
            "workflow_path": ".github/workflows/trusted-reverse-producer-v2.yml",
            "workflow_ref": "tonyaiuser/babata-board/.github/workflows/trusted-reverse-producer-v2.yml@refs/heads/main",
            "commit": "c" * 40,
            "blob": "e" * 40,
        },
        "run": {"id": "42", "attempt": "1", "finalize_job": "finalize-without-candidate", "prepare_result": "success"},
        "artifact": {"name": "raw-reverse-42-1"},
        "runner": {"os": "macOS", "image": "macos-14"},
        "tools": {"python": "3.9.6", "tar": "bsd-tar"},
        "cache": {"shared": False, "enabled": False},
        "test_matrix": {"command": "python -m unittest", "result": "pass"},
    }


def _octal(value: int, width: int) -> bytes:
    return ("%0*o" % (width - 1, value)).encode("ascii") + b"\0"


def _checksum(header: bytearray) -> None:
    header[148:156] = b" " * 8
    header[148:156] = ("%06o" % sum(header)).encode("ascii") + b"\0 "


def _strict_header(name: str, body: bytes, kind: str, *, last_feasible_split: bool = False) -> bytes:
    encoded = name.encode("ascii")
    prefix = b""
    if len(encoded) > 100:
        if last_feasible_split:
            prefix, encoded = encoded.rsplit(b"/", 1)
        else:
            canonical_name, canonical_prefix = validator._canonical_ustar_fields(name)
            encoded = canonical_name.encode("ascii")
            prefix = canonical_prefix.encode("ascii")
        if not prefix or len(prefix) > 155 or len(encoded) > 100:
            raise ValueError(name)
    typeflag = {"file": b"0", "dir": b"5", "symlink": b"2", "hardlink": b"1", "fifo": b"6", "device": b"3", "sparse": b"S", "pax": b"x"}[kind]
    header = bytearray(512)
    header[0:len(encoded)] = encoded
    header[100:108] = _octal(0o600, 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    header[124:136] = _octal(len(body), 12)
    header[136:148] = _octal(0, 12)
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8)
    header[337:345] = _octal(0, 8)
    header[345:345 + len(prefix)] = prefix
    _checksum(header)
    return bytes(header)


def tar_bytes(members: Iterable[Tuple[str, str, bytes]]) -> bytes:
    chunks = []
    for name, kind, body in members:
        chunks.extend((_strict_header(name, body, kind), body, b"\0" * ((-len(body)) % 512)))
    return b"".join(chunks) + b"\0" * 1024


def fixture_policy(path: Path) -> Path:
    document = {
        "schema": "spspy.trusted-reverse-producer-v2.release-policy",
        "version": 1,
        "archive": dict(validator.ARCHIVE_CONTRACT),
        "inventory": dict(validator.INVENTORY_CONTRACT),
        "limits": {"max_entries": 100, "max_file_bytes": 1024, "max_payload_bytes": 4096, "max_path_bytes": 240},
        "paths": {
            "allowed_files": ["dir/a.txt", "large", "safe", "safe.txt", "z.txt"],
            "allowed_prefixes": ["dir/"],
            "required_files": [],
            "required_prefixes": [],
        },
    }
    path.write_bytes(validator.canonical_json(document))
    return path


def stress_policy(path: Path, max_entries: int) -> Path:
    document = {
        "schema": "spspy.trusted-reverse-producer-v2.release-policy",
        "version": 1,
        "archive": dict(validator.ARCHIVE_CONTRACT),
        "inventory": dict(validator.INVENTORY_CONTRACT),
        "limits": {
            "max_entries": max_entries,
            "max_file_bytes": 1,
            "max_payload_bytes": 4096,
            "max_path_bytes": 240,
        },
        "paths": {
            "allowed_files": [],
            "allowed_prefixes": ["dir/"],
            "required_files": [],
            "required_prefixes": ["dir/"],
        },
    }
    path.write_bytes(validator.canonical_json(document))
    return path


def deep_git_paths(count: int) -> list[str]:
    return [
        "dir/" + f"{index:03d}/" + "a" * 50 + "/" + "b" * 50 + "/" + "c" * 95
        for index in range(count)
    ]


def git_object_database(root: Path, members: Iterable[Tuple[str, str, bytes]]) -> tuple[Path, str, str]:
    """Create a real object graph, including modes a normal worktree may reject."""
    repository = root / "candidate-objects"
    repository.mkdir()
    subprocess.run(["/usr/bin/git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["/usr/bin/git", "config", "core.ignoreCase", "false"], cwd=repository, check=True)
    commit_environment = dict(os.environ)
    commit_environment.update({
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    })
    empty_tree = subprocess.check_output(["/usr/bin/git", "mktree"], cwd=repository, input=b"").decode("ascii").strip()
    gitlink_commit = subprocess.check_output(
        ["/usr/bin/git", "commit-tree", empty_tree, "-m", "gitlink target"],
        cwd=repository,
        env=commit_environment,
    ).decode("ascii").strip()
    for name, mode, content in members:
        if mode == "160000":
            object_id = gitlink_commit
        else:
            object_id = subprocess.check_output(
                ["/usr/bin/git", "hash-object", "-w", "--stdin"], cwd=repository, input=content,
            ).decode("ascii").strip()
        subprocess.run(
            ["/usr/bin/git", "update-index", "--add", "--cacheinfo", f"{mode},{object_id},{name}"],
            cwd=repository,
            check=True,
        )
    tree = subprocess.check_output(["/usr/bin/git", "write-tree"], cwd=repository).decode("ascii").strip()
    commit = subprocess.check_output(
        ["/usr/bin/git", "commit-tree", tree, "-m", "candidate"], cwd=repository, env=commit_environment,
    ).decode("ascii").strip()
    subprocess.run(["/usr/bin/git", "update-ref", "refs/heads/main", commit], cwd=repository, check=True)
    return repository / ".git", commit, tree


def pax_tar_bytes() -> bytes:
    return tar_bytes([("safe.txt", "pax", b"x")])


def rewrite_checksum(raw: bytes) -> bytes:
    header = bytearray(raw[:512])
    _checksum(header)
    return bytes(header) + raw[512:]


class FinalizerTests(unittest.TestCase):
    def canonicalize(
        self,
        raw: bytes,
        *,
        candidate_members: Optional[Iterable[Tuple[str, str, bytes]]] = None,
        source_receipt: bytes = b"{}\n",
    ):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        output = root / "canonical.tar"
        receipt = root / "receipt.json"
        git_dir, commit, tree = git_object_database(
            root,
            candidate_members if candidate_members is not None else [("safe", "100644", b"x")],
        )
        provenance = binding()
        provenance["candidate"]["commit"] = commit
        provenance["candidate"]["tree"] = tree
        document = validator.canonicalize_archive(
            io.BytesIO(raw), output, receipt, provenance,
            release_policy=validator.load_release_policy(fixture_policy(root / "policy.json")),
            candidate_git_dir=git_dir,
            source_receipt=io.BytesIO(source_receipt),
        )
        return output, receipt, document

    def test_canonical_tar_is_deterministic_and_has_strict_metadata(self):
        candidate_members = [("dir/a.txt", "100644", b"a"), ("z.txt", "100755", b"z")]
        first = tar_bytes([("dir/a.txt", "file", b"a"), ("z.txt", "file", b"z")])
        second = tar_bytes([("dir/a.txt", "file", b"a"), ("z.txt", "file", b"z")])
        output_a, _, document_a = self.canonicalize(first, candidate_members=candidate_members)
        output_b, _, document_b = self.canonicalize(second, candidate_members=candidate_members)
        self.assertEqual(output_a.read_bytes(), output_b.read_bytes())
        self.assertEqual(document_a["canonical"]["sha256"], document_b["canonical"]["sha256"])
        self.assertEqual(document_a["payload"]["sha256"], document_b["payload"]["sha256"])
        with tarfile.open(output_a, "r") as archive:
            members = archive.getmembers()
        self.assertEqual([member.name for member in members], ["dir/a.txt", "z.txt"])
        self.assertTrue(all(member.uid == member.gid == member.mtime == 0 for member in members))
        self.assertEqual([member.mode for member in members], [0o600, 0o600])
        self.assertTrue(all(member.type == tarfile.REGTYPE and not member.pax_headers for member in members))
        self.assertEqual(output_a.read_bytes()[257:263], b"ustar\x00")
        expected_length = 1024 + sum(512 + ((member.size + 511) // 512) * 512 for member in members)
        self.assertEqual(output_a.stat().st_size, expected_length)

    def test_long_ustar_path_uses_stdlib_first_feasible_split_and_rejects_last_feasible_split(self):
        long_path = "dir/" + "a" * 39 + "/" + "b" * 60
        self.assertGreater(len(long_path.encode("ascii")), 100)
        self.assertLessEqual(len(long_path.encode("ascii")), 240)

        info = tarfile.TarInfo(long_path)
        info.size = 1
        info.mode = 0o600
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ""
        info.type = tarfile.REGTYPE
        stdlib_header = info.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")[:512]
        stdlib_name = stdlib_header[0:100].split(b"\0", 1)[0].decode("ascii")
        stdlib_prefix = stdlib_header[345:500].split(b"\0", 1)[0].decode("ascii")
        self.assertEqual(validator._canonical_ustar_fields(long_path), (stdlib_name, stdlib_prefix))
        self.assertEqual(len(stdlib_name.encode("ascii")), 100)
        self.assertNotIn(b"\0", stdlib_header[0:100])

        canonical_raw = tar_bytes([(long_path, "file", b"x")])
        self.assertEqual(canonical_raw[0:100], stdlib_header[0:100])
        self.assertEqual(canonical_raw[345:500], stdlib_header[345:500])
        output, _receipt, _document = self.canonicalize(
            canonical_raw,
            candidate_members=[(long_path, "100644", b"x")],
        )
        emitted = output.read_bytes()
        self.assertEqual(emitted[0:100], canonical_raw[0:100])
        self.assertEqual(emitted[345:500], canonical_raw[345:500])

        noncanonical_header = _strict_header(
            long_path,
            b"x",
            "file",
            last_feasible_split=True,
        )
        noncanonical_raw = noncanonical_header + b"x" + b"\0" * 511 + b"\0" * 1024
        with self.assertRaises(validator.ValidationError):
            self.canonicalize(
                noncanonical_raw,
                candidate_members=[(long_path, "100644", b"x")],
            )

        full_prefix_path = "p" * 155 + "/n"
        prefix_info = tarfile.TarInfo(full_prefix_path)
        prefix_info.size = 1
        prefix_info.mode = 0o600
        prefix_info.uid = prefix_info.gid = prefix_info.mtime = 0
        prefix_info.uname = prefix_info.gname = ""
        prefix_info.type = tarfile.REGTYPE
        prefix_header = prefix_info.tobuf(
            format=tarfile.USTAR_FORMAT,
            encoding="ascii",
            errors="strict",
        )[:512]
        self.assertNotIn(b"\0", prefix_header[345:500])
        self.assertEqual(validator._verify_ustar_header(prefix_header), (full_prefix_path, 1))

        with self.assertRaises(validator.ValidationError):
            validator._ustar_ascii_field(
                b"n" * 99,
                "name",
                allow_empty=False,
                full_width=100,
            )
        with self.assertRaises(validator.ValidationError):
            validator._ustar_ascii_field(
                b"p" * 154,
                "prefix",
                allow_empty=True,
                full_width=155,
            )

    def test_receipt_is_canonical_json_and_binds_source_receipt_bytes(self):
        raw = tar_bytes([("safe.txt", "file", b"payload")])
        output, receipt, document = self.canonicalize(
            raw,
            candidate_members=[("safe.txt", "100644", b"payload")],
            source_receipt=b'{"untrusted":true}\n',
        )
        encoded = receipt.read_bytes()
        self.assertEqual(encoded, validator.canonical_json(document))
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(document["source_receipt"]["sha256"], hashlib.sha256(b'{"untrusted":true}\n').hexdigest())
        self.assertEqual(document["canonical"]["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(document["provenance"]["candidate"]["commit"], document["candidate_inventory"]["commit"])
        self.assertEqual(document["provenance"]["cache"], {"shared": False, "enabled": False})
        self.assertEqual(document["payload"]["input_tree_sha256"], document["payload"]["sha256"])
        self.assertEqual(document["candidate_inventory"]["sha256"], document["payload"]["input_tree_sha256"])
        self.assertEqual(document["canonicalization"], validator.ARCHIVE_CONTRACT)

    def test_rejects_hostile_names_and_collisions(self):
        non_ascii = bytearray(tar_bytes([("safe", "file", b"x")]))
        non_ascii[0:100] = b"cafe\xcc\x81\0" + b"\0" * (100 - len(b"cafe\xcc\x81\0"))
        invalid_archives = [
            tar_bytes([("/absolute", "file", b"x")]),
            tar_bytes([("../dotdot", "file", b"x")]),
            tar_bytes([("a//b", "file", b"x")]),
            tar_bytes([("same", "file", b"x"), ("same", "file", b"y")]),
            tar_bytes([("A", "file", b"x"), ("a", "file", b"y")]),
            tar_bytes([("dir/new\nline", "file", b"x")]),
            tar_bytes([("dir/tab\tname", "file", b"x")]),
            rewrite_checksum(bytes(non_ascii)),
            tar_bytes([("file", "file", b"x"), ("file/child", "file", b"y")]),
        ]
        for raw in invalid_archives:
            with self.subTest(raw_digest=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(validator.ValidationError):
                    self.canonicalize(raw)

    def test_rejects_links_devices_fifos_sparse_and_pax(self):
        invalid_archives = [
            tar_bytes([("link", "symlink", b"")]),
            tar_bytes([("link", "hardlink", b"")]),
            tar_bytes([("pipe", "fifo", b"")]),
            tar_bytes([("dev", "device", b"")]),
            tar_bytes([("sparse", "sparse", b"")]),
            pax_tar_bytes(),
        ]
        for raw in invalid_archives:
            with self.subTest(raw_digest=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(validator.ValidationError):
                    self.canonicalize(raw)

    def test_rejects_non_zero_trailing_bytes_and_never_leaves_outputs(self):
        raw = tar_bytes([("safe", "file", b"x")]) + b"malicious-tail"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "canonical.tar"
            receipt = root / "receipt.json"
            with self.assertRaises(validator.ValidationError):
                validator.canonicalize_archive(
                    io.BytesIO(raw), output, receipt, binding(),
                    release_policy=validator.load_release_policy(fixture_policy(root / "policy.json")),
                    candidate_git_dir=root / "missing.git",
                    source_receipt=io.BytesIO(b"{}\n"),
                )
            self.assertFalse(output.exists())
            self.assertFalse(receipt.exists())

    def test_raw_archive_requires_strict_ustar_metadata_and_exact_two_block_eoa(self):
        valid = tar_bytes([("safe.txt", "file", b"payload")])
        mode_drift = bytearray(valid)
        mode_drift[100:108] = _octal(0o644, 8)
        uid_drift = bytearray(valid)
        uid_drift[108:116] = _octal(1, 8)
        empty_uid = bytearray(valid)
        empty_uid[108:116] = b"\0" * 8
        mtime_drift = bytearray(valid)
        mtime_drift[136:148] = _octal(1, 12)
        gnu_magic = bytearray(valid)
        gnu_magic[257:263] = b"ustar "
        bad_version = bytearray(valid)
        bad_version[263:265] = b"01"
        link_drift = bytearray(valid)
        link_drift[157:163] = b"target"
        owner_drift = bytearray(valid)
        owner_drift[265:270] = b"owner"
        device_drift = bytearray(valid)
        device_drift[329:337] = _octal(1, 8)
        padding_drift = bytearray(valid)
        padding_drift[500] = 1
        nul_typeflag = bytearray(valid)
        nul_typeflag[156] = 0
        prefix_drift_header = bytearray(_strict_header("a", b"payload", "file"))
        prefix_drift_header[345:349] = b"dir\0"
        prefix_drift = rewrite_checksum(bytes(prefix_drift_header) + valid[512:])
        gnu_record_padding = valid + b"\0" * (10_240 - len(valid))
        invalid_archives = [
            rewrite_checksum(bytes(mode_drift)),
            rewrite_checksum(bytes(uid_drift)),
            rewrite_checksum(bytes(empty_uid)),
            rewrite_checksum(bytes(mtime_drift)),
            rewrite_checksum(bytes(gnu_magic)),
            rewrite_checksum(bytes(bad_version)),
            rewrite_checksum(bytes(link_drift)),
            rewrite_checksum(bytes(owner_drift)),
            rewrite_checksum(bytes(device_drift)),
            rewrite_checksum(bytes(padding_drift)),
            rewrite_checksum(bytes(nul_typeflag)),
            prefix_drift,
            tar_bytes([("z.txt", "file", b"z"), ("safe.txt", "file", b"payload")]),
            valid + b"\0" * 512,
            gnu_record_padding,
            valid + b"x",
        ]
        for raw in invalid_archives:
            with self.subTest(raw_digest=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(validator.ValidationError):
                    self.canonicalize(raw)

    def test_raw_headers_are_prevalidated_without_candidate_tar_decoder(self):
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        self.assertIn("def _verify_ustar_header", source)
        self.assertIn("def _stage_archive", source)
        self.assertNotIn("tarfile.open(fileobj=reader", source)

    def test_size_limits_and_binding_schema_are_fail_closed(self):
        original = validator.MAX_MEMBER_BYTES
        try:
            validator.MAX_MEMBER_BYTES = 3
            with self.assertRaises(validator.ValidationError):
                self.canonicalize(tar_bytes([("large", "file", b"four")]))
        finally:
            validator.MAX_MEMBER_BYTES = original
        invalid = binding()
        invalid["cache"] = {"shared": False, "enabled": True}
        with self.assertRaises(validator.ValidationError):
            validator.validate_binding(invalid)
        invalid = binding()
        invalid["signer"]["workflow_ref"] = "tonyaiuser/babata-board/.github/workflows/other.yml@refs/heads/main"
        with self.assertRaises(validator.ValidationError):
            validator.validate_binding(invalid)

    def test_trusted_release_policy_rejects_arbitrary_safe_tar_paths_and_requires_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = validator.load_release_policy(TRUSTED_POLICY_PATH)
            forbidden = tar_bytes([("arbitrary-but-safe.txt", "file", b"x")])
            with self.assertRaises(validator.ValidationError):
                validator.canonicalize_archive(
                    io.BytesIO(forbidden), root / "bad.tar", root / "bad.json", binding(),
                    release_policy=policy, candidate_git_dir=root / "missing.git", source_receipt=io.BytesIO(b"{}\n"),
                )
            forbidden_directory = tar_bytes([
                ("scripts/report_delivery_outbox_v1.py", "file", b"outbox"),
                ("scripts/report_delivery_adapters_v1.py", "file", b"adapter"),
                ("single-page-monitor/", "dir", b""),
            ])
            with self.assertRaises(validator.ValidationError):
                validator.canonicalize_archive(
                    io.BytesIO(forbidden_directory), root / "dir.tar", root / "dir.json", binding(),
                    release_policy=policy, candidate_git_dir=root / "missing.git", source_receipt=io.BytesIO(b"{}\n"),
                )
            forbidden_git = tar_bytes([
                ("scripts/report_delivery_outbox_v1.py", "file", b"outbox"),
                ("scripts/report_delivery_adapters_v1.py", "file", b"adapter"),
                ("single-page-monitor/.git/config", "file", b"hostile"),
            ])
            with self.assertRaises(validator.ValidationError):
                validator.canonicalize_archive(
                    io.BytesIO(forbidden_git), root / "git.tar", root / "git.json", binding(),
                    release_policy=policy, candidate_git_dir=root / "missing.git", source_receipt=io.BytesIO(b"{}\n"),
                )
            accepted = tar_bytes([
                ("scripts/report_delivery_adapters_v1.py", "file", b"adapter"),
                ("scripts/report_delivery_outbox_v1.py", "file", b"outbox"),
                ("single-page-monitor/latest.html", "file", b"report"),
            ])
            git_dir, commit, tree = git_object_database(root, [
                ("scripts/report_delivery_adapters_v1.py", "100644", b"adapter"),
                ("scripts/report_delivery_outbox_v1.py", "100644", b"outbox"),
                ("single-page-monitor/latest.html", "100644", b"report"),
            ])
            provenance = binding()
            provenance["candidate"].update({"commit": commit, "tree": tree})
            document = validator.canonicalize_archive(
                io.BytesIO(accepted), root / "good.tar", root / "good.json", provenance,
                release_policy=policy, candidate_git_dir=git_dir, source_receipt=io.BytesIO(b"{}\n"),
            )
            self.assertEqual(document["release_policy"]["sha256"], hashlib.sha256(TRUSTED_POLICY_PATH.read_bytes()).hexdigest())
            self.assertEqual(document["release_policy"]["blob"]["paths"]["required_files"], ["scripts/report_delivery_adapters_v1.py", "scripts/report_delivery_outbox_v1.py"])

    def test_raw_archive_must_exactly_match_independent_candidate_git_blobs(self):
        forged = tar_bytes([("safe", "file", b"forged")])
        with self.assertRaises(validator.ValidationError):
            self.canonicalize(forged, candidate_members=[("safe", "100644", b"genuine")])

        correct = tar_bytes([("dir/a.txt", "file", b"a"), ("safe", "file", b"genuine")])
        output, _receipt, document = self.canonicalize(
            correct,
            candidate_members=[("safe", "100644", b"genuine"), ("dir/a.txt", "100755", b"a")],
        )
        self.assertTrue(output.is_file())
        self.assertEqual(document["candidate_inventory"]["bytes"], len(b"genuine") + 1)

        omitted = tar_bytes([("safe", "file", b"genuine")])
        with self.assertRaises(validator.ValidationError):
            self.canonicalize(
                omitted,
                candidate_members=[("safe", "100644", b"genuine"), ("dir/omitted.txt", "100644", b"missing")],
            )

    def test_candidate_git_inventory_rejects_symlink_gitlink_tree_mismatch_and_case_path_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = validator.load_release_policy(fixture_policy(root / "policy.json"))
            for mode in ("120000", "160000"):
                scoped_root = root / mode
                scoped_root.mkdir()
                git_dir, commit, tree = git_object_database(scoped_root, [
                    ("safe", "100644", b"safe"),
                    ("dir/nonregular", mode, b"target"),
                ])
                with self.subTest(mode=mode), self.assertRaises(validator.ValidationError):
                    validator.load_candidate_inventory(git_dir, commit, tree, policy)

            mismatch_root = root / "mismatch"
            mismatch_root.mkdir()
            git_dir, commit, tree = git_object_database(mismatch_root, [("safe", "100644", b"safe")])
            with self.assertRaises(validator.ValidationError):
                validator.load_candidate_inventory(git_dir, commit, "f" * 40, policy)
            with self.assertRaises(validator.ValidationError):
                validator.load_candidate_inventory(git_dir, "a" * 64, tree, policy)

            collision_root = root / "collision"
            collision_root.mkdir()
            git_dir, commit, tree = git_object_database(collision_root, [
                ("safe", "100644", b"safe"),
                ("dir/A/value", "100644", b"upper"),
                ("dir/a/other", "100644", b"lower"),
            ])
            with self.assertRaises(validator.ValidationError):
                validator.load_candidate_inventory(git_dir, commit, tree, policy)

            directory_root = root / "exact-directory"
            directory_root.mkdir()
            git_dir, commit, tree = git_object_database(
                directory_root,
                [("safe/child", "100644", b"not an exact regular file")],
            )
            with self.assertRaises(validator.ValidationError):
                validator.load_candidate_inventory(git_dir, commit, tree, policy)

            control_root = root / "control"
            control_root.mkdir()
            git_dir, commit, tree = git_object_database(control_root, [
                ("safe", "100644", b"safe"),
                ("dir/new\nline", "100644", b"control"),
            ])
            with self.assertRaises(validator.ValidationError):
                validator.load_candidate_inventory(git_dir, commit, tree, policy)

    def test_deep_git_inventory_streams_180_leaves_in_one_blob_batch_and_fails_at_entry_181(self):
        paths = deep_git_paths(181)
        self.assertTrue(all(len(path.encode("ascii")) == 205 for path in paths))
        accepted_members = [(path, "100644", b"x") for path in paths[:180]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = validator.load_release_policy(stress_policy(root / "policy.json", 180))
            git_dir, commit, tree = git_object_database(root, accepted_members)
            provenance = binding()
            provenance["candidate"].update({"commit": commit, "tree": tree})
            git_calls: list[tuple[str, ...]] = []
            original_run = validator._run_git_stream

            def tracked_git(git_database, arguments, **kwargs):
                git_calls.append(tuple(arguments))
                return original_run(git_database, arguments, **kwargs)

            with mock.patch.object(validator, "_run_git_stream", side_effect=tracked_git):
                document = validator.canonicalize_archive(
                    io.BytesIO(tar_bytes((path, "file", b"x") for path in paths[:180])),
                    root / "canonical.tar",
                    root / "receipt.json",
                    provenance,
                    release_policy=policy,
                    candidate_git_dir=git_dir,
                    source_receipt=io.BytesIO(b"{}\n"),
                )
            self.assertEqual(document["candidate_inventory"]["entries"], 180)
            self.assertEqual(git_calls.count(("cat-file", "--batch")), 1)
            self.assertIn(
                ("ls-tree", "-r", "-z", "-l", "--full-tree", tree, "--", ":(top,literal)dir"),
                git_calls,
            )

            overflow_root = root / "overflow"
            overflow_root.mkdir()
            overflow_git, overflow_commit, overflow_tree = git_object_database(
                overflow_root,
                [(path, "100644", b"x") for path in paths],
            )
            with mock.patch.object(
                validator,
                "_git_blob_entries",
                side_effect=AssertionError("entry overflow must fail before blob reads"),
            ):
                with self.assertRaises(validator.ValidationError):
                    validator.load_candidate_inventory(
                        overflow_git,
                        overflow_commit,
                        overflow_tree,
                        policy,
                    )

    def test_git_object_inspection_has_stream_caps_one_deadline_and_no_unbounded_run(self):
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        self.assertIn('["ls-tree", "-r", "-z", "-l"', source)
        self.assertNotIn('["ls-tree", "-r", "-t"', source)
        self.assertIn('["cat-file", "--batch"]', source)
        self.assertNotIn('["cat-file", "blob"', source)
        self.assertNotIn("subprocess.run(", source)
        self.assertIn("selectors.DefaultSelector", source)
        self.assertIn("deadline = time.monotonic() + GIT_INSPECTION_TIMEOUT_SECONDS", source)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_dir, commit, _tree = git_object_database(root, [("safe", "100644", b"x")])
            with self.assertRaises(validator.ValidationError):
                validator._run_git_stream(
                    git_dir,
                    ["rev-parse", "--verify", commit],
                    deadline=time.monotonic() - 1,
                    stdout_cap=128,
                    on_stdout=lambda _chunk: None,
                )

    def test_space_in_policy_scoped_git_path_is_parsed_without_shell_splitting(self):
        raw = tar_bytes([("dir/with space.txt", "file", b"space")])
        _output, _receipt, document = self.canonicalize(
            raw,
            candidate_members=[("dir/with space.txt", "100644", b"space")],
        )
        self.assertEqual(document["candidate_inventory"]["entries"], 1)

    def test_policy_and_receipt_have_one_machine_readable_v2_contract_shape(self):
        raw = tar_bytes([("safe", "file", b"safe")])
        _output, _receipt, document = self.canonicalize(
            raw,
            candidate_members=[("safe", "100644", b"safe")],
            source_receipt=b'{"hostile":true}\n',
        )
        self.assertEqual(
            set(document),
            {
                "canonical", "canonicalization", "candidate_inventory", "payload", "provenance", "raw",
                "release_policy", "schema", "source_receipt", "version",
            },
        )
        self.assertEqual(set(document["canonical"]), {"bytes", "sha256"})
        self.assertEqual(set(document["candidate_inventory"]), {"bytes", "commit", "entries", "format", "sha256", "tree"})
        self.assertEqual(set(document["payload"]), {"bytes", "entries", "input_tree_sha256", "sha256"})
        self.assertEqual(set(document["raw"]), {"bytes", "sha256"})
        self.assertEqual(set(document["source_receipt"]), {"bytes", "sha256"})
        self.assertEqual(set(document["release_policy"]), {"blob", "sha256"})
        self.assertEqual(document["schema"], "spspy.trusted-reverse-producer-v2.receipt")
        self.assertEqual(document["version"], 1)
        self.assertEqual(document["canonicalization"], validator.ARCHIVE_CONTRACT)
        self.assertEqual(document["release_policy"]["blob"]["archive"], validator.ARCHIVE_CONTRACT)
        self.assertEqual(document["release_policy"]["blob"]["inventory"], validator.INVENTORY_CONTRACT)
        self.assertEqual(document["candidate_inventory"]["format"], validator.INVENTORY_CONTRACT["format"])


class PrepareTests(unittest.TestCase):
    def _candidate(
        self,
        root: Path,
        *,
        builder_prefix: str = "",
        test_body: str = "self.assertTrue(True)",
    ) -> tuple[Path, str, str]:
        candidate = root / "candidate"
        (candidate / "tools").mkdir(parents=True)
        (candidate / "config").mkdir()
        (candidate / "tests").mkdir()
        (candidate / "scripts").mkdir()
        (candidate / "single-page-monitor").mkdir()
        (candidate / "config" / "reverse_producer_v2.json").write_text('{"version":1}\n', encoding="utf-8")
        (candidate / "scripts" / "report_delivery_adapters_v1.py").write_bytes(b"adapter\n")
        (candidate / "scripts" / "report_delivery_outbox_v1.py").write_bytes(b"outbox\n")
        (candidate / "single-page-monitor" / "latest.html").write_bytes(b"report\n")
        (candidate / "tests" / "test_fixed_wrapper.py").write_text(
            "import unittest\n"
            "class FixedWrapperTest(unittest.TestCase):\n"
            " def test_fixed(self):\n"
            f"  {test_body}\n",
            encoding="utf-8",
        )
        (candidate / "tools" / "reverse_candidate_build_v2.py").write_text(
            "import argparse, json, os\n"
            "p=argparse.ArgumentParser(); p.add_argument('--candidate-root'); p.add_argument('--source-commit'); p.add_argument('--source-tree'); p.add_argument('--candidate-repository'); p.add_argument('--workflow-repository'); p.add_argument('--workflow-path'); p.add_argument('--workflow-ref'); p.add_argument('--signer-workflow-ref'); p.add_argument('--workflow-commit'); p.add_argument('--workflow-blob'); p.add_argument('--output-dir'); a=p.parse_args()\n"
            "assert a.workflow_ref == 'refs/heads/main'\n"
            "assert a.signer_workflow_ref == 'tonyaiuser/babata-board/.github/workflows/trusted-reverse-producer-v2.yml@refs/heads/main'\n"
            + builder_prefix
            + "def octal(value, width): return ('%0*o' % (width - 1, value)).encode('ascii') + b'\\0'\n"
            "def header(name, body):\n"
            " e=name.encode('ascii'); h=bytearray(512); h[0:len(e)]=e; h[100:108]=octal(0o600,8); h[108:116]=octal(0,8); h[116:124]=octal(0,8); h[124:136]=octal(len(body),12); h[136:148]=octal(0,12); h[156:157]=b'0'; h[257:263]=b'ustar\\0'; h[263:265]=b'00'; h[329:337]=octal(0,8); h[337:345]=octal(0,8); h[148:156]=b' '*8; h[148:156]=('%06o' % sum(h)).encode('ascii') + b'\\0 '; return bytes(h)\n"
            "names=('scripts/report_delivery_adapters_v1.py','scripts/report_delivery_outbox_v1.py','single-page-monitor/latest.html')\n"
            "with open(os.path.join(a.output_dir, 'release-payload.tar'), 'xb') as output:\n"
            " for name in names:\n"
            "  body=open(os.path.join(a.candidate_root, name), 'rb').read(); output.write(header(name, body)); output.write(body); output.write(b'\\0' * ((-len(body)) % 512))\n"
            " output.write(b'\\0' * 1024)\n"
            "open(os.path.join(a.output_dir, 'release-receipt.json'), 'x', encoding='utf-8').write(json.dumps({'workflow_ref': a.workflow_ref}) + '\\n')\n",
            encoding="utf-8",
        )
        for command in (
            ["/usr/bin/git", "init", "-q"],
            ["/usr/bin/git", "add", "."],
            ["/usr/bin/git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "candidate"],
        ):
            subprocess.run(command, cwd=candidate, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        commit = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=candidate, text=True).strip()
        tree = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD^{tree}"], cwd=candidate, text=True).strip()
        return candidate, commit, tree

    def _real_candidate(
        self,
        root: Path,
        source_root: Path,
        *,
        extra_monitor_files: Optional[dict[str, bytes]] = None,
    ) -> tuple[Path, str, str]:
        candidate = root / "real-candidate"
        for directory in ("tools", "config", "tests", "scripts", "single-page-monitor"):
            (candidate / directory).mkdir(parents=True, exist_ok=True)
        builder_source = source_root / "tools" / "reverse_candidate_build_v2.py"
        config_source = source_root / "config" / "reverse_producer_v2.json"
        (candidate / "tools" / builder_source.name).write_bytes(builder_source.read_bytes())
        config = json.loads(config_source.read_text(encoding="utf-8"))
        config["workflow"].update({
            "repository": prepare.TRUSTED_REPOSITORY,
            "path": prepare.CANONICAL_WORKFLOW_PATH,
            "authority_ref": prepare.CANONICAL_BUILDER_AUTHORITY_REF,
            "signer_workflow_ref": prepare.CANONICAL_SIGNER_WORKFLOW_REF,
            "blob_oid": "e" * 40,
        })
        (candidate / "config" / "reverse_producer_v2.json").write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
        (candidate / "tests" / "test_fixed_wrapper.py").write_text(
            "import unittest\nclass FixedWrapperTest(unittest.TestCase):\n def test_fixed(self): self.assertTrue(True)\n",
            encoding="utf-8",
        )
        (candidate / "scripts" / "report_delivery_adapters_v1.py").write_bytes(b"adapter\n")
        (candidate / "scripts" / "report_delivery_outbox_v1.py").write_bytes(b"outbox\n")
        (candidate / "single-page-monitor" / "latest.html").write_bytes(b"report\n")
        for relative, body in (extra_monitor_files or {}).items():
            target = candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        for command in (
            ["/usr/bin/git", "init", "-q"],
            ["/usr/bin/git", "add", "."],
            ["/usr/bin/git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "real candidate"],
        ):
            subprocess.run(command, cwd=candidate, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        commit = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=candidate, text=True).strip()
        tree = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD^{tree}"], cwd=candidate, text=True).strip()
        return candidate, commit, tree

    def test_fixed_wrapper_executes_only_canonical_candidate_interface_and_copies_two_regular_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, commit, tree = self._candidate(root)
            output = root / "out"
            result = prepare.prepare_candidate(
                candidate, output, commit, tree,
                prepare.TRUSTED_REPOSITORY, prepare.TRUSTED_REPOSITORY,
                prepare.CANONICAL_SIGNER_WORKFLOW_REF, prepare.CANONICAL_BUILDER_AUTHORITY_REF,
                "c" * 40, "e" * 40, 30,
            )
            self.assertEqual(set(path.name for path in output.iterdir()), {"raw-reverse.tar", "raw-reverse-receipt.json"})
            self.assertEqual(result["raw_archive_sha256"], hashlib.sha256((output / "raw-reverse.tar").read_bytes()).hexdigest())
            self.assertEqual(result["raw_receipt_sha256"], hashlib.sha256((output / "raw-reverse-receipt.json").read_bytes()).hexdigest())
            self.assertEqual((output / "raw-reverse.tar").stat().st_nlink, 1)
            wrapper_receipt = json.loads((output / "raw-reverse-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(wrapper_receipt["schema"], prepare.PREPARE_RECEIPT_SCHEMA)
            self.assertEqual(wrapper_receipt["execution"]["tests"]["exit_code"], 0)
            self.assertEqual(wrapper_receipt["execution"]["tests"]["positive_test_count"], 1)
            self.assertEqual(wrapper_receipt["execution"]["build"]["exit_code"], 0)
            self.assertTrue(wrapper_receipt["execution"]["build"]["stdout"]["within_cap"])
            test_budget = wrapper_receipt["commands"]["tests"]["timeout_seconds"]
            build_budget = wrapper_receipt["commands"]["build"]["timeout_seconds"]
            self.assertGreaterEqual(test_budget, build_budget)
            self.assertGreaterEqual(build_budget, 1)
            self.assertLessEqual(test_budget, 30)
            self.assertEqual(wrapper_receipt["limits"]["overall_prepare_seconds"], 30)
            self.assertIn("candidate_raw_receipt", wrapper_receipt)
            self.assertNotIn("ok", wrapper_receipt)
            self.assertEqual(wrapper_receipt["workflow"]["signer_workflow_ref"], prepare.CANONICAL_SIGNER_WORKFLOW_REF)
            self.assertEqual(wrapper_receipt["workflow"]["builder_authority_ref"], "refs/heads/main")
            self.assertEqual(wrapper_receipt["commands"]["tests"]["argv"], list(prepare.FIXED_TEST_COMMAND))
            build_argv = wrapper_receipt["commands"]["build"]["argv"]
            self.assertEqual(build_argv[build_argv.index("--workflow-ref") + 1], "refs/heads/main")
            self.assertEqual(build_argv[build_argv.index("--signer-workflow-ref") + 1], prepare.CANONICAL_SIGNER_WORKFLOW_REF)
            self.assertNotIn("--input-tree", wrapper_receipt["commands"]["build"]["argv"])
            self.assertNotIn("--check", wrapper_receipt["commands"]["build"]["argv"])
            self.assertNotIn("tests", wrapper_receipt["commands"]["build"]["argv"])
            with self.assertRaises(prepare.PrepareError):
                prepare.prepare_candidate(
                    candidate, root / "wrong-tree", commit, "f" * 40,
                    prepare.TRUSTED_REPOSITORY, prepare.TRUSTED_REPOSITORY,
                    prepare.CANONICAL_SIGNER_WORKFLOW_REF, prepare.CANONICAL_BUILDER_AUTHORITY_REF,
                    "c" * 40, "e" * 40, 30,
                )

    def test_fixed_unittest_fails_closed_on_capped_output(self):
        original = prepare.MAX_CANDIDATE_STDOUT_BYTES
        try:
            prepare.MAX_CANDIDATE_STDOUT_BYTES = 64
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                candidate, commit, tree = self._candidate(
                    root,
                    test_body="import sys; sys.stdout.write('x' * 128); sys.stdout.flush(); self.assertTrue(True)",
                )
                with self.assertRaises(prepare.PrepareError):
                    prepare.prepare_candidate(
                        candidate, root / "capped", commit, tree,
                        prepare.TRUSTED_REPOSITORY, prepare.TRUSTED_REPOSITORY,
                        prepare.CANONICAL_SIGNER_WORKFLOW_REF, prepare.CANONICAL_BUILDER_AUTHORITY_REF,
                        "c" * 40, "e" * 40, 30,
                    )
        finally:
            prepare.MAX_CANDIDATE_STDOUT_BYTES = original

    def test_prepare_to_finalizer_cross_contract_uses_real_git_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, commit, tree = self._candidate(root)
            raw_output = root / "raw"
            prepare.prepare_candidate(
                candidate, raw_output, commit, tree,
                prepare.TRUSTED_REPOSITORY, prepare.TRUSTED_REPOSITORY,
                prepare.CANONICAL_SIGNER_WORKFLOW_REF, prepare.CANONICAL_BUILDER_AUTHORITY_REF,
                "c" * 40, "e" * 40, 30,
            )
            provenance = binding()
            provenance["candidate"].update({"commit": commit, "tree": tree})
            canonical = root / "final" / "canonical-reverse.tar"
            receipt = root / "final" / "canonical-reverse-receipt.json"
            with (raw_output / "raw-reverse.tar").open("rb") as raw_stream, (raw_output / "raw-reverse-receipt.json").open("rb") as receipt_stream:
                document = validator.canonicalize_archive(
                    raw_stream,
                    canonical,
                    receipt,
                    provenance,
                    release_policy=validator.load_release_policy(TRUSTED_POLICY_PATH),
                    candidate_git_dir=candidate / ".git",
                    source_receipt=receipt_stream,
                )
            self.assertEqual(document["canonicalization"]["format"], "ustar-v1")
            self.assertEqual(document["candidate_inventory"]["tree"], tree)
            self.assertEqual(document["candidate_inventory"]["sha256"], document["payload"]["input_tree_sha256"])
            self.assertEqual(canonical.stat().st_size, (raw_output / "raw-reverse.tar").stat().st_size)
            self.assertEqual(canonical.read_bytes()[-1024:], b"\0" * 1024)

    def test_actual_candidate_builder_cross_worktree_contract_when_available(self):
        configured = os.environ.get("SPSPY_REAL_CANDIDATE_V2_ROOT")
        source_root = Path(configured) if configured else ROOT
        if not (source_root / "tools" / "reverse_candidate_build_v2.py").is_file():
            self.skipTest("actual candidate builder is developed in a separate worktree")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            long_path = "single-page-monitor/" + "a" * 39 + "/" + "b" * 60
            self.assertGreater(len(long_path.encode("ascii")), 100)
            self.assertLessEqual(len(long_path.encode("ascii")), 240)
            candidate, commit, tree = self._real_candidate(
                root,
                source_root,
                extra_monitor_files={long_path: b"long-path\n"},
            )
            raw_output = root / "raw"
            prepare.prepare_candidate(
                candidate, raw_output, commit, tree,
                prepare.TRUSTED_REPOSITORY, prepare.TRUSTED_REPOSITORY,
                prepare.CANONICAL_SIGNER_WORKFLOW_REF, prepare.CANONICAL_BUILDER_AUTHORITY_REF,
                "c" * 40, "e" * 40, 30,
            )
            provenance = binding()
            provenance["candidate"].update({"commit": commit, "tree": tree})
            canonical_path = root / "canonical.tar"
            with (raw_output / "raw-reverse.tar").open("rb") as raw_stream, (raw_output / "raw-reverse-receipt.json").open("rb") as receipt_stream:
                document = validator.canonicalize_archive(
                    raw_stream,
                    canonical_path,
                    root / "canonical.json",
                    provenance,
                    release_policy=validator.load_release_policy(TRUSTED_POLICY_PATH),
                    candidate_git_dir=candidate / ".git",
                    source_receipt=receipt_stream,
                )
            self.assertEqual(document["candidate_inventory"]["tree"], tree)
            self.assertEqual(document["candidate_inventory"]["entries"], 4)
            self.assertEqual(
                canonical_path.read_bytes(),
                (raw_output / "raw-reverse.tar").read_bytes(),
            )
            with tarfile.open(canonical_path, "r:") as archive:
                member = archive.getmember(long_path)
            expected_name, expected_prefix = validator._canonical_ustar_fields(long_path)
            canonical_bytes = canonical_path.read_bytes()
            header = canonical_bytes[member.offset:member.offset + 512]
            self.assertEqual(len(expected_name.encode("ascii")), 100)
            self.assertNotIn(b"\0", header[0:100])
            self.assertEqual(header[0:100].split(b"\0", 1)[0].decode("ascii"), expected_name)
            self.assertEqual(header[345:500].split(b"\0", 1)[0].decode("ascii"), expected_prefix)

    def test_failing_fixed_unittest_prevents_candidate_builder_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, commit, tree = self._candidate(
                root,
                builder_prefix="open(os.path.join(a.candidate_root, 'builder-ran'), 'w').write('unexpected')\n",
                test_body="self.fail('fixed tests must gate builder')",
            )
            with self.assertRaises(prepare.PrepareError):
                prepare.prepare_candidate(
                    candidate, root / "failed-test", commit, tree,
                    prepare.TRUSTED_REPOSITORY, prepare.TRUSTED_REPOSITORY,
                    prepare.CANONICAL_SIGNER_WORKFLOW_REF, prepare.CANONICAL_BUILDER_AUTHORITY_REF,
                    "c" * 40, "e" * 40, 30,
                )
            self.assertFalse((candidate / "builder-ran").exists())

    def test_naturally_reaped_leader_receives_no_cleanup_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = prepare._clean_environment(root / "home", root / "tmp")
            with mock.patch.object(prepare, "_signal_direct_leader", side_effect=AssertionError("must not signal after reap")):
                exit_code, _stdout, _stderr = prepare._run_fixed_command(
                    ["/usr/bin/python3", "-c", "pass"], root, environment, 5, phase="test",
                )
            self.assertEqual(exit_code, 0)

    def test_wrapper_cli_is_fixed_to_candidate_root_and_job_workflow_identity(self):
        source = PREPARE_PATH.read_text(encoding="utf-8")
        for token in (
            "--candidate-root", "--source-commit", "--source-tree", "--candidate-repository",
            "--workflow-repository", "--workflow-path", "--workflow-ref", "--signer-workflow-ref",
            "--builder-authority-ref", "--workflow-commit", "--workflow-blob", "--output-dir",
        ):
            self.assertIn(token, source)
        self.assertEqual(
            prepare.FIXED_TEST_COMMAND,
            ("/usr/bin/python3", "-I", "-B", "-S", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"),
        )
        self.assertIn("_positive_unittest_count", source)
        self.assertIn("_remaining_budget_seconds", source)
        self.assertIn("process.poll()", source)
        self.assertIn("_signal_direct_leader", source)
        self.assertNotIn("os.killpg", source)
        self.assertNotIn("os.waitid", source)
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("os.link(temporary, destination, follow_symlinks=False)", source)
        self.assertNotIn("os.replace", source)
        self.assertNotIn("--input-tree", source)
        self.assertNotIn("--policy", source)
        self.assertIn("CANONICAL_SIGNER_WORKFLOW_REF", source)
        self.assertEqual(prepare.CANONICAL_BUILDER_AUTHORITY_REF, "refs/heads/main")
        invalid = binding()
        invalid["candidate"]["commit"] = "short"
        with self.assertRaises(validator.ValidationError):
            validator.validate_binding(invalid)


class WorkflowStaticTests(unittest.TestCase):
    def _read(self, path: Path) -> str:
        self.assertTrue(path.is_file(), f"missing required workflow {path}")
        return path.read_text(encoding="utf-8")

    def test_workflow_static_security_contract(self):
        workflow = self._read(WORKFLOW_PATH)
        dispatch = self._read(DISPATCH_PATH)
        self.assertIn("workflow_call:", workflow)
        self.assertIn("workflow_dispatch:", dispatch)
        self.assertNotIn("pull_request_target", workflow + dispatch)
        self.assertNotIn("self-hosted", workflow + dispatch)
        self.assertNotIn("secrets.", workflow + dispatch)
        self.assertIn("concurrency:", workflow)
        self.assertGreaterEqual(workflow.count("timeout-minutes:"), 2)
        self.assertIn("contents: read", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertNotIn("actions/cache@", workflow)
        self.assertIn("PIP_NO_CACHE_DIR: \"1\"", workflow)
        self.assertIn("raw-reverse-${{ github.run_id }}-${{ github.run_attempt }}", workflow)
        self.assertIn("job.workflow_repository", workflow)
        self.assertIn("job.workflow_sha", workflow)
        self.assertIn("job.workflow_ref", workflow)
        self.assertNotIn("github.workflow_sha", workflow)
        self.assertIn("TRUSTED_REPOSITORY: tonyaiuser/babata-board", workflow)
        self.assertIn("--policy trusted/.github/reverse_producer_v2/policy.json", workflow)
        self.assertTrue(TRUSTED_POLICY_PATH.is_file())
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6", workflow)
        self.assertNotIn("actions/attest-build-provenance@", workflow)
        self.assertIn("final/canonical-reverse.tar\n            final/canonical-reverse-receipt.json", workflow)
        self.assertIn("SOURCE_COMMIT: ${{ github.sha }}", workflow)
        self.assertIn("SIGNER_COMMIT: ${{ job.workflow_sha }}", workflow)
        self.assertIn("PREPARE_RESULT: ${{ needs.prepare.result }}", workflow)
        self.assertIn("BUILDER_AUTHORITY_REF: refs/heads/main", workflow)
        self.assertIn("--signer-workflow-ref \"$SIGNER_WORKFLOW_REF\"", workflow)
        self.assertIn("--builder-authority-ref \"$BUILDER_AUTHORITY_REF\"", workflow)
        self.assertNotIn("predicate-type:", workflow)
        self.assertNotIn("predicate-path:", workflow)
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow + "\n" + dispatch, re.MULTILINE)
        self.assertGreaterEqual(len(uses), 5)
        for action in uses:
            if action == "./.github/workflows/trusted-reverse-producer-v2.yml":
                continue
            owner_name, sha = action.rsplit("@", 1)
            if owner_name.startswith("actions/"):
                self.assertRegex(sha, r"^[0-9a-f]{40}$", action)
            else:
                self.fail(f"non-official remote action: {action}")

    def test_job_b_uses_candidate_object_database_without_executing_or_importing_candidate(self):
        workflow = self._read(WORKFLOW_PATH)
        match = re.search(r"\n  finalize:\n(?P<body>.*)\Z", workflow, re.DOTALL)
        self.assertIsNotNone(match)
        body = match.group("body")
        self.assertIn("ref: ${{ inputs.candidate_sha }}", body)
        self.assertIn("path: candidate-object-db", body)
        self.assertIn("--candidate-git-dir candidate-object-db/.git", body)
        self.assertIn("submodules: false", body)
        self.assertIn("lfs: false", body)
        self.assertNotRegex(body, r"python3[^\n]*candidate-object-db")
        self.assertNotRegex(body, r"(?:source|bash|sh)\s+candidate-object-db")
        self.assertIn("actions/download-artifact@", body)
        self.assertIn("validate.py", body)
        self.assertIn("actions/attest@", body)
        self.assertIn("ref: ${{ job.workflow_sha }}", body)

    def test_dispatch_is_thin_caller_only(self):
        dispatch = self._read(DISPATCH_PATH)
        self.assertIn("uses: ./.github/workflows/trusted-reverse-producer-v2.yml", dispatch)
        self.assertNotIn("runs-on:", dispatch)
        self.assertNotIn("steps:", dispatch)


if __name__ == "__main__":
    unittest.main()
