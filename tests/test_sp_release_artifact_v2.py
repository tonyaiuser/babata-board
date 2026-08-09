import base64
import dataclasses
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import select
import stat
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock


def _tool(name):
    path = Path(__file__).resolve().parents[1] / "tools" / name
    spec = importlib.util.spec_from_file_location("_" + name.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


artifact = _tool("sp_release_artifact_v2.py")
FIXTURE = Path(__file__).parent / "fixtures" / "gh_attestation_verify_v2.json"
CALLER_COMMIT = "a" * 40
SIGNER_COMMIT = "b" * 40
CANDIDATE_COMMIT = "c" * 40
CANDIDATE_TREE = "d" * 40
WORKFLOW_BYTES = b"name: Trusted reverse producer v2\n"
TRUSTED_ROOT = b'{"trusted_root":"pre-fetched-out-of-band"}\n'


def _git_blob_oid(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _producer_json(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode()


SIGNER_BLOB = _git_blob_oid(WORKFLOW_BYTES)


POLICY_DOCUMENT = {
    "archive": dict(artifact.ARCHIVE_CONTRACT),
    "inventory": dict(artifact.INVENTORY_CONTRACT),
    "limits": {"max_entries": 4096, "max_file_bytes": 67108864, "max_path_bytes": 240,
               "max_payload_bytes": 268435456},
    "paths": {
        "allowed_files": ["scripts/report_delivery_adapters_v1.py", "scripts/report_delivery_outbox_v1.py"],
        "allowed_prefixes": ["single-page-monitor/"],
        "required_files": ["scripts/report_delivery_adapters_v1.py", "scripts/report_delivery_outbox_v1.py"],
        "required_prefixes": ["single-page-monitor/"],
    },
    "schema": artifact.POLICY_SCHEMA,
    "version": 1,
}
TRUSTED_POLICY = (json.dumps(POLICY_DOCUMENT, indent=2) + "\n").encode()
GOLDEN_POLICY_SHA256 = "cba580d3683481b17db1541fe44315aec24d61fbb0804823058181231ce3b9d6"
POLICY_BLOB = _git_blob_oid(TRUSTED_POLICY)
GOLDEN_TAR_SHA256 = "bd6fae6e6a68e1be5dbd78e3a88cf6ab9ebff404c7dc5b096068690714b7729d"
GOLDEN_R1_RECEIPT_SHA256 = "097cbf8d6010e04525d8b7ef046a8a65f1c905eb853a957805f81893adb73638"
GOLDEN_LONG_PATH_TAR_SHA256 = "6011ab3172d0704b2f026e7f2f50ccc62f960a1c9965979ff5af00ed38f482e5"


def _canonical_tar(entries=None):
    if entries is None:
        entries = [("scripts/report_delivery_adapters_v1.py", b"adapter"),
                   ("scripts/report_delivery_outbox_v1.py", b"outbox"),
                   ("single-page-monitor/file.txt", b"payload")]
    return _raw_ustar(sorted(entries, key=lambda item: item[0].encode("utf-8")))


def _zip(payload, receipt):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("canonical-reverse.tar", payload)
        archive.writestr("canonical-reverse-receipt.json", receipt)
    return stream.getvalue()


def _authority(run=1, artifact_id=9, job_id=201, **changes):
    value = dict(
        candidate_repository_id=101,
        candidate_repository="owner/repo",
        candidate_commit=CANDIDATE_COMMIT,
        candidate_tree=CANDIDATE_TREE,
        candidate_ref="refs/heads/candidate",
        candidate_input_tree_sha256="0" * 64,
        caller_repository_id=101,
        caller_repository="owner/repo",
        caller_commit=CALLER_COMMIT,
        caller_ref="refs/heads/main",
        caller_workflow_id=88,
        caller_workflow_path=".github/workflows/trusted-reverse-dispatch-v2.yml",
        signer_repository_id=202,
        signer_repository="owner/signer",
        signer_workflow_path=".github/workflows/trusted-reverse-producer-v2.yml",
        signer_ref="refs/heads/main",
        signer_commit=SIGNER_COMMIT,
        signer_blob=SIGNER_BLOB,
        signer_workflow_sha256=hashlib.sha256(WORKFLOW_BYTES).hexdigest(),
        policy_path=".github/reverse_producer_v2/policy.json",
        policy_blob=POLICY_BLOB,
        policy_sha256=hashlib.sha256(TRUSTED_POLICY).hexdigest(),
        trusted_root_sha256=hashlib.sha256(TRUSTED_ROOT).hexdigest(),
        runner_label="macos-14",
        runner_os="macOS",
        runner_image="macos-14-14.7.1",
        run_id=run,
        run_attempt=1,
        artifact_id=artifact_id,
        artifact_name="canonical-reverse-%d-1" % run,
        job_id=job_id,
        job_name="invoke / finalize-without-candidate",
        receipt_artifact_name="raw-reverse-%d-1" % run,
    )
    value.update(changes)
    return artifact.ExpectedAuthority(**value)


def _receipt(payload, authority, raw_tag=b"raw"):
    files = artifact.parse_canonical_ustar(payload, POLICY_DOCUMENT)
    inventory = artifact._inventory_sha256(files)
    authority = dataclasses.replace(authority, candidate_input_tree_sha256=inventory)
    document = {
        "canonical": {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
        "canonicalization": dict(artifact.ARCHIVE_CONTRACT),
        "candidate_inventory": {"bytes": sum(map(len, files.values())), "commit": authority.candidate_commit,
                                "entries": len(files), "format": artifact.INVENTORY_CONTRACT["format"],
                                "sha256": inventory, "tree": authority.candidate_tree},
        "payload": {"bytes": sum(map(len, files.values())), "entries": len(files),
                    "input_tree_sha256": inventory, "sha256": inventory},
        "provenance": {
            "schema": "spspy.trusted-reverse-producer-v2.binding",
            "source": {"id": str(authority.caller_repository_id), "repository": authority.caller_repository,
                       "commit": authority.caller_commit, "ref": authority.caller_ref},
            "candidate": {"commit": authority.candidate_commit, "ref": authority.candidate_ref, "tree": authority.candidate_tree},
            "signer": {"repository": authority.signer_repository, "workflow_path": authority.signer_workflow_path,
                       "workflow_ref": authority.signer_workflow_identity, "commit": authority.signer_commit,
                       "blob": authority.signer_blob},
            "run": {"id": str(authority.run_id), "attempt": str(authority.run_attempt),
                    "finalize_job": artifact.FINALIZE_JOB, "prepare_result": "success"},
            "artifact": {"name": authority.receipt_artifact_name},
            "runner": {"os": authority.runner_os, "image": authority.runner_image},
            "tools": {"python": "Python 3.9.6", "tar": "bsdtar 3.5.3"},
            "cache": {"shared": False, "enabled": False},
            "test_matrix": {"prepare_result": "success", "runner": authority.runner_label},
        },
        "raw": {"bytes": len(raw_tag), "sha256": hashlib.sha256(raw_tag).hexdigest()},
        "release_policy": {"blob": POLICY_DOCUMENT, "sha256": hashlib.sha256(TRUSTED_POLICY).hexdigest()},
        "schema": artifact.RECEIPT_SCHEMA,
        "source_receipt": {"bytes": 3, "sha256": hashlib.sha256(b"src").hexdigest()},
        "version": 1,
    }
    return _producer_json(document), authority


class FakeGitHub(artifact.GitHubAdapter):
    def __init__(self, authority, transport, *, mutations=None):
        self.authority = authority
        self.transport = transport
        self.mutations = mutations or {}
        self.job_queries = []

    def repository_metadata(self, *, repository):
        ids = {self.authority.caller_repository: self.authority.caller_repository_id,
               self.authority.candidate_repository: self.authority.candidate_repository_id,
               self.authority.signer_repository: self.authority.signer_repository_id}
        value = {"id": ids[repository], "full_name": repository}
        value.update(self.mutations.get("repository", {}))
        return value

    def artifact_metadata(self, *, repository, artifact_id):
        branch = self.authority.caller_ref.removeprefix("refs/heads/")
        value = {"id": self.authority.artifact_id, "name": self.authority.artifact_name,
                 "size_in_bytes": len(self.transport), "expired": False,
                 "digest": "sha256:" + hashlib.sha256(self.transport).hexdigest(),
                 "workflow_run": {"id": self.authority.run_id, "repository_id": self.authority.caller_repository_id,
                                  "head_repository_id": self.authority.candidate_repository_id,
                                  "head_branch": branch, "head_sha": self.authority.caller_commit}}
        for key, item in self.mutations.get("artifact", {}).items():
            if key == "workflow_run": value[key].update(item)
            else: value[key] = item
        return value

    def download_artifact(self, *, repository, artifact_id):
        return self.transport

    def workflow_run(self, *, repository, run_id):
        branch = self.authority.caller_ref.removeprefix("refs/heads/")
        value = {"id": self.authority.run_id, "run_attempt": self.authority.run_attempt,
                 "head_sha": self.authority.caller_commit, "head_branch": branch, "event": "workflow_dispatch",
                 "status": "completed", "conclusion": "success", "workflow_id": self.authority.caller_workflow_id,
                 "path": self.authority.caller_workflow_path,
                 "repository": {"id": self.authority.caller_repository_id, "full_name": self.authority.caller_repository},
                 "head_repository": {"id": self.authority.candidate_repository_id, "full_name": self.authority.candidate_repository}}
        value.update(self.mutations.get("run", {}))
        return value

    def jobs_for_run_attempt(self, *, repository, run_id, run_attempt):
        self.job_queries.append((repository, run_id, run_attempt))
        branch = self.authority.caller_ref.removeprefix("refs/heads/")
        value = {"id": self.authority.job_id, "name": self.authority.job_name, "run_id": self.authority.run_id,
                 "run_attempt": self.authority.run_attempt, "head_sha": self.authority.caller_commit,
                 "head_branch": branch, "status": "completed", "conclusion": "success",
                 "labels": [self.authority.runner_label, "arm64"], "runner_id": 9001,
                 "runner_name": "GitHub Actions 9001", "runner_group_name": "GitHub Actions"}
        value.update(self.mutations.get("job", {}))
        return [value]

    def git_blob(self, *, repository, commit, path):
        if path == self.authority.signer_workflow_path:
            return {"oid": self.authority.signer_blob, "bytes": WORKFLOW_BYTES}
        if path == self.authority.policy_path:
            return {"oid": self.authority.policy_blob, "bytes": TRUSTED_POLICY}
        raise AssertionError(path)


def _fixture_for(authority, subject_path):
    fixture = json.loads(FIXTURE.read_text())
    result = fixture[0]["verificationResult"]
    certificate = result["signature"]["certificate"]
    certificate.update({
        "subjectAlternativeName": authority.signer_uri,
        "sourceRepositoryURI": authority.caller_uri,
        "sourceRepositoryDigest": authority.caller_commit,
        "sourceRepositoryRef": authority.caller_ref,
        "sourceRepositoryIdentifier": str(authority.caller_repository_id),
        "buildSignerURI": authority.signer_uri,
        "buildSignerDigest": authority.signer_commit,
        "buildConfigURI": authority.caller_workflow_uri,
        "buildConfigDigest": authority.caller_commit,
        "githubWorkflowSHA": authority.caller_commit,
        "githubWorkflowRepository": authority.caller_repository,
        "githubWorkflowRef": authority.caller_ref,
        "runInvocationURI": authority.invocation_uri,
    })
    statement = result["statement"]
    statement["subject"] = [{"name": subject_path.name, "digest": {"sha256": hashlib.sha256(subject_path.read_bytes()).hexdigest()}}]
    workflow = statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
    workflow.update({"ref": authority.caller_ref, "repository": authority.caller_uri, "path": "/" + authority.caller_workflow_path})
    dependencies = statement["predicate"]["buildDefinition"]["resolvedDependencies"]
    dependencies[0] = {"uri": "git+https://github.com/%s@%s" % (authority.caller_repository, authority.caller_ref),
                       "digest": {"gitCommit": authority.caller_commit}}
    statement["predicate"]["buildDefinition"]["internalParameters"]["github"]["repository_id"] = str(
        authority.caller_repository_id)
    statement["predicate"]["runDetails"]["metadata"]["invocationId"] = authority.invocation_uri
    return json.dumps(fixture, sort_keys=True).encode()


def _gh_runner(authorities, calls, download_authority=None, certificate_authorities=None):
    by_run = {authority.run_id: authority for authority in authorities}
    certificate_authorities = certificate_authorities or by_run
    def runner(argv, *, cwd, timeout_seconds):
        calls.append((list(argv), cwd, timeout_seconds))
        if argv[2] == "download":
            if download_authority is None:
                raise AssertionError("offline runner must not download")
            subject = Path(argv[3]).read_bytes()
            marker = {"bundle": "schema-fixture", "run_id": download_authority.run_id}
            (Path(cwd) / ("sha256:%s.jsonl" % hashlib.sha256(subject).hexdigest())).write_bytes(
                (json.dumps(marker, sort_keys=True) + "\n").encode())
            return 0, b"bundle written to cwd\n", b""
        bundle_index = argv.index("--bundle") + 1
        marker = json.loads(Path(argv[bundle_index]).read_text().splitlines()[0])
        expected = by_run[marker["run_id"]]
        signed = certificate_authorities[marker["run_id"]]
        # argv flags must be driven by the expected external authority.
        assert argv[0] == artifact.GH_EXECUTABLE
        assert argv[argv.index("-R") + 1] == expected.caller_repository
        identity_group = ("--cert-identity", "--signer-repo", "--signer-workflow")
        assert sum(argv.count(flag) for flag in identity_group) == 1
        assert argv.count("--cert-identity") == 1
        assert argv[argv.index("--source-digest") + 1] == expected.caller_commit
        assert argv[argv.index("--signer-digest") + 1] == expected.signer_commit
        assert argv[argv.index("--source-ref") + 1] == expected.caller_ref
        assert argv[argv.index("--cert-identity") + 1] == expected.signer_uri
        return 0, _fixture_for(signed, Path(argv[3])), b""
    return runner


def _online(authority, payload, receipt, calls):
    transport = _zip(payload, receipt)
    return artifact.verify_artifact(adapter=FakeGitHub(authority, transport), authority=authority,
                                    trusted_root_bytes=TRUSTED_ROOT, trusted_policy_bytes=TRUSTED_POLICY,
                                    gh_runner=_gh_runner([authority], calls, download_authority=authority))


class ArtifactProtocolTests(unittest.TestCase):
    def setUp(self):
        self.payload = _canonical_tar()
        files = artifact.parse_canonical_ustar(self.payload, POLICY_DOCUMENT)
        self.inventory = artifact._inventory_sha256(files)
        self.r1 = dataclasses.replace(_authority(1, 9, 201), candidate_input_tree_sha256=self.inventory)
        self.r2 = dataclasses.replace(_authority(2, 10, 202), candidate_input_tree_sha256=self.inventory)
        self.receipt1, self.r1 = _receipt(self.payload, self.r1, b"raw-one")
        self.receipt2, self.r2 = _receipt(self.payload, self.r2, b"raw-two")

    def _sealed(self):
        calls = []
        one = _online(self.r1, self.payload, self.receipt1, calls)
        two = _online(self.r2, self.payload, self.receipt2, calls)
        self.assertEqual([item[0][2] for item in calls], ["download", "verify", "download", "verify"] * 2)
        return artifact.seal_receipt_pair(one, two)[0]

    def test_producer_golden_pair_online_offline_activation_and_transactional_cas(self):
        self.assertEqual(hashlib.sha256(TRUSTED_POLICY).hexdigest(), GOLDEN_POLICY_SHA256)
        self.assertEqual(_git_blob_oid(TRUSTED_POLICY), POLICY_BLOB)
        self.assertEqual(hashlib.sha256(self.payload).hexdigest(), GOLDEN_TAR_SHA256)
        self.assertEqual(hashlib.sha256(self.receipt1).hexdigest(), GOLDEN_R1_RECEIPT_SHA256)
        self.assertEqual(self.receipt1, _producer_json(json.loads(self.receipt1)))
        envelope = self._sealed()
        calls = []
        offline_runner = _gh_runner([self.r1, self.r2], calls)
        proof = artifact.reverify_for_activation(envelope_bytes=envelope, payload=self.payload,
                                                 trusted_root_bytes=TRUSTED_ROOT, trusted_policy_bytes=TRUSTED_POLICY,
                                                 r1_authority=self.r1, r2_authority=self.r2, gh_runner=offline_runner)
        self.assertIsInstance(proof, artifact.ActivationReverifyResult)
        self.assertEqual(proof.payload_digest, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(proof.trusted_root_digest, hashlib.sha256(TRUSTED_ROOT).hexdigest())
        self.assertEqual(len(calls), 4)
        with self.assertRaises(artifact.ArtifactError):
            artifact.ActivationReverifyResult(None, authority_digest="0" * 64, envelope_digest="0" * 64,
                                              payload_digest="0" * 64, trusted_root_digest="0" * 64)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            cas_calls = []
            with artifact.RepositoryCAS(directory) as cas:
                digest = cas.store_release(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                           trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1, r2_authority=self.r2,
                                           gh_runner=_gh_runner([self.r1, self.r2], cas_calls))
                again = cas.store_release(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                          trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1, r2_authority=self.r2,
                                          gh_runner=_gh_runner([self.r1, self.r2], cas_calls))
            self.assertEqual(digest, again)
            release = Path(directory) / "releases" / digest
            self.assertTrue((release / "commit.json").is_file())
            self.assertEqual(list((Path(directory) / ".transactions").iterdir()), [])
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1
                                for path in release.iterdir()))

    def test_external_authority_rejects_legitimate_repo_or_signer_replay(self):
        envelope = self._sealed()
        alternate = dataclasses.replace(self.r1, signer_repository_id=303, signer_repository="other/signer",
                                        signer_commit="7" * 40, signer_blob="8" * 40,
                                        signer_workflow_sha256="9" * 64)
        calls = []
        runner = _gh_runner([alternate, self.r2], calls, certificate_authorities={alternate.run_id: self.r1, self.r2.run_id: self.r2})
        with self.assertRaises(artifact.ArtifactError):
            artifact.offline_verify_to_seal(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                             trusted_policy_bytes=TRUSTED_POLICY, r1_authority=alternate,
                                             r2_authority=self.r2, gh_runner=runner)
        other_caller = dataclasses.replace(self.r1, caller_repository_id=404, candidate_repository_id=404,
                                           caller_repository="other/repo", candidate_repository="other/repo")
        with self.assertRaises(artifact.ArtifactError):
            artifact.offline_verify_to_seal(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                             trusted_policy_bytes=TRUSTED_POLICY, r1_authority=other_caller,
                                             r2_authority=self.r2, gh_runner=_gh_runner([other_caller, self.r2], [],
                                             certificate_authorities={other_caller.run_id: self.r1, self.r2.run_id: self.r2}))
        with tempfile.TemporaryDirectory() as directory:
            subject = Path(directory) / "canonical-reverse.tar"
            subject.write_bytes(self.payload)
            signed_by_original = _fixture_for(self.r1, subject)
            with self.assertRaises(artifact.ArtifactError):
                artifact._parse_gh_output(signed_by_original, alternate, subject.name,
                                          hashlib.sha256(self.payload).hexdigest())
        same_run = dataclasses.replace(self.r2, run_id=self.r1.run_id,
                                       artifact_name=self.r1.artifact_name,
                                       receipt_artifact_name=self.r1.receipt_artifact_name)
        with self.assertRaises(artifact.ArtifactError):
            artifact.offline_verify_to_seal(envelope_bytes=envelope, payload=self.payload,
                                             trusted_root_bytes=TRUSTED_ROOT, trusted_policy_bytes=TRUSTED_POLICY,
                                             r1_authority=self.r1, r2_authority=same_run,
                                             gh_runner=_gh_runner([self.r1, same_run], []))

    def test_attempt_specific_rest_and_artifact_linkage_fail_closed(self):
        for area, changes in (("artifact", {"workflow_run": {"repository_id": 999}}),
                              ("artifact", {"workflow_run": {"head_repository_id": 999}}),
                              ("artifact", {"workflow_run": {"head_sha": "0" * 40}}),
                              ("run", {"run_attempt": 2}), ("run", {"head_branch": "other"}),
                              ("job", {"run_attempt": 2}), ("job", {"head_sha": "0" * 40}),
                              ("job", {"runner_group_name": "self-hosted"})):
            with self.subTest(area=area, changes=changes):
                transport = _zip(self.payload, self.receipt1)
                with self.assertRaises(artifact.ArtifactError):
                    artifact.verify_artifact(adapter=FakeGitHub(self.r1, transport, mutations={area: changes}),
                                             authority=self.r1, trusted_root_bytes=TRUSTED_ROOT,
                                             trusted_policy_bytes=TRUSTED_POLICY,
                                             gh_runner=_gh_runner([self.r1], [], download_authority=self.r1))
        transport = _zip(self.payload, self.receipt1)
        adapter = FakeGitHub(self.r1, transport)
        artifact.verify_artifact(adapter=adapter, authority=self.r1, trusted_root_bytes=TRUSTED_ROOT,
                                 trusted_policy_bytes=TRUSTED_POLICY,
                                 gh_runner=_gh_runner([self.r1], [], download_authority=self.r1))
        self.assertEqual(adapter.job_queries,
                         [(self.r1.caller_repository, self.r1.run_id, self.r1.run_attempt)])

    def test_receipt_policy_root_and_envelope_tamper_fail_before_cas_write(self):
        envelope = self._sealed()
        value = json.loads(envelope)
        value["payload_sha256"] = "0" * 64
        forged = artifact._canonical(value)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            with artifact.RepositoryCAS(directory) as cas:
                with self.assertRaises(artifact.ArtifactError):
                    cas.store_release(envelope_bytes=forged, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                      trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1, r2_authority=self.r2,
                                      gh_runner=_gh_runner([self.r1, self.r2], []))
            self.assertEqual(os.listdir(directory), [])
        with self.assertRaises(artifact.ArtifactError):
            artifact.offline_verify_to_seal(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=b'{"other":true}\n',
                                             trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1,
                                             r2_authority=self.r2, gh_runner=_gh_runner([self.r1, self.r2], []))
        changed_policy = TRUSTED_POLICY + b" "
        with self.assertRaises(artifact.ArtifactError):
            artifact.offline_verify_to_seal(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                             trusted_policy_bytes=changed_policy, r1_authority=self.r1,
                                             r2_authority=self.r2, gh_runner=_gh_runner([self.r1, self.r2], []))
        rest_tamper = json.loads(envelope)
        rest_tamper["r1"]["rest"]["artifact"]["workflow_run"]["repository_id"] = 999
        with self.assertRaises(artifact.ArtifactError):
            artifact.offline_verify_to_seal(envelope_bytes=artifact._canonical(rest_tamper), payload=self.payload,
                                             trusted_root_bytes=TRUSTED_ROOT, trusted_policy_bytes=TRUSTED_POLICY,
                                             r1_authority=self.r1, r2_authority=self.r2,
                                             gh_runner=_gh_runner([self.r1, self.r2], []))
        noncanonical_receipt = b" " + self.receipt1
        with self.assertRaises(artifact.ArtifactError):
            artifact.verify_artifact(adapter=FakeGitHub(self.r1, _zip(self.payload, noncanonical_receipt)),
                                     authority=self.r1, trusted_root_bytes=TRUSTED_ROOT,
                                     trusted_policy_bytes=TRUSTED_POLICY,
                                     gh_runner=_gh_runner([self.r1], [], download_authority=self.r1))
        wrong_policy_blob = dataclasses.replace(self.r1, policy_blob="0" * 40)
        with self.assertRaises(artifact.ArtifactError):
            artifact.verify_artifact(adapter=FakeGitHub(wrong_policy_blob, _zip(self.payload, self.receipt1)),
                                     authority=wrong_policy_blob, trusted_root_bytes=TRUSTED_ROOT,
                                     trusted_policy_bytes=TRUSTED_POLICY,
                                     gh_runner=_gh_runner([wrong_policy_blob], [], download_authority=wrong_policy_blob))

    def test_hostile_ustar_matrix_rejects_nul_type_control_ancestor_and_tail(self):
        valid = bytearray(_canonical_tar([("a", b"x")]))
        cases = []
        nul_type = bytearray(valid); nul_type[156] = 0; _rewrite_checksum(nul_type); cases.append(bytes(nul_type))
        control = bytearray(valid); control[0:2] = b"x\n"; _rewrite_checksum(control); cases.append(bytes(control))
        noncanonical_mode = bytearray(valid); noncanonical_mode[100:108] = b"000600\0\0"; _rewrite_checksum(noncanonical_mode); cases.append(bytes(noncanonical_mode))
        cases.append(bytes(valid) + b"\0" * 512)
        cases.append(_raw_ustar([("a", b"x"), ("a/b", b"y")]))
        for raw in cases:
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(artifact.ArtifactError):
                    artifact.parse_canonical_ustar(raw)

    def test_producer_first_feasible_ustar_split_is_the_only_long_path_encoding(self):
        path = "p" * 10 + "/" + "q" * 10 + "/" + "r" * 89
        self.assertEqual(len(path.encode("ascii")), 111)
        golden = _canonical_tar([(path, b"x")])
        self.assertEqual(hashlib.sha256(golden).hexdigest(), GOLDEN_LONG_PATH_TAR_SHA256)
        self.assertEqual(golden[:100].split(b"\0", 1)[0], ("q" * 10 + "/" + "r" * 89).encode())
        self.assertEqual(golden[345:500].split(b"\0", 1)[0], b"p" * 10)
        self.assertEqual(artifact.parse_canonical_ustar(golden), {path: b"x"})
        last_feasible = bytearray(golden)
        last_feasible[:100] = b"\0" * 100
        last_feasible[345:500] = b"\0" * 155
        last_feasible[:89] = b"r" * 89
        last_feasible[345:366] = ("p" * 10 + "/" + "q" * 10).encode()
        _rewrite_checksum(last_feasible)
        with self.assertRaises(artifact.ArtifactError):
            artifact.parse_canonical_ustar(bytes(last_feasible))
        full_prefix_path = "p" * 155 + "/n"
        full_prefix = _canonical_tar([(full_prefix_path, b"x")])
        self.assertEqual(full_prefix[345:500], b"p" * 155)
        self.assertEqual(artifact.parse_canonical_ustar(full_prefix), {full_prefix_path: b"x"})
        with self.assertRaises(artifact.ArtifactError):
            artifact._nul_ascii(b"n" * 99, "name", width=100)
        with self.assertRaises(artifact.ArtifactError):
            artifact._nul_ascii(b"p" * 154, "prefix", width=155, allow_empty=True)

    def test_production_gh_path_version_hash_and_cross_invocation_identity_are_pinned(self):
        identity = (1, 2, 3, 4, 5, 0o555, os.getuid(), 1, artifact.GH_EXECUTABLE_SHA256)
        argv = [artifact.GH_EXECUTABLE, "attestation", "verify", "subject"]
        with self.assertRaises(artifact.ArtifactError):
            artifact._production_gh(["/opt/homebrew/bin/gh", "attestation", "verify", "subject"],
                                    cwd="/tmp", timeout_seconds=5)
        with mock.patch.object(artifact, "_hash_regular_executable", return_value=identity[:-1] + ("0" * 64,)):
            with self.assertRaises(artifact.ArtifactError):
                artifact._production_gh(argv, cwd="/tmp", timeout_seconds=5)
        with mock.patch.object(artifact, "_hash_regular_executable", return_value=identity), \
                mock.patch.object(artifact, "_bounded_subprocess", return_value=(0, b"gh version 9.9.9\n", b"")):
            with self.assertRaises(artifact.ArtifactError):
                artifact._production_gh(argv, cwd="/tmp", timeout_seconds=5)
        changed = identity[:1] + (99,) + identity[2:]
        with mock.patch.object(artifact, "_hash_regular_executable", side_effect=[identity, changed]), \
                mock.patch.object(artifact, "_bounded_subprocess",
                                  side_effect=[(0, (artifact.GH_VERSION + "\n").encode(), b""), (0, b"[]", b"")]):
            with self.assertRaises(artifact.ArtifactError):
                artifact._production_gh(argv, cwd="/tmp", timeout_seconds=5)

    def test_pinned_gh_accepts_verification_flags_before_reading_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            subject = Path(directory) / "canonical-reverse.tar"
            subject.write_bytes(b"subject")
            bundle = Path(directory) / "bundle.unsupported"
            bundle.write_text("{}\n", encoding="utf-8")
            root = Path(directory) / "trusted-root.jsonl"
            root.write_text("{}\n", encoding="utf-8")
            argv = artifact._verification_argv(subject_path=str(subject), bundle_path=str(bundle),
                                                root_path=str(root), authority=self.r1)
            selectors = [flag for flag in ("--cert-identity", "--signer-repo", "--signer-workflow")
                         if flag in argv]
            self.assertEqual(selectors, ["--cert-identity"])
            self.assertEqual(argv.count("--cert-identity"), 1)
            code, _stdout, stderr = artifact._production_gh(argv, cwd=directory, timeout_seconds=10)
            error = stderr.decode("utf-8", "replace").lower()
            self.assertNotEqual(code, 0)
            # Cobra accepted the complete production flag set and advanced to
            # parsing the deliberately invalid trust evidence.
            self.assertIn("unsupported trustedroot media type", error)
            self.assertNotIn("mutually exclusive", error)
            self.assertNotIn("cannot be used with", error)

    def test_cas_lock_contention_has_bounded_cross_process_deadline(self):
        envelope = self._sealed()
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            process = os.fork()
            if process == 0:
                os.close(ready_read)
                os.close(release_write)
                exit_code = 1
                try:
                    with artifact.RepositoryCAS(directory) as holder:
                        fcntl.flock(holder.root, fcntl.LOCK_EX)
                        os.write(ready_write, b"R")
                        if os.read(release_read, 1) != b"X":
                            raise RuntimeError("release pipe closed")
                        fcntl.flock(holder.root, fcntl.LOCK_UN)
                    exit_code = 0
                finally:
                    os.close(ready_write)
                    os.close(release_read)
                    os._exit(exit_code)

            os.close(ready_write)
            os.close(release_read)
            original_timeout = artifact.CAS_LOCK_TIMEOUT_SECONDS
            released = waited = False
            child_status = None
            try:
                readable, _, _ = select.select([ready_read], [], [], 5)
                self.assertEqual(readable, [ready_read])
                self.assertEqual(os.read(ready_read, 1), b"R")
                artifact.CAS_LOCK_TIMEOUT_SECONDS = 0.2
                with artifact.RepositoryCAS(directory) as contender:
                    before = set(os.listdir(directory))
                    started = time.monotonic()
                    with self.assertRaisesRegex(artifact.ArtifactError, "busy after bounded wait"):
                        contender.store_release(envelope_bytes=envelope, payload=self.payload,
                                                trusted_root_bytes=TRUSTED_ROOT,
                                                trusted_policy_bytes=TRUSTED_POLICY,
                                                r1_authority=self.r1, r2_authority=self.r2,
                                                gh_runner=_gh_runner([self.r1, self.r2], []))
                    self.assertLess(time.monotonic() - started, 1)
                    self.assertEqual(set(os.listdir(directory)), before)
                    os.write(release_write, b"X")
                    released = True
                    _, child_status = os.waitpid(process, 0)
                    waited = True
                    digest = contender.store_release(envelope_bytes=envelope, payload=self.payload,
                                                       trusted_root_bytes=TRUSTED_ROOT,
                                                       trusted_policy_bytes=TRUSTED_POLICY,
                                                       r1_authority=self.r1, r2_authority=self.r2,
                                                       gh_runner=_gh_runner([self.r1, self.r2], []))
                    self.assertTrue((Path(directory) / "releases" / digest / "commit.json").is_file())
            finally:
                artifact.CAS_LOCK_TIMEOUT_SECONDS = original_timeout
                if not released:
                    try:
                        os.write(release_write, b"X")
                    except OSError:
                        pass
                if not waited:
                    _, child_status = os.waitpid(process, 0)
                os.close(ready_read)
                os.close(release_write)
            self.assertTrue(os.WIFEXITED(child_status))
            self.assertEqual(os.WEXITSTATUS(child_status), 0)

    def test_cas_recovers_uncommitted_transaction_and_rejects_hardlink_alias(self):
        envelope = self._sealed()
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            with artifact.RepositoryCAS(directory) as cas:
                with mock.patch.object(artifact.RepositoryCAS, "_write_file", side_effect=RuntimeError("simulated crash")):
                    with self.assertRaises(RuntimeError):
                        cas.store_release(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                          trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1, r2_authority=self.r2,
                                          gh_runner=_gh_runner([self.r1, self.r2], []))
                self.assertTrue(any((Path(directory) / ".transactions").iterdir()))
                # First recovery removes the incomplete transaction; a second
                # simulated crash occurs only after all files and commit marker
                # are durable, immediately before atomic publication.
                with mock.patch.object(artifact.os, "rename", side_effect=RuntimeError("post-marker crash")):
                    with self.assertRaises(RuntimeError):
                        cas.store_release(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                          trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1,
                                          r2_authority=self.r2, gh_runner=_gh_runner([self.r1, self.r2], []))
                transaction = next((Path(directory) / ".transactions").iterdir())
                self.assertTrue((transaction / "commit.json").is_file())
                digest = cas.store_release(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                           trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1, r2_authority=self.r2,
                                           gh_runner=_gh_runner([self.r1, self.r2], []))
                self.assertFalse(any((Path(directory) / ".transactions").iterdir()))
                os.link(Path(directory) / "releases" / digest / "payload.tar", Path(directory) / "alias")
                with self.assertRaises(artifact.ArtifactError):
                    cas.store_release(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                      trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1, r2_authority=self.r2,
                                      gh_runner=_gh_runner([self.r1, self.r2], []))

    def test_cas_never_publishes_a_forged_durable_transaction(self):
        envelope = self._sealed()
        digest = hashlib.sha256(self.payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            transactions = root / ".transactions"; transactions.mkdir(mode=0o700)
            releases = root / "releases"; releases.mkdir(mode=0o700)
            transaction = transactions / ("txn-%s-%s" % (digest, "0" * 16)); transaction.mkdir(mode=0o700)
            forged_digests = {}
            for name in artifact.CAS_RELEASE_FILES:
                data = ("forged:" + name).encode()
                path = transaction / name
                path.write_bytes(data); os.chmod(path, 0o600)
                forged_digests[name] = hashlib.sha256(data).hexdigest()
            marker = artifact._canonical({"schema": artifact.CAS_COMMIT_SCHEMA, "payload_sha256": digest,
                                          "files": forged_digests})
            (transaction / "commit.json").write_bytes(marker); os.chmod(transaction / "commit.json", 0o600)
            with artifact.RepositoryCAS(root) as cas:
                with self.assertRaises(artifact.ArtifactError):
                    cas.store_release(envelope_bytes=envelope, payload=self.payload, trusted_root_bytes=TRUSTED_ROOT,
                                      trusted_policy_bytes=TRUSTED_POLICY, r1_authority=self.r1, r2_authority=self.r2,
                                      gh_runner=_gh_runner([self.r1, self.r2], []))
            self.assertEqual(list(releases.iterdir()), [])
            self.assertTrue(transaction.is_dir())


def _rewrite_checksum(raw):
    raw[148:156] = b" " * 8
    raw[148:156] = ("%06o" % sum(raw[:512])).encode("ascii") + b"\0 "


def _raw_ustar(entries):
    chunks = []
    for name, data in entries:
        encoded = name.encode("ascii")
        if len(encoded) <= 100:
            name_field, prefix = encoded, b""
        else:
            components = encoded.split(b"/")
            for index in range(1, len(components)):
                prefix = b"/".join(components[:index])
                name_field = b"/".join(components[index:])
                if len(prefix) <= 155 and len(name_field) <= 100:
                    break
            else:
                raise ValueError(name)
        header = bytearray(512)
        header[:len(name_field)] = name_field
        header[100:108] = b"0000600\0"
        header[108:116] = b"0000000\0"
        header[116:124] = b"0000000\0"
        header[124:136] = ("%011o" % len(data)).encode("ascii") + b"\0"
        header[136:148] = b"00000000000\0"
        header[156:157] = b"0"
        header[257:263] = b"ustar\0"
        header[263:265] = b"00"
        header[345:345 + len(prefix)] = prefix
        _rewrite_checksum(header)
        chunks.extend((bytes(header), data, b"\0" * ((-len(data)) % 512)))
    return b"".join(chunks) + b"\0" * 1024


if __name__ == "__main__":
    unittest.main()
