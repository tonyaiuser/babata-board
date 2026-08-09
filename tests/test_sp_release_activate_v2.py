import dataclasses
import fcntl
import hashlib
import importlib
import importlib.util
import json
import os
import select
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Protocol-v3 is deliberately fixed-width and little-endian.  Keep these
# offsets in the Python boundary tests as independently maintained witnesses;
# do not import a serializer from the implementation under test.
V3_MAGIC = 0x53505232
V3_VERSION = 3
ZERO_DIGEST = b"\0" * 32
STATE_SIZE = 416
MARKER_SIZE = 352
READY_SIZE = 500
GO_SIZE = 252
RESULT_SIZE = 260
STATE_OFFSETS = {
    "magic": 0, "version": 4, "phase": 8, "prior_present": 12,
    "recovery_from_phase": 16, "reserved": 20, "epoch": 24,
    "activation_pid": 32, "rollback_pid": 36, "nonce": 56,
    "payload_digest": 88, "previous_digest": 120, "authority_digest": 152,
    "trusted_root_digest": 184, "envelope_digest": 216, "helper_digest": 248,
    "profile_digest": 280, "activation_lease": 312, "rollback_lease": 364,
}
MARKER_OFFSETS = {
    "magic": 0, "version": 4, "prior_present": 8, "reserved": 12,
    "epoch": 16, "nonce": 24, "payload_digest": 56, "previous_digest": 88,
    "authority_digest": 120, "trusted_root_digest": 152, "envelope_digest": 184,
    "helper_digest": 216, "activation_lease": 248, "rollback_lease": 300,
}


def _u32(raw, offset):
    return struct.unpack_from("<I", raw, offset)[0]


def _u64(raw, offset):
    return struct.unpack_from("<Q", raw, offset)[0]


def _put_u32(raw, offset, value):
    struct.pack_into("<I", raw, offset, value)


def _put_u64(raw, offset, value):
    struct.pack_into("<Q", raw, offset, value)


def _tool(name):
    path = ROOT / "tools" / name
    spec = importlib.util.spec_from_file_location("_" + name.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


activate = _tool("sp_release_activate_v2.py")


def _write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def _overwrite(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def _cas_payload(fixture, name, data):
    path = fixture.base / name
    _write(path, data)
    source_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        digest = fixture.store.put_fd(source_fd)
    finally:
        os.close(source_fd)
    return digest, fixture.store.open_cas(digest)


def _compile(directory, *definitions):
    target = Path(directory) / ("helper-" + str(len(list(Path(directory).glob("helper-*")))))
    command = [activate.NATIVE_CLANG, *activate.NATIVE_BUILD_FLAGS]
    command.extend("-D" + item for item in definitions)
    command.extend(["-o", os.fspath(target), os.fspath(ROOT / "native" / "sp_release_seatbelt_v2.c")])
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", "replace"))
    os.chmod(target, 0o700)
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        data, info = activate._read_regular_fd(fd, maximum=8 * 1024 * 1024, exact_mode=0o700)
    finally:
        os.close(fd)
    return activate._HelperRecord(path=os.fspath(target), digest=hashlib.sha256(data).hexdigest(),
                                  fingerprint=activate._fingerprint(info))


class NativeFixture:
    def __init__(self, directory, payload=b"payload-v1", previous=b"previous-v0"):
        self.base = Path(directory)
        self.root = self.base / "root"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.payload_path = self.base / "payload.bin"
        self.previous_path = self.base / "previous.bin"
        _write(self.payload_path, payload)
        _write(self.previous_path, previous)
        self.payload_input = os.open(self.payload_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        self.previous_input = os.open(self.previous_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        self.store = activate.DirFDStore(self.root)
        self.payload_digest = self.store.put_fd(self.payload_input)
        self.previous_digest = self.store.put_fd(self.previous_input)
        self.payload_fd = self.store.open_cas(self.payload_digest)
        self.previous_fd = self.store.open_cas(self.previous_digest)

    def close(self):
        os.close(self.payload_fd)
        os.close(self.previous_fd)
        self.store.close()
        os.close(self.payload_input)
        os.close(self.previous_input)

    def run(self, helper=None, *, epoch=1, nonce="1" * 64, payload_digest=None,
            previous_digest=None, authority=None, trusted_root=None, envelope=None,
            prior_present=False):
        if not prior_present:
            previous_fd = None
            previous_digest = activate.ZERO_SHA256
        else:
            previous_fd = self.previous_fd
        return activate._run_parent(
            root_fd=self.store.fd, payload_fd=self.payload_fd, previous_fd=previous_fd,
            epoch=epoch, nonce=nonce, payload_digest=payload_digest or self.payload_digest,
            previous_digest=previous_digest or self.previous_digest,
            authority_digest=authority or hashlib.sha256(b"authority").hexdigest(),
            trusted_root_digest=trusted_root or hashlib.sha256(b"trusted-root").hexdigest(),
            envelope_digest=envelope or hashlib.sha256(b"envelope").hexdigest(), helper_record=helper)


def _commit_prior_present(fixture, *, helper=None, candidate_name="payload-v2", candidate=b"payload-v2"):
    fixture.run(helper=helper, nonce="1" * 64, prior_present=False)
    digest, fd = _cas_payload(fixture, candidate_name, candidate)
    activate._run_parent(
        root_fd=fixture.store.fd, payload_fd=fd, previous_fd=fixture.payload_fd,
        epoch=2, nonce="2" * 64, payload_digest=digest,
        previous_digest=fixture.payload_digest,
        authority_digest=hashlib.sha256(b"authority-2").hexdigest(),
        trusted_root_digest=hashlib.sha256(b"root-2").hexdigest(),
        envelope_digest=hashlib.sha256(b"envelope-2").hexdigest(), helper_record=helper)
    return digest, fd


def _state(root):
    return (Path(root) / ".sp-release-v2.state").read_bytes()


def _phase(raw):
    return struct.unpack_from("<I", raw, 8)[0]


def _root_inventory(root):
    root = Path(root)
    entries = []
    for path in sorted(root.rglob("*"), key=lambda item: os.fspath(item.relative_to(root))):
        info = path.lstat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else None
        entries.append((os.fspath(path.relative_to(root)), info.st_mode, info.st_uid,
                        info.st_nlink, info.st_size, digest))
    return tuple(entries)


def _fd_count():
    return len(os.listdir("/dev/fd"))


def _activate_test(**kwargs):
    """Local dynamic entrypoint; production helper authority is intentionally absent."""
    return activate._activate_verified(helper_record=activate._helper(), **kwargs)


class ActivationTests(unittest.TestCase):
    def test_public_production_helper_is_sealed_before_root_open_and_never_falls_back(self):
        """This checkout deliberately has no sealed root-owned helper."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            payload = Path(directory) / "payload"
            _write(payload, b"payload")
            payload_fd = os.open(payload, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                before = _root_inventory(root)
                descriptors = _fd_count()
                calls = (
                    lambda: activate.inspect_reconciliation(root),
                    lambda: activate.recover_interrupted(root, "a" * 64),
                    lambda: activate.activate_verified(
                        root=root, envelope_bytes=b"envelope", canonical_tar_fd=payload_fd,
                        trusted_root_bytes=b"root", trusted_policy_bytes=b"policy",
                        r1_authority=object(), r2_authority=object(), epoch=1, nonce="b" * 64),
                )
                for call in calls:
                    with self.assertRaisesRegex(activate.ActivationError, "production helper authority is not sealed"):
                        call()
                    self.assertEqual(_root_inventory(root), before)
                    self.assertEqual(_fd_count(), descriptors)
            finally:
                os.close(payload_fd)

    def test_production_helper_source_contract_requires_root_owned_no_follow_authority_chain(self):
        source = (ROOT / "tools" / "sp_release_activate_v2.py").read_text(encoding="utf-8")
        for required in (
                'PRODUCTION_HELPER_PATH = "/Library/Application Support/SPSPY/libexec/',
                "PRODUCTION_HELPER_BINARY_SHA256 = None", "PRODUCTION_HELPER_CDHASH = None",
                "PRODUCTION_HELPER_ARCH = None", "exact_mode=0o555", "exact_uid=0",
                "O_NOFOLLOW", "st_nlink", "codesign", "CDHash", "lipo", "-archs",
                'execution="installed"', "root-owned production helper authority is not sealed"):
            self.assertIn(required, source)

    def test_v3_reconciliation_parser_classifies_phase8_only_with_canonical_fields(self):
        value = {
            "protocol": "SP_RELEASE_V3", "operation": "INSPECT",
            "classification": "RECOVERABLE_ROLLBACK_REQUIRED",
            "state_sha256": "a" * 64, "epoch": 9, "phase": 8,
            "recovery_from_phase": 4, "prior_present": False,
            "current": "PAYLOAD", "current_sha256": "b" * 64,
        }
        encoded = ("SP_RELEASE_V3_INSPECT " + json.dumps(value, separators=(",", ":")) + "\n").encode("ascii")
        self.assertEqual(
            activate._parse_reconciliation_line(encoded, prefix=b"SP_RELEASE_V3_INSPECT ", operation="INSPECT"),
            value)
        for field, replacement in (("phase", 9), ("recovery_from_phase", 8),
                                   ("prior_present", 0), ("current_sha256", activate.ZERO_SHA256)):
            with self.subTest(field=field):
                invalid = dict(value)
                invalid[field] = replacement
                wire = ("SP_RELEASE_V3_INSPECT " + json.dumps(invalid, separators=(",", ":")) + "\n").encode("ascii")
                with self.assertRaises(activate.ActivationError):
                    activate._parse_reconciliation_line(
                        wire, prefix=b"SP_RELEASE_V3_INSPECT ", operation="INSPECT")
        invalid = dict(value)
        invalid["recovery_from_phase"] = 5
        wire = ("SP_RELEASE_V3_INSPECT " + json.dumps(invalid, separators=(",", ":")) + "\n").encode("ascii")
        with self.assertRaises(activate.ActivationError):
            activate._parse_reconciliation_line(
                wire, prefix=b"SP_RELEASE_V3_INSPECT ", operation="INSPECT")

    def test_v3_reconciliation_parser_binds_operation_class_phase_and_current(self):
        def parse(operation, document):
            prefix = ("SP_RELEASE_V3_%s " % operation).encode("ascii")
            wire = prefix + json.dumps(document, separators=(",", ":")).encode("ascii") + b"\n"
            return activate._parse_reconciliation_line(wire, prefix=prefix, operation=operation)

        fresh = {
            "protocol": "SP_RELEASE_V3", "operation": "INSPECT", "classification": "FRESH",
            "state_sha256": activate.ZERO_SHA256, "epoch": 0, "phase": 0,
            "recovery_from_phase": 0, "prior_present": False,
            "current": "ABSENT", "current_sha256": activate.ZERO_SHA256,
        }
        self.assertEqual(parse("INSPECT", fresh), fresh)
        for classification in ("BUSY", "ACTIVE"):
            empty = dict(fresh)
            empty.update(classification=classification, current="UNKNOWN")
            self.assertEqual(parse("INSPECT", empty), empty)
        invalid = []
        wrong = dict(fresh); wrong["classification"] = "RECOVERED_COMMITTED"; invalid.append(("INSPECT", wrong))
        for classification in ("FRESH", "BUSY", "ACTIVE"):
            wrong = dict(fresh)
            wrong.update(classification=classification, phase=1, epoch=1,
                         state_sha256="a" * 64)
            invalid.append(("INSPECT", wrong))
        wrong = dict(fresh); wrong.update(classification="TERMINAL_COMMITTED", phase=6, epoch=1,
                                          state_sha256="a" * 64, current="PAYLOAD", current_sha256="b" * 64)
        invalid.append(("INSPECT", wrong))
        wrong = dict(fresh); wrong.update(classification="RECOVERABLE_COMMITTED", phase=7, epoch=1,
                                          state_sha256="a" * 64, recovery_from_phase=0,
                                          current="PAYLOAD", current_sha256="b" * 64)
        invalid.append(("INSPECT", wrong))
        recovered = dict(fresh)
        recovered.update(operation="RECOVER", classification="RECOVERED_COMMITTED", epoch=2, phase=5,
                         state_sha256="a" * 64, current="PAYLOAD", current_sha256="b" * 64)
        self.assertEqual(parse("RECOVER", recovered), recovered)
        wrong = dict(recovered); wrong["classification"] = "RECOVERED_ROLLED_BACK"; invalid.append(("RECOVER", wrong))
        wrong = dict(recovered); wrong["current"] = "PRIOR"; invalid.append(("RECOVER", wrong))
        for operation, document in invalid:
            with self.subTest(operation=operation, classification=document["classification"]):
                with self.assertRaises(activate.ActivationError):
                    parse(operation, document)

    def test_fresh_verified_activation_rejects_every_prior_before_reverify_or_cas(self):
        class NeverVerify:
            class ActivationReverifyResult:
                pass

            calls = 0

            @classmethod
            def reverify_for_activation(cls, **unused):
                cls.calls += 1
                raise AssertionError("fresh prior must be rejected before re-verification")

        original = activate._ARTIFACT_MODULE
        activate._ARTIFACT_MODULE = NeverVerify
        try:
            for previous in (b"one", b"different-prior", b"payload"):
                with self.subTest(previous=previous), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory) / "fresh-root"
                    root.mkdir(mode=0o700)
                    payload_path = Path(directory) / "payload"
                    previous_path = Path(directory) / "previous"
                    _write(payload_path, b"payload")
                    _write(previous_path, previous)
                    payload_fd = os.open(payload_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    previous_fd = os.open(previous_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    before = _root_inventory(root)
                    try:
                        with self.assertRaisesRegex(activate.ActivationError, "fresh activation root"):
                            _activate_test(
                                root=root, envelope_bytes=b"envelope", canonical_tar_fd=payload_fd,
                                trusted_root_bytes=b"root", trusted_policy_bytes=b"policy",
                                r1_authority=object(), r2_authority=object(), previous_fd=previous_fd,
                                epoch=1, nonce="a" * 64)
                    finally:
                        os.close(payload_fd)
                        os.close(previous_fd)
                    self.assertEqual(_root_inventory(root), before)
            self.assertEqual(NeverVerify.calls, 0)
        finally:
            activate._ARTIFACT_MODULE = original

    def test_v3_fresh_success_and_activation_failure_roll_back_to_absence(self):
        """No-prior transaction commits data, or restores true absence on failure."""
        with tempfile.TemporaryDirectory() as build_directory:
            failing = _compile(build_directory, "SP_TEST_OPERATION_FAILURE_AFTER_SELECT_ROLE=1")
            for helper, expected in ((None, "COMMITTED"), (failing, "ROLLED_BACK")):
                with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                    fixture = NativeFixture(directory)
                    try:
                        outcome = fixture.run(helper=helper, prior_present=False,
                                              nonce=("c" if helper is None else "d") * 64)
                        self.assertEqual(outcome["phase"], expected)
                        self.assertFalse(outcome["prior_present"])
                        current = fixture.root / "current.payload"
                        if expected == "COMMITTED":
                            self.assertEqual(current.read_bytes(), b"payload-v1")
                        else:
                            self.assertFalse(current.exists())
                        raw = _state(fixture.root)
                        self.assertEqual(len(raw), STATE_SIZE)
                        self.assertEqual(_u32(raw, STATE_OFFSETS["version"]), V3_VERSION)
                        self.assertEqual(_u32(raw, STATE_OFFSETS["prior_present"]), 0)
                        self.assertEqual(raw[STATE_OFFSETS["previous_digest"]:STATE_OFFSETS["previous_digest"] + 32], ZERO_DIGEST)
                    finally:
                        fixture.close()

    def test_v3_present_payload_equal_prior_is_rejected_without_state_or_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory, payload=b"same", previous=b"same")
            duplicate_fd = None
            try:
                # A present-prior transaction is meaningful only after a
                # different initial selection has committed.  The candidate
                # below deliberately duplicates that selected v1 predecessor.
                fixture.run(nonce="1" * 64, prior_present=False)
                duplicate = Path(directory) / "duplicate-v1"
                _write(duplicate, b"same")
                duplicate_input = os.open(duplicate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    duplicate_digest = fixture.store.put_fd(duplicate_input)
                finally:
                    os.close(duplicate_input)
                duplicate_fd = fixture.store.open_cas(duplicate_digest)
                before = _root_inventory(fixture.root)
                with self.assertRaises(activate.ActivationError):
                    activate._run_parent(
                        root_fd=fixture.store.fd, payload_fd=duplicate_fd, previous_fd=fixture.payload_fd,
                        epoch=2, nonce="e" * 64, payload_digest=duplicate_digest,
                        previous_digest=fixture.payload_digest,
                        authority_digest=hashlib.sha256(b"authority-2").hexdigest(),
                        trusted_root_digest=hashlib.sha256(b"root-2").hexdigest(),
                        envelope_digest=hashlib.sha256(b"envelope-2").hexdigest())
                self.assertEqual(_root_inventory(fixture.root), before)
            finally:
                if duplicate_fd is not None:
                    os.close(duplicate_fd)
                fixture.close()

    def test_v3_state_and_marker_canonical_fields_fail_closed_under_read_only_inspection(self):
        """Every durable v3 field is authoritative, including the absent form."""
        mutations = (
            ("state-prior-flag", ".sp-release-v2.state", STATE_OFFSETS["prior_present"], "u32", 2),
            ("state-recovery-origin", ".sp-release-v2.state", STATE_OFFSETS["recovery_from_phase"], "u32", 4),
            ("state-reserved", ".sp-release-v2.state", STATE_OFFSETS["reserved"], "u32", 1),
            ("state-version", ".sp-release-v2.state", STATE_OFFSETS["version"], "u32", 2),
            ("state-lease", ".sp-release-v2.state", STATE_OFFSETS["activation_lease"], "bytes", ZERO_DIGEST),
            ("state-authority-cross-binding", ".sp-release-v2.state", STATE_OFFSETS["authority_digest"],
             "bytes", b"\x11" * 32),
            ("state-helper-cross-binding", ".sp-release-v2.state", STATE_OFFSETS["helper_digest"],
             "bytes", b"\x12" * 32),
            ("marker-prior-flag", "marker", MARKER_OFFSETS["prior_present"], "u32", 2),
            ("marker-reserved", "marker", MARKER_OFFSETS["reserved"], "u32", 1),
            ("marker-version", "marker", MARKER_OFFSETS["version"], "u32", 2),
            ("marker-lease", "marker", MARKER_OFFSETS["rollback_lease"], "bytes", ZERO_DIGEST),
            ("marker-authority-cross-binding", "marker", MARKER_OFFSETS["authority_digest"],
             "bytes", b"\x13" * 32),
            ("marker-helper-cross-binding", "marker", MARKER_OFFSETS["helper_digest"],
             "bytes", b"\x14" * 32),
        )
        for label, selector, offset, kind, replacement in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                try:
                    fixture.run(nonce="b" * 64)
                    if selector == "marker":
                        path = fixture.root / (".sp-release-v2.nonce." + "b" * 64)
                    else:
                        path = fixture.root / selector
                    raw = bytearray(path.read_bytes())
                    self.assertEqual(len(raw), MARKER_SIZE if selector == "marker" else STATE_SIZE)
                    if kind == "u32":
                        _put_u32(raw, offset, replacement)
                    else:
                        raw[offset:offset + len(replacement)] = replacement
                    _overwrite(path, raw)
                    before = _root_inventory(fixture.root)
                    if label == "state-recovery-origin":
                        with self.assertRaises(activate.ActivationError):
                            activate._inspect_reconciliation(
                                fixture.root, helper_record=activate._helper())
                    else:
                        result = activate._inspect_reconciliation(
                            fixture.root, helper_record=activate._helper())
                        self.assertEqual(result["classification"], "BLOCKED")
                    self.assertEqual(_root_inventory(fixture.root), before)
                finally:
                    fixture.close()

        # Keep each edited record internally canonical while making its
        # prior-presence tuple disagree with the other durable witness.
        for selector in ("state", "marker"):
            with self.subTest(label=selector + "-prior-cross-binding"), tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                second_fd = None
                try:
                    fixture.run(nonce="1" * 64, prior_present=False)
                    second_digest, second_fd = _cas_payload(fixture, "payload-v2", b"payload-v2")
                    activate._run_parent(
                        root_fd=fixture.store.fd, payload_fd=second_fd, previous_fd=fixture.payload_fd,
                        epoch=2, nonce="2" * 64, payload_digest=second_digest,
                        previous_digest=fixture.payload_digest,
                        authority_digest=hashlib.sha256(b"authority-2").hexdigest(),
                        trusted_root_digest=hashlib.sha256(b"root-2").hexdigest(),
                        envelope_digest=hashlib.sha256(b"envelope-2").hexdigest())
                    path = (fixture.root / ".sp-release-v2.state" if selector == "state" else
                            fixture.root / (".sp-release-v2.nonce." + "2" * 64))
                    raw = bytearray(path.read_bytes())
                    offsets = STATE_OFFSETS if selector == "state" else MARKER_OFFSETS
                    _put_u32(raw, offsets["prior_present"], 0)
                    raw[offsets["previous_digest"]:offsets["previous_digest"] + 32] = ZERO_DIGEST
                    _overwrite(path, raw)
                    before = _root_inventory(fixture.root)
                    result = activate._inspect_reconciliation(
                        fixture.root, helper_record=activate._helper())
                    self.assertEqual(result["classification"], "BLOCKED")
                    self.assertEqual(_root_inventory(fixture.root), before)
                finally:
                    if second_fd is not None:
                        os.close(second_fd)
                    fixture.close()

    def test_recovery_uses_unlinked_previous_snapshot_or_rejects_before_any_selector_write(self):
        """A recovery helper must never receive the caller's mutable inode.

        The mutation runs *after* the Python recovery API has accepted and
        snapshotted previous_fd, but immediately before the real native helper
        is spawned.  Thus a post-native Python identity check is insufficient:
        either the helper receives an immutable private snapshot containing the
        original bytes, or the call must fail without changing root state.
        """
        with tempfile.TemporaryDirectory() as build_directory, tempfile.TemporaryDirectory() as directory:
            interrupted = _compile(build_directory, "SP_TEST_OPERATION_FAILURE_AFTER_SELECT_ROLE=1",
                                   "SP_TEST_CRASH_AFTER_PHASE=4")
            recovery = _compile(build_directory)
            fixture = NativeFixture(directory)
            second_fd = None
            original_runner = activate._run_native_command
            try:
                # Establish the only legal predecessor, then interrupt an
                # upgrade after rollback intent is durable.
                fixture.run(nonce="1" * 64, prior_present=False)
                second_path = Path(directory) / "payload-v2"
                _write(second_path, b"payload-v2")
                second_input = os.open(second_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    second_digest = fixture.store.put_fd(second_input)
                finally:
                    os.close(second_input)
                second_fd = fixture.store.open_cas(second_digest)
                with self.assertRaises(activate.ActivationError):
                    activate._run_parent(
                        root_fd=fixture.store.fd, payload_fd=second_fd, previous_fd=fixture.payload_fd,
                        epoch=2, nonce="2" * 64, payload_digest=second_digest,
                        previous_digest=fixture.payload_digest,
                        authority_digest=hashlib.sha256(b"authority-2").hexdigest(),
                        trusted_root_digest=hashlib.sha256(b"root-2").hexdigest(),
                        envelope_digest=hashlib.sha256(b"envelope-2").hexdigest(), helper_record=interrupted)
                state_before = _state(fixture.root)
                self.assertEqual(_phase(state_before), 4)
                inventory_before = _root_inventory(fixture.root)
                mutated = b"mutated-v1"  # Same length as b"payload-v1".
                self.assertEqual(len(mutated), len(b"payload-v1"))
                invoked = []

                def mutate_after_snapshot(arguments, *, helper_record, helper_fd=None, pass_fds, timeout_message):
                    invoked.append(tuple(arguments))
                    child = os.fork()
                    if child == 0:
                        code = 1
                        fd = -1
                        try:
                            fd = os.open(fixture.payload_path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
                            if os.pwrite(fd, mutated, 0) != len(mutated):
                                raise RuntimeError("short mutation")
                            os.fsync(fd)
                            code = 0
                        finally:
                            if fd >= 0:
                                os.close(fd)
                            os._exit(code)
                    _, status = os.waitpid(child, 0)
                    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                        raise AssertionError("mutation child failed")
                    return original_runner(arguments, helper_record=helper_record, helper_fd=helper_fd,
                                           pass_fds=pass_fds, timeout_message=timeout_message)

                activate._run_native_command = mutate_after_snapshot
                try:
                    result = activate._recover_interrupted(
                        fixture.root, hashlib.sha256(state_before).hexdigest(),
                        previous_fd=fixture.payload_input, helper_record=recovery)
                except activate.ActivationError:
                    # Rejection is safe only while every durable selector file
                    # (including state, journal, and current) remains exact.
                    self.assertEqual(_root_inventory(fixture.root), inventory_before)
                else:
                    self.assertEqual(result["classification"], "RECOVERED_ROLLED_BACK")
                    self.assertEqual((fixture.root / "current.payload").read_bytes(), b"payload-v1")
                finally:
                    activate._run_native_command = original_runner
                self.assertEqual(len(invoked), 1)
                self.assertEqual(fixture.payload_path.read_bytes(), mutated)
            finally:
                activate._run_native_command = original_runner
                if second_fd is not None:
                    os.close(second_fd)
                fixture.close()

    def test_recovery_crash_points_are_idempotently_terminal_rolled_back(self):
        """All currently exposed durable recovery crash points resume only rollback."""
        with tempfile.TemporaryDirectory() as build_directory:
            interrupted_prior = _compile(build_directory, "SP_TEST_OPERATION_FAILURE_ROLE=1",
                                         "SP_TEST_CRASH_AFTER_PHASE=4")
            interrupted_payload = _compile(
                build_directory, "SP_TEST_OPERATION_FAILURE_AFTER_SELECT_ROLE=1",
                "SP_TEST_CRASH_AFTER_PHASE=4")
            clean_recovery = _compile(build_directory)
            crashing = {
                point: _compile(build_directory, "SP_TEST_RECOVERY_CRASH_POINT=%d" % point)
                for point in range(1, 7)
            }
            for point, helper in crashing.items():
                with self.subTest(crash_point=point), tempfile.TemporaryDirectory() as directory:
                    fixture = NativeFixture(directory)
                    second_fd = None
                    try:
                        fixture.run(nonce="1" * 64, prior_present=False)
                        next_path = Path(directory) / "next"
                        _write(next_path, b"payload-v2")
                        input_fd = os.open(next_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                        try:
                            next_digest = fixture.store.put_fd(input_fd)
                        finally:
                            os.close(input_fd)
                        second_fd = fixture.store.open_cas(next_digest)
                        interrupted = interrupted_prior if point <= 3 else interrupted_payload
                        with self.assertRaises(activate.ActivationError):
                            activate._run_parent(
                                root_fd=fixture.store.fd, payload_fd=second_fd, previous_fd=fixture.payload_fd,
                                epoch=2, nonce="2" * 64, payload_digest=next_digest,
                                previous_digest=fixture.payload_digest,
                                authority_digest=hashlib.sha256(b"authority-2").hexdigest(),
                                trusted_root_digest=hashlib.sha256(b"root-2").hexdigest(),
                                envelope_digest=hashlib.sha256(b"envelope-2").hexdigest(),
                                helper_record=interrupted)
                        interrupted_state = _state(fixture.root)
                        interrupted_sha = hashlib.sha256(interrupted_state).hexdigest()
                        self.assertEqual(_phase(interrupted_state), 4)
                        expected_before = b"payload-v1" if point <= 3 else b"payload-v2"
                        self.assertEqual((fixture.root / "current.payload").read_bytes(), expected_before)
                        with self.assertRaises(activate.ActivationError):
                            activate._recover_interrupted(
                                fixture.root, interrupted_sha,
                                previous_fd=fixture.payload_input, helper_record=helper)
                        latest_state = _state(fixture.root)
                        latest_sha = hashlib.sha256(latest_state).hexdigest()
                        if point == 1:
                            # Terminal-state temp was fsynced but not renamed;
                            # the exact original state token remains usable.
                            self.assertEqual(latest_sha, interrupted_sha)
                            result = activate._recover_interrupted(
                                fixture.root, latest_sha, previous_fd=fixture.payload_input,
                                helper_record=clean_recovery)
                            self.assertEqual(result["classification"], "RECOVERED_ROLLED_BACK")
                        elif point in (2, 3):
                            # The phase-6 rename is already authoritative.
                            self.assertNotEqual(latest_sha, interrupted_sha)
                            before_stale = _root_inventory(fixture.root)
                            with self.assertRaises(activate.ActivationError):
                                activate._recover_interrupted(
                                    fixture.root, interrupted_sha, previous_fd=fixture.payload_input,
                                    helper_record=clean_recovery)
                            self.assertEqual(_root_inventory(fixture.root), before_stale)
                            inspected = activate._inspect_reconciliation(
                                fixture.root, helper_record=clean_recovery)
                            self.assertEqual(inspected["classification"], "TERMINAL_ROLLED_BACK")
                        else:
                            # Restore points 4-6 are reachable only when the
                            # interrupted P4 transaction had selected payload.
                            self.assertEqual(_phase(latest_state), 8)
                            self.assertEqual(_u32(latest_state, STATE_OFFSETS["recovery_from_phase"]), 4)
                            inspected = activate._inspect_reconciliation(
                                fixture.root, helper_record=clean_recovery)
                            expected = ("DEBRIS" if point == 4 else "RECOVERABLE_ROLLED_BACK")
                            self.assertEqual(inspected["classification"], expected)
                            result = activate._recover_interrupted(
                                fixture.root, latest_sha, previous_fd=fixture.payload_input,
                                helper_record=clean_recovery)
                            self.assertEqual(result["classification"], "RECOVERED_ROLLED_BACK")
                        self.assertEqual((fixture.root / "current.payload").read_bytes(), b"payload-v1")
                        self.assertEqual(_phase(_state(fixture.root)), 6)
                    finally:
                        if second_fd is not None:
                            os.close(second_fd)
                        fixture.close()

    def test_recovery_decision_full_native_phase_origin_and_current_matrix(self):
        """Exercise every legal recovery_decision branch through the native helper."""
        cases = (
            (1, 0, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (2, 0, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (2, 0, "PAYLOAD", "RECOVERABLE_COMMITTED", "RECOVERED_COMMITTED", 5),
            (3, 0, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (3, 0, "PAYLOAD", "RECOVERABLE_COMMITTED", "RECOVERED_COMMITTED", 5),
            (4, 0, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (4, 0, "PAYLOAD", "RECOVERABLE_ROLLBACK_REQUIRED", "RECOVERED_ROLLED_BACK", 6),
            (7, 1, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (7, 2, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (7, 2, "PAYLOAD", "RECOVERABLE_COMMITTED", "RECOVERED_COMMITTED", 5),
            (7, 3, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (7, 3, "PAYLOAD", "RECOVERABLE_COMMITTED", "RECOVERED_COMMITTED", 5),
            (7, 4, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (7, 4, "PAYLOAD", "RECOVERABLE_ROLLBACK_REQUIRED", "RECOVERED_ROLLED_BACK", 6),
            (7, 5, "PAYLOAD", "RECOVERABLE_COMMITTED", "RECOVERED_COMMITTED", 5),
            (7, 6, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (8, 4, "PRIOR", "RECOVERABLE_ROLLED_BACK", "RECOVERED_ROLLED_BACK", 6),
            (8, 4, "PAYLOAD", "RECOVERABLE_ROLLBACK_REQUIRED", "RECOVERED_ROLLED_BACK", 6),
            (5, 0, "PAYLOAD", "TERMINAL_COMMITTED", None, 5),
            (6, 0, "PRIOR", "TERMINAL_ROLLED_BACK", None, 6),
        )
        helper = activate._helper()
        for phase, origin, current_kind, inspect_class, recover_class, terminal_phase in cases:
            label = "p%d-o%d-%s" % (phase, origin, current_kind.lower())
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                candidate_fd = None
                try:
                    candidate_digest, candidate_fd = _commit_prior_present(fixture, helper=helper)
                    state_path = fixture.root / ".sp-release-v2.state"
                    raw = bytearray(state_path.read_bytes())
                    _put_u32(raw, STATE_OFFSETS["phase"], phase)
                    _put_u32(raw, STATE_OFFSETS["recovery_from_phase"], origin)
                    _overwrite(state_path, raw)
                    current = fixture.root / "current.payload"
                    expected_current = b"payload-v1" if current_kind == "PRIOR" else b"payload-v2"
                    _overwrite(current, expected_current)
                    state_sha = hashlib.sha256(raw).hexdigest()
                    before_inspect = _root_inventory(fixture.root)
                    inspected = activate._inspect_reconciliation(fixture.root, helper_record=helper)
                    self.assertEqual(inspected["classification"], inspect_class)
                    self.assertEqual(inspected["phase"], phase)
                    self.assertEqual(inspected["recovery_from_phase"], origin)
                    self.assertEqual(inspected["current"], current_kind)
                    self.assertEqual(_root_inventory(fixture.root), before_inspect)
                    if recover_class is None:
                        with self.assertRaises(activate.ActivationError):
                            activate._recover_interrupted(
                                fixture.root, state_sha, previous_fd=fixture.payload_input,
                                helper_record=helper)
                        self.assertEqual(_root_inventory(fixture.root), before_inspect)
                    else:
                        recovered = activate._recover_interrupted(
                            fixture.root, state_sha, previous_fd=fixture.payload_input,
                            helper_record=helper)
                        self.assertEqual(recovered["classification"], recover_class)
                        self.assertEqual(_phase(_state(fixture.root)), terminal_phase)
                        final_bytes = (b"payload-v2" if terminal_phase == 5 else b"payload-v1")
                        self.assertEqual(current.read_bytes(), final_bytes)
                    self.assertEqual(candidate_digest, hashlib.sha256(b"payload-v2").hexdigest())
                finally:
                    if candidate_fd is not None:
                        os.close(candidate_fd)
                    fixture.close()

    def test_after_select_phase4_to_phase8_recovery_state_crash_points_resume_rollback(self):
        with tempfile.TemporaryDirectory() as build_directory:
            interrupted = _compile(
                build_directory, "SP_TEST_OPERATION_FAILURE_AFTER_SELECT_ROLE=1",
                "SP_TEST_CRASH_AFTER_PHASE=4")
            clean = _compile(build_directory)
            crashing = {point: _compile(build_directory, "SP_TEST_RECOVERY_CRASH_POINT=%d" % point)
                        for point in (1, 2, 3)}
            for point, recovery in crashing.items():
                with self.subTest(crash_point=point), tempfile.TemporaryDirectory() as directory:
                    fixture = NativeFixture(directory)
                    candidate_fd = None
                    try:
                        fixture.run(nonce="1" * 64, prior_present=False)
                        candidate_digest, candidate_fd = _cas_payload(fixture, "payload-v2", b"payload-v2")
                        with self.assertRaises(activate.ActivationError):
                            activate._run_parent(
                                root_fd=fixture.store.fd, payload_fd=candidate_fd,
                                previous_fd=fixture.payload_fd, epoch=2, nonce="2" * 64,
                                payload_digest=candidate_digest, previous_digest=fixture.payload_digest,
                                authority_digest=hashlib.sha256(b"authority-2").hexdigest(),
                                trusted_root_digest=hashlib.sha256(b"root-2").hexdigest(),
                                envelope_digest=hashlib.sha256(b"envelope-2").hexdigest(),
                                helper_record=interrupted)
                        phase4 = _state(fixture.root)
                        phase4_sha = hashlib.sha256(phase4).hexdigest()
                        self.assertEqual(_phase(phase4), 4)
                        self.assertEqual((fixture.root / "current.payload").read_bytes(), b"payload-v2")
                        with self.assertRaises(activate.ActivationError):
                            activate._recover_interrupted(
                                fixture.root, phase4_sha, previous_fd=fixture.payload_input,
                                helper_record=recovery)
                        latest = _state(fixture.root)
                        latest_sha = hashlib.sha256(latest).hexdigest()
                        inspected = activate._inspect_reconciliation(fixture.root, helper_record=clean)
                        if point == 1:
                            self.assertEqual(latest, phase4)
                            self.assertEqual(inspected["classification"], "DEBRIS")
                            recovery_sha = phase4_sha
                        else:
                            self.assertEqual(_phase(latest), 8)
                            self.assertEqual(_u32(latest, STATE_OFFSETS["recovery_from_phase"]), 4)
                            self.assertEqual(inspected["classification"], "RECOVERABLE_ROLLBACK_REQUIRED")
                            before_stale = _root_inventory(fixture.root)
                            with self.assertRaises(activate.ActivationError):
                                activate._recover_interrupted(
                                    fixture.root, phase4_sha, previous_fd=fixture.payload_input,
                                    helper_record=clean)
                            self.assertEqual(_root_inventory(fixture.root), before_stale)
                            recovery_sha = latest_sha
                        result = activate._recover_interrupted(
                            fixture.root, recovery_sha, previous_fd=fixture.payload_input,
                            helper_record=clean)
                        self.assertEqual(result["classification"], "RECOVERED_ROLLED_BACK")
                        self.assertEqual(_phase(_state(fixture.root)), 6)
                        self.assertEqual((fixture.root / "current.payload").read_bytes(), b"payload-v1")
                    finally:
                        if candidate_fd is not None:
                            os.close(candidate_fd)
                        fixture.close()

    def test_fresh_after_select_phase4_recovery_crash_points_restore_true_absence(self):
        with tempfile.TemporaryDirectory() as build_directory:
            interrupted = _compile(
                build_directory, "SP_TEST_OPERATION_FAILURE_AFTER_SELECT_ROLE=1",
                "SP_TEST_CRASH_AFTER_PHASE=4")
            clean = _compile(build_directory)
            crashing = {point: _compile(build_directory, "SP_TEST_RECOVERY_CRASH_POINT=%d" % point)
                        for point in (4, 5, 6)}
            for point, recovery in crashing.items():
                with self.subTest(crash_point=point), tempfile.TemporaryDirectory() as directory:
                    fixture = NativeFixture(directory)
                    try:
                        with self.assertRaises(activate.ActivationError):
                            fixture.run(helper=interrupted, nonce="1" * 64, prior_present=False)
                        phase4 = _state(fixture.root)
                        self.assertEqual(_phase(phase4), 4)
                        self.assertEqual((fixture.root / "current.payload").read_bytes(), b"payload-v1")
                        with self.assertRaises(activate.ActivationError):
                            activate._recover_interrupted(
                                fixture.root, hashlib.sha256(phase4).hexdigest(), previous_fd=None,
                                helper_record=recovery)
                        latest = _state(fixture.root)
                        self.assertEqual(_phase(latest), 8)
                        inspected = activate._inspect_reconciliation(fixture.root, helper_record=clean)
                        expected_class = ("RECOVERABLE_ROLLBACK_REQUIRED" if point == 4 else
                                          "RECOVERABLE_ROLLED_BACK")
                        self.assertEqual(inspected["classification"], expected_class)
                        if point == 4:
                            self.assertEqual((fixture.root / "current.payload").read_bytes(), b"payload-v1")
                        else:
                            self.assertFalse((fixture.root / "current.payload").exists())
                        result = activate._recover_interrupted(
                            fixture.root, hashlib.sha256(latest).hexdigest(), previous_fd=None,
                            helper_record=clean)
                        self.assertEqual(result["classification"], "RECOVERED_ROLLED_BACK")
                        self.assertEqual(_phase(_state(fixture.root)), 6)
                        self.assertFalse((fixture.root / "current.payload").exists())
                    finally:
                        fixture.close()

    def test_unknown_current_is_reported_with_observed_digest_and_never_recovered(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            candidate_fd = None
            try:
                _, candidate_fd = _commit_prior_present(fixture)
                state_path = fixture.root / ".sp-release-v2.state"
                raw = bytearray(state_path.read_bytes())
                _put_u32(raw, STATE_OFFSETS["phase"], 4)
                _put_u32(raw, STATE_OFFSETS["recovery_from_phase"], 0)
                _overwrite(state_path, raw)
                attacker_current = b"neither-prior-nor-payload"
                _overwrite(fixture.root / "current.payload", attacker_current)
                state_sha = hashlib.sha256(raw).hexdigest()
                before = _root_inventory(fixture.root)
                inspected = activate._inspect_reconciliation(
                    fixture.root, helper_record=activate._helper())
                self.assertEqual(inspected["classification"], "BLOCKED")
                self.assertEqual(inspected["current"], "UNKNOWN")
                self.assertEqual(inspected["current_sha256"], hashlib.sha256(attacker_current).hexdigest())
                self.assertEqual(_root_inventory(fixture.root), before)
                with self.assertRaises(activate.ActivationError):
                    activate._recover_interrupted(
                        fixture.root, state_sha, previous_fd=fixture.payload_input,
                        helper_record=activate._helper())
                self.assertEqual(_root_inventory(fixture.root), before)
            finally:
                if candidate_fd is not None:
                    os.close(candidate_fd)
                fixture.close()

    def test_malicious_selector_temporaries_block_inspect_and_recovery_without_writes(self):
        temporary_names = (
            ".sp-release-v2.attacker.tmp",
            ".sp-release-v2.2.2222222222222222.1.tmp",
        )
        for temporary_name in temporary_names:
            with self.subTest(name=temporary_name), tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                candidate_fd = None
                try:
                    _, candidate_fd = _commit_prior_present(fixture)
                    state_path = fixture.root / ".sp-release-v2.state"
                    raw = bytearray(state_path.read_bytes())
                    _put_u32(raw, STATE_OFFSETS["phase"], 2)
                    _put_u32(raw, STATE_OFFSETS["recovery_from_phase"], 0)
                    _overwrite(state_path, raw)
                    _write(fixture.root / temporary_name, b"attacker-controlled-temporary")
                    state_sha = hashlib.sha256(raw).hexdigest()
                    before = _root_inventory(fixture.root)
                    inspected = activate._inspect_reconciliation(
                        fixture.root, helper_record=activate._helper())
                    self.assertEqual(inspected["classification"], "BLOCKED")
                    self.assertEqual(_root_inventory(fixture.root), before)
                    with self.assertRaises(activate.ActivationError):
                        activate._recover_interrupted(
                            fixture.root, state_sha, previous_fd=fixture.payload_input,
                            helper_record=activate._helper())
                    self.assertEqual(_root_inventory(fixture.root), before)
                finally:
                    if candidate_fd is not None:
                        os.close(candidate_fd)
                    fixture.close()

    def test_state_transition_temporary_filename_must_match_embedded_phase_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            candidate_fd = None
            try:
                _, candidate_fd = _commit_prior_present(fixture)
                state_path = fixture.root / ".sp-release-v2.state"
                base = bytearray(state_path.read_bytes())
                _put_u32(base, STATE_OFFSETS["phase"], 1)
                _put_u32(base, STATE_OFFSETS["recovery_from_phase"], 0)
                _overwrite(state_path, base)
                _overwrite(fixture.root / "current.payload", b"payload-v1")
                transition = bytearray(base)
                _put_u32(transition, STATE_OFFSETS["phase"], 2)
                # The embedded phase is 2, but the attacker supplied suffix
                # falsely claims phase 3.  Prefix-only acceptance would let
                # recovery delete an unauthorised selector temporary.
                wrong_name = ".sp-release-v2.state.%s.3.tmp" % ("2" * 64)
                _write(fixture.root / wrong_name, transition)
                state_sha = hashlib.sha256(base).hexdigest()
                before = _root_inventory(fixture.root)
                inspected = activate._inspect_reconciliation(
                    fixture.root, helper_record=activate._helper())
                self.assertEqual(inspected["classification"], "BLOCKED")
                self.assertEqual(_root_inventory(fixture.root), before)
                with self.assertRaises(activate.ActivationError):
                    activate._recover_interrupted(
                        fixture.root, state_sha, previous_fd=fixture.payload_input,
                        helper_record=activate._helper())
                self.assertEqual(_root_inventory(fixture.root), before)
            finally:
                if candidate_fd is not None:
                    os.close(candidate_fd)
                fixture.close()

    def test_recovery_wrong_state_token_and_replaced_lease_inode_are_zero_write_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            candidate_fd = None
            try:
                _, candidate_fd = _commit_prior_present(fixture)
                state_path = fixture.root / ".sp-release-v2.state"
                raw = bytearray(state_path.read_bytes())
                _put_u32(raw, STATE_OFFSETS["phase"], 1)
                _overwrite(state_path, raw)
                _overwrite(fixture.root / "current.payload", b"payload-v1")
                before = _root_inventory(fixture.root)
                with self.assertRaises(activate.ActivationError):
                    activate._recover_interrupted(
                        fixture.root, "f" * 64, previous_fd=fixture.payload_input,
                        helper_record=activate._helper())
                self.assertEqual(_root_inventory(fixture.root), before)
            finally:
                if candidate_fd is not None:
                    os.close(candidate_fd)
                fixture.close()

        for lease_name in (".sp-release-v2.activate.lease", ".sp-release-v2.rollback.lease"):
            with self.subTest(replaced_lease=lease_name), tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                candidate_fd = None
                try:
                    _, candidate_fd = _commit_prior_present(fixture)
                    state_path = fixture.root / ".sp-release-v2.state"
                    raw = bytearray(state_path.read_bytes())
                    _put_u32(raw, STATE_OFFSETS["phase"], 1)
                    _overwrite(state_path, raw)
                    _overwrite(fixture.root / "current.payload", b"payload-v1")
                    replacement = Path(directory) / (lease_name + ".replacement")
                    _write(replacement, b"")
                    os.replace(replacement, fixture.root / lease_name)
                    before = _root_inventory(fixture.root)
                    inspected = activate._inspect_reconciliation(
                        fixture.root, helper_record=activate._helper())
                    self.assertEqual(inspected["classification"], "BLOCKED")
                    self.assertEqual(_root_inventory(fixture.root), before)
                    with self.assertRaises(activate.ActivationError):
                        activate._recover_interrupted(
                            fixture.root, hashlib.sha256(raw).hexdigest(),
                            previous_fd=fixture.payload_input, helper_record=activate._helper())
                    self.assertEqual(_root_inventory(fixture.root), before)
                finally:
                    if candidate_fd is not None:
                        os.close(candidate_fd)
                    fixture.close()

    def test_inspect_is_strictly_read_only_and_role_lease_busy_is_active(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            try:
                fixture.run(nonce="1" * 64, prior_present=False)

                # Inventory equality cannot see a same-bytes rewrite.  Vnode
                # notifications independently prove that inspection performs
                # no write, truncate, chmod, link, rename, or delete on the
                # selector root or any top-level protocol entry.
                watched_fds = []
                queue = select.kqueue()
                try:
                    watched = [fixture.root, *sorted(fixture.root.iterdir())]
                    for path in watched:
                        watched_fds.append(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)))
                    notes = (select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_ATTRIB |
                             select.KQ_NOTE_LINK | select.KQ_NOTE_RENAME | select.KQ_NOTE_DELETE)
                    changes = [select.kevent(fd, filter=select.KQ_FILTER_VNODE,
                                             flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                                             fflags=notes) for fd in watched_fds]
                    queue.control(changes, 0, 0)
                    before = _root_inventory(fixture.root)
                    terminal = activate._inspect_reconciliation(
                        fixture.root, helper_record=activate._helper())
                    self.assertEqual(terminal["classification"], "TERMINAL_COMMITTED")
                    self.assertEqual(_root_inventory(fixture.root), before)
                    self.assertEqual(queue.control(None, len(watched_fds), 0), [])
                finally:
                    queue.close()
                    for watched_fd in watched_fds:
                        os.close(watched_fd)

                for name in (".sp-release-v2.activate.lease", ".sp-release-v2.rollback.lease"):
                    with self.subTest(lease=name):
                        ready_read, ready_write = os.pipe()
                        release_read, release_write = os.pipe()
                        child = os.fork()
                        if child == 0:
                            fd = -1
                            code = 1
                            try:
                                os.close(ready_read)
                                os.close(release_write)
                                fd = os.open(fixture.root / name, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
                                fcntl.flock(fd, fcntl.LOCK_EX)
                                os.write(ready_write, b"R")
                                if os.read(release_read, 1) != b"X":
                                    raise RuntimeError("release pipe closed")
                                code = 0
                            finally:
                                if fd is not None and fd >= 0:
                                    os.close(fd)
                                os.close(ready_write)
                                os.close(release_read)
                                os._exit(code)
                        os.close(ready_write)
                        os.close(release_read)
                        released = waited = False
                        try:
                            readable, _, _ = select.select([ready_read], [], [], 5)
                            self.assertEqual(readable, [ready_read])
                            self.assertEqual(os.read(ready_read, 1), b"R")
                            before = _root_inventory(fixture.root)
                            result = activate._inspect_reconciliation(
                                fixture.root, helper_record=activate._helper())
                            self.assertEqual(result["classification"], "ACTIVE")
                            self.assertEqual(_root_inventory(fixture.root), before)
                            with self.assertRaises(activate.ActivationError):
                                activate._recover_interrupted(
                                    fixture.root, hashlib.sha256(_state(fixture.root)).hexdigest(),
                                    previous_fd=None, helper_record=activate._helper())
                            self.assertEqual(_root_inventory(fixture.root), before)
                            os.write(release_write, b"X")
                            released = True
                            _, status = os.waitpid(child, 0)
                            waited = True
                            self.assertTrue(os.WIFEXITED(status))
                            self.assertEqual(os.WEXITSTATUS(status), 0)
                        finally:
                            if not released:
                                try:
                                    os.write(release_write, b"X")
                                except OSError:
                                    pass
                            if not waited:
                                _, status = os.waitpid(child, 0)
                            os.close(ready_read)
                            os.close(release_write)

                # Hold the original activation lease after unlinking it from
                # the directory, then install a lookalike pathname.  The live
                # orphan lock cannot authorise the replacement inode.
                name = ".sp-release-v2.activate.lease"
                ready_read, ready_write = os.pipe()
                release_read, release_write = os.pipe()
                child = os.fork()
                if child == 0:
                    fd = -1
                    code = 1
                    try:
                        os.close(ready_read)
                        os.close(release_write)
                        fd = os.open(fixture.root / name, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
                        fcntl.flock(fd, fcntl.LOCK_EX)
                        os.write(ready_write, b"R")
                        if os.read(release_read, 1) != b"X":
                            raise RuntimeError("release pipe closed")
                        code = 0
                    finally:
                        if fd >= 0:
                            os.close(fd)
                        os.close(ready_write)
                        os.close(release_read)
                        os._exit(code)
                os.close(ready_write)
                os.close(release_read)
                released = waited = False
                try:
                    readable, _, _ = select.select([ready_read], [], [], 5)
                    self.assertEqual(readable, [ready_read])
                    self.assertEqual(os.read(ready_read, 1), b"R")
                    replacement = Path(directory) / "orphan-lease-replacement"
                    _write(replacement, b"")
                    os.replace(replacement, fixture.root / name)
                    before = _root_inventory(fixture.root)
                    result = activate._inspect_reconciliation(
                        fixture.root, helper_record=activate._helper())
                    self.assertEqual(result["classification"], "BLOCKED")
                    self.assertEqual(_root_inventory(fixture.root), before)
                    with self.assertRaises(activate.ActivationError):
                        activate._recover_interrupted(
                            fixture.root, hashlib.sha256(_state(fixture.root)).hexdigest(),
                            previous_fd=None, helper_record=activate._helper())
                    self.assertEqual(_root_inventory(fixture.root), before)
                    os.write(release_write, b"X")
                    released = True
                    _, status = os.waitpid(child, 0)
                    waited = True
                    self.assertTrue(os.WIFEXITED(status))
                    self.assertEqual(os.WEXITSTATUS(status), 0)
                finally:
                    if not released:
                        try:
                            os.write(release_write, b"X")
                        except OSError:
                            pass
                    if not waited:
                        _, status = os.waitpid(child, 0)
                    os.close(ready_read)
                    os.close(release_write)
            finally:
                fixture.close()

    def test_activate_verified_holds_original_root_across_path_rename_swap(self):
        class Proof:
            def __init__(self, payload, root, envelope):
                self.authority_digest = hashlib.sha256(b"swap-authority").hexdigest()
                self.trusted_root_digest = hashlib.sha256(root).hexdigest()
                self.payload_digest = hashlib.sha256(payload).hexdigest()
                self.envelope_digest = hashlib.sha256(envelope).hexdigest()

        class SwappingArtifact:
            ActivationReverifyResult = Proof
            root_path = other_root = parked_root = None
            swapped = False

            @classmethod
            def reverify_for_activation(cls, **kwargs):
                os.rename(cls.root_path, cls.parked_root)
                os.rename(cls.other_root, cls.root_path)
                cls.swapped = True
                return Proof(kwargs["payload"], kwargs["trusted_root_bytes"], kwargs["envelope_bytes"])

        original = activate._ARTIFACT_MODULE
        activate._ARTIFACT_MODULE = SwappingArtifact
        try:
            with tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                payload_v2_fd = None
                try:
                    fixture.run(nonce="1" * 64, prior_present=False)
                    root_path = fixture.root
                    other_root = Path(directory) / "fresh-replacement"
                    other_root.mkdir(mode=0o700)
                    os.chmod(other_root, 0o700)
                    parked_root = Path(directory) / "held-original"
                    replacement_before = _root_inventory(other_root)
                    original_before = _root_inventory(root_path)
                    v2 = Path(directory) / "v2"
                    _write(v2, b"payload-v2")
                    payload_v2_fd = os.open(v2, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    SwappingArtifact.root_path = root_path
                    SwappingArtifact.other_root = other_root
                    SwappingArtifact.parked_root = parked_root
                    SwappingArtifact.swapped = False
                    try:
                        result = _activate_test(
                            root=root_path, envelope_bytes=b"swap-envelope", canonical_tar_fd=payload_v2_fd,
                            trusted_root_bytes=b"swap-root", trusted_policy_bytes=b"swap-policy",
                            r1_authority=object(), r2_authority=object(), previous_fd=fixture.payload_input,
                            epoch=2, nonce="2" * 64)
                    except activate.ActivationError:
                        # Rejecting a rename race is valid, but neither the
                        # replacement nor the held original may be polluted.
                        self.assertTrue(SwappingArtifact.swapped)
                        self.assertEqual(_root_inventory(root_path), replacement_before)
                        self.assertEqual(_root_inventory(parked_root), original_before)
                    else:
                        self.assertEqual(result["phase"], "COMMITTED")
                        self.assertTrue(SwappingArtifact.swapped)
                        self.assertEqual(_root_inventory(root_path), replacement_before)
                        self.assertEqual((parked_root / "current.payload").read_bytes(), b"payload-v2")
                finally:
                    if payload_v2_fd is not None:
                        os.close(payload_v2_fd)
                    fixture.close()
        finally:
            activate._ARTIFACT_MODULE = original

    def test_terminal_replay_epoch_and_prior_fail_before_cas_or_reverification(self):
        class NeverVerify:
            class ActivationReverifyResult:
                pass

            calls = 0

            @classmethod
            def reverify_for_activation(cls, **unused):
                cls.calls += 1
                raise AssertionError("terminal binding must fail before re-verification/CAS")

        original = activate._ARTIFACT_MODULE
        activate._ARTIFACT_MODULE = NeverVerify
        try:
            with tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                payload_fd = wrong_fd = None
                try:
                    fixture.run(nonce="1" * 64, prior_present=False)
                    next_path = Path(directory) / "next"
                    wrong_path = Path(directory) / "wrong"
                    _write(next_path, b"payload-v2")
                    _write(wrong_path, b"wrong-prior")
                    payload_fd = os.open(next_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    wrong_fd = os.open(wrong_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    before = _root_inventory(fixture.root)
                    attacks = (
                        ("wrong-prior", wrong_fd, 2, "2" * 64),
                        ("old-epoch", fixture.payload_input, 1, "2" * 64),
                        ("replayed-nonce", fixture.payload_input, 2, "1" * 64),
                    )
                    for label, previous_fd, epoch, nonce in attacks:
                        with self.subTest(label=label):
                            with self.assertRaises(activate.ActivationError):
                                _activate_test(
                                    root=fixture.root, envelope_bytes=b"terminal-envelope",
                                    canonical_tar_fd=payload_fd, trusted_root_bytes=b"terminal-root",
                                    trusted_policy_bytes=b"terminal-policy", r1_authority=object(), r2_authority=object(),
                                    previous_fd=previous_fd, epoch=epoch, nonce=nonce)
                            self.assertEqual(_root_inventory(fixture.root), before)
                    self.assertEqual(NeverVerify.calls, 0)
                finally:
                    if payload_fd is not None:
                        os.close(payload_fd)
                    if wrong_fd is not None:
                        os.close(wrong_fd)
                    fixture.close()
        finally:
            activate._ARTIFACT_MODULE = original

    def test_helper_path_replacement_cannot_change_executed_binary_or_public_api(self):
        with tempfile.TemporaryDirectory() as build_directory, tempfile.TemporaryDirectory() as directory:
            helper = _compile(build_directory)
            fixture = NativeFixture(directory)
            original_runner = activate._run_native_command
            try:
                marker = fixture.root / "MALICIOUS_HELPER_EXECUTED"
                attacker = Path(build_directory) / "attacker"
                script = ("#!/bin/sh\n"
                          "printf attacker > %s\n"
                          "exit 91\n" % os.fspath(marker))
                _write(attacker, script.encode("ascii"))
                os.chmod(attacker, 0o700)
                swapped = []
                runner_calls = []

                def replace_verified_path(arguments, *, helper_record, helper_fd=None, pass_fds, timeout_message):
                    # This hook runs after _verify_helper but before the
                    # process creation inside the real command runner.
                    runner_calls.append(tuple(arguments))
                    if not swapped:
                        os.replace(attacker, helper.path)
                        swapped.append(True)
                    return original_runner(arguments, helper_record=helper_record, helper_fd=helper_fd,
                                           pass_fds=pass_fds, timeout_message=timeout_message)

                activate._run_native_command = replace_verified_path
                result = fixture.run(helper=helper, nonce="1" * 64, prior_present=False)
                self.assertEqual(result["phase"], "COMMITTED")
                self.assertEqual(swapped, [True])
                self.assertEqual(len(runner_calls), 2)
                self.assertFalse(marker.exists())
                # The public reconciliation interfaces select their own
                # independently pinned recovery helper; accepting a caller
                # supplied transaction helper would re-open this attack.
                with self.assertRaises(TypeError):
                    activate.inspect_reconciliation(fixture.root, helper_record=helper)
                with self.assertRaises(TypeError):
                    activate.recover_interrupted(
                        fixture.root, hashlib.sha256(_state(fixture.root)).hexdigest(),
                        helper_record=helper)
            finally:
                activate._run_native_command = original_runner
                fixture.close()

    def test_native_build_does_not_honor_tmpdir_inside_selector_root_or_leak_fds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "selector-root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            before = _root_inventory(root)
            descriptors_before = _fd_count()
            old_tmpdir = os.environ.get("TMPDIR")
            old_cache = tempfile.tempdir
            old_record, old_temporary = activate._HELPER_RECORD, activate._HELPER_TEMPORARY
            activate._HELPER_RECORD = activate._HELPER_TEMPORARY = None
            try:
                os.environ["TMPDIR"] = os.fspath(root)
                tempfile.tempdir = None
                for _ in range(3):
                    activate._helper()
                self.assertEqual(_root_inventory(root), before)
                self.assertEqual(_fd_count(), descriptors_before)
            finally:
                temporary = activate._HELPER_TEMPORARY
                activate._HELPER_RECORD = old_record
                activate._HELPER_TEMPORARY = old_temporary
                if temporary is not None:
                    temporary.cleanup()
                if old_tmpdir is None:
                    os.environ.pop("TMPDIR", None)
                else:
                    os.environ["TMPDIR"] = old_tmpdir
                tempfile.tempdir = old_cache

    def test_second_cas_open_failure_and_first_close_error_do_not_leak_rollback_fd(self):
        class Proof:
            def __init__(self, payload, root, envelope):
                self.authority_digest = hashlib.sha256(b"fd-authority").hexdigest()
                self.trusted_root_digest = hashlib.sha256(root).hexdigest()
                self.payload_digest = hashlib.sha256(payload).hexdigest()
                self.envelope_digest = hashlib.sha256(envelope).hexdigest()

        class Artifact:
            ActivationReverifyResult = Proof

            @classmethod
            def reverify_for_activation(cls, **kwargs):
                return Proof(kwargs["payload"], kwargs["trusted_root_bytes"], kwargs["envelope_bytes"])

        original_artifact = activate._ARTIFACT_MODULE
        activate._ARTIFACT_MODULE = Artifact
        try:
            with tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                payload_fd = None
                original_open = activate.DirFDStore.open_cas
                original_run = activate._run_parent
                original_close = activate.os.close
                opened = []
                try:
                    fixture.run(nonce="1" * 64, prior_present=False)
                    v2_path = Path(directory) / "v2"
                    _write(v2_path, b"payload-v2")
                    populate = os.open(v2_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        fixture.store.put_fd(populate)
                    finally:
                        os.close(populate)
                    payload_fd = os.open(v2_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    before_fds = _fd_count()
                    def fail_second_open(store, digest):
                        if opened:
                            raise activate.ActivationError("forced rollback open failure")
                        fd = original_open(store, digest)
                        opened.append(fd)
                        return fd

                    activate.DirFDStore.open_cas = fail_second_open
                    with self.assertRaisesRegex(activate.ActivationError, "rollback open failure"):
                        _activate_test(
                            root=fixture.root, envelope_bytes=b"fd-envelope", canonical_tar_fd=payload_fd,
                            trusted_root_bytes=b"fd-root", trusted_policy_bytes=b"fd-policy",
                            r1_authority=object(), r2_authority=object(), previous_fd=fixture.payload_input,
                            epoch=2, nonce="2" * 64)
                    self.assertEqual(_fd_count(), before_fds)
                    self.assertEqual(len(opened), 1)
                    with self.assertRaises(OSError):
                        os.fstat(opened[0])

                    # Re-run with both FDs opened.  The rollback descriptor is
                    # the first one closed by the inner finally; even when its
                    # close reports an error after succeeding, the later
                    # payload descriptor must still be closed.
                    opened.clear()
                    activate.DirFDStore.open_cas = lambda store, digest: (
                        opened.append(original_open(store, digest)) or opened[-1])
                    activate._run_parent = lambda **unused: {"phase": "COMMITTED"}
                    faulted = []

                    def close_first_then_raise(fd):
                        if len(opened) == 2 and fd == opened[1] and not faulted:
                            original_close(fd)
                            faulted.append(fd)
                            raise OSError("forced first close failure")
                        return original_close(fd)

                    activate.os.close = close_first_then_raise
                    with self.assertRaisesRegex(OSError, "first close failure"):
                        _activate_test(
                            root=fixture.root, envelope_bytes=b"fd-envelope-2", canonical_tar_fd=payload_fd,
                            trusted_root_bytes=b"fd-root-2", trusted_policy_bytes=b"fd-policy-2",
                            r1_authority=object(), r2_authority=object(), previous_fd=fixture.payload_input,
                            epoch=2, nonce="3" * 64)
                    self.assertEqual(len(opened), 2)
                    for fd in opened:
                        with self.assertRaises(OSError):
                            os.fstat(fd)
                finally:
                    activate.os.close = original_close
                    activate._run_parent = original_run
                    activate.DirFDStore.open_cas = original_open
                    for opened_fd in opened:
                        try:
                            original_close(opened_fd)
                        except OSError:
                            pass
                    if payload_fd is not None:
                        os.close(payload_fd)
                    fixture.close()
        finally:
            activate._ARTIFACT_MODULE = original_artifact

    def test_run_parent_selector_acquisition_failure_closes_only_owned_helper_fd(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            record = activate._helper()
            original_helper_open = activate._open_verified_helper
            original_selector_open = activate._open_locked_selector
            opened_owned = []
            borrowed_helper = None

            def tracking_helper_open(helper_record):
                fd = original_helper_open(helper_record)
                opened_owned.append(fd)
                return fd

            def fail_selector_open(*unused, **unused_kwargs):
                raise activate.ActivationError("forced selector acquisition failure")

            activate._open_verified_helper = tracking_helper_open
            activate._open_locked_selector = fail_selector_open
            baseline = _fd_count()
            try:
                for _ in range(16):
                    with self.assertRaisesRegex(activate.ActivationError, "selector acquisition failure"):
                        fixture.run(helper=record, prior_present=False)
                    self.assertEqual(_fd_count(), baseline)
                    with self.assertRaises(OSError):
                        os.fstat(opened_owned[-1])

                # A caller-owned held helper follows the opposite lifetime:
                # selector acquisition failure must leave it open.
                borrowed_helper = original_helper_open(record)
                borrowed_baseline = _fd_count()
                with self.assertRaisesRegex(activate.ActivationError, "selector acquisition failure"):
                    activate._run_parent(
                        root_fd=fixture.store.fd, payload_fd=fixture.payload_fd, previous_fd=None,
                        epoch=1, nonce="1" * 64, payload_digest=fixture.payload_digest,
                        previous_digest=activate.ZERO_SHA256,
                        authority_digest=hashlib.sha256(b"authority").hexdigest(),
                        trusted_root_digest=hashlib.sha256(b"trusted-root").hexdigest(),
                        envelope_digest=hashlib.sha256(b"envelope").hexdigest(),
                        helper_record=record, helper_fd=borrowed_helper)
                self.assertEqual(_fd_count(), borrowed_baseline)
                self.assertGreaterEqual(os.fstat(borrowed_helper).st_size, 1)
            finally:
                activate._open_locked_selector = original_selector_open
                activate._open_verified_helper = original_helper_open
                for opened_fd in set(opened_owned):
                    if borrowed_helper is not None and opened_fd == borrowed_helper:
                        continue
                    try:
                        os.close(opened_fd)
                    except OSError:
                        pass
                if borrowed_helper is not None:
                    try:
                        os.close(borrowed_helper)
                    except OSError:
                        pass
                fixture.close()

    def test_success_with_stderr_is_rejected_and_timeout_pipe_holder_is_bounded(self):
        with tempfile.TemporaryDirectory() as build_directory, tempfile.TemporaryDirectory() as directory:
            helper = _compile(build_directory)
            fixture = NativeFixture(directory)
            original_runner = activate._run_native_command
            original_timeout = activate.PYTHON_NATIVE_TIMEOUT_SECONDS
            original_cleanup = activate.NATIVE_CLEANUP_TIMEOUT_SECONDS
            holder = Path(directory) / "holder.pid"
            try:
                activate._run_native_command = lambda *unused, **unused_kwargs: (
                    0, b"SP_RELEASE_V3 COMMITTED\n", b"unexpected stderr", False)
                with self.assertRaises(activate.ActivationError):
                    fixture.run(helper=helper, nonce="1" * 64, prior_present=False)
                self.assertFalse((fixture.root / ".sp-release-v2.state").exists())

                script = Path(build_directory) / "pipe-holder"
                _write(script, ("#!/bin/sh\n"
                                "sleep 30 &\n"
                                "printf '%%s' \"$!\" > %s\n"
                                "wait\n" % os.fspath(holder)).encode("ascii"))
                os.chmod(script, 0o700)
                activate.PYTHON_NATIVE_TIMEOUT_SECONDS = 0.15
                activate.NATIVE_CLEANUP_TIMEOUT_SECONDS = 0.15
                fd = os.open(script, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    data, info = activate._read_regular_fd(fd, exact_mode=0o700)
                finally:
                    os.close(fd)
                script_record = activate._HelperRecord(
                    path=os.fspath(script), digest=hashlib.sha256(data).hexdigest(),
                    fingerprint=activate._fingerprint(info))
                activate._run_native_command = original_runner
                started = time.monotonic()
                returncode, stdout, stderr, timed_out = activate._run_native_command(
                    [], helper_record=script_record, pass_fds=(), timeout_message="pipe holder deadline")
                self.assertTrue(timed_out)
                self.assertNotEqual(returncode, 0)
                self.assertIsInstance(stdout, bytes)
                self.assertIsInstance(stderr, bytes)
                # The grandchild deliberately holds both pipes for 30s.  The
                # wrapper must finish through its bounded TERM/KILL cleanup,
                # not by waiting for natural pipe EOF.
                self.assertLess(time.monotonic() - started, 7.0)
            finally:
                activate._run_native_command = original_runner
                activate.PYTHON_NATIVE_TIMEOUT_SECONDS = original_timeout
                activate.NATIVE_CLEANUP_TIMEOUT_SECONDS = original_cleanup
                if holder.exists():
                    try:
                        os.kill(int(holder.read_text(encoding="ascii")), 9)
                    except (OSError, ValueError):
                        pass
                fixture.close()

    def test_canary_selects_data_but_does_not_claim_deployment(self):
        with tempfile.TemporaryDirectory() as directory:
            result = activate.run_canary(payload=b"canary-data", root=directory)
            self.assertEqual(result["phase"], "COMMITTED")
            self.assertEqual(result["semantics"], "selected-data-not-deployed")
            selected = Path(result["directory"]) / "transaction" / "current.payload"
            self.assertEqual(selected.read_bytes(), b"canary-data")
            with self.assertRaises(activate.ActivationError):
                activate.DenyNetworkNotifier().notify("forbidden")

    def test_terminal_state_requires_incremented_epoch_current_digest_and_fresh_nonce(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            candidate_fd = None
            try:
                self.assertEqual(fixture.run()["phase"], "COMMITTED")
                candidate_digest, candidate_fd = _cas_payload(fixture, "payload-v2", b"payload-v2")
                original_state = _state(fixture.root)
                original_current = (fixture.root / "current.payload").read_bytes()
                common = dict(
                    root_fd=fixture.store.fd, payload_fd=candidate_fd, previous_fd=fixture.payload_fd,
                    payload_digest=candidate_digest, previous_digest=fixture.payload_digest,
                    authority_digest=hashlib.sha256(b"authority").hexdigest(),
                    trusted_root_digest=hashlib.sha256(b"trusted-root").hexdigest(),
                    envelope_digest=hashlib.sha256(b"envelope").hexdigest())
                with self.assertRaisesRegex(activate.ActivationError, "semantic preflight"):
                    activate._run_parent(epoch=1, nonce="2" * 64, **common)
                with self.assertRaisesRegex(activate.ActivationError, "semantic preflight"):
                    activate._run_parent(epoch=2, nonce="1" * 64, **common)
                self.assertEqual(_state(fixture.root), original_state)
                self.assertEqual((fixture.root / "current.payload").read_bytes(), original_current)
            finally:
                if candidate_fd is not None:
                    os.close(candidate_fd)
                fixture.close()

    def test_native_rejects_declared_input_digest_mismatch_before_durable_changes(self):
        for field in ("payload_digest", "previous_digest"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                try:
                    arguments = {field: hashlib.sha256((field + "-wrong").encode()).hexdigest()}
                    with self.assertRaises(activate.ActivationError):
                        fixture.run(prior_present=(field == "previous_digest"), **arguments)
                    self.assertFalse((fixture.root / ".sp-release-v2.state").exists())
                    self.assertFalse((fixture.root / "current.payload").exists())
                    self.assertEqual(list(fixture.root.glob(".sp-release-v2.nonce.*")), [])
                finally:
                    fixture.close()

    def test_malformed_or_unsafe_durable_state_is_never_overwritten(self):
        cases = ("short", "version", "phase", "epoch", "pid", "nonce", "digest", "mode", "hardlink")
        for label in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = NativeFixture(directory)
                candidate_fd = None
                try:
                    fixture.run()
                    candidate_digest, candidate_fd = _cas_payload(fixture, "payload-v2", b"payload-v2")
                    state_path = fixture.root / ".sp-release-v2.state"
                    raw = bytearray(state_path.read_bytes())
                    if label == "short":
                        state_path.write_bytes(raw[:-1])
                    elif label == "version":
                        struct.pack_into("<I", raw, 4, 99)
                        state_path.write_bytes(raw)
                    elif label == "phase":
                        struct.pack_into("<I", raw, 8, 99)
                        state_path.write_bytes(raw)
                    elif label == "epoch":
                        _put_u64(raw, STATE_OFFSETS["epoch"], 0)
                        state_path.write_bytes(raw)
                    elif label == "pid":
                        struct.pack_into("<i", raw, STATE_OFFSETS["activation_pid"], 1)
                        state_path.write_bytes(raw)
                    elif label == "nonce":
                        raw[STATE_OFFSETS["nonce"]:STATE_OFFSETS["nonce"] + 32] = ZERO_DIGEST
                        state_path.write_bytes(raw)
                    elif label == "digest":
                        raw[STATE_OFFSETS["payload_digest"]:STATE_OFFSETS["payload_digest"] + 32] = ZERO_DIGEST
                        state_path.write_bytes(raw)
                    elif label == "mode":
                        os.chmod(state_path, 0o644)
                    else:
                        os.link(state_path, fixture.root / "state-hardlink")
                    state_before = state_path.read_bytes()
                    metadata_before = state_path.stat()
                    with self.assertRaisesRegex(activate.ActivationError, "semantic preflight"):
                        activate._run_parent(
                            root_fd=fixture.store.fd, payload_fd=candidate_fd,
                            previous_fd=fixture.payload_fd, epoch=2, nonce="c" * 64,
                            payload_digest=candidate_digest, previous_digest=fixture.payload_digest,
                            authority_digest=hashlib.sha256(b"authority-next").hexdigest(),
                            trusted_root_digest=hashlib.sha256(b"root-next").hexdigest(),
                            envelope_digest=hashlib.sha256(b"envelope-next").hexdigest())
                    metadata_after = state_path.stat()
                    self.assertEqual(state_path.read_bytes(), state_before)
                    self.assertEqual(metadata_after.st_mode, metadata_before.st_mode)
                    self.assertEqual(metadata_after.st_nlink, metadata_before.st_nlink)
                    self.assertEqual((fixture.root / "current.payload").read_bytes(), b"payload-v1")
                finally:
                    if candidate_fd is not None:
                        os.close(candidate_fd)
                    fixture.close()

    def test_nonce_journal_is_bounded_and_fails_closed_without_overwriting_terminal_state(self):
        with tempfile.TemporaryDirectory() as build_directory, tempfile.TemporaryDirectory() as directory:
            helper = _compile(build_directory, "SP_MAX_NONCE_MARKERS=2")
            fixture = NativeFixture(directory)
            second_fd = third_fd = None
            try:
                fixture.run(helper=helper)
                second_digest, second_fd = _cas_payload(fixture, "payload-v2", b"payload-v2")
                third_digest, third_fd = _cas_payload(fixture, "payload-v3", b"payload-v3")
                activate._run_parent(
                    root_fd=fixture.store.fd, payload_fd=second_fd, previous_fd=fixture.payload_fd,
                    payload_digest=second_digest, previous_digest=fixture.payload_digest,
                    authority_digest=hashlib.sha256(b"authority-2").hexdigest(),
                    trusted_root_digest=hashlib.sha256(b"trusted-root-2").hexdigest(),
                    envelope_digest=hashlib.sha256(b"envelope-2").hexdigest(), helper_record=helper,
                    epoch=2, nonce="2" * 64)
                state_before = _state(fixture.root)
                current_before = (fixture.root / "current.payload").read_bytes()
                with self.assertRaisesRegex(activate.ActivationError, "semantic preflight"):
                    activate._run_parent(
                        root_fd=fixture.store.fd, payload_fd=third_fd, previous_fd=second_fd,
                        payload_digest=third_digest, previous_digest=second_digest,
                        authority_digest=hashlib.sha256(b"authority-3").hexdigest(),
                        trusted_root_digest=hashlib.sha256(b"trusted-root-3").hexdigest(),
                        envelope_digest=hashlib.sha256(b"envelope-3").hexdigest(), helper_record=helper,
                        epoch=3, nonce="3" * 64)
                self.assertEqual(_state(fixture.root), state_before)
                self.assertEqual((fixture.root / "current.payload").read_bytes(), current_before)
                markers = list(fixture.root.glob(".sp-release-v2.nonce.*"))
                self.assertEqual(len(markers), 2)
                for marker in markers:
                    info = marker.lstat()
                    self.assertEqual(info.st_mode & 0o777, 0o600)
                    self.assertEqual(info.st_nlink, 1)
            finally:
                if third_fd is not None:
                    os.close(third_fd)
                if second_fd is not None:
                    os.close(second_fd)
                fixture.close()

    def test_second_terminal_transaction_uses_selected_current_as_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            third_fd = None
            try:
                fixture.run()
                second = Path(directory) / "payload-v2.bin"
                _write(second, b"payload-v2")
                second_input = os.open(second, os.O_RDONLY)
                try:
                    second_digest = fixture.store.put_fd(second_input)
                finally:
                    os.close(second_input)
                second_fd = fixture.store.open_cas(second_digest)
                old_fd = fixture.store.open_cas(fixture.payload_digest)
                try:
                    outcome = activate._run_parent(
                        root_fd=fixture.store.fd, payload_fd=second_fd, previous_fd=old_fd,
                        epoch=2, nonce="2" * 64, payload_digest=second_digest,
                        previous_digest=fixture.payload_digest,
                        authority_digest=hashlib.sha256(b"authority-2").hexdigest(),
                        trusted_root_digest=hashlib.sha256(b"root-2").hexdigest(),
                        envelope_digest=hashlib.sha256(b"envelope-2").hexdigest())
                    state_before_replay = _state(fixture.root)
                    third_digest, third_fd = _cas_payload(fixture, "payload-v3.bin", b"payload-v3")
                    with self.assertRaisesRegex(activate.ActivationError, "semantic preflight"):
                        activate._run_parent(
                            root_fd=fixture.store.fd, payload_fd=third_fd, previous_fd=second_fd,
                            epoch=3, nonce="1" * 64, payload_digest=third_digest,
                            previous_digest=second_digest,
                            authority_digest=hashlib.sha256(b"authority-3").hexdigest(),
                            trusted_root_digest=hashlib.sha256(b"root-3").hexdigest(),
                            envelope_digest=hashlib.sha256(b"envelope-3").hexdigest())
                    self.assertEqual(_state(fixture.root), state_before_replay)
                    marker = fixture.root / (".sp-release-v2.nonce." + "1" * 64)
                    corrupt = bytearray(marker.read_bytes())
                    corrupt[0] ^= 0xFF
                    marker.write_bytes(corrupt)
                    with self.assertRaisesRegex(activate.ActivationError, "semantic preflight"):
                        activate._run_parent(
                            root_fd=fixture.store.fd, payload_fd=third_fd, previous_fd=second_fd,
                            epoch=4, nonce="4" * 64, payload_digest=third_digest,
                            previous_digest=second_digest,
                            authority_digest=hashlib.sha256(b"authority-4").hexdigest(),
                            trusted_root_digest=hashlib.sha256(b"root-4").hexdigest(),
                            envelope_digest=hashlib.sha256(b"envelope-4").hexdigest())
                    self.assertEqual(_state(fixture.root), state_before_replay)
                finally:
                    if third_fd is not None:
                        os.close(third_fd)
                    os.close(second_fd)
                    os.close(old_fd)
                self.assertEqual(outcome["phase"], "COMMITTED")
                self.assertEqual((fixture.root / "current.payload").read_bytes(), b"payload-v2")
                self.assertEqual(_phase(_state(fixture.root)), 5)
            finally:
                fixture.close()

    def test_parent_crash_at_every_durable_nonterminal_boundary_blocks_restart(self):
        cases = ((1, ()), (2, ()), (3, ()), (4, ("SP_TEST_OPERATION_FAILURE_ROLE=1",)),
                 (7, ("SP_TEST_WORKER_AFTER_READY_ROLE=1",)))
        with tempfile.TemporaryDirectory() as build_directory:
            helpers = {phase: _compile(build_directory, "SP_TEST_CRASH_AFTER_PHASE=%d" % phase, *extra)
                       for phase, extra in cases}
            for phase, _ in cases:
                with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                    fixture = NativeFixture(directory)
                    try:
                        with self.assertRaises(activate.ActivationError):
                            fixture.run(helper=helpers[phase])
                        time.sleep(0.05)
                        raw_before = _state(fixture.root)
                        self.assertEqual(_phase(raw_before), phase)
                        current_path = fixture.root / "current.payload"
                        current_before = current_path.read_bytes() if current_path.exists() else None
                        with self.assertRaisesRegex(activate.ActivationError, "semantic preflight"):
                            fixture.run(epoch=2, nonce=("%x" % (phase + 4)) * 64)
                        self.assertEqual(_state(fixture.root), raw_before)
                        current_after = current_path.read_bytes() if current_path.exists() else None
                        self.assertEqual(current_after, current_before)
                    finally:
                        fixture.close()

    def test_parent_crash_after_each_terminal_boundary_allows_strict_next_epoch(self):
        cases = ((5, ()), (6, ("SP_TEST_OPERATION_FAILURE_ROLE=1",)))
        with tempfile.TemporaryDirectory() as build_directory:
            helpers = {phase: _compile(build_directory, "SP_TEST_CRASH_AFTER_PHASE=%d" % phase, *extra)
                       for phase, extra in cases}
            for phase, _ in cases:
                with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                    fixture = NativeFixture(directory)
                    next_fd = None
                    try:
                        with self.assertRaises(activate.ActivationError):
                            fixture.run(helper=helpers[phase])
                        self.assertEqual(_phase(_state(fixture.root)), phase)
                        current = fixture.root / "current.payload"
                        if phase == 5:
                            selected_digest = fixture.payload_digest
                            previous_fd = fixture.payload_fd
                            self.assertEqual(current.read_bytes(), b"payload-v1")
                        else:
                            selected_digest = activate.ZERO_SHA256
                            previous_fd = None
                            self.assertFalse(current.exists())
                        next_path = Path(directory) / "payload-v2"
                        _write(next_path, b"payload-v2")
                        next_input = os.open(next_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                        try:
                            next_digest = fixture.store.put_fd(next_input)
                        finally:
                            os.close(next_input)
                        next_fd = fixture.store.open_cas(next_digest)
                        outcome = activate._run_parent(
                            root_fd=fixture.store.fd, payload_fd=next_fd, previous_fd=previous_fd,
                            epoch=2, nonce=("a" if phase == 5 else "b") * 64,
                            payload_digest=next_digest, previous_digest=selected_digest,
                            authority_digest=hashlib.sha256(b"authority-next").hexdigest(),
                            trusted_root_digest=hashlib.sha256(b"root-next").hexdigest(),
                            envelope_digest=hashlib.sha256(b"envelope-next").hexdigest())
                        self.assertEqual(outcome["phase"], "COMMITTED")
                        self.assertEqual(_u64(_state(fixture.root), STATE_OFFSETS["epoch"]), 2)
                        self.assertEqual(current.read_bytes(), b"payload-v2")
                    finally:
                        if next_fd is not None:
                            os.close(next_fd)
                        fixture.close()

    def test_worker_after_ready_exit_causes_sigpipe_safe_uncertain_and_no_retry(self):
        with tempfile.TemporaryDirectory() as build_directory, tempfile.TemporaryDirectory() as directory:
            helper = _compile(build_directory, "SP_TEST_WORKER_AFTER_READY_ROLE=1")
            fixture = NativeFixture(directory)
            try:
                with self.assertRaises(activate.ActivationError):
                    fixture.run(helper=helper)
                self.assertEqual(_phase(_state(fixture.root)), 7)
                state_before = _state(fixture.root)
                with self.assertRaisesRegex(activate.ActivationError, "semantic preflight"):
                    fixture.run(epoch=2, nonce="8" * 64)
                self.assertEqual(_state(fixture.root), state_before)
            finally:
                fixture.close()

    def test_worker_before_ready_and_kqueue_registration_failure_are_reaped_without_state(self):
        with tempfile.TemporaryDirectory() as build_directory:
            helpers = (_compile(build_directory, "SP_TEST_WORKER_BEFORE_READY_ROLE=1"),
                       _compile(build_directory, "SP_TEST_REGISTER_FAILURE=1"))
            for index, helper in enumerate(helpers):
                with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                    fixture = NativeFixture(directory)
                    try:
                        started = time.monotonic()
                        with self.assertRaises(activate.ActivationError):
                            fixture.run(helper=helper, nonce=("%x" % (index + 9)) * 64)
                        self.assertLess(time.monotonic() - started, 4)
                        self.assertFalse((fixture.root / ".sp-release-v2.state").exists())
                        self.assertFalse((fixture.root / "current.payload").exists())
                    finally:
                        fixture.close()

    def test_stalled_worker_hits_shared_deadline_then_term_kill_cleanup(self):
        with tempfile.TemporaryDirectory() as build_directory, tempfile.TemporaryDirectory() as directory:
            helper = _compile(build_directory, "SP_TEST_WORKER_STALL_ROLE=1", "SP_TOTAL_TIMEOUT_MS=250",
                              "SP_CLEANUP_TIMEOUT_MS=600")
            fixture = NativeFixture(directory)
            try:
                started = time.monotonic()
                with self.assertRaises(activate.ActivationError):
                    fixture.run(helper=helper)
                self.assertLess(time.monotonic() - started, 4)
                self.assertEqual(_phase(_state(fixture.root)), 7)
            finally:
                fixture.close()

    def test_python_wrapper_timeout_terminates_parent_and_leaves_no_direct_children(self):
        with tempfile.TemporaryDirectory() as build_directory, tempfile.TemporaryDirectory() as directory:
            helper = _compile(build_directory, "SP_TEST_WORKER_STALL_ROLE=1", "SP_TOTAL_TIMEOUT_MS=60000",
                              "SP_CLEANUP_TIMEOUT_MS=300")
            fixture = NativeFixture(directory)
            original_timeout = activate.PYTHON_NATIVE_TIMEOUT_SECONDS
            activate.PYTHON_NATIVE_TIMEOUT_SECONDS = 3.0
            try:
                started = time.monotonic()
                with self.assertRaisesRegex(activate.ActivationError, "exceeded total deadline"):
                    fixture.run(helper=helper)
                self.assertLess(time.monotonic() - started, 5)
                raw = _state(fixture.root)
                self.assertEqual(_phase(raw), 7)
                for pid in struct.unpack_from("<ii", raw, STATE_OFFSETS["activation_pid"]):
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
            finally:
                activate.PYTHON_NATIVE_TIMEOUT_SECONDS = original_timeout
                fixture.close()

    def test_parent_crash_closes_worker_sockets_and_children_exit_on_eof(self):
        with tempfile.TemporaryDirectory() as build_directory, tempfile.TemporaryDirectory() as directory:
            helper = _compile(build_directory, "SP_TEST_CRASH_AFTER_PHASE=1")
            fixture = NativeFixture(directory)
            try:
                with self.assertRaises(activate.ActivationError):
                    fixture.run(helper=helper)
                raw = _state(fixture.root)
                activation_pid, rollback_pid = struct.unpack_from("<ii", raw, STATE_OFFSETS["activation_pid"])
                deadline = time.monotonic() + 2
                alive = {activation_pid, rollback_pid}
                while alive and time.monotonic() < deadline:
                    for pid in tuple(alive):
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            alive.remove(pid)
                    if alive:
                        time.sleep(0.02)
                self.assertEqual(alive, set())
            finally:
                fixture.close()

    def test_cas_recovers_nlink_two_publication_and_orphan_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            source = Path(directory) / "source.bin"
            _write(source, b"cas-recovery")
            source_fd = os.open(source, os.O_RDONLY)
            try:
                with activate.DirFDStore(root) as store:
                    digest = store.put_fd(source_fd)
                    objects = store._directory("objects")
                    try:
                        temporary = ".%s.%s.tmp" % (digest, "a" * 32)
                        os.link(digest, temporary, src_dir_fd=objects, dst_dir_fd=objects, follow_symlinks=False)
                        os.fsync(objects)
                    finally:
                        os.close(objects)
                with activate.DirFDStore(root) as recovered:
                    fd = recovered.open_cas(digest)
                    try:
                        self.assertEqual(os.read(fd, 64), b"cas-recovery")
                        self.assertEqual(os.fstat(fd).st_nlink, 1)
                    finally:
                        os.close(fd)
                    objects = recovered._directory("objects")
                    try:
                        self.assertNotIn(temporary, os.listdir(objects))
                        orphan = ".%s.%s.tmp" % ("b" * 64, "c" * 32)
                        orphan_fd = os.open(orphan, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=objects)
                        try:
                            os.write(orphan_fd, b"orphan")
                            os.fsync(orphan_fd)
                        finally:
                            os.close(orphan_fd)
                        os.fsync(objects)
                    finally:
                        os.close(objects)
                with activate.DirFDStore(root) as recovered_again:
                    with recovered_again._locked_objects() as objects:
                        self.assertNotIn(orphan, os.listdir(objects))
            finally:
                os.close(source_fd)

    def test_existing_hardlinked_locks_are_rejected_without_chmod_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cas-root"
            root.mkdir(mode=0o700)
            victim = Path(directory) / "cas-victim"
            _write(victim, b"victim")
            os.chmod(victim, 0o644)
            os.link(victim, root / ".sp-release-v2.cas.lock")
            with self.assertRaises(activate.ActivationError):
                activate.DirFDStore(root)
            self.assertEqual(victim.stat().st_mode & 0o777, 0o644)
            self.assertEqual(victim.stat().st_nlink, 2)

        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            try:
                victim = Path(directory) / "native-victim"
                _write(victim, b"victim")
                os.chmod(victim, 0o644)
                os.link(victim, fixture.root / ".sp-release-v2.lock")
                with self.assertRaises(activate.ActivationError):
                    fixture.run()
                self.assertEqual(victim.stat().st_mode & 0o777, 0o644)
                self.assertEqual(victim.stat().st_nlink, 2)
                self.assertFalse((fixture.root / ".sp-release-v2.state").exists())
            finally:
                fixture.close()

    def test_cas_lock_contention_has_a_real_cross_process_deadline(self):
        self.assertLess(activate.CAS_LOCK_TIMEOUT_SECONDS, activate.NATIVE_TOTAL_TIMEOUT_SECONDS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir(mode=0o700)
            ready_read, ready_write = os.pipe()
            release_read, release_write = os.pipe()
            process = os.fork()
            if process == 0:
                os.close(ready_read)
                os.close(release_write)
                exit_code = 1
                try:
                    with activate.DirFDStore(root) as holder:
                        with holder._locked_objects():
                            os.write(ready_write, b"R")
                            if os.read(release_read, 1) != b"X":
                                raise RuntimeError("release pipe closed")
                    exit_code = 0
                finally:
                    os.close(ready_write)
                    os.close(release_read)
                    os._exit(exit_code)

            os.close(ready_write)
            os.close(release_read)
            released = waited = False
            child_status = None
            original_timeout = activate.CAS_LOCK_TIMEOUT_SECONDS
            try:
                readable, _, _ = select.select([ready_read], [], [], 5)
                self.assertEqual(readable, [ready_read])
                self.assertEqual(os.read(ready_read, 1), b"R")
                activate.CAS_LOCK_TIMEOUT_SECONDS = 0.2
                with activate.DirFDStore(root) as contender:
                    started = time.monotonic()
                    with self.assertRaisesRegex(activate.ActivationError, "busy after bounded wait"):
                        contender.put_bytes(b"must-not-publish")
                    self.assertLess(time.monotonic() - started, 1)
                    blocked_digest = hashlib.sha256(b"must-not-publish").hexdigest()
                    self.assertFalse((root / "objects" / blocked_digest).exists())
                    os.write(release_write, b"X")
                    released = True
                    _, child_status = os.waitpid(process, 0)
                    waited = True
                    self.assertEqual(contender.put_bytes(b"after-release"),
                                     hashlib.sha256(b"after-release").hexdigest())
                    with self.assertRaisesRegex(RuntimeError, "body-failure"):
                        with contender._locked_objects():
                            raise RuntimeError("body-failure")
                    with contender._locked_objects() as objects:
                        self.assertIsInstance(objects, int)
            finally:
                activate.CAS_LOCK_TIMEOUT_SECONDS = original_timeout
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

    def test_dirfdstore_constructor_failures_do_not_leak_root_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            unsafe_root = Path(directory) / "unsafe-root"
            unsafe_root.mkdir(mode=0o700)
            os.chmod(unsafe_root, 0o755)
            before = _fd_count()
            for _ in range(32):
                with self.assertRaises(activate.ActivationError):
                    activate.DirFDStore(unsafe_root)
            self.assertEqual(_fd_count(), before)

            lock_root = Path(directory) / "lock-root"
            lock_root.mkdir(mode=0o700)
            victim = Path(directory) / "lock-victim"
            _write(victim, b"unsafe-lock")
            os.chmod(victim, 0o644)
            os.link(victim, lock_root / ".sp-release-v2.cas.lock")
            before = _fd_count()
            for _ in range(32):
                with self.assertRaises(activate.ActivationError):
                    activate.DirFDStore(lock_root)
            self.assertEqual(_fd_count(), before)

    def test_helper_is_snapshotted_pinned_and_rechecked_before_each_exec(self):
        record = activate._helper()
        self.assertEqual(hashlib.sha256((ROOT / "native" / "sp_release_seatbelt_v2.c").read_bytes()).hexdigest(),
                         activate.NATIVE_SOURCE_SHA256)
        self.assertEqual(Path(record.path).parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(Path(record.path).stat().st_mode & 0o777, 0o700)
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "helper"
            _write(copied, b"one")
            os.chmod(copied, 0o700)
            fd = os.open(copied, os.O_RDONLY)
            try:
                data, info = activate._read_regular_fd(fd, exact_mode=0o700)
            finally:
                os.close(fd)
            fake = activate._HelperRecord(path=os.fspath(copied), digest=hashlib.sha256(data).hexdigest(),
                                          fingerprint=activate._fingerprint(info))
            os.chmod(copied, 0o600)
            with self.assertRaises(activate.ActivationError):
                activate._verify_helper(fake)

    def test_activate_verified_calls_full_raw_reverify_and_binds_all_digests(self):
        class Proof:
            def __init__(self, authority, root, payload, envelope):
                self.authority_digest = authority
                self.trusted_root_digest = root
                self.payload_digest = payload
                self.envelope_digest = envelope

        class FakeArtifact:
            ActivationReverifyResult = Proof
            calls = []

            @classmethod
            def reverify_for_activation(cls, **kwargs):
                cls.calls.append(kwargs)
                authority = hashlib.sha256(b"out-of-band-authority").hexdigest()
                return Proof(authority, hashlib.sha256(kwargs["trusted_root_bytes"]).hexdigest(),
                             hashlib.sha256(kwargs["payload"]).hexdigest(),
                             hashlib.sha256(kwargs["envelope_bytes"]).hexdigest())

        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeFixture(directory)
            original = activate._ARTIFACT_MODULE
            activate._ARTIFACT_MODULE = FakeArtifact
            try:
                outcome = _activate_test(
                    root=fixture.root, envelope_bytes=b"raw-envelope", canonical_tar_fd=fixture.payload_input,
                    trusted_root_bytes=b"external-root", trusted_policy_bytes=b"external-policy",
                    r1_authority=object(), r2_authority=object(), previous_fd=None,
                    epoch=1, nonce="d" * 64, gh_runner="test-offline-runner")
            finally:
                activate._ARTIFACT_MODULE = original
                fixture.close()
            self.assertEqual(outcome["phase"], "COMMITTED")
            call = FakeArtifact.calls[0]
            self.assertEqual(call["envelope_bytes"], b"raw-envelope")
            self.assertEqual(call["payload"], b"payload-v1")
            self.assertEqual(call["gh_runner"], "test-offline-runner")
            raw = _state(Path(directory) / "root")
            self.assertEqual(raw[STATE_OFFSETS["authority_digest"]:STATE_OFFSETS["authority_digest"] + 32],
                             bytes.fromhex(hashlib.sha256(b"out-of-band-authority").hexdigest()))
            self.assertEqual(raw[STATE_OFFSETS["trusted_root_digest"]:STATE_OFFSETS["trusted_root_digest"] + 32],
                             bytes.fromhex(hashlib.sha256(b"external-root").hexdigest()))
            self.assertEqual(raw[STATE_OFFSETS["envelope_digest"]:STATE_OFFSETS["envelope_digest"] + 32],
                             bytes.fromhex(hashlib.sha256(b"raw-envelope").hexdigest()))

    def test_activate_verified_rejects_non_private_input_before_reverification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir(mode=0o700)
            payload = Path(directory) / "payload.tar"
            previous = Path(directory) / "previous.tar"
            _write(payload, b"payload")
            _write(previous, b"previous")
            os.chmod(payload, 0o644)
            payload_fd = os.open(payload, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(activate.ActivationError, "metadata is unsafe"):
                    _activate_test(
                        root=root, envelope_bytes=b"envelope", canonical_tar_fd=payload_fd,
                        trusted_root_bytes=b"root", trusted_policy_bytes=b"policy",
                        r1_authority=object(), r2_authority=object(), previous_fd=None,
                        epoch=1, nonce="f" * 64)
            finally:
                os.close(payload_fd)
            self.assertEqual(list(root.iterdir()), [])

    def test_post_reverify_same_size_input_switch_leaves_root_inventory_unchanged(self):
        class Proof:
            def __init__(self, *, payload, trusted_root, envelope):
                self.authority_digest = hashlib.sha256(b"switch-authority").hexdigest()
                self.trusted_root_digest = hashlib.sha256(trusted_root).hexdigest()
                self.payload_digest = hashlib.sha256(payload).hexdigest()
                self.envelope_digest = hashlib.sha256(envelope).hexdigest()

        class SwitchingArtifact:
            ActivationReverifyResult = Proof
            payload_path = None

            @classmethod
            def reverify_for_activation(cls, **kwargs):
                replacement = b"payload-v2"
                self.assertEqual(len(replacement), len(kwargs["payload"]))
                switched = os.open(cls.payload_path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    self.assertEqual(os.pwrite(switched, replacement, 0), len(replacement))
                    os.fsync(switched)
                finally:
                    os.close(switched)
                return Proof(payload=kwargs["payload"], trusted_root=kwargs["trusted_root_bytes"],
                             envelope=kwargs["envelope_bytes"])

        original = activate._ARTIFACT_MODULE
        activate._ARTIFACT_MODULE = SwitchingArtifact
        try:
            for preexisting in (False, True):
                with self.subTest(preexisting=preexisting), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory) / "root"
                    root.mkdir(mode=0o700)
                    _write(root / "sentinel", b"must-remain-identical")
                    payload_path = Path(directory) / "payload"
                    previous_path = Path(directory) / "previous"
                    _write(payload_path, b"payload-v1")
                    _write(previous_path, b"previous-v0")
                    payload_fd = os.open(payload_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    previous_fd = os.open(previous_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    SwitchingArtifact.payload_path = payload_path
                    before = _root_inventory(root)
                    descriptors_before = _fd_count()
                    try:
                        with self.assertRaisesRegex(activate.ActivationError, "changed after stable snapshot"):
                            _activate_test(
                                root=root, envelope_bytes=b"switch-envelope", canonical_tar_fd=payload_fd,
                                trusted_root_bytes=b"switch-root", trusted_policy_bytes=b"switch-policy",
                                r1_authority=object(), r2_authority=object(), previous_fd=None,
                                epoch=1, nonce="9" * 64)
                        self.assertEqual(_fd_count(), descriptors_before)
                    finally:
                        os.close(payload_fd)
                        os.close(previous_fd)
                    self.assertEqual(payload_path.read_bytes(), b"payload-v2")
                    self.assertEqual(_root_inventory(root), before)
        finally:
            activate._ARTIFACT_MODULE = original

    def test_previous_snapshot_failure_occurs_before_reverify_and_root_writes(self):
        class BombArtifact:
            class ActivationReverifyResult:
                pass

            @staticmethod
            def reverify_for_activation(**unused):
                raise AssertionError("reverification must not run")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir(mode=0o700)
            _write(root / "sentinel", b"unchanged")
            _write(root / "current.payload", b"established-selection")
            payload_path = Path(directory) / "payload"
            previous_path = Path(directory) / "previous"
            _write(payload_path, b"payload")
            _write(previous_path, b"previous")
            os.chmod(previous_path, 0o644)
            payload_fd = os.open(payload_path, os.O_RDONLY)
            previous_fd = os.open(previous_path, os.O_RDONLY)
            original = activate._ARTIFACT_MODULE
            activate._ARTIFACT_MODULE = BombArtifact
            before = _root_inventory(root)
            descriptors_before = _fd_count()
            try:
                with self.assertRaisesRegex(activate.ActivationError, "metadata is unsafe"):
                    _activate_test(
                        root=root, envelope_bytes=b"envelope", canonical_tar_fd=payload_fd,
                        trusted_root_bytes=b"root", trusted_policy_bytes=b"policy",
                        r1_authority=object(), r2_authority=object(), previous_fd=previous_fd,
                        epoch=1, nonce="a" * 64)
                self.assertEqual(_fd_count(), descriptors_before)
            finally:
                activate._ARTIFACT_MODULE = original
                os.close(payload_fd)
                os.close(previous_fd)
            self.assertEqual(_root_inventory(root), before)

    def test_reverification_proof_digest_mismatch_precedes_all_root_writes(self):
        class WrongProof:
            authority_digest = hashlib.sha256(b"authority").hexdigest()
            trusted_root_digest = hashlib.sha256(b"trusted-root").hexdigest()
            payload_digest = hashlib.sha256(b"wrong-payload").hexdigest()
            envelope_digest = hashlib.sha256(b"envelope").hexdigest()

        class WrongArtifact:
            ActivationReverifyResult = WrongProof

            @staticmethod
            def reverify_for_activation(**unused):
                return WrongProof()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir(mode=0o700)
            _write(root / "sentinel", b"unchanged")
            payload_path = Path(directory) / "payload"
            previous_path = Path(directory) / "previous"
            _write(payload_path, b"payload")
            _write(previous_path, b"previous")
            payload_fd = os.open(payload_path, os.O_RDONLY)
            previous_fd = os.open(previous_path, os.O_RDONLY)
            original = activate._ARTIFACT_MODULE
            activate._ARTIFACT_MODULE = WrongArtifact
            before = _root_inventory(root)
            try:
                with self.assertRaisesRegex(activate.ActivationError, "proof digest differs"):
                    _activate_test(
                        root=root, envelope_bytes=b"envelope", canonical_tar_fd=payload_fd,
                        trusted_root_bytes=b"trusted-root", trusted_policy_bytes=b"policy",
                        r1_authority=object(), r2_authority=object(), previous_fd=None,
                        epoch=1, nonce="b" * 64)
            finally:
                activate._ARTIFACT_MODULE = original
                os.close(payload_fd)
                os.close(previous_fd)
            self.assertEqual(_root_inventory(root), before)

    def test_activate_verified_integrates_with_real_artifact_reverification(self):
        artifact_fixture = importlib.import_module("tests.test_sp_release_artifact_v2")
        payload = artifact_fixture._canonical_tar()
        files = artifact_fixture.artifact.parse_canonical_ustar(payload, artifact_fixture.POLICY_DOCUMENT)
        inventory = artifact_fixture.artifact._inventory_sha256(files)
        r1 = dataclasses.replace(artifact_fixture._authority(1, 9, 201),
                                 candidate_input_tree_sha256=inventory)
        r2 = dataclasses.replace(artifact_fixture._authority(2, 10, 202),
                                 candidate_input_tree_sha256=inventory)
        receipt1, r1 = artifact_fixture._receipt(payload, r1, b"activation-raw-one")
        receipt2, r2 = artifact_fixture._receipt(payload, r2, b"activation-raw-two")
        online_calls = []
        verified1 = artifact_fixture._online(r1, payload, receipt1, online_calls)
        verified2 = artifact_fixture._online(r2, payload, receipt2, online_calls)
        envelope = artifact_fixture.artifact.seal_receipt_pair(verified1, verified2)[0]
        activation_artifact = activate._artifact_module()
        activation_r1 = activation_artifact.ExpectedAuthority(**dataclasses.asdict(r1))
        activation_r2 = activation_artifact.ExpectedAuthority(**dataclasses.asdict(r2))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir(mode=0o700)
            payload_path = Path(directory) / "payload.tar"
            previous_path = Path(directory) / "previous.tar"
            _write(payload_path, payload)
            _write(previous_path, b"previous-data-only")
            payload_fd = os.open(payload_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            previous_fd = os.open(previous_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            offline_calls = []
            try:
                outcome = _activate_test(
                    root=root, envelope_bytes=envelope, canonical_tar_fd=payload_fd,
                    trusted_root_bytes=artifact_fixture.TRUSTED_ROOT,
                    trusted_policy_bytes=artifact_fixture.TRUSTED_POLICY,
                    r1_authority=activation_r1, r2_authority=activation_r2, previous_fd=None,
                    epoch=1, nonce="e" * 64,
                    gh_runner=artifact_fixture._gh_runner([activation_r1, activation_r2], offline_calls))
            finally:
                os.close(payload_fd)
                os.close(previous_fd)

            self.assertEqual(outcome["phase"], "COMMITTED")
            self.assertEqual(len(offline_calls), 4)
            self.assertTrue(all(call[0][2] == "verify" for call in offline_calls))
            raw = _state(root)
            self.assertEqual(raw[STATE_OFFSETS["payload_digest"]:STATE_OFFSETS["payload_digest"] + 32],
                             hashlib.sha256(payload).digest())
            self.assertEqual(raw[STATE_OFFSETS["trusted_root_digest"]:STATE_OFFSETS["trusted_root_digest"] + 32],
                             hashlib.sha256(artifact_fixture.TRUSTED_ROOT).digest())
            self.assertEqual(raw[STATE_OFFSETS["envelope_digest"]:STATE_OFFSETS["envelope_digest"] + 32],
                             hashlib.sha256(envelope).digest())


if __name__ == "__main__":
    unittest.main()
