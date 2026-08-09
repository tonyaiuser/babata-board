import hashlib
import importlib.util
import platform
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _c_function_body(source, name):
    """Return exactly one C function body, with lexical brace matching.

    Tests that merely take the source from a convenient string literal onward
    accidentally include later functions (and used to miss the relevant
    recovery definition entirely).  This small scanner understands C comments
    and quoted strings sufficiently to bind each assertion to the function it
    names.
    """
    signature = re.search(
        rf"(?m)^static\s+[A-Za-z_][\w\s\*]*?\b{re.escape(name)}\s*\(", source
    )
    if signature is None:
        raise AssertionError("C function %r was not found" % name)
    opening = source.find("{", signature.end())
    if opening < 0:
        raise AssertionError("C function %r has no body" % name)

    depth, index, state = 0, opening, "code"
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "/":
                state, index = "line-comment", index + 2
                continue
            if char == "/" and following == "*":
                state, index = "block-comment", index + 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "character"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[opening:index + 1]
        elif state == "line-comment":
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and following == "/":
                state, index = "code", index + 2
                continue
        elif state in ("string", "character"):
            if char == "\\":
                index += 2
                continue
            if (state == "string" and char == '"') or (state == "character" and char == "'"):
                state = "code"
        index += 1
    raise AssertionError("C function %r has an unclosed body" % name)


@unittest.skipUnless(platform.system() == "Darwin", "Darwin Seatbelt boundary")
class SeatbeltContractTests(unittest.TestCase):
    def test_source_contract_is_exact_pid_fixed_protocol_and_no_command_runner(self):
        source = (ROOT / "native" / "sp_release_seatbelt_v2.c").read_text(encoding="utf-8")
        for required in ("SO_NOSIGPIPE", "SIGPIPE", "EVFILT_PROC", "NOTE_EXIT", "waitid", "WNOWAIT", "waitpid",
                         "WIFEXITED", "WEXITSTATUS", "process-fork", "process-exec", "network*", "sandbox_check",
                         "execve(\"/dev/null/", "ENOTDIR", "GO_COMMITTED", "ROLLBACK_GO", "RECOVERY_REQUIRED",
                         "authority_digest", "trusted_root_digest", "envelope_digest", "helper_digest",
                         "current.payload is an atomically selected"):
            self.assertIn(required, source)
        for forbidden in ("killpg", "setpgid", "getpgid", "system(", "popen(", "execl(", "execvp("):
            self.assertNotIn(forbidden, source)

    def test_enotdir_is_explicitly_not_claimed_as_sandbox_errno(self):
        source = (ROOT / "native" / "sp_release_seatbelt_v2.c").read_text(encoding="utf-8")
        self.assertIn("ENOTDIR below is intentionally not presented as a Sandbox errno", source)
        self.assertIn("allow-default is an additional fixed-worker boundary, not the trust basis", source)
        self.assertIn('sandbox_check(getpid(), "process-exec", 0)', source)

    def test_fixed_source_hash_and_real_native_canary(self):
        path = ROOT / "tools" / "sp_release_activate_v2.py"
        spec = importlib.util.spec_from_file_location("_seatbelt_contract_activation", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertEqual(hashlib.sha256((ROOT / "native" / "sp_release_seatbelt_v2.c").read_bytes()).hexdigest(),
                         module.NATIVE_SOURCE_SHA256)
        with tempfile.TemporaryDirectory() as directory:
            result = module.run_canary(payload=b"seatbelt-contract", root=directory)
            self.assertEqual(result["phase"], "COMMITTED")

    def test_production_native_default_keeps_owner_helper_test_escape_disabled(self):
        """The installed native build must not inherit Python's test-only flag."""
        source_path = ROOT / "native" / "sp_release_seatbelt_v2.c"
        makefile = ROOT / "native" / "Makefile"
        source = source_path.read_text(encoding="utf-8")
        make_text = makefile.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^#ifndef SP_TEST_ALLOW_OWNER_HELPER\n#define SP_TEST_ALLOW_OWNER_HELPER 0\n#endif$")
        self.assertNotIn("SP_TEST_", make_text)

        # Preprocessing and syntax-only compilation exercise the production
        # default, including all wire ABI static assertions, without producing
        # a helper or relying on the Python-only test build flags.
        preprocessed = subprocess.run(
            ["/usr/bin/clang", "-std=c11", "-dM", "-E", str(source_path)],
            cwd=ROOT / "native", text=True, capture_output=True, check=False,
        )
        self.assertEqual(preprocessed.returncode, 0, preprocessed.stderr)
        self.assertIn("#define SP_TEST_ALLOW_OWNER_HELPER 0", preprocessed.stdout)
        production_compile = subprocess.run(
            ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsyntax-only", str(source_path)],
            cwd=ROOT / "native", text=True, capture_output=True, check=False,
        )
        self.assertEqual(production_compile.returncode, 0, production_compile.stderr)
        dry_run = subprocess.run(
            ["/usr/bin/make", "-n", "sp_release_seatbelt_v2"], cwd=ROOT / "native",
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertNotIn("SP_TEST_", dry_run.stdout)

    def test_v3_wire_records_are_packed_little_endian_and_bind_prior_presence(self):
        """Protocol fields are security inputs, never best-effort hints.

        This remains source-level so the exact ABI is checked even on the
        non-Darwin test host where Seatbelt itself cannot be compiled.
        """
        source = (ROOT / "native" / "sp_release_seatbelt_v2.c").read_text(encoding="utf-8")
        for required in (
                "#define V2_VERSION 3U", "__attribute__((packed))",
                "uint32_t prior_present;", "uint32_t recovery_from_phase;",
                "uint32_t reserved;", "FdIdentity activation_lease_identity;",
                "FdIdentity rollback_lease_identity;", "sizeof(Ready) == 500",
                "sizeof(Go) == 252", "sizeof(Result) == 260",
                "sizeof(DurableState) == 416", "sizeof(NonceMarker) == 352",
                "offsetof(Ready, epoch) == 28", "offsetof(Ready, nonce) == 36",
                "offsetof(Ready, lease_identity) == 448", "offsetof(Go, epoch) == 20",
                "offsetof(Result, epoch) == 28", "offsetof(DurableState, epoch) == 24",
                "offsetof(DurableState, nonce) == 56",
                "offsetof(DurableState, activation_lease_identity) == 312",
                "offsetof(NonceMarker, epoch) == 16",
                "prior_semantics_valid", "ready_valid", "go_valid", "result_valid",
                "state_semantics_valid", "PHASE_RECOVERING_ROLLBACK"):
            self.assertIn(required, source)
        # Every inbound wire record must reject the v3 reserved word and bind
        # prior_present, rather than merely copying those fields onward.
        self.assertIn("ready->prior_present", source)
        self.assertIn("go->prior_present", source)
        self.assertIn("result->prior_present", source)
        self.assertIn("ready->reserved", source)
        self.assertIn("go->reserved", source)
        self.assertIn("result->reserved", source)

    def test_old_v2_records_fail_closed_and_v3_semantics_bind_reserved_prior_and_leases(self):
        source = (ROOT / "native" / "sp_release_seatbelt_v2.c").read_text(encoding="utf-8")
        self.assertIn("#define V2_VERSION 3U", source)
        self.assertNotRegex(source, r"(?m)^#define V2_VERSION 2U$")
        for function, required in {
            "ready_valid": ("ready->version == V2_VERSION", "ready->reserved == 0", "ready->prior_present", "lease_identity"),
            "go_valid": ("go->version == V2_VERSION", "go->reserved == 0", "go->prior_present"),
            "result_valid": ("result->version != V2_VERSION", "result->reserved != 0", "result->prior_present"),
            "state_semantics_valid": ("state->version != V2_VERSION", "state->reserved != 0", "prior_semantics_valid", "activation_lease_identity", "rollback_lease_identity"),
        }.items():
            body = _c_function_body(source, function)
            for token in required:
                self.assertIn(token, body, "%s does not bind %s" % (function, token))

    def test_v3_recovery_contract_has_no_pid_liveness_trust_or_mutating_inspect(self):
        source = (ROOT / "native" / "sp_release_seatbelt_v2.c").read_text(encoding="utf-8")
        for required in (
                '"--inspect"', '"--recover"', "RECOVERING_ROLLBACK",
                "expected_state_digest", "activation_lease", "rollback_lease",
                "RECOVERY_BLOCKED", "RECOVERED_COMMITTED", "RECOVERED_ROLLED_BACK",
                "CURRENT_UNKNOWN", "CURRENT_ABSENT", "CURRENT_PAYLOAD", "CURRENT_PRIOR",
                "safe_existing_regular", "O_NOFOLLOW", "O_NONBLOCK", "fsync("):
            self.assertIn(required, source)
        # Recover must not use a persisted PID as a process-control capability:
        # PID reuse is excluded through nonce-bound role leases.  Check the
        # actual function body, not text after the command-line literal.
        recovery = _c_function_body(source, "recover_mode")
        self.assertNotRegex(recovery, r"\bkill\s*\(")
        self.assertNotIn("activation_pid", recovery)
        self.assertNotIn("rollback_pid", recovery)
        self.assertIn("acquire_existing_locks", recovery)
        self.assertIn("read_valid_locked_state", recovery)

        # Inspection takes only existing locks/files and reports.  It may call
        # reconciliation in observation mode, but never with remove_valid=1.
        inspect = _c_function_body(source, "inspect_mode")
        for forbidden in (
                r"\b(?:write|pwrite|rename|renameat|unlink|unlinkat|fsync|fdatasync|mkdir|rmdir)\s*\(",
                r"\b(?:O_CREAT|O_TRUNC|O_WRONLY|O_RDWR)\b",
                r"\b(?:atomic_select|atomic_restore_absence|write_recovery_state)\s*\(",
        ):
            self.assertNotRegex(inspect, forbidden)
        calls = re.findall(r"reconcile_temporary\s*\([^;]*?\)", inspect)
        self.assertTrue(calls, "inspect must explicitly inspect temporary debris")
        self.assertTrue(all(re.search(r",\s*0\s*,", call) for call in calls), calls)


if __name__ == "__main__":
    unittest.main()
