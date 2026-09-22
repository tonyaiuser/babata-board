import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback
import types
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = REPO_ROOT / "skills" / "sp-monitor" / "run.py"
EXPECTED_LIVE_SHA256 = "1f46674bf365bb7b7bc4f59aa581c4ac1e7776b80f447f72cf898d28a7145e00"


def source_bytes():
    return SOURCE_PATH.read_bytes()


def load_repo_module(module_name="sp_monitor_repo_test"):
    code = compile(source_bytes(), str(SOURCE_PATH), "exec")
    module = types.ModuleType(module_name)
    module.__file__ = str(SOURCE_PATH)
    module.__package__ = ""
    exec(code, module.__dict__)
    return module


class SecretFixture:
    def __init__(self, root, payload=None, raw=None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.directory = self.root / "sp-monitor"
        self.directory.mkdir()
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "report_delivery.json"
        if raw is None:
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.path.write_bytes(raw)
        os.chmod(self.path, 0o600)


class StatProxy:
    def __init__(self, value, **changes):
        self._value = value
        self._changes = changes

    def __getattr__(self, name):
        if name in self._changes:
            return self._changes[name]
        return getattr(self._value, name)


class SpMonitorSecretSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_repo_module()

    def test_repo_source_is_default_and_contains_import_baseline(self):
        self.assertTrue(SOURCE_PATH.is_file())
        self.assertEqual(self.module.__file__, str(SOURCE_PATH))
        self.assertEqual(self.module.IMPORTED_FROM_LIVE_SHA256, EXPECTED_LIVE_SHA256)

    def test_source_has_no_hardcoded_dingtalk_credentials(self):
        raw = source_bytes()
        self.assertNotIn(b"oapi.dingtalk.com/robot/send?access_token=", raw)
        self.assertIsNone(re.search(rb"['\"]SEC[A-Za-z0-9_-]{32,}['\"]", raw))
        tree = ast.parse(raw, filename=str(SOURCE_PATH))
        suspicious = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            value = node.value
            if "oapi.dingtalk.com/robot/send?access_token=" in value:
                suspicious.append(node.lineno)
            if value.startswith("SEC") and len(value) >= 32:
                suspicious.append(node.lineno)
        self.assertEqual(suspicious, [])

    def test_import_executes_without_secret_or_file_io(self):
        code = compile(source_bytes(), str(SOURCE_PATH), "exec")
        module = types.ModuleType("sp_monitor_zero_io_test")
        module.__file__ = str(SOURCE_PATH)
        module.__package__ = ""
        with mock.patch("builtins.open", side_effect=AssertionError("unexpected builtins.open")), \
             mock.patch.object(os, "open", side_effect=AssertionError("unexpected os.open")):
            exec(code, module.__dict__)
        self.assertEqual(module.IMPORTED_FROM_LIVE_SHA256, EXPECTED_LIVE_SHA256)

    def test_secret_loader_is_referenced_only_by_send_helpers(self):
        tree = ast.parse(source_bytes(), filename=str(SOURCE_PATH))
        callers = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                    if child.func.id == "_load_dingtalk_credentials":
                        callers.add(node.name)
        self.assertEqual(callers, {"_dingtalk_signed_url", "send_dingtalk_payload"})

    def test_valid_injected_secret_uses_same_fd_and_repr_is_redacted(self):
        webhook = "dummy-webhook-value"
        secret = "dummy-signing-value"
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": webhook, "secret": secret})
            with mock.patch("builtins.open", side_effect=AssertionError("path reopened")):
                credentials = self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))
        self.assertEqual(credentials.webhook, webhook)
        self.assertEqual(credentials.secret, secret)
        rendered = repr(credentials)
        self.assertNotIn(webhook, rendered)
        self.assertNotIn(secret, rendered)
        self.assertIn("redacted", rendered)

    def test_secret_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = SecretFixture(root / "real", {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            link = root / "linked"
            link.symlink_to(fixture.directory, target_is_directory=True)
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(link / fixture.path.name, trusted_root=root)

    def test_intermediate_secret_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            os.chmod(real, 0o700)
            nested = real / "nested"
            fixture = SecretFixture(nested, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            link = root / "middle"
            link.symlink_to(real, target_is_directory=True)
            attacked_path = link / "nested" / "sp-monitor" / fixture.path.name
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(attacked_path, trusted_root=root)

    def test_secret_file_symlink_and_nonregular_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = SecretFixture(root / "real", {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            linked_directory = root / "linked"
            linked_directory.mkdir()
            os.chmod(linked_directory, 0o700)
            link = linked_directory / "report_delivery.json"
            link.symlink_to(fixture.path)
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(link, trusted_root=root)
            link.unlink()
            link.mkdir()
            os.chmod(link, 0o600)
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(link, trusted_root=root)

    def test_secret_hardlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            hardlink = fixture.directory / "copy.json"
            os.link(fixture.path, hardlink)
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_secret_directory_and_file_modes_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            os.chmod(fixture.directory, 0o755)
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_trusted_home_anchor_allows_0750_but_rejects_group_or_world_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            fixture = SecretFixture(
                home / ".openclaw" / "secrets",
                {"webhook": "dummy-webhook", "secret": "dummy-secret"},
            )
            os.chmod(home / ".openclaw", 0o700)
            os.chmod(home, 0o750)
            credentials = self.module._load_dingtalk_credentials(
                fixture.path,
                trusted_root=home,
            )
            self.assertEqual(credentials.webhook, "dummy-webhook")
            for mode in (0o770, 0o752):
                with self.subTest(mode=oct(mode)):
                    os.chmod(home, mode)
                    with self.assertRaises(self.module.DingTalkCredentialError):
                        self.module._load_dingtalk_credentials(fixture.path, trusted_root=home)
            os.chmod(home, 0o750)
            os.chmod(fixture.directory, 0o700)
            os.chmod(fixture.path, 0o644)
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_secret_file_owner_is_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            real_fstat = os.fstat
            calls = 0
            def wrong_file_owner(fd):
                nonlocal calls
                calls += 1
                value = real_fstat(fd)
                if calls == 3:
                    return StatProxy(value, st_uid=value.st_uid + 1)
                return value
            with mock.patch.object(self.module.os, "fstat", side_effect=wrong_file_owner):
                with self.assertRaises(self.module.DingTalkCredentialError):
                    self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_secret_parent_directory_owner_is_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            real_fstat = os.fstat
            calls = 0
            def wrong_parent_owner(fd):
                nonlocal calls
                calls += 1
                value = real_fstat(fd)
                if calls == 2:
                    return StatProxy(value, st_uid=value.st_uid + 1)
                return value
            with mock.patch.object(self.module.os, "fstat", side_effect=wrong_parent_owner):
                with self.assertRaises(self.module.DingTalkCredentialError):
                    self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_secret_file_rename_replace_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": "dummy-webhook-one", "secret": "dummy-secret-one"})
            real_read = os.read
            raced = False
            def replace_path(fd, count):
                nonlocal raced
                if not raced:
                    raced = True
                    fixture.path.replace(fixture.directory / "old.json")
                    fixture.path.write_text(
                        json.dumps({"webhook": "dummy-webhook-two", "secret": "dummy-secret-two"}),
                        encoding="utf-8",
                    )
                    os.chmod(fixture.path, 0o600)
                return real_read(fd, count)
            with mock.patch.object(self.module.os, "read", side_effect=replace_path):
                with self.assertRaises(self.module.DingTalkCredentialError):
                    self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_secret_same_inode_truncate_rewrite_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            original_inode = fixture.path.stat().st_ino
            real_read = os.read
            raced = False
            def rewrite_path(fd, count):
                nonlocal raced
                if not raced:
                    raced = True
                    fixture.path.write_bytes(b"{}")
                    os.chmod(fixture.path, 0o600)
                    self.assertEqual(fixture.path.stat().st_ino, original_inode)
                return real_read(fd, count)
            with mock.patch.object(self.module.os, "read", side_effect=rewrite_path):
                with self.assertRaises(self.module.DingTalkCredentialError):
                    self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_secret_path_missing_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            real_read = os.read
            raced = False
            def remove_path(fd, count):
                nonlocal raced
                if not raced:
                    raced = True
                    fixture.path.unlink()
                return real_read(fd, count)
            with mock.patch.object(self.module.os, "read", side_effect=remove_path):
                with self.assertRaises(self.module.DingTalkCredentialError):
                    self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_intermediate_directory_rename_rebind_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            fixture = SecretFixture(
                home / ".openclaw" / "secrets",
                {"webhook": "dummy-webhook", "secret": "dummy-secret"},
            )
            os.chmod(home / ".openclaw", 0o700)
            os.chmod(home, 0o750)
            openclaw = home / ".openclaw"
            real_read = os.read
            raced = False

            def replace_intermediate(fd, count):
                nonlocal raced
                if not raced:
                    raced = True
                    openclaw.rename(home / ".openclaw-old")
                    openclaw.mkdir()
                    os.chmod(openclaw, 0o700)
                    (openclaw / "secrets").mkdir()
                    os.chmod(openclaw / "secrets", 0o700)
                return real_read(fd, count)

            with mock.patch.object(self.module.os, "read", side_effect=replace_intermediate):
                with self.assertRaises(self.module.DingTalkCredentialError):
                    self.module._load_dingtalk_credentials(fixture.path, trusted_root=home)

    def test_one_byte_short_reads_are_fully_consumed(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
            real_read = os.read
            with mock.patch.object(
                self.module.os,
                "read",
                side_effect=lambda fd, count: real_read(fd, min(count, 1)),
            ):
                credentials = self.module._load_dingtalk_credentials(
                    fixture.path,
                    trusted_root=Path(temp),
                )
            self.assertEqual(credentials.webhook, "dummy-webhook")

    def test_oversize_secret_is_rejected_before_decode(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, raw=b"x" * (16 * 1024 + 1))
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_mode_0600_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / "sp-monitor"
            directory.mkdir()
            os.chmod(directory, 0o700)
            fifo = directory / "report_delivery.json"
            os.mkfifo(fifo, 0o600)
            os.chmod(fifo, 0o600)
            code = (
                "import runpy,sys; ns=runpy.run_path(sys.argv[1]); "
                "\ntry: ns['_load_dingtalk_credentials'](sys.argv[2], trusted_root=sys.argv[3])"
                "\nexcept ns['DingTalkCredentialError']: raise SystemExit(0)"
                "\nraise SystemExit(1)"
            )
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            result = subprocess.run(
                [sys.executable, "-c", code, str(SOURCE_PATH), str(fifo), str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3,
                env=environment,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))

    def test_secret_schema_is_exact_typed_nonempty_and_duplicate_free(self):
        cases = (
            {},
            {"webhook": "dummy-webhook"},
            {"webhook": "dummy-webhook", "secret": "dummy-secret", "extra": "x"},
            {"webhook": 1, "secret": "dummy-secret"},
            {"webhook": "dummy-webhook", "secret": None},
            {"webhook": "", "secret": "dummy-secret"},
            {"webhook": "dummy-webhook", "secret": "   "},
        )
        for index, payload in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temp:
                fixture = SecretFixture(temp, payload)
                with self.assertRaises(self.module.DingTalkCredentialError):
                    self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))
        duplicate = b'{"webhook":"dummy-one","webhook":"dummy-two","secret":"dummy-secret"}'
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, raw=duplicate)
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))

    def test_recursive_json_is_typed_and_fatal_exceptions_propagate(self):
        recursive = b"[" * 1100 + b"]" * 1100
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, raw=recursive)
            with self.assertRaises(self.module.DingTalkCredentialError):
                self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))
        for exception in (MemoryError("memory"), KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(exception=type(exception).__name__), tempfile.TemporaryDirectory() as temp:
                fixture = SecretFixture(temp, {"webhook": "dummy-webhook", "secret": "dummy-secret"})
                with mock.patch.object(self.module.json, "loads", side_effect=exception):
                    with self.assertRaises(type(exception)) as caught:
                        self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))
                self.assertIs(caught.exception, exception)

    def test_parse_failure_has_no_context_or_secret_marker_in_traceback(self):
        marker = "dummy-secret-marker-must-not-leak"
        raw = ('{"webhook":"' + marker).encode("utf-8")
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, raw=raw)
            with self.assertRaises(self.module.DingTalkCredentialError) as caught:
                self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))
        error = caught.exception
        rendered = f"{error!r}\n{''.join(traceback.format_exception(type(error), error, error.__traceback__))}"
        self.assertIsNone(error.__context__)
        self.assertNotIn(marker, rendered)

    def test_errors_do_not_leak_dummy_values(self):
        webhook = "dummy-webhook-never-leak"
        secret = "dummy-secret-never-leak"
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": webhook, "secret": secret, "extra": "invalid"})
            try:
                self.module._load_dingtalk_credentials(fixture.path, trusted_root=Path(temp))
            except self.module.DingTalkCredentialError as error:
                rendered = f"{error!s} {error!r}"
            else:
                self.fail("invalid schema was accepted")
        self.assertNotIn(webhook, rendered)
        self.assertNotIn(secret, rendered)

    def test_real_send_path_loads_once_and_delivery_error_is_redacted(self):
        credentials = self.module._DingTalkCredentials("dummy-webhook-send", "dummy-secret-send")
        loader = mock.Mock(return_value=credentials)
        with mock.patch.object(self.module, "_load_dingtalk_credentials", loader), \
             mock.patch.object(self.module.urllib.request, "urlopen", side_effect=OSError("dummy-webhook-send")), \
             mock.patch.object(self.module.time, "sleep"):
            with self.assertRaises(self.module.DingTalkDeliveryError) as caught:
                self.module.send_dingtalk_payload({"msgtype": "text"})
        loader.assert_called_once_with()
        rendered = f"{caught.exception!s} {caught.exception!r}"
        self.assertNotIn(credentials.webhook, rendered)
        self.assertNotIn(credentials.secret, rendered)

    @unittest.skipUnless(
        os.environ.get("SP_MONITOR_VERIFY_LIVE_PARITY") == "1",
        "live parity is explicitly opt-in",
    )
    def test_optional_live_baseline_parity(self):
        live = Path.home() / ".openclaw" / "workspace" / "skills" / "sp-monitor" / "run.py"
        self.assertEqual(hashlib.sha256(live.read_bytes()).hexdigest(), EXPECTED_LIVE_SHA256)


if __name__ == "__main__":
    unittest.main()
