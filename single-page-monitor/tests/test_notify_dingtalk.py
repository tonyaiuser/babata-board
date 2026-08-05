import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "notify_dingtalk.py"
SPEC = importlib.util.spec_from_file_location("single_page_notify_dingtalk", SOURCE)
notify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notify)


VALID_WEBHOOK = "https://oapi.dingtalk.com/robot/send?access_token=synthetic-token"
VALID_SECRET = "synthetic-signing-value"
VALID_PAYLOAD = {
    "msgtype": "markdown",
    "markdown": {"title": "Synthetic title", "text": "Synthetic text"},
}


def canonical_secret(payload):
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


class SecretFixture:
    def __init__(self, root, payload=None, raw=None):
        self.home = Path(root) / "home"
        self.home.mkdir()
        os.chmod(self.home, 0o750)
        current = self.home
        for component in notify.SECRET_RELATIVE[:-1]:
            current /= component
            current.mkdir()
            os.chmod(current, 0o700)
        self.parent = current
        self.path = current / notify.SECRET_RELATIVE[-1]
        content = raw
        if content is None:
            content = canonical_secret(payload or {
                "webhook": VALID_WEBHOOK,
                "secret": VALID_SECRET,
            })
        self.path.write_bytes(content)
        os.chmod(self.path, 0o600)


class FakeResponse:
    def __init__(self, body=b'{"errcode":0,"errmsg":"ok"}', status=200):
        self.body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit):
        return self.body[:limit]


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error = error
        self.calls = []

    def __call__(self, request, *, timeout):
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self.response


def payload_bytes(value=VALID_PAYLOAD):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class NotifyDingTalkTests(unittest.TestCase):
    def test_fixed_secret_loads_through_test_only_trusted_home(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp)
            credentials = notify.load_credentials(fixture.path, fixture.home)
        self.assertEqual(credentials.webhook, VALID_WEBHOOK)
        self.assertEqual(credentials.secret, VALID_SECRET)
        self.assertNotIn(VALID_WEBHOOK, repr(credentials))
        self.assertNotIn(VALID_SECRET, repr(credentials))
        self.assertIn("redacted", repr(credentials))

    def test_arbitrary_secret_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp)
            other = fixture.home / "other.json"
            other.write_bytes(fixture.path.read_bytes())
            os.chmod(other, 0o600)
            with self.assertRaises(notify.SecretError):
                notify.load_credentials(other, fixture.home)

    def test_duplicate_or_extra_secret_fields_are_rejected(self):
        values = (
            b'{"webhook":"x","webhook":"y","secret":"z"}',
            json.dumps({"webhook": VALID_WEBHOOK, "secret": VALID_SECRET, "extra": 1}).encode(),
        )
        for raw in values:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temp:
                fixture = SecretFixture(temp, raw=raw)
                with self.assertRaises(notify.SecretError):
                    notify.load_credentials(fixture.path, fixture.home)

    def test_noncanonical_secret_json_is_rejected(self):
        payload = {"webhook": VALID_WEBHOOK, "secret": VALID_SECRET}
        invalid = (
            json.dumps(payload).encode("utf-8"),
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n\n").encode(),
            canonical_secret(payload)[:-1],
        )
        for raw in invalid:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temp:
                fixture = SecretFixture(temp, raw=raw)
                with self.assertRaises(notify.SecretError):
                    notify.load_credentials(fixture.path, fixture.home)

    def test_secret_whitespace_and_control_characters_are_rejected(self):
        invalid = (" leading", "trailing ", "line\nbreak", "tab\tvalue", "delete\x7fvalue")
        for secret in invalid:
            with self.subTest(secret=repr(secret)), tempfile.TemporaryDirectory() as temp:
                fixture = SecretFixture(temp, {"webhook": VALID_WEBHOOK, "secret": secret})
                with self.assertRaises(notify.SecretError):
                    notify.load_credentials(fixture.path, fixture.home)

    def test_only_exact_dingtalk_https_webhook_is_allowed(self):
        invalid = (
            "http://oapi.dingtalk.com/robot/send?access_token=x",
            "https://evil.example/robot/send?access_token=x",
            "https://oapi.dingtalk.com.evil.example/robot/send?access_token=x",
            "https://oapi.dingtalk.com/other?access_token=x",
            "https://oapi.dingtalk.com/robot/send?access_token=",
            "https://oapi.dingtalk.com/robot/send?access_token=x&extra=y",
            "https://user@oapi.dingtalk.com/robot/send?access_token=x",
        )
        for webhook in invalid:
            with self.subTest(webhook=webhook), tempfile.TemporaryDirectory() as temp:
                fixture = SecretFixture(temp, {"webhook": webhook, "secret": VALID_SECRET})
                with self.assertRaises(notify.SecretError):
                    notify.load_credentials(fixture.path, fixture.home)

    def test_parent_and_file_security_are_enforced(self):
        cases = ("parent_mode", "file_mode", "hardlink", "symlink")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                fixture = SecretFixture(temp)
                if case == "parent_mode":
                    os.chmod(fixture.parent, 0o750)
                elif case == "file_mode":
                    os.chmod(fixture.path, 0o640)
                elif case == "hardlink":
                    os.link(fixture.path, fixture.parent / "copy.json")
                else:
                    target = fixture.parent / "real.json"
                    fixture.path.rename(target)
                    fixture.path.symlink_to(target)
                with self.assertRaises(notify.SecretError):
                    notify.load_credentials(fixture.path, fixture.home)

    def test_intermediate_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp)
            openclaw = fixture.home / ".openclaw"
            real = fixture.home / ".openclaw-real"
            openclaw.rename(real)
            openclaw.symlink_to(real, target_is_directory=True)
            with self.assertRaises(notify.SecretError):
                notify.load_credentials(fixture.home.joinpath(*notify.SECRET_RELATIVE), fixture.home)

    def test_short_reads_are_fully_consumed(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp)
            real_read = os.read
            with mock.patch.object(notify.os, "read", side_effect=lambda fd, size: real_read(fd, min(size, 1))):
                credentials = notify.load_credentials(fixture.path, fixture.home)
        self.assertEqual(credentials.secret, VALID_SECRET)

    def test_atomic_secret_replacement_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp)
            real_read = os.read
            raced = False

            def replace_named_file(fd, size):
                nonlocal raced
                if not raced:
                    raced = True
                    fixture.path.rename(fixture.parent / "old-secret.json")
                    fixture.path.write_bytes(canonical_secret({
                        "webhook": VALID_WEBHOOK,
                        "secret": "replacement-synthetic-secret",
                    }))
                    os.chmod(fixture.path, 0o600)
                return real_read(fd, size)

            with mock.patch.object(notify.os, "read", side_effect=replace_named_file):
                with self.assertRaises(notify.SecretError):
                    notify.load_credentials(fixture.path, fixture.home)

    def test_intermediate_directory_retarget_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp)
            openclaw = fixture.home / ".openclaw"
            real_read = os.read
            raced = False

            def retarget_intermediate(fd, size):
                nonlocal raced
                if not raced:
                    raced = True
                    openclaw.rename(fixture.home / ".openclaw-old")
                    replacement = openclaw / "secrets" / "sp-monitor"
                    replacement.mkdir(parents=True)
                    os.chmod(openclaw, 0o700)
                    os.chmod(openclaw / "secrets", 0o700)
                    os.chmod(replacement, 0o700)
                return real_read(fd, size)

            with mock.patch.object(notify.os, "read", side_effect=retarget_intermediate):
                with self.assertRaises(notify.SecretError):
                    notify.load_credentials(fixture.path, fixture.home)

    def test_strict_stdin_schema_and_size(self):
        invalid = (
            b"",
            b'{"msgtype":"markdown","msgtype":"text","markdown":{}}',
            b'{"msgtype":"text","text":{"content":"x"}}',
            b'{"msgtype":"markdown","markdown":{"title":"x","text":"y","extra":1}}',
            b"x" * (notify.MAX_PAYLOAD_BYTES + 1),
        )
        for raw in invalid:
            with self.subTest(size=len(raw)):
                with self.assertRaises(notify.InputError):
                    notify.parse_payload(io.BytesIO(raw))
        self.assertEqual(notify.parse_payload(io.BytesIO(payload_bytes())), VALID_PAYLOAD)

    def test_dry_run_validates_input_without_secret_or_transport(self):
        output = io.StringIO()
        transport = mock.Mock(side_effect=AssertionError("network used"))
        with mock.patch.object(notify, "load_credentials", side_effect=AssertionError("secret read")):
            code = notify.main(
                ["--dry-run"],
                input_stream=io.BytesIO(payload_bytes()),
                output_stream=output,
                transport=transport,
            )
        self.assertEqual(code, notify.EXIT_OK)
        self.assertEqual(transport.call_count, 0)
        self.assertEqual(
            output.getvalue(),
            'NOTIFY_SUMMARY_JSON {"dry_run":true,"sent":false}\n',
        )

    def test_fake_transport_receives_signed_allowed_request(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp)
            transport = FakeTransport()
            output = io.StringIO()
            code = notify.main(
                [],
                input_stream=io.BytesIO(payload_bytes()),
                output_stream=output,
                secret_path=fixture.path,
                trusted_home=fixture.home,
                transport=transport,
                clock_ms=123456789,
            )
        self.assertEqual(code, notify.EXIT_OK)
        self.assertEqual(output.getvalue(), 'NOTIFY_SUMMARY_JSON {"sent":true}\n')
        self.assertEqual(len(transport.calls), 1)
        request, timeout = transport.calls[0]
        parsed = notify.urllib.parse.urlsplit(request.full_url)
        query = dict(notify.urllib.parse.parse_qsl(parsed.query))
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, notify.DINGTALK_HOST)
        self.assertEqual(parsed.path, notify.DINGTALK_PATH)
        self.assertEqual(query["timestamp"], "123456789")
        self.assertTrue(query["sign"])
        self.assertEqual(timeout, 20)
        self.assertEqual(json.loads(request.data), VALID_PAYLOAD)

    def test_failures_have_fixed_redacted_status_and_exit(self):
        marker = "synthetic-secret-marker-never-print"
        error = io.StringIO()
        with tempfile.TemporaryDirectory() as temp:
            fixture = SecretFixture(temp, {"webhook": VALID_WEBHOOK, "secret": marker})
            code = notify.main(
                [],
                input_stream=io.BytesIO(payload_bytes()),
                error_stream=error,
                secret_path=fixture.path,
                trusted_home=fixture.home,
                transport=FakeTransport(error=OSError(marker)),
            )
        self.assertEqual(code, notify.EXIT_TRANSPORT)
        self.assertEqual(
            error.getvalue(),
            'NOTIFY_SUMMARY_JSON {"reason":"transport_failed","sent":false}\n',
        )
        self.assertNotIn(marker, error.getvalue())

    def test_public_cli_rejects_all_override_arguments(self):
        error = io.StringIO()
        code = notify.main(
            ["--secret-path", "/tmp/value"],
            input_stream=io.BytesIO(payload_bytes()),
            error_stream=error,
        )
        self.assertEqual(code, notify.EXIT_ARGUMENT)
        self.assertEqual(
            error.getvalue(),
            'NOTIFY_SUMMARY_JSON {"reason":"invalid_arguments","sent":false}\n',
        )

    def test_unexpected_internal_failure_is_redacted(self):
        marker = "synthetic-internal-marker-never-print"
        error = io.StringIO()
        with mock.patch.object(notify, "load_credentials", side_effect=RuntimeError(marker)):
            code = notify.main(
                [],
                input_stream=io.BytesIO(payload_bytes()),
                error_stream=error,
            )
        self.assertEqual(code, notify.EXIT_INTERNAL)
        self.assertEqual(
            error.getvalue(),
            'NOTIFY_SUMMARY_JSON {"reason":"internal_failure","sent":false}\n',
        )
        self.assertNotIn(marker, error.getvalue())


if __name__ == "__main__":
    unittest.main()
