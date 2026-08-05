import importlib.util
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts" / "notify_dingtalk.py"
spec = importlib.util.spec_from_file_location("notify_dingtalk", SCRIPT)
notify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notify)


class Response:
    def __init__(self, raw=b'{"errcode":0}'):
        self.raw = raw

    def read(self, *_args):
        return self.raw

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class NotifyDingTalkTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        self.secret_path = self.home / ".openclaw/secrets/sp-monitor/report_delivery.json"
        self.secret_path.parent.mkdir(parents=True)
        for directory in (self.home, self.home / ".openclaw", self.home / ".openclaw/secrets", self.secret_path.parent):
            directory.chmod(0o700)
        self.write_json({"webhook": "https://oapi.dingtalk.com/robot/send?access_token=test", "secret": "test-secret"})

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, value, mode=0o600):
        self.secret_path.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n")
        self.secret_path.chmod(mode)

    def load(self):
        return notify.load_credentials(trusted_home=self.home)

    def argv(self, *extra):
        return ["--verified-count", "3", "--matched-count", "2", "--fresh-count", "1",
                "--multi-site-count", "4", "--matched-products-json",
                '[{"title":"Product","source_domain":"shop.test","first_start_date":"2026-01-01","latest_start_date":"2026-01-02","relevant_ads_count":2,"cross_site_domains_count":3,"own_domain_hit":true}]',
                "--batch-url", "https://batch.invalid/page", "--dashboard-url", "https://dashboard.invalid/page", *extra]

    def test_valid_end_to_end_preserves_message_details_and_links(self):
        seen = []
        code = notify.main(self.argv(), credential_loader=self.load,
                           transport=lambda request, timeout: seen.append(request) or Response(), clock=lambda: 1)
        self.assertEqual(code, notify.EXIT_OK)
        body = seen[0].data.decode("utf-8")
        self.assertIn("本轮完成 FB 查询：3", body)
        self.assertIn("Product", body)
        self.assertIn("shop.test", body)
        self.assertIn("https://batch.invalid/page", body)
        self.assertIn("https://dashboard.invalid/page", body)

    def test_dry_run_validates_products_but_never_touches_sensitive_dependencies(self):
        out = StringIO()
        loader = mock.Mock(side_effect=AssertionError())
        transport = mock.Mock(side_effect=AssertionError())
        clock = mock.Mock(side_effect=AssertionError())
        with mock.patch.object(notify.os, "open", side_effect=AssertionError()) as opened, \
             redirect_stderr(StringIO()), \
             redirect_stdout(out):
            self.assertEqual(notify.main(self.argv("--dry-run"), credential_loader=loader, transport=transport, clock=clock), 0)
        self.assertEqual((loader.call_count, transport.call_count, clock.call_count, opened.call_count), (0, 0, 0, 0))
        self.assertNotIn("https://", out.getvalue())
        self.assertEqual(notify.main(self.argv("--dry-run", "--matched-products-json", "{}")), notify.EXIT_USAGE)

    def test_canonical_secret_byte_cases_and_valid_canonical(self):
        canonical = json.dumps({"secret": "s", "webhook": "https://oapi.dingtalk.com/robot/send?access_token=x"},
                               sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        self.secret_path.write_bytes(canonical)
        self.secret_path.chmod(0o600)
        self.assertEqual(self.load()[1], "s")
        cases = [canonical[:-1], canonical + b"\n", b'{\n "secret":"s","webhook":"https://oapi.dingtalk.com/robot/send?access_token=x"\n}\n',
                 b'{"webhook":"https://oapi.dingtalk.com/robot/send?access_token=x","secret":"s"}\n',
                 b'{"secret":"","webhook":"https://oapi.dingtalk.com/robot/send?access_token=x"}\n',
                 b'{"secret":" s","webhook":"https://oapi.dingtalk.com/robot/send?access_token=x"}\n',
                 b'{"secret":"s","webhook":"https://oapi.dingtalk.com/robot/send?access_token=x","x":1}\n', b'{"secret":"s"}\n']
        for raw in cases:
            self.secret_path.write_bytes(raw)
            self.secret_path.chmod(0o600)
            with self.subTest(raw=raw), self.assertRaises(notify.NotifierFailure):
                self.load()

    def test_actual_wrapper_option_contract_and_message_overflow(self):
        wrapper = (Path(__file__).parents[1] / "run_daily_fb_verify.sh").read_text()
        block = re.search(r"NOTIFY_ARGS=\((.*?)\n\s*\[\[.*?--dry-run", wrapper, re.S).group(1)
        options = re.findall(r"(--[a-z-]+)", block)
        self.assertEqual(set(options), {"--verified-count", "--matched-count", "--fresh-count", "--multi-site-count", "--matched-products-json", "--batch-url", "--dashboard-url"})
        products = [{"title": f"P{i}", "source_domain": "shop.test", "relevant_ads_count": 1,
                     "cross_site_domains_count": 2, "own_domain_hit": i == 1, "sample_limited": i == 1} for i in range(11)]
        values = {"--verified-count": "3", "--matched-count": "11", "--fresh-count": "1", "--multi-site-count": "4",
                  "--matched-products-json": json.dumps(products), "--batch-url": "https://batch.invalid/x", "--dashboard-url": "https://dash.invalid/x"}
        argv = [item for option in options for item in (option, values[option])]
        traps = [mock.Mock(side_effect=AssertionError()) for _ in range(3)]
        with mock.patch.object(notify.os, "open", side_effect=AssertionError()), redirect_stdout(StringIO()):
            self.assertEqual(notify.main(argv + ["--dry-run"], credential_loader=traps[0], transport=traps[1], clock=traps[2]), 0)
        seen = []
        self.assertEqual(notify.main(argv, credential_loader=lambda: ("https://oapi.dingtalk.com/robot/send?access_token=x", "s"), transport=lambda req, timeout: seen.append(req) or Response(), clock=lambda: 1), 0)
        body = seen[0].data.decode()
        self.assertIn("另有 1 个", body); self.assertIn("广告条数为本次抓到的首屏相关样本", body)
        self.assertIn("首屏相关样本 1+ 条", body); self.assertIn("原站在投", body)
        self.assertIn("https://batch.invalid/x", body); self.assertIn("https://dash.invalid/x", body)

    def test_loader_rejects_missing_unsafe_files_and_retarget(self):
        self.secret_path.unlink()
        with self.assertRaises(notify.NotifierFailure) as missing:
            self.load()
        self.assertEqual(missing.exception.code, notify.EXIT_SECRET_MISSING)
        self.write_json({"webhook": "https://oapi.dingtalk.com/robot/send?access_token=x", "secret": "s"}, 0o644)
        with self.assertRaises(notify.NotifierFailure) as unsafe:
            self.load()
        self.assertEqual(unsafe.exception.code, notify.EXIT_UNSAFE)
        self.secret_path.unlink()
        self.secret_path.symlink_to("/dev/null")
        with self.assertRaises(notify.NotifierFailure):
            self.load()
        self.secret_path.unlink()
        other = self.home / "other"
        other.write_text("x")
        other.chmod(0o600)
        os.link(other, self.secret_path)
        with self.assertRaises(notify.NotifierFailure):
            self.load()

        self.secret_path.unlink()
        self.write_json({"webhook": "https://oapi.dingtalk.com/robot/send?access_token=x", "secret": "s"})
        original_read = notify.os.read
        def retarget(fd, count):
            data = original_read(fd, count)
            moved = self.secret_path.with_suffix(".new")
            moved.write_bytes(self.secret_path.read_bytes())
            moved.chmod(0o600)
            os.replace(moved, self.secret_path)
            return data
        with mock.patch.object(notify.os, "read", retarget), self.assertRaises(notify.NotifierFailure):
            self.load()

    def test_loader_rejects_fifo_oversize_and_intermediate_retarget(self):
        self.secret_path.unlink()
        os.mkfifo(self.secret_path, 0o600)
        with self.assertRaises(notify.NotifierFailure) as failure:
            self.load()
        self.assertEqual(failure.exception.code, notify.EXIT_UNSAFE)
        self.secret_path.unlink()
        self.secret_path.write_bytes(b"x" * (notify.MAX_SECRET_BYTES + 1))
        self.secret_path.chmod(0o600)
        with self.assertRaises(notify.NotifierFailure) as failure:
            self.load()
        self.assertEqual(failure.exception.code, notify.EXIT_UNSAFE)
        self.write_json({"webhook": "https://oapi.dingtalk.com/robot/send?access_token=x", "secret": "s"})
        original_read = notify.os.read
        old_component = self.home / ".openclaw.old"
        def retarget_directory(fd, count):
            data = original_read(fd, count)
            component = self.home / ".openclaw"
            if component.exists():
                os.replace(component, old_component)
                component.mkdir(mode=0o700)
            return data
        with mock.patch.object(notify.os, "read", retarget_directory), self.assertRaises(notify.NotifierFailure) as failure:
            self.load()
        self.assertEqual(failure.exception.code, notify.EXIT_UNSAFE)

    def test_strict_credential_content_and_endpoints(self):
        bad = [
            b'\xef\xbb\xbf{}', b'{"webhook":"x","webhook":"x","secret":"s"}',
            b'{"webhook":"https://oapi.dingtalk.com/robot/send?access_token=x","secret":"s' + bytes([0]) + b'"}',
            b'{"webhook":"https://oapi.dingtalk.com/robot/send?access_token=x","secret":NaN}', b'\xff',
            b'{"secret":"s", "webhook":"https://oapi.dingtalk.com/robot/send?access_token=x"}\n',
        ]
        endpoints = ["http://oapi.dingtalk.com/robot/send?access_token=x", "https://oapi.dingtalk.com:443/robot/send?access_token=x",
                     "https://oapi.dingtalk.com/robot/send?access_token=x&extra=y", "https://oapi.dingtalk.com/other?access_token=x",
                     "https://evil.invalid/robot/send?access_token=x", "https://u@oapi.dingtalk.com/robot/send?access_token=x",
                     "https://oapi.dingtalk.com/robot/send?access_token=x#fragment", "https://oapi.dingtalk.com/robot/send?access_token=x&access_token=y",
                     "https://oapi.dingtalk.com/robot/send?access_token=", "https://oapi.dingtalk.com/robot/send?access_token=%20",
                     "https://oapi.dingtalk.com/robot/send?access_token=%00", "https://oapi.dingtalk.com/robot/send?access_token=x&sign=y"]
        endpoints.extend(["https://oapi.dingtalk.com/robot/send?access_token=a%20b",
                          "https://oapi.dingtalk.com/robot/send?access_token=" + "x" * (notify.MAX_CREDENTIAL_TEXT + 1)])
        for raw in bad:
            self.secret_path.write_bytes(raw)
            self.secret_path.chmod(0o600)
            with self.subTest(raw=raw):
                with self.assertRaises(notify.NotifierFailure) as failure:
                    self.load()
                self.assertEqual(failure.exception.code, notify.EXIT_SECRET_CONTENT)
        for endpoint in endpoints:
            self.write_json({"webhook": endpoint, "secret": "s"})
            with self.subTest(endpoint=endpoint), self.assertRaises(notify.NotifierFailure):
                self.load()
        self.write_json({"webhook": "https://oapi.dingtalk.com/robot/send?access_token=x", "secret": "s" * notify.MAX_CREDENTIAL_TEXT})
        self.assertEqual(self.load()[1], "s" * notify.MAX_CREDENTIAL_TEXT)
        self.write_json({"webhook": "https://oapi.dingtalk.com/robot/send?access_token=x", "secret": "s" * (notify.MAX_CREDENTIAL_TEXT + 1)})
        with self.assertRaises(notify.NotifierFailure) as failure:
            self.load()
        self.assertEqual(failure.exception.code, notify.EXIT_SECRET_CONTENT)

    def test_exit_mappings_and_redaction(self):
        args = self.argv()
        self.assertEqual(notify.main(["--verified-count", "x"]), notify.EXIT_USAGE)
        self.assertEqual(notify.main(args, credential_loader=lambda: (_ for _ in ()).throw(notify.NotifierFailure(65))), 65)
        self.assertEqual(notify.main(args, credential_loader=lambda: (_ for _ in ()).throw(notify.NotifierFailure(66))), 66)
        self.assertEqual(notify.main(args, credential_loader=lambda: (_ for _ in ()).throw(notify.NotifierFailure(77))), 77)
        creds = ("https://oapi.dingtalk.com/robot/send?access_token=x", "s")
        self.assertEqual(notify.main(args, credential_loader=lambda: creds, transport=lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("SECRET https://x"))), 75)
        self.assertEqual(notify.main(args, credential_loader=lambda: creds, transport=lambda *_a, **_k: Response(b'{"errcode":1}'), clock=lambda: 1), 76)
        self.assertEqual(notify.main(args, credential_loader=lambda: creds, clock=lambda: (_ for _ in ()).throw(RuntimeError("SECRET https://x"))), 70)
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            notify.main(args, credential_loader=lambda: (_ for _ in ()).throw(RuntimeError("SECRET https://x")))
        self.assertNotIn("SECRET", out.getvalue() + err.getvalue())
        self.assertNotIn("https://x", out.getvalue() + err.getvalue())

    def test_summary_stream_contract_and_strict_response(self):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(notify.main(["--verified-count", "bad"]), 64)
            self.assertEqual(notify.main(self.argv("--dry-run")), 0)
        self.assertEqual(out.getvalue().splitlines(), ['NOTIFY_SUMMARY_JSON {"sent":false,"dry_run":true}'])
        self.assertEqual(err.getvalue().splitlines(), ['NOTIFY_SUMMARY_JSON {"sent":false,"code":64}'])
        creds = ("https://oapi.dingtalk.com/robot/send?access_token=x", "s")
        for raw in (b'{"errcode":NaN}', b'{"errcode":0,"errcode":0}', b"x" * 65537):
            with self.subTest(raw=raw[:20]):
                self.assertEqual(notify.main(self.argv(), credential_loader=lambda: creds,
                                              transport=lambda *_a, **_k: Response(raw), clock=lambda: 1), 76)

    def test_help_and_static_contract(self):
        self.assertEqual(notify.PRODUCTION_HOME, "/Users/tonyaiuser")
        self.assertEqual(notify.SECRET_COMPONENTS, (".openclaw", "secrets", "sp-monitor", "report_delivery.json"))
        self.assertEqual(notify.MAX_SECRET_BYTES, 16 * 1024)
        self.assertEqual(notify.MAX_CREDENTIAL_TEXT, 4096)
        opener = mock.Mock()
        with mock.patch.object(notify.urllib.request, "build_opener", return_value=opener) as build:
            notify._default_transport("request", timeout=9)
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], notify._NoRedirect)
        opener.open.assert_called_once_with("request", timeout=9)
        self.assertEqual(notify.main(["--help"]), 0)
        source = SCRIPT.read_text()
        for forbidden in ("sp-monitor/run.py", "import ast", "--config", "DINGTALK_WEBHOOK"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
