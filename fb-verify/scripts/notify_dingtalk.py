#!/usr/bin/env python3
"""Fail-closed FB DingTalk notifier with a fixed credential location."""

import argparse
import base64
import hashlib
import hmac
import json
import os
import stat
import sys
import time
import urllib.parse
import urllib.request


PRODUCTION_HOME = "/Users/tonyaiuser"
SECRET_COMPONENTS = (".openclaw", "secrets", "sp-monitor", "report_delivery.json")
MAX_SECRET_BYTES = 16 * 1024
MAX_CREDENTIAL_TEXT = 4096
MAX_RESPONSE_BYTES = 65536
MAX_PRODUCT_DETAILS = 10

EXIT_OK = 0
EXIT_USAGE = 64
EXIT_SECRET_CONTENT = 65
EXIT_SECRET_MISSING = 66
EXIT_INTERNAL = 70
EXIT_TRANSPORT = 75
EXIT_RESPONSE = 76
EXIT_UNSAFE = 77


class NotifierFailure(Exception):
    def __init__(self, code):
        super().__init__()
        self.code = code


class UsageFailure(Exception):
    pass


SecretError = NotifierFailure


def clean_inline(value, limit=72):
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    for char in ("\\", "*", "_", "[", "]"):
        text = text.replace(char, f"\\{char}")
    return text


def product_markdown(index, product):
    title = clean_inline(product.get("title") or product.get("group_id") or "未命名产品")
    domain = clean_inline(product.get("source_domain") or "未知来源", limit=80)
    first_date = product.get("first_start_date") or "未知"
    latest_date = product.get("latest_start_date") or ""
    if latest_date and latest_date != first_date:
        date_text = f"首次：{first_date}｜最近：{latest_date}"
    else:
        date_text = f"起投：{first_date}"

    ad_count = int(product.get("relevant_ads_count") or 0)
    domain_count = int(product.get("cross_site_domains_count") or 0)
    own_hit = "｜原站在投" if product.get("own_domain_hit") else ""
    sample_suffix = "+" if product.get("sample_limited") else ""
    return (
        f"{index}. **{title}**（{domain}）\n\n"
        f"{date_text}｜首屏相关样本 {ad_count}{sample_suffix} 条 / {domain_count} 个落地域名{own_hit}"
    )


def build_message(verified_count, matched_count, fresh_count, multi_site_count,
                  dashboard_url, matched_products=None, batch_url=""):
    title = "FB 投放验证已更新"
    products = list(matched_products or [])
    detail_products = products[:MAX_PRODUCT_DETAILS]
    detail_text = ""
    if detail_products:
        blocks = [product_markdown(index, product) for index, product in enumerate(detail_products, 1)]
        detail_text = "\n\n#### 本轮确认产品\n\n" + "\n\n".join(blocks) + "\n"
        if len(products) > len(detail_products):
            detail_text += f"\n另有 {len(products) - len(detail_products)} 个确认产品，请在看板查看。\n"

    batch_link = ""
    if batch_url:
        batch_link = f"[查看本轮 {matched_count} 个产品图文看板]({batch_url})\n\n"
    text = f"""### {title}

- 本轮完成 FB 查询：{verified_count}
- ✅ 确认相关投放：{matched_count}
- 🔥 新起投（首次起投 ≤3 天）：{fresh_count}
- 首屏样本多落地域名（≥3）：{multi_site_count}
{detail_text}
> 广告条数为本次抓到的首屏相关样本，不等于 Facebook 广告总量。

{batch_link}[查看完整月度看板]({dashboard_url})
"""
    return title, text


def _required_flag(name):
    value = getattr(os, name, None)
    if value is None:
        raise NotifierFailure(EXIT_UNSAFE)
    return value


def _safe_close(fd):
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass


def _open_directory(name, parent_fd, final=False):
    flags = (_required_flag("O_RDONLY") | _required_flag("O_DIRECTORY") |
             _required_flag("O_NOFOLLOW") | _required_flag("O_CLOEXEC"))
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise NotifierFailure(EXIT_SECRET_MISSING) from exc
    except OSError as exc:
        raise NotifierFailure(EXIT_UNSAFE) from exc
    try:
        details = os.fstat(fd)
        mode = stat.S_IMODE(details.st_mode)
        unsafe = (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or
                  (final and mode != 0o700) or (not final and mode & 0o022))
        if unsafe:
            raise NotifierFailure(EXIT_UNSAFE)
        return fd
    except Exception:
        _safe_close(fd)
        raise


def _same_binding(left, right):
    fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_uid", "st_nlink",
              "st_mtime_ns", "st_ctime_ns")
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def _read_secret_file(directory_fd):
    name = SECRET_COMPONENTS[-1]
    flags = (_required_flag("O_RDONLY") | _required_flag("O_NOFOLLOW") |
             _required_flag("O_NONBLOCK") | _required_flag("O_CLOEXEC"))
    try:
        file_fd = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError as exc:
        raise NotifierFailure(EXIT_SECRET_MISSING) from exc
    except OSError as exc:
        raise NotifierFailure(EXIT_UNSAFE) from exc
    try:
        before = os.fstat(file_fd)
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                mode != 0o600 or before.st_nlink != 1 or before.st_size > MAX_SECRET_BYTES):
            raise NotifierFailure(EXIT_UNSAFE)
        initial_named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not _same_binding(before, initial_named):
            raise NotifierFailure(EXIT_UNSAFE)
        chunks = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(8192, MAX_SECRET_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SECRET_BYTES:
                raise NotifierFailure(EXIT_UNSAFE)
        after = os.fstat(file_fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not _same_binding(before, after) or not _same_binding(after, named):
            raise NotifierFailure(EXIT_UNSAFE)
        if total != before.st_size:
            raise NotifierFailure(EXIT_UNSAFE)
        return b"".join(chunks)
    finally:
        _safe_close(file_fd)


def _reject_constant(_value):
    raise ValueError("non-finite number")


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _validate_text(value):
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > MAX_CREDENTIAL_TEXT:
        raise ValueError("invalid text")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("control character")


def _parse_credentials(raw):
    try:
        if raw.startswith(b"\xef\xbb\xbf") or b"\0" in raw:
            raise ValueError("forbidden encoding")
        decoded = raw.decode("utf-8", "strict")
        data = json.loads(decoded, object_pairs_hook=_no_duplicate_keys,
                          parse_constant=_reject_constant)
        if not isinstance(data, dict) or set(data) != {"webhook", "secret"}:
            raise ValueError("unexpected keys")
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8") + b"\n"
        if raw != canonical:
            raise ValueError("noncanonical bytes")
        _validate_text(data["webhook"])
        _validate_text(data["secret"])
        if any(char.isspace() and ord(char) < 128 for char in data["webhook"]):
            raise ValueError("webhook whitespace")
        parsed = urllib.parse.urlsplit(data["webhook"])
        if parsed.query.partition("=")[0] != "access_token":
            raise ValueError("invalid webhook query")
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        if (parsed.scheme != "https" or parsed.hostname != "oapi.dingtalk.com" or
                parsed.path != "/robot/send" or parsed.port is not None or
                parsed.username is not None or parsed.password is not None or parsed.fragment or
                len(query) != 1 or query[0][0] != "access_token" or not query[0][1]):
            raise ValueError("invalid webhook")
        _validate_text(query[0][1])
        if any(char.isspace() and ord(char) < 128 for char in query[0][1]):
            raise ValueError("token whitespace")
        return data["webhook"], data["secret"]
    except Exception as exc:
        raise NotifierFailure(EXIT_SECRET_CONTENT) from exc


def load_credentials(*, trusted_home=None):
    """Load the fixed production file; trusted_home exists only for tests."""
    root = trusted_home if trusted_home is not None else PRODUCTION_HOME
    directory_fds = []
    bindings = []
    try:
        if not isinstance(root, (str, bytes, os.PathLike)) or not os.path.isabs(root):
            raise NotifierFailure(EXIT_UNSAFE)
        root_fd = _open_directory(root, None)
        directory_fds.append(root_fd)
        root_binding = os.fstat(root_fd)
        if not _same_binding(root_binding, os.stat(root, follow_symlinks=False)):
            raise NotifierFailure(EXIT_UNSAFE)
        current_fd = root_fd
        for index, component in enumerate(SECRET_COMPONENTS[:-1]):
            next_fd = _open_directory(component, current_fd,
                                      final=index == len(SECRET_COMPONENTS) - 2)
            directory_fds.append(next_fd)
            named = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            opened = os.fstat(next_fd)
            if not _same_binding(opened, named):
                raise NotifierFailure(EXIT_UNSAFE)
            bindings.append((current_fd, component, next_fd, opened))
            current_fd = next_fd
        raw = _read_secret_file(current_fd)
        for parent_fd, component, child_fd, binding in bindings:
            if not _same_binding(binding, os.fstat(child_fd)):
                raise NotifierFailure(EXIT_UNSAFE)
            if not _same_binding(binding, os.stat(component, dir_fd=parent_fd, follow_symlinks=False)):
                raise NotifierFailure(EXIT_UNSAFE)
        if (not _same_binding(root_binding, os.fstat(root_fd)) or
                not _same_binding(root_binding, os.stat(root, follow_symlinks=False))):
            raise NotifierFailure(EXIT_UNSAFE)
        return _parse_credentials(raw)
    except NotifierFailure:
        raise
    except (AttributeError, OSError, TypeError, ValueError):
        raise NotifierFailure(EXIT_UNSAFE) from None
    finally:
        for directory_fd in reversed(directory_fds):
            _safe_close(directory_fd)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _default_transport(request, *, timeout):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    return opener.open(request, timeout=timeout)


def send(webhook, secret, title, text, *, transport, clock):
    timestamp = str(round(clock() * 1000))
    string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
    signature = base64.b64encode(
        hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).digest()
    ).decode("ascii")
    separator = "&" if "?" in webhook else "?"
    signed_url = f"{webhook}{separator}timestamp={timestamp}&sign={urllib.parse.quote_plus(signature)}"
    payload = json.dumps({"msgtype": "markdown", "markdown": {"title": title, "text": text}},
                         ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(signed_url, data=payload, headers={"Content-Type": "application/json"})
    try:
        response = transport(request, timeout=20)
        with response as opened_response:
            raw = opened_response.read(MAX_RESPONSE_BYTES + 1)
            status = opened_response.getcode() if hasattr(opened_response, "getcode") else None
    except Exception as exc:
        raise NotifierFailure(EXIT_TRANSPORT) from exc
    if status is not None and status != 200:
        raise NotifierFailure(EXIT_TRANSPORT)
    if not isinstance(raw, bytes):
        raise NotifierFailure(EXIT_RESPONSE)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise NotifierFailure(EXIT_RESPONSE)
    try:
        reply = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_no_duplicate_keys,
                           parse_constant=_reject_constant)
        if type(reply) is not dict or type(reply.get("errcode")) is not int or reply["errcode"] != 0:
            raise ValueError("rejected reply")
    except Exception as exc:
        raise NotifierFailure(EXIT_RESPONSE) from exc


class _QuietArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise UsageFailure()


def _parser():
    parser = _QuietArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verified-count", type=int, required=True)
    parser.add_argument("--matched-count", type=int, required=True)
    parser.add_argument("--fresh-count", type=int, default=0)
    parser.add_argument("--multi-site-count", type=int, default=0)
    parser.add_argument("--matched-products-json", default="[]")
    parser.add_argument("--batch-url", default="")
    parser.add_argument("--dashboard-url", required=True)
    return parser


def _validate_public_url(value, *, required):
    if not value:
        if required:
            raise ValueError("missing URL")
        return
    if (not isinstance(value, str) or len(value) > 8192 or value != value.strip() or
            any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("invalid URL")
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.fragment):
        raise ValueError("invalid URL")


def _summary(sent, code=None, dry_run=False, stream=None):
    result = {"sent": sent}
    if dry_run:
        result["dry_run"] = True
    if code is not None:
        result["code"] = code
    print("NOTIFY_SUMMARY_JSON " + json.dumps(result, separators=(",", ":")), file=stream or sys.stdout)


def main(argv=None, *, credential_loader=None, transport=None, clock=None):
    parser = _parser()
    raw_argv = sys.argv[1:] if argv is None else argv
    if any(item in ("-h", "--help") for item in raw_argv):
        print("usage: notify_dingtalk.py [options]")
        return EXIT_OK
    try:
        args = parser.parse_args(raw_argv)
    except (UsageFailure, SystemExit):
        _summary(False, EXIT_USAGE, stream=sys.stderr)
        return EXIT_USAGE
    try:
        products = json.loads(args.matched_products_json)
        if not isinstance(products, list):
            raise ValueError("products must be a list")
        if min(args.verified_count, args.matched_count, args.fresh_count, args.multi_site_count) < 0:
            raise ValueError("negative count")
        _validate_public_url(args.dashboard_url, required=True)
        _validate_public_url(args.batch_url, required=False)
        title, text = build_message(args.verified_count, args.matched_count, args.fresh_count,
                                    args.multi_site_count, args.dashboard_url, products, args.batch_url)
    except Exception:
        _summary(False, EXIT_USAGE, stream=sys.stderr)
        return EXIT_USAGE
    if args.dry_run:
        _summary(False, dry_run=True)
        return EXIT_OK
    try:
        loader = _load if credential_loader is None else credential_loader
        webhook, secret = loader()
        sender = _default_transport if transport is None else transport
        now = time.time if clock is None else clock
        send(webhook, secret, title, text, transport=sender, clock=now)
    except NotifierFailure as failure:
        _summary(False, failure.code, stream=sys.stderr)
        return failure.code
    except Exception:
        _summary(False, EXIT_INTERNAL, stream=sys.stderr)
        return EXIT_INTERNAL
    _summary(True)
    return EXIT_OK


# Compatibility is intentionally private: public CLI callers cannot select a path.
_load = load_credentials


if __name__ == "__main__":
    raise SystemExit(main())
