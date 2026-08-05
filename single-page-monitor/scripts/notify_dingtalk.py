#!/usr/bin/env python3
"""Send one strict DingTalk markdown payload using a fixed protected secret.

The public CLI accepts JSON only on stdin and intentionally exposes no secret
path, credential, or transport override.  Keyword-only seams on ``main`` and
``load_credentials`` exist solely for isolated tests.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys
import time
import urllib.parse
import urllib.request


SECRET_RELATIVE = (".openclaw", "secrets", "sp-monitor", "report_delivery.json")
MAX_SECRET_BYTES = 16 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_CREDENTIAL_TEXT = 4096
DINGTALK_HOST = "oapi.dingtalk.com"
DINGTALK_PATH = "/robot/send"

EXIT_OK = 0
EXIT_ARGUMENT = 2
EXIT_SECRET = 3
EXIT_TRANSPORT = 4
EXIT_INTERNAL = 70
STATUS_PREFIX = "NOTIFY_SUMMARY_JSON "


class InputError(Exception):
    """A deliberately value-free input validation failure."""


class SecretError(Exception):
    """A deliberately value-free secret loading failure."""


class TransportError(Exception):
    """A deliberately value-free delivery failure."""


class Credentials:
    __slots__ = ("webhook", "secret")

    def __init__(self, webhook: str, secret: str):
        self.webhook = webhook
        self.secret = secret

    def __repr__(self) -> str:
        return "Credentials(webhook=<redacted>, secret=<redacted>)"


def _fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require_directory(value: os.stat_result, *, exact_0700: bool) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid():
        raise SecretError("credential source is unavailable")
    if exact_0700:
        if mode != 0o700:
            raise SecretError("credential source is unavailable")
    elif mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SecretError("credential source is unavailable")


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _validate_webhook(value: str) -> str:
    try:
        if (
            type(value) is not str
            or not value
            or len(value) > MAX_CREDENTIAL_TEXT
            or value != value.strip()
            or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)
        ):
            raise SecretError("credential file is invalid")
        parsed = urllib.parse.urlsplit(value)
        query = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
        token = query[0][1] if len(query) == 1 else ""
        if (
            parsed.scheme != "https"
            or parsed.hostname != DINGTALK_HOST
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.path != DINGTALK_PATH
            or parsed.fragment
            or len(query) != 1
            or query[0][0] != "access_token"
            or not token
            or len(token) > MAX_CREDENTIAL_TEXT
            or token != token.strip()
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in token)
        ):
            raise SecretError("credential file is invalid")
    except (UnicodeError, ValueError, SecretError):
        raise SecretError("credential file is invalid") from None
    return value


def _credential_locations(secret_path=None, trusted_home=None) -> tuple[Path, Path]:
    if secret_path is None and trusted_home is None:
        root = Path.home()
        return root, root.joinpath(*SECRET_RELATIVE)
    if trusted_home is None:
        raise SecretError("credential source is unavailable")
    root = Path(trusted_home)
    expected = root.joinpath(*SECRET_RELATIVE)
    path = expected if secret_path is None else Path(secret_path)
    if path != expected:
        raise SecretError("credential source is unavailable")
    return root, path


def load_credentials(secret_path=None, trusted_home=None) -> Credentials:
    """Read the fixed secret through a stable no-follow descriptor chain."""
    directory_fds: list[int] = []
    bindings: list[tuple[int, str, int, tuple[int, ...]]] = []
    file_fd = None
    raw = b""
    try:
        root, path = _credential_locations(secret_path, trusted_home)
        if not root.is_absolute() or not path.is_absolute():
            raise SecretError("credential source is unavailable")
        if getattr(os, "O_NOFOLLOW", None) is None:
            raise SecretError("credential source is unavailable")

        directory_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        root_fd = os.open(os.fspath(root), directory_flags)
        directory_fds.append(root_fd)
        root_stat = os.fstat(root_fd)
        _require_directory(root_stat, exact_0700=False)
        root_fingerprint = _fingerprint(root_stat)
        if root_fingerprint != _fingerprint(os.stat(root, follow_symlinks=False)):
            raise SecretError("credential source is unavailable")

        for index, component in enumerate(SECRET_RELATIVE[:-1]):
            parent_fd = directory_fds[-1]
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            directory_fds.append(child_fd)
            child_stat = os.fstat(child_fd)
            child_named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            _require_directory(
                child_stat,
                exact_0700=index == len(SECRET_RELATIVE[:-1]) - 1,
            )
            fingerprint = _fingerprint(child_stat)
            if fingerprint != _fingerprint(child_named):
                raise SecretError("credential source is unavailable")
            bindings.append((parent_fd, component, child_fd, fingerprint))

        parent_fd = directory_fds[-1]
        filename = SECRET_RELATIVE[-1]
        file_flags = (
            os.O_RDONLY
            | os.O_NONBLOCK
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        file_fd = os.open(filename, file_flags, dir_fd=parent_fd)
        initial = os.fstat(file_fd)
        named = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        initial_fingerprint = _fingerprint(initial)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_uid != os.geteuid()
            or stat.S_IMODE(initial.st_mode) != 0o600
            or initial.st_nlink != 1
            or initial.st_size > MAX_SECRET_BYTES
            or initial_fingerprint != _fingerprint(named)
        ):
            raise SecretError("credential source is unavailable")

        chunks = []
        remaining = MAX_SECRET_BYTES + 1
        while remaining:
            chunk = os.read(file_fd, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        final = os.fstat(file_fd)
        final_named = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(raw) > MAX_SECRET_BYTES
            or len(raw) != initial.st_size
            or initial_fingerprint != _fingerprint(final)
            or initial_fingerprint != _fingerprint(final_named)
        ):
            raise SecretError("credential source is unavailable")

        for bound_parent, component, child_fd, fingerprint in bindings:
            if fingerprint != _fingerprint(os.fstat(child_fd)):
                raise SecretError("credential source is unavailable")
            if fingerprint != _fingerprint(
                os.stat(component, dir_fd=bound_parent, follow_symlinks=False)
            ):
                raise SecretError("credential source is unavailable")
        if root_fingerprint != _fingerprint(os.fstat(root_fd)):
            raise SecretError("credential source is unavailable")
        if root_fingerprint != _fingerprint(os.stat(root, follow_symlinks=False)):
            raise SecretError("credential source is unavailable")
    except SecretError:
        raise
    except (AttributeError, OSError, TypeError, ValueError):
        raise SecretError("credential source is unavailable") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)

    try:
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError("BOM")
        payload = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_strict_object,
        )
        if type(payload) is not dict or set(payload) != {"webhook", "secret"}:
            raise ValueError("schema")
        canonical = (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if raw != canonical:
            raise ValueError("canonical")
        webhook = payload["webhook"]
        secret = payload["secret"]
        if (
            type(secret) is not str
            or not secret
            or len(secret) > MAX_CREDENTIAL_TEXT
            or secret != secret.strip()
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in secret)
        ):
            raise ValueError("schema")
        webhook = _validate_webhook(webhook)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError, SecretError, RecursionError):
        raise SecretError("credential file is invalid") from None
    return Credentials(webhook, secret)


def parse_payload(stream) -> dict:
    try:
        raw = stream.read(MAX_PAYLOAD_BYTES + 1)
    except Exception:
        raise InputError("invalid input") from None
    if type(raw) is str:
        raw = raw.encode("utf-8")
    if type(raw) is not bytes or not raw or len(raw) > MAX_PAYLOAD_BYTES:
        raise InputError("invalid input")
    try:
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError("BOM")
        payload = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_strict_object,
        )
        if type(payload) is not dict or set(payload) != {"msgtype", "markdown"}:
            raise ValueError("schema")
        markdown = payload["markdown"]
        if (
            payload["msgtype"] != "markdown"
            or type(markdown) is not dict
            or set(markdown) != {"title", "text"}
            or type(markdown["title"]) is not str
            or type(markdown["text"]) is not str
            or not markdown["title"].strip()
            or not markdown["text"].strip()
            or "\x00" in markdown["title"]
            or "\x00" in markdown["text"]
        ):
            raise ValueError("schema")
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        raise InputError("invalid input") from None
    return payload


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _default_transport(request, *, timeout):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(),
        _NoRedirect(),
    )
    return opener.open(request, timeout=timeout)


def send_payload(payload, credentials, *, transport=None, clock_ms=None) -> None:
    try:
        webhook = _validate_webhook(credentials.webhook)
        timestamp = str(int(time.time() * 1000) if clock_ms is None else int(clock_ms))
        to_sign = f"{timestamp}\n{credentials.secret}".encode("utf-8")
        signature = base64.b64encode(
            hmac.new(credentials.secret.encode("utf-8"), to_sign, hashlib.sha256).digest()
        ).decode("ascii")
        parsed = urllib.parse.urlsplit(webhook)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query.extend((("timestamp", timestamp), ("sign", signature)))
        signed_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), "")
        )
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_PAYLOAD_BYTES:
            raise TransportError("delivery failed")
        request = urllib.request.Request(
            signed_url,
            data=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        sender = _default_transport if transport is None else transport
        with sender(request, timeout=20) as response:
            status_code = getattr(response, "status", 200)
            response_bytes = response.read(MAX_RESPONSE_BYTES + 1)
        if status_code != 200 or len(response_bytes) > MAX_RESPONSE_BYTES:
            raise TransportError("delivery failed")
        response_payload = json.loads(
            response_bytes.decode("utf-8", "strict"),
            object_pairs_hook=_strict_object,
        )
        if type(response_payload) is not dict or type(response_payload.get("errcode")) is not int:
            raise TransportError("delivery failed")
        if response_payload["errcode"] != 0:
            raise TransportError("delivery failed")
    except TransportError:
        raise
    except Exception:
        raise TransportError("delivery failed") from None


def _emit(stream, **values) -> None:
    stream.write(STATUS_PREFIX + json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n")


def main(
    argv=None,
    *,
    input_stream=None,
    output_stream=None,
    error_stream=None,
    secret_path=None,
    trusted_home=None,
    transport=None,
    clock_ms=None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    output = sys.stdout if output_stream is None else output_stream
    error = sys.stderr if error_stream is None else error_stream
    source = sys.stdin.buffer if input_stream is None else input_stream
    if arguments not in ([], ["--dry-run"]):
        _emit(error, reason="invalid_arguments", sent=False)
        return EXIT_ARGUMENT
    try:
        payload = parse_payload(source)
    except InputError:
        _emit(error, reason="invalid_input", sent=False)
        return EXIT_ARGUMENT
    if arguments == ["--dry-run"]:
        _emit(output, dry_run=True, sent=False)
        return EXIT_OK
    try:
        credentials = load_credentials(secret_path=secret_path, trusted_home=trusted_home)
    except SecretError:
        _emit(error, reason="secret_unavailable", sent=False)
        return EXIT_SECRET
    except Exception:
        _emit(error, reason="internal_failure", sent=False)
        return EXIT_INTERNAL
    try:
        send_payload(payload, credentials, transport=transport, clock_ms=clock_ms)
    except TransportError:
        _emit(error, reason="transport_failed", sent=False)
        return EXIT_TRANSPORT
    except Exception:
        _emit(error, reason="internal_failure", sent=False)
        return EXIT_INTERNAL
    _emit(output, sent=True)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
