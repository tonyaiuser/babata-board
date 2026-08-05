#!/usr/bin/env python3
"""
SP集团每日爆品播报 — 每天11:30自动运行
策略：Top150站扫描 → 近3天新品 → 流量Top20旗舰站FB广告验证 → 推钉钉
"""
import argparse, copy, csv, json, re, urllib.request, urllib.parse, urllib.error, subprocess, time, hmac, hashlib, base64, random, os, shutil, gzip, threading, math, stat, zlib, binascii, importlib, importlib.util, sys, types, unicodedata
import concurrent.futures
import html as html_lib
import tempfile
from email.utils import parsedate_to_datetime
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


SHANGHAI_TIMEZONE = timezone(timedelta(hours=8))

IMPORTED_FROM_LIVE_SHA256 = "1f46674bf365bb7b7bc4f59aa581c4ac1e7776b80f447f72cf898d28a7145e00"
REPORT_DELIVERY_SECRET_FILE = (
    Path.home() / ".openclaw" / "secrets" / "sp-monitor" / "report_delivery.json"
)
REPORT_DELIVERY_TRUSTED_ROOT = Path.home()
_REPORT_DELIVERY_SECRET_KEYS = frozenset(("webhook", "secret"))
_REPORT_DELIVERY_SECRET_MAX_BYTES = 16 * 1024


class DingTalkCredentialError(RuntimeError):
    """A redacted credential-loading failure."""


class DingTalkDeliveryError(RuntimeError):
    """A redacted delivery failure."""


class _DingTalkCredentials:
    __slots__ = ("webhook", "secret")

    def __init__(self, webhook, secret):
        self.webhook = webhook
        self.secret = secret

    def __repr__(self):
        return "_DingTalkCredentials(webhook=<redacted>, secret=<redacted>)"


def _credential_stat_fingerprint(value):
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


def _require_secure_credential_directory(value):
    if not stat.S_ISDIR(value.st_mode):
        raise DingTalkCredentialError("credential directory is not secure")
    if value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise DingTalkCredentialError("credential directory is not secure")


def _require_trusted_credential_root(value):
    """Validate the account-owned home/root anchor without over-constraining it."""
    if not stat.S_ISDIR(value.st_mode):
        raise DingTalkCredentialError("credential directory is not secure")
    if value.st_uid != os.geteuid() or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise DingTalkCredentialError("credential directory is not secure")


def _verify_credential_directory_bindings(bindings):
    """Require every original parent/name/child relationship to remain intact."""
    for parent_fd, component, child_fd, initial_fingerprint in bindings:
        child_stat = os.fstat(child_fd)
        child_path_stat = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
        if (
            _credential_stat_fingerprint(child_stat) != initial_fingerprint
            or _credential_stat_fingerprint(child_path_stat) != initial_fingerprint
        ):
            raise DingTalkCredentialError("credential directory changed while reading")


def _load_dingtalk_credentials(secret_file=None, trusted_root=None):
    """Load credentials through a stable, no-follow descriptor chain."""
    path = REPORT_DELIVERY_SECRET_FILE if secret_file is None else Path(secret_file)
    root = REPORT_DELIVERY_TRUSTED_ROOT if trusted_root is None else Path(trusted_root)
    directory_fds = []
    directory_bindings = []
    file_fd = None
    try:
        if not path.is_absolute() or not root.is_absolute():
            raise DingTalkCredentialError("credential source is unavailable")
        try:
            relative = path.relative_to(root)
        except ValueError:
            raise DingTalkCredentialError("credential source is unavailable") from None
        parts = relative.parts
        if len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
            raise DingTalkCredentialError("credential source is unavailable")

        nofollow = os.O_NOFOLLOW
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | nofollow
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        root_fd = os.open(root, directory_flags)
        directory_fds.append(root_fd)
        root_stat = os.fstat(root_fd)
        _require_trusted_credential_root(root_stat)
        root_fingerprint = _credential_stat_fingerprint(root_stat)
        root_path_stat = os.stat(root, follow_symlinks=False)
        if root_fingerprint != _credential_stat_fingerprint(root_path_stat):
            raise DingTalkCredentialError("credential directory is not secure")

        for component in parts[:-1]:
            parent_fd = directory_fds[-1]
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            directory_fds.append(child_fd)
            child_stat = os.fstat(child_fd)
            child_path_stat = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            _require_secure_credential_directory(child_stat)
            if _credential_stat_fingerprint(child_stat) != _credential_stat_fingerprint(child_path_stat):
                raise DingTalkCredentialError("credential directory is not secure")
            directory_bindings.append(
                (parent_fd, component, child_fd, _credential_stat_fingerprint(child_stat))
            )

        directory_fd = directory_fds[-1]
        filename = parts[-1]

        file_flags = os.O_RDONLY | os.O_NONBLOCK | nofollow | getattr(os, "O_CLOEXEC", 0)
        file_fd = os.open(filename, file_flags, dir_fd=directory_fd)
        initial_stat = os.fstat(file_fd)
        initial_path_stat = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(initial_stat.st_mode):
            raise DingTalkCredentialError("credential file is not secure")
        if stat.S_IMODE(initial_stat.st_mode) != 0o600:
            raise DingTalkCredentialError("credential file is not secure")
        if initial_stat.st_uid != os.geteuid() or initial_stat.st_nlink != 1:
            raise DingTalkCredentialError("credential file is not secure")
        initial_fingerprint = _credential_stat_fingerprint(initial_stat)
        if initial_fingerprint != _credential_stat_fingerprint(initial_path_stat):
            raise DingTalkCredentialError("credential file is not secure")
        if initial_stat.st_size > _REPORT_DELIVERY_SECRET_MAX_BYTES:
            raise DingTalkCredentialError("credential file is invalid")

        chunks = []
        remaining = _REPORT_DELIVERY_SECRET_MAX_BYTES + 1
        while remaining:
            chunk = os.read(file_fd, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _REPORT_DELIVERY_SECRET_MAX_BYTES:
            raise DingTalkCredentialError("credential file is invalid")
        final_stat = os.fstat(file_fd)
        final_path_stat = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        if initial_fingerprint != _credential_stat_fingerprint(final_stat):
            raise DingTalkCredentialError("credential file changed while reading")
        if initial_fingerprint != _credential_stat_fingerprint(final_path_stat):
            raise DingTalkCredentialError("credential file changed while reading")
        if len(raw) != initial_stat.st_size:
            raise DingTalkCredentialError("credential file changed while reading")
        _verify_credential_directory_bindings(directory_bindings)
        if root_fingerprint != _credential_stat_fingerprint(os.fstat(root_fd)):
            raise DingTalkCredentialError("credential directory changed while reading")
        if root_fingerprint != _credential_stat_fingerprint(os.stat(root, follow_symlinks=False)):
            raise DingTalkCredentialError("credential directory changed while reading")
    except DingTalkCredentialError:
        raise
    except (AttributeError, OSError):
        raise DingTalkCredentialError("credential source is unavailable") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)

    def reject_duplicate_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    parse_failed = False
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        payload = None
        raw = None
        parse_failed = True
    if parse_failed:
        raise DingTalkCredentialError("credential file is invalid")
    if not isinstance(payload, dict) or set(payload) != _REPORT_DELIVERY_SECRET_KEYS:
        raise DingTalkCredentialError("credential file is invalid")
    webhook = payload.get("webhook")
    secret = payload.get("secret")
    if type(webhook) is not str or type(secret) is not str:
        raise DingTalkCredentialError("credential file is invalid")
    if not webhook.strip() or not secret.strip():
        raise DingTalkCredentialError("credential file is invalid")
    return _DingTalkCredentials(webhook, secret)


def shanghai_now_iso(now=None):
    """Return an explicit Asia/Shanghai-offset timestamp for trusted artifacts."""
    value = datetime.now(SHANGHAI_TIMEZONE) if now is None else now
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("scan clock must be timezone-aware")
    return value.astimezone(SHANGHAI_TIMEZONE).isoformat()


def shanghai_run_clock(now=None):
    """Derive every schema date and timestamp from one Shanghai instant."""
    value = datetime.now(SHANGHAI_TIMEZONE) if now is None else now
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("scan clock must be timezone-aware")
    now_shanghai = value.astimezone(SHANGHAI_TIMEZONE)
    return (
        now_shanghai,
        now_shanghai.strftime("%Y-%m-%d"),
        (now_shanghai - timedelta(days=1)).strftime("%Y-%m-%d"),
        (now_shanghai - timedelta(days=3)).strftime("%Y-%m-%d"),
    )


def _env_int(name, default, minimum=1):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _env_float(name, default, minimum=None, maximum=None):
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value


class CircuitConfig:
    def __init__(
        self,
        consecutive_threshold,
        rate_min_completed,
        rate_window,
        rate_threshold,
        long_retry_after,
        cooldown_seconds,
        cooldown_cap_seconds,
        cooldown_jitter_seconds,
    ):
        self.consecutive_threshold = int(consecutive_threshold)
        self.rate_min_completed = int(rate_min_completed)
        self.rate_window = int(rate_window)
        self.rate_threshold = float(rate_threshold)
        self.long_retry_after = float(long_retry_after)
        self.cooldown_seconds = float(cooldown_seconds)
        self.cooldown_cap_seconds = float(cooldown_cap_seconds)
        self.cooldown_jitter_seconds = float(cooldown_jitter_seconds)
        if not all(math.isfinite(value) for value in (
            self.rate_threshold,
            self.long_retry_after,
            self.cooldown_seconds,
            self.cooldown_cap_seconds,
            self.cooldown_jitter_seconds,
        )):
            raise ValueError("circuit numeric thresholds must be finite")
        if self.consecutive_threshold < 1:
            raise ValueError("consecutive_threshold must be >= 1")
        if self.rate_min_completed < 1 or self.rate_window < 1:
            raise ValueError("rate_min_completed and rate_window must be >= 1")
        if self.rate_min_completed > self.rate_window:
            raise ValueError("rate_min_completed must be <= rate_window")
        if not 0 < self.rate_threshold <= 1:
            raise ValueError("rate_threshold must be greater than 0 and at most 1")
        if self.long_retry_after < 0 or self.cooldown_seconds <= 0:
            raise ValueError("retry-after threshold must be >= 0 and cooldown must be > 0")
        if self.cooldown_cap_seconds < self.cooldown_seconds:
            raise ValueError("cooldown cap must be >= base cooldown")
        if not 0 <= self.cooldown_jitter_seconds <= self.cooldown_cap_seconds:
            raise ValueError("cooldown jitter must be between 0 and cooldown cap")

def translate_zh(text):
    """用 Google Translate 免费接口翻译英文产品名为中文，失败则返回空字符串"""
    try:
        params = urllib.parse.urlencode({"client": "gtx", "sl": "en", "tl": "zh-CN", "dt": "t", "q": text})
        req = urllib.request.Request(
            f"https://translate.googleapis.com/translate_a/single?{params}",
            headers={"User-Agent": "Mozilla/5.0"})
        with urlopen_with_retry(req, timeout=6) as r:
            data = json.loads(r.read())
        return "".join(part[0] for part in data[0] if part[0])
    except:
        return ""

WORKSPACE = Path.home() / ".openclaw/workspace"
DEFAULT_REPORT_STATE_FILE = WORKSPACE / "memory" / "sp_dingtalk_report_state.json"
REPORT_STATE_FILE = Path(os.environ.get("SP_REPORT_STATE_FILE", DEFAULT_REPORT_STATE_FILE))
SPSPY_PROJECT_DIR = Path(os.environ.get("SPSPY_PROJECT_DIR", str(Path.home() / "Desktop/spspy")))
DINGTALK_REPORT_DIR = SPSPY_PROJECT_DIR / "reports" / "dingtalk"
DINGTALK_IMAGE_CACHE = SPSPY_PROJECT_DIR / "data" / "images.json"
DINGTALK_PUBLIC_BASE_URL = os.environ.get("SPSPY_PUBLIC_BASE_URL", "https://tonyaiuser.github.io/babata-board").rstrip("/")
DINGTALK_IMAGE_BASE_URL = os.environ.get("SPSPY_IMAGE_BASE_URL", "https://raw.githubusercontent.com/tonyaiuser/babata-board/main").rstrip("/")
DINGTALK_DASHBOARD_URL = os.environ.get(
    "SP_DINGTALK_DASHBOARD_URL",
    f"{DINGTALK_PUBLIC_BASE_URL}/sp_picker_dashboard.html",
)
DINGTALK_IMAGE_LIMIT = int(os.environ.get("SP_DINGTALK_IMAGE_LIMIT", "8"))
DINGTALK_IMAGE_RETAIN_DAYS = int(os.environ.get("SP_DINGTALK_IMAGE_RETAIN_DAYS", "30"))
REPORT_DELIVERY_STORE_ROOT = Path.home() / ".spspy-report-delivery-outbox-v1"
REPORT_DELIVERY_GITHUB_REPOSITORY = "tonyaiuser/babata-board"
REPORT_DELIVERY_GITHUB_REF = "refs/heads/main"
REPORT_DELIVERY_GITHUB_PATH_PREFIX = "reports/dingtalk"
REPORT_DELIVERY_RAW_BASE_URL = (
    "https://raw.githubusercontent.com/tonyaiuser/babata-board/main"
)
REPORT_DELIVERY_GH_EXECUTABLE = "/opt/homebrew/bin/gh"
REPORT_DELIVERY_ENVELOPE_SCHEMA = "sp-report-delivery-envelope/v1"
REPORT_DELIVERY_PLAN_SCHEMA = "sp-report-dedupe-plan/v1"
REPORT_DELIVERY_RECEIPT_SCHEMA = "sp-report-delivery-receipt/v1"
_REPORT_DELIVERY_ENVELOPE_MAX_BYTES = 1024 * 1024
_REPORT_DELIVERY_PLAN_MAX_BYTES = 512 * 1024
_REPORT_DELIVERY_STATE_MAX_BYTES = 8 * 1024 * 1024
_REPORT_DELIVERY_GH_OUTPUT_MAX_BYTES = 2 * 1024 * 1024
_REPORT_DELIVERY_MODULE_CACHE = None
REPORT_SCAN_TOP_N = _env_int("SP_REPORT_SCAN_TOP_N", 150)
SCAN_MAX_WORKERS = _env_int("SP_MONITOR_MAX_WORKERS", 3)
PRODUCT_PAGE_SIZE = _env_int("SP_PRODUCT_PAGE_SIZE", 50)
PRODUCT_MAX_PAGES = _env_int("SP_PRODUCT_MAX_PAGES", 5)
MIN_SCAN_SUCCESS_RATIO = _env_float("SP_MONITOR_MIN_SUCCESS_RATIO", 0.80, 0.0, 1.0)
MIN_FLAGSHIP_SUCCESS_RATIO = _env_float("SP_MONITOR_MIN_FLAGSHIP_SUCCESS_RATIO", 0.80, 0.0, 1.0)
CIRCUIT_CONFIG = CircuitConfig(
    consecutive_threshold=_env_int("SP_MONITOR_429_CONSECUTIVE", 5),
    rate_min_completed=_env_int("SP_MONITOR_429_RATE_MIN_COMPLETED", 10),
    rate_window=_env_int("SP_MONITOR_429_RATE_WINDOW", 20),
    rate_threshold=_env_float("SP_MONITOR_429_RATE_THRESHOLD", 0.30, 0.0, 1.0),
    long_retry_after=_env_float("SP_MONITOR_429_LONG_RETRY_AFTER", 120.0, 0.0),
    cooldown_seconds=_env_float("SP_MONITOR_429_COOLDOWN_SECONDS", 120.0, 0.001),
    cooldown_cap_seconds=_env_float("SP_MONITOR_429_COOLDOWN_CAP_SECONDS", 300.0, 0.001),
    cooldown_jitter_seconds=_env_float("SP_MONITOR_429_COOLDOWN_JITTER_SECONDS", 15.0, 0.0),
)
SIGNIFICANT_SCORE_DELTA = 5.0
TOP_ENTRY_RANK = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Language": "en-GB,en;q=0.9",
    "Connection": "close",
}
CHROME_PROFILE = "chrome-relay"
TAB = "5CCF7743B4B3BD3A723972544B703D45"  # chrome-relay FB 登录 tab

# 旗舰站默认按 SimilarWeb 月访问量 Top N 动态生成；这里仅作为 CSV 不可用时的兜底名单。
FLAGSHIP_TOP_N = _env_int("SP_FLAGSHIP_TOP_N", 20)
STATIC_FLAGSHIP_FALLBACK = [
    {"name": "shimmer07",   "domain": "shimmer07.com",   "country": "GB", "weight": 6},
    {"name": "charm-cart",  "domain": "charm-cart.com",  "country": "GB", "weight": 5},
    {"name": "bebuyby",     "domain": "bebuyby.com",     "country": "GB", "weight": 4},
    {"name": "britneed",    "domain": "britneed.com",    "country": "GB", "weight": 4},
    {"name": "rouvenor",    "domain": "rouvenor.com",    "country": "US", "weight": 3},
    {"name": "copensunny",  "domain": "copensunny.com",  "country": "FR", "weight": 3},
    {"name": "loungon",     "domain": "loungon.com",     "country": "GB", "weight": 3},
    {"name": "boniss",      "domain": "boniss.com",      "country": "GB", "weight": 3},
    {"name": "londonnk",    "domain": "londonnk.com",    "country": "GB", "weight": 3},
]
FLAGSHIP_SP = STATIC_FLAGSHIP_FALLBACK
FLAGSHIP_DOMAINS = {f["domain"] for f in FLAGSHIP_SP}
FLAGSHIP_WEIGHT = {f["domain"]: f["weight"] for f in FLAGSHIP_SP}

# 钉钉 credentials are loaded lazily only by the real send path.
OPENCLAW_BIN = None


def resolve_openclaw_bin():
    global OPENCLAW_BIN
    if OPENCLAW_BIN:
        return OPENCLAW_BIN
    candidates = [
        os.environ.get("OPENCLAW_BIN", ""),
        "/opt/homebrew/bin/openclaw",
        shutil.which("openclaw") or "",
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            OPENCLAW_BIN = c
            return OPENCLAW_BIN
    return None


def _retry_after_seconds(headers, fallback):
    retry_after = headers.get("Retry-After", "") if headers else ""
    try:
        return max(float(retry_after), fallback)
    except (TypeError, ValueError):
        return fallback


def _optional_retry_after(headers, now=None):
    value = headers.get("Retry-After", "") if headers else ""
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        pass
    try:
        retry_at = parsedate_to_datetime(value)
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return max(0.0, (retry_at - current).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


class RateLimitCircuit:
    """Cross-worker CLOSED/OPEN/HALF_OPEN breaker driven by final per-site results."""

    def __init__(self, config, clock=time.monotonic, jitter_fn=None):
        self.config = config
        self._clock = clock
        self._jitter_fn = jitter_fn or random.uniform
        self.state = "CLOSED"
        self.open_reason = None
        self.cooldown_until = None
        self.consecutive_429 = 0
        self.recent_results = deque(maxlen=config.rate_window)
        self.completed_sites = set()
        self.http_429_sites = set()
        self.probe_in_flight = False
        self.probe_attempts = 0
        self.events = []
        self._lock = threading.Lock()

    def _open(self, reason, retry_after=None):
        if self.probe_attempts >= 1:
            self.state = "TERMINATED"
            self.open_reason = f"{reason}_after_probe"
            self.cooldown_until = None
            self.events.append({"event": "terminated", "reason": self.open_reason})
            return
        requested = max(self.config.cooldown_seconds, float(retry_after or 0.0))
        jitter = self._jitter_fn(0.0, self.config.cooldown_jitter_seconds)
        cooldown = min(self.config.cooldown_cap_seconds, requested + jitter)
        self.state = "OPEN"
        self.open_reason = reason
        self.cooldown_until = self._clock() + cooldown
        self.events.append({"event": "open", "reason": reason, "cooldown_seconds": cooldown})

    def record_site_result(self, domain, fetch_error, metadata=None, was_probe=False):
        metadata = metadata or {}
        with self._lock:
            if domain in self.completed_sites:
                return
            self.completed_sites.add(domain)
            is_429 = fetch_error == "http_429"
            self.recent_results.append(is_429)
            if is_429:
                self.http_429_sites.add(domain)
                self.consecutive_429 += 1
            else:
                self.consecutive_429 = 0

            if was_probe or self.state == "HALF_OPEN":
                self.probe_in_flight = False
                probe_succeeded = fetch_error is None and metadata.get("parsed_products") is True
                if not probe_succeeded:
                    self.state = "TERMINATED"
                    self.open_reason = "half_open_probe_failed"
                    self.events.append({
                        "event": "terminated",
                        "reason": self.open_reason,
                        "domain": domain,
                        "fetch_error": fetch_error,
                        "parsed_products": metadata.get("parsed_products") is True,
                    })
                else:
                    self.state = "CLOSED"
                    self.open_reason = None
                    self.cooldown_until = None
                    self.consecutive_429 = 0
                    self.recent_results.clear()
                    self.events.append({"event": "closed", "reason": "probe_succeeded", "domain": domain})
                return

            if self.state != "CLOSED":
                retry_after = metadata.get("retry_after")
                if (
                    self.state == "OPEN"
                    and is_429
                    and retry_after is not None
                    and retry_after >= self.config.long_retry_after
                ):
                    previous_until = self.cooldown_until
                    self._open("long_retry_after_inflight", retry_after)
                    if previous_until is not None:
                        self.cooldown_until = max(previous_until, self.cooldown_until)
                return

            retry_after = metadata.get("retry_after")
            long_retry = is_429 and retry_after is not None and retry_after >= self.config.long_retry_after
            recent_429_rate = (
                sum(self.recent_results) / len(self.recent_results) if self.recent_results else 0.0
            )
            rate_trigger = (
                len(self.recent_results) >= self.config.rate_min_completed
                and recent_429_rate >= self.config.rate_threshold
            )
            if long_retry:
                self._open("long_retry_after", retry_after)
            elif self.consecutive_429 >= self.config.consecutive_threshold:
                self._open("consecutive_429", retry_after)
            elif rate_trigger:
                self._open("recent_429_rate", retry_after)

    def remaining_cooldown(self):
        with self._lock:
            if self.state != "OPEN" or self.cooldown_until is None:
                return 0.0
            return max(0.0, self.cooldown_until - self._clock())

    def begin_probe(self):
        with self._lock:
            if self.state != "OPEN" or self.cooldown_until is None:
                return False
            if self._clock() < self.cooldown_until or self.probe_in_flight:
                return False
            if self.probe_attempts >= 1:
                self.state = "TERMINATED"
                self.open_reason = "probe_budget_exhausted"
                self.cooldown_until = None
                self.events.append({"event": "terminated", "reason": self.open_reason})
                return False
            self.state = "HALF_OPEN"
            self.probe_in_flight = True
            self.probe_attempts += 1
            self.events.append({"event": "half_open", "probe_number": self.probe_attempts})
            return True

    def snapshot(self):
        with self._lock:
            recent_rate = sum(self.recent_results) / len(self.recent_results) if self.recent_results else 0.0
            return {
                "state": self.state,
                "open_reason": self.open_reason,
                "completed_site_count": len(self.completed_sites),
                "429_site_count": len(self.http_429_sites),
                "consecutive_429": self.consecutive_429,
                "recent_window_size": len(self.recent_results),
                "recent_429_rate": round(recent_rate, 4),
                "probe_attempts": self.probe_attempts,
                "events": list(self.events),
            }


def _normalize_fetch_result(value):
    if len(value) == 2:
        products, error = value
        return products, error, {}
    products, error, metadata = value
    return products, error, metadata or {}


def scan_sites_bounded(sites, fetch_fn, max_workers, circuit, sleep_fn=time.sleep):
    """Scan without pre-submitting the pool; OPEN prevents all new submissions."""
    planned = list(sites)
    next_index = 0
    outcomes = []
    inflight = {}

    def submit_one(executor, is_probe=False):
        nonlocal next_index
        if next_index >= len(planned):
            return False
        item = planned[next_index]
        next_index += 1
        future = executor.submit(fetch_fn, item)
        inflight[future] = (item, is_probe)
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        while True:
            while circuit.state == "CLOSED" and len(inflight) < max_workers and next_index < len(planned):
                submit_one(executor)

            if not inflight:
                if next_index >= len(planned) or circuit.state == "TERMINATED":
                    break
                if circuit.state == "OPEN":
                    remaining = circuit.remaining_cooldown()
                    if remaining > 0:
                        sleep_fn(remaining)
                    if circuit.begin_probe():
                        submit_one(executor, is_probe=True)
                        continue
                if circuit.state == "HALF_OPEN":
                    continue
                if circuit.state == "CLOSED":
                    continue
                break

            done, _ = concurrent.futures.wait(
                tuple(inflight), return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                item, is_probe = inflight.pop(future)
                try:
                    products, error, metadata = _normalize_fetch_result(future.result())
                except Exception as exc:
                    products, error, metadata = [], f"worker:{type(exc).__name__}:{str(exc)[:100]}", {}
                row = {
                    "site": item,
                    "products": products,
                    "fetch_error": error,
                    "metadata": metadata,
                    "attempted": True,
                    "was_probe": is_probe,
                }
                outcomes.append(row)
                circuit.record_site_result(item["domain"], error, metadata, was_probe=is_probe)

    for item in planned[next_index:]:
        outcomes.append({
            "site": item,
            "products": [],
            "fetch_error": "circuit_open",
            "metadata": {},
            "attempted": False,
            "was_probe": False,
        })
    return outcomes, circuit.snapshot()


def urlopen_with_retry(req, timeout=8, retries=3, backoff=1.2):
    last_err = None
    for attempt in range(retries):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                raise
            if attempt < retries - 1:
                delay = min(30.0, _retry_after_seconds(e.headers, backoff * (attempt + 1)))
                time.sleep(delay)
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
    raise last_err


def read_json_response(response):
    raw = response.read()
    if (response.headers.get("Content-Encoding") or "").lower() == "gzip":
        raw = gzip.decompress(raw)
    return json.loads(raw)


class AtomicWriteCommitUncertain(OSError):
    """The target was replaced, but directory durability could not be proven."""

    def __init__(self, path, *, target_matches):
        super().__init__(f"atomic replace committed but directory fsync failed: {path}")
        self.path = Path(path)
        self.target_matches = target_matches


def atomic_write_json(path, payload):
    """Replace a JSON file only after a complete, fsynced temporary write."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    replaced = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        replaced = True
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException as exc:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        if replaced:
            try:
                target_matches = path.read_bytes() == serialized
            except OSError:
                target_matches = False
            raise AtomicWriteCommitUncertain(
                path, target_matches=target_matches
            ) from exc
        raise
    return path


def write_scan_failure_diagnostic(today, payload, workspace=WORKSPACE):
    """The sole persistence path for an unhealthy main scan."""
    return atomic_write_json(workspace / f"sp_scan_failed_{today}.json", payload)


def error_distribution(site_stats, planned_total=None):
    counts = defaultdict(int)
    for row in site_stats:
        error = row.get("fetch_error")
        if not error:
            counts["success"] += 1
        else:
            counts[str(error).split(":", 1)[0]] += 1
    if planned_total is not None and planned_total > len(site_stats):
        counts["not_loaded"] += planned_total - len(site_stats)
    return dict(sorted(counts.items()))


def evaluate_scan_health(
    site_stats,
    planned_total,
    expected_flagships,
    min_overall=MIN_SCAN_SUCCESS_RATIO,
    min_flagship=MIN_FLAGSHIP_SUCCESS_RATIO,
):
    attempted = sum(1 for row in site_stats if row.get("attempted", True) is True)
    successful = sum(
        1
        for row in site_stats
        if row.get("attempted", True) is True and not row.get("fetch_error")
    )
    flagship_rows = [row for row in site_stats if _as_int(row.get("rank"), 10**9) <= expected_flagships]
    flagship_success = sum(
        1
        for row in flagship_rows
        if row.get("attempted", True) is True and not row.get("fetch_error")
    )
    overall_ratio = successful / planned_total if planned_total else 0.0
    flagship_ratio = flagship_success / expected_flagships if expected_flagships else 0.0
    failed_gates = []
    if planned_total <= 0 or len(site_stats) != planned_total:
        failed_gates.append("planned_coverage")
    if overall_ratio < min_overall:
        failed_gates.append("overall_success_ratio")
    if expected_flagships <= 0 or len(flagship_rows) != expected_flagships:
        failed_gates.append("flagship_coverage")
    if flagship_ratio < min_flagship:
        failed_gates.append("flagship_success_ratio")
    overall = {
        "planned_total": planned_total,
        "sites_total": len(site_stats),
        "sites_successful": successful,
        "success_ratio": round(overall_ratio, 4),
    }
    top20 = {
        "planned_total": expected_flagships,
        "sites_total": len(flagship_rows),
        "sites_successful": flagship_success,
        "success_ratio": round(flagship_ratio, 4),
    }
    return {
        "healthy": not failed_gates,
        "overall": overall,
        "top20": top20,
        # Flat fields remain for older readers; nested overall/top20 are canonical.
        "planned_total": planned_total,
        "attempted_total": attempted,
        "success_total": successful,
        "overall_success_ratio": round(overall_ratio, 4),
        "required_overall_success_ratio": min_overall,
        "flagship_planned": expected_flagships,
        "flagship_attempted": sum(
            1 for row in flagship_rows if row.get("attempted", True) is True
        ),
        "flagship_success": flagship_success,
        "flagship_success_ratio": round(flagship_ratio, 4),
        "required_flagship_success_ratio": min_flagship,
        "failed_gates": failed_gates,
    }

def _dingtalk_signed_url(credentials=None):
    credentials = credentials or _load_dingtalk_credentials()
    ts = str(round(time.time() * 1000))
    sign = urllib.parse.quote_plus(
        base64.b64encode(hmac.new(credentials.secret.encode(),
            f"{ts}\n{credentials.secret}".encode(), digestmod=hashlib.sha256).digest()).decode())
    return f"{credentials.webhook}&timestamp={ts}&sign={sign}"


def send_dingtalk_payload(payload, max_attempts=3):
    if type(max_attempts) is not int or not 1 <= max_attempts <= 3:
        raise ValueError("max_attempts must be between 1 and 3")
    credentials = _load_dingtalk_credentials()
    data = (
        bytes(payload)
        if type(payload) is bytes
        else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    )
    for attempt in range(max_attempts):
        try:
            req = urllib.request.Request(
                _dingtalk_signed_url(credentials),
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                resp = json.loads(r.read())
            if resp.get("errcode") not in (None, 0):
                raise DingTalkDeliveryError("DingTalk delivery failed")
            return resp
        except (KeyboardInterrupt, MemoryError):
            raise
        except Exception:
            if attempt + 1 < max_attempts:
                time.sleep(1.5 * (attempt + 1))
    raise DingTalkDeliveryError("DingTalk delivery failed") from None


def send_dingtalk(content):
    return send_dingtalk_payload({"msgtype": "text", "text": {"content": content}})


def send_dingtalk_markdown(title, content):
    return send_dingtalk_payload({
        "msgtype": "markdown",
        "markdown": {
            "title": title,
            "text": content,
        },
    })


def _date_from_hotlist_path(path):
    m = re.search(r"sp_hotlist_(\d{4}-\d{2}-\d{2})\.json$", path.name)
    return m.group(1) if m else None


def _as_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def _as_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _domain_names(domains):
    return [d.replace(".com", "") for d in domains if d]


def _state_snapshot(row, rank, day, previous=None, reported=False):
    previous = previous or {}
    entry = dict(previous)
    entry.setdefault("first_seen", day)
    entry["last_seen"] = day
    entry["last_rank"] = rank
    entry["last_sites_count"] = _as_int(row.get("sites_count"))
    entry["last_score"] = _as_float(row.get("score"))
    entry["last_fb_hits"] = sorted(row.get("fb_hits") or [])
    entry["last_is_lp"] = bool(row.get("is_lp"))
    entry["last_flagship_count"] = _as_int(row.get("flagship_count"))
    if reported:
        entry["last_reported_at"] = day
    return entry


class ReportStateError(RuntimeError):
    """The report dedupe state cannot be trusted or durably persisted."""


class ReportStateCommitUncertain(ReportStateError):
    """The new state reached the target, but directory durability is uncertain."""

    def __init__(self, message, *, target_matches):
        super().__init__(message)
        self.target_matches = target_matches


def _require_report_day(value, field):
    if not isinstance(value, str):
        raise ReportStateError(f"{field} must be a YYYY-MM-DD string")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise ReportStateError(f"{field} must be a YYYY-MM-DD string") from exc
    if parsed.strftime("%Y-%m-%d") != value:
        raise ReportStateError(f"{field} must be a canonical YYYY-MM-DD string")


def _require_report_timestamp(value, field, allow_none=False):
    if value is None and allow_none:
        return
    if not isinstance(value, str) or not value:
        raise ReportStateError(f"{field} must be an ISO timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportStateError(f"{field} must be an ISO timestamp") from exc


def _require_nonnegative_int(value, field, positive=False):
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        comparator = "> 0" if positive else ">= 0"
        raise ReportStateError(f"{field} must be an integer {comparator}")


def _validate_report_delivery_receipt(receipt):
    keys = {
        "schema", "outbox_id", "digest", "handles", "plan_sha256",
        "next_state_sha256",
    }
    if not isinstance(receipt, dict) or set(receipt) != keys:
        raise ReportStateError("delivery_receipt has invalid fields")
    if receipt["schema"] != REPORT_DELIVERY_RECEIPT_SCHEMA:
        raise ReportStateError("delivery_receipt has invalid schema")
    if not isinstance(receipt["outbox_id"], str) or not re.fullmatch(
        r"rdo1-[0-9a-f]{64}", receipt["outbox_id"]
    ):
        raise ReportStateError("delivery_receipt has invalid outbox_id")
    for field in ("digest", "plan_sha256", "next_state_sha256"):
        if not isinstance(receipt[field], str) or not re.fullmatch(
            r"[0-9a-f]{64}", receipt[field]
        ):
            raise ReportStateError(f"delivery_receipt has invalid {field}")
    handles = receipt["handles"]
    if (
        not isinstance(handles, list)
        or not handles
        or handles != sorted(handles)
        or len(handles) != len(set(handles))
        or any(
            not isinstance(handle, str)
            or not handle
            or handle != unicodedata.normalize("NFC", handle)
            or len(handle.encode("utf-8")) > 255
            for handle in handles
        )
    ):
        raise ReportStateError("delivery_receipt has invalid handles")


def validate_report_state(state):
    if not isinstance(state, dict):
        raise ReportStateError("report state root must be an object")
    if isinstance(state.get("version"), bool) or state.get("version") != 1:
        raise ReportStateError(f"unsupported report state version: {state.get('version')!r}")
    for required in ("created_at", "last_run", "products"):
        if required not in state:
            raise ReportStateError(f"report state is missing required field: {required}")
    _require_report_timestamp(state["created_at"], "created_at")
    _require_report_timestamp(state["last_run"], "last_run", allow_none=True)
    for field in ("last_result_count", "last_reported_count"):
        if field in state:
            _require_nonnegative_int(state[field], field)
    if "bootstrapped_from" in state and (
        not isinstance(state["bootstrapped_from"], str) or not state["bootstrapped_from"]
    ):
        raise ReportStateError("bootstrapped_from must be a non-empty string")
    if "delivery_receipt" in state:
        _validate_report_delivery_receipt(state["delivery_receipt"])

    products = state["products"]
    if not isinstance(products, dict):
        raise ReportStateError("products must be an object")
    required_product_fields = (
        "first_seen",
        "last_seen",
        "last_rank",
        "last_sites_count",
        "last_score",
        "last_fb_hits",
        "last_is_lp",
        "last_flagship_count",
    )
    for handle, product in products.items():
        if not isinstance(handle, str) or not handle.strip():
            raise ReportStateError("product handles must be non-empty strings")
        if not isinstance(product, dict):
            raise ReportStateError(f"products[{handle!r}] must be an object")
        missing = [field for field in required_product_fields if field not in product]
        if missing:
            raise ReportStateError(
                f"products[{handle!r}] is missing required fields: {', '.join(missing)}"
            )
        _require_report_day(product["first_seen"], f"products[{handle!r}].first_seen")
        _require_report_day(product["last_seen"], f"products[{handle!r}].last_seen")
        if "last_reported_at" in product:
            _require_report_day(
                product["last_reported_at"], f"products[{handle!r}].last_reported_at"
            )
        _require_nonnegative_int(product["last_rank"], f"products[{handle!r}].last_rank", positive=True)
        _require_nonnegative_int(
            product["last_sites_count"], f"products[{handle!r}].last_sites_count"
        )
        _require_nonnegative_int(
            product["last_flagship_count"], f"products[{handle!r}].last_flagship_count"
        )
        score = product["last_score"]
        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(float(score))
        ):
            raise ReportStateError(f"products[{handle!r}].last_score must be finite numeric")
        fb_hits = product["last_fb_hits"]
        if not isinstance(fb_hits, list) or any(
            not isinstance(domain, str) or not domain for domain in fb_hits
        ):
            raise ReportStateError(f"products[{handle!r}].last_fb_hits must be a string list")
        if not isinstance(product["last_is_lp"], bool):
            raise ReportStateError(f"products[{handle!r}].last_is_lp must be boolean")
    return state


def load_report_state(today):
    if REPORT_STATE_FILE.exists() or REPORT_STATE_FILE.is_symlink():
        try:
            exists, state = _strict_report_state_snapshot(REPORT_STATE_FILE)
        except ReportDeliveryIntegrityError as exc:
            raise ReportStateError("report state is unreadable or unsafe") from exc
        if not exists:
            raise ReportStateError("report state disappeared while reading")
        return state

    state = {
        "version": 1,
        "created_at": datetime.now().isoformat(),
        "last_run": None,
        "products": {},
    }
    prev_day, prev_payload = latest_healthy_snapshot_before(today, WORKSPACE)
    if not prev_payload:
        return validate_report_state(state)

    prev_results = prev_payload["results"]
    seen_handles = set()
    for rank, row in enumerate(prev_results, 1):
        if not isinstance(row, dict):
            raise ReportStateError(f"bootstrap results[{rank - 1}] must be an object")
        handle = row.get("handle")
        if not isinstance(handle, str) or not handle.strip():
            raise ReportStateError(f"bootstrap results[{rank - 1}].handle must be a non-empty string")
        if handle in seen_handles:
            raise ReportStateError(f"bootstrap snapshot contains duplicate handle: {handle}")
        seen_handles.add(handle)
        state["products"][handle] = _state_snapshot(
            row, rank, prev_day, reported=True
        )
    prev_path = WORKSPACE / f"sp_hotlist_{prev_day}.json"
    state["bootstrapped_from"] = str(prev_path)
    validate_report_state(state)
    print(
        f"报告状态未初始化，已在内存中用 {prev_path.name} 建立基线 "
        f"{len(state['products'])} 个品；仅在通知成功后持久化",
        flush=True,
    )
    return state


def change_reasons(row, previous, rank, allow_rank_reason=False):
    if not previous:
        return ["首次发现"]

    reasons = []
    sites = _as_int(row.get("sites_count"))
    prev_sites = _as_int(previous.get("last_sites_count"))
    site_delta = sites - prev_sites
    if site_delta > 0:
        reasons.append(f"铺货+{site_delta}站")

    score = _as_float(row.get("score"))
    prev_score = _as_float(previous.get("last_score"))
    score_delta = score - prev_score
    if score_delta >= SIGNIFICANT_SCORE_DELTA:
        reasons.append(f"分数+{score_delta:.1f}")

    fb_hits = set(row.get("fb_hits") or [])
    prev_fb_hits = set(previous.get("last_fb_hits") or [])
    new_fb = sorted(fb_hits - prev_fb_hits)
    if new_fb:
        reasons.append("新增FB:" + "+".join(_domain_names(new_fb)))

    if row.get("is_lp") and not previous.get("last_is_lp"):
        reasons.append("新增LP")

    prev_rank = _as_int(previous.get("last_rank"), 999)
    if allow_rank_reason and rank <= TOP_ENTRY_RANK < prev_rank and (site_delta > 0 or score_delta >= 1):
        reasons.append(f"新进Top{TOP_ENTRY_RANK}")

    return reasons


def classify_report_changes(results, state, today):
    products_state = state.get("products", {})
    changes = []
    allow_rank_reason = bool(state.get("last_run")) and len(results) > TOP_ENTRY_RANK
    for rank, row in enumerate(results, 1):
        handle = row.get("handle")
        if not handle:
            continue
        previous = products_state.get(handle)
        reasons = change_reasons(row, previous, rank, allow_rank_reason=allow_rank_reason)
        if reasons:
            changes.append({"row": row, "rank": rank, "reasons": reasons})

    groups = {"new": [], "signal": [], "growth": []}
    for item in changes:
        reasons = item["reasons"]
        if "首次发现" in reasons:
            groups["new"].append(item)
        elif any(r.startswith("新增FB") or r == "新增LP" for r in reasons):
            groups["signal"].append(item)
        else:
            groups["growth"].append(item)

    for items in groups.values():
        items.sort(key=lambda x: _as_float(x["row"].get("score")), reverse=True)
    return groups


def build_next_report_state(
    state,
    results,
    delivered_handles,
    today,
    changed_handles=None,
    frozen_at=None,
):
    """Purely build the next dedupe state for one frozen delivery intent."""
    validate_report_state(state)
    delivered_handles = set(delivered_handles)
    changed_handles = delivered_handles if changed_handles is None else set(changed_handles)
    if not delivered_handles.issubset(changed_handles):
        raise ReportStateError("delivered handles must be a subset of changed handles")
    next_state = copy.deepcopy(state)
    next_state.pop("delivery_receipt", None)
    products_state = {}
    for existing_handle, product in next_state["products"].items():
        canonical_handle = unicodedata.normalize("NFC", existing_handle)
        if canonical_handle in products_state:
            raise ReportStateError("report state contains canonically duplicate handles")
        products_state[canonical_handle] = product
    next_state["products"] = products_state
    for rank, row in enumerate(results, 1):
        raw_handle = row.get("handle")
        if not raw_handle:
            continue
        handle = unicodedata.normalize("NFC", raw_handle) if isinstance(raw_handle, str) else raw_handle
        if handle in changed_handles and handle not in delivered_handles:
            continue
        products_state[handle] = _state_snapshot(
            row,
            rank,
            today,
            previous=products_state.get(handle),
            reported=handle in delivered_handles,
        )
    next_state["last_run"] = datetime.now().isoformat() if frozen_at is None else frozen_at
    next_state["last_result_count"] = len(results)
    next_state["last_reported_count"] = len(delivered_handles)
    validate_report_state(next_state)
    return next_state


def save_report_state(state, results, delivered_handles, today, changed_handles=None):
    """Decommissioned: receipt-bound R1/B dedupe is the only persistence path."""
    raise ReportDeliveryInputError("legacy report state persistence is disabled")


def render_report_item(item, icon):
    row = item["row"]
    reasons = "、".join(item["reasons"])
    title = row["title"][:55]
    zh = translate_zh(row["title"]) or ""
    fs = "、".join(_domain_names(row.get("flagship_hits") or [])) or "无旗舰"
    fb = "、".join(_domain_names(row.get("fb_hits") or [])) or "-"
    lp = "LP+" if row.get("is_lp") else ""
    country_str = "/".join(row.get("countries", [])) or "?"
    delta = row.get("spread_delta", 0)
    spread = f" +{delta}站" if delta else ""
    lines = [
        f"{icon} {title}",
    ]
    if zh:
        lines.append(f"   {zh}")
    lines.append(f"   变化:{reasons}")
    lines.append(
        f"   ${row['price']} | {row['sites_count']}站{spread} | {country_str} | {row.get('published_at', '')} | 总分:{_as_float(row.get('score')):.1f}"
    )
    lines.append(f"   FB:{lp}{fb} | 旗舰:{fs}")
    lines.append(f"   {row['sample_url']}")
    return lines


def append_change_section(lines, title, items, limit, icons):
    if not items:
        return []
    selected = items[:limit]
    lines.append(title)
    for i, item in enumerate(selected):
        icon = icons[i] if i < len(icons) else f"#{i + 1}"
        lines.extend(render_report_item(item, icon))
        lines.append("")
    return [x["row"]["handle"] for x in selected]


def select_visual_report_items(change_groups, limit=DINGTALK_IMAGE_LIMIT):
    selected = []
    seen = set()
    for group_name in ("new", "signal", "growth"):
        for item in change_groups.get(group_name, []):
            handle = item["row"].get("handle")
            if not handle or handle in seen:
                continue
            selected.append(item)
            seen.add(handle)
            if len(selected) >= limit:
                return selected
    return selected


def _load_image_cache():
    if not DINGTALK_IMAGE_CACHE.exists():
        return {}
    try:
        with open(DINGTALK_IMAGE_CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_image_cache(cache):
    DINGTALK_IMAGE_CACHE.parent.mkdir(parents=True, exist_ok=True)
    with open(DINGTALK_IMAGE_CACHE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def _image_url_from_cache_entry(entry):
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return entry.get("url") or ""
    return ""


def _candidate_product_urls(row):
    urls = []
    sample_url = row.get("sample_url")
    if sample_url:
        urls.append(sample_url)
    handle = row.get("handle")
    for site in row.get("sites") or []:
        if not handle:
            continue
        alt = f"https://{site}/products/{handle}"
        if alt not in urls:
            urls.append(alt)
    return urls[:4]


def _normalize_image_url(img_url, page_url):
    img_url = (img_url or "").strip()
    if not img_url:
        return ""
    if img_url.startswith("//"):
        return "https:" + img_url
    if img_url.startswith("http://"):
        return "https://" + img_url[len("http://"):]
    if img_url.startswith("https://"):
        return img_url
    return urllib.parse.urljoin(page_url, img_url)


def _product_payload_image(product):
    candidates = []
    image = product.get("image")
    if isinstance(image, dict):
        candidates.append(image)
    candidates.extend(product.get("images") or [])
    for item in candidates:
        if isinstance(item, dict) and item.get("src"):
            return _normalize_image_url(item["src"], "")
    return ""


def _extract_meta_image(page_html, page_url):
    for tag in re.findall(r"<meta\s+[^>]+>", page_html, re.I):
        if not re.search(r'(?:property|name)=["\'](?:og:image|twitter:image)["\']', tag, re.I):
            continue
        m = re.search(r'content=["\']([^"\']+)["\']', tag, re.I)
        if m:
            return _normalize_image_url(html_lib.unescape(m.group(1)), page_url)
    return ""


def _fetch_shopify_image(product_url, handle):
    parsed = urllib.parse.urlparse(product_url)
    if not parsed.scheme or not parsed.netloc or not handle:
        return ""
    api_url = f"{parsed.scheme}://{parsed.netloc}/products/{handle}.json"
    req = urllib.request.Request(api_url, headers=HEADERS)
    try:
        with urlopen_with_retry(req, timeout=6, retries=1) as r:
            data = json.loads(r.read())
        images = data.get("product", {}).get("images", [])
        if images:
            return images[0].get("src") or ""
    except Exception:
        return ""
    return ""


def _fetch_product_image(row):
    handle = row.get("handle", "")
    for product_url in _candidate_product_urls(row):
        req = urllib.request.Request(product_url, headers={**HEADERS, "Accept": "text/html,application/xhtml+xml"})
        try:
            with urlopen_with_retry(req, timeout=6, retries=1) as r:
                page_html = r.read(1500000).decode("utf-8", errors="ignore")
            img_url = _extract_meta_image(page_html, product_url)
            if img_url:
                return img_url
        except Exception:
            pass

        img_url = _fetch_shopify_image(product_url, handle)
        if img_url:
            return img_url
    return ""


def _image_data_url(img_url):
    if not img_url:
        return ""
    parsed = urllib.parse.urlparse(img_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if "/cdn/shop/" in parsed.path and "width" not in query:
        query["width"] = ["600"]
        parsed = parsed._replace(query=urllib.parse.urlencode(query, doseq=True))
        img_url = urllib.parse.urlunparse(parsed)
    req = urllib.request.Request(
        img_url,
        headers={
            "User-Agent": HEADERS["User-Agent"],
            "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
            "Referer": f"{parsed.scheme}://{parsed.netloc}/",
            "Connection": "close",
        },
    )
    try:
        with urlopen_with_retry(req, timeout=20, retries=2, backoff=2.0) as r:
            raw = r.read(8_000_001)
            content_type = (r.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if not raw or len(raw) > 8_000_000:
            return ""
        if not content_type.startswith("image/"):
            if raw.startswith(b"\xff\xd8\xff"):
                content_type = "image/jpeg"
            elif raw.startswith(b"\x89PNG\r\n\x1a\n"):
                content_type = "image/png"
            elif raw.startswith((b"GIF87a", b"GIF89a")):
                content_type = "image/gif"
            elif raw.startswith(b"RIFF") and raw[8:12] == b"WEBP":
                content_type = "image/webp"
            else:
                return ""
        return f"data:{content_type};base64,{base64.b64encode(raw).decode('ascii')}"
    except Exception:
        return ""


def ensure_visual_item_images(items, today):
    cache = _load_image_cache()
    changed = False
    for item in items:
        row = item["row"]
        handle = row.get("handle")
        img_url = _image_url_from_cache_entry(cache.get(handle)) if handle else ""
        if not img_url and handle:
            img_url = _fetch_product_image(row)
            cache[handle] = {
                "url": img_url or None,
                "fetched_at": today,
                "source": "dingtalk_report",
                "error_type": None if img_url else "not_found",
                "error": None if img_url else "image not found for selected report item",
            }
            changed = True
            if img_url:
                print(f"  [图片] {handle}: {img_url[:80]}...", flush=True)
            else:
                print(f"  [图片] {handle}: 未抓到，使用占位图", flush=True)
        if img_url.startswith("http://"):
            img_url = "https://" + img_url[len("http://"):]
        row["_image_url"] = img_url
    if changed:
        _save_image_cache(cache)

    rows_with_images = [item["row"] for item in items if item["row"].get("_image_url")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(rows_with_images) or 1)) as ex:
        futures = {ex.submit(_image_data_url, row["_image_url"]): row for row in rows_with_images}
        for future in concurrent.futures.as_completed(futures):
            row = futures[future]
            embedded = future.result()
            row["_image_url"] = embedded
            if not embedded:
                print(f"  [图片] {row.get('handle', '?')}: 下载失败，使用占位图", flush=True)


def _short_text(text, limit):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _format_price(price):
    value = str(price or "0").strip()
    if value.startswith(("$", "€", "£", "¥")):
        return value
    return f"€{value}"


def _format_report_date(value):
    value = str(value or "")
    m = re.match(r"(\d{4}-\d{2}-\d{2})", value)
    if m:
        return m.group(1)[5:]
    return value or "-"


def _primary_reason(reasons):
    if not reasons:
        return "新变化"
    reason = reasons[0]
    if reason == "首次发现":
        return "新发现"
    if reason.startswith("新增FB"):
        return "新FB"
    if reason == "新增LP":
        return "新LP"
    if reason.startswith("铺货+"):
        return reason.replace("铺货", "")
    return reason


def _report_chip(label, class_name=""):
    cls = f"chip {class_name}".strip()
    return f'<span class="{cls}">{html_lib.escape(str(label))}</span>'


def build_visual_report_html(items, today, results_count, changed_count):
    overflow_count = max(0, changed_count - len(items))
    cards = []
    for visual_rank, item in enumerate(items, 1):
        row = item["row"]
        title = html_lib.escape(_short_text(row.get("title"), 88))
        handle = html_lib.escape(row.get("handle", ""))
        img_url = row.get("_image_url") or ""
        if img_url:
            image_html = f'<img src="{html_lib.escape(img_url, quote=True)}" alt="{title}" referrerpolicy="no-referrer" />'
        else:
            words = [w[:1].upper() for w in re.findall(r"[A-Za-z0-9]+", row.get("handle", ""))[:2]]
            initials = "".join(words) or "SP"
            image_html = f'<div class="placeholder">{html_lib.escape(initials)}</div>'

        score = _as_float(row.get("score"))
        delta = _as_int(row.get("spread_delta"))
        flagship_count = _as_int(row.get("flagship_count"))
        site_count = _as_int(row.get("sites_count"))
        chips = [
            _report_chip("💰 " + _format_price(row.get("price")), "money"),
            _report_chip(f"🏬 {site_count}站", "site"),
            _report_chip(f"⭐ {flagship_count}旗舰", "flagship"),
            _report_chip(_primary_reason(item.get("reasons")), "reason"),
        ]
        if delta > 0:
            chips.append(_report_chip(f"+{delta}站", "delta"))
        chips.append(_report_chip("🛒 " + _format_report_date(row.get("published_at")), "date"))
        if row.get("is_lp"):
            chips.append(_report_chip("LP", "lp"))
        if row.get("fb_hits"):
            chips.append(_report_chip("FB投放", "fb"))

        cards.append(f"""
        <article class="card">
          <div class="media">
            {image_html}
            <div class="rank">#{visual_rank}</div>
            <div class="new-badge">NEW</div>
          </div>
          <div class="info">
            <div class="title-row">
              <h2>{title}</h2>
              <div class="score">⭐ {score:.1f}</div>
            </div>
            <div class="handle">{handle}</div>
            <div class="chips">{"".join(chips)}</div>
            <div class="link-button">🔗 样品链接</div>
          </div>
        </article>
        """)

    overflow_html = ""
    if overflow_count:
        overflow_html = f'<div class="overflow">还有 {overflow_count} 个变化品，点钉钉里的完整看板查看。</div>'

    css = """
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: #eef2f7;
      color: #172033;
      font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
    }
    #report {
      width: 720px;
      padding: 22px 18px 24px;
      background: linear-gradient(180deg, #f8fbff 0%, #eef3f8 100%);
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
      margin: 2px 2px 14px;
    }
    .eyebrow {
      color: #536078;
      font-size: 20px;
      font-weight: 700;
      margin-bottom: 4px;
    }
    h1 {
      margin: 0;
      font-size: 34px;
      line-height: 1.15;
      letter-spacing: 0;
    }
    .date {
      flex: 0 0 auto;
      color: #5a43f1;
      background: #ffffff;
      border: 1px solid #dfe5f0;
      border-radius: 16px;
      padding: 10px 14px;
      font-size: 22px;
      font-weight: 800;
      box-shadow: 0 4px 14px rgba(36, 46, 77, 0.08);
    }
    .stats {
      display: flex;
      gap: 10px;
      margin: 0 2px 16px;
      color: #5d6980;
      font-size: 20px;
      font-weight: 700;
    }
    .stat {
      background: #ffffff;
      border: 1px solid #dfe5f0;
      border-radius: 14px;
      padding: 9px 12px;
    }
    .card {
      display: grid;
      grid-template-columns: 190px 1fr;
      gap: 14px;
      min-height: 206px;
      margin: 13px 0;
      padding: 10px;
      border: 3px solid #ff8a2a;
      border-radius: 18px;
      background: #ffffff;
      box-shadow: 0 7px 18px rgba(30, 46, 82, 0.12);
      overflow: hidden;
    }
    .media {
      position: relative;
      width: 190px;
      height: 190px;
      border-radius: 12px;
      overflow: hidden;
      background: #e8edf5;
    }
    .media img {
      display: block;
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    .placeholder {
      width: 100%;
      height: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #eaf0f8, #d7e1ef);
      color: #6d7790;
      font-size: 42px;
      font-weight: 900;
    }
    .rank {
      position: absolute;
      top: 8px;
      left: 8px;
      min-width: 58px;
      text-align: center;
      padding: 5px 8px;
      border-radius: 999px;
      color: #ffffff;
      font-size: 19px;
      font-weight: 900;
      background: linear-gradient(180deg, #ffb321, #fa7a19);
      box-shadow: 0 2px 8px rgba(94, 54, 9, 0.25);
    }
    .new-badge {
      position: absolute;
      top: 8px;
      right: 8px;
      padding: 5px 9px;
      border-radius: 7px;
      color: #ffffff;
      font-size: 17px;
      font-weight: 900;
      background: #ff673f;
      box-shadow: 0 2px 8px rgba(97, 33, 21, 0.22);
    }
    .info {
      min-width: 0;
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding: 2px 0 0;
    }
    .title-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: start;
    }
    h2 {
      margin: 0;
      min-height: 60px;
      color: #172033;
      font-size: 25px;
      line-height: 1.2;
      letter-spacing: 0;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }
    .score {
      color: #18a56b;
      background: #ebfff5;
      border-radius: 12px;
      padding: 5px 8px;
      font-size: 20px;
      font-weight: 900;
      white-space: nowrap;
    }
    .handle {
      color: #68748a;
      font-size: 19px;
      line-height: 1.2;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      align-items: center;
    }
    .chip {
      min-height: 29px;
      display: inline-flex;
      align-items: center;
      border-radius: 9px;
      padding: 4px 8px;
      background: #f1f4f8;
      color: #526077;
      font-size: 18px;
      line-height: 1;
      font-weight: 800;
      white-space: nowrap;
    }
    .chip.money { color: #357047; background: #edf9f0; }
    .chip.site { color: #3d586d; background: #eef6fb; }
    .chip.flagship { color: #a46a00; background: #fff5d8; }
    .chip.reason { color: #0e63b6; background: #eaf4ff; }
    .chip.delta { color: #14966f; background: #eafaf4; }
    .chip.lp, .chip.fb { color: #9b3a24; background: #fff0e8; }
    .link-button {
      margin-top: auto;
      width: 100%;
      height: 42px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 10px;
      background: #625cf2;
      color: #ffffff;
      font-size: 20px;
      font-weight: 900;
    }
    .overflow {
      margin: 18px 4px 0;
      padding: 14px 16px;
      border-radius: 14px;
      background: #ffffff;
      color: #526077;
      font-size: 21px;
      font-weight: 800;
      text-align: center;
      border: 1px solid #dfe5f0;
    }
    """

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <style>{css}</style>
</head>
<body>
  <main id="report">
    <section class="topbar">
      <div>
        <div class="eyebrow">Top 产品列表 · 只推新变化</div>
        <h1>SP集团爆品变化日报</h1>
      </div>
      <div class="date">{html_lib.escape(today)}</div>
    </section>
    <section class="stats">
      <div class="stat">候选 {results_count}</div>
      <div class="stat">变化 {changed_count}</div>
      <div class="stat">Top{REPORT_SCAN_TOP_N} 站</div>
    </section>
    {"".join(cards)}
    {overflow_html}
  </main>
</body>
</html>"""


def render_html_to_png(report_html, output_path):
    old_font_wait_setting = os.environ.get("PW_TEST_SCREENSHOT_NO_FONTS_READY")
    os.environ["PW_TEST_SCREENSHOT_NO_FONTS_READY"] = "1"
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        raise RuntimeError(f"Playwright 不可用: {e}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".html", encoding="utf-8", delete=False) as f:
            f.write(report_html)
            tmp_path = Path(f.name)

        with sync_playwright() as p:
            chrome_path = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            if chrome_path.exists():
                browser = p.chromium.launch(headless=True, executable_path=str(chrome_path))
            else:
                browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 760, "height": 2200}, device_scale_factor=1)
            page.goto(tmp_path.as_uri(), wait_until="domcontentloaded", timeout=15000)
            try:
                page.wait_for_function(
                    "() => Array.from(document.images).every(img => img.complete)",
                    timeout=8000,
                )
            except Exception:
                page.wait_for_timeout(2000)
            page.locator("#report").screenshot(
                path=str(output_path),
                animations="disabled",
                timeout=90000,
            )
            browser.close()
    finally:
        if old_font_wait_setting is None:
            os.environ.pop("PW_TEST_SCREENSHOT_NO_FONTS_READY", None)
        else:
            os.environ["PW_TEST_SCREENSHOT_NO_FONTS_READY"] = old_font_wait_setting
        if tmp_path:
            try:
                tmp_path.unlink()
            except Exception:
                pass

    if not output_path.exists() or output_path.stat().st_size < 5000:
        raise RuntimeError(f"图片生成失败或文件过小: {output_path}")


def cleanup_old_report_images(today):
    if not DINGTALK_REPORT_DIR.exists():
        return
    cutoff = datetime.strptime(today, "%Y-%m-%d") - timedelta(days=DINGTALK_IMAGE_RETAIN_DAYS)
    for path in DINGTALK_REPORT_DIR.glob("sp_report_*.png"):
        m = re.search(r"sp_report_(\d{4}-\d{2}-\d{2})\.png$", path.name)
        if not m:
            continue
        try:
            file_day = datetime.strptime(m.group(1), "%Y-%m-%d")
        except Exception:
            continue
        if file_day < cutoff:
            path.unlink()


def public_url_for_report_image(image_path):
    rel = image_path.relative_to(SPSPY_PROJECT_DIR).as_posix()
    return f"{DINGTALK_IMAGE_BASE_URL}/{urllib.parse.quote(rel, safe='/')}"


def ensure_repo_git_identity():
    """Decommissioned: report publication never mutates local Git identity."""
    raise ReportDeliveryInputError("legacy report Git publication is disabled")


def publish_report_image(image_path, today):
    """Decommissioned: R1/B GitHub CAS is the only report publication path."""
    raise ReportDeliveryInputError("legacy report Git publication is disabled")


def create_dingtalk_report_image(change_groups, today, results_count, changed_count, publish=True):
    if publish is not False:
        raise ReportDeliveryInputError("legacy report Git publication is disabled")
    items = select_visual_report_items(change_groups)
    if not items:
        raise RuntimeError("没有可渲染的变化商品")
    print(f"生成钉钉图片日报: {len(items)} 个商品", flush=True)
    ensure_visual_item_images(items, today)
    report_html = build_visual_report_html(items, today, results_count, changed_count)
    image_path = DINGTALK_REPORT_DIR / f"sp_report_{today}.png"
    render_html_to_png(report_html, image_path)
    return {"path": image_path, "url": str(image_path), "items": items}


def build_dingtalk_image_markdown(
    today, results_count, changed_count, image_url, items, release_receipt=None
):
    lines = [
        f"### 🔥 SP集团爆品变化日报（{today}）",
        f"近3天新品 × 流量Top{FLAGSHIP_TOP_N}旗舰站FB验证 × 只推变化",
        "",
        f"候选{results_count}个 | 今日变化{changed_count}个 | 扫描Top{REPORT_SCAN_TOP_N}站",
        "",
        f"![SP日报]({image_url})",
        "",
    ]
    lines.extend(dashboard_notification_lines(release_receipt))
    link_items = [item for item in items[:5] if item["row"].get("sample_url")]
    if link_items:
        lines.extend(["", "样品链接："])
        for item in link_items:
            row = item["row"]
            title = _short_text(row.get("title"), 38)
            lines.append(f"- [{title}]({row['sample_url']})")
    return "\n".join(lines)


def dashboard_notification_lines(release_receipt):
    """Return only a verified dashboard link, never a possibly stale one."""
    if isinstance(release_receipt, dict):
        source_date = release_receipt.get("source_date")
        source_hash = release_receipt.get("source_hash")
        if (
            isinstance(source_date, str)
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}", source_date)
            and isinstance(source_hash, str)
            and re.fullmatch(r"[0-9a-f]{64}", source_hash)
        ):
            return [
                f"看板已核验：数据日 {source_date} · 源哈希 {source_hash[:12]}",
                f"[查看完整看板]({DINGTALK_DASHBOARD_URL})",
            ]
    return ["⚠️ 完整看板本次刷新/发布未核验成功，未附链接以避免指向旧数据。"]


class NotificationDeliveryError(RuntimeError):
    def __init__(self, image_error, fallback_error):
        super().__init__(f"image delivery failed: {image_error}; text fallback failed: {fallback_error}")
        self.image_error = str(image_error)
        self.fallback_error = str(fallback_error)


def send_change_notification(
    change_groups,
    today,
    results_count,
    changed_count,
    text_message,
    text_delivered_handles,
    dashboard_receipt,
):
    """Decommissioned: durable R1/B delivery is the only notification path."""
    raise ReportDeliveryInputError("legacy report notification is disabled")


class ReportDeliveryInputError(RuntimeError):
    """A deterministic, redacted report-delivery input failure."""


class ReportDeliveryIntegrityError(RuntimeError):
    """A frozen delivery intent or local state failed closed validation."""


class ReportGithubTransportError(RuntimeError):
    """The fixed GitHub transport failed without exposing command output."""


def _report_delivery_sha256(value):
    return hashlib.sha256(value).hexdigest()


def _canonical_report_delivery_json(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ReportDeliveryInputError("report delivery JSON is not canonicalizable") from exc


def _unique_report_delivery_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_report_delivery_constant(_value):
    raise ValueError("non-finite JSON number")


def _strict_report_delivery_json(value, *, max_bytes, require_canonical=False):
    if type(value) is not bytes or not value or len(value) > max_bytes:
        raise ReportDeliveryIntegrityError("report delivery JSON exceeds limits")
    if value.startswith(b"\xef\xbb\xbf"):
        raise ReportDeliveryIntegrityError("report delivery JSON is invalid")
    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_unique_report_delivery_object,
            parse_constant=_reject_report_delivery_constant,
        )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise ReportDeliveryIntegrityError("report delivery JSON is invalid") from exc
    if require_canonical and _canonical_report_delivery_json(parsed) != value:
        raise ReportDeliveryIntegrityError("report delivery JSON is not canonical")
    return parsed


def _report_delivery_fingerprint(value):
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


def _read_report_delivery_regular(path, *, max_bytes, missing_ok=False):
    """Read one stable, same-owner, single-link regular file without following links."""
    path = Path(path)
    try:
        named_before = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ReportDeliveryIntegrityError("report delivery file is unavailable") from None
    except OSError as exc:
        raise ReportDeliveryIntegrityError("report delivery file is unavailable") from exc
    if (
        not stat.S_ISREG(named_before.st_mode)
        or named_before.st_uid != os.geteuid()
        or named_before.st_nlink != 1
        or named_before.st_size > max_bytes
    ):
        raise ReportDeliveryIntegrityError("report delivery file is unsafe")
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        expected = _report_delivery_fingerprint(named_before)
        if (
            _report_delivery_fingerprint(opened) != expected
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
        ):
            raise ReportDeliveryIntegrityError("report delivery file changed while reading")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > max_bytes:
            raise ReportDeliveryIntegrityError("report delivery file exceeds limits")
        final = os.fstat(descriptor)
        named_after = os.lstat(path)
        if (
            _report_delivery_fingerprint(final) != expected
            or _report_delivery_fingerprint(named_after) != expected
            or len(value) != opened.st_size
        ):
            raise ReportDeliveryIntegrityError("report delivery file changed while reading")
        return value
    except ReportDeliveryIntegrityError:
        raise
    except OSError as exc:
        raise ReportDeliveryIntegrityError("report delivery file is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _canonical_report_state_bytes(state):
    validate_report_state(state)
    return _canonical_report_delivery_json(state)


def _strict_report_state_snapshot(path=REPORT_STATE_FILE):
    value = _read_report_delivery_regular(
        path, max_bytes=_REPORT_DELIVERY_STATE_MAX_BYTES, missing_ok=True
    )
    if value is None:
        return False, None
    state = _strict_report_delivery_json(
        value, max_bytes=_REPORT_DELIVERY_STATE_MAX_BYTES
    )
    try:
        validate_report_state(state)
    except ReportStateError as exc:
        raise ReportDeliveryIntegrityError("report state is invalid") from exc
    return True, state


def _canonical_report_handles(value, *, allow_empty=False):
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ReportDeliveryIntegrityError("report delivery handles are invalid")
    handles = []
    try:
        for handle in value:
            if not isinstance(handle, str):
                raise ValueError
            normalized = unicodedata.normalize("NFC", handle)
            if (
                not normalized
                or len(normalized.encode("utf-8")) > 255
                or any(unicodedata.category(char) == "Cc" for char in normalized)
            ):
                raise ValueError
            handles.append(normalized)
    except (UnicodeError, ValueError):
        raise ReportDeliveryIntegrityError("report delivery handles are invalid")
    if not allow_empty and not handles:
        raise ReportDeliveryIntegrityError("report delivery handles are invalid")
    canonical = sorted(handles)
    if len(canonical) != len(set(canonical)):
        raise ReportDeliveryIntegrityError("report delivery handles are invalid")
    return canonical


def _validate_report_delivery_wire(channel, wire):
    if channel == "primary":
        if not isinstance(wire, dict) or set(wire) != {"msgtype", "markdown"}:
            raise ReportDeliveryIntegrityError("primary wire is invalid")
        markdown = wire.get("markdown")
        if (
            wire.get("msgtype") != "markdown"
            or not isinstance(markdown, dict)
            or set(markdown) != {"title", "text"}
            or not isinstance(markdown.get("title"), str)
            or not markdown.get("title")
            or not isinstance(markdown.get("text"), str)
            or not markdown.get("text")
        ):
            raise ReportDeliveryIntegrityError("primary wire is invalid")
    elif channel == "fallback":
        if not isinstance(wire, dict) or set(wire) != {"msgtype", "text"}:
            raise ReportDeliveryIntegrityError("fallback wire is invalid")
        text_payload = wire.get("text")
        if (
            wire.get("msgtype") != "text"
            or not isinstance(text_payload, dict)
            or set(text_payload) != {"content"}
            or not isinstance(text_payload.get("content"), str)
            or not text_payload.get("content")
        ):
            raise ReportDeliveryIntegrityError("fallback wire is invalid")
    else:
        raise ReportDeliveryIntegrityError("report delivery channel is invalid")
    return wire


def _validate_report_delivery_plan(plan, *, expected_channel=None, expected_handles=None):
    keys = {
        "schema", "channel", "prior_exists", "prior_state_sha256",
        "frozen_last_run", "changed_handles", "delivered_handles",
        "next_state", "next_state_sha256",
    }
    if not isinstance(plan, dict) or set(plan) != keys:
        raise ReportDeliveryIntegrityError("report delivery plan has invalid fields")
    if plan["schema"] != REPORT_DELIVERY_PLAN_SCHEMA:
        raise ReportDeliveryIntegrityError("report delivery plan has invalid schema")
    channel = plan["channel"]
    if channel not in ("primary", "fallback") or (
        expected_channel is not None and channel != expected_channel
    ):
        raise ReportDeliveryIntegrityError("report delivery plan channel is invalid")
    if type(plan["prior_exists"]) is not bool:
        raise ReportDeliveryIntegrityError("report delivery plan prior binding is invalid")
    prior_sha = plan["prior_state_sha256"]
    if not isinstance(prior_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", prior_sha):
        raise ReportDeliveryIntegrityError("report delivery plan prior binding is invalid")
    try:
        _require_report_timestamp(plan["frozen_last_run"], "frozen_last_run")
    except ReportStateError as exc:
        raise ReportDeliveryIntegrityError("report delivery plan timestamp is invalid") from exc
    changed = _canonical_report_handles(plan["changed_handles"])
    delivered = _canonical_report_handles(plan["delivered_handles"])
    if changed != plan["changed_handles"] or delivered != plan["delivered_handles"]:
        raise ReportDeliveryIntegrityError("report delivery plan handles are not canonical")
    if not set(delivered).issubset(changed):
        raise ReportDeliveryIntegrityError("report delivery plan handles are invalid")
    if expected_handles is not None and tuple(delivered) != tuple(expected_handles):
        raise ReportDeliveryIntegrityError("report delivery plan handles do not match intent")
    next_state = plan["next_state"]
    try:
        validate_report_state(next_state)
    except ReportStateError as exc:
        raise ReportDeliveryIntegrityError("report delivery next state is invalid") from exc
    if "delivery_receipt" in next_state or next_state.get("last_run") != plan["frozen_last_run"]:
        raise ReportDeliveryIntegrityError("report delivery next state binding is invalid")
    next_bytes = _canonical_report_state_bytes(next_state)
    next_sha = plan["next_state_sha256"]
    if (
        not isinstance(next_sha, str)
        or not re.fullmatch(r"[0-9a-f]{64}", next_sha)
        or _report_delivery_sha256(next_bytes) != next_sha
    ):
        raise ReportDeliveryIntegrityError("report delivery next state hash is invalid")
    return plan


def build_report_delivery_plan(
    *, channel, prior_exists, prior_state, next_state,
    changed_handles, delivered_handles, frozen_last_run
):
    changed = _canonical_report_handles(changed_handles)
    delivered = _canonical_report_handles(delivered_handles)
    if not set(delivered).issubset(changed):
        raise ReportDeliveryInputError("delivered handles are outside changed handles")
    prior_bytes = _canonical_report_state_bytes(prior_state)
    next_bytes = _canonical_report_state_bytes(next_state)
    plan = {
        "schema": REPORT_DELIVERY_PLAN_SCHEMA,
        "channel": channel,
        "prior_exists": prior_exists,
        "prior_state_sha256": _report_delivery_sha256(prior_bytes),
        "frozen_last_run": frozen_last_run,
        "changed_handles": changed,
        "delivered_handles": delivered,
        "next_state": copy.deepcopy(next_state),
        "next_state_sha256": _report_delivery_sha256(next_bytes),
    }
    try:
        return _validate_report_delivery_plan(plan)
    except ReportDeliveryIntegrityError as exc:
        raise ReportDeliveryInputError("report delivery plan is invalid") from exc


def build_report_delivery_envelope(channel, wire, plan):
    try:
        _validate_report_delivery_wire(channel, wire)
        _validate_report_delivery_plan(plan, expected_channel=channel)
    except ReportDeliveryIntegrityError as exc:
        raise ReportDeliveryInputError("report delivery envelope input is invalid") from exc
    wire_bytes = _canonical_report_delivery_json(wire)
    plan_bytes = _canonical_report_delivery_json(plan)
    if len(plan_bytes) > _REPORT_DELIVERY_PLAN_MAX_BYTES:
        raise ReportDeliveryInputError("report delivery plan exceeds limits")
    compressed = zlib.compress(plan_bytes, level=9)
    encoded = base64.b64encode(compressed).decode("ascii")
    envelope = {
        "schema": REPORT_DELIVERY_ENVELOPE_SCHEMA,
        "channel": channel,
        "wire": {
            "payload": copy.deepcopy(wire),
            "size": len(wire_bytes),
            "sha256": _report_delivery_sha256(wire_bytes),
        },
        "plan": {
            "encoding": "zlib+base64",
            "b64": encoded,
            "size": len(plan_bytes),
            "compressed_size": len(compressed),
            "sha256": _report_delivery_sha256(plan_bytes),
        },
    }
    value = _canonical_report_delivery_json(envelope)
    if len(value) > _REPORT_DELIVERY_ENVELOPE_MAX_BYTES:
        raise ReportDeliveryInputError("report delivery envelope exceeds limits")
    decode_report_delivery_envelope(value, expected_channel=channel)
    return value


def _bounded_decompress_report_plan(compressed):
    if type(compressed) is not bytes or len(compressed) > _REPORT_DELIVERY_PLAN_MAX_BYTES:
        raise ReportDeliveryIntegrityError("compressed report plan exceeds limits")
    inflater = zlib.decompressobj()
    try:
        value = inflater.decompress(compressed, _REPORT_DELIVERY_PLAN_MAX_BYTES + 1)
        if len(value) > _REPORT_DELIVERY_PLAN_MAX_BYTES:
            raise ReportDeliveryIntegrityError("decompressed report plan exceeds limits")
        flushed = inflater.flush(_REPORT_DELIVERY_PLAN_MAX_BYTES + 1 - len(value))
        value += flushed
    except (zlib.error, ValueError) as exc:
        raise ReportDeliveryIntegrityError("compressed report plan is invalid") from exc
    if (
        len(value) > _REPORT_DELIVERY_PLAN_MAX_BYTES
        or not inflater.eof
        or inflater.unused_data
        or inflater.unconsumed_tail
    ):
        raise ReportDeliveryIntegrityError("compressed report plan is invalid")
    return value


def decode_report_delivery_envelope(value, *, expected_channel=None, expected_handles=None):
    envelope = _strict_report_delivery_json(
        value,
        max_bytes=_REPORT_DELIVERY_ENVELOPE_MAX_BYTES,
        require_canonical=True,
    )
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "channel", "wire", "plan"}:
        raise ReportDeliveryIntegrityError("report delivery envelope has invalid fields")
    if envelope["schema"] != REPORT_DELIVERY_ENVELOPE_SCHEMA:
        raise ReportDeliveryIntegrityError("report delivery envelope has invalid schema")
    channel = envelope["channel"]
    if channel not in ("primary", "fallback") or (
        expected_channel is not None and channel != expected_channel
    ):
        raise ReportDeliveryIntegrityError("report delivery envelope channel is invalid")
    wire_entry = envelope["wire"]
    if not isinstance(wire_entry, dict) or set(wire_entry) != {"payload", "size", "sha256"}:
        raise ReportDeliveryIntegrityError("report delivery wire envelope is invalid")
    wire = _validate_report_delivery_wire(channel, wire_entry["payload"])
    wire_bytes = _canonical_report_delivery_json(wire)
    if (
        type(wire_entry["size"]) is not int
        or wire_entry["size"] != len(wire_bytes)
        or not isinstance(wire_entry["sha256"], str)
        or _report_delivery_sha256(wire_bytes) != wire_entry["sha256"]
    ):
        raise ReportDeliveryIntegrityError("report delivery wire integrity is invalid")
    plan_entry = envelope["plan"]
    if not isinstance(plan_entry, dict) or set(plan_entry) != {
        "encoding", "b64", "size", "compressed_size", "sha256"
    }:
        raise ReportDeliveryIntegrityError("report delivery plan envelope is invalid")
    if plan_entry["encoding"] != "zlib+base64" or not isinstance(plan_entry["b64"], str):
        raise ReportDeliveryIntegrityError("report delivery plan encoding is invalid")
    try:
        compressed = base64.b64decode(plan_entry["b64"].encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise ReportDeliveryIntegrityError("report delivery plan base64 is invalid") from exc
    if base64.b64encode(compressed).decode("ascii") != plan_entry["b64"]:
        raise ReportDeliveryIntegrityError("report delivery plan base64 is not canonical")
    if (
        type(plan_entry["compressed_size"]) is not int
        or plan_entry["compressed_size"] != len(compressed)
        or type(plan_entry["size"]) is not int
        or plan_entry["size"] < 1
        or plan_entry["size"] > _REPORT_DELIVERY_PLAN_MAX_BYTES
    ):
        raise ReportDeliveryIntegrityError("report delivery plan size is invalid")
    plan_bytes = _bounded_decompress_report_plan(compressed)
    if (
        len(plan_bytes) != plan_entry["size"]
        or not isinstance(plan_entry["sha256"], str)
        or _report_delivery_sha256(plan_bytes) != plan_entry["sha256"]
    ):
        raise ReportDeliveryIntegrityError("report delivery plan integrity is invalid")
    plan = _strict_report_delivery_json(
        plan_bytes,
        max_bytes=_REPORT_DELIVERY_PLAN_MAX_BYTES,
        require_canonical=True,
    )
    _validate_report_delivery_plan(
        plan, expected_channel=channel, expected_handles=expected_handles
    )
    return {
        "channel": channel,
        "wire": wire,
        "wire_bytes": wire_bytes,
        "wire_sha256": wire_entry["sha256"],
        "plan": plan,
        "plan_bytes": plan_bytes,
        "plan_sha256": plan_entry["sha256"],
    }


class ReportStateDedupeAdapter:
    """Apply the frozen channel plan exactly once, including ACK-loss recovery."""

    def __init__(self, payload_bytes, *, state_path=REPORT_STATE_FILE, adapters_module=None):
        self.decoded = decode_report_delivery_envelope(payload_bytes)
        self.state_path = Path(state_path)
        self.adapters = adapters_module

    def _integrity(self, message):
        cls = self.adapters.DedupeIntegrityError if self.adapters else ReportDeliveryIntegrityError
        return cls(message)

    def apply(self, outbox_id, digest, handles):
        if not isinstance(outbox_id, str) or not re.fullmatch(r"rdo1-[0-9a-f]{64}", outbox_id):
            raise self._integrity("dedupe identity is invalid")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise self._integrity("dedupe digest is invalid")
        plan = self.decoded["plan"]
        exact_handles = tuple(plan["delivered_handles"])
        if tuple(handles) != exact_handles:
            raise self._integrity("dedupe handles do not match frozen plan")
        current_exists, current = _strict_report_state_snapshot(self.state_path)
        if current_exists and "delivery_receipt" in current:
            receipt = current["delivery_receipt"]
            if receipt["outbox_id"] == outbox_id:
                expected = {
                    "schema": REPORT_DELIVERY_RECEIPT_SCHEMA,
                    "outbox_id": outbox_id,
                    "digest": digest,
                    "handles": list(exact_handles),
                    "plan_sha256": self.decoded["plan_sha256"],
                    "next_state_sha256": plan["next_state_sha256"],
                }
                if receipt != expected:
                    raise self._integrity("same outbox id has a different dedupe receipt")
                without_receipt = copy.deepcopy(current)
                without_receipt.pop("delivery_receipt", None)
                if without_receipt != plan["next_state"]:
                    raise self._integrity("dedupe receipt does not bind current state")
                return {"outbox_id": outbox_id, "digest": digest, "outcome": "unchanged"}
        if current_exists != plan["prior_exists"]:
            raise self._integrity("report state existence diverged from frozen plan")
        if current_exists:
            current_sha = _report_delivery_sha256(_canonical_report_state_bytes(current))
            if current_sha != plan["prior_state_sha256"]:
                raise self._integrity("report state diverged from frozen plan")
        next_state = copy.deepcopy(plan["next_state"])
        next_state["delivery_receipt"] = {
            "schema": REPORT_DELIVERY_RECEIPT_SCHEMA,
            "outbox_id": outbox_id,
            "digest": digest,
            "handles": list(exact_handles),
            "plan_sha256": self.decoded["plan_sha256"],
            "next_state_sha256": plan["next_state_sha256"],
        }
        try:
            validate_report_state(next_state)
            atomic_write_json(self.state_path, next_state)
        except AtomicWriteCommitUncertain:
            raise
        except (OSError, TypeError, ValueError, ReportStateError) as exc:
            raise self._integrity("report state apply failed") from exc
        written_exists, written = _strict_report_state_snapshot(self.state_path)
        if not written_exists or written != next_state:
            raise self._integrity("report state apply verification failed")
        return {"outbox_id": outbox_id, "digest": digest, "outcome": "applied"}


def _load_report_delivery_modules():
    """Load only the helper copies deployed beside this exact entrypoint."""
    global _REPORT_DELIVERY_MODULE_CACHE
    if _REPORT_DELIVERY_MODULE_CACHE is not None:
        return _REPORT_DELIVERY_MODULE_CACHE
    missing = object()
    module_names = (
        "scripts",
        "scripts.report_delivery_outbox_v1",
        "scripts.report_delivery_adapters_v1",
    )
    previous_modules = {name: sys.modules.get(name, missing) for name in module_names}
    previous_package = previous_modules["scripts"]
    previous_attributes = {}
    if previous_package is not missing:
        previous_attributes = {
            name: getattr(previous_package, name, missing)
            for name in (
                "__package__", "__path__",
                "report_delivery_outbox_v1", "report_delivery_adapters_v1",
            )
        }

    def restore_partial_load():
        global _REPORT_DELIVERY_MODULE_CACHE
        _REPORT_DELIVERY_MODULE_CACHE = None
        for name, previous in previous_modules.items():
            if previous is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
        if previous_package is not missing:
            for name, previous in previous_attributes.items():
                if previous is missing:
                    try:
                        delattr(previous_package, name)
                    except AttributeError:
                        pass
                else:
                    setattr(previous_package, name, previous)

    failed = False
    try:
        run_file_value = globals().get("__file__")
        if not isinstance(run_file_value, str) or not Path(run_file_value).is_absolute():
            raise RuntimeError
        scripts_dir = Path(run_file_value).resolve().parent / "scripts"
        sources = (
            ("report_delivery_outbox_v1", scripts_dir / "report_delivery_outbox_v1.py"),
            ("report_delivery_adapters_v1", scripts_dir / "report_delivery_adapters_v1.py"),
        )
        if any(not source.is_file() for _name, source in sources):
            raise RuntimeError
        package = previous_package
        if package is missing:
            package = types.ModuleType("scripts")
            sys.modules["scripts"] = package
        package.__package__ = "scripts"
        package.__path__ = [str(scripts_dir)]
        modules = []
        for short_name, source in sources:
            full_name = "scripts." + short_name
            spec = importlib.util.spec_from_file_location(full_name, source)
            if spec is None or spec.loader is None:
                raise RuntimeError
            module = importlib.util.module_from_spec(spec)
            sys.modules[full_name] = module
            setattr(package, short_name, module)
            spec.loader.exec_module(module)
            modules.append(module)
        outbox, adapters = modules
        required_outbox = ("create_record", "resume_action", "record_sha256", "ResumeAction")
        required_adapters = (
            "initialize_store", "open_transaction", "publish_github", "deliver",
            "apply_dedupe", "project", "GithubPolicy",
        )
        if any(not hasattr(outbox, name) for name in required_outbox) or any(
            not hasattr(adapters, name) for name in required_adapters
        ):
            raise RuntimeError
    except (KeyboardInterrupt, MemoryError, SystemExit):
        restore_partial_load()
        raise
    except Exception:
        restore_partial_load()
        failed = True
    if failed:
        raise ReportDeliveryInputError("report delivery modules are unavailable") from None
    _REPORT_DELIVERY_MODULE_CACHE = (outbox, adapters)
    return _REPORT_DELIVERY_MODULE_CACHE


_REPORT_GITHUB_OID = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"


class ReportGithubTransport:
    """A fixed, allowlisted `gh api` transport for the report image CAS."""

    def __init__(self, executable=REPORT_DELIVERY_GH_EXECUTABLE, *, timeout=20):
        if executable != REPORT_DELIVERY_GH_EXECUTABLE:
            raise ReportGithubTransportError("GitHub executable is outside policy")
        if type(timeout) is not int or not 1 <= timeout <= 60:
            raise ReportGithubTransportError("GitHub timeout is invalid")
        self.executable = executable
        self.timeout = timeout

    @staticmethod
    def _allowed(method, path):
        prefix = "/repos/tonyaiuser/babata-board"
        exact = {
            ("GET", prefix + "/git/ref/heads/main"),
            ("PATCH", prefix + "/git/refs/heads/main"),
            ("POST", prefix + "/git/blobs"),
            ("POST", prefix + "/git/trees"),
            ("POST", prefix + "/git/commits"),
        }
        if (method, path) in exact:
            return True
        if method != "GET":
            return False
        patterns = (
            rf"{re.escape(prefix)}/git/commits/{_REPORT_GITHUB_OID}",
            rf"{re.escape(prefix)}/git/blobs/{_REPORT_GITHUB_OID}",
            rf"{re.escape(prefix)}/git/trees/{_REPORT_GITHUB_OID}\?recursive=1",
            rf"{re.escape(prefix)}/compare/{_REPORT_GITHUB_OID}\.\.\.{_REPORT_GITHUB_OID}",
        )
        return any(re.fullmatch(pattern, path) for pattern in patterns)

    @staticmethod
    def _parse_include(value):
        if type(value) is not bytes or not value or len(value) > _REPORT_DELIVERY_GH_OUTPUT_MAX_BYTES:
            raise ReportGithubTransportError("GitHub response exceeds limits")
        normalized = value.replace(b"\r\n", b"\n")
        if b"\r" in normalized:
            raise ReportGithubTransportError("GitHub response framing is invalid")
        try:
            header, body = normalized.split(b"\n\n", 1)
        except ValueError as exc:
            raise ReportGithubTransportError("GitHub response framing is invalid") from exc
        lines = header.split(b"\n")
        match = re.fullmatch(rb"HTTP/(?:1\.[01]|2(?:\.0)?) ([1-5][0-9]{2})(?: [^\r\n]*)?", lines[0])
        if match is None or any(line.startswith(b"HTTP/") for line in lines[1:]):
            raise ReportGithubTransportError("GitHub response status is invalid")
        seen_headers = set()
        for line in lines[1:]:
            if b":" not in line:
                raise ReportGithubTransportError("GitHub response headers are invalid")
            name, _ignored = line.split(b":", 1)
            lowered = name.strip().lower()
            if not re.fullmatch(rb"[a-z0-9-]+", lowered) or lowered in seen_headers:
                raise ReportGithubTransportError("GitHub response headers are invalid")
            seen_headers.add(lowered)
        if b"\nHTTP/" in body or body.startswith(b"HTTP/"):
            raise ReportGithubTransportError("GitHub response contains multiple messages")
        if not body.strip():
            parsed = {}
        else:
            try:
                parsed = _strict_report_delivery_json(
                    body, max_bytes=_REPORT_DELIVERY_GH_OUTPUT_MAX_BYTES
                )
            except ReportDeliveryIntegrityError as exc:
                raise ReportGithubTransportError("GitHub response body is invalid") from exc
            if not isinstance(parsed, dict):
                raise ReportGithubTransportError("GitHub response body is invalid")
        return int(match.group(1)), parsed

    def request(self, method, path, body=None):
        if method not in ("GET", "POST", "PATCH") or not isinstance(path, str):
            raise ReportGithubTransportError("GitHub request is invalid")
        if not self._allowed(method, path):
            raise ReportGithubTransportError("GitHub endpoint is outside policy")
        if body is None:
            body = {}
        if not isinstance(body, dict):
            raise ReportGithubTransportError("GitHub request body is invalid")
        stdin = _canonical_report_delivery_json(body)
        argv = [
            self.executable,
            "api",
            "--include",
            "--method",
            method,
            path,
            "--input",
            "-",
        ]
        allowed_environment = (
            "HOME", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "LANG", "LC_ALL",
            "SSL_CERT_FILE", "SSL_CERT_DIR",
        )
        environment = {
            name: os.environ[name]
            for name in allowed_environment
            if name in os.environ
        }
        environment["NO_COLOR"] = "1"
        try:
            completed = subprocess.run(
                argv,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                timeout=self.timeout,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReportGithubTransportError("GitHub transport is unavailable") from exc
        status, response = self._parse_include(completed.stdout)
        if completed.returncode != 0 and status not in (409, 422):
            raise ReportGithubTransportError("GitHub transport failed")
        return {"status": status, "body": response}

    def ancestry(self, ancestor, tip):
        if (
            not isinstance(ancestor, str)
            or not isinstance(tip, str)
            or not re.fullmatch(_REPORT_GITHUB_OID, ancestor)
            or not re.fullmatch(_REPORT_GITHUB_OID, tip)
        ):
            return None
        path = (
            f"/repos/{REPORT_DELIVERY_GITHUB_REPOSITORY}/compare/"
            f"{ancestor}...{tip}"
        )
        try:
            response = self.request("GET", path)
        except ReportGithubTransportError:
            return None
        if response["status"] != 200:
            return None
        comparison = response["body"].get("status")
        if comparison in ("ahead", "identical"):
            return True
        if comparison in ("behind", "diverged"):
            return False
        return None


class ReportDingTalkTransport:
    """Bind one DingTalk attempt to one active record and exact payload bytes."""

    def __init__(
        self,
        expected_outbox_id,
        expected_channel,
        expected_payload_sha256,
        expected_handles,
    ):
        if not isinstance(expected_outbox_id, str) or not re.fullmatch(
            r"rdo1-[0-9a-f]{64}", expected_outbox_id
        ):
            raise ReportDeliveryIntegrityError("DingTalk outbox binding is invalid")
        if expected_channel not in ("primary", "fallback"):
            raise ReportDeliveryIntegrityError("DingTalk channel binding is invalid")
        if not isinstance(expected_payload_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_payload_sha256
        ):
            raise ReportDeliveryIntegrityError("DingTalk payload binding is invalid")
        self.expected_outbox_id = expected_outbox_id
        self.expected_channel = expected_channel
        self.expected_payload_sha256 = expected_payload_sha256
        self.expected_handles = tuple(_canonical_report_handles(expected_handles))

    def send(self, channel, payload, *, idempotency_key):
        if (
            channel != self.expected_channel
            or idempotency_key != self.expected_outbox_id
            or type(payload) is not bytes
            or _report_delivery_sha256(payload) != self.expected_payload_sha256
        ):
            raise DingTalkDeliveryError("DingTalk delivery binding failed")
        try:
            decoded = decode_report_delivery_envelope(
                payload,
                expected_channel=self.expected_channel,
                expected_handles=self.expected_handles,
            )
        except ReportDeliveryIntegrityError as exc:
            raise DingTalkDeliveryError("DingTalk delivery binding failed") from exc
        response = send_dingtalk_payload(decoded["wire_bytes"], max_attempts=1)
        if (
            not isinstance(response, dict)
            or type(response.get("errcode")) is not int
            or response.get("errcode") != 0
        ):
            raise DingTalkDeliveryError("DingTalk delivery failed")
        return {"status": 200, "ack": len(self.expected_handles)}


def _report_delivery_target_path(today):
    try:
        _require_report_day(today, "today")
    except ReportStateError as exc:
        raise ReportDeliveryInputError("report delivery date is invalid") from exc
    return f"{REPORT_DELIVERY_GITHUB_PATH_PREFIX}/sp_report_{today}.png"


def _validate_report_delivery_target(target):
    path_pattern = rf"{re.escape(REPORT_DELIVERY_GITHUB_PATH_PREFIX)}/sp_report_\d{{4}}-\d{{2}}-\d{{2}}\.png"
    if (
        target.repository != REPORT_DELIVERY_GITHUB_REPOSITORY
        or target.ref != REPORT_DELIVERY_GITHUB_REF
        or not re.fullmatch(path_pattern, target.path)
    ):
        raise ReportDeliveryIntegrityError("report delivery target is outside policy")
    day = target.path[-14:-4]
    try:
        _require_report_day(day, "target day")
    except ReportStateError as exc:
        raise ReportDeliveryIntegrityError("report delivery target is invalid") from exc
    return target


def _report_delivery_raw_url(repository, ref, path):
    if (
        repository != REPORT_DELIVERY_GITHUB_REPOSITORY
        or ref != REPORT_DELIVERY_GITHUB_REF
        or path != _report_delivery_target_path(path[-14:-4])
    ):
        raise ReportDeliveryInputError("report delivery raw URL target is invalid")
    return REPORT_DELIVERY_RAW_BASE_URL + "/" + urllib.parse.quote(path, safe="/")


def build_report_delivery_record_v1(
    *,
    outbox_module,
    state,
    results,
    change_groups,
    today,
    text_message,
    text_delivered_handles,
    dashboard_receipt,
    image_factory=create_dingtalk_report_image,
    frozen_last_run=None,
    state_path=REPORT_STATE_FILE,
):
    """Render and freeze one deterministic R1 record after the active check."""
    validate_report_state(state)
    changed_handles = _canonical_report_handles([
        item["row"]["handle"]
        for items in change_groups.values()
        for item in items
    ])
    frozen_last_run = frozen_last_run or datetime.now(SHANGHAI_TIMEZONE).isoformat()
    try:
        _require_report_timestamp(frozen_last_run, "frozen_last_run")
    except ReportStateError as exc:
        raise ReportDeliveryInputError("report delivery timestamp is invalid") from exc
    prior_exists, disk_state = _strict_report_state_snapshot(state_path)
    if prior_exists and disk_state != state:
        raise ReportDeliveryInputError("report state changed before intent creation")
    target_path = _report_delivery_target_path(today)
    image = image_factory(
        change_groups,
        today,
        len(results),
        len(changed_handles),
        publish=False,
    )
    if not isinstance(image, dict) or not isinstance(image.get("items"), list):
        raise ReportDeliveryInputError("report image result is invalid")
    image_path = image.get("path")
    image_bytes = _read_report_delivery_regular(image_path, max_bytes=16 * 1024 * 1024)
    if not image_bytes:
        raise ReportDeliveryInputError("report image is empty")
    primary_handles = _canonical_report_handles([
        item.get("row", {}).get("handle")
        for item in image["items"]
        if isinstance(item, dict) and isinstance(item.get("row"), dict)
    ])
    fallback_handles = _canonical_report_handles(text_delivered_handles)
    if not set(primary_handles).issubset(changed_handles) or not set(fallback_handles).issubset(changed_handles):
        raise ReportDeliveryInputError("report payload handles are outside changed handles")
    remote_url = _report_delivery_raw_url(
        REPORT_DELIVERY_GITHUB_REPOSITORY,
        REPORT_DELIVERY_GITHUB_REF,
        target_path,
    )
    markdown = build_dingtalk_image_markdown(
        today,
        len(results),
        len(changed_handles),
        remote_url,
        image["items"],
        dashboard_receipt,
    )
    primary_wire = {
        "msgtype": "markdown",
        "markdown": {
            "title": f"SP集团爆品变化日报 {today}",
            "text": markdown,
        },
    }
    fallback_wire = {"msgtype": "text", "text": {"content": text_message}}
    primary_next = build_next_report_state(
        state,
        results,
        primary_handles,
        today,
        changed_handles=changed_handles,
        frozen_at=frozen_last_run,
    )
    fallback_next = build_next_report_state(
        state,
        results,
        fallback_handles,
        today,
        changed_handles=changed_handles,
        frozen_at=frozen_last_run,
    )
    primary_plan = build_report_delivery_plan(
        channel="primary",
        prior_exists=prior_exists,
        prior_state=state,
        next_state=primary_next,
        changed_handles=changed_handles,
        delivered_handles=primary_handles,
        frozen_last_run=frozen_last_run,
    )
    fallback_plan = build_report_delivery_plan(
        channel="fallback",
        prior_exists=prior_exists,
        prior_state=state,
        next_state=fallback_next,
        changed_handles=changed_handles,
        delivered_handles=fallback_handles,
        frozen_last_run=frozen_last_run,
    )
    primary_payload = build_report_delivery_envelope("primary", primary_wire, primary_plan)
    fallback_payload = build_report_delivery_envelope("fallback", fallback_wire, fallback_plan)
    record = outbox_module.create_record(
        repository=REPORT_DELIVERY_GITHUB_REPOSITORY,
        ref=REPORT_DELIVERY_GITHUB_REF,
        path=target_path,
        image_bytes=image_bytes,
        primary_payload_bytes=primary_payload,
        changed_handles=changed_handles,
        primary_handles=primary_handles,
        fallback_payload_bytes=fallback_payload,
        fallback_handles=fallback_handles,
    )
    if record.outbox_id.encode("ascii") in primary_payload or record.outbox_id.encode("ascii") in fallback_payload:
        raise ReportDeliveryInputError("report delivery envelope is self-referential")
    return record


def _validate_active_report_delivery(record):
    _validate_report_delivery_target(record.intent.target)
    primary = decode_report_delivery_envelope(
        record.intent.primary.payload,
        expected_channel="primary",
        expected_handles=record.intent.primary.handles,
    )
    expected_url = _report_delivery_raw_url(
        record.intent.target.repository,
        record.intent.target.ref,
        record.intent.target.path,
    )
    if expected_url not in primary["wire"]["markdown"]["text"]:
        raise ReportDeliveryIntegrityError("primary wire is not bound to frozen target")
    fallback = None
    if record.intent.fallback is not None:
        fallback = decode_report_delivery_envelope(
            record.intent.fallback.payload,
            expected_channel="fallback",
            expected_handles=record.intent.fallback.handles,
        )
    for decoded in (primary, fallback):
        if decoded is not None and tuple(decoded["plan"]["changed_handles"]) != record.intent.changed_handles:
            raise ReportDeliveryIntegrityError("frozen plan does not match active intent")
    return primary, fallback


def _report_delivery_error_class(error, adapters):
    mappings = (
        (getattr(adapters, "StoreBusy", ()), "store_busy"),
        (getattr(adapters, "PendingTransaction", ()), "pending_transaction"),
        (getattr(adapters, "StoreIntegrityError", ()), "store_integrity"),
        (getattr(adapters, "CommitUncertain", ()), "commit_uncertain"),
        (getattr(adapters, "DedupeIntegrityError", ()), "dedupe_integrity"),
        (getattr(adapters, "TransportFailure", ()), "transport_failure"),
        (AtomicWriteCommitUncertain, "commit_uncertain"),
        (ReportDeliveryIntegrityError, "delivery_integrity"),
        (ReportDeliveryInputError, "delivery_input"),
    )
    for cls, label in mappings:
        if cls and isinstance(error, cls):
            return label
    return "delivery_failure"


def _report_delivery_result(snapshot, adapters, *, error_class=None, created=False, had_active=True):
    projection = adapters.project(snapshot, error_class=error_class)
    if projection["state"] == "complete":
        primary = projection["channel"] == "primary"
        return {
            "exit_code": 0 if primary else 3,
            "report": {"state": "succeeded" if primary else "degraded", "projection": projection},
            "created": created,
            "had_active": had_active,
        }
    return {
        "exit_code": 3,
        "report": {"state": "blocked", "projection": projection},
        "created": created,
        "had_active": had_active,
    }


def run_report_delivery_v1(
    *,
    today,
    state=None,
    results=None,
    change_groups=None,
    text_message=None,
    text_delivered_handles=None,
    dashboard_receipt=None,
    recover_only=False,
    store_root=None,
    state_path=None,
    outbox_module=None,
    adapters_module=None,
    github_transport=None,
    dingtalk_transport_factory=ReportDingTalkTransport,
    image_factory=create_dingtalk_report_image,
    frozen_last_run=None,
):
    """Drive at most one durable intent, stopping immediately on uncertainty."""
    if outbox_module is None or adapters_module is None:
        try:
            loaded_outbox, loaded_adapters = _load_report_delivery_modules()
        except ReportDeliveryInputError:
            return {
                "exit_code": 2,
                "report": {"state": "blocked_input"},
                "created": False,
                "had_active": False,
            }
        outbox_module = outbox_module or loaded_outbox
        adapters_module = adapters_module or loaded_adapters
    root = Path(REPORT_DELIVERY_STORE_ROOT if store_root is None else store_root)
    state_path = Path(REPORT_STATE_FILE if state_path is None else state_path)
    created = False
    had_active = False
    snapshot = None
    try:
        adapters_module.initialize_store(root)
        with adapters_module.open_transaction(root) as transaction:
            snapshot = transaction.load_active()
            had_active = snapshot is not None
            if snapshot is None:
                if recover_only:
                    return {
                        "exit_code": None,
                        "report": {"state": "no_active"},
                        "created": False,
                        "had_active": False,
                    }
                if any(value is None for value in (
                    state, results, change_groups, text_message, text_delivered_handles
                )):
                    raise ReportDeliveryInputError("new report delivery intent is incomplete")
                try:
                    record = build_report_delivery_record_v1(
                        outbox_module=outbox_module,
                        state=state,
                        results=results,
                        change_groups=change_groups,
                        today=today,
                        text_message=text_message,
                        text_delivered_handles=text_delivered_handles,
                        dashboard_receipt=dashboard_receipt,
                        image_factory=image_factory,
                        frozen_last_run=frozen_last_run,
                        state_path=state_path,
                    )
                except (KeyboardInterrupt, MemoryError, SystemExit):
                    raise
                except ReportDeliveryInputError:
                    raise
                except Exception as exc:
                    raise ReportDeliveryInputError("report delivery intent build failed") from exc
                snapshot = transaction.ensure(record)
                created = True
                if not hasattr(snapshot, "record"):
                    return _report_delivery_result(
                        snapshot, adapters_module, created=created, had_active=False
                    )
            policy = adapters_module.GithubPolicy(
                REPORT_DELIVERY_GITHUB_REPOSITORY,
                REPORT_DELIVERY_GITHUB_REF,
                REPORT_DELIVERY_GITHUB_PATH_PREFIX,
            )
            for _step in range(12):
                snapshot = transaction.load_active()
                if snapshot is None:
                    raise ReportDeliveryIntegrityError("active report delivery disappeared")
                record = snapshot.record
                primary, fallback = _validate_active_report_delivery(record)
                action = outbox_module.resume_action(record)
                before_sha = outbox_module.record_sha256(record)
                if action in (
                    outbox_module.ResumeAction.PREPARE_PUBLICATION,
                    outbox_module.ResumeAction.START_PUBLICATION,
                    outbox_module.ResumeAction.RECONCILE_PUBLICATION,
                ):
                    if github_transport is None:
                        github_transport = ReportGithubTransport()
                    adapters_module.publish_github(
                        transaction,
                        github_transport,
                        ancestry=github_transport.ancestry,
                        policy=policy,
                    )
                elif action in (
                    outbox_module.ResumeAction.START_PRIMARY_DELIVERY,
                    outbox_module.ResumeAction.START_FALLBACK_DELIVERY,
                ):
                    selected_channel = (
                        "primary"
                        if action is outbox_module.ResumeAction.START_PRIMARY_DELIVERY
                        else "fallback"
                    )
                    payload = (
                        record.intent.primary
                        if selected_channel == "primary"
                        else record.intent.fallback
                    )
                    if payload is None:
                        raise ReportDeliveryIntegrityError("active fallback payload is missing")
                    transport = dingtalk_transport_factory(
                        record.outbox_id,
                        selected_channel,
                        _report_delivery_sha256(payload.payload),
                        payload.handles,
                    )
                    adapters_module.deliver(transaction, transport)
                elif action is outbox_module.ResumeAction.RECONCILE_DELIVERY:
                    return _report_delivery_result(
                        snapshot,
                        adapters_module,
                        error_class="delivery_unknown",
                        created=created,
                        had_active=had_active,
                    )
                elif action is outbox_module.ResumeAction.APPLY_DEDUPE:
                    selected = primary if record.delivery.channel.value == "primary" else fallback
                    if selected is None:
                        raise ReportDeliveryIntegrityError("active dedupe plan is missing")
                    adapter = ReportStateDedupeAdapter(
                        record.intent.primary.payload
                        if record.delivery.channel.value == "primary"
                        else record.intent.fallback.payload,
                        state_path=state_path,
                        adapters_module=adapters_module,
                    )
                    adapters_module.apply_dedupe(transaction, adapter)
                elif action in (
                    outbox_module.ResumeAction.COMPLETE,
                    outbox_module.ResumeAction.TERMINAL_CONFLICT,
                ):
                    receipt = transaction.finalize()
                    return _report_delivery_result(
                        receipt,
                        adapters_module,
                        created=created,
                        had_active=had_active,
                    )
                else:
                    raise ReportDeliveryIntegrityError("active resume action is invalid")
                after = transaction.load_active()
                if after is None:
                    raise ReportDeliveryIntegrityError("active report delivery disappeared")
                if after.record_sha256 == before_sha:
                    return _report_delivery_result(
                        after,
                        adapters_module,
                        error_class="no_progress",
                        created=created,
                        had_active=had_active,
                    )
            return _report_delivery_result(
                transaction.load_active(),
                adapters_module,
                error_class="step_limit",
                created=created,
                had_active=had_active,
            )
    except ReportDeliveryInputError as error:
        if snapshot is None and not had_active:
            return {
                "exit_code": 2,
                "report": {"state": "blocked_input"},
                "created": created,
                "had_active": had_active,
            }
        error_class = _report_delivery_error_class(error, adapters_module)
    except (KeyboardInterrupt, MemoryError, SystemExit):
        raise
    except Exception as error:
        error_class = _report_delivery_error_class(error, adapters_module)
    try:
        if snapshot is not None:
            return _report_delivery_result(
                snapshot,
                adapters_module,
                error_class=error_class,
                created=created,
                had_active=had_active,
            )
    except Exception:
        pass
    return {
        "exit_code": 3,
        "report": {"state": "blocked", "projection": None},
        "created": created,
        "had_active": had_active,
    }


DASHBOARD_EXACT_SOURCE_BOOTSTRAP = r"""
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import sys
from datetime import datetime


def inode_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid)


def snapshot_identity(info):
    return inode_identity(info) + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def require_owned_regular(info, label):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        raise SystemExit(f"{label} must be an owned, single-link regular file")


def read_regular_snapshot(path, label):
    requested = pathlib.Path(path)
    parent = requested.parent.resolve(strict=True)
    directory_fd = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    descriptor = None
    try:
        before = os.stat(requested.name, dir_fd=directory_fd, follow_symlinks=False)
        require_owned_regular(before, label)
        descriptor = os.open(
            requested.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        opened = os.fstat(descriptor)
        require_owned_regular(opened, label)
        current = os.stat(requested.name, dir_fd=directory_fd, follow_symlinks=False)
        if snapshot_identity(before) != snapshot_identity(opened) or snapshot_identity(current) != snapshot_identity(opened):
            raise SystemExit(f"{label} changed identity while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read()
        final = os.fstat(descriptor)
        after = os.stat(requested.name, dir_fd=directory_fd, follow_symlinks=False)
        if snapshot_identity(final) != snapshot_identity(opened) or snapshot_identity(after) != snapshot_identity(opened):
            raise SystemExit(f"{label} changed while reading")
        return raw, parent / requested.name
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def open_dashboard_lock(project):
    canonical = pathlib.Path(project).resolve(strict=True)
    directory_fd = os.open(
        canonical,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    descriptor = None
    try:
        directory_info = os.fstat(directory_fd)
        current_directory = canonical.lstat()
        if not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != os.getuid() or inode_identity(directory_info) != inode_identity(current_directory):
            raise SystemExit("dashboard project directory is missing or unsafe")
        try:
            existing = os.stat(".dashboard_build.lock", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            require_owned_regular(existing, "dashboard build lock")
        descriptor = os.open(
            ".dashboard_build.lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        opened = os.fstat(descriptor)
        require_owned_regular(opened, "dashboard build lock")
        if existing is not None and inode_identity(existing) != inode_identity(opened):
            raise SystemExit("dashboard build lock changed identity while opening")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = os.stat(".dashboard_build.lock", dir_fd=directory_fd, follow_symlinks=False)
        if inode_identity(current) != inode_identity(opened):
            raise SystemExit("dashboard build lock changed identity while locking")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(directory_fd)


builder_path, publisher_path, source_value, expected_date = sys.argv[1:5]
requested_source = pathlib.Path(source_value)
if requested_source.name != f"sp_hotlist_{expected_date}.json":
    raise SystemExit("dashboard source filename/date mismatch")
source_bytes, source_path = read_regular_snapshot(requested_source, "dashboard source")
payload = json.loads(source_bytes)
if not isinstance(payload, dict) or payload.get("source_date") != expected_date or payload.get("healthy") is not True:
    raise SystemExit("dashboard source metadata/date mismatch or unhealthy source")
source_hash = hashlib.sha256(source_bytes).hexdigest()

builder_file = pathlib.Path(builder_path)
dashboard_project = builder_file.resolve().parents[1]
expected_builder = dashboard_project / "scripts/build_top150_dashboard.py"
if builder_file.is_symlink() or builder_file.resolve() != expected_builder or not builder_file.is_file():
    raise SystemExit("dashboard builder path is missing or unsafe")

lock_descriptor = open_dashboard_lock(dashboard_project)
try:
    # This is the stable release transaction lock shared with legitimate
    # builder/template deployers.  It remains exclusive through builder
    # execution, local verification, publisher consumption, remote
    # verification and the final receipt.
    manifest_path = dashboard_project / "dashboard_build_deployment.manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise SystemExit("dashboard deployment manifest is missing or unsafe")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"dashboard deployment manifest is unreadable: {exc}")

    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "producer", "deployed_at", "files"}:
        raise SystemExit("dashboard deployment manifest schema is invalid")
    if manifest.get("schema_version") != 1 or manifest.get("producer") != "deploy_top150_dashboard":
        raise SystemExit("dashboard deployment manifest identity is invalid")
    deployed_at = manifest.get("deployed_at")
    if not isinstance(deployed_at, str) or not deployed_at:
        raise SystemExit("dashboard deployment timestamp is invalid")
    try:
        datetime.fromisoformat(deployed_at.replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit("dashboard deployment timestamp is invalid")

    required_paths = {
        "scripts/build_top150_dashboard.py",
        "scripts/hotlist_contract.py",
        "templates/dashboard_template.html",
    }
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != len(required_paths):
        raise SystemExit("dashboard deployment file list is invalid")
    seen = set()
    for row in files:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise SystemExit("dashboard deployment file entry is invalid")
        relative_value = row.get("path")
        if relative_value not in required_paths or relative_value in seen:
            raise SystemExit("dashboard deployment paths are not the exact allowlist")
        relative = pathlib.Path(relative_value)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != relative_value:
            raise SystemExit("dashboard deployment path is unsafe")
        expected_bytes = row.get("bytes")
        expected_sha = row.get("sha256")
        if (
            not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes < 0
            or not isinstance(expected_sha, str)
            or len(expected_sha) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha)
        ):
            raise SystemExit("dashboard deployment size/hash metadata is invalid")
        artifact = dashboard_project / relative
        if artifact.is_symlink() or not artifact.is_file():
            raise SystemExit(f"dashboard deployment artifact is missing or unsafe: {relative_value}")
        artifact_bytes = artifact.read_bytes()
        if len(artifact_bytes) != expected_bytes or hashlib.sha256(artifact_bytes).hexdigest() != expected_sha:
            raise SystemExit(f"dashboard deployment artifact hash mismatch: {relative_value}")
        seen.add(relative_value)
    if seen != required_paths:
        raise SystemExit("dashboard deployment paths are not the exact allowlist")

    builder_spec = importlib.util.spec_from_file_location("sp_exact_dashboard_builder", expected_builder)
    builder = importlib.util.module_from_spec(builder_spec)
    builder_spec.loader.exec_module(builder)
    builder._main_lock_held(
        ["--expected-date", expected_date, "--source", str(source_path)],
        capability=builder._BUILD_LOCK_CAPABILITY,
    )

    # The builder's manifest is its local transaction commit marker.  Verify
    # the exact source hash and both generated pages before the publisher is
    # allowed to expose them.
    bundle_manifest_path = dashboard_project / "sp_top150_dashboard.manifest.json"
    if bundle_manifest_path.is_symlink() or not bundle_manifest_path.is_file():
        raise SystemExit("dashboard builder manifest is missing or unsafe")
    try:
        bundle_manifest_bytes = bundle_manifest_path.read_bytes()
        bundle_manifest = json.loads(bundle_manifest_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"dashboard builder manifest is unreadable: {exc}")
    if not isinstance(bundle_manifest, dict):
        raise SystemExit("dashboard builder manifest is invalid")
    if (
        bundle_manifest.get("producer") != "build_top150_dashboard"
        or bundle_manifest.get("expected_date") != expected_date
        or bundle_manifest.get("source_date") != expected_date
        or bundle_manifest.get("source_hash") != source_hash
    ):
        raise SystemExit("dashboard builder manifest does not bind the exact source")
    source = bundle_manifest.get("source")
    if not isinstance(source, dict) or source.get("sha256") != source_hash:
        raise SystemExit("dashboard builder source hash metadata mismatch")
    html_hash = bundle_manifest.get("html_sha256")
    outputs = bundle_manifest.get("outputs")
    if not isinstance(html_hash, str) or len(html_hash) != 64 or not isinstance(outputs, list):
        raise SystemExit("dashboard builder output manifest is invalid")
    expected_outputs = {"sp_picker_dashboard.html", "sp_top150_dashboard.html"}
    output_metadata = {row.get("name"): row for row in outputs if isinstance(row, dict)}
    if set(output_metadata) != expected_outputs:
        raise SystemExit("dashboard builder outputs are incomplete")
    verified_artifacts = {}
    for name in expected_outputs:
        row = output_metadata[name]
        artifact = dashboard_project / name
        if artifact.is_symlink() or not artifact.is_file():
            raise SystemExit(f"dashboard builder artifact is missing or unsafe: {name}")
        artifact_bytes = artifact.read_bytes()
        if (
            row.get("sha256") != html_hash
            or row.get("bytes") != len(artifact_bytes)
            or hashlib.sha256(artifact_bytes).hexdigest() != html_hash
        ):
            raise SystemExit(f"dashboard builder artifact hash mismatch: {name}")
        verified_artifacts[name] = artifact_bytes

    publisher_spec = importlib.util.spec_from_file_location("sp_dashboard_publisher", publisher_path)
    publisher = importlib.util.module_from_spec(publisher_spec)
    publisher_spec.loader.exec_module(publisher)
    if not publisher.publish_dashboard(
        _inherited_lock_descriptor=lock_descriptor,
        _lock_capability=publisher._DASHBOARD_LOCK_CAPABILITY,
    ):
        raise SystemExit("dashboard publish failed")

    # The publisher's True result means its existing atomic remote contract
    # verified the exact release.  Re-read every local input and commit marker
    # while still holding the same lock so the receipt cannot describe a
    # different legal bundle swapped between build and publish.
    final_source_bytes, final_source_path = read_regular_snapshot(source_path, "dashboard source")
    if final_source_path != source_path or final_source_bytes != source_bytes:
        raise SystemExit("dashboard source changed during publish transaction")
    if bundle_manifest_path.read_bytes() != bundle_manifest_bytes:
        raise SystemExit("dashboard builder manifest changed during publish transaction")
    for name, expected_bytes in verified_artifacts.items():
        if (dashboard_project / name).read_bytes() != expected_bytes:
            raise SystemExit(f"dashboard builder artifact changed during publish transaction: {name}")

    print("[dashboard-release]" + json.dumps({
        "source_date": expected_date,
        "source_hash": source_hash,
        "html_hash": html_hash,
        "manifest_hash": hashlib.sha256(bundle_manifest_bytes).hexdigest(),
        "generated_at": bundle_manifest.get("generated_at"),
    }, sort_keys=True))
finally:
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
    finally:
        os.close(lock_descriptor)
"""


def refresh_product_dashboard(source_path, expected_date, runner=subprocess.run):
    requested_source = Path(source_path)
    if requested_source.name != f"sp_hotlist_{expected_date}.json":
        print(f"[看板] 拒绝非本次扫描源: {requested_source} ({expected_date})", flush=True)
        return False
    try:
        source_info = requested_source.lstat()
        source_parent = requested_source.parent.resolve(strict=True)
    except OSError:
        print(f"[看板] 拒绝缺失或不安全扫描源: {requested_source}", flush=True)
        return False
    if requested_source.is_symlink() or not requested_source.is_file() or source_info.st_nlink != 1:
        print(f"[看板] 拒绝非普通扫描源: {requested_source}", flush=True)
        return False
    source_path = source_parent / requested_source.name
    dashboard_project = Path(
        os.environ.get("SP_DASHBOARD_PROJECT_DIR", str(WORKSPACE / "spspy_dashboard"))
    )
    builder = dashboard_project / "scripts/build_top150_dashboard.py"
    publisher = WORKSPACE / "skills/sp-hot-picker/scripts/scan.py"
    if not builder.exists() or not publisher.exists():
        print(f"[看板] 构建/发布脚本不存在: {builder} / {publisher}", flush=True)
        return False
    if source_path.name != f"sp_hotlist_{expected_date}.json" or not source_path.exists():
        print(f"[看板] 拒绝非本次扫描源: {source_path} ({expected_date})", flush=True)
        return False
    env = os.environ.copy()
    env["SP_DASHBOARD_PROJECT_DIR"] = str(dashboard_project)
    env.setdefault("SP_DASHBOARD_PUBLISH_DIR", "/private/tmp/babata-board-pages-main")
    env.setdefault("SP_DASHBOARD_PUBLISH_MODE", "api")
    env["SP_DASHBOARD_SOURCE_PATH"] = str(source_path)
    env["SP_DASHBOARD_EXPECTED_DATE"] = expected_date
    try:
        result = runner(
            [
                "/opt/homebrew/bin/python3",
                "-c",
                DASHBOARD_EXACT_SOURCE_BOOTSTRAP,
                str(builder),
                str(publisher),
                str(source_path),
                expected_date,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.stdout.strip():
            print(result.stdout.strip(), flush=True)
        if result.returncode != 0:
            detail = (result.stderr or "").strip()[-800:]
            print(f"[看板] 刷新失败，退出码 {result.returncode}: {detail}", flush=True)
            return False
        receipt = None
        for line in reversed((result.stdout or "").splitlines()):
            if line.startswith("[dashboard-release]"):
                try:
                    candidate = json.loads(line.removeprefix("[dashboard-release]"))
                except json.JSONDecodeError:
                    break
                if isinstance(candidate, dict):
                    receipt = candidate
                break
        expected_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if not isinstance(receipt, dict) or (
            receipt.get("source_date") != expected_date
            or receipt.get("source_hash") != expected_hash
            or not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("html_hash") or ""))
            or not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("manifest_hash") or ""))
        ):
            print("[看板] 刷新未返回本次源数据的核验回执", flush=True)
            return False
        print(
            f"[看板] 已核验并发布：数据日 {expected_date}，源哈希 {expected_hash[:12]}",
            flush=True,
        )
        return receipt
    except Exception as e:
        print(f"[看板] 刷新异常: {e}", flush=True)
        return False


def load_top_sites(n=100):
    with open(WORKSPACE / "sp_similarweb_full.csv") as f:
        rows = list(csv.DictReader(f))
    with open(WORKSPACE / "sp_domains.txt") as f:
        sp_set = {l.strip() for l in f if l.strip()}
    sites = []
    for r in rows:
        domain = r["domain"].replace("www.", "")
        if domain not in sp_set: continue
        try: visits = int(r.get("monthly_visits", "0") or 0)
        except: visits = 0
        sites.append({"domain": domain, "visits": visits, "country": r.get("top_country", "?")})
    sites.sort(key=lambda x: -x["visits"])
    return sites[:n]

def flagship_weight_for_rank(rank):
    if rank <= 3:
        return 6
    if rank <= 7:
        return 5
    if rank <= 12:
        return 4
    return 3

def build_flagship_config(sites):
    """
    旗舰站 = 当前 SimilarWeb 月访问量排序 Top N。
    权重随流量排名递减，用于评分和 FB 投放验证优先级。
    """
    ranked = [s for s in sites if s.get("visits", 0) > 0]
    if not ranked:
        return STATIC_FLAGSHIP_FALLBACK
    flagships = []
    for rank, site in enumerate(ranked[:FLAGSHIP_TOP_N], 1):
        domain = site["domain"]
        flagships.append({
            "name": domain.replace(".com", ""),
            "domain": domain,
            "country": site.get("country", "?") or "?",
            "weight": flagship_weight_for_rank(rank),
            "traffic_rank": rank,
            "visits": site.get("visits", 0),
        })
    return flagships

def load_top50():
    return load_top_sites(50)

def fetch_site(site, cutoff):
    domain = site["domain"]
    country = site.get("country", "?") or "?"
    prods = []
    try:
        for page in range(1, PRODUCT_MAX_PAGES + 1):
            url = (
                f"https://{domain}/products.json?limit={PRODUCT_PAGE_SIZE}"
                f"&sort_by=created-descending&page={page}"
            )
            req = urllib.request.Request(url, headers={**HEADERS, "Accept-Encoding": "gzip"})
            with urlopen_with_retry(req, timeout=20, retries=2, backoff=2.0) as r:
                data = read_json_response(r)

            page_products = data.get("products")
            if not isinstance(page_products, list):
                raise ValueError("products.json missing products list")

            page_dates = []
            for p in page_products:
                created_day = (p.get("created_at") or p.get("published_at") or "")[:10]
                if created_day:
                    page_dates.append(created_day)
                pub = (p.get("published_at") or p.get("created_at") or "")[:10]
                if pub < cutoff:
                    continue
                if any(kw in p.get("handle", "").lower() for kw in ["gift-card", "insurance", "shipping-protection"]):
                    continue
                prods.append({
                    "domain": domain, "visits": site["visits"], "country": country,
                    "traffic_rank": site.get("rank"),
                    "monthly_visits": site["visits"],
                    "handle": p.get("handle", ""), "title": p.get("title", ""),
                    "published_at": pub,
                    "price": p.get("variants", [{}])[0].get("price", "0") if p.get("variants") else "0",
                    "image_url": _product_payload_image(p),
                })

            if len(page_products) < PRODUCT_PAGE_SIZE:
                break
            if page_dates and min(page_dates) < cutoff:
                break
            time.sleep(random.uniform(0.4, 0.8))
    except urllib.error.HTTPError as e:
        return [], f"http_{e.code}", {
            "http_status": e.code,
            "retry_after": _optional_retry_after(e.headers),
        }
    except urllib.error.URLError as e:
        return [], f"network:{str(e.reason)[:120]}", {}
    except (TimeoutError, json.JSONDecodeError, ValueError) as e:
        return [], f"data_or_timeout:{str(e)[:120]}", {}
    except Exception as e:
        return [], f"other:{type(e).__name__}:{str(e)[:100]}", {}
    return prods, None, {"parsed_products": True}


def update_main_timeline(timeline, products, today):
    """Append rank snapshots only for genuinely new handle/domain events."""
    for product in products:
        handle = product.get("handle", "")
        if not handle:
            continue
        if handle not in timeline:
            timeline[handle] = {
                "title": product.get("title", ""),
                "price": product.get("price", "0"),
                "first_seen": today,
                "sites": {},
            }
        sites = timeline[handle].setdefault("sites", {})
        domain = product["domain"]
        if domain in sites:
            continue
        sites[domain] = {
            "pub_date": product.get("published_at", ""),
            "first_scan": today,
            "traffic_rank": product.get("traffic_rank"),
            "monthly_visits": product.get("monthly_visits", product.get("visits")),
            "rank_snapshot_date": today,
            "producer": "sp-monitor",
        }
    return timeline


def is_lp_page(domain, handle):
    """
    检测产品页是否为专门优化的 LP 落地页。
    核心特征：隐藏导航（没有 <header> 或 <nav>）且图片超多（≥60张）。
    这类页面说明卖家专门为 FB 广告做了转化优化，几乎必然是爆品。
    """
    try:
        url = f"https://{domain}/products/{handle}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen_with_retry(req, timeout=8) as r:
            html = r.read().decode("utf-8", errors="ignore")
        has_nav = bool(re.search(r'<(header|nav)[^>]*>', html, re.I))
        img_count = len(re.findall(r'<img ', html, re.I))
        return (not has_nav) and img_count >= 60
    except:
        return False

def compute_flagship_days(candidates, today):
    """
    查历史 sp_hotlist_DATE.json，找每个品在旗舰站的真正首发日。
    有旗舰命中的品往前查最多14天，原地写入 flagship_days（int 或 None）。
    """
    today_dt = datetime.strptime(today, "%Y-%m-%d")

    # 先把今天有旗舰命中的品标记为"今天首发"
    key_first = {}  # handle → 最早旗舰日期
    for c in candidates:
        if c.get("flagship_count", 0) > 0:
            key_first[c["handle"]] = today_dt

    # 往前翻最多14天，越早的日期越能定位真正首发日
    for days_back in range(1, 15):
        hist_dt = today_dt - timedelta(days=days_back)
        hist_file = WORKSPACE / f"sp_hotlist_{hist_dt.strftime('%Y-%m-%d')}.json"
        if not hist_file.exists():
            continue
        try:
            hist_data = json.load(open(hist_file)).get("results", [])
        except Exception:
            continue
        for r in hist_data:
            handle = r.get("handle", "")
            if handle and r.get("flagship_count", 0) > 0 and handle in key_first:
                key_first[handle] = hist_dt

    for c in candidates:
        if c["handle"] in key_first:
            c["flagship_days"] = (today_dt - key_first[c["handle"]]).days
        else:
            c["flagship_days"] = None

    return candidates


def _health_metadata_matches(metadata, computed):
    if metadata.get("overall") != computed["overall"] or metadata.get("top20") != computed["top20"]:
        return False
    exact_keys = (
        "planned_total",
        "attempted_total",
        "success_total",
        "flagship_planned",
        "flagship_attempted",
        "flagship_success",
    )
    if any(_as_int(metadata.get(key), -1) != computed[key] for key in exact_keys):
        return False
    ratio_keys = ("overall_success_ratio", "flagship_success_ratio")
    return all(abs(_as_float(metadata.get(key), -1.0) - computed[key]) < 0.00011 for key in ratio_keys)


def _validated_snapshot_payload(path, day, payload):
    """Validate provenance and recompute coverage before trusting historical results."""
    if path.name != f"sp_hotlist_{day}.json":
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return None
    stats = payload.get("site_stats")
    if not isinstance(stats, list) or not stats:
        return None
    domains = [row.get("domain") for row in stats if isinstance(row, dict)]
    if len(domains) != len(stats) or any(not domain for domain in domains) or len(set(domains)) != len(domains):
        return None

    schema_version = payload.get("schema_version")
    if schema_version is not None:
        if (
            schema_version != 2
            or payload.get("producer") != "sp-monitor"
            or payload.get("source_date") != day
            or payload.get("healthy") is not True
        ):
            return None
        metadata = payload.get("scan_health")
        if not isinstance(metadata, dict) or metadata.get("healthy") is not True:
            return None
        planned = _as_int(metadata.get("planned_total"), 0)
        expected_flagships = _as_int(metadata.get("flagship_planned"), 0)
        if planned != REPORT_SCAN_TOP_N or expected_flagships != min(FLAGSHIP_TOP_N, REPORT_SCAN_TOP_N):
            return None
        if sorted(_as_int(row.get("rank"), 0) for row in stats) != list(range(1, planned + 1)):
            return None
        computed = evaluate_scan_health(stats, planned, expected_flagships)
        if not computed["healthy"] or not _health_metadata_matches(metadata, computed):
            return None
        return payload

    # Legacy files have no trustworthy top-level health claim. Recompute solely
    # from their complete site_stats; a results-only legacy file is never valid.
    if payload.get("healthy") is False:
        return None
    old_health = payload.get("scan_health")
    if isinstance(old_health, dict) and old_health.get("healthy") is False:
        return None
    if payload.get("source_date") not in (None, day):
        return None
    if len(stats) != REPORT_SCAN_TOP_N:
        return None
    expected_flagships = min(FLAGSHIP_TOP_N, REPORT_SCAN_TOP_N)
    if sorted(_as_int(row.get("rank"), 0) for row in stats) != list(range(1, REPORT_SCAN_TOP_N + 1)):
        return None
    computed = evaluate_scan_health(stats, REPORT_SCAN_TOP_N, expected_flagships)
    return payload if computed["healthy"] else None


def latest_healthy_snapshot_before(today, workspace=WORKSPACE):
    """Return the newest *strictly earlier* healthy hotlist snapshot, if any."""
    candidates = []
    for path in workspace.glob("sp_hotlist_*.json"):
        day = _date_from_hotlist_path(path)
        if not day or day >= today:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        validated = _validated_snapshot_payload(path, day, payload)
        if validated is not None:
            candidates.append((day, validated))
    return max(candidates, key=lambda item: item[0]) if candidates else (None, None)


def spread_baseline(today, workspace=WORKSPACE):
    """Load a dated baseline and make gaps explicit to callers and report readers."""
    baseline_day, payload = latest_healthy_snapshot_before(today, workspace)
    if not payload:
        return {}, None, None, True
    try:
        elapsed_days = (datetime.strptime(today, "%Y-%m-%d") - datetime.strptime(baseline_day, "%Y-%m-%d")).days
    except ValueError:
        return {}, None, None, True
    counts = {
        row.get("handle"): _as_int(row.get("sites_count"))
        for row in payload.get("results", [])
        if row.get("handle")
    }
    return counts, baseline_day, elapsed_days, elapsed_days != 1


def rescore(candidates, today, flagship_weight=None, workspace=WORKSPACE):
    """
    SP 专属评分公式（利用 published_at 精确日期，这是 SP 相对 AW 的独特优势）：
      旗舰命中 + FB精准命中 + LP落地页 + 上架新鲜度(published_at) + 扩散速度 - 老化惩罚

    设计原则：
    - published_at 是 SP 独有的精确信号，权重应远高于站数、扩散等辅助信号
    - FB 精准命中（旗舰正在投该 handle）是最强爆品信号，权重最高
    - LP 页面说明卖家已专门针对 FB 转化优化，几乎必然是主推品
    - 老化惩罚：站数太多说明品已普及，不再是独家信号
    """
    today_dt = datetime.strptime(today, "%Y-%m-%d")
    flagship_weight = flagship_weight or FLAGSHIP_WEIGHT
    previous_sc, baseline_day, elapsed_days, spread_gap = spread_baseline(today, workspace)

    for c in candidates:
        sc = c["sites_count"]
        pub = c.get("published_at", "")

        # ── 旗舰命中分（按 SimilarWeb 流量排名分层加权）──────────
        flagship_score = sum(flagship_weight.get(d, 3) for d in c.get("flagship_hits", []))

        # ── FB 精准命中分（旗舰正在投放该 handle，最强爆品信号）────────────
        fb_bonus = sum(flagship_weight.get(d, 3) for d in c.get("fb_hits", []))

        # ── LP 落地页分（SP 独有：隐藏导航 + ≥60 图 = 高转化优化页）────────
        lp_bonus = 10 if c.get("is_lp") else 0

        # ── 上架新鲜度衰减（回测最优：k=0.3，命中率 83.72%→86.05%）────────
        # sites_count 乘以衰减因子，越新的品 base 分越高
        # days_old=0: ×1.0, days_old=1: ×0.77, days_old=2: ×0.625
        try:
            days_old = (today_dt - datetime.strptime(pub, "%Y-%m-%d")).days
        except Exception:
            days_old = 99
        c["days_old"] = days_old
        base = round(sc * (1 / (1 + 0.3 * days_old)), 2)
        c["base_score"] = base

        # ── 扩散速度分（基线缺失时未知；断档只计算跨窗平均速度）──────────
        has_handle_baseline = baseline_day is not None and c["handle"] in previous_sc
        total_delta = None
        one_day_delta = None
        velocity = None
        if has_handle_baseline:
            total_delta = max(0, sc - previous_sc[c["handle"]])
            if elapsed_days == 1:
                one_day_delta = total_delta
            if elapsed_days and elapsed_days > 0:
                velocity = total_delta / elapsed_days
        c["spread_baseline_date"] = baseline_day
        c["spread_elapsed_days"] = elapsed_days
        c["spread_gap"] = spread_gap if baseline_day is not None else None
        c["spread_delta_total"] = total_delta
        c["spread_delta_1d"] = one_day_delta
        c["spread_velocity_per_day"] = velocity
        # Compatibility alias: spread_delta now strictly means a one-day delta.
        c["spread_delta"] = one_day_delta
        c["spread_delta_semantics"] = "one_day_only"
        spread_score = one_day_delta if one_day_delta is not None else 0.0

        # ── 老化惩罚（站数 > 30 说明品已普及，不再是稀缺信号）──────────────
        aging_penalty = round(min((sc - 30) * 0.4, 6), 2) if sc > 30 else 0
        c["aging_penalty"] = aging_penalty

        c["score"] = round(
            base + flagship_score + fb_bonus + lp_bonus + spread_score - aging_penalty, 2
        )

    candidates.sort(key=lambda x: -x["score"])
    return candidates


def get_site_fb_handles(domain, country="ALL"):
    """
    搜索 FB Ad Library 中该域名正在投放广告的产品 handle 列表。
    原理：按域名搜索 → 滚动加载 → 提取落地链接里的 handle。
    同时检测是否为 LP 优化页面（无导航+大量图片），LP 页面单独标记。
    返回: (handles列表, lp_handles集合)
    """
    enc = urllib.parse.quote(domain)
    url = (f"https://www.facebook.com/ads/library/"
           f"?active_status=active&ad_type=all&country={country}"
           f"&q={enc}&search_type=keyword_unordered")

    openclaw_bin = resolve_openclaw_bin()
    if not openclaw_bin:
        print("    ⚠️ openclaw CLI 不可用，跳过FB验证", flush=True)
        return [], set()

    nav = subprocess.run(
        [openclaw_bin, "browser", "--browser-profile", CHROME_PROFILE, "navigate", url],
        capture_output=True, timeout=15
    )
    if nav.returncode != 0:
        return [], set()
    time.sleep(random.uniform(4.0, 6.0))

    # 多滚加载更多广告（每次滚动后稍等，让懒加载完成）
    for _ in range(20):
        subprocess.run(
            [openclaw_bin, "browser", "--browser-profile", CHROME_PROFILE, "evaluate",
             "--fn", "() => { window.scrollBy(0, 2000); return true; }"],
            capture_output=True, text=True, timeout=10
        )
        time.sleep(1.2)
    time.sleep(2)

    # 用 innerHTML 全量抓，比 snapshot 覆盖更全
    r = subprocess.run(
        [openclaw_bin, "browser", "--browser-profile", CHROME_PROFILE, "evaluate",
         "--fn", "() => document.body.innerHTML"],
        capture_output=True, text=True, timeout=15
    )
    full = "\n".join(l for l in r.stdout.split("\n") if not l.startswith("\x1b"))

    handles = []
    seen = set()

    def add_handle(h):
        h = h.lower()
        if len(h) >= 8 and h not in seen:
            seen.add(h)
            handles.append(h)

    # 直接匹配明文链接
    for m in re.finditer(rf'{re.escape(domain)}/products/([a-z0-9][a-z0-9\-]{{2,}})', full):
        add_handle(m.group(1))
    # 解码 l.facebook.com 跳转链接（%3A%2F%2F 格式）
    for m in re.finditer(r'u=https?%3A%2F%2F([^&\s%"\']+)', full):
        real = urllib.parse.unquote(m.group(1))
        pm = re.search(rf'{re.escape(domain)}/products/([a-z0-9][a-z0-9\-]{{2,}})', real)
        if pm:
            add_handle(pm.group(1))
    # 解码 %2F 格式
    for m in re.finditer(rf'{re.escape(domain)}%2Fproducts%2F([a-zA-Z0-9][a-zA-Z0-9\-]{{2,}})', full):
        add_handle(m.group(1))

    # 检测哪些 handle 是 LP 优化页面
    lp_handles = set()
    for h in handles:
        if is_lp_page(domain, h):
            lp_handles.add(h)
            print(f"    🎯 LP页面: {domain}/products/{h}", flush=True)

    return handles, lp_handles


def write_run_status(today, status, workspace=WORKSPACE):
    """Persist scan/report/dashboard phases so partial publishes are observable."""
    status["updated_at"] = datetime.now().isoformat()
    path = workspace / f"sp_monitor_status_{today}.json"
    return atomic_write_json(path, status)

def main():
    parser = argparse.ArgumentParser(description="SP集团每日爆品变化播报")
    parser.add_argument("--quick", action="store_true", help="跳过FB广告查询，只做扫描和评分预览")
    parser.add_argument("--send", action="store_true", help="发送钉钉，并在发送成功后更新去重状态")
    parser.add_argument("--send-empty", action="store_true", help="没有商品变化时也发送摘要；默认不发送")
    args = parser.parse_args()
    quick = args.quick

    now_shanghai, today, yesterday, cutoff = shanghai_run_clock()
    scan_time = shanghai_now_iso(now_shanghai)
    run_status = {
        "version": 1,
        "date": today,
        "scan": {"state": "running"},
        "report": {"state": "pending" if args.send else "not_requested"},
        "dashboard": {"state": "pending" if args.send else "not_requested"},
        "final_state": "running",
    }
    mode = "快速预览（跳过FB）" if quick else "完整模式（含FB广告）"
    print(f"=== SP集团每日播报 {today} [{mode}] ===\n", flush=True)

    # Step1: 小并发扫描 TopN，控制对 Shopify 公共接口的压力。
    sites = [
        {**site, "rank": rank}
        for rank, site in enumerate(load_top_sites(REPORT_SCAN_TOP_N), start=1)
    ]
    flagship_sp = build_flagship_config(sites)
    flagship_domains = {f["domain"] for f in flagship_sp}
    flagship_weight = {f["domain"]: f["weight"] for f in flagship_sp}
    planned_total = REPORT_SCAN_TOP_N
    expected_flagships = min(FLAGSHIP_TOP_N, REPORT_SCAN_TOP_N)
    print(
        f"扫描计划 {planned_total} 个站，已加载 {len(sites)} 个"
        f"（{SCAN_MAX_WORKERS}线程并发，近3天新品）...",
        flush=True,
    )
    print(f"旗舰站: SimilarWeb流量Top{len(flagship_sp)}（{', '.join(f['domain'] for f in flagship_sp[:5])}...）", flush=True)
    circuit = RateLimitCircuit(CIRCUIT_CONFIG)
    outcomes, circuit_snapshot = scan_sites_bounded(
        sites,
        lambda site: fetch_site(site, cutoff),
        max_workers=SCAN_MAX_WORKERS,
        circuit=circuit,
    )
    all_products = []
    site_stats_list = []
    for done, outcome in enumerate(outcomes, start=1):
        site = outcome["site"]
        prods = outcome["products"]
        fetch_error = outcome["fetch_error"]
        all_products.extend(prods)
        today_count = sum(1 for product in prods if product["published_at"] >= today)
        site_stats_list.append({
            "rank": site["rank"],
            "traffic_rank": site["rank"],
            "domain": site["domain"],
            "visits": site["visits"],
            "monthly_visits": site["visits"],
            "rank_snapshot_date": today,
            "producer": "sp-monitor",
            "country": site.get("country", "?"),
            "today_new": today_count,
            "recent_new": len(prods),
            "is_flagship": site["rank"] <= expected_flagships,
            "attempted": outcome["attempted"],
            "was_probe": outcome["was_probe"],
            "fetch_error": fetch_error,
            "fetch_metadata": outcome["metadata"],
        })
        if prods:
            print(f"  [{done:>3}/{planned_total}] {site['domain']:28} 今日{today_count}个 / 近3天{len(prods)}个", flush=True)
        elif fetch_error:
            print(f"  [{done:>3}/{planned_total}] {site['domain']:28} 抓取失败: {fetch_error}", flush=True)
    print(f"  → 共 {len(all_products)} 条近3天新品\n", flush=True)

    # 站点维度：与昨日对比
    yesterday_stats = {}
    ystat_file = WORKSPACE / f"sp_site_stats_{yesterday}.json"
    if ystat_file.exists():
        with open(ystat_file) as f:
            yd = json.load(f)
            yesterday_stats = {s["domain"]: s for s in yd.get("sites", [])}

    for stat in site_stats_list:
        previous = yesterday_stats.get(stat["domain"], {})
        stat["yesterday_recent"] = previous.get("recent_new")
        stat["diff"] = stat["recent_new"] - previous.get("recent_new", 0)
    site_stats_list.sort(key=lambda row: row["rank"])

    health = evaluate_scan_health(site_stats_list, planned_total, expected_flagships)
    failed_sites = [site for site in site_stats_list if site.get("fetch_error")]
    print(
        f"扫描健康度: 成功 {health['success_total']}/{planned_total} "
        f"({health['overall_success_ratio']:.1%})，旗舰 "
        f"{health['flagship_success']}/{expected_flagships} "
        f"({health['flagship_success_ratio']:.1%})",
        flush=True,
    )
    if not health["healthy"]:
        failure_path = WORKSPACE / f"sp_scan_failed_{today}.json"
        write_scan_failure_diagnostic(today, {
            "schema_version": 2,
            "producer": "sp-monitor",
            "source_date": today,
            "scan_time": scan_time,
            "healthy": False,
            "scan_health": health,
            "planned_domains_loaded": len(sites),
            "error_distribution": error_distribution(site_stats_list, planned_total),
            "circuit": circuit_snapshot,
            "failed_sites": failed_sites,
        })
        print(
            "⛔ 扫描健康门未通过。仅写独立诊断；热榜、站点统计、时间线、"
            "去重、通知及看板均保持原字节。",
            flush=True,
        )
        print(f"失败诊断已保存: {failure_path}", flush=True)
        return 2

    # 保存站点维度数据
    atomic_write_json(WORKSPACE / f"sp_site_stats_{today}.json", {
        "schema_version": 2,
        "producer": "sp-monitor",
        "source_date": today,
        "healthy": True,
        "scan_time": scan_time,
        "scan_health": health,
        "sites": site_stats_list,
    })

    # 保存原始产品-站点时间线（用于追溯首发站）
    # 格式：{handle: [{domain, pub_date, price, title, scan_date}]}
    timeline_file = WORKSPACE / "sp_product_timeline.json"
    timeline = {}
    if timeline_file.exists():
        timeline = json.load(open(timeline_file))
    update_main_timeline(timeline, all_products, today)
    atomic_write_json(timeline_file, timeline)

    # Step2: 分组筛选
    grouped = defaultdict(lambda: {"sites":[], "title":"", "price":"0", "image_url":"",
                                    "published_at":"", "flagship_hits":[], "countries":[]})
    for p in all_products:
        key = p["handle"]
        if not key: continue
        g = grouped[key]
        if p["domain"] not in g["sites"]:
            g["sites"].append(p["domain"])
            if not g["title"]:
                g["title"] = p["title"]
                g["price"] = p["price"]
                g["published_at"] = p["published_at"]
            if p.get("image_url") and not g["image_url"]:
                g["image_url"] = p["image_url"]
            c = p.get("country", "?")
            if c and c != "?" and c not in g["countries"]:
                g["countries"].append(c)
            if p["domain"] in flagship_domains and p["domain"] not in g["flagship_hits"]:
                g["flagship_hits"].append(p["domain"])

    candidates = []
    for key, g in grouped.items():
        n = len(g["sites"])
        if n < 3: continue
        pub = g["published_at"]
        freshness = 2 if pub >= today else (1 if pub >= yesterday else 0)
        best = sorted(g["sites"],
                      key=lambda d: next((s["visits"] for s in sites if s["domain"]==d), 0),
                      reverse=True)[0]
        candidates.append({
            "title": g["title"], "price": g["price"], "published_at": pub,
            "handle": key, "sites_count": n,
            "image_url": g["image_url"],
            "flagship_hits": g["flagship_hits"], "flagship_count": len(g["flagship_hits"]),
            "sample_url": f"https://{best}/products/{key}",
            "sites": g["sites"], "freshness": freshness,
            "countries": g["countries"],
        })
    candidates.sort(key=lambda x: (x["flagship_count"], x["sites_count"], x["freshness"]), reverse=True)
    print(f"候选品: {len(candidates)} 个（≥3站同步）\n", flush=True)

    # Step3: 按旗舰站域名查 FB 广告，提取正在投放的产品 handle，并检测 LP 页面
    flagship_fb_handles = {}  # {handle: [domain, ...]}
    flagship_lp_handles = set()  # 确认为 LP 优化页面的 handle
    if quick:
        print("⚡ 快速模式：跳过FB广告查询\n", flush=True)
    else:
        print("查旗舰站 FB 广告投放产品...", flush=True)
        for f in flagship_sp:
            handles, lp_handles = get_site_fb_handles(f["domain"], f["country"])
            for h in handles:
                flagship_fb_handles.setdefault(h, []).append(f["domain"])
            flagship_lp_handles.update(lp_handles)
            flag = "🔥" if handles else "○"
            lp_str = f" | 🎯LP: {len(lp_handles)}个" if lp_handles else ""
            print(f"  {flag} {f['domain']:28} 投放: {len(handles)}个{lp_str}", flush=True)
            time.sleep(random.uniform(5.0, 10.0))

    # Step4: 评分（升级版：旗舰首发日 + 扩散速度 + 老化惩罚）
    results = []
    for c in candidates:
        fb_hits = flagship_fb_handles.get(c["handle"], [])
        is_lp = c["handle"] in flagship_lp_handles
        results.append({**c, "fb_hits": fb_hits, "is_lp": is_lp, "score": 0})

    # 综合评分（旗舰 + FB + LP + published_at新鲜度 + 扩散速度 - 老化惩罚）
    results = rescore(results, today, flagship_weight)
    print(f"Top1: {results[0]['title'][:40] if results else '无'} ({results[0]['score'] if results else 0}分)", flush=True)

    # Step5: 保存
    out = WORKSPACE / f"sp_hotlist_{today}.json"
    hotlist_payload = {
        "schema_version": 2,
        "producer": "sp-monitor",
        "source_date": today,
        "healthy": True,
        "scan_time": scan_time,
        "results": results,
        "flagship_fb_handles": flagship_fb_handles,
        "flagship_sites": flagship_sp,
        "flagship_rule": f"SimilarWeb monthly visits Top{len(flagship_sp)}",
        "scan_health": {**health, "circuit": circuit_snapshot},
        "site_stats": site_stats_list,
    }
    atomic_write_json(out, hotlist_payload)
    run_status["scan"] = {
        "state": "succeeded",
        **health,
        "circuit": circuit_snapshot,
        "source_path": str(out),
    }
    write_run_status(today, run_status)

    # Step6: Build, publish and independently verify the exact dashboard
    # bundle before any notification can mention its public URL.  A report
    # state error or a notification failure must not strand this healthy scan
    # on the previous public dashboard.
    dashboard_receipt = None
    if args.send:
        # Active-first: an older frozen intent must be recovered before this
        # run can publish or render any current-day report artifact.
        recovery = run_report_delivery_v1(today=today, recover_only=True)
        if recovery["report"].get("state") != "no_active":
            run_status["report"] = recovery["report"]
            run_status["dashboard"] = {"state": "not_attempted_active_recovery"}
            exit_code = recovery["exit_code"]
            run_status["final_state"] = "succeeded" if exit_code == 0 else "partial_failure"
            write_run_status(today, run_status)
            if exit_code == 0:
                print("\n✅ 已完成先前冻结的报告交付。", flush=True)
            else:
                print("\n⚠️ 先前冻结的报告交付仍需恢复；本次未创建新意图。", flush=True)
            return exit_code

        # `--send-empty` must have a zero-external-call rejection when there
        # is no active intent and no change.  Its dashboard refresh is delayed
        # until Step7 proves that a normal, non-empty report will be built.
        if not args.send_empty:
            write_run_status(today, run_status)
            dashboard_receipt = refresh_product_dashboard(out, today)
            dashboard_ok = isinstance(dashboard_receipt, dict)
            run_status["dashboard"] = {
                "state": "succeeded" if dashboard_ok else "failed",
            }
            if dashboard_ok:
                run_status["dashboard"].update({
                    "source_date": dashboard_receipt["source_date"],
                    "source_hash": dashboard_receipt["source_hash"],
                    "html_hash": dashboard_receipt["html_hash"],
                    "manifest_hash": dashboard_receipt["manifest_hash"],
                })
            else:
                print("⛔ 看板刷新/发布失败：通知将明确不附旧看板链接。", flush=True)
            write_run_status(today, run_status)

    # Step7: 只提取相对上次报告真正有变化的商品
    try:
        state = load_report_state(today)
    except ReportStateError as exc:
        run_status["report"] = {
            "state": "blocked_invalid_dedupe_state",
        }
        run_status["final_state"] = "failed"
        write_run_status(today, run_status)
        print(
            f"⛔ 报告去重状态不可用，已在通知前停止且未覆盖状态文件: {exc}",
            flush=True,
        )
        return 2
    change_groups = classify_report_changes(results, state, today)
    changed_count = sum(len(v) for v in change_groups.values())
    changed_handles = {
        item["row"]["handle"]
        for items in change_groups.values()
        for item in items
    }
    print(f"\n报告变化项: {changed_count} 个", flush=True)

    if args.send and args.send_empty and changed_count == 0:
        run_status["report"] = {"state": "unsupported_empty_notification"}
        run_status["dashboard"] = {"state": "not_attempted_unsupported_empty"}
        run_status["final_state"] = "failed"
        write_run_status(today, run_status)
        print("⛔ --send-empty 不受持久化报告交付协议支持；未创建或发送报告。", flush=True)
        return 2

    if args.send and args.send_empty:
        dashboard_receipt = refresh_product_dashboard(out, today)
        dashboard_ok = isinstance(dashboard_receipt, dict)
        run_status["dashboard"] = {"state": "succeeded" if dashboard_ok else "failed"}
        if dashboard_ok:
            run_status["dashboard"].update({
                "source_date": dashboard_receipt["source_date"],
                "source_hash": dashboard_receipt["source_hash"],
                "html_hash": dashboard_receipt["html_hash"],
                "manifest_hash": dashboard_receipt["manifest_hash"],
            })
        else:
            print("⛔ 看板刷新/发布失败：通知将明确不附旧看板链接。", flush=True)
        write_run_status(today, run_status)

    # Step8: 推钉钉
    icons = ["🥇","🥈","🥉","4️⃣","5️⃣","6️⃣","7️⃣","8️⃣","9️⃣","🔟"]
    lines = [
        f"🔥 SP集团爆品变化日报（{today}）",
        f"近3天新品 × 流量Top{len(flagship_sp)}旗舰站FB验证 × 只推变化",
        "━━━━━━━━━━━━━━━━━━━━━━━",
        f"候选{len(results)}个 | 今日变化{changed_count}个 | 扫描Top{REPORT_SCAN_TOP_N}站",
        "",
    ]

    text_delivered_handles = []
    if changed_count:
        text_delivered_handles += append_change_section(
            lines, f"🆕 新爆款预警 {len(change_groups['new'])} 个", change_groups["new"], 6, icons
        )
        text_delivered_handles += append_change_section(
            lines, f"📣 新投放/LP信号 {len(change_groups['signal'])} 个", change_groups["signal"], 5, icons
        )
        text_delivered_handles += append_change_section(
            lines, f"📈 扩散加速 {len(change_groups['growth'])} 个", change_groups["growth"], 6, icons
        )
    else:
        lines.append("今日暂无需要重复推送的商品变化。")
        lines.append("稳定老品已自动过滤；有站点增长、FB/LP新信号或新进Top榜时再推。")
        lines.append("")

    # 站点维度摘要：只报有今日新品或近3天数量发生变化的站点
    active_sites = [s for s in site_stats_list if s["recent_new"] > 0]
    changed_sites = [s for s in active_sites if s["today_new"] > 0 or s.get("diff")]
    changed_sites.sort(key=lambda s: (s["today_new"], abs(s.get("diff", 0)), s["recent_new"]), reverse=True)
    if changed_sites:
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"📊 站点异动（有今日新品或近3天数量变化，Top{min(len(changed_sites),8)}）")
        for s in changed_sites[:8]:
            flag = "🏆" if s["is_flagship"] else "  "
            diff_str = ""
            if s.get("yesterday_recent") is not None:
                d = s["diff"]
                diff_str = f" ↑{d}" if d > 0 else (f" ↓{abs(d)}" if d < 0 else "")
            lines.append(f"{flag} {s['domain']} | 今日{s['today_new']} | 近3天{s['recent_new']}{diff_str}")
        lines.append("")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━")
    fb_summary = " | ".join(
        f"{f['domain'].replace('.com','')} {len([h for h,ds in flagship_fb_handles.items() if f['domain'] in ds])}品"
        for f in flagship_sp[:3]
    )
    lines.append(f"旗舰站FB投放：{fb_summary}")
    lines.append("")
    lines.extend(dashboard_notification_lines(dashboard_receipt))

    msg = "\n".join(lines)
    print(f"\n{msg}\n", flush=True)

    report_exit_code = 0
    if args.send and changed_count > 0:
        delivery = run_report_delivery_v1(
            today=today,
            state=state,
            results=results,
            change_groups=change_groups,
            text_message=msg,
            text_delivered_handles=text_delivered_handles,
            dashboard_receipt=dashboard_receipt,
        )
        run_status["report"] = delivery["report"]
        report_exit_code = delivery["exit_code"]
        if report_exit_code == 0:
            print(f"\n[报告交付] 已完成；去重状态: {REPORT_STATE_FILE}", flush=True)
        else:
            print("\n[报告交付] 未获得端到端确定结果，已保留 active 供下次恢复。", flush=True)
    elif args.send:
        run_status["report"] = {"state": "skipped_no_changes"}
        print("\n[钉钉] 今日商品变化为 0，跳过发送空摘要且未推进去重状态", flush=True)
    else:
        print("\n[dry-run] 未发送钉钉，未更新去重状态；正式发送请加 --send", flush=True)

    if args.send and run_status["dashboard"].get("state") != "succeeded":
        report_exit_code = 3
    if report_exit_code != 0:
        run_status["final_state"] = "partial_failure"
        write_run_status(today, run_status)
        print(f"\n⚠️ 扫描完成，但发布阶段不完整；状态见 {WORKSPACE / f'sp_monitor_status_{today}.json'}")
        return report_exit_code

    run_status["final_state"] = "succeeded"
    write_run_status(today, run_status)
    print(f"\n✅ 完成！变化 {changed_count} 个，保存到 {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
