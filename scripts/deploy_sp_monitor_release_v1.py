"""Fail-closed SP monitor release deployment coordinator (v1).

The coordinator has no import-time I/O and never invokes Git or the network.
Filesystem, clock, and process/launchd observations are injected boundaries.
"""
from __future__ import annotations

import argparse
import ast
import datetime as _datetime
import errno
import fcntl
import functools
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import plistlib
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from zoneinfo import ZoneInfo

_manifest_path = Path(__file__).resolve(strict=True).with_name("sp_monitor_release_manifest_v1.py")
_manifest_name = "_spspy_bound_sp_monitor_release_manifest_v1"
_manifest_spec = importlib.util.spec_from_file_location(_manifest_name, _manifest_path)
if (_manifest_spec is None or _manifest_spec.loader is None or type(_manifest_spec.origin) is not str or
        Path(_manifest_spec.origin).resolve(strict=True) != _manifest_path):
    raise ImportError("exact sibling manifest binding failed")
manifest = importlib.util.module_from_spec(_manifest_spec)
sys.modules[_manifest_name] = manifest
try: _manifest_spec.loader.exec_module(manifest)
except BaseException:
    sys.modules.pop(_manifest_name, None); raise

EXIT_OK = 0
EXIT_SCHEMA = 64
EXIT_INTEGRITY = 65
EXIT_MISSING = 66
EXIT_INTERNAL = 70
EXIT_STAGING = 73
EXIT_ROLLED_BACK = 74
EXIT_RETRY = 75
EXIT_PROTOCOL = 76
EXIT_UNSAFE = 77
EXIT_CONFLICT = 78
EXIT_UNCERTAIN = 80
JOURNAL_SCHEMA = "sp-monitor-deploy-journal/v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class DeploymentError(Exception):
    def __init__(self, message, exit_code): super().__init__(message); self.exit_code = exit_code


class FaultInjector:
    """Deterministic test-only fault hook."""
    def __init__(self, fail_at=None): self.fail_at, self.events = fail_at, []
    def hit(self, event):
        self.events.append(event)
        if event == self.fail_at: raise OSError(f"injected fault at {event}")


class Clock:
    def now(self): return _datetime.datetime.now(_datetime.timezone.utc)


class ProcessInspector:
    """Production integration boundary; implementations must only observe state."""
    def repo_state(self, repo_root): raise DeploymentError("repository state inspector is required", EXIT_PROTOCOL)
    def main_state(self, plist_policy): raise DeploymentError("launchd inspector is required", EXIT_PROTOCOL)
    def process_scan(self): raise DeploymentError("process inspector is required", EXIT_PROTOCOL)
    def dependent_state(self, consumer_policy): raise DeploymentError("dependent inspector is required", EXIT_PROTOCOL)


class ProductionProcessInspector(ProcessInspector):
    """Read-only local Git/launchctl/ps observer; every subprocess uses argv+timeout."""
    def _run(self, argv, accepted=(0,), env=None):
        try: result = subprocess.run(list(argv), shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5, check=False, env=env)
        except (OSError, subprocess.SubprocessError) as error: raise DeploymentError("read-only process inspector command failed", EXIT_PROTOCOL) from error
        if result.returncode not in accepted or len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 1024 * 1024: raise DeploymentError("read-only process inspector response failed", EXIT_PROTOCOL)
        return result
    def repo_state(self, repo_root):
        root = os.path.abspath(os.fspath(repo_root))
        environment = dict(os.environ); environment["GIT_OPTIONAL_LOCKS"] = "0"
        status = self._run(["git", "-C", root, "status", "--porcelain=v1", "--untracked-files=normal"], env=environment).stdout
        ref = self._run(["git", "-C", root, "symbolic-ref", "--quiet", "HEAD"], env=environment).stdout.strip()
        commit = self._run(["git", "-C", root, "rev-parse", "--verify", "HEAD^{commit}"], env=environment).stdout.strip()
        proof = self._run(["git", "-C", root, "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"], accepted=(0, 1), env=environment).returncode == 0
        return {"clean": status == "", "ref": ref, "commit": commit, "merge_proven": proof}
    def process_scan(self):
        output = self._run(["ps", "-axo", "pid=,command="]).stdout; rows = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped: continue
            pieces = stripped.split(None, 1)
            if len(pieces) != 2 or not pieces[0].isdigit(): raise DeploymentError("ps output is not pid+argv", EXIT_PROTOCOL)
            try: argv = shlex.split(pieces[1], posix=True)
            except ValueError as error: raise DeploymentError("ps argv parsing failed", EXIT_PROTOCOL) from error
            if not argv or any(type(value) is not str or not value for value in argv): raise DeploymentError("ps argv is invalid", EXIT_PROTOCOL)
            rows.append(argv)
        return rows
    def _plist(self, label, exact_keys=None, environment_keys=None):
        path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
        try: raw = path.read_bytes(); value = plistlib.loads(raw)
        except Exception as error: raise DeploymentError("dependent plist read/parse failed", EXIT_PROTOCOL) from error
        if type(value) is not dict or (exact_keys is not None and set(value) != set(exact_keys)):
            raise DeploymentError("plist exact key inventory differs", EXIT_PROTOCOL)
        if environment_keys is not None:
            environment = value.get("EnvironmentVariables")
            if type(environment) is not dict or set(environment) != set(environment_keys) or any(type(key) is not str or type(item) is not str for key, item in environment.items()):
                raise DeploymentError("plist environment inventory differs", EXIT_PROTOCOL)
        argv = value.get("ProgramArguments")
        if type(argv) is not list or not argv or any(type(x) is not str or not x for x in argv): raise DeploymentError("plist ProgramArguments is invalid", EXIT_PROTOCOL)
        return raw, argv
    def _launch(self, label, configured, process_match_tokens):
        domain = f"gui/{os.getuid()}"; printed = self._run(["launchctl", "print", f"{domain}/{label}"], accepted=(0, 113))
        disabled = self._run(["launchctl", "print-disabled", domain]).stdout
        match = re.search(r'"' + re.escape(label) + r'"\s*=>\s*(true|false)', disabled)
        if match is None: raise DeploymentError("launchctl enabled state is unavailable", EXIT_PROTOCOL)
        loaded = printed.returncode == 0; pid_match = re.search(r"(?:^|\n)\s*pid\s*=\s*(\d+)", printed.stdout); pid = None if pid_match is None else int(pid_match.group(1))
        identities = [_text_identity(token) for token in process_match_tokens]
        running = [argv for argv in _validated_process_scan(self.process_scan()) if any(_argv_references(identity, argv) for identity in identities)]
        if len(running) > 1: raise DeploymentError("multiple matching processes found", EXIT_PROTOCOL)
        return {"enabled": match.group(1) == "false", "loaded": loaded, "pid": pid, "configured_argv": configured, "runtime_argv": [] if not running else running[0]}
    def main_state(self, plist_policy):
        label = plist_policy["label"]
        raw, argv = self._plist(label, plist_policy["plist_keys"], plist_policy["environment_variable_keys"]); state = self._launch(label, argv, [os.path.expanduser(plist_policy["entrypoint"])])
        return {"loaded": state["loaded"], "enabled": state["enabled"], "pid": state["pid"], "argv": state["configured_argv"]}
    def _fixed_source_sha256(self, path):
        actual = os.path.expanduser(path); flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try: fd = os.open(actual, flags)
        except OSError as error: raise DeploymentError("dependent source read failed", EXIT_PROTOCOL) from error
        try:
            before, named = os.fstat(fd), os.stat(actual, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or
                    (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)):
                raise DeploymentError("dependent source path is unsafe", EXIT_PROTOCOL)
            digest = hashlib.sha256(); total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk: break
                total += len(chunk)
                if total > 64 * 1024 * 1024: raise DeploymentError("dependent source exceeds resource limit", EXIT_PROTOCOL)
                digest.update(chunk)
            after, again = os.fstat(fd), os.stat(actual, follow_symlinks=False)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                    (after.st_dev, after.st_ino) != (again.st_dev, again.st_ino)):
                raise DeploymentError("dependent source changed during read", EXIT_PROTOCOL)
            return digest.hexdigest()
        finally: os.close(fd)
    def dependent_state(self, consumer_policy):
        name = consumer_policy["name"]
        labels = dict(manifest.EXACT_DEPENDENTS)
        if name not in labels: raise DeploymentError("unknown dependent consumer", EXIT_PROTOCOL)
        label = labels[name]; raw, argv = self._plist(label)
        sources = [{"path": item["path"], "sha256": self._fixed_source_sha256(item["path"])} for item in consumer_policy["source_files"]]
        return {"source_files": sources, "plist_sha256": _sha(raw), "labels": {label: self._launch(label, argv, consumer_policy["process_match_tokens"])}}


class Ops:
    """Same-UID local filesystem boundary. A mapper is useful for fake tests."""
    def __init__(self, mapper=None): self.mapper = mapper
    def resolve(self, path):
        value = os.fspath(path)
        return os.fspath(self.mapper(value)) if self.mapper else os.path.expanduser(value)
    def read_bytes(self, path):
        actual = self.resolve(path)
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try: fd = os.open(actual, flags)
        except FileNotFoundError as error: raise DeploymentError("required file is missing", EXIT_MISSING) from error
        try:
            st = os.fstat(fd); named = os.stat(actual, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or (st.st_dev, st.st_ino) != (named.st_dev, named.st_ino): raise DeploymentError("unsafe file", EXIT_UNSAFE)
            chunks = []
            while True:
                data = os.read(fd, 65536)
                if not data: break
                chunks.append(data)
                if sum(map(len, chunks)) > 64 * 1024 * 1024: raise DeploymentError("file exceeds resource limit", EXIT_INTERNAL)
            after = os.fstat(fd); again = os.stat(actual, follow_symlinks=False)
            if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or (after.st_dev, after.st_ino) != (again.st_dev, again.st_ino): raise DeploymentError("file changed during read", EXIT_UNSAFE)
            return b"".join(chunks)
        finally: os.close(fd)
    def lstat(self, path): return os.lstat(self.resolve(path))
    def exists(self, path):
        try: os.lstat(self.resolve(path)); return True
        except FileNotFoundError: return False
    def mkdir_private(self, path):
        actual = self.resolve(path)
        try: os.mkdir(actual, 0o700); return True
        except FileExistsError:
            st = os.lstat(actual)
            if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.getuid(): raise DeploymentError("unsafe private directory", EXIT_UNSAFE)
            return False
    def plist_bytes(self, label): return self.read_bytes(f"~/Library/LaunchAgents/{label}.plist")
def _sha(data): return hashlib.sha256(data).hexdigest()
def _canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode() + b"\n"
def _policy(value):
    if type(value) is bytes: return manifest.parse_source_policy(value)
    manifest.canonical_source_policy_bytes(value); return value
def _runtime(value):
    if type(value) is bytes: return manifest.parse_runtime_release(value)
    manifest.canonical_runtime_release_bytes(value); return value
def _join(root, relative): return root.rstrip("/") + "/" + relative
def _safe_regular(st, mode=None): return stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1 and (mode is None or stat.S_IMODE(st.st_mode) == mode)


def _validated_argv(value, what="process argv"):
    if type(value) is not list or not value or any(type(token) is not str or not token for token in value):
        raise DeploymentError(f"{what} protocol mismatch", EXIT_PROTOCOL)
    return value


def _validated_process_scan(value):
    if type(value) is not list:
        raise DeploymentError("process scan protocol mismatch", EXIT_PROTOCOL)
    for argv in value:
        _validated_argv(argv)
    return value


def _argv_references(executable, argv):
    if type(executable) is not str or not executable:
        raise DeploymentError("fixed executable protocol mismatch", EXIT_PROTOCOL)
    _validated_argv(argv)
    return any(executable in token for token in argv)


def _text_identity(value):
    if type(value) is not str or not value or value == "/bin/bash":
        raise DeploymentError("process identity protocol mismatch", EXIT_PROTOCOL)
    return os.path.expanduser(value)


def _source_blobs(policy, runtime, repo_root, ops):
    blobs = {}
    for item in runtime["bundle"]:
        path = os.path.join(os.fspath(repo_root), item["source"])
        data = ops.read_bytes(path); st = ops.lstat(path)
        if not _safe_regular(st, int(item["mode"], 8)): raise DeploymentError("unsafe source owner/mode/link/type", EXIT_UNSAFE)
        if len(data) != item["size"] or _sha(data) != item["sha256"]: raise DeploymentError("source hash/size mismatch", EXIT_INTEGRITY)
        blobs[item["source"]] = data
    manifest.verify_runtime_release(policy, runtime, blobs)
    return blobs


def _check_repository(runtime, repo_root, inspector):
    state = inspector.repo_state(repo_root)
    if type(state) is not dict or set(state) != {"clean", "ref", "commit", "merge_proven"}: raise DeploymentError("repository inspector protocol mismatch", EXIT_PROTOCOL)
    if state["clean"] is not True or state["ref"] != runtime["repository"]["ref"] or state["commit"] != runtime["repository"]["commit"] or state["merge_proven"] is not True: raise DeploymentError("repository ref/commit/clean/local-merge-proof gate failed", EXIT_INTEGRITY)


def _check_unresolved_dependents(policy):
    for item in policy["deployment"]["dependent_consumers"]:
        placeholder = "REQUIRED_AT_DEPLOY"
        if (item["unresolved"] or item["plist_sha256"] == placeholder or
                placeholder in item["configured_argv"] or placeholder in item["process_match_tokens"] or
                any(placeholder in (source["path"], source["sha256"]) for source in item["source_files"])):
            raise DeploymentError("dependent consumer inventory is unresolved", EXIT_CONFLICT)


def _check_dependents(policy, inspector):
    _check_unresolved_dependents(policy)
    scanned = _validated_process_scan(inspector.process_scan())
    for item in policy["deployment"]["dependent_consumers"]:
        state = inspector.dependent_state(item)
        expected = {"source_files", "plist_sha256", "labels"}
        if type(state) is not dict or set(state) != expected or type(state["labels"]) is not dict: raise DeploymentError("dependent inspector protocol mismatch", EXIT_PROTOCOL)
        if type(state["source_files"]) is not list or state["source_files"] != item["source_files"]:
            raise DeploymentError("dependent source inventory gate failed", EXIT_CONFLICT)
        if state["plist_sha256"] != item["plist_sha256"] or set(state["labels"]) != set(item["labels"]): raise DeploymentError("dependent plist/label inventory gate failed", EXIT_CONFLICT)
        for value in state["labels"].values():
            if type(value) is not dict or set(value) != {"enabled", "loaded", "pid", "configured_argv", "runtime_argv"}: raise DeploymentError("dependent label protocol mismatch", EXIT_PROTOCOL)
            configured = _validated_argv(value["configured_argv"], "dependent configured argv")
            runtime_argv = value["runtime_argv"]
            if type(value["enabled"]) is not bool or type(value["loaded"]) is not bool or type(runtime_argv) is not list:
                raise DeploymentError("dependent label protocol mismatch", EXIT_PROTOCOL)
            if runtime_argv: _validated_argv(runtime_argv, "dependent runtime argv")
            if value["pid"] is not None or runtime_argv != []: raise DeploymentError("dependent argv/pid idle gate failed", EXIT_CONFLICT)
            if configured != item["configured_argv"]: raise DeploymentError("dependent configured argv gate failed", EXIT_CONFLICT)
            if any(_argv_references(_text_identity(identity), argv) for identity in item["process_match_tokens"] for argv in scanned): raise DeploymentError("dependent process wrapper is active", EXIT_CONFLICT)
            if value["enabled"] is not False or value["loaded"] is not False: raise DeploymentError("dependent is not disabled/unloaded idle", EXIT_CONFLICT)


def _check_idle(policy, inspector, ops):
    plist = policy["deployment"]["plist"]
    expected_plist_sha = plist["plist_sha256"]
    if _sha(ops.plist_bytes(plist["label"])) != expected_plist_sha: raise DeploymentError("plist bytes/schema mismatch", EXIT_PROTOCOL)
    state = inspector.main_state(plist)
    argv = [ops.resolve(plist["interpreter"]), ops.resolve(plist["entrypoint"]), *plist["arguments"]]
    if type(state) is not dict or set(state) != {"loaded", "enabled", "pid", "argv"}:
        raise DeploymentError("main launchd inspector protocol mismatch", EXIT_PROTOCOL)
    _validated_argv(state["argv"], "main configured argv")
    if type(state["loaded"]) is not bool or type(state["enabled"]) is not bool:
        raise DeploymentError("main launchd inspector protocol mismatch", EXIT_PROTOCOL)
    if state != {"loaded": True, "enabled": True, "pid": None, "argv": argv}: raise DeploymentError("main launchd job is not loaded/enabled/idle with exact argv", EXIT_RETRY)
    scan = _validated_process_scan(inspector.process_scan())
    if _sha(ops.plist_bytes(plist["label"])) != expected_plist_sha: raise DeploymentError("plist changed during idle verification", EXIT_PROTOCOL)
    if any(_argv_references(argv[plist["entrypoint_index"]], row) for row in scan): raise DeploymentError("SP monitor process is active", EXIT_RETRY)


def _check_window(policy, clock):
    window = policy["deployment"]["allow_window"]; now = clock.now()
    if not isinstance(now, _datetime.datetime): raise DeploymentError("clock protocol mismatch", EXIT_PROTOCOL)
    try:
        if now.tzinfo is None or now.utcoffset() is None: raise DeploymentError("clock must be timezone-aware", EXIT_PROTOCOL)
        local = now.astimezone(ZoneInfo("Asia/Shanghai"))
    except DeploymentError: raise
    except Exception: raise DeploymentError("clock protocol mismatch", EXIT_PROTOCOL) from None
    minute = local.hour * 60 + local.minute
    def minutes(value): hour, minute = map(int, value.split(":")); return hour * 60 + minute
    start, end = minutes(window["start"]), minutes(window["end"])
    allowed = start <= minute <= end if start <= end else minute >= start or minute <= end
    if not allowed: raise DeploymentError("outside deployment allow-window", EXIT_RETRY)


def _check_live_baseline(policy, runtime, ops):
    root = policy["deployment"]["live_root"]; run = _join(root, "run.py")
    if not ops.exists(run): raise DeploymentError("live entrypoint is missing", EXIT_MISSING)
    digest = _sha(ops.read_bytes(run))
    known = {policy["baseline"]["live_entrypoint_sha256"], next(item["sha256"] for item in runtime["bundle"] if item["target"] == "run.py")}
    if digest not in known: raise DeploymentError("live entrypoint is neither baseline nor this release", EXIT_CONFLICT)


def _check_live_layout(policy, ops, create_helpers=False, lock=None):
    live = ops.resolve(policy["deployment"]["live_root"]); scripts = os.path.join(live, "scripts")
    try:
        live_st = os.lstat(live)
        if not stat.S_ISDIR(live_st.st_mode) or live_st.st_uid != os.getuid() or stat.S_IMODE(live_st.st_mode) & 0o022: raise DeploymentError("unsafe live root", EXIT_UNSAFE)
        if not os.path.lexists(scripts):
            if not create_helpers: return
            _fence(lock); os.mkdir(scripts, 0o700)
            dfd = os.open(live, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
            try: os.fsync(dfd)
            finally: os.close(dfd)
            _fence(lock)
        fd = os.open(scripts, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            current, named = os.fstat(fd), os.stat(scripts, follow_symlinks=False)
            if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) & 0o022 or
                    (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino)):
                raise DeploymentError("unsafe helper scripts directory", EXIT_UNSAFE)
        finally: os.close(fd)
    except DeploymentError: raise
    except OSError as error: raise DeploymentError("live layout check/create failed", EXIT_STAGING if create_helpers else EXIT_UNSAFE) from error


def verify_only(policy, runtime, repo_root, expected_release_id=None, *, ops=None, clock=None, process_inspector=None):
    """Perform every read-only gate; this function never acquires/creates a lock."""
    ops, clock, inspector = ops or Ops(), clock or Clock(), process_inspector or ProcessInspector()
    try: policy, runtime = _policy(policy), _runtime(runtime)
    except manifest.ManifestError as error: raise DeploymentError(str(error), error.exit_code) from error
    manifest.verify_runtime_release(policy, runtime)
    if expected_release_id is not None and runtime["release_id"] != expected_release_id: raise DeploymentError("expected release id mismatch", EXIT_INTEGRITY)
    _check_repository(runtime, repo_root, inspector); blobs = _source_blobs(policy, runtime, repo_root, ops)
    _check_window(policy, clock); _check_idle(policy, inspector, ops); _check_dependents(policy, inspector); _check_live_layout(policy, ops); _check_live_baseline(policy, runtime, ops)
    return {"ok": True, "release_id": runtime["release_id"], "bundle_digest": runtime["bundle_digest"], "source_count": len(blobs)}


def _extract_credentials(source):
    try: tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError): raise DeploymentError("live credential source AST is invalid", EXIT_INTEGRITY) from None
    wanted = {"DINGTALK_WEBHOOK": [], "DINGTALK_SECRET": []}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    value = node.value
                    if len(targets) != 1 or not isinstance(value, ast.Constant) or type(value.value) is not str or not value.value.strip(): raise DeploymentError("credential assignment is not exact single-Name/single-Constant", EXIT_INTEGRITY)
                    wanted[target.id].append(value.value)
    if any(len(values) != 1 for values in wanted.values()): raise DeploymentError("credential AST must contain each exact Name once", EXIT_INTEGRITY)
    return wanted["DINGTALK_WEBHOOK"][0], wanted["DINGTALK_SECRET"][0]


def _secure_existing_secret(path, ops):
    st = ops.lstat(path)
    if not _safe_regular(st, 0o600): raise DeploymentError("unsafe existing secret", EXIT_UNSAFE)
    return ops.read_bytes(path)


def _open_stable_secret_parent(parent, trusted_anchor):
    if not os.path.isabs(parent) or not os.path.isabs(trusted_anchor): raise DeploymentError("secret path anchor must be absolute", EXIT_UNSAFE)
    absolute, anchor = os.path.abspath(parent), os.path.abspath(trusted_anchor)
    try: relative = os.path.relpath(absolute, anchor); inside = os.path.commonpath((absolute, anchor)) == anchor
    except ValueError as error: raise DeploymentError("secret path is outside trusted anchor", EXIT_UNSAFE) from error
    if not inside or relative == os.pardir or relative.startswith(os.pardir + os.sep): raise DeploymentError("secret path is outside trusted anchor", EXIT_UNSAFE)
    current = os.open(anchor, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        anchor_st, anchor_named = os.fstat(current), os.stat(anchor, follow_symlinks=False)
        if (not stat.S_ISDIR(anchor_st.st_mode) or anchor_st.st_uid != os.getuid() or stat.S_IMODE(anchor_st.st_mode) & 0o022 or
                (anchor_st.st_dev, anchor_st.st_ino) != (anchor_named.st_dev, anchor_named.st_ino)):
            raise DeploymentError("unsafe trusted secret anchor", EXIT_UNSAFE)
        for component in [part for part in relative.split(os.sep) if part and part != "."]:
            child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=current)
            st, named = os.fstat(child), os.stat(component, dir_fd=current, follow_symlinks=False)
            if (not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o022 or
                    (st.st_dev, st.st_ino) != (named.st_dev, named.st_ino)):
                os.close(child); raise DeploymentError("unsafe secret path directory", EXIT_UNSAFE)
            os.close(current); current = child
        final = os.fstat(current)
        if final.st_uid != os.getuid() or stat.S_IMODE(final.st_mode) != 0o700: raise DeploymentError("secret directory must be same-owner 0700", EXIT_UNSAFE)
        return current, final
    except DeploymentError:
        os.close(current); raise
    except OSError as error:
        os.close(current); raise DeploymentError("secret path binding failed", EXIT_UNSAFE) from error


def _read_secret_at(dfd, name):
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
    try:
        before, named = os.fstat(fd), os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if not _safe_regular(before, 0o600) or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino): raise DeploymentError("unsafe existing secret", EXIT_UNSAFE)
        chunks, total = [], 0
        while True:
            data = os.read(fd, 4096)
            if not data: break
            total += len(data)
            if total > 65536: raise DeploymentError("secret exceeds resource limit", EXIT_INTERNAL)
            chunks.append(data)
        after, again = os.fstat(fd), os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or (after.st_dev, after.st_ino) != (again.st_dev, again.st_ino): raise DeploymentError("secret changed during read", EXIT_UNSAFE)
        return b"".join(chunks)
    finally: os.close(fd)


def _revalidate_secret_binding(parent, dfd, parent_before, name, expected):
    before_fp = (parent_before.st_dev, parent_before.st_ino)
    def check_parent():
        try:
            parent_fd_after = os.fstat(dfd)
            parent_path_after = os.stat(parent, follow_symlinks=False)
        except OSError:
            raise DeploymentError("secret directory binding changed", EXIT_UNSAFE) from None
        if (before_fp != (parent_fd_after.st_dev, parent_fd_after.st_ino) or
                before_fp != (parent_path_after.st_dev, parent_path_after.st_ino) or
                not stat.S_ISDIR(parent_fd_after.st_mode) or parent_fd_after.st_uid != os.getuid() or
                stat.S_IMODE(parent_fd_after.st_mode) != 0o700):
            raise DeploymentError("secret directory binding changed", EXIT_UNSAFE)
    check_parent()
    try: reread = _read_secret_at(dfd, name)
    except OSError: raise DeploymentError("existing secret changed during verification", EXIT_UNSAFE) from None
    if reread != expected:
        raise DeploymentError("existing secret changed during verification", EXIT_UNSAFE)
    check_parent()
    return reread


def _parse_secret_fields(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate")
            result[key] = value
        return result
    try: value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Exception: raise DeploymentError("existing secret JSON is invalid", EXIT_CONFLICT) from None
    if type(value) is not dict or set(value) != {"webhook", "secret"} or any(type(value[key]) is not str or not value[key].strip() for key in value): raise DeploymentError("existing secret JSON fields are invalid", EXIT_CONFLICT)
    return value["webhook"], value["secret"]


def _full_write(fd, data):
    offset = 0
    while offset < len(data):
        count = os.write(fd, data[offset:])
        if count <= 0: raise OSError("short write")
        offset += count


def migrate_credentials(policy, live_source_bytes=None, *, ops=None, fault=None, _lock=None):
    """No-clobber migrate two legacy AST constants to a private JSON secret."""
    ops, fault = ops or Ops(), fault or FaultInjector(); policy = _policy(policy)
    live = live_source_bytes if live_source_bytes is not None else ops.read_bytes(_join(policy["deployment"]["live_root"], "run.py"))
    webhook, secret = _extract_credentials(live)
    desired = _canonical({"secret": secret, "webhook": webhook}); path = ops.resolve(policy["deployment"]["secret_path"]); parent, name = os.path.dirname(path), os.path.basename(path)
    trusted_anchor = ops.resolve("~")
    dfd, parent_before = _open_stable_secret_parent(parent, trusted_anchor); temp = ".report_delivery.tmp." + os.urandom(12).hex(); fd = None; linked = False; temp_fp = None
    try:
        _fence(_lock)
        try: existing = _read_secret_at(dfd, name)
        except FileNotFoundError: existing = None
        if existing is not None:
            if _parse_secret_fields(existing) != (webhook, secret): raise DeploymentError("existing secret conflicts with migrated credentials", EXIT_CONFLICT)
            _fence(_lock)
            confirmed = _revalidate_secret_binding(parent, dfd, parent_before, name, existing)
            if _parse_secret_fields(confirmed) != (webhook, secret):
                raise DeploymentError("existing secret changed during verification", EXIT_UNSAFE)
            _fence(_lock)
            return {"created": False, "reused": True}
        _fence(_lock); fault.hit("secret.temp.open"); fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dfd)
        opened = os.fstat(fd); temp_fp = (opened.st_dev, opened.st_ino)
        _full_write(fd, desired); os.fchmod(fd, 0o600); fault.hit("secret.file.fsync"); os.fsync(fd); os.close(fd); fd = None; _fence(_lock)
        _fence(_lock); fault.hit("secret.hardlink"); os.link(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False); linked = True; _fence(_lock)
        _fence(_lock); os.unlink(temp, dir_fd=dfd); temp_fp = None; _fence(_lock); fault.hit("secret.dir.fsync"); os.fsync(dfd); _fence(_lock)
        parent_after = os.stat(parent, follow_symlinks=False)
        if (parent_before.st_dev, parent_before.st_ino) != (parent_after.st_dev, parent_after.st_ino): raise DeploymentError("secret directory path changed", EXIT_UNCERTAIN)
        if _parse_secret_fields(_read_secret_at(dfd, name)) != (webhook, secret): raise DeploymentError("secret post-verification failed", EXIT_UNCERTAIN)
        _fence(_lock)
        return {"created": True, "reused": False}
    except DeploymentError as error:
        if linked and error.exit_code != EXIT_UNCERTAIN: raise DeploymentError("secret migration outcome is uncertain", EXIT_UNCERTAIN) from error
        raise
    except FileExistsError as error:
        raise DeploymentError("secret appeared concurrently", EXIT_CONFLICT) from error
    except Exception as error:
        if linked: raise DeploymentError("secret migration outcome is uncertain", EXIT_UNCERTAIN) from error
        raise DeploymentError("secret staging failed with no live change", EXIT_STAGING) from error
    finally:
        if fd is not None: os.close(fd)
        try:
            current = os.stat(temp, dir_fd=dfd, follow_symlinks=False)
            if temp_fp is not None and (current.st_dev, current.st_ino) == temp_fp:
                _fence(_lock); os.unlink(temp, dir_fd=dfd); _fence(_lock)
        except FileNotFoundError: pass
        os.close(dfd)


class _Lock:
    def __init__(self, fd, parent_fd, scope_fd, guard_parent_fd, parent_path, scope_path, guard_parent_path, name, guard_name, parent_fp, scope_fp, guard_parent_fp, lock_fp):
        self.fd, self.parent_fd, self.parent_path, self.name = fd, parent_fd, parent_path, name
        self.scope_fd, self.scope_path = scope_fd, scope_path
        self.guard_parent_fd, self.guard_parent_path, self.guard_name = guard_parent_fd, guard_parent_path, guard_name
        self.parent_fp, self.scope_fp, self.guard_parent_fp, self.lock_fp = parent_fp, scope_fp, guard_parent_fp, lock_fp
    def fence(self):
        if self.fd is None: raise DeploymentError("deployment lock is not held", EXIT_UNSAFE)
        try:
            parent_fd_st = os.fstat(self.parent_fd); parent_path_st = os.stat(self.parent_path, follow_symlinks=False)
            scope_fd_st = os.fstat(self.scope_fd); scope_path_st = os.stat(self.scope_path, follow_symlinks=False)
            guard_parent_fd_st = os.fstat(self.guard_parent_fd); guard_parent_path_st = os.stat(self.guard_parent_path, follow_symlinks=False)
            lock_fd_st = os.fstat(self.fd); lock_name_st = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            guard_name_st = os.stat(self.guard_name, dir_fd=self.guard_parent_fd, follow_symlinks=False)
        except OSError:
            raise DeploymentError("permanent lock fence failed", EXIT_UNSAFE) from None
        parent_now = (parent_fd_st.st_dev, parent_fd_st.st_ino)
        lock_now = (lock_fd_st.st_dev, lock_fd_st.st_ino)
        scope_now = (scope_fd_st.st_dev, scope_fd_st.st_ino)
        guard_parent_now = (guard_parent_fd_st.st_dev, guard_parent_fd_st.st_ino)
        if (parent_now != self.parent_fp or parent_now != (parent_path_st.st_dev, parent_path_st.st_ino) or
                scope_now != self.scope_fp or scope_now != (scope_path_st.st_dev, scope_path_st.st_ino) or
                guard_parent_now != self.guard_parent_fp or guard_parent_now != (guard_parent_path_st.st_dev, guard_parent_path_st.st_ino) or
                lock_now != self.lock_fp or lock_now != (lock_name_st.st_dev, lock_name_st.st_ino) or
                lock_now != (guard_name_st.st_dev, guard_name_st.st_ino) or
                not stat.S_ISREG(lock_fd_st.st_mode) or lock_fd_st.st_uid != os.getuid() or
                stat.S_IMODE(lock_fd_st.st_mode) != 0o600 or
                lock_fd_st.st_nlink != 2 or lock_name_st.st_nlink != 2 or guard_name_st.st_nlink != 2 or
                not stat.S_ISDIR(parent_fd_st.st_mode) or
                parent_fd_st.st_uid != os.getuid() or stat.S_IMODE(parent_fd_st.st_mode) != 0o700 or
                not stat.S_ISDIR(scope_fd_st.st_mode) or scope_fd_st.st_uid != os.getuid() or stat.S_IMODE(scope_fd_st.st_mode) != 0o700 or
                not stat.S_ISDIR(guard_parent_fd_st.st_mode) or guard_parent_fd_st.st_uid != os.getuid() or
                stat.S_IMODE(guard_parent_fd_st.st_mode) & 0o022):
            raise DeploymentError("permanent lock fence failed", EXIT_UNSAFE)
    def close(self):
        if self.fd is not None:
            error = None
            try: self.fence()
            except DeploymentError as caught: error = caught
            try: fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd); os.close(self.scope_fd); os.close(self.parent_fd); os.close(self.guard_parent_fd)
                self.fd = self.scope_fd = self.parent_fd = self.guard_parent_fd = None
            if error is not None: raise error
    def __enter__(self): return self
    def __exit__(self, *unused): self.close()


def _acquire_lock(policy, ops):
    rollback = policy["deployment"]["rollback_root"]; lock_path = ops.resolve(policy["deployment"]["lock_path"]); parent_path = os.path.dirname(lock_path)
    created_lock_parent = ops.mkdir_private(parent_path); created_scope = ops.mkdir_private(rollback)
    if os.path.dirname(ops.resolve(rollback)) != parent_path: raise DeploymentError("lock parent does not anchor frozen rollback root", EXIT_UNSAFE)
    guard_parent_path = os.path.dirname(parent_path)
    if os.path.abspath(guard_parent_path) != os.path.abspath(ops.resolve("~")):
        raise DeploymentError("lock guard parent is not the frozen home anchor", EXIT_UNSAFE)
    name = os.path.basename(lock_path); guard_name = name + ".guard"; parent_fd = scope_fd = guard_parent_fd = fd = None
    created_primary = False
    try:
        parent_fd = os.open(parent_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        parent_st = os.fstat(parent_fd); parent_named = os.stat(parent_path, follow_symlinks=False)
        if (not stat.S_ISDIR(parent_st.st_mode) or parent_st.st_uid != os.getuid() or stat.S_IMODE(parent_st.st_mode) != 0o700 or
                (parent_st.st_dev, parent_st.st_ino) != (parent_named.st_dev, parent_named.st_ino)):
            raise DeploymentError("unsafe lock parent", EXIT_UNSAFE)
        guard_parent_fd = os.open(guard_parent_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        guard_parent_st, guard_parent_named = os.fstat(guard_parent_fd), os.stat(guard_parent_path, follow_symlinks=False)
        if (not stat.S_ISDIR(guard_parent_st.st_mode) or guard_parent_st.st_uid != os.getuid() or stat.S_IMODE(guard_parent_st.st_mode) & 0o022 or
                (guard_parent_st.st_dev, guard_parent_st.st_ino) != (guard_parent_named.st_dev, guard_parent_named.st_ino)):
            raise DeploymentError("unsafe lock guard parent", EXIT_UNSAFE)
        scope_name = os.path.basename(ops.resolve(rollback)); scope_fd = os.open(scope_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        scope_st, scope_named = os.fstat(scope_fd), os.stat(scope_name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(scope_st.st_mode) or scope_st.st_uid != os.getuid() or stat.S_IMODE(scope_st.st_mode) != 0o700 or
                (scope_st.st_dev, scope_st.st_ino) != (scope_named.st_dev, scope_named.st_ino)):
            raise DeploymentError("unsafe rollback scope", EXIT_UNSAFE)
        primary_exists = guard_exists = True
        try: os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError: primary_exists = False
        try: os.stat(guard_name, dir_fd=guard_parent_fd, follow_symlinks=False)
        except FileNotFoundError: guard_exists = False
        if primary_exists != guard_exists:
            raise DeploymentError("permanent lock dual-name guard is incomplete", EXIT_UNSAFE)
        if not primary_exists:
            if not (created_lock_parent or created_scope): raise DeploymentError("permanent lock disappeared or parent was retargeted", EXIT_UNSAFE)
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=parent_fd)
            created_primary = True
            os.fsync(fd)
            os.link(name, guard_name, src_dir_fd=parent_fd, dst_dir_fd=guard_parent_fd, follow_symlinks=False)
            os.fsync(parent_fd); os.fsync(guard_parent_fd)
        else:
            fd = os.open(name, os.O_RDWR | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        lock_st = os.fstat(fd); lock_named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False); guard_named = os.stat(guard_name, dir_fd=guard_parent_fd, follow_symlinks=False)
        lock_fp = (lock_st.st_dev, lock_st.st_ino)
        if (not stat.S_ISREG(lock_st.st_mode) or lock_st.st_uid != os.getuid() or stat.S_IMODE(lock_st.st_mode) != 0o600 or
                lock_st.st_nlink != 2 or lock_named.st_nlink != 2 or guard_named.st_nlink != 2 or
                lock_fp != (lock_named.st_dev, lock_named.st_ino) or lock_fp != (guard_named.st_dev, guard_named.st_ino)):
            raise DeploymentError("unsafe permanent lock dual-name guard", EXIT_UNSAFE)
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error: raise DeploymentError("deployment lock is busy", EXIT_RETRY) from error
        result = _Lock(fd, parent_fd, scope_fd, guard_parent_fd, parent_path, ops.resolve(rollback), guard_parent_path, name, guard_name, (parent_st.st_dev, parent_st.st_ino), (scope_st.st_dev, scope_st.st_ino), (guard_parent_st.st_dev, guard_parent_st.st_ino), lock_fp); result.fence(); return result
    except DeploymentError:
        if fd is not None: os.close(fd)
        if scope_fd is not None: os.close(scope_fd)
        if parent_fd is not None: os.close(parent_fd)
        if guard_parent_fd is not None: os.close(guard_parent_fd)
        raise
    except OSError as error:
        if created_primary and fd is not None:
            try:
                lock_st = os.fstat(fd)
                try: guard_st = os.stat(guard_name, dir_fd=guard_parent_fd, follow_symlinks=False)
                except (FileNotFoundError, TypeError): guard_st = None
                try: primary_st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except (FileNotFoundError, TypeError): primary_st = None
                guard_same = guard_st is not None and (guard_st.st_dev, guard_st.st_ino) == (lock_st.st_dev, lock_st.st_ino)
                if not guard_same and primary_st is not None and (primary_st.st_dev, primary_st.st_ino) == (lock_st.st_dev, lock_st.st_ino) and lock_st.st_nlink == 1:
                    os.unlink(name, dir_fd=parent_fd); os.fsync(parent_fd)
            except OSError:
                pass
        if fd is not None: os.close(fd)
        if scope_fd is not None: os.close(scope_fd)
        if parent_fd is not None: os.close(parent_fd)
        if guard_parent_fd is not None: os.close(guard_parent_fd)
        raise DeploymentError("permanent lock open failed", EXIT_UNSAFE) from error


def _fence(lock):
    if lock is not None: lock.fence()


def _mkdir_private_locked(path, ops, lock):
    _fence(lock); created = ops.mkdir_private(path)
    if created:
        actual = ops.resolve(path); dfd = os.open(os.path.dirname(actual), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
    _fence(lock); return created


def _owned_temp_name(name): return f".{name}.release-tmp-{os.urandom(12).hex()}"


def _target_state(path, ops):
    if not ops.exists(path): return False, None, None
    data = ops.read_bytes(path); st = ops.lstat(path)
    if not _safe_regular(st): raise DeploymentError("unsafe compare-before-replace target", EXIT_UNSAFE)
    return True, data, stat.S_IMODE(st.st_mode)


def _assert_expected_target(path, expected, ops):
    if (type(expected) is not tuple or len(expected) != 3 or type(expected[0]) is not bool or
            (expected[0] and (type(expected[1]) is not bytes or type(expected[2]) is not int)) or
            (not expected[0] and expected[1:] != (None, None))):
        raise DeploymentError("invalid expected target state", EXIT_PROTOCOL)
    if _target_state(path, ops) != expected:
        raise DeploymentError("compare-before-replace target drifted", EXIT_UNCERTAIN)


def _atomic_replace(path, data, mode, ops, fault, event, lock=None, expected=None):
    actual = ops.resolve(path); parent = os.path.dirname(actual); name = os.path.basename(actual); temp = os.path.join(parent, _owned_temp_name(name)); fd = None; attempted = False; temp_fp = None
    try:
        _fence(lock)
        if os.path.lexists(actual):
            current = os.lstat(actual)
            if not _safe_regular(current): raise DeploymentError("unsafe existing live target", EXIT_UNSAFE)
        fault.hit(event + ".open"); fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), mode)
        opened = os.fstat(fd); temp_fp = (opened.st_dev, opened.st_ino)
        _full_write(fd, data); os.fchmod(fd, mode); fault.hit(event + ".file_fsync"); os.fsync(fd); os.close(fd); fd = None; _fence(lock)
        st = os.lstat(temp)
        if not _safe_regular(st, mode) or ops.read_bytes(temp) != data: raise DeploymentError("staged file verification failed", EXIT_UNSAFE)
        _fence(lock); fault.hit(event + ".compare")
        if expected is not None: _assert_expected_target(path, expected, ops)
        _fence(lock); attempted = True; fault.hit(event + ".replace"); os.replace(temp, actual); _fence(lock); fault.hit(event + ".dir_fsync")
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
        if ops.read_bytes(path) != data or stat.S_IMODE(ops.lstat(path).st_mode) != mode: raise DeploymentError("installed file post-verification failed", EXIT_UNCERTAIN)
        _fence(lock)
    except DeploymentError as error:
        if attempted and error.exit_code != EXIT_UNCERTAIN: raise DeploymentError("atomic install outcome is uncertain", EXIT_UNCERTAIN) from error
        raise
    except Exception as error:
        if attempted: raise DeploymentError("atomic install outcome is uncertain", EXIT_UNCERTAIN) from error
        raise DeploymentError("atomic staging failed", EXIT_STAGING) from error
    finally:
        if fd is not None: os.close(fd)
        try:
            current = os.lstat(temp)
            if temp_fp is not None and (current.st_dev, current.st_ino) == temp_fp:
                _fence(lock); os.unlink(temp); _fence(lock)
        except FileNotFoundError: pass


def _write_new_private(path, data, ops, fault, event, lock=None):
    actual = ops.resolve(path); parent = os.path.dirname(actual); name = os.path.basename(actual); temp = os.path.join(parent, _owned_temp_name(name)); fd = None; temp_fp = None; linked = False
    try:
        _fence(lock); fault.hit(event + ".open"); fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        opened = os.fstat(fd); temp_fp = (opened.st_dev, opened.st_ino)
        _full_write(fd, data); os.fchmod(fd, 0o600); fault.hit(event + ".file_fsync"); os.fsync(fd); os.close(fd); fd = None; _fence(lock)
        if ops.read_bytes(temp) != data: raise DeploymentError("private staging readback failed", EXIT_UNCERTAIN)
        _fence(lock); fault.hit(event + ".link"); os.link(temp, actual, follow_symlinks=False); linked = True; _fence(lock)
        _fence(lock); os.unlink(temp); temp_fp = None; _fence(lock); fault.hit(event + ".dir_fsync")
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(dfd)
        finally: os.close(dfd)
        if ops.read_bytes(path) != data: raise DeploymentError("private write post-verification failed", EXIT_UNCERTAIN)
        _fence(lock)
    except FileExistsError as error:
        if os.path.lexists(actual):
            try:
                if _safe_regular(os.lstat(actual), 0o600) and ops.read_bytes(path) == data:
                    _fence(lock); return
            except DeploymentError: pass
        raise DeploymentError("private staging path already exists with different or unsafe bytes", EXIT_CONFLICT) from error
    except DeploymentError as error:
        if linked and error.exit_code != EXIT_UNCERTAIN: raise DeploymentError("private write outcome is uncertain", EXIT_UNCERTAIN) from error
        raise
    except OSError as error:
        raise DeploymentError("private write outcome is uncertain" if linked else "private staging failed", EXIT_UNCERTAIN if linked else EXIT_STAGING) from error
    finally:
        if fd is not None: os.close(fd)
        try:
            current = os.lstat(temp)
            if temp_fp is not None and (current.st_dev, current.st_ino) == temp_fp:
                _fence(lock); os.unlink(temp); _fence(lock)
        except FileNotFoundError: pass


def _install_plan(policy, runtime, blobs):
    install = [(item["target"], blobs[item["source"]], int(item["mode"], 8)) for item in runtime["bundle"][:2]]
    install.append((policy["deployment"]["runtime_manifest_target"], manifest.canonical_runtime_release_bytes(runtime), 0o644))
    entry = runtime["bundle"][2]; install.append((entry["target"], blobs[entry["source"]], int(entry["mode"], 8)))
    return install


def _journal_entries(policy, runtime, blobs, ops, release_root, fault, lock=None):
    live = policy["deployment"]["live_root"]; entries = []; expected_states = []
    install = _install_plan(policy, runtime, blobs)
    for index, (target, new, mode) in enumerate(install):
        live_path = _join(live, target); present = ops.exists(live_path); old = ops.read_bytes(live_path) if present else None; old_mode = None
        backup = None
        if present:
            old_st = ops.lstat(live_path)
            if not _safe_regular(old_st): raise DeploymentError("unsafe live target before backup", EXIT_UNSAFE)
            old_mode = f"{stat.S_IMODE(old_st.st_mode):04o}"; backup = f"backup-{index}.bin"; _write_new_private(_join(release_root, backup), old, ops, fault, f"backup.{index}", lock)
        expected_states.append((present, old, None if old_mode is None else int(old_mode, 8)))
        entries.append({"target": target, "old_mode": old_mode, "new_mode": f"{mode:04o}", "old_present": present, "old_sha256": None if old is None else _sha(old), "backup": backup, "new_sha256": _sha(new), "new_size": len(new)})
    return install, entries, expected_states


def _read_journal(policy, expected_release_id, ops):
    path = _join(_join(policy["deployment"]["rollback_root"], expected_release_id), policy["deployment"]["journal_name"])
    raw = ops.read_bytes(path)
    try: value = json.loads(raw.decode())
    except Exception as error: raise DeploymentError("invalid rollback journal", EXIT_UNCERTAIN) from error
    if (type(value) is not dict or set(value) != {"schema", "release_id", "bundle_digest", "status", "entries"} or
            value.get("schema") != JOURNAL_SCHEMA or value.get("release_id") != expected_release_id or
            value.get("status") not in ("prepared", "installed", "rolled_back") or
            type(value.get("entries")) is not list or len(value["entries"]) != 4 or not HEX64.fullmatch(value.get("bundle_digest", ""))):
        raise DeploymentError("invalid rollback journal", EXIT_UNCERTAIN)
    fixed_targets = [item["target"] for item in policy["bundle"][:2]] + [policy["deployment"]["runtime_manifest_target"], policy["bundle"][2]["target"]]
    if [entry.get("target") if type(entry) is dict else None for entry in value["entries"]] != fixed_targets: raise DeploymentError("journal target order differs", EXIT_UNCERTAIN)
    for index, entry in enumerate(value["entries"]):
        if (type(entry) is not dict or set(entry) != {"target", "old_mode", "new_mode", "old_present", "old_sha256", "backup", "new_sha256", "new_size"} or
                type(entry["old_present"]) is not bool or type(entry["new_size"]) is not int or entry["new_size"] < 0 or
                not re.fullmatch(r"0[0-7]{3}", entry["new_mode"]) or not HEX64.fullmatch(entry["new_sha256"]) or
                (entry["old_present"] and (not HEX64.fullmatch(entry["old_sha256"] or "") or entry["backup"] != f"backup-{index}.bin" or not re.fullmatch(r"0[0-7]{3}", entry["old_mode"] or ""))) or
                (not entry["old_present"] and (entry["old_sha256"] is not None or entry["backup"] is not None or entry["old_mode"] is not None))):
            raise DeploymentError("invalid rollback journal entry", EXIT_UNCERTAIN)
    if _canonical(value) != raw: raise DeploymentError("noncanonical rollback journal", EXIT_UNCERTAIN)
    return path, value


def _resume_existing_deploy(policy, runtime, install, ops, inspector, fault, canary, lock):
    _fence(lock)
    journal_path, journal = _read_journal(policy, runtime["release_id"], ops)
    if journal["bundle_digest"] != runtime["bundle_digest"]: raise DeploymentError("existing journal belongs to different bundle", EXIT_UNCERTAIN)
    expected_targets = [target for target, _, _ in install]
    if [entry["target"] for entry in journal["entries"]] != expected_targets: raise DeploymentError("journal target order differs", EXIT_UNCERTAIN)
    states = []; old_states = []
    live = policy["deployment"]["live_root"]; release_root = _join(policy["deployment"]["rollback_root"], runtime["release_id"])
    for entry, (_, new, mode) in zip(journal["entries"], install):
        if (_sha(new) != entry["new_sha256"] or len(new) != entry["new_size"] or
                f"{mode:04o}" != entry["new_mode"]):
            raise DeploymentError("journal new inventory differs", EXIT_UNCERTAIN)
        old = None
        if entry["old_present"]:
            backup_path = _join(release_root, entry["backup"])
            backup = ops.read_bytes(backup_path)
            if not _safe_regular(ops.lstat(backup_path), 0o600) or _sha(backup) != entry["old_sha256"]:
                raise DeploymentError("journal backup inventory differs", EXIT_UNCERTAIN)
            old = backup
        old_expected = (entry["old_present"], old, None if entry["old_mode"] is None else int(entry["old_mode"], 8)); old_states.append(old_expected)
        target = _join(live, entry["target"]); current_state = _target_state(target, ops)
        old_match = current_state == old_expected
        new_match = current_state == (True, new, mode)
        if not old_match and not new_match: raise DeploymentError("journal recovery found divergent live bytes or mode", EXIT_UNCERTAIN)
        states.append("new" if new_match else "old")
    if journal["status"] == "rolled_back": raise DeploymentError("release journal is already rolled back", EXIT_CONFLICT)
    if journal["status"] == "installed" and any(state != "new" for state in states): raise DeploymentError("installed journal does not match live state", EXIT_UNCERTAIN)
    try:
        for index, ((target, data, mode), state, old_expected) in enumerate(zip(install, states, old_states)):
            if state == "new": continue
            _check_idle(policy, inspector, ops)
            _atomic_replace(_join(live, target), data, mode, ops, fault, f"recover.install.{index}", lock, expected=old_expected)
        _canary_bundle_bytes(policy, runtime, ops)
        if canary:
            _fence(lock); run_fake_canary(policy, runtime, ops=ops); _fence(lock)
        if journal["status"] != "installed":
            journal["status"] = "installed"; _atomic_replace(journal_path, _canonical(journal), 0o600, ops, fault, "recover.journal.commit", lock)
        return {"deployed": True, "recovered": True, "release_id": runtime["release_id"], "bundle_digest": runtime["bundle_digest"]}
    except DeploymentError as error:
        if error.exit_code == EXIT_UNCERTAIN: raise
        try: _rollback_locked(policy, runtime["release_id"], ops, fault, lock)
        except DeploymentError as rollback_error: raise DeploymentError("recovery and rollback outcome uncertain", EXIT_UNCERTAIN) from rollback_error
        raise DeploymentError("recovered deployment failed and was fully rolled back", EXIT_ROLLED_BACK) from error


def _unlink_exact(path, expected_sha, expected_size, expected_mode, ops, fault, event, lock):
    actual = ops.resolve(path); parent, name = os.path.dirname(actual), os.path.basename(actual); attempted = False
    try:
        _fence(lock); current = ops.read_bytes(path)
        if (_sha(current) != expected_sha or len(current) != expected_size or
                not _safe_regular(ops.lstat(path), expected_mode)): raise DeploymentError("delete target is not exact new file", EXIT_UNCERTAIN)
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            fault.hit(event + ".unlink"); attempted = True; os.unlink(name, dir_fd=dfd); fault.hit(event + ".dir_fsync"); os.fsync(dfd)
        finally: os.close(dfd)
        if ops.exists(path): raise DeploymentError("delete post-verification failed", EXIT_UNCERTAIN)
        _fence(lock)
    except DeploymentError as error:
        if attempted and error.exit_code != EXIT_UNCERTAIN: raise DeploymentError("delete outcome is uncertain", EXIT_UNCERTAIN) from error
        raise
    except OSError as error: raise DeploymentError("delete outcome is uncertain" if attempted else "safe delete failed", EXIT_UNCERTAIN) from error


def _rollback_locked(policy, expected_release_id, ops, fault, lock):
    _fence(lock)
    journal_path, journal = _read_journal(policy, expected_release_id, ops); release_root = _join(policy["deployment"]["rollback_root"], expected_release_id); live = policy["deployment"]["live_root"]
    for index in range(len(journal["entries"]) - 1, -1, -1):
        entry = journal["entries"][index]
        target = _join(live, entry["target"]); current_state = _target_state(target, ops); current = current_state[1]
        current_sha = None if current is None else _sha(current)
        if entry["old_present"]:
            backup_path = _join(release_root, entry["backup"]); old = ops.read_bytes(backup_path)
            if not _safe_regular(ops.lstat(backup_path), 0o600): raise DeploymentError("unsafe rollback backup", EXIT_UNCERTAIN)
            if _sha(old) != entry["old_sha256"]: raise DeploymentError("backup digest mismatch", EXIT_UNCERTAIN)
            old_exact = (True, old, int(entry["old_mode"], 8))
            if current_state == old_exact: continue
            old_bytes_wrong_mode = current is not None and current == old
            new_exact = (current is not None and current_sha == entry["new_sha256"] and len(current) == entry["new_size"] and
                    current_state[2] == int(entry["new_mode"], 8))
            if not old_bytes_wrong_mode and not new_exact: raise DeploymentError("live file diverged; rollback refused", EXIT_UNCERTAIN)
            _atomic_replace(target, old, int(entry["old_mode"], 8), ops, fault, f"rollback.{index}", lock, expected=current_state)
        else:
            if current is None: continue
            if (current_sha != entry["new_sha256"] or len(current) != entry["new_size"] or
                    current_state[2] != int(entry["new_mode"], 8)): raise DeploymentError("unknown file cannot be deleted", EXIT_UNCERTAIN)
            _unlink_exact(target, entry["new_sha256"], entry["new_size"], int(entry["new_mode"], 8), ops, fault, f"rollback.{index}", lock)
    journal["status"] = "rolled_back"; _atomic_replace(journal_path, _canonical(journal), 0o600, ops, fault, "journal.rollback", lock)
    return {"rolled_back": True, "release_id": expected_release_id, "secret_retained": True}


def deploy_release(policy, runtime, repo_root, expected_release_id=None, *, ops=None, clock=None, process_inspector=None, fault=None, canary=True):
    ops, clock, inspector, fault = ops or Ops(), clock or Clock(), process_inspector or ProcessInspector(), fault or FaultInjector()
    policy, runtime = _policy(policy), _runtime(runtime)
    _check_unresolved_dependents(policy)
    _check_repository(runtime, repo_root, inspector); blobs = _source_blobs(policy, runtime, repo_root, ops)
    if expected_release_id is not None and runtime["release_id"] != expected_release_id: raise DeploymentError("expected release id mismatch", EXIT_INTEGRITY)
    with _acquire_lock(policy, ops) as lock:
        _check_window(policy, clock); _check_idle(policy, inspector, ops); _check_dependents(policy, inspector); _check_live_layout(policy, ops, True, lock); _check_live_baseline(policy, runtime, ops)
        release_root = _join(policy["deployment"]["rollback_root"], runtime["release_id"]); _mkdir_private_locked(release_root, ops, lock)
        journal_path = _join(release_root, policy["deployment"]["journal_name"])
        if ops.exists(journal_path): return _resume_existing_deploy(policy, runtime, _install_plan(policy, runtime, blobs), ops, inspector, fault, canary, lock)
        migrate_credentials(policy, ops=ops, fault=fault, _lock=lock)
        install, entries, expected_states = _journal_entries(policy, runtime, blobs, ops, release_root, fault, lock)
        journal = {"schema": JOURNAL_SCHEMA, "release_id": runtime["release_id"], "bundle_digest": runtime["bundle_digest"], "status": "prepared", "entries": entries}
        _write_new_private(journal_path, _canonical(journal), ops, fault, "journal", lock)
        try:
            for index, ((target, data, mode), expected_state) in enumerate(zip(install, expected_states)):
                _check_idle(policy, inspector, ops)
                _source_blobs(policy, runtime, repo_root, ops)
                _atomic_replace(_join(policy["deployment"]["live_root"], target), data, mode, ops, fault, f"install.{index}", lock, expected=expected_state)
            _canary_bundle_bytes(policy, runtime, ops)
            if canary:
                _fence(lock); run_fake_canary(policy, runtime, ops=ops); _fence(lock)
            journal["status"] = "installed"; _atomic_replace(journal_path, _canonical(journal), 0o600, ops, fault, "journal.commit", lock)
            return {"deployed": True, "release_id": runtime["release_id"], "bundle_digest": runtime["bundle_digest"]}
        except DeploymentError as error:
            if error.exit_code == EXIT_UNCERTAIN: raise
            try: _rollback_locked(policy, runtime["release_id"], ops, fault, lock)
            except DeploymentError as rollback_error: raise DeploymentError("deploy and rollback outcome uncertain", EXIT_UNCERTAIN) from rollback_error
            raise DeploymentError("deployment failed and was fully rolled back", EXIT_ROLLED_BACK) from error


def rollback_release(policy, expected_release_id, *, ops=None, clock=None, process_inspector=None, fault=None):
    ops, clock, inspector, fault = ops or Ops(), clock or Clock(), process_inspector or ProcessInspector(), fault or FaultInjector(); policy = _policy(policy)
    if not re.fullmatch(r"spmrv1-[0-9a-f]{32}", expected_release_id): raise DeploymentError("invalid expected release id", EXIT_SCHEMA)
    _check_unresolved_dependents(policy)
    with _acquire_lock(policy, ops) as lock:
        _check_window(policy, clock); _check_idle(policy, inspector, ops); _check_dependents(policy, inspector); _check_live_layout(policy, ops)
        return _rollback_locked(policy, expected_release_id, ops, fault, lock)


class _ExactCanarySourceLoader(importlib.machinery.SourceFileLoader):
    """Compile only the already verified installed bytes; never consult a pyc."""
    def __init__(self, fullname, path, exact_source):
        super().__init__(fullname, path); self._exact_source = exact_source
    def get_code(self, fullname):
        if fullname != self.name: raise ImportError("canary loader name mismatch")
        return self.source_to_code(self._exact_source, self.path)


def _canary_bundle_bytes(policy, runtime, ops):
    live = policy["deployment"]["live_root"]; installed = {}
    for item in runtime["bundle"]:
        path = _join(live, item["target"]); data = ops.read_bytes(path); st = ops.lstat(path)
        if not _safe_regular(st, int(item["mode"], 8)):
            raise DeploymentError("canary deployed bundle metadata mismatch", EXIT_UNSAFE)
        if _sha(data) != item["sha256"] or len(data) != item["size"]:
            raise DeploymentError("canary deployed bundle mismatch", EXIT_INTEGRITY)
        installed[item["source"]] = (ops.resolve(path), data)
    runtime_path = _join(live, policy["deployment"]["runtime_manifest_target"]); runtime_bytes = ops.read_bytes(runtime_path)
    if not _safe_regular(ops.lstat(runtime_path), 0o644):
        raise DeploymentError("installed runtime manifest metadata mismatch", EXIT_UNSAFE)
    if runtime_bytes != manifest.canonical_runtime_release_bytes(runtime):
        raise DeploymentError("installed runtime manifest differs from exact canonical bytes", EXIT_INTEGRITY)
    return installed


def _load_installed_canary_modules(installed):
    outbox_path, outbox_source = installed["scripts/report_delivery_outbox_v1.py"]
    adapter_path, adapter_source = installed["scripts/report_delivery_adapters_v1.py"]
    namespace = "_sp_monitor_installed_canary_" + os.urandom(16).hex()
    if namespace in sys.modules or any(name.startswith(namespace + ".") for name in sys.modules):
        raise DeploymentError("canary private namespace collision", EXIT_PROTOCOL)
    scripts_present = "scripts" in sys.modules; scripts_package = sys.modules.get("scripts")
    created_scripts_package = False
    if not scripts_present:
        scripts_spec = importlib.machinery.ModuleSpec("scripts", loader=None, is_package=True)
        scripts_package = importlib.util.module_from_spec(scripts_spec); scripts_package.__path__ = [os.fspath(Path(__file__).resolve(strict=True).parent)]
        sys.modules["scripts"] = scripts_package; created_scripts_package = True
    elif scripts_package is None or not hasattr(scripts_package, "__path__"):
        raise DeploymentError("scripts package binding is unavailable", EXIT_PROTOCOL)
    outbox_name = namespace + ".report_delivery_outbox_v1"; adapter_name = namespace + ".report_delivery_adapters_v1"
    alias_name = "scripts.report_delivery_outbox_v1"; alias_attr = "report_delivery_outbox_v1"
    alias_present = alias_name in sys.modules; alias_previous = sys.modules.get(alias_name)
    attr_present = hasattr(scripts_package, alias_attr); attr_previous = getattr(scripts_package, alias_attr, None)
    try:
        package_spec = importlib.machinery.ModuleSpec(namespace, loader=None, is_package=True)
        package = importlib.util.module_from_spec(package_spec); package.__path__ = [os.path.dirname(outbox_path)]
        sys.modules[namespace] = package
        outbox_spec = importlib.util.spec_from_file_location(outbox_name, outbox_path, loader=_ExactCanarySourceLoader(outbox_name, outbox_path, outbox_source))
        if outbox_spec is None or outbox_spec.loader is None: raise DeploymentError("installed outbox import spec failed", EXIT_PROTOCOL)
        outbox = importlib.util.module_from_spec(outbox_spec); sys.modules[outbox_name] = outbox; outbox_spec.loader.exec_module(outbox)
        sys.modules[alias_name] = outbox; setattr(scripts_package, alias_attr, outbox)
        adapter_spec = importlib.util.spec_from_file_location(adapter_name, adapter_path, loader=_ExactCanarySourceLoader(adapter_name, adapter_path, adapter_source))
        if adapter_spec is None or adapter_spec.loader is None: raise DeploymentError("installed adapter import spec failed", EXIT_PROTOCOL)
        adapter = importlib.util.module_from_spec(adapter_spec); sys.modules[adapter_name] = adapter; adapter_spec.loader.exec_module(adapter)
        if getattr(adapter, "outbox", None) is not outbox:
            raise DeploymentError("installed adapter is not bound to installed outbox", EXIT_PROTOCOL)
        yield outbox, adapter
    finally:
        if alias_present: sys.modules[alias_name] = alias_previous
        else: sys.modules.pop(alias_name, None)
        if attr_present: setattr(scripts_package, alias_attr, attr_previous)
        elif hasattr(scripts_package, alias_attr): delattr(scripts_package, alias_attr)
        for name in [name for name in tuple(sys.modules) if name == namespace or name.startswith(namespace + ".")]:
            sys.modules.pop(name, None)
        if created_scripts_package: sys.modules.pop("scripts", None)


def run_fake_canary(policy, runtime, *, ops=None):
    ops, policy, runtime = ops or Ops(), _policy(policy), _runtime(runtime)
    binding_error = None
    try: manifest.verify_runtime_release(policy, runtime)
    except manifest.ManifestError: binding_error = DeploymentError("runtime release policy binding mismatch", EXIT_INTEGRITY)
    if binding_error is not None: raise binding_error from None
    _check_live_layout(policy, ops)
    installed = _canary_bundle_bytes(policy, runtime, ops)
    normalized = None
    try:
        loader = _load_installed_canary_modules(installed)
        outbox, adapter = next(loader)
        try:
            record = outbox.create_record(repository="synthetic/report-delivery-canary", ref="refs/heads/report-delivery-canary", path="synthetic/report-delivery/canary.png", image_bytes=b"synthetic-image", primary_payload_bytes=b"synthetic-primary", changed_handles=("synthetic-handle",), primary_handles=("synthetic-handle",))
            with tempfile.TemporaryDirectory(prefix="sp-monitor-controlled-canary-") as temp:
                os.chmod(temp, 0o700)
                result = adapter.controlled_canary(os.path.realpath(os.path.join(temp, "store")), record)
            _canary_bundle_bytes(policy, runtime, ops)
        finally:
            try: next(loader)
            except StopIteration: pass
    except (DeploymentError, KeyboardInterrupt, SystemExit): raise
    except Exception: normalized = DeploymentError("bound controlled canary failed", EXIT_PROTOCOL)
    if normalized is not None: raise normalized from None
    if type(result) is not dict or result.get("state") != "complete" or result.get("reconcile_required") is not False: raise DeploymentError("controlled canary protocol mismatch", EXIT_PROTOCOL)
    return {"ok": True, "state": "complete", "reconcile_required": False}


def _read(path):
    try: return Path(path).read_bytes()
    except FileNotFoundError as error: raise DeploymentError("required input is missing", EXIT_MISSING) from error


def main(argv=None, *, ops=None, clock=None, process_inspector=None):
    parser = argparse.ArgumentParser(prog="deploy-sp-monitor-release-v1")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("verify-only", "deploy", "canary"):
        cmd = sub.add_parser(name); cmd.add_argument("--policy", required=True); cmd.add_argument("--runtime", required=True); cmd.add_argument("--repo-root", required=True); cmd.add_argument("--expected-release-id")
    rollback = sub.add_parser("rollback"); rollback.add_argument("--policy", required=True); rollback.add_argument("--expected-release-id", required=True)
    args = parser.parse_args(argv)
    process_inspector = process_inspector or ProductionProcessInspector()
    try:
        policy = _read(args.policy)
        if args.command == "rollback": rollback_release(policy, args.expected_release_id, ops=ops, clock=clock, process_inspector=process_inspector); return 0
        runtime = _read(args.runtime)
        if args.command == "verify-only": verify_only(policy, runtime, args.repo_root, args.expected_release_id, ops=ops, clock=clock, process_inspector=process_inspector); return 0
        if args.command == "canary":
            parsed_policy = _policy(policy); parsed_runtime = _runtime(runtime)
            binding_error = None
            try: manifest.verify_runtime_release(parsed_policy, parsed_runtime)
            except manifest.ManifestError: binding_error = DeploymentError("runtime release policy binding mismatch", EXIT_INTEGRITY)
            if binding_error is not None: raise binding_error from None
            if args.expected_release_id is not None and parsed_runtime["release_id"] != args.expected_release_id: raise DeploymentError("expected release id mismatch", EXIT_INTEGRITY)
            run_fake_canary(parsed_policy, parsed_runtime, ops=ops); return 0
        deploy_release(policy, runtime, args.repo_root, args.expected_release_id, ops=ops, clock=clock, process_inspector=process_inspector); return 0
    except DeploymentError as error:
        print(f"ERROR[{error.exit_code}]: {error}", file=sys.stderr); return error.exit_code
    except manifest.ManifestError as error:
        print(f"ERROR[{error.exit_code}]: {error}", file=sys.stderr); return error.exit_code
    except KeyboardInterrupt: raise
    except OSError:
        print("ERROR[70]: internal/resource failure", file=sys.stderr); return EXIT_INTERNAL
    except Exception:
        print("ERROR[70]: internal/resource failure", file=sys.stderr); return EXIT_INTERNAL


def _normalize_public(default_code):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except (DeploymentError, KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                normalized = DeploymentError("public operation failed", default_code)
            # Raise after leaving the handler so the sensitive original exception
            # is not retained as __cause__ or __context__.
            raise normalized from None
        return wrapped
    return decorate


verify_only = _normalize_public(EXIT_INTERNAL)(verify_only)
migrate_credentials = _normalize_public(EXIT_STAGING)(migrate_credentials)
deploy_release = _normalize_public(EXIT_UNCERTAIN)(deploy_release)
rollback_release = _normalize_public(EXIT_UNCERTAIN)(rollback_release)
run_fake_canary = _normalize_public(EXIT_PROTOCOL)(run_fake_canary)


if __name__ == "__main__": raise SystemExit(main())


__all__ = ["verify_only", "migrate_credentials", "deploy_release", "rollback_release", "run_fake_canary", "main", "Ops", "Clock", "ProcessInspector", "ProductionProcessInspector", "FaultInjector", "DeploymentError"]
