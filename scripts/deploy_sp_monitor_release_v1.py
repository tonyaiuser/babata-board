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
import pwd
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unicodedata
import urllib.parse
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
CREDENTIAL_FIELD_MAX_CHARS = 4096
DELIVERY_SECRET_MAX_BYTES = 16 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
POLICY_ARCHIVE_NAME = "source-policy.json"
RUNTIME_ARCHIVE_NAME = "runtime-release-authority.json"
GIT_BIN = "/usr/bin/git"
LAUNCHCTL_BIN = "/bin/launchctl"
PS_BIN = "/bin/ps"
GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}


def _stat_fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_uid, value.st_nlink)


def _account_home(injected=None):
    try:
        value = os.fspath(injected) if injected is not None else pwd.getpwuid(os.getuid()).pw_dir
        if not os.path.isabs(value) or os.path.normpath(value) != value:
            raise DeploymentError("account home is not canonical absolute", EXIT_UNSAFE)
        observed = os.stat(value, follow_symlinks=False)
    except DeploymentError:
        raise
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise DeploymentError("account home binding failed", EXIT_UNSAFE) from error
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid() or
            stat.S_IMODE(observed.st_mode) & 0o022):
        raise DeploymentError("account home is unsafe", EXIT_UNSAFE)
    return value


def _read_regular_fd(fd, named_stat, *, expected_mode=None, max_bytes=MAX_FILE_BYTES,
                     failure_code=EXIT_UNSAFE, allowed_nlinks=(1,), oversize_code=None):
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
            before.st_nlink not in allowed_nlinks or
            (expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode) or
            _stat_fingerprint(before) != _stat_fingerprint(named_stat)):
        raise DeploymentError("unsafe exact file", failure_code)
    if before.st_size > max_bytes:
        raise DeploymentError("exact file exceeds resource limit", oversize_code or failure_code)
    chunks = []; total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk: break
        total += len(chunk)
        if total > max_bytes: raise DeploymentError("exact file exceeds resource limit", oversize_code or failure_code)
        chunks.append(chunk)
    after = os.fstat(fd)
    if _stat_fingerprint(before) != _stat_fingerprint(after):
        raise DeploymentError("exact file changed during read", failure_code)
    return b"".join(chunks), stat.S_IMODE(after.st_mode), _stat_fingerprint(after)


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
    def repo_file_at_commit(self, repo_root, commit, relative_path): raise DeploymentError("repository commit file inspector is required", EXIT_PROTOCOL)
    def repo_commit_proven(self, repo_root, commit): raise DeploymentError("repository commit proof inspector is required", EXIT_PROTOCOL)
    def main_state(self, plist_policy): raise DeploymentError("launchd inspector is required", EXIT_PROTOCOL)
    def process_scan(self): raise DeploymentError("process inspector is required", EXIT_PROTOCOL)
    def dependent_state(self, consumer_policy): raise DeploymentError("dependent inspector is required", EXIT_PROTOCOL)
    def migration_dependent_state(self, consumer_policy): raise DeploymentError("migration dependent inspector is required", EXIT_PROTOCOL)


class ProductionProcessInspector(ProcessInspector):
    """Read-only local Git/launchctl/ps observer; every subprocess uses argv+timeout."""
    def __init__(self, *, home=None):
        self.home = _account_home(home)
        for binary in (GIT_BIN, LAUNCHCTL_BIN, PS_BIN):
            try: observed = os.stat(binary, follow_symlinks=False)
            except OSError as error: raise DeploymentError("trusted observer binary is unavailable", EXIT_PROTOCOL) from error
            if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or
                    stat.S_IMODE(observed.st_mode) & 0o022 or not os.access(binary, os.X_OK)):
                raise DeploymentError("trusted observer binary is unsafe", EXIT_PROTOCOL)
    def _environment(self, extra=None, *, git=False):
        value = {"HOME": self.home, "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
        if git:
            value.update(GIT_ENVIRONMENT)
        elif extra:
            value.update(extra)
        return value
    def _resolve_home(self, value):
        value = os.fspath(value)
        if value == "~": return self.home
        if value.startswith("~/"):
            parts = value[2:].split("/")
            if any(part in ("", ".", "..") for part in parts): raise DeploymentError("home-relative path is unsafe", EXIT_PROTOCOL)
            return os.path.join(self.home, *parts)
        return value
    def _run(self, argv, accepted=(0,), env=None):
        if (type(argv) not in (list, tuple) or not argv or argv[0] not in (GIT_BIN, LAUNCHCTL_BIN, PS_BIN)):
            raise DeploymentError("observer command is outside frozen binary inventory", EXIT_PROTOCOL)
        try: result = subprocess.run(list(argv), shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5, check=False, env=self._environment(env, git=argv[0] == GIT_BIN))
        except (OSError, subprocess.SubprocessError) as error: raise DeploymentError("read-only process inspector command failed", EXIT_PROTOCOL) from error
        if result.returncode not in accepted or len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 1024 * 1024: raise DeploymentError("read-only process inspector response failed", EXIT_PROTOCOL)
        return result
    def _run_bytes(self, argv, accepted=(0,), env=None, max_stdout=MAX_FILE_BYTES):
        if (type(argv) not in (list, tuple) or not argv or argv[0] != GIT_BIN):
            raise DeploymentError("binary observer command is outside frozen inventory", EXIT_PROTOCOL)
        try: result = subprocess.run(list(argv), shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=False, timeout=5, check=False, env=self._environment(env, git=True))
        except (OSError, subprocess.SubprocessError) as error: raise DeploymentError("binary repository inspector command failed", EXIT_PROTOCOL) from error
        if result.returncode not in accepted or len(result.stdout) > max_stdout or len(result.stderr) > 1024 * 1024:
            raise DeploymentError("binary repository inspector response failed", EXIT_PROTOCOL)
        return result
    def repo_state(self, repo_root):
        root = os.path.abspath(os.fspath(repo_root))
        prefix = [GIT_BIN, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", root]
        status = self._run([*prefix, "status", "--porcelain=v1", "--untracked-files=all"]).stdout
        ref = self._run([*prefix, "symbolic-ref", "--quiet", "HEAD"]).stdout.strip()
        commit = self._run([*prefix, "rev-parse", "--verify", "HEAD^{commit}"]).stdout.strip()
        proof = self._run([*prefix, "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"], accepted=(0, 1)).returncode == 0
        return {"clean": status == "", "ref": ref, "commit": commit, "merge_proven": proof}
    def repo_file_at_commit(self, repo_root, commit, relative_path):
        if (type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit) is None or
                type(relative_path) is not str or relative_path.startswith("/") or "\\" in relative_path or
                any(part in ("", ".", "..") for part in relative_path.split("/"))):
            raise DeploymentError("repository commit file request is unsafe", EXIT_PROTOCOL)
        root = os.path.abspath(os.fspath(repo_root))
        prefix = [GIT_BIN, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", root]
        tree = self._run([*prefix, "ls-tree", commit, "--", relative_path]).stdout.strip().splitlines()
        if len(tree) != 1: return {"present": False, "mode": None, "oid": None, "bytes": None}
        match = re.fullmatch(r"([0-7]{6}) blob ([0-9a-f]{40}|[0-9a-f]{64})\t(.+)", tree[0])
        if match is None or match.group(3) != relative_path: raise DeploymentError("repository commit tree response differs", EXIT_PROTOCOL)
        raw = self._run_bytes([*prefix, "cat-file", "blob", match.group(2)]).stdout
        return {"present": True, "mode": match.group(1), "oid": match.group(2), "bytes": raw}
    def repo_commit_proven(self, repo_root, commit):
        if type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit) is None:
            raise DeploymentError("repository commit proof request is invalid", EXIT_PROTOCOL)
        root = os.path.abspath(os.fspath(repo_root))
        prefix = [GIT_BIN, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", root]
        return self._run([*prefix, "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"], accepted=(0, 1)).returncode == 0
    def process_scan(self):
        output = self._run([PS_BIN, "-axo", "pid=,command="]).stdout; rows = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped: continue
            pieces = stripped.split(None, 1)
            if len(pieces) != 2 or not pieces[0].isdigit(): raise DeploymentError("ps output is not pid+argv", EXIT_PROTOCOL)
            try: argv = shlex.split(pieces[1], posix=True)
            except ValueError as error: raise DeploymentError("ps argv parsing failed", EXIT_PROTOCOL) from error
            if not argv or any(type(value) is not str or not value for value in argv): raise DeploymentError("ps argv is invalid", EXIT_PROTOCOL)
            rows.append({"argv": argv, "raw": pieces[1]})
        return rows
    def _plist(self, label, exact_keys=None, environment_keys=None, exact_value=None):
        if type(label) is not str or re.fullmatch(r"[A-Za-z0-9._-]+", label) is None:
            raise DeploymentError("launchd label is invalid", EXIT_PROTOCOL)
        if label == manifest.EXACT_MAIN_PLIST["label"]: expected_mode = 0o600
        elif label in {dependent_label for _, dependent_label in manifest.EXACT_DEPENDENTS}: expected_mode = 0o644
        else: raise DeploymentError("launchd label is outside exact inventory", EXIT_PROTOCOL)
        bindings = []; fd = None; name = f"{label}.plist"
        try:
            bindings, directories_before = self._open_home_directory_chain(["Library", "LaunchAgents"])
            parent_fd = bindings[-1][0]
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
            before = os.fstat(fd); named_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            before_fp = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode, before.st_uid, before.st_nlink)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or
                    stat.S_IMODE(before.st_mode) != expected_mode or (before.st_dev, before.st_ino) != (named_before.st_dev, named_before.st_ino) or
                    before.st_size > 1024 * 1024):
                raise DeploymentError("launchd plist metadata is unsafe", EXIT_PROTOCOL)
            chunks = []; total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk: break
                total += len(chunk)
                if total > 1024 * 1024: raise DeploymentError("launchd plist exceeds resource limit", EXIT_PROTOCOL)
                chunks.append(chunk)
            raw = b"".join(chunks); after = os.fstat(fd); named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            after_fp = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_uid, after.st_nlink)
            directories_after = self._validate_home_directory_chain(bindings)
            if (before_fp != after_fp or before_fp[:2] != (named_after.st_dev, named_after.st_ino) or
                    directories_before != directories_after):
                raise DeploymentError("launchd plist changed during observation", EXIT_PROTOCOL)
            value = plistlib.loads(raw)
        except DeploymentError: raise
        except Exception as error: raise DeploymentError("dependent plist read/parse failed", EXIT_PROTOCOL) from error
        finally:
            if fd is not None: os.close(fd)
            self._close_home_directory_chain(bindings)
        if type(value) is not dict or (exact_keys is not None and set(value) != set(exact_keys)):
            raise DeploymentError("plist exact key inventory differs", EXIT_PROTOCOL)
        if exact_value is not None and value != exact_value:
            raise DeploymentError("dependent plist semantic contract differs", EXIT_PROTOCOL)
        if environment_keys is not None:
            environment = value.get("EnvironmentVariables")
            if type(environment) is not dict or set(environment) != set(environment_keys) or any(type(key) is not str or type(item) is not str for key, item in environment.items()):
                raise DeploymentError("plist environment inventory differs", EXIT_PROTOCOL)
        argv = value.get("ProgramArguments")
        if type(argv) is not list or not argv or any(type(x) is not str or not x for x in argv): raise DeploymentError("plist ProgramArguments is invalid", EXIT_PROTOCOL)
        return raw, argv
    def _loaded_launch_config(self, output, label=None, plist_contract=None):
        if type(output) is not str or not output or "\x00" in output:
            raise DeploymentError("loaded launchctl output is invalid", EXIT_PROTOCOL)
        lines = output.splitlines(); paths = []; programs = []; blocks = []
        for index, line in enumerate(lines):
            path = re.fullmatch(r"[ \t]*path[ \t]*=[ \t]*(\S(?:.*\S)?)[ \t]*", line)
            if path is not None: paths.append(path.group(1))
            program = re.fullmatch(r"[ \t]*program[ \t]*=[ \t]*(\S(?:.*\S)?)[ \t]*", line)
            if program is not None: programs.append(program.group(1))
            opening = re.fullmatch(r"([ \t]*)arguments[ \t]*=[ \t]*\{[ \t]*", line)
            if opening is None: continue
            prefix = opening.group(1); arguments = []; closed = False
            for child in lines[index + 1:]:
                if child == prefix + "}":
                    closed = True
                    break
                match = re.fullmatch(r"([ \t]+)(.*\S)[ \t]*", child)
                if (match is None or not match.group(1).startswith(prefix) or
                        len(match.group(1)) <= len(prefix)):
                    raise DeploymentError("loaded launchctl arguments are malformed", EXIT_PROTOCOL)
                arguments.append(match.group(2))
            if not closed: raise DeploymentError("loaded launchctl arguments are unterminated", EXIT_PROTOCOL)
            blocks.append(arguments)
        if len(paths) != 1 or len(programs) != 1 or len(blocks) != 1:
            raise DeploymentError("loaded launchctl argv inventory differs", EXIT_PROTOCOL)
        argv = _validated_argv(blocks[0], "loaded launchctl argv")
        if programs[0] != argv[0]:
            raise DeploymentError("loaded launchctl program/argv mismatch", EXIT_PROTOCOL)
        if plist_contract is not None:
            stdout_paths = re.findall(r"(?m)^[ \t]*stdout path[ \t]*=[ \t]*(\S(?:.*\S)?)[ \t]*$", output)
            stderr_paths = re.findall(r"(?m)^[ \t]*stderr path[ \t]*=[ \t]*(\S(?:.*\S)?)[ \t]*$", output)
            properties = re.findall(r"(?m)^[ \t]*properties[ \t]*=[ \t]*(.*\S)[ \t]*$", output)
            intervals = re.findall(r"(?m)^[ \t]*run interval[ \t]*=[ \t]*([0-9]+) seconds[ \t]*$", output)
            property_set = set() if len(properties) != 1 else {part.strip() for part in properties[0].split("|")}
            if (stdout_paths != [plist_contract["StandardOutPath"]] or stderr_paths != [plist_contract["StandardErrorPath"]] or
                    len(properties) != 1 or label not in manifest.EXACT_LOADED_PROPERTIES or
                    property_set != manifest.EXACT_LOADED_PROPERTIES[label] or
                    (("runatload" in property_set) is not plist_contract["RunAtLoad"])):
                raise DeploymentError("loaded launchctl paths/properties differ", EXIT_CONFLICT)
            if re.search(r"(?mi)^[ \t]*(?:working directory|queue directories|watch paths)[ \t]*=", output):
                raise DeploymentError("loaded launchctl contains unreviewed execution/trigger state", EXIT_CONFLICT)
            expected_interval = plist_contract.get("StartInterval")
            if intervals != ([] if expected_interval is None else [str(expected_interval)]):
                raise DeploymentError("loaded launchctl interval differs", EXIT_CONFLICT)
            descriptor_matches = re.findall(r"descriptor[ \t]*=[ \t]*\{([^{}]*)\}", output, flags=re.S)
            expected_calendar = plist_contract.get("StartCalendarInterval")
            if expected_calendar is None:
                if descriptor_matches: raise DeploymentError("loaded launchctl calendar differs", EXIT_CONFLICT)
            else:
                if len(descriptor_matches) != 1: raise DeploymentError("loaded launchctl calendar differs", EXIT_CONFLICT)
                pairs = re.findall(r'"([^"\n]+)"[ \t]*=>[ \t]*([^\s}]+)', descriptor_matches[0])
                try: descriptor = {key: int(value) for key, value in pairs}
                except ValueError as error: raise DeploymentError("loaded launchctl calendar differs", EXIT_CONFLICT) from error
                if len(pairs) != len(descriptor) or descriptor != expected_calendar:
                    raise DeploymentError("loaded launchctl calendar differs", EXIT_CONFLICT)
            environment_blocks = re.findall(r"(?m)^[ \t]*environment[ \t]*=[ \t]*\{\n(.*?)^[ \t]*\}", output, flags=re.S)
            if len(environment_blocks) != 1: raise DeploymentError("loaded launchctl environment differs", EXIT_CONFLICT)
            pairs = re.findall(r"(?m)^[ \t]+([^\s=]+)[ \t]*=>[ \t]*(.*\S)[ \t]*$", environment_blocks[0])
            environment = {key: value for key, value in pairs if key not in ("OSLogRateLimit", "XPC_SERVICE_NAME")}
            if len(pairs) != len({key for key, _ in pairs}) or environment != plist_contract.get("EnvironmentVariables", {}):
                raise DeploymentError("loaded launchctl environment differs", EXIT_CONFLICT)
            if label is not None and dict(pairs).get("XPC_SERVICE_NAME") != label:
                raise DeploymentError("loaded launchctl service identity differs", EXIT_CONFLICT)
        return paths[0], argv
    def _launch(self, label, configured, process_match_tokens, plist_contract=None):
        domain = f"gui/{os.getuid()}"; printed = self._run([LAUNCHCTL_BIN, "print", f"{domain}/{label}"], accepted=(0, 113))
        disabled = self._run([LAUNCHCTL_BIN, "print-disabled", domain]).stdout
        loaded = printed.returncode == 0
        match = re.search(r'"' + re.escape(label) + r'"\s*=>\s*(true|false|enabled|disabled)', disabled)
        if match is None and not loaded: raise DeploymentError("launchctl enabled state is unavailable", EXIT_PROTOCOL)
        enabled = True if match is None else match.group(1) in ("false", "enabled")
        if loaded:
            loaded_path, loaded_argv = self._loaded_launch_config(printed.stdout, label, plist_contract)
            expected_path = os.path.join(self.home, "Library", "LaunchAgents", f"{label}.plist")
            if loaded_path != expected_path or loaded_argv != configured:
                raise DeploymentError("loaded launchctl path/argv differs from plist", EXIT_CONFLICT)
        pid_match = re.search(r"(?:^|\n)\s*pid\s*=\s*(\d+)", printed.stdout); pid = None if pid_match is None else int(pid_match.group(1))
        identities = [_text_identity(token) for token in process_match_tokens]
        running = [observation["argv"] for observation in _validated_process_scan(self.process_scan())
                   if any((_raw_command_references(identity, observation) if index == 0 else
                           _argv_references(identity, observation["argv"])) for index, identity in enumerate(identities))]
        if len(running) > 1: raise DeploymentError("multiple matching processes found", EXIT_PROTOCOL)
        return {"enabled": enabled, "loaded": loaded, "pid": pid, "configured_argv": configured, "runtime_argv": [] if not running else running[0]}
    def main_state(self, plist_policy):
        label = plist_policy["label"]
        exact_plist = manifest.exact_main_plist_value(self.home)
        raw, argv = self._plist(label, plist_policy["plist_keys"], plist_policy["environment_variable_keys"], exact_plist); state = self._launch(label, argv, [self._resolve_home(plist_policy["entrypoint"])], exact_plist)
        return {"loaded": state["loaded"], "enabled": state["enabled"], "pid": state["pid"], "argv": state["configured_argv"]}
    def _home_parts(self, path):
        if type(path) is not str or not path.startswith("~/"):
            raise DeploymentError("dependent path is not home-anchored", EXIT_PROTOCOL)
        parts = path[2:].split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise DeploymentError("dependent path is unsafe", EXIT_PROTOCOL)
        return parts
    def _validate_home_directory_chain(self, bindings):
        observations = []
        try:
            for index, (fd, component, expected_fp) in enumerate(bindings):
                current = os.fstat(fd)
                named = os.stat(self.home, follow_symlinks=False) if index == 0 else os.stat(component, dir_fd=bindings[index - 1][0], follow_symlinks=False)
                current_fp = (current.st_dev, current.st_ino)
                if (current_fp != expected_fp or current_fp != (named.st_dev, named.st_ino) or
                        not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) & 0o022):
                    raise DeploymentError("dependent directory chain is unsafe", EXIT_PROTOCOL)
                observations.append((current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns, current.st_mode))
            return tuple(observations)
        except DeploymentError: raise
        except OSError as error: raise DeploymentError("dependent directory chain changed", EXIT_PROTOCOL) from error
    def _open_home_directory_chain(self, parts):
        bindings = []
        try:
            current = os.open(self.home, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            bindings.append((current, None, None)); anchor = os.fstat(current); bindings[-1] = (current, None, (anchor.st_dev, anchor.st_ino))
            for component in parts:
                child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=current)
                bindings.append((child, component, None)); child_st = os.fstat(child); bindings[-1] = (child, component, (child_st.st_dev, child_st.st_ino)); current = child
            observations = self._validate_home_directory_chain(bindings)
            return bindings, observations
        except BaseException:
            for fd, _, _ in reversed(bindings): os.close(fd)
            raise
    @staticmethod
    def _close_home_directory_chain(bindings):
        for fd, _, _ in reversed(bindings): os.close(fd)
    def _fixed_source_bytes(self, path, expected_mode):
        """Read one source through a retained same-UID, no-follow directory chain."""
        if type(expected_mode) is not str or re.fullmatch(r"0[0-7]{3}", expected_mode) is None:
            raise DeploymentError("dependent source mode contract is invalid", EXIT_PROTOCOL)
        parts = self._home_parts(path); bindings = []; fd = None
        try:
            bindings, directories_before = self._open_home_directory_chain(parts[:-1]); parent_fd = bindings[-1][0]; name = parts[-1]
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            before, named = os.fstat(fd), os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or
                    stat.S_IMODE(before.st_mode) != int(expected_mode, 8) or
                    (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)):
                raise DeploymentError("dependent source path is unsafe", EXIT_PROTOCOL)
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk: break
                total += len(chunk)
                if total > 64 * 1024 * 1024: raise DeploymentError("dependent source exceeds resource limit", EXIT_PROTOCOL)
                chunks.append(chunk)
            after, again = os.fstat(fd), os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            directories_after = self._validate_home_directory_chain(bindings)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode) or
                    (after.st_dev, after.st_ino) != (again.st_dev, again.st_ino) or directories_before != directories_after):
                raise DeploymentError("dependent source changed during read", EXIT_PROTOCOL)
            file_fingerprint = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode)
            return b"".join(chunks), (directories_after, file_fingerprint)
        except DeploymentError: raise
        except OSError as error: raise DeploymentError("dependent source read failed", EXIT_PROTOCOL) from error
        finally:
            if fd is not None: os.close(fd)
            self._close_home_directory_chain(bindings)
    def _selected_release(self, consumer_policy):
        selected = consumer_policy["selected_release"]
        if (selected["current_path"] != selected["root"] + "/current" or
                selected["release_path"] != selected["root"] + "/" + selected["target"]):
            raise DeploymentError("dependent selected release relation differs", EXIT_PROTOCOL)
        current_parts = self._home_parts(selected["current_path"]); release_parts = self._home_parts(selected["release_path"])
        current_bindings = release_bindings = []
        try:
            current_bindings, current_directories = self._open_home_directory_chain(current_parts[:-1]); current_parent = current_bindings[-1][0]; current_name = current_parts[-1]
            before = os.stat(current_name, dir_fd=current_parent, follow_symlinks=False)
            if not stat.S_ISLNK(before.st_mode) or before.st_uid != os.getuid() or os.readlink(current_name, dir_fd=current_parent) != selected["target"]:
                raise DeploymentError("dependent current selector differs", EXIT_PROTOCOL)
            release_bindings, release_directories = self._open_home_directory_chain(release_parts)
            current_after = os.stat(current_name, dir_fd=current_parent, follow_symlinks=False)
            current_directories_after = self._validate_home_directory_chain(current_bindings)
            release_directories_after = self._validate_home_directory_chain(release_bindings)
            current_fp = (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_mode)
            current_after_fp = (current_after.st_dev, current_after.st_ino, current_after.st_mtime_ns, current_after.st_ctime_ns, current_after.st_mode)
            if (current_fp != current_after_fp or current_directories != current_directories_after or release_directories != release_directories_after):
                raise DeploymentError("dependent selected release changed during observation", EXIT_PROTOCOL)
            return current_fp, current_directories_after, release_directories_after
        except DeploymentError: raise
        except OSError as error: raise DeploymentError("dependent selected release unavailable", EXIT_PROTOCOL) from error
        finally:
            self._close_home_directory_chain(release_bindings); self._close_home_directory_chain(current_bindings)
    def _dependent_snapshot(self, consumer_policy):
        selector_before = self._selected_release(consumer_policy)
        source_observations = {item["role"]: self._fixed_source_bytes(item["path"], item["mode"]) for item in consumer_policy["source_files"]}
        source_bytes = {role: observation[0] for role, observation in source_observations.items()}
        selector_after = self._selected_release(consumer_policy)
        if selector_before != selector_after: raise DeploymentError("dependent current selector changed during observation", EXIT_PROTOCOL)
        sources = [{"role": item["role"], "path": item["path"], "mode": item["mode"], "sha256": hashlib.sha256(source_bytes[item["role"]]).hexdigest()} for item in consumer_policy["source_files"]]
        reviewed_helper_sha256 = manifest.EXACT_DEPENDENT_HELPER_SHA256[consumer_policy["name"]]
        # The contract comes only from an exact reviewed helper digest.  Text
        # in comments or dead code cannot spoof this evidence.
        contract = (manifest.DEPENDENT_CREDENTIAL_CONTRACT if
                    reviewed_helper_sha256 is not None and sources[2]["sha256"] == reviewed_helper_sha256 else None)
        binding = _sha(_canonical({"selected_release": consumer_policy["selected_release"], "sources": sources}))
        source_fingerprints = tuple((item["role"], source_observations[item["role"]][1]) for item in consumer_policy["source_files"])
        return sources, contract, binding, (selector_after, source_fingerprints)
    def dependent_state(self, consumer_policy):
        name = consumer_policy["name"]
        labels = dict(manifest.EXACT_DEPENDENTS)
        if name not in labels: raise DeploymentError("unknown dependent consumer", EXIT_PROTOCOL)
        label = labels[name]; exact_plist = manifest.EXACT_DEPENDENT_PLISTS[name]
        raw, argv = self._plist(label, exact_value=exact_plist)
        first = self._dependent_snapshot(consumer_policy)
        # A complete second observation makes the plist/current/source chain a
        # compare-and-swap gate, rather than three unrelated point-in-time reads.
        raw_again, argv_again = self._plist(label, exact_value=exact_plist)
        second = self._dependent_snapshot(consumer_policy)
        if raw_again != raw or argv_again != argv or second != first:
            raise DeploymentError("dependent observation changed during gate", EXIT_PROTOCOL)
        sources, contract, binding, _selector_fingerprint = first
        selected = dict(consumer_policy["selected_release"])
        return {"source_files": sources, "selected_release": selected, "plist_sha256": _sha(raw), "credential_contract": contract, "binding": binding, "labels": {label: self._launch(label, argv, consumer_policy["process_match_tokens"], exact_plist)}}
    def migration_dependent_state(self, consumer_policy):
        name = consumer_policy["name"]
        labels = dict(manifest.EXACT_DEPENDENTS)
        if name not in labels: raise DeploymentError("unknown migration dependent", EXIT_PROTOCOL)
        label = labels[name]; exact_plist = manifest.EXACT_DEPENDENT_PLISTS[name]
        raw, argv = self._plist(label, exact_value=exact_plist)
        launch = self._launch(label, argv, manifest.EXACT_DEPENDENT_MIGRATION_PROCESS_TOKENS[name], exact_plist)
        return {"plist_sha256": _sha(raw), "label": label, "launch": launch}


class Ops:
    """Same-UID local filesystem boundary. A mapper is useful for fake tests."""
    def __init__(self, mapper=None):
        self.mapper = mapper
        self.home = _account_home(mapper("~") if mapper is not None else None)
    def resolve(self, path):
        value = os.fspath(path)
        if self.mapper: return os.fspath(self.mapper(value))
        if value == "~": return self.home
        if value.startswith("~/"):
            parts = value[2:].split("/")
            if any(part in ("", ".", "..") for part in parts): raise DeploymentError("home-relative path is unsafe", EXIT_UNSAFE)
            return os.path.join(self.home, *parts)
        return value
    def exact_state(self, path, *, expected_mode=None, max_bytes=MAX_FILE_BYTES,
                    missing_ok=False, failure_code=EXIT_UNSAFE):
        actual = self.resolve(path)
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try: fd = os.open(actual, flags)
        except FileNotFoundError as error:
            if missing_ok: return False, None, None
            raise DeploymentError("required file is missing", EXIT_MISSING) from error
        except OSError as error: raise DeploymentError("exact file open failed", failure_code) from error
        try:
            before_named = os.stat(actual, follow_symlinks=False)
            data, mode, fingerprint = _read_regular_fd(fd, before_named, expected_mode=expected_mode,
                    max_bytes=max_bytes, failure_code=failure_code)
            named_after = os.stat(actual, follow_symlinks=False)
            if fingerprint != _stat_fingerprint(named_after):
                raise DeploymentError("exact file name changed during read", failure_code)
            return True, data, mode
        except DeploymentError: raise
        except OSError as error: raise DeploymentError("exact file observation failed", failure_code) from error
        finally: os.close(fd)
    def read_bytes(self, path): return self.exact_state(path)[1]
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
    observations = []
    for row in value:
        if type(row) is list:
            argv = _validated_argv(row); raw = " ".join(argv)
        elif type(row) is dict and set(row) == {"argv", "raw"}:
            argv = _validated_argv(row["argv"]); raw = row["raw"]
        else:
            raise DeploymentError("process scan row protocol mismatch", EXIT_PROTOCOL)
        if type(raw) is not str or not raw or len(raw) > 1024 * 1024 or "\x00" in raw or "\n" in raw or "\r" in raw:
            raise DeploymentError("process raw command protocol mismatch", EXIT_PROTOCOL)
        observations.append({"argv": argv, "raw": raw})
    return observations


def _raw_command_references(identity, observation):
    if type(identity) is not str or not identity or type(observation) is not dict or set(observation) != {"argv", "raw"}:
        raise DeploymentError("raw process identity protocol mismatch", EXIT_PROTOCOL)
    return identity in observation["raw"]


def _argv_references(executable, argv):
    if type(executable) is not str or not executable:
        raise DeploymentError("fixed executable protocol mismatch", EXIT_PROTOCOL)
    _validated_argv(argv)
    return any(executable in token for token in argv)


def _text_identity(value, resolver=None):
    if type(value) is not str or not value or value == "/bin/bash":
        raise DeploymentError("process identity protocol mismatch", EXIT_PROTOCOL)
    return resolver(value) if resolver is not None else value


def _source_blobs(policy, runtime, repo_root, ops):
    blobs = {}
    for item in runtime["bundle"]:
        path = os.path.join(os.fspath(repo_root), item["source"])
        _, data, mode = ops.exact_state(path, expected_mode=int(item["mode"], 8))
        if mode != int(item["mode"], 8): raise DeploymentError("unsafe source owner/mode/link/type", EXIT_UNSAFE)
        if len(data) != item["size"] or _sha(data) != item["sha256"]: raise DeploymentError("source hash/size mismatch", EXIT_INTEGRITY)
        blobs[item["source"]] = data
    manifest.verify_runtime_release(policy, runtime, blobs)
    return blobs


def _check_repository(runtime, repo_root, inspector):
    state = inspector.repo_state(repo_root)
    if type(state) is not dict or set(state) != {"clean", "ref", "commit", "merge_proven"}: raise DeploymentError("repository inspector protocol mismatch", EXIT_PROTOCOL)
    if state["clean"] is not True or state["ref"] != runtime["repository"]["ref"] or state["commit"] != runtime["repository"]["commit"] or state["merge_proven"] is not True: raise DeploymentError("repository ref/commit/clean/local-merge-proof gate failed", EXIT_INTEGRITY)


def _check_repository_policy(policy, runtime, repo_root, inspector, ops):
    relative = runtime["policy"]["path"]
    expected = manifest.canonical_source_policy_bytes(policy)
    path = os.path.join(os.fspath(repo_root), relative)
    _, observed, mode = ops.exact_state(path, expected_mode=0o644)
    try: observed_policy = manifest.parse_source_policy(observed)
    except manifest.ManifestError as error: raise DeploymentError("repository policy file is invalid", EXIT_INTEGRITY) from error
    state = inspector.repo_file_at_commit(repo_root, runtime["repository"]["commit"], relative)
    if (type(state) is not dict or set(state) != {"present", "mode", "oid", "bytes"} or
            state["present"] is not True or state["mode"] != "100644" or type(state["oid"]) is not str or
            state["bytes"] != observed or manifest.canonical_source_policy_bytes(observed_policy) != expected or
            _sha(expected) != runtime["policy"]["sha256"] or mode != 0o644):
        raise DeploymentError("repository policy authority gate failed", EXIT_INTEGRITY)


def _check_repository_bundle(runtime, repo_root, inspector, blobs):
    for item in runtime["bundle"]:
        state = inspector.repo_file_at_commit(repo_root, runtime["repository"]["commit"], item["source"])
        if (type(state) is not dict or set(state) != {"present", "mode", "oid", "bytes"} or
                state["present"] is not True or state["mode"] != "100644" or type(state["oid"]) is not str or
                state["bytes"] != blobs[item["source"]] or len(state["bytes"]) != item["size"] or _sha(state["bytes"]) != item["sha256"]):
            raise DeploymentError("repository bundle commit authority gate failed", EXIT_INTEGRITY)


def _check_archived_runtime_repository(archived_policy, runtime, repo_root, inspector):
    if inspector.repo_commit_proven(repo_root, runtime["repository"]["commit"]) is not True:
        raise DeploymentError("archived runtime commit lacks merge proof", EXIT_INTEGRITY)
    policy_state = inspector.repo_file_at_commit(repo_root, runtime["repository"]["commit"], runtime["policy"]["path"])
    if (type(policy_state) is not dict or set(policy_state) != {"present", "mode", "oid", "bytes"} or
            policy_state["present"] is not True or policy_state["mode"] != "100644"):
        raise DeploymentError("archived runtime policy Git authority is unavailable", EXIT_INTEGRITY)
    try: committed_policy = manifest.parse_source_policy(policy_state["bytes"])
    except manifest.ManifestError as error: raise DeploymentError("archived runtime committed policy is invalid", EXIT_INTEGRITY) from error
    expected_policy = manifest.canonical_source_policy_bytes(archived_policy)
    if manifest.canonical_source_policy_bytes(committed_policy) != expected_policy or _sha(expected_policy) != runtime["policy"]["sha256"]:
        raise DeploymentError("archived runtime committed policy differs", EXIT_INTEGRITY)
    for item in runtime["bundle"]:
        state = inspector.repo_file_at_commit(repo_root, runtime["repository"]["commit"], item["source"])
        if (type(state) is not dict or set(state) != {"present", "mode", "oid", "bytes"} or state["present"] is not True or
                state["mode"] != "100644" or len(state["bytes"]) != item["size"] or _sha(state["bytes"]) != item["sha256"]):
            raise DeploymentError("archived runtime bundle Git authority differs", EXIT_INTEGRITY)


def _check_source_policy_repository(policy, repo_root, inspector, ops):
    state = inspector.repo_state(repo_root)
    if (type(state) is not dict or set(state) != {"clean", "ref", "commit", "merge_proven"} or
            state["clean"] is not True or state["ref"] != policy["repository"]["required_ref"] or state["merge_proven"] is not True or
            type(state["commit"]) is not str or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", state["commit"]) is None):
        raise DeploymentError("repository authority gate failed", EXIT_INTEGRITY)
    relative = policy["deployment"]["policy_path"]; expected = manifest.canonical_source_policy_bytes(policy)
    _, observed, mode = ops.exact_state(os.path.join(os.fspath(repo_root), relative), expected_mode=0o644)
    try: observed_policy = manifest.parse_source_policy(observed)
    except manifest.ManifestError as error: raise DeploymentError("repository source policy is invalid", EXIT_INTEGRITY) from error
    authority = inspector.repo_file_at_commit(repo_root, state["commit"], relative)
    if (type(authority) is not dict or set(authority) != {"present", "mode", "oid", "bytes"} or
            authority["present"] is not True or authority["mode"] != "100644" or authority["bytes"] != observed or
            manifest.canonical_source_policy_bytes(observed_policy) != expected or mode != 0o644):
        raise DeploymentError("repository source policy gate failed", EXIT_INTEGRITY)
    return state["commit"]


def _check_unresolved_dependents(policy):
    for item in policy["deployment"]["dependent_consumers"]:
        placeholder = "REQUIRED_AT_DEPLOY"
        if (item["unresolved"] or item["plist_sha256"] == placeholder or
                placeholder in item["configured_argv"] or placeholder in item["process_match_tokens"] or
                any(placeholder in (source["path"], source["sha256"]) for source in item["source_files"])):
            raise DeploymentError("dependent consumer inventory is unresolved", EXIT_CONFLICT)


def _check_canary_interpreter():
    # The installed outbox uses dataclass(slots=True), introduced in Python
    # 3.10. Refuse before lock, secret, journal, or live-file writes.
    if tuple(sys.version_info[:2]) < (3, 10):
        raise DeploymentError("controlled canary requires Python 3.10 or later", EXIT_PROTOCOL)


def _check_production_python(policy, inspector):
    if not isinstance(inspector, ProductionProcessInspector): return
    flags = sys.flags
    if (getattr(flags, "isolated", 0) != 1 or getattr(flags, "safe_path", False) is not True or
            getattr(flags, "no_user_site", 0) != 1 or getattr(flags, "no_site", 0) != 1 or getattr(flags, "dont_write_bytecode", 0) != 1 or
            getattr(flags, "ignore_environment", 0) != 1):
        raise DeploymentError("production Python must run with -I -B", EXIT_PROTOCOL)
    if any(key.startswith("PYTHON") for key in os.environ):
        raise DeploymentError("production Python environment contains forbidden variables", EXIT_PROTOCOL)
    expected = {"HOME": inspector.home, "LANG": "C", "LC_ALL": "C", "PATH": "/opt/homebrew/bin:/usr/bin:/bin",
                "TMPDIR": os.path.join(inspector.home, ".spspy-code-backups", "tmp")}
    if any(os.environ.get(key) != value for key, value in expected.items()):
        raise DeploymentError("production Python environment differs from clean contract", EXIT_PROTOCOL)
    try:
        configured = os.stat(policy["deployment"]["plist"]["interpreter"])
        running = os.stat(sys.executable)
        temp = os.stat(expected["TMPDIR"], follow_symlinks=False)
    except OSError as error: raise DeploymentError("production Python binding is unavailable", EXIT_PROTOCOL) from error
    if ((configured.st_dev, configured.st_ino) != (running.st_dev, running.st_ino) or
            not stat.S_ISREG(running.st_mode) or running.st_uid != os.getuid() or running.st_nlink != 1 or stat.S_IMODE(running.st_mode) & 0o022 or
            not stat.S_ISDIR(temp.st_mode) or temp.st_uid != os.getuid() or stat.S_IMODE(temp.st_mode) != 0o700):
        raise DeploymentError("production Python executable/temp binding differs", EXIT_PROTOCOL)


def _check_dependents(policy, inspector, ops):
    _check_unresolved_dependents(policy)
    scanned = _validated_process_scan(inspector.process_scan())
    for item in policy["deployment"]["dependent_consumers"]:
        state = inspector.dependent_state(item)
        expected = {"source_files", "selected_release", "plist_sha256", "credential_contract", "binding", "labels"}
        if type(state) is not dict or set(state) != expected or type(state["labels"]) is not dict: raise DeploymentError("dependent inspector protocol mismatch", EXIT_PROTOCOL)
        if type(state["source_files"]) is not list or state["source_files"] != item["source_files"]:
            raise DeploymentError("dependent source inventory gate failed", EXIT_CONFLICT)
        if state["selected_release"] != item["selected_release"]:
            raise DeploymentError("dependent selected release gate failed", EXIT_CONFLICT)
        if state["credential_contract"] != item["credential_contract"]: raise DeploymentError("dependent credential contract gate failed", EXIT_CONFLICT)
        expected_binding = _sha(_canonical({"selected_release": item["selected_release"], "sources": item["source_files"]}))
        if state["binding"] != expected_binding: raise DeploymentError("dependent source binding gate failed", EXIT_CONFLICT)
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
            for index, identity in enumerate(item["process_match_tokens"]):
                fixed = _text_identity(identity, ops.resolve)
                if any((_raw_command_references(fixed, observation) if index == 0 else
                        _argv_references(fixed, observation["argv"])) for observation in scanned):
                    raise DeploymentError("dependent process wrapper is active", EXIT_CONFLICT)
            required = item["required_launch_state"]
            if value["enabled"] is not required["enabled"] or value["loaded"] is not required["loaded"]: raise DeploymentError("dependent launch state gate failed", EXIT_CONFLICT)


def _check_migration_dependents(policy, inspector):
    for item in policy["deployment"]["dependent_consumers"]:
        state = inspector.migration_dependent_state(item)
        if type(state) is not dict or set(state) != {"plist_sha256", "label", "launch"}:
            raise DeploymentError("migration dependent inspector protocol mismatch", EXIT_PROTOCOL)
        if item["plist_sha256"] == "REQUIRED_AT_DEPLOY" or state["plist_sha256"] != item["plist_sha256"] or state["label"] != item["labels"][0]:
            raise DeploymentError("migration dependent plist gate failed", EXIT_CONFLICT)
        launch = state["launch"]; required = item["required_launch_state"]
        if (type(launch) is not dict or set(launch) != {"enabled", "loaded", "pid", "configured_argv", "runtime_argv"} or
                launch["configured_argv"] != manifest.EXACT_DEPENDENT_CONFIGURED_ARGV[item["name"]] or
                launch["enabled"] is not required["enabled"] or launch["loaded"] is not required["loaded"] or
                launch["pid"] is not None or launch["runtime_argv"] != []):
            raise DeploymentError("migration dependent launch idle gate failed", EXIT_CONFLICT)


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
    if any(_argv_references(argv[plist["entrypoint_index"]], observation["argv"]) for observation in scan): raise DeploymentError("SP monitor process is active", EXIT_RETRY)


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


class _LiveScope:
    def __init__(self, bindings, home_path, live_path, allowed_targets, lock):
        self.bindings, self.home_path, self.live_path = bindings, home_path, live_path
        self.allowed_targets, self.lock = frozenset(allowed_targets), lock
        self.root_fd, self.scripts_fd = bindings[-2][0], bindings[-1][0]
    def fence(self, failure_code=EXIT_UNSAFE):
        _fence(self.lock)
        try:
            for index, (fd, component, expected) in enumerate(self.bindings):
                current = os.fstat(fd)
                named = os.stat(self.home_path, follow_symlinks=False) if index == 0 else os.stat(component, dir_fd=self.bindings[index - 1][0], follow_symlinks=False)
                observed = (current.st_dev, current.st_ino, current.st_mode, current.st_uid)
                if (observed != expected or (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino) or
                        not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) & 0o022):
                    raise DeploymentError("live directory chain binding changed", failure_code)
        except DeploymentError: raise
        except OSError: raise DeploymentError("live directory chain binding changed", failure_code) from None
        _fence(self.lock)
    def binding(self, target):
        if target not in self.allowed_targets:
            raise DeploymentError("live target is outside exact inventory", EXIT_PROTOCOL)
        parts = target.split("/")
        if len(parts) == 1 and parts[0] not in ("", ".", ".."):
            return self.root_fd, parts[0]
        if len(parts) == 2 and parts[0] == "scripts" and parts[1] not in ("", ".", ".."):
            return self.scripts_fd, parts[1]
        raise DeploymentError("live target shape is outside exact inventory", EXIT_PROTOCOL)
    def state(self, target, *, expected_mode=None, missing_ok=True, failure_code=EXIT_UNSAFE, max_bytes=MAX_FILE_BYTES):
        dfd, name = self.binding(target); fd = None
        try:
            self.fence(failure_code)
            try: fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
            except FileNotFoundError as error:
                self.fence(failure_code)
                if missing_ok: return False, None, None
                raise DeploymentError("live target is missing", EXIT_MISSING) from error
            named = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            data, mode, fingerprint = _read_regular_fd(fd, named, expected_mode=expected_mode,
                    max_bytes=max_bytes, failure_code=failure_code)
            named_after = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if fingerprint != _stat_fingerprint(named_after):
                raise DeploymentError("live target name changed during read", failure_code)
            self.fence(failure_code)
            return True, data, mode
        except DeploymentError: raise
        except OSError as error: raise DeploymentError("live target exact read failed", failure_code) from error
        finally:
            if fd is not None: os.close(fd)
    def absolute_path(self, target):
        self.binding(target)
        return os.path.join(self.live_path, *target.split("/"))
    def close(self):
        error = None
        if self.bindings:
            try: self.fence()
            except DeploymentError as caught: error = caught
            for fd, _, _ in reversed(self.bindings): os.close(fd)
            self.bindings = []; self.root_fd = self.scripts_fd = None
        if error is not None: raise error
    def __enter__(self): return self
    def __exit__(self, *unused): self.close()


def _open_live_scope(policy, ops, lock=None):
    configured = policy["deployment"]["live_root"]
    if type(configured) is not str or not configured.startswith("~/"):
        raise DeploymentError("live root is not home-anchored", EXIT_PROTOCOL)
    parts = configured[2:].split("/")
    if any(part in ("", ".", "..") for part in parts): raise DeploymentError("live root components are unsafe", EXIT_PROTOCOL)
    home_path = os.path.abspath(ops.resolve("~")); live_path = os.path.join(home_path, *parts)
    if os.path.abspath(ops.resolve(configured)) != live_path:
        raise DeploymentError("live root mapping is inconsistent", EXIT_UNSAFE)
    bindings = []
    try:
        current = os.open(home_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        home_st = os.fstat(current); bindings.append((current, None, (home_st.st_dev, home_st.st_ino, home_st.st_mode, home_st.st_uid)))
        for component in [*parts, "scripts"]:
            child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=current)
            child_st = os.fstat(child); bindings.append((child, component, (child_st.st_dev, child_st.st_ino, child_st.st_mode, child_st.st_uid))); current = child
        allowed = [item["target"] for item in policy["bundle"]] + [policy["deployment"]["runtime_manifest_target"]]
        scope = _LiveScope(bindings, home_path, live_path, allowed, lock); scope.fence(); return scope
    except FileNotFoundError as error:
        for fd, _, _ in reversed(bindings): os.close(fd)
        raise DeploymentError("required live directory chain is missing", EXIT_MISSING) from error
    except DeploymentError:
        for fd, _, _ in reversed(bindings): os.close(fd)
        raise
    except OSError as error:
        for fd, _, _ in reversed(bindings): os.close(fd)
        raise DeploymentError("live directory chain open failed", EXIT_UNSAFE) from error


def _check_live_baseline(policy, runtime, ops, live_scope, allow_journal_recovery=False, reject_same_release=False, lock=None, repo_root=None, inspector=None):
    present, live_bytes, mode = live_scope.state("run.py", expected_mode=0o644, missing_ok=False)
    if not present or mode != 0o644: raise DeploymentError("live entrypoint metadata is unsafe", EXIT_UNSAFE)
    digest = _sha(live_bytes)
    if allow_journal_recovery:
        return {"kind": "journal_recovery", "legacy_source": None, "prior_runtime": None, "prior_secret_sha256": None}
    runtime_target = policy["deployment"]["runtime_manifest_target"]
    if digest == policy["baseline"]["live_entrypoint_sha256"]:
        if live_scope.state(runtime_target)[0]: raise DeploymentError("baseline live entrypoint has an unexpected installed runtime", EXIT_CONFLICT)
        return {"kind": "legacy", "legacy_source": live_bytes, "prior_runtime": None, "prior_secret_sha256": None}
    if not live_scope.state(runtime_target)[0]: raise DeploymentError("nonbaseline live entrypoint lacks installed runtime provenance", EXIT_CONFLICT)
    try:
        prior_runtime = _runtime(live_scope.state(runtime_target, expected_mode=0o644, missing_ok=False)[1])
        prior_policy = _archived_policy_for_runtime(policy, prior_runtime, ops, lock)
        manifest.verify_runtime_release(prior_policy, prior_runtime)
        if repo_root is None or inspector is None: raise DeploymentError("prior runtime repository authority is unavailable", EXIT_CONFLICT)
        _check_archived_runtime_repository(prior_policy, prior_runtime, repo_root, inspector)
    except (manifest.ManifestError, DeploymentError) as error:
        raise DeploymentError("installed prior runtime provenance is invalid", EXIT_CONFLICT) from error
    prior_entry = next(item for item in prior_runtime["bundle"] if item["target"] == "run.py")
    if digest != prior_entry["sha256"]: raise DeploymentError("live entrypoint differs from installed prior runtime", EXIT_CONFLICT)
    try: _canary_bundle_bytes(prior_policy, prior_runtime, ops, live_scope)
    except DeploymentError as error: raise DeploymentError("installed prior bundle provenance is invalid", EXIT_CONFLICT) from error
    try:
        _, prior_journal = _read_journal(policy, prior_runtime["release_id"], ops, lock)
    except DeploymentError as error: raise DeploymentError("installed prior journal provenance is invalid", EXIT_CONFLICT) from error
    if prior_journal["status"] != "installed" or prior_journal["bundle_digest"] != prior_runtime["bundle_digest"]:
        raise DeploymentError("installed prior journal does not prove the live bundle", EXIT_CONFLICT)
    if reject_same_release and prior_runtime["release_id"] == runtime["release_id"]:
        raise DeploymentError("requested release is installed without its journal", EXIT_CONFLICT)
    return {"kind": "prior_runtime", "legacy_source": None, "prior_runtime": prior_runtime, "prior_secret_sha256": prior_journal["secret_sha256"]}


def verify_only(policy, runtime, repo_root, expected_release_id=None, *, ops=None, clock=None, process_inspector=None, _live_scope=None):
    """Perform every read-only gate; this function never acquires/creates a lock."""
    ops, clock, inspector = ops or Ops(), clock or Clock(), process_inspector or ProcessInspector()
    try: policy, runtime = _policy(policy), _runtime(runtime)
    except manifest.ManifestError as error: raise DeploymentError(str(error), error.exit_code) from error
    _check_production_python(policy, inspector)
    _check_canary_interpreter()
    _check_unresolved_dependents(policy)
    try: manifest.verify_runtime_release(policy, runtime)
    except manifest.ManifestError as error: raise DeploymentError(str(error), error.exit_code) from error
    if expected_release_id is not None and runtime["release_id"] != expected_release_id: raise DeploymentError("expected release id mismatch", EXIT_INTEGRITY)
    _check_repository(runtime, repo_root, inspector); _check_repository_policy(policy, runtime, repo_root, inspector, ops); blobs = _source_blobs(policy, runtime, repo_root, ops); _check_repository_bundle(runtime, repo_root, inspector, blobs)
    _check_window(policy, clock); _check_idle(policy, inspector, ops); _check_dependents(policy, inspector, ops)
    if _live_scope is None:
        with _open_live_scope(policy, ops) as live_scope: _check_live_baseline(policy, runtime, ops, live_scope, repo_root=repo_root, inspector=inspector)
    else:
        _check_live_baseline(policy, runtime, ops, _live_scope, repo_root=repo_root, inspector=inspector)
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
    return _validate_delivery_credentials(wanted["DINGTALK_WEBHOOK"][0], wanted["DINGTALK_SECRET"][0], EXIT_INTEGRITY, "live credential source")


def _validate_delivery_text(value, what, exit_code, context, *, reject_ascii_whitespace=False):
    if (type(value) is not str or not value or value != value.strip() or len(value) > CREDENTIAL_FIELD_MAX_CHARS or
            any(unicodedata.category(character) == "Cc" for character in value) or
            (reject_ascii_whitespace and any(character.isspace() and ord(character) < 128 for character in value))):
        raise DeploymentError(f"{context} {what} is invalid", exit_code)
    return value


def _validate_delivery_credentials(webhook, secret, exit_code, context):
    webhook = _validate_delivery_text(webhook, "webhook", exit_code, context, reject_ascii_whitespace=True)
    secret = _validate_delivery_text(secret, "secret", exit_code, context)
    try:
        parsed = urllib.parse.urlsplit(webhook)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2)
        hostname, port, username, password = parsed.hostname, parsed.port, parsed.username, parsed.password
    except (UnicodeError, ValueError):
        raise DeploymentError(f"{context} webhook is invalid", exit_code) from None
    if (not webhook.startswith("https://") or parsed.scheme != "https" or parsed.netloc != "oapi.dingtalk.com" or
            hostname != "oapi.dingtalk.com" or port is not None or username is not None or password is not None or
            parsed.path != "/robot/send" or parsed.fragment or "#" in webhook or len(query) != 1 or query[0][0] != "access_token"):
        raise DeploymentError(f"{context} webhook endpoint is invalid", exit_code)
    if re.search(r"%(?![0-9A-Fa-f]{2})", parsed.query):
        raise DeploymentError(f"{context} webhook endpoint is invalid", exit_code)
    _validate_delivery_text(query[0][1], "access_token", exit_code, context, reject_ascii_whitespace=True)
    return webhook, secret


def _open_stable_secret_parent(parent, trusted_anchor):
    if not os.path.isabs(parent) or not os.path.isabs(trusted_anchor): raise DeploymentError("secret path anchor must be absolute", EXIT_UNSAFE)
    absolute, anchor = os.path.abspath(parent), os.path.abspath(trusted_anchor)
    try: relative = os.path.relpath(absolute, anchor); inside = os.path.commonpath((absolute, anchor)) == anchor
    except ValueError as error: raise DeploymentError("secret path is outside trusted anchor", EXIT_UNSAFE) from error
    if not inside or relative == os.pardir or relative.startswith(os.pardir + os.sep): raise DeploymentError("secret path is outside trusted anchor", EXIT_UNSAFE)
    bindings = []
    try:
        current = os.open(anchor, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        bindings.append((current, None, None))
        anchor_st, anchor_named = os.fstat(current), os.stat(anchor, follow_symlinks=False)
        if (not stat.S_ISDIR(anchor_st.st_mode) or anchor_st.st_uid != os.getuid() or stat.S_IMODE(anchor_st.st_mode) & 0o022 or
                (anchor_st.st_dev, anchor_st.st_ino) != (anchor_named.st_dev, anchor_named.st_ino)):
            raise DeploymentError("unsafe trusted secret anchor", EXIT_UNSAFE)
        bindings[-1] = (current, None, (anchor_st.st_dev, anchor_st.st_ino))
        for component in [part for part in relative.split(os.sep) if part and part != "."]:
            child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=current)
            bindings.append((child, component, None))
            st, named = os.fstat(child), os.stat(component, dir_fd=current, follow_symlinks=False)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700 or
                    (st.st_dev, st.st_ino) != (named.st_dev, named.st_ino)):
                raise DeploymentError("unsafe secret path directory", EXIT_UNSAFE)
            bindings[-1] = (child, component, (st.st_dev, st.st_ino)); current = child
        final = os.fstat(current)
        if final.st_uid != os.getuid() or stat.S_IMODE(final.st_mode) != 0o700: raise DeploymentError("secret directory must be same-owner 0700", EXIT_UNSAFE)
        chain = (anchor, tuple(bindings))
        _validate_secret_directory_chain(chain)
        return current, final, chain
    except DeploymentError:
        for fd, _, _ in reversed(bindings): os.close(fd)
        raise
    except OSError as error:
        for fd, _, _ in reversed(bindings): os.close(fd)
        raise DeploymentError("secret path binding failed", EXIT_UNSAFE) from error


def _validate_secret_directory_chain(chain, exit_code=EXIT_UNSAFE):
    anchor, bindings = chain
    try:
        for index, (fd, component, expected_fp) in enumerate(bindings):
            current = os.fstat(fd)
            named = os.stat(anchor, follow_symlinks=False) if index == 0 else os.stat(component, dir_fd=bindings[index - 1][0], follow_symlinks=False)
            current_fp = (current.st_dev, current.st_ino)
            if (current_fp != expected_fp or current_fp != (named.st_dev, named.st_ino) or
                    not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or
                    (stat.S_IMODE(current.st_mode) & 0o022 if index == 0 else stat.S_IMODE(current.st_mode) != 0o700)):
                raise DeploymentError("secret directory chain binding changed", exit_code)
    except DeploymentError: raise
    except OSError:
        raise DeploymentError("secret directory chain binding changed", exit_code) from None


def _close_secret_directory_chain(chain):
    for fd, _, _ in reversed(chain[1]): os.close(fd)


def _read_secret_at(dfd, name, oversize_exit=EXIT_CONFLICT):
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
    try:
        before, named = os.fstat(fd), os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if not _safe_regular(before, 0o600) or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino): raise DeploymentError("unsafe existing secret", EXIT_UNSAFE)
        chunks, total = [], 0
        while True:
            data = os.read(fd, 4096)
            if not data: break
            total += len(data)
            if total > DELIVERY_SECRET_MAX_BYTES: raise DeploymentError("secret exceeds resource limit", oversize_exit)
            chunks.append(data)
        after, again = os.fstat(fd), os.stat(name, dir_fd=dfd, follow_symlinks=False)
        before_fp = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode, before.st_uid, before.st_nlink)
        after_fp = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_uid, after.st_nlink)
        named_fp = (again.st_dev, again.st_ino, again.st_size, again.st_mtime_ns, again.st_ctime_ns, again.st_mode, again.st_uid, again.st_nlink)
        if before_fp != after_fp or after_fp != named_fp or not _safe_regular(after, 0o600): raise DeploymentError("secret changed during read", EXIT_UNSAFE)
        return b"".join(chunks)
    finally: os.close(fd)


def _revalidate_secret_binding(parent, dfd, parent_before, name, expected, directory_chain, failure_exit=EXIT_UNSAFE):
    before_fp = (parent_before.st_dev, parent_before.st_ino)
    def check_parent():
        _validate_secret_directory_chain(directory_chain, failure_exit)
        try:
            parent_fd_after = os.fstat(dfd)
            parent_path_after = os.stat(parent, follow_symlinks=False)
        except OSError:
            raise DeploymentError("secret directory binding changed", failure_exit) from None
        if (before_fp != (parent_fd_after.st_dev, parent_fd_after.st_ino) or
                before_fp != (parent_path_after.st_dev, parent_path_after.st_ino) or
                not stat.S_ISDIR(parent_fd_after.st_mode) or parent_fd_after.st_uid != os.getuid() or
                stat.S_IMODE(parent_fd_after.st_mode) != 0o700):
            raise DeploymentError("secret directory binding changed", failure_exit)
    check_parent()
    try: reread = _read_secret_at(dfd, name, failure_exit)
    except OSError: raise DeploymentError("existing secret changed during verification", failure_exit) from None
    if reread != expected:
        raise DeploymentError("existing secret changed during verification", failure_exit)
    check_parent()
    return reread


def _parse_secret_fields(raw):
    if type(raw) is not bytes or len(raw) > DELIVERY_SECRET_MAX_BYTES:
        raise DeploymentError("existing secret JSON exceeds exact contract", EXIT_CONFLICT)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate")
            result[key] = value
        return result
    try: value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Exception: raise DeploymentError("existing secret JSON is invalid", EXIT_CONFLICT) from None
    if type(value) is not dict or set(value) != {"webhook", "secret"}: raise DeploymentError("existing secret JSON fields are invalid", EXIT_CONFLICT)
    webhook, secret = _validate_delivery_credentials(value["webhook"], value["secret"], EXIT_CONFLICT, "existing secret JSON")
    if raw != _canonical({"secret": secret, "webhook": webhook}):
        raise DeploymentError("existing secret JSON is not exact canonical UTF-8", EXIT_CONFLICT)
    return webhook, secret


def _full_write(fd, data):
    offset = 0
    while offset < len(data):
        count = os.write(fd, data[offset:])
        if count <= 0: raise OSError("short write")
        offset += count


def _read_named_exact(dfd, name, *, expected_mode=0o600, allowed_nlinks=(1,), max_bytes=MAX_FILE_BYTES,
                      missing_ok=False, failure_code=EXIT_UNSAFE, oversize_code=None):
    fd = None
    try:
        try: fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
        except FileNotFoundError as error:
            if missing_ok: return None
            raise DeploymentError("exact private file is missing", EXIT_MISSING) from error
        named = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        data, mode, fingerprint = _read_regular_fd(fd, named, expected_mode=expected_mode, allowed_nlinks=allowed_nlinks,
                max_bytes=max_bytes, failure_code=failure_code, oversize_code=oversize_code)
        if fingerprint != _stat_fingerprint(os.stat(name, dir_fd=dfd, follow_symlinks=False)):
            raise DeploymentError("exact private filename changed", failure_code)
        return data, mode, fingerprint
    except DeploymentError: raise
    except OSError as error: raise DeploymentError("exact private file read failed", failure_code) from error
    finally:
        if fd is not None: os.close(fd)


def _bounded_temp_names(dfd, prefix, failure_code):
    try:
        names = os.listdir(dfd)
    except OSError as error: raise DeploymentError("private temp inventory failed", failure_code) from error
    if len(names) > 4096: raise DeploymentError("private directory exceeds reconciliation limit", failure_code)
    matches = [name for name in names if name.startswith(prefix)]
    if len(matches) > 1: raise DeploymentError("ambiguous private temp residue", failure_code)
    if matches and re.fullmatch(re.escape(prefix) + r"[0-9a-f]{24}", matches[0]) is None:
        raise DeploymentError("malformed private temp residue", failure_code)
    return matches


def _reconcile_secret_temp(dfd, name, desired, directory_chain, lock):
    prefix = ".report_delivery.tmp."
    _fence(lock); _validate_secret_directory_chain(directory_chain)
    matches = _bounded_temp_names(dfd, prefix, EXIT_CONFLICT)
    final = _read_named_exact(dfd, name, expected_mode=0o600, allowed_nlinks=(1, 2),
            max_bytes=DELIVERY_SECRET_MAX_BYTES, missing_ok=True, failure_code=EXIT_UNSAFE,
            oversize_code=EXIT_CONFLICT)
    temp = None if not matches else _read_named_exact(dfd, matches[0], expected_mode=0o600, allowed_nlinks=(1, 2),
            max_bytes=DELIVERY_SECRET_MAX_BYTES, failure_code=EXIT_UNSAFE, oversize_code=EXIT_CONFLICT)
    if temp is not None:
        same_inode = final is not None and temp[2][:2] == final[2][:2]
        linked_pair = same_inode and temp[2][7] == 2 and final[2][7] == 2
        separate_files = not same_inode and temp[2][7] == 1 and (final is None or final[2][7] == 1)
        if not linked_pair and not separate_files:
            raise DeploymentError("secret temp link relation is ambiguous", EXIT_CONFLICT)
    elif final is not None and final[2][7] != 1:
        raise DeploymentError("secret final link relation is ambiguous", EXIT_UNSAFE)
    if final is not None and final[0] != desired: raise DeploymentError("existing secret conflicts with exact canonical migrated credentials", EXIT_CONFLICT)
    if temp is not None and temp[0] != desired: raise DeploymentError("secret temp residue differs from exact credentials", EXIT_CONFLICT)
    if temp is not None:
        same_inode = final is not None and temp[2][:2] == final[2][:2]
        _fence(lock); _validate_secret_directory_chain(directory_chain)
        fresh_temp = _read_named_exact(dfd, matches[0], expected_mode=0o600, allowed_nlinks=((2,) if same_inode else (1,)), max_bytes=DELIVERY_SECRET_MAX_BYTES, failure_code=EXIT_CONFLICT)
        if fresh_temp[0] != desired or fresh_temp[2] != temp[2]: raise DeploymentError("secret temp changed before reconciliation", EXIT_CONFLICT)
        os.unlink(matches[0], dir_fd=dfd); os.fsync(dfd)
        _fence(lock); _validate_secret_directory_chain(directory_chain)
    if final is not None:
        exact = _read_named_exact(dfd, name, expected_mode=0o600, allowed_nlinks=(1,), max_bytes=DELIVERY_SECRET_MAX_BYTES, failure_code=EXIT_CONFLICT)
        if exact[0] != desired: raise DeploymentError("reconciled secret differs", EXIT_CONFLICT)
        os.fsync(dfd); _fence(lock); _validate_secret_directory_chain(directory_chain)
        return exact[0]
    return None


def _migrate_credentials_from_bytes(policy, live_source_bytes, *, ops=None, fault=None, _lock=None, pre_publish=None):
    """No-clobber migrate two legacy AST constants to a private JSON secret."""
    ops, fault = ops or Ops(), fault or FaultInjector(); policy = _policy(policy)
    if type(live_source_bytes) is not bytes: raise DeploymentError("legacy credential source must be exact bytes", EXIT_PROTOCOL)
    webhook, secret = _extract_credentials(live_source_bytes)
    desired = _canonical({"secret": secret, "webhook": webhook})
    if len(desired) > DELIVERY_SECRET_MAX_BYTES: raise DeploymentError("canonical secret exceeds resource limit", EXIT_INTEGRITY)
    path = ops.resolve(policy["deployment"]["secret_path"]); parent, name = os.path.dirname(path), os.path.basename(path)
    trusted_anchor = ops.resolve("~")
    dfd, parent_before, directory_chain = _open_stable_secret_parent(parent, trusted_anchor); temp = ".report_delivery.tmp." + os.urandom(12).hex(); fd = None; linked = False; temp_fp = None
    try:
        _fence(_lock); _validate_secret_directory_chain(directory_chain)
        existing = _reconcile_secret_temp(dfd, name, desired, directory_chain, _lock)
        if existing is not None:
            observed_existing = _read_secret_at(dfd, name)
            if observed_existing != existing: raise DeploymentError("existing secret changed after reconciliation", EXIT_UNSAFE)
            _parse_secret_fields(existing)
            if existing != desired: raise DeploymentError("existing secret conflicts with exact canonical migrated credentials", EXIT_CONFLICT)
            if pre_publish is not None: pre_publish()
            _fence(_lock)
            _revalidate_secret_binding(parent, dfd, parent_before, name, desired, directory_chain)
            if pre_publish is not None: pre_publish()
            _fence(_lock)
            return {"created": False, "reused": True}
        _fence(_lock); _validate_secret_directory_chain(directory_chain); fault.hit("secret.temp.open"); fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dfd)
        opened = os.fstat(fd); temp_fp = (opened.st_dev, opened.st_ino)
        _full_write(fd, desired); os.fchmod(fd, 0o600); fault.hit("secret.file.fsync"); os.fsync(fd); os.close(fd); fd = None; _fence(_lock)
        if pre_publish is not None: pre_publish()
        fault.hit("secret.hardlink"); _fence(_lock); _validate_secret_directory_chain(directory_chain)
        staged = _read_named_exact(dfd, temp, expected_mode=0o600, allowed_nlinks=(1,), max_bytes=DELIVERY_SECRET_MAX_BYTES, failure_code=EXIT_CONFLICT)
        if staged[0] != desired or staged[2][:2] != temp_fp or _read_named_exact(dfd, name, missing_ok=True, failure_code=EXIT_CONFLICT) is not None:
            raise DeploymentError("secret publish compare gate drifted", EXIT_CONFLICT)
        _fence(_lock); _validate_secret_directory_chain(directory_chain); os.link(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False); linked = True; _fence(_lock)
        linked_temp = _read_named_exact(dfd, temp, expected_mode=0o600, allowed_nlinks=(2,), max_bytes=DELIVERY_SECRET_MAX_BYTES, failure_code=EXIT_UNCERTAIN)
        linked_final = _read_named_exact(dfd, name, expected_mode=0o600, allowed_nlinks=(2,), max_bytes=DELIVERY_SECRET_MAX_BYTES, failure_code=EXIT_UNCERTAIN)
        if linked_temp[0] != desired or linked_temp[2][:2] != temp_fp or linked_final[2][:2] != temp_fp:
            raise DeploymentError("secret publish link relation differs", EXIT_UNCERTAIN)
        fault.hit("secret.linked")
        _fence(_lock); _validate_secret_directory_chain(directory_chain, EXIT_UNCERTAIN); os.unlink(temp, dir_fd=dfd); temp_fp = None; _fence(_lock)
        fault.hit("secret.unlinked"); fault.hit("secret.dir.fsync"); os.fsync(dfd); _fence(_lock)
        _revalidate_secret_binding(parent, dfd, parent_before, name, desired, directory_chain, EXIT_UNCERTAIN)
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
                _fence(_lock); os.unlink(temp, dir_fd=dfd); os.fsync(dfd); _fence(_lock)
        except FileNotFoundError: pass
        _close_secret_directory_chain(directory_chain)


def _legacy_migration_source(policy, live_scope):
    present, source, mode = live_scope.state("run.py", expected_mode=0o644, missing_ok=False)
    if not present or mode != 0o644 or _sha(source) != policy["baseline"]["live_entrypoint_sha256"]:
        raise DeploymentError("migrate-only requires exact legacy baseline", EXIT_CONFLICT)
    if live_scope.state(policy["deployment"]["runtime_manifest_target"])[0]:
        raise DeploymentError("migrate-only refuses an installed runtime", EXIT_CONFLICT)
    return source


def migrate_credentials(policy, repo_root, *, ops=None, clock=None, process_inspector=None, fault=None):
    """Supported secret-only operation with the full fixed migration idle gate."""
    ops, clock, inspector, fault = ops or Ops(), clock or Clock(), process_inspector or ProcessInspector(), fault or FaultInjector()
    policy = _policy(policy)
    _check_production_python(policy, inspector)
    _check_source_policy_repository(policy, repo_root, inspector, ops)
    with _open_live_scope(policy, ops) as preflight_scope:
        _legacy_migration_source(policy, preflight_scope)
        _check_window(policy, clock); _check_idle(policy, inspector, ops); _check_migration_dependents(policy, inspector)
    with _acquire_lock(policy, ops) as lock:
        with _open_live_scope(policy, ops, lock) as live_scope:
            def gate():
                source_now = _legacy_migration_source(policy, live_scope)
                _check_window(policy, clock); _check_idle(policy, inspector, ops); _check_migration_dependents(policy, inspector)
                if source_now != source: raise DeploymentError("legacy baseline changed during migrate-only", EXIT_CONFLICT)
            source = _legacy_migration_source(policy, live_scope)
            _check_window(policy, clock); _check_idle(policy, inspector, ops); _check_migration_dependents(policy, inspector)
            result = _migrate_credentials_from_bytes(policy, source, ops=ops, fault=fault, _lock=lock, pre_publish=gate)
            gate()
            return result


def _reuse_canonical_credentials(policy, ops, lock=None, expected_sha256=None):
    """Reuse only an already canonical secret; caller must prove prior provenance."""
    path = ops.resolve(policy["deployment"]["secret_path"]); parent, name = os.path.dirname(path), os.path.basename(path)
    dfd, parent_before, directory_chain = _open_stable_secret_parent(parent, ops.resolve("~"))
    try:
        _fence(lock); _validate_secret_directory_chain(directory_chain)
        try: existing = _read_secret_at(dfd, name)
        except FileNotFoundError as error: raise DeploymentError("canonical delivery secret is missing", EXIT_MISSING) from error
        _parse_secret_fields(existing)
        digest = _sha(existing)
        if expected_sha256 is not None and digest != expected_sha256:
            raise DeploymentError("canonical delivery secret differs from journal binding", EXIT_CONFLICT)
        _fence(lock); _revalidate_secret_binding(parent, dfd, parent_before, name, existing, directory_chain); _fence(lock)
        return digest
    finally:
        _close_secret_directory_chain(directory_chain)


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


class _ReadOnlyRollbackAnchor:
    def __init__(self, bindings, home_path, scope_path):
        self.bindings, self.home_path, self.scope_path = bindings, home_path, scope_path
        self.scope_fd = bindings[-1][0]
    def fence(self):
        for index, (fd, component, fingerprint) in enumerate(self.bindings):
            try:
                current = os.fstat(fd)
                named = os.stat(self.home_path, follow_symlinks=False) if index == 0 else os.stat(component, dir_fd=self.bindings[index - 1][0], follow_symlinks=False)
            except OSError: raise DeploymentError("read-only rollback anchor fence failed", EXIT_UNSAFE) from None
            current_fp = (current.st_dev, current.st_ino); mode = stat.S_IMODE(current.st_mode)
            if (current_fp != fingerprint or current_fp != (named.st_dev, named.st_ino) or
                    not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or
                    (mode & 0o022 if index == 0 else mode != 0o700)):
                raise DeploymentError("read-only rollback anchor fence failed", EXIT_UNSAFE)
    def close(self):
        error = None
        try: self.fence()
        except DeploymentError as caught: error = caught
        for fd, _, _ in reversed(self.bindings): os.close(fd)
        self.bindings = []; self.scope_fd = None
        if error is not None: raise error


def _open_readonly_rollback_anchor(policy, ops):
    configured = policy["deployment"]["rollback_root"]
    if type(configured) is not str or not configured.startswith("~/"):
        raise DeploymentError("rollback root is not home-anchored", EXIT_PROTOCOL)
    parts = configured[2:].split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise DeploymentError("rollback root components are unsafe", EXIT_PROTOCOL)
    home_path = os.path.abspath(ops.resolve("~")); scope_path = os.path.join(home_path, *parts)
    if os.path.abspath(ops.resolve(configured)) != scope_path:
        raise DeploymentError("rollback root mapping is inconsistent", EXIT_UNSAFE)
    bindings = []
    try:
        current = os.open(home_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        bindings.append((current, None, None)); home_st = os.fstat(current); bindings[-1] = (current, None, (home_st.st_dev, home_st.st_ino))
        for component in parts:
            child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=current)
            bindings.append((child, component, None)); child_st = os.fstat(child); bindings[-1] = (child, component, (child_st.st_dev, child_st.st_ino)); current = child
        anchor = _ReadOnlyRollbackAnchor(bindings, home_path, scope_path); anchor.fence(); return anchor
    except FileNotFoundError as error:
        for fd, _, _ in reversed(bindings): os.close(fd)
        raise DeploymentError("read-only rollback anchor is missing", EXIT_MISSING) from error
    except DeploymentError:
        for fd, _, _ in reversed(bindings): os.close(fd)
        raise
    except OSError as error:
        for fd, _, _ in reversed(bindings): os.close(fd)
        raise DeploymentError("read-only rollback anchor open failed", EXIT_UNSAFE) from error


class _ReleaseScope:
    def __init__(self, fd, name, fingerprint, lock, owned_anchor=None):
        self.fd, self.name, self.fingerprint, self.lock, self.owned_anchor = fd, name, fingerprint, lock, owned_anchor
    def fence(self):
        _fence(self.lock)
        try: current, named = os.fstat(self.fd), os.stat(self.name, dir_fd=self.lock.scope_fd, follow_symlinks=False)
        except OSError: raise DeploymentError("rollback release directory fence failed", EXIT_UNSAFE) from None
        current_fp = (current.st_dev, current.st_ino)
        if (current_fp != self.fingerprint or current_fp != (named.st_dev, named.st_ino) or
                not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700):
            raise DeploymentError("rollback release directory fence failed", EXIT_UNSAFE)
    def read_private(self, name, failure_code=EXIT_UNCERTAIN):
        if type(name) is not str or not name or name in (".", "..") or "/" in name:
            raise DeploymentError("invalid rollback private filename", EXIT_PROTOCOL)
        try:
            self.fence()
            exact = _read_named_exact(self.fd, name, expected_mode=0o600, allowed_nlinks=(1,),
                    max_bytes=MAX_FILE_BYTES, failure_code=failure_code)
            self.fence(); return exact[0]
        except FileNotFoundError as error: raise DeploymentError("rollback private file is missing", EXIT_MISSING) from error
        except DeploymentError: raise
        except OSError as error: raise DeploymentError("rollback private file read failed", failure_code) from error
    def close(self):
        error = None
        if self.fd is not None:
            try: self.fence()
            except DeploymentError as caught: error = caught
            os.close(self.fd); self.fd = None
        if self.owned_anchor is not None:
            try: self.owned_anchor.close()
            except DeploymentError as caught:
                if error is None: error = caught
            self.owned_anchor = None
        if error is not None: raise error
    def __enter__(self): return self
    def __exit__(self, *unused): self.close()


def _open_release_scope(policy, expected_release_id, ops, lock):
    if not re.fullmatch(r"spmrv1-[0-9a-f]{32}", expected_release_id):
        raise DeploymentError("invalid rollback release scope", EXIT_PROTOCOL)
    owned_anchor = _open_readonly_rollback_anchor(policy, ops) if lock is None else None
    anchor = owned_anchor or lock
    rollback_root = os.path.abspath(ops.resolve(policy["deployment"]["rollback_root"]))
    if rollback_root != os.path.abspath(anchor.scope_path):
        if owned_anchor is not None: owned_anchor.close()
        raise DeploymentError("rollback release scope is outside locked root", EXIT_UNSAFE)
    fd = None
    try:
        _fence(anchor)
        fd = os.open(expected_release_id, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=anchor.scope_fd)
        current, named = os.fstat(fd), os.stat(expected_release_id, dir_fd=anchor.scope_fd, follow_symlinks=False)
        fingerprint = (current.st_dev, current.st_ino)
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700 or
                fingerprint != (named.st_dev, named.st_ino)):
            raise DeploymentError("unsafe rollback release directory", EXIT_UNSAFE)
        scope = _ReleaseScope(fd, expected_release_id, fingerprint, anchor, owned_anchor); scope.fence(); return scope
    except FileNotFoundError as error:
        if fd is not None: os.close(fd)
        if owned_anchor is not None: owned_anchor.close()
        raise DeploymentError("rollback release directory is missing", EXIT_MISSING) from error
    except DeploymentError:
        if fd is not None: os.close(fd)
        if owned_anchor is not None: owned_anchor.close()
        raise
    except OSError as error:
        if fd is not None: os.close(fd)
        if owned_anchor is not None: owned_anchor.close()
        raise DeploymentError("rollback release directory open failed", EXIT_UNSAFE) from error


def _owned_temp_name(name): return f".{name}.release-tmp-{os.urandom(12).hex()}"


def _target_state(target, live_scope):
    return live_scope.state(target)


def _assert_expected_target(target, expected, live_scope):
    if (type(expected) is not tuple or len(expected) != 3 or type(expected[0]) is not bool or
            (expected[0] and (type(expected[1]) is not bytes or type(expected[2]) is not int)) or
            (not expected[0] and expected[1:] != (None, None))):
        raise DeploymentError("invalid expected target state", EXIT_PROTOCOL)
    if _target_state(target, live_scope) != expected:
        raise DeploymentError("compare-before-replace target drifted", EXIT_UNCERTAIN)


def _atomic_replace(target, data, mode, live_scope, fault, event, lock=None, expected=None, pre_publish=None):
    dfd, name = live_scope.binding(target); temp = _owned_temp_name(name); fd = None; attempted = False; temp_fp = None
    try:
        live_scope.fence()
        live_scope.state(target)
        fault.hit(event + ".open"); fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), mode, dir_fd=dfd)
        opened = os.fstat(fd); temp_fp = (opened.st_dev, opened.st_ino)
        _full_write(fd, data); os.fchmod(fd, mode); fault.hit(event + ".file_fsync"); os.fsync(fd); os.close(fd); fd = None; live_scope.fence()
        staged_fd = os.open(temp, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
        try:
            staged_named = os.stat(temp, dir_fd=dfd, follow_symlinks=False)
            staged, staged_mode, staged_fp = _read_regular_fd(staged_fd, staged_named, expected_mode=mode)
            if staged != data or staged_mode != mode or staged_fp != _stat_fingerprint(os.stat(temp, dir_fd=dfd, follow_symlinks=False)):
                raise DeploymentError("staged file verification failed", EXIT_UNSAFE)
        finally: os.close(staged_fd)
        fault.hit(event + ".compare")
        if pre_publish is not None: pre_publish()
        live_scope.fence()
        if expected is not None: _assert_expected_target(target, expected, live_scope)
        live_scope.fence(); attempted = True; fault.hit(event + ".replace"); os.replace(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd); temp_fp = None
        live_scope.fence(EXIT_UNCERTAIN); fault.hit(event + ".dir_fsync"); os.fsync(dfd); live_scope.fence(EXIT_UNCERTAIN)
        if live_scope.state(target, expected_mode=mode, missing_ok=False, failure_code=EXIT_UNCERTAIN) != (True, data, mode): raise DeploymentError("installed file post-verification failed", EXIT_UNCERTAIN)
    except DeploymentError as error:
        if attempted and error.exit_code != EXIT_UNCERTAIN: raise DeploymentError("atomic install outcome is uncertain", EXIT_UNCERTAIN) from error
        raise
    except Exception as error:
        if attempted: raise DeploymentError("atomic install outcome is uncertain", EXIT_UNCERTAIN) from error
        raise DeploymentError("atomic staging failed", EXIT_STAGING) from error
    finally:
        if fd is not None: os.close(fd)
        try:
            current = os.stat(temp, dir_fd=dfd, follow_symlinks=False)
            if temp_fp is not None and (current.st_dev, current.st_ino) == temp_fp:
                live_scope.fence(); os.unlink(temp, dir_fd=dfd); os.fsync(dfd); live_scope.fence()
        except FileNotFoundError: pass


def _replace_release_private(scope, name, data, expected, fault, event, lock, pre_publish=None):
    if type(data) is not bytes or type(expected) is not bytes:
        raise DeploymentError("invalid rollback private replacement", EXIT_PROTOCOL)
    temp = _owned_temp_name(name); fd = None; attempted = False; temp_fp = None
    try:
        scope.fence(); fault.hit(event + ".open")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=scope.fd)
        opened = os.fstat(fd); temp_fp = (opened.st_dev, opened.st_ino)
        _full_write(fd, data); os.fchmod(fd, 0o600); fault.hit(event + ".file_fsync"); os.fsync(fd); os.close(fd); fd = None
        scope.fence()
        if scope.read_private(temp) != data: raise DeploymentError("rollback private staging readback failed", EXIT_UNCERTAIN)
        fault.hit(event + ".compare")
        if pre_publish is not None: pre_publish()
        scope.fence()
        staged = _read_named_exact(scope.fd, temp, expected_mode=0o600, allowed_nlinks=(1,), failure_code=EXIT_UNCERTAIN)
        if staged[0] != data or staged[2][:2] != temp_fp or scope.read_private(name) != expected:
            raise DeploymentError("rollback journal compare-before-replace drifted", EXIT_UNCERTAIN)
        scope.fence(); attempted = True; fault.hit(event + ".replace")
        os.replace(temp, name, src_dir_fd=scope.fd, dst_dir_fd=scope.fd); temp_fp = None
        scope.fence(); fault.hit(event + ".dir_fsync"); os.fsync(scope.fd)
        if scope.read_private(name) != data: raise DeploymentError("rollback private replacement post-verification failed", EXIT_UNCERTAIN)
        scope.fence()
    except DeploymentError as error:
        if attempted and error.exit_code != EXIT_UNCERTAIN: raise DeploymentError("rollback private replacement outcome is uncertain", EXIT_UNCERTAIN) from error
        raise
    except OSError as error:
        raise DeploymentError("rollback private replacement outcome is uncertain" if attempted else "rollback private staging failed", EXIT_UNCERTAIN if attempted else EXIT_STAGING) from error
    finally:
        if fd is not None: os.close(fd)
        if temp_fp is not None:
            try:
                current = os.stat(temp, dir_fd=scope.fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == temp_fp:
                    _fence(lock); os.unlink(temp, dir_fd=scope.fd); os.fsync(scope.fd); _fence(lock)
            except FileNotFoundError: pass


def _reconcile_release_private(scope, name, data, lock):
    prefix = f".{name}.release-tmp-"
    scope.fence(); matches = _bounded_temp_names(scope.fd, prefix, EXIT_CONFLICT)
    final = _read_named_exact(scope.fd, name, expected_mode=0o600, allowed_nlinks=(1, 2),
            missing_ok=True, failure_code=EXIT_CONFLICT)
    temp = None if not matches else _read_named_exact(scope.fd, matches[0], expected_mode=0o600,
            allowed_nlinks=(1, 2), failure_code=EXIT_CONFLICT)
    if final is not None and final[0] != data: raise DeploymentError("rollback private final differs", EXIT_CONFLICT)
    if temp is not None and temp[0] != data: raise DeploymentError("rollback private temp differs", EXIT_CONFLICT)
    if temp is not None:
        same_inode = final is not None and temp[2][:2] == final[2][:2]
        if (same_inode and (temp[2][7] != 2 or final[2][7] != 2)) or (not same_inode and temp[2][7] != 1):
            raise DeploymentError("rollback private temp link relation is ambiguous", EXIT_CONFLICT)
        scope.fence(); fresh_temp = _read_named_exact(scope.fd, matches[0], expected_mode=0o600,
                allowed_nlinks=((2,) if same_inode else (1,)), failure_code=EXIT_CONFLICT)
        if fresh_temp[0] != data or fresh_temp[2] != temp[2]: raise DeploymentError("rollback private temp changed before reconciliation", EXIT_CONFLICT)
        os.unlink(matches[0], dir_fd=scope.fd); os.fsync(scope.fd); scope.fence()
    elif final is not None and final[2][7] != 1:
        raise DeploymentError("rollback private final link relation is ambiguous", EXIT_CONFLICT)
    if final is not None:
        exact = _read_named_exact(scope.fd, name, expected_mode=0o600, allowed_nlinks=(1,), failure_code=EXIT_CONFLICT)
        if exact[0] != data: raise DeploymentError("reconciled rollback private file differs", EXIT_CONFLICT)
        os.fsync(scope.fd); scope.fence(); return True
    return False


def _write_new_release_private(scope, name, data, fault, event, lock):
    if type(data) is not bytes: raise DeploymentError("invalid rollback private bytes", EXIT_PROTOCOL)
    temp = _owned_temp_name(name); fd = None; temp_fp = None; linked = False
    try:
        if _reconcile_release_private(scope, name, data, lock): return
        scope.fence(); fault.hit(event + ".open")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=scope.fd)
        opened = os.fstat(fd); temp_fp = (opened.st_dev, opened.st_ino)
        _full_write(fd, data); os.fchmod(fd, 0o600); fault.hit(event + ".file_fsync"); os.fsync(fd); os.close(fd); fd = None
        scope.fence()
        if scope.read_private(temp) != data: raise DeploymentError("rollback private staging readback failed", EXIT_UNCERTAIN)
        fault.hit(event + ".link"); scope.fence()
        staged = _read_named_exact(scope.fd, temp, expected_mode=0o600, allowed_nlinks=(1,), failure_code=EXIT_CONFLICT)
        if staged[0] != data or staged[2][:2] != temp_fp or _read_named_exact(scope.fd, name, missing_ok=True, failure_code=EXIT_CONFLICT) is not None:
            raise DeploymentError("rollback private publish compare gate drifted", EXIT_CONFLICT)
        scope.fence(); os.link(temp, name, src_dir_fd=scope.fd, dst_dir_fd=scope.fd, follow_symlinks=False); linked = True
        linked_temp = _read_named_exact(scope.fd, temp, expected_mode=0o600, allowed_nlinks=(2,), failure_code=EXIT_UNCERTAIN)
        linked_final = _read_named_exact(scope.fd, name, expected_mode=0o600, allowed_nlinks=(2,), failure_code=EXIT_UNCERTAIN)
        if linked_temp[0] != data or linked_temp[2][:2] != temp_fp or linked_final[2][:2] != temp_fp:
            raise DeploymentError("rollback private publish link relation differs", EXIT_UNCERTAIN)
        fault.hit(event + ".linked")
        scope.fence(); fresh_temp = _read_named_exact(scope.fd, temp, expected_mode=0o600, allowed_nlinks=(2,), failure_code=EXIT_UNCERTAIN)
        if fresh_temp[0] != data or fresh_temp[2][:2] != temp_fp: raise DeploymentError("rollback private temp changed before unlink", EXIT_UNCERTAIN)
        os.unlink(temp, dir_fd=scope.fd); temp_fp = None; scope.fence(); fault.hit(event + ".unlinked"); fault.hit(event + ".dir_fsync"); os.fsync(scope.fd)
        if scope.read_private(name) != data: raise DeploymentError("rollback private write post-verification failed", EXIT_UNCERTAIN)
    except FileExistsError as error:
        try:
            if scope.read_private(name) == data: os.fsync(scope.fd); scope.fence(); return
        except DeploymentError: pass
        raise DeploymentError("rollback private path exists with different or unsafe bytes", EXIT_CONFLICT) from error
    except DeploymentError as error:
        if linked and error.exit_code != EXIT_UNCERTAIN: raise DeploymentError("rollback private write outcome is uncertain", EXIT_UNCERTAIN) from error
        raise
    except OSError as error:
        raise DeploymentError("rollback private write outcome is uncertain" if linked else "rollback private staging failed", EXIT_UNCERTAIN if linked else EXIT_STAGING) from error
    finally:
        if fd is not None: os.close(fd)
        if temp_fp is not None:
            try:
                current = os.stat(temp, dir_fd=scope.fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == temp_fp:
                    _fence(lock); os.unlink(temp, dir_fd=scope.fd); os.fsync(scope.fd); _fence(lock)
            except FileNotFoundError: pass


def _install_plan(policy, runtime, blobs):
    install = [(item["target"], blobs[item["source"]], int(item["mode"], 8)) for item in runtime["bundle"][:2]]
    install.append((policy["deployment"]["runtime_manifest_target"], manifest.canonical_runtime_release_bytes(runtime), 0o644))
    entry = runtime["bundle"][2]; install.append((entry["target"], blobs[entry["source"]], int(entry["mode"], 8)))
    return install


def _journal_entries(policy, runtime, blobs, live_scope, scope, fault, lock=None):
    entries = []; expected_states = []
    install = _install_plan(policy, runtime, blobs)
    for index, (target, new, mode) in enumerate(install):
        present, old, observed_mode = live_scope.state(target); old_mode = None
        backup = None
        if present:
            old_mode = f"{observed_mode:04o}"; backup = f"backup-{index}.bin"; _write_new_release_private(scope, backup, old, fault, f"backup.{index}", lock)
        expected_states.append((present, old, None if old_mode is None else int(old_mode, 8)))
        entries.append({"target": target, "old_mode": old_mode, "new_mode": f"{mode:04o}", "old_present": present, "old_sha256": None if old is None else _sha(old), "backup": backup, "new_sha256": _sha(new), "new_size": len(new)})
    return install, entries, expected_states


def _parse_journal(policy, expected_release_id, raw):
    try: value = json.loads(raw.decode())
    except Exception as error: raise DeploymentError("invalid rollback journal", EXIT_UNCERTAIN) from error
    if (type(value) is not dict or set(value) != {"schema", "release_id", "bundle_digest", "secret_sha256", "status", "entries"} or
            value.get("schema") != JOURNAL_SCHEMA or value.get("release_id") != expected_release_id or
            value.get("status") not in ("prepared", "installed", "rolled_back") or
            type(value.get("entries")) is not list or len(value["entries"]) != 4 or not HEX64.fullmatch(value.get("bundle_digest", "")) or
            not HEX64.fullmatch(value.get("secret_sha256", ""))):
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
    return value


def _read_journal_from_scope(policy, expected_release_id, scope):
    raw = scope.read_private(policy["deployment"]["journal_name"])
    return raw, _parse_journal(policy, expected_release_id, raw)


def _read_journal(policy, expected_release_id, ops, lock):
    path = _join(_join(policy["deployment"]["rollback_root"], expected_release_id), policy["deployment"]["journal_name"])
    with _open_release_scope(policy, expected_release_id, ops, lock) as scope:
        _, value = _read_journal_from_scope(policy, expected_release_id, scope)
    return path, value


def _read_archived_policy_from_scope(runtime, scope):
    raw = scope.read_private(POLICY_ARCHIVE_NAME)
    try: archived = manifest.parse_source_policy(raw)
    except manifest.ManifestError as error: raise DeploymentError("archived release policy is invalid", EXIT_UNCERTAIN) from error
    if (manifest.canonical_source_policy_bytes(archived) != raw or _sha(raw) != runtime["policy"]["sha256"] or
            runtime["policy"]["path"] != archived["deployment"]["policy_path"]):
        raise DeploymentError("archived release policy binding differs", EXIT_UNCERTAIN)
    return archived


def _read_archived_runtime_from_scope(expected_release_id, scope):
    raw = scope.read_private(RUNTIME_ARCHIVE_NAME)
    try: archived_runtime = manifest.parse_runtime_release(raw)
    except manifest.ManifestError as error: raise DeploymentError("archived runtime authority is invalid", EXIT_UNCERTAIN) from error
    if archived_runtime["release_id"] != expected_release_id:
        raise DeploymentError("archived runtime authority release differs", EXIT_UNCERTAIN)
    return archived_runtime


def _validate_initial_journal_authority(policy, runtime, raw, scope):
    archived_runtime = _read_archived_runtime_from_scope(runtime["release_id"], scope)
    if manifest.canonical_runtime_release_bytes(archived_runtime) != manifest.canonical_runtime_release_bytes(runtime):
        raise DeploymentError("initial journal runtime authority differs", EXIT_UNCERTAIN)
    archived_policy = _read_archived_policy_from_scope(archived_runtime, scope)
    if manifest.canonical_source_policy_bytes(archived_policy) != manifest.canonical_source_policy_bytes(policy):
        raise DeploymentError("initial journal policy authority differs", EXIT_UNCERTAIN)
    try: manifest.verify_runtime_release(archived_policy, archived_runtime)
    except manifest.ManifestError as error: raise DeploymentError("initial journal release authority differs", EXIT_UNCERTAIN) from error
    journal = _parse_journal(archived_policy, runtime["release_id"], raw)
    if journal["bundle_digest"] != runtime["bundle_digest"]:
        raise DeploymentError("initial journal bundle authority differs", EXIT_UNCERTAIN)
    return journal


def _reconcile_initial_journal(policy, runtime, scope, lock):
    """Normalize one crash residue before the first ordinary journal read."""
    name = policy["deployment"]["journal_name"]; prefix = f".{name}.release-tmp-"
    try:
        scope.fence(); matches = _bounded_temp_names(scope.fd, prefix, EXIT_UNCERTAIN)
        final = _read_named_exact(scope.fd, name, expected_mode=0o600, allowed_nlinks=(1, 2),
                missing_ok=True, failure_code=EXIT_UNCERTAIN)
        temp = None if not matches else _read_named_exact(scope.fd, matches[0], expected_mode=0o600,
                allowed_nlinks=(1, 2), failure_code=EXIT_UNCERTAIN)
        if final is None and temp is None: return False
        if temp is None:
            if final[2][7] != 1: raise DeploymentError("initial journal final link relation is ambiguous", EXIT_UNCERTAIN)
        elif final is None:
            if temp[2][7] != 1: raise DeploymentError("initial journal temp link relation is ambiguous", EXIT_UNCERTAIN)
        else:
            if (temp[2][:2] != final[2][:2] or temp[2][7] != 2 or final[2][7] != 2 or temp[0] != final[0]):
                raise DeploymentError("initial journal linked relation is ambiguous", EXIT_UNCERTAIN)
        candidate = final[0] if final is not None else temp[0]
        _validate_initial_journal_authority(policy, runtime, candidate, scope)
        scope.fence(); _fence(lock)
        if final is None:
            fresh_temp = _read_named_exact(scope.fd, matches[0], expected_mode=0o600, allowed_nlinks=(1,), failure_code=EXIT_UNCERTAIN)
            if fresh_temp[0] != candidate or fresh_temp[2] != temp[2] or _read_named_exact(scope.fd, name, missing_ok=True, failure_code=EXIT_UNCERTAIN) is not None:
                raise DeploymentError("initial journal prelink state changed", EXIT_UNCERTAIN)
            scope.fence(); os.link(matches[0], name, src_dir_fd=scope.fd, dst_dir_fd=scope.fd, follow_symlinks=False)
            linked_temp = _read_named_exact(scope.fd, matches[0], expected_mode=0o600, allowed_nlinks=(2,), failure_code=EXIT_UNCERTAIN)
            linked_final = _read_named_exact(scope.fd, name, expected_mode=0o600, allowed_nlinks=(2,), failure_code=EXIT_UNCERTAIN)
            if (linked_temp[0] != candidate or linked_final[0] != candidate or
                    linked_temp[2][:2] != fresh_temp[2][:2] or linked_final[2][:2] != fresh_temp[2][:2]):
                raise DeploymentError("initial journal prelink publication differs", EXIT_UNCERTAIN)
            temp = linked_temp
        if temp is not None:
            fresh_temp = _read_named_exact(scope.fd, matches[0], expected_mode=0o600, allowed_nlinks=(2,), failure_code=EXIT_UNCERTAIN)
            fresh_final = _read_named_exact(scope.fd, name, expected_mode=0o600, allowed_nlinks=(2,), failure_code=EXIT_UNCERTAIN)
            if (fresh_temp[0] != candidate or fresh_final[0] != candidate or fresh_temp[2][:2] != fresh_final[2][:2]):
                raise DeploymentError("initial journal linked state changed", EXIT_UNCERTAIN)
            scope.fence(); os.unlink(matches[0], dir_fd=scope.fd)
        scope.fence(); os.fsync(scope.fd); scope.fence()
        exact = _read_named_exact(scope.fd, name, expected_mode=0o600, allowed_nlinks=(1,), failure_code=EXIT_UNCERTAIN)
        if exact[0] != candidate: raise DeploymentError("initial journal reconciliation postcheck differs", EXIT_UNCERTAIN)
        _validate_initial_journal_authority(policy, runtime, exact[0], scope)
        return True
    except DeploymentError: raise
    except OSError as error: raise DeploymentError("initial journal reconciliation failed", EXIT_UNCERTAIN) from error


def _archived_policy_for_runtime(anchor_policy, runtime, ops, lock):
    with _open_release_scope(anchor_policy, runtime["release_id"], ops, lock) as scope:
        return _read_archived_policy_from_scope(runtime, scope)


def _prior_runtime_from_journal_backups(policy, old_states, ops, lock, repo_root, inspector):
    runtime_state = old_states[2]
    if not runtime_state[0] or runtime_state[2] != 0o644:
        raise DeploymentError("journal lacks prior runtime provenance", EXIT_UNCERTAIN)
    try:
        prior_runtime = _runtime(runtime_state[1]); prior_policy = _archived_policy_for_runtime(policy, prior_runtime, ops, lock); manifest.verify_runtime_release(prior_policy, prior_runtime); _check_archived_runtime_repository(prior_policy, prior_runtime, repo_root, inspector)
    except (manifest.ManifestError, DeploymentError) as error:
        raise DeploymentError("journal prior runtime provenance is invalid", EXIT_UNCERTAIN) from error
    by_target = {
        policy["bundle"][0]["target"]: old_states[0],
        policy["bundle"][1]["target"]: old_states[1],
        policy["bundle"][2]["target"]: old_states[3],
    }
    for item in prior_runtime["bundle"]:
        state = by_target[item["target"]]
        if (not state[0] or state[1] is None or _sha(state[1]) != item["sha256"] or len(state[1]) != item["size"] or
                state[2] != int(item["mode"], 8)):
            raise DeploymentError("journal prior bundle provenance is invalid", EXIT_UNCERTAIN)
    return prior_runtime


def _resume_credentials(policy, old_states, expected_sha256, ops, fault, lock, allow_recreate, repo_root, inspector, clock):
    old_run = old_states[3]
    if old_run[0] and old_run[1] is not None and _sha(old_run[1]) == policy["baseline"]["live_entrypoint_sha256"]:
        if old_run[2] != 0o644: raise DeploymentError("legacy journal entrypoint mode differs", EXIT_UNCERTAIN)
        if old_states[2][0]: raise DeploymentError("legacy journal has unexpected prior runtime", EXIT_UNCERTAIN)
        try: return _reuse_canonical_credentials(policy, ops, lock, expected_sha256)
        except DeploymentError as error:
            if error.exit_code != EXIT_MISSING or not allow_recreate: raise
        _migrate_credentials_from_bytes(policy, old_run[1], ops=ops, fault=fault, _lock=lock,
                pre_publish=lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops), _check_window(policy, clock)))
        return _reuse_canonical_credentials(policy, ops, lock, expected_sha256)
    _prior_runtime_from_journal_backups(policy, old_states, ops, lock, repo_root, inspector)
    return _reuse_canonical_credentials(policy, ops, lock, expected_sha256)


def _resume_existing_deploy_in_scope(policy, runtime, install, ops, inspector, fault, canary, lock, clock, scope, live_scope, repo_root):
    _fence(lock)
    archived_runtime = _read_archived_runtime_from_scope(runtime["release_id"], scope)
    if manifest.canonical_runtime_release_bytes(archived_runtime) != manifest.canonical_runtime_release_bytes(runtime):
        raise DeploymentError("prepared release runtime authority differs", EXIT_UNCERTAIN)
    archived = _read_archived_policy_from_scope(runtime, scope)
    if manifest.canonical_source_policy_bytes(archived) != manifest.canonical_source_policy_bytes(policy):
        raise DeploymentError("prepared release policy differs from current policy", EXIT_UNCERTAIN)
    journal_raw, journal = _read_journal_from_scope(policy, runtime["release_id"], scope)
    if journal["bundle_digest"] != runtime["bundle_digest"]: raise DeploymentError("existing journal belongs to different bundle", EXIT_UNCERTAIN)
    expected_targets = [target for target, _, _ in install]
    if [entry["target"] for entry in journal["entries"]] != expected_targets: raise DeploymentError("journal target order differs", EXIT_UNCERTAIN)
    states = []; old_states = []
    for entry, (_, new, mode) in zip(journal["entries"], install):
        if (_sha(new) != entry["new_sha256"] or len(new) != entry["new_size"] or
                f"{mode:04o}" != entry["new_mode"]):
            raise DeploymentError("journal new inventory differs", EXIT_UNCERTAIN)
        old = None
        if entry["old_present"]:
            backup = scope.read_private(entry["backup"])
            if _sha(backup) != entry["old_sha256"]:
                raise DeploymentError("journal backup inventory differs", EXIT_UNCERTAIN)
            old = backup
        old_expected = (entry["old_present"], old, None if entry["old_mode"] is None else int(entry["old_mode"], 8)); old_states.append(old_expected)
        target = entry["target"]; current_state = _target_state(target, live_scope)
        old_match = current_state == old_expected
        new_match = current_state == (True, new, mode)
        if not old_match and not new_match: raise DeploymentError("journal recovery found divergent live bytes or mode", EXIT_UNCERTAIN)
        states.append("new" if new_match else "old")
    if journal["status"] == "rolled_back": raise DeploymentError("release journal is already rolled back", EXIT_CONFLICT)
    if journal["status"] == "installed" and any(state != "new" for state in states): raise DeploymentError("installed journal does not match live state", EXIT_UNCERTAIN)
    if journal["status"] == "installed":
        _check_idle(policy, inspector, ops); _check_dependents(policy, inspector, ops); _check_window(policy, clock)
        _resume_credentials(policy, old_states, journal["secret_sha256"], ops, fault, lock, False, repo_root, inspector, clock)
        _check_window(policy, clock)
    try:
        if journal["status"] == "prepared":
            _check_idle(policy, inspector, ops); _check_dependents(policy, inspector, ops); _check_window(policy, clock)
            _resume_credentials(policy, old_states, journal["secret_sha256"], ops, fault, lock, True, repo_root, inspector, clock)
            _check_window(policy, clock)
        for index, ((target, data, mode), state, old_expected) in enumerate(zip(install, states, old_states)):
            if state == "new": continue
            _check_idle(policy, inspector, ops)
            _check_dependents(policy, inspector, ops)
            _check_window(policy, clock)
            gate = lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops), _check_window(policy, clock))
            _atomic_replace(target, data, mode, live_scope, fault, f"recover.install.{index}", lock, expected=old_expected, pre_publish=gate)
        _check_idle(policy, inspector, ops)
        _check_dependents(policy, inspector, ops)
        _canary_bundle_bytes(policy, runtime, ops, live_scope)
        if canary:
            _check_idle(policy, inspector, ops)
            _check_dependents(policy, inspector, ops)
            _check_window(policy, clock)
            live_scope.fence(); run_fake_canary(policy, runtime, ops=ops, _live_scope=live_scope); live_scope.fence()
        if journal["status"] != "installed":
            _check_idle(policy, inspector, ops)
            _check_dependents(policy, inspector, ops)
            _check_window(policy, clock)
            live_scope.fence(); journal["status"] = "installed"
            gate = lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops), _check_window(policy, clock), live_scope.fence())
            _replace_release_private(scope, policy["deployment"]["journal_name"], _canonical(journal), journal_raw, fault, "recover.journal.commit", lock, gate); live_scope.fence(EXIT_UNCERTAIN)
        return {"deployed": True, "recovered": True, "release_id": runtime["release_id"], "bundle_digest": runtime["bundle_digest"]}
    except DeploymentError as error:
        if error.exit_code == EXIT_UNCERTAIN: raise
        try: _rollback_locked(policy, runtime["release_id"], ops, inspector, fault, lock, live_scope)
        except DeploymentError as rollback_error: raise DeploymentError("recovery and rollback outcome uncertain", EXIT_UNCERTAIN) from rollback_error
        raise DeploymentError("recovered deployment failed and was fully rolled back", EXIT_ROLLED_BACK) from error


def _unlink_exact(target, expected_sha, expected_size, expected_mode, live_scope, fault, event, lock, pre_publish):
    dfd, name = live_scope.binding(target); attempted = False
    try:
        live_scope.fence(); state = live_scope.state(target, expected_mode=expected_mode, missing_ok=False, failure_code=EXIT_UNCERTAIN)
        if (_sha(state[1]) != expected_sha or len(state[1]) != expected_size or state[2] != expected_mode): raise DeploymentError("delete target is not exact new file", EXIT_UNCERTAIN)
        pre_publish(); live_scope.fence()
        if live_scope.state(target, expected_mode=expected_mode, missing_ok=False, failure_code=EXIT_UNCERTAIN) != state:
            raise DeploymentError("delete compare-before-unlink drifted", EXIT_UNCERTAIN)
        live_scope.fence(); fault.hit(event + ".unlink"); attempted = True; os.unlink(name, dir_fd=dfd)
        live_scope.fence(EXIT_UNCERTAIN); fault.hit(event + ".dir_fsync"); os.fsync(dfd); live_scope.fence(EXIT_UNCERTAIN)
        if live_scope.state(target, missing_ok=True, failure_code=EXIT_UNCERTAIN)[0]: raise DeploymentError("delete post-verification failed", EXIT_UNCERTAIN)
    except DeploymentError as error:
        if attempted and error.exit_code != EXIT_UNCERTAIN: raise DeploymentError("delete outcome is uncertain", EXIT_UNCERTAIN) from error
        raise
    except OSError as error: raise DeploymentError("delete outcome is uncertain" if attempted else "safe delete failed", EXIT_UNCERTAIN) from error


def _rollback_locked(policy, expected_release_id, ops, inspector, fault, lock, live_scope):
    with _open_release_scope(policy, expected_release_id, ops, lock) as scope:
        return _rollback_locked_in_scope(policy, expected_release_id, ops, inspector, fault, lock, scope, live_scope)


def _rollback_locked_in_scope(policy, expected_release_id, ops, inspector, fault, lock, scope, live_scope):
    _fence(lock)
    journal_raw, journal = _read_journal_from_scope(policy, expected_release_id, scope)
    for index in range(len(journal["entries"]) - 1, -1, -1):
        entry = journal["entries"][index]
        target = entry["target"]; current_state = _target_state(target, live_scope); current = current_state[1]
        current_sha = None if current is None else _sha(current)
        if entry["old_present"]:
            old = scope.read_private(entry["backup"])
            if _sha(old) != entry["old_sha256"]: raise DeploymentError("backup digest mismatch", EXIT_UNCERTAIN)
            old_exact = (True, old, int(entry["old_mode"], 8))
            if current_state == old_exact: continue
            old_bytes_wrong_mode = current is not None and current == old
            new_exact = (current is not None and current_sha == entry["new_sha256"] and len(current) == entry["new_size"] and
                    current_state[2] == int(entry["new_mode"], 8))
            if not old_bytes_wrong_mode and not new_exact: raise DeploymentError("live file diverged; rollback refused", EXIT_UNCERTAIN)
            _check_idle(policy, inspector, ops)
            _check_dependents(policy, inspector, ops)
            gate = lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops))
            _atomic_replace(target, old, int(entry["old_mode"], 8), live_scope, fault, f"rollback.{index}", lock, expected=current_state, pre_publish=gate)
        else:
            if current is None: continue
            if (current_sha != entry["new_sha256"] or len(current) != entry["new_size"] or
                    current_state[2] != int(entry["new_mode"], 8)): raise DeploymentError("unknown file cannot be deleted", EXIT_UNCERTAIN)
            _check_idle(policy, inspector, ops)
            _check_dependents(policy, inspector, ops)
            gate = lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops))
            _unlink_exact(target, entry["new_sha256"], entry["new_size"], int(entry["new_mode"], 8), live_scope, fault, f"rollback.{index}", lock, gate)
    _check_idle(policy, inspector, ops)
    _check_dependents(policy, inspector, ops)
    live_scope.fence(); journal["status"] = "rolled_back"
    gate = lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops), live_scope.fence())
    _replace_release_private(scope, policy["deployment"]["journal_name"], _canonical(journal), journal_raw, fault, "journal.rollback", lock, gate); live_scope.fence(EXIT_UNCERTAIN)
    return {"rolled_back": True, "release_id": expected_release_id, "secret_retained": True}


def _fresh_install_locked(policy, runtime, repo_root, blobs, secret_sha256, ops, inspector, fault, canary, lock, clock, scope, live_scope):
    _check_idle(policy, inspector, ops)
    _check_dependents(policy, inspector, ops)
    _write_new_release_private(scope, POLICY_ARCHIVE_NAME, manifest.canonical_source_policy_bytes(policy), fault, "policy.archive", lock)
    _write_new_release_private(scope, RUNTIME_ARCHIVE_NAME, manifest.canonical_runtime_release_bytes(runtime), fault, "runtime.archive", lock)
    install, entries, expected_states = _journal_entries(policy, runtime, blobs, live_scope, scope, fault, lock)
    journal = {"schema": JOURNAL_SCHEMA, "release_id": runtime["release_id"], "bundle_digest": runtime["bundle_digest"], "secret_sha256": secret_sha256, "status": "prepared", "entries": entries}
    journal_raw = _canonical(journal)
    _check_idle(policy, inspector, ops)
    _check_dependents(policy, inspector, ops)
    _check_window(policy, clock)
    _write_new_release_private(scope, policy["deployment"]["journal_name"], journal_raw, fault, "journal", lock)
    try:
        for index, ((target, data, mode), expected_state) in enumerate(zip(install, expected_states)):
            _check_idle(policy, inspector, ops)
            _check_dependents(policy, inspector, ops)
            _source_blobs(policy, runtime, repo_root, ops)
            _check_window(policy, clock)
            gate = lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops), _check_window(policy, clock))
            _atomic_replace(target, data, mode, live_scope, fault, f"install.{index}", lock, expected=expected_state, pre_publish=gate)
        _check_idle(policy, inspector, ops)
        _check_dependents(policy, inspector, ops)
        _canary_bundle_bytes(policy, runtime, ops, live_scope)
        if canary:
            _check_idle(policy, inspector, ops)
            _check_dependents(policy, inspector, ops)
            _check_window(policy, clock)
            live_scope.fence(); run_fake_canary(policy, runtime, ops=ops, _live_scope=live_scope); live_scope.fence()
        _check_idle(policy, inspector, ops)
        _check_dependents(policy, inspector, ops)
        _check_window(policy, clock)
        journal["status"] = "installed"
        live_scope.fence()
        gate = lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops), _check_window(policy, clock), live_scope.fence())
        _replace_release_private(scope, policy["deployment"]["journal_name"], _canonical(journal), journal_raw, fault, "journal.commit", lock, gate); live_scope.fence(EXIT_UNCERTAIN)
        return {"deployed": True, "release_id": runtime["release_id"], "bundle_digest": runtime["bundle_digest"]}
    except DeploymentError as error:
        if error.exit_code == EXIT_UNCERTAIN: raise
        try: _rollback_locked(policy, runtime["release_id"], ops, inspector, fault, lock, live_scope)
        except DeploymentError as rollback_error: raise DeploymentError("deploy and rollback outcome uncertain", EXIT_UNCERTAIN) from rollback_error
        raise DeploymentError("deployment failed and was fully rolled back", EXIT_ROLLED_BACK) from error


def _prepare_fresh_credentials(policy, provenance, ops, inspector, fault, lock, clock):
    _check_idle(policy, inspector, ops)
    _check_dependents(policy, inspector, ops)
    _check_window(policy, clock)
    if provenance["kind"] == "legacy":
        _migrate_credentials_from_bytes(policy, provenance["legacy_source"], ops=ops, fault=fault, _lock=lock,
                pre_publish=lambda: (_check_idle(policy, inspector, ops), _check_dependents(policy, inspector, ops), _check_window(policy, clock)))
        secret_sha256 = _reuse_canonical_credentials(policy, ops, lock)
    elif provenance["kind"] == "prior_runtime":
        secret_sha256 = _reuse_canonical_credentials(policy, ops, lock, provenance["prior_secret_sha256"])
    else:
        raise DeploymentError("new deployment lacks credential provenance", EXIT_CONFLICT)
    _check_window(policy, clock)
    return secret_sha256


def deploy_release(policy, runtime, repo_root, expected_release_id=None, *, ops=None, clock=None, process_inspector=None, fault=None, canary=True):
    ops, clock, inspector, fault = ops or Ops(), clock or Clock(), process_inspector or ProcessInspector(), fault or FaultInjector()
    policy, runtime = _policy(policy), _runtime(runtime)
    _check_production_python(policy, inspector)
    _check_unresolved_dependents(policy)
    _check_canary_interpreter()
    _check_repository(runtime, repo_root, inspector); _check_repository_policy(policy, runtime, repo_root, inspector, ops); blobs = _source_blobs(policy, runtime, repo_root, ops); _check_repository_bundle(runtime, repo_root, inspector, blobs)
    if expected_release_id is not None and runtime["release_id"] != expected_release_id: raise DeploymentError("expected release id mismatch", EXIT_INTEGRITY)
    with _acquire_lock(policy, ops) as lock:
        _check_window(policy, clock); _check_idle(policy, inspector, ops); _check_dependents(policy, inspector, ops)
        with _open_live_scope(policy, ops, lock) as live_scope:
            release_root = _join(policy["deployment"]["rollback_root"], runtime["release_id"])
            release_exists = ops.exists(release_root)
            if release_exists:
                _mkdir_private_locked(release_root, ops, lock)
                with _open_release_scope(policy, runtime["release_id"], ops, lock) as scope:
                    journal_exists = _reconcile_initial_journal(policy, runtime, scope, lock)
                    provenance = _check_live_baseline(policy, runtime, ops, live_scope, journal_exists, reject_same_release=True, lock=lock, repo_root=repo_root, inspector=inspector)
                    if journal_exists:
                        return _resume_existing_deploy_in_scope(policy, runtime, _install_plan(policy, runtime, blobs), ops, inspector, fault, canary, lock, clock, scope, live_scope, repo_root)
                    secret_sha256 = _prepare_fresh_credentials(policy, provenance, ops, inspector, fault, lock, clock)
                    return _fresh_install_locked(policy, runtime, repo_root, blobs, secret_sha256, ops, inspector, fault, canary, lock, clock, scope, live_scope)
            provenance = _check_live_baseline(policy, runtime, ops, live_scope, False, reject_same_release=True, lock=lock, repo_root=repo_root, inspector=inspector)
            secret_sha256 = _prepare_fresh_credentials(policy, provenance, ops, inspector, fault, lock, clock)
            _mkdir_private_locked(release_root, ops, lock)
            with _open_release_scope(policy, runtime["release_id"], ops, lock) as scope:
                return _fresh_install_locked(policy, runtime, repo_root, blobs, secret_sha256, ops, inspector, fault, canary, lock, clock, scope, live_scope)


def rollback_release(policy, expected_release_id, repo_root=None, *, ops=None, clock=None, process_inspector=None, fault=None):
    ops, clock, inspector, fault = ops or Ops(), clock or Clock(), process_inspector or ProcessInspector(), fault or FaultInjector(); policy = _policy(policy)
    _check_production_python(policy, inspector)
    if not re.fullmatch(r"spmrv1-[0-9a-f]{32}", expected_release_id): raise DeploymentError("invalid expected release id", EXIT_SCHEMA)
    _check_unresolved_dependents(policy)
    if repo_root is not None: _check_source_policy_repository(policy, repo_root, inspector, ops)
    elif isinstance(inspector, ProductionProcessInspector): raise DeploymentError("production rollback requires repository authority", EXIT_PROTOCOL)
    with _acquire_lock(policy, ops) as lock:
        _check_idle(policy, inspector, ops); _check_dependents(policy, inspector, ops)
        with _open_live_scope(policy, ops, lock) as live_scope:
            if repo_root is not None:
                with _open_release_scope(policy, expected_release_id, ops, lock) as scope:
                    archived_runtime = _read_archived_runtime_from_scope(expected_release_id, scope)
                    archived_policy = _read_archived_policy_from_scope(archived_runtime, scope)
                    try: manifest.verify_runtime_release(archived_policy, archived_runtime)
                    except manifest.ManifestError as error: raise DeploymentError("archived rollback authority differs", EXIT_UNCERTAIN) from error
                    _check_archived_runtime_repository(archived_policy, archived_runtime, repo_root, inspector)
                    _, journal = _read_journal_from_scope(archived_policy, expected_release_id, scope)
                    if journal["bundle_digest"] != archived_runtime["bundle_digest"]:
                        raise DeploymentError("rollback journal differs from runtime authority", EXIT_UNCERTAIN)
                    return _rollback_locked_in_scope(archived_policy, expected_release_id, ops, inspector, fault, lock, scope, live_scope)
            return _rollback_locked(policy, expected_release_id, ops, inspector, fault, lock, live_scope)


class _ExactCanarySourceLoader(importlib.machinery.SourceFileLoader):
    """Compile only the already verified installed bytes; never consult a pyc."""
    def __init__(self, fullname, path, exact_source):
        super().__init__(fullname, path); self._exact_source = exact_source
    def get_code(self, fullname):
        if fullname != self.name: raise ImportError("canary loader name mismatch")
        return self.source_to_code(self._exact_source, self.path)


def _canary_bundle_bytes(policy, runtime, ops, live_scope=None):
    if live_scope is None:
        with _open_live_scope(policy, ops) as owned:
            return _canary_bundle_bytes(policy, runtime, ops, owned)
    installed = {}
    for item in runtime["bundle"]:
        present, data, mode = live_scope.state(item["target"], expected_mode=int(item["mode"], 8), missing_ok=False)
        if not present or mode != int(item["mode"], 8): raise DeploymentError("canary deployed bundle metadata mismatch", EXIT_UNSAFE)
        if _sha(data) != item["sha256"] or len(data) != item["size"]:
            raise DeploymentError("canary deployed bundle mismatch", EXIT_INTEGRITY)
        installed[item["source"]] = (live_scope.absolute_path(item["target"]), data)
    runtime_target = policy["deployment"]["runtime_manifest_target"]
    present, runtime_bytes, mode = live_scope.state(runtime_target, expected_mode=0o644, missing_ok=False)
    if not present or mode != 0o644: raise DeploymentError("installed runtime manifest metadata mismatch", EXIT_UNSAFE)
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


def run_fake_canary(policy, runtime, *, ops=None, _live_scope=None):
    ops, policy, runtime = ops or Ops(), _policy(policy), _runtime(runtime)
    _check_canary_interpreter()
    binding_error = None
    try: manifest.verify_runtime_release(policy, runtime)
    except manifest.ManifestError: binding_error = DeploymentError("runtime release policy binding mismatch", EXIT_INTEGRITY)
    if binding_error is not None: raise binding_error from None
    if _live_scope is None:
        with _open_live_scope(policy, ops) as owned:
            return run_fake_canary(policy, runtime, ops=ops, _live_scope=owned)
    installed = _canary_bundle_bytes(policy, runtime, ops, _live_scope)
    normalized = None
    try:
        loader = _load_installed_canary_modules(installed)
        outbox, adapter = next(loader)
        try:
            record = outbox.create_record(repository="synthetic/report-delivery-canary", ref="refs/heads/report-delivery-canary", path="synthetic/report-delivery/canary.png", image_bytes=b"synthetic-image", primary_payload_bytes=b"synthetic-primary", changed_handles=("synthetic-handle",), primary_handles=("synthetic-handle",))
            with tempfile.TemporaryDirectory(prefix="sp-monitor-controlled-canary-") as temp:
                os.chmod(temp, 0o700)
                result = adapter.controlled_canary(os.path.realpath(os.path.join(temp, "store")), record)
            _canary_bundle_bytes(policy, runtime, ops, _live_scope)
        finally:
            try: next(loader)
            except StopIteration: pass
    except (DeploymentError, KeyboardInterrupt, SystemExit): raise
    except Exception: normalized = DeploymentError("bound controlled canary failed", EXIT_PROTOCOL)
    if normalized is not None: raise normalized from None
    if type(result) is not dict or result.get("state") != "complete" or result.get("reconcile_required") is not False: raise DeploymentError("controlled canary protocol mismatch", EXIT_PROTOCOL)
    return {"ok": True, "state": "complete", "reconcile_required": False}


def main(argv=None, *, ops=None, clock=None, process_inspector=None):
    parser = argparse.ArgumentParser(prog="deploy-sp-monitor-release-v1")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("verify-only", "deploy", "canary"):
        cmd = sub.add_parser(name); cmd.add_argument("--policy", required=True); cmd.add_argument("--runtime", required=True); cmd.add_argument("--repo-root", required=True); cmd.add_argument("--expected-release-id")
    rollback = sub.add_parser("rollback"); rollback.add_argument("--policy", required=True); rollback.add_argument("--repo-root", required=True); rollback.add_argument("--expected-release-id", required=True)
    migrate = sub.add_parser("migrate-only"); migrate.add_argument("--policy", required=True); migrate.add_argument("--repo-root", required=True)
    args = parser.parse_args(argv)
    process_inspector = process_inspector or ProductionProcessInspector()
    operation_ops = ops or Ops()
    try:
        policy = operation_ops.exact_state(args.policy, expected_mode=0o644)[1]
        if args.command == "migrate-only":
            result = migrate_credentials(policy, args.repo_root, ops=operation_ops, clock=clock, process_inspector=process_inspector)
            if (type(result) is not dict or set(result) != {"created", "reused"} or
                    type(result["created"]) is not bool or type(result["reused"]) is not bool or
                    result["created"] is result["reused"]):
                raise DeploymentError("migration result protocol mismatch", EXIT_PROTOCOL)
            sys.stdout.write(_canonical(result).decode("utf-8")); return 0
        if args.command == "rollback": rollback_release(policy, args.expected_release_id, args.repo_root, ops=operation_ops, clock=clock, process_inspector=process_inspector); return 0
        runtime = operation_ops.exact_state(args.runtime, expected_mode=0o600)[1]
        if args.command == "verify-only": verify_only(policy, runtime, args.repo_root, args.expected_release_id, ops=operation_ops, clock=clock, process_inspector=process_inspector); return 0
        if args.command == "canary":
            canary_ops, canary_clock = operation_ops, clock or Clock()
            parsed_policy = _policy(policy)
            with _open_live_scope(parsed_policy, canary_ops) as live_scope:
                verify_only(policy, runtime, args.repo_root, args.expected_release_id, ops=canary_ops, clock=canary_clock, process_inspector=process_inspector, _live_scope=live_scope)
                _check_idle(parsed_policy, process_inspector, canary_ops)
                _check_dependents(parsed_policy, process_inspector, canary_ops)
                _check_window(parsed_policy, canary_clock)
                run_fake_canary(parsed_policy, _runtime(runtime), ops=canary_ops, _live_scope=live_scope); return 0
        deploy_release(policy, runtime, args.repo_root, args.expected_release_id, ops=operation_ops, clock=clock, process_inspector=process_inspector); return 0
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
_migrate_credentials_from_bytes = _normalize_public(EXIT_STAGING)(_migrate_credentials_from_bytes)
migrate_credentials = _normalize_public(EXIT_STAGING)(migrate_credentials)
deploy_release = _normalize_public(EXIT_UNCERTAIN)(deploy_release)
rollback_release = _normalize_public(EXIT_UNCERTAIN)(rollback_release)
run_fake_canary = _normalize_public(EXIT_PROTOCOL)(run_fake_canary)


if __name__ == "__main__": raise SystemExit(main())


__all__ = ["verify_only", "migrate_credentials", "deploy_release", "rollback_release", "run_fake_canary", "main", "Ops", "Clock", "ProcessInspector", "ProductionProcessInspector", "FaultInjector", "DeploymentError"]
