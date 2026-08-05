"""Pure source-policy and runtime-release manifest primitives for SP monitor v1."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

SOURCE_SCHEMA = "sp-monitor-source-policy/v1"
RUNTIME_SCHEMA = "sp-monitor-runtime-release/v1"
POLICY_TOP = {"schema", "policy_name", "runtime_schema", "repository", "baseline", "bundle", "deployment"}
RUNTIME_TOP = {"schema", "policy", "repository", "bundle", "bundle_digest", "release_id"}
EXACT_BUNDLE = (
    ("helper", "scripts/report_delivery_outbox_v1.py", "scripts/report_delivery_outbox_v1.py", "0644"),
    ("helper", "scripts/report_delivery_adapters_v1.py", "scripts/report_delivery_adapters_v1.py", "0644"),
    ("entrypoint", "skills/sp-monitor/run.py", "run.py", "0644"),
)
EXACT_DEPLOYMENT_PATHS = {
    "live_root": "~/.openclaw/workspace/skills/sp-monitor",
    "secret_path": "~/.openclaw/secrets/sp-monitor/report_delivery.json",
    "rollback_root": "~/.spspy-code-backups/sp-monitor",
    "lock_path": "~/.spspy-code-backups/.sp-monitor-release.lock",
    "policy_path": "config/sp_monitor_release_manifest_v1.json",
    "runtime_manifest_target": "runtime-release.json",
    "journal_name": "release-journal.json",
}
EXACT_DEPENDENTS = (
    ("single-page-monitor", "com.spspy.single-page-monitor"),
    ("fb-verify", "com.spspy.fb-verify"),
    ("single-page-fb-nightly", "com.spspy.single-page-fb-nightly"),
)
EXACT_MAIN_PLIST = {
    "label": "ai.openclaw.sp.morning",
    "interpreter": "/opt/homebrew/bin/python3",
    "entrypoint": "~/.openclaw/workspace/skills/sp-monitor/run.py",
    "arguments": ["--send"],
    "entrypoint_index": 1,
    "plist_keys": ["EnvironmentVariables", "Label", "ProgramArguments", "RunAtLoad", "StandardErrorPath", "StandardOutPath", "StartCalendarInterval"],
    "environment_variable_keys": ["HOME", "OPENCLAW_BIN", "PATH"],
    "calendar": {"Hour": 11, "Minute": 30},
    "run_at_load": False,
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class ManifestError(Exception):
    exit_code = 64


class ManifestSchemaError(ManifestError): pass
class ManifestHashError(ManifestError): exit_code = 65
class ManifestMissingError(ManifestError): exit_code = 66


def _load_json_bytes(value, what):
    if type(value) is not bytes: raise ManifestSchemaError(f"{what} must be bytes")
    if value.startswith(b"\xef\xbb\xbf"): raise ManifestSchemaError(f"{what} has a BOM")
    try: text = value.decode("utf-8")
    except UnicodeDecodeError as error: raise ManifestSchemaError(f"{what} is not UTF-8") from error
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result: raise ManifestSchemaError(f"duplicate key in {what}")
            result[key] = item
        return result
    try: return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ManifestSchemaError("non-finite JSON")))
    except ManifestError: raise
    except (ValueError, TypeError, RecursionError) as error: raise ManifestSchemaError(f"invalid {what} JSON") from error


def _dict(value, keys, what):
    if type(value) is not dict or set(value) != set(keys): raise ManifestSchemaError(f"invalid {what} fields")
    return value


def _text(value, what):
    if type(value) is not str or not value or any(ord(c) < 32 for c in value): raise ManifestSchemaError(f"invalid {what}")
    return value


def _sha(value, what):
    value = _text(value, what)
    if not HEX64.fullmatch(value): raise ManifestSchemaError(f"invalid {what}")
    return value


def _relpath(value, what):
    value = _text(value, what)
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or any(part in ("", ".", "..") for part in parts): raise ManifestSchemaError(f"unsafe {what}")
    return value


def _fixed_path(value, what):
    value = _text(value, what)
    if value == "REQUIRED_AT_DEPLOY": return value
    expanded = value[2:] if value.startswith("~/") else value.lstrip("/")
    if not (value.startswith("~/") or value.startswith("/")) or "\\" in value or any(part in ("", ".", "..") for part in expanded.split("/")):
        raise ManifestSchemaError(f"unsafe {what}")
    return value


def _validate_source_files(value, what, unresolved=False):
    if type(value) is not list or not value: raise ManifestSchemaError(f"invalid {what}")
    paths = []
    for item in value:
        _dict(item, {"path", "sha256"}, what + " item")
        path = _fixed_path(item["path"], what + " path"); digest = item["sha256"]
        if digest != "REQUIRED_AT_DEPLOY": _sha(digest, what + " SHA-256")
        if not unresolved and (path == "REQUIRED_AT_DEPLOY" or digest == "REQUIRED_AT_DEPLOY"): raise ManifestSchemaError(f"unresolved {what}")
        paths.append(path)
    if len(paths) != len(set(paths)): raise ManifestSchemaError(f"duplicate {what} path")
    return value


def _validate_dependency(item):
    _dict(item, {"name", "source_files", "plist_sha256", "labels", "configured_argv", "process_match_tokens", "unresolved"}, "dependent consumer")
    _text(item["name"], "consumer name")
    if type(item["unresolved"]) is not bool: raise ManifestSchemaError("invalid unresolved flag")
    _validate_source_files(item["source_files"], "source_files", item["unresolved"])
    if item["plist_sha256"] != "REQUIRED_AT_DEPLOY": _sha(item["plist_sha256"], "plist_sha256")
    argv = item["configured_argv"]
    tokens = item["process_match_tokens"]
    if type(argv) is not list or not argv or any(type(x) is not str or not x for x in argv): raise ManifestSchemaError("invalid dependent configured argv")
    if type(tokens) is not list or not tokens or any(type(x) is not str or not x for x in tokens): raise ManifestSchemaError("invalid dependent process match tokens")
    if len(tokens) != len(set(tokens)): raise ManifestSchemaError("duplicate dependent process match token")
    if argv != ["REQUIRED_AT_DEPLOY"] and (argv[:2] != ["/bin/bash", "-lc"] or len(argv) != 3): raise ManifestSchemaError("invalid dependent wrapper argv")
    if tokens != ["REQUIRED_AT_DEPLOY"] and ("/bin/bash" in tokens or (argv != ["REQUIRED_AT_DEPLOY"] and argv[2] not in tokens)):
        raise ManifestSchemaError("invalid dependent process identity contract")
    unresolved_values = item["plist_sha256"] == "REQUIRED_AT_DEPLOY" or argv == ["REQUIRED_AT_DEPLOY"] or tokens == ["REQUIRED_AT_DEPLOY"]
    if not item["unresolved"]:
        if unresolved_values: raise ManifestSchemaError("invalid resolved dependent process contract")
    elif not unresolved_values and all(source["path"] != "REQUIRED_AT_DEPLOY" and source["sha256"] != "REQUIRED_AT_DEPLOY" for source in item["source_files"]):
        raise ManifestSchemaError("unresolved dependent lacks explicit placeholder")
    if type(item["labels"]) is not list or not item["labels"] or any(type(x) is not str or not x for x in item["labels"]): raise ManifestSchemaError("invalid consumer labels")


def _validate_policy(policy):
    _dict(policy, POLICY_TOP, "source policy")
    if policy["schema"] != SOURCE_SCHEMA or policy["runtime_schema"] != RUNTIME_SCHEMA: raise ManifestSchemaError("unsupported schema")
    _text(policy["policy_name"], "policy_name")
    repo = _dict(policy["repository"], {"required_ref"}, "repository policy")
    if repo["required_ref"] != "refs/heads/main": raise ManifestSchemaError("repository ref must be refs/heads/main")
    baseline = _dict(policy["baseline"], {"live_entrypoint_sha256"}, "baseline")
    _sha(baseline["live_entrypoint_sha256"], "baseline SHA-256")
    if type(policy["bundle"]) is not list or len(policy["bundle"]) != 3: raise ManifestSchemaError("bundle must contain exact three entries")
    actual = []
    for item in policy["bundle"]:
        _dict(item, {"role", "source", "target", "mode"}, "bundle policy item")
        actual.append((_text(item["role"], "role"), _relpath(item["source"], "source"), _relpath(item["target"], "target"), item["mode"]))
    if tuple(actual) != EXACT_BUNDLE: raise ManifestSchemaError("bundle mapping/order is not the frozen exact3")
    dep = _dict(policy["deployment"], {"allow_window", "credential_names", "dependent_consumers", "journal_name", "live_root", "lock_path", "plist", "policy_path", "rollback_root", "runtime_manifest_target", "secret_path"}, "deployment")
    if dep["credential_names"] != ["DINGTALK_WEBHOOK", "DINGTALK_SECRET"]: raise ManifestSchemaError("credential Name inventory differs")
    for key, expected in EXACT_DEPLOYMENT_PATHS.items():
        if dep[key] != expected: raise ManifestSchemaError(f"frozen deployment path differs: {key}")
    window = _dict(dep["allow_window"], {"timezone", "start", "end"}, "allow window")
    clock_time = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")
    if (type(window["timezone"]) is not str or window["timezone"] != "Asia/Shanghai" or
            type(window["start"]) is not str or clock_time.fullmatch(window["start"]) is None or
            type(window["end"]) is not str or clock_time.fullmatch(window["end"]) is None):
        raise ManifestSchemaError("invalid allow window")
    plist = _dict(dep["plist"], {"label", "interpreter", "entrypoint", "arguments", "entrypoint_index", "plist_keys", "environment_variable_keys", "calendar", "run_at_load", "plist_sha256"}, "plist policy")
    if (type(plist["label"]) is not str or type(plist["interpreter"]) is not str or type(plist["entrypoint"]) is not str or
            type(plist["arguments"]) is not list or any(type(value) is not str for value in plist["arguments"]) or
            type(plist["entrypoint_index"]) is not int or type(plist["plist_keys"]) is not list or any(type(value) is not str for value in plist["plist_keys"]) or
            type(plist["environment_variable_keys"]) is not list or any(type(value) is not str for value in plist["environment_variable_keys"]) or
            type(plist["calendar"]) is not dict or set(plist["calendar"]) != {"Hour", "Minute"} or
            any(type(plist["calendar"][key]) is not int for key in ("Hour", "Minute")) or type(plist["run_at_load"]) is not bool):
        raise ManifestSchemaError("invalid exact plist policy types")
    if {key: plist[key] for key in EXACT_MAIN_PLIST} != EXACT_MAIN_PLIST: raise ManifestSchemaError("plist execution policy differs from frozen value")
    _sha(plist["plist_sha256"], "main plist SHA-256")
    consumers = dep["dependent_consumers"]
    if type(consumers) is not list or [(x.get("name"), x.get("labels")) if type(x) is dict else None for x in consumers] != [(name, [label]) for name, label in EXACT_DEPENDENTS]: raise ManifestSchemaError("dependent consumer inventory differs")
    for item in consumers: _validate_dependency(item)
    install_targets = [item["target"] for item in policy["bundle"]] + [dep["runtime_manifest_target"]]
    if len(set(install_targets)) != 4: raise ManifestSchemaError("installation targets must be unique")
    split_targets = [target.split("/") for target in install_targets]
    for index, left in enumerate(split_targets):
        for right in split_targets[index + 1:]:
            if left == right[:len(left)] or right == left[:len(right)]: raise ManifestSchemaError("installation targets have an ancestor conflict")
    forbidden = {"head", "source_hash", "source_sha256", "size", "policy_sha256", "release_id", "timestamp", "time"}
    for key in policy:
        if key.lower() in forbidden: raise ManifestSchemaError("dynamic value present in source policy")
    return policy


def parse_source_policy(value):
    return _validate_policy(_load_json_bytes(value, "source policy"))


def canonical_source_policy_bytes(policy):
    _validate_policy(policy)
    return json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def source_policy_sha256(policy): return hashlib.sha256(canonical_source_policy_bytes(policy)).hexdigest()


def _canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def build_runtime_release(policy, repo_commit, source_blobs):
    _validate_policy(policy)
    if type(repo_commit) is not str or not COMMIT.fullmatch(repo_commit): raise ManifestSchemaError("invalid repository commit")
    expected = [entry[1] for entry in EXACT_BUNDLE]
    if type(source_blobs) is not dict or set(source_blobs) != set(expected) or any(type(source_blobs[x]) is not bytes for x in expected): raise ManifestSchemaError("source_blobs must be the exact3 mapping")
    bundle = []
    for (role, source, target, mode) in EXACT_BUNDLE:
        blob = source_blobs[source]
        bundle.append({"role": role, "source": source, "target": target, "mode": mode, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()})
    core = {"schema": RUNTIME_SCHEMA, "policy": {"path": policy["deployment"]["policy_path"], "sha256": source_policy_sha256(policy)}, "repository": {"ref": policy["repository"]["required_ref"], "commit": repo_commit}, "bundle": bundle, "bundle_digest": hashlib.sha256(_canonical(bundle)).hexdigest()}
    release_id = "spmrv1-" + hashlib.sha256(_canonical(core)).hexdigest()[:32]
    return {**core, "release_id": release_id}


def _validate_runtime(runtime):
    _dict(runtime, RUNTIME_TOP, "runtime release")
    if runtime["schema"] != RUNTIME_SCHEMA: raise ManifestSchemaError("unsupported runtime schema")
    policy = _dict(runtime["policy"], {"path", "sha256"}, "runtime policy pointer")
    _relpath(policy["path"], "policy path"); _sha(policy["sha256"], "policy SHA-256")
    repo = _dict(runtime["repository"], {"ref", "commit"}, "runtime repository")
    if repo["ref"] != "refs/heads/main" or type(repo["commit"]) is not str or not COMMIT.fullmatch(repo["commit"]): raise ManifestSchemaError("invalid runtime repository")
    if type(runtime["bundle"]) is not list or len(runtime["bundle"]) != 3: raise ManifestSchemaError("invalid runtime bundle")
    frozen = []
    for item in runtime["bundle"]:
        _dict(item, {"role", "source", "target", "mode", "size", "sha256"}, "runtime bundle item")
        if type(item["size"]) is not int or item["size"] < 0: raise ManifestSchemaError("invalid source size")
        _sha(item["sha256"], "source SHA-256")
        frozen.append((item["role"], item["source"], item["target"], item["mode"]))
    if tuple(frozen) != EXACT_BUNDLE: raise ManifestSchemaError("runtime bundle mapping/order differs")
    _sha(runtime["bundle_digest"], "bundle digest")
    if not re.fullmatch(r"spmrv1-[0-9a-f]{32}", runtime["release_id"]): raise ManifestSchemaError("invalid release id")
    core = {k: runtime[k] for k in ("schema", "policy", "repository", "bundle", "bundle_digest")}
    if runtime["bundle_digest"] != hashlib.sha256(_canonical(runtime["bundle"])).hexdigest(): raise ManifestHashError("bundle digest mismatch")
    if runtime["release_id"] != "spmrv1-" + hashlib.sha256(_canonical(core)).hexdigest()[:32]: raise ManifestHashError("release id mismatch")
    return runtime


def canonical_runtime_release_bytes(runtime):
    _validate_runtime(runtime); return _canonical(runtime)


def parse_runtime_release(value):
    runtime = _validate_runtime(_load_json_bytes(value, "runtime release"))
    if canonical_runtime_release_bytes(runtime) != value: raise ManifestSchemaError("runtime release is not canonical")
    return runtime


def runtime_release_sha256(runtime): return hashlib.sha256(canonical_runtime_release_bytes(runtime)).hexdigest()


def verify_runtime_release(policy, runtime, source_blobs=None, repo_commit=None):
    _validate_policy(policy); _validate_runtime(runtime)
    if runtime["policy"] != {"path": policy["deployment"]["policy_path"], "sha256": source_policy_sha256(policy)}: raise ManifestHashError("runtime policy pointer mismatch")
    if runtime["repository"]["ref"] != policy["repository"]["required_ref"]: raise ManifestHashError("runtime ref mismatch")
    if repo_commit is not None and runtime["repository"]["commit"] != repo_commit: raise ManifestHashError("runtime commit mismatch")
    if source_blobs is not None and build_runtime_release(policy, runtime["repository"]["commit"], source_blobs) != runtime: raise ManifestHashError("runtime source inventory mismatch")
    return True


def _read(path):
    try: return Path(path).read_bytes()
    except FileNotFoundError as error: raise ManifestMissingError("required file is missing") from error


def _write_exclusive_outside_repo(path, repo_root, value):
    output = Path(path).resolve(strict=False); root = Path(repo_root).resolve(strict=True)
    if output == root or root in output.parents: raise ManifestSchemaError("runtime output must be outside repository")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(output, flags, 0o600)
    try:
        offset = 0
        while offset < len(value): offset += os.write(fd, value[offset:])
        os.fsync(fd)
    finally: os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sp-monitor-release-manifest-v1")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-policy"); validate.add_argument("--policy", required=True)
    build = sub.add_parser("build-runtime"); build.add_argument("--policy", required=True); build.add_argument("--repo-root", required=True); build.add_argument("--repo-commit", required=True); build.add_argument("--output", required=True)
    verify = sub.add_parser("verify-runtime"); verify.add_argument("--policy", required=True); verify.add_argument("--runtime", required=True); verify.add_argument("--repo-root")
    args = parser.parse_args(argv)
    try:
        policy = parse_source_policy(_read(args.policy))
        if args.command == "validate-policy": canonical_source_policy_bytes(policy); return 0
        if args.command == "build-runtime":
            blobs = {source: _read(Path(args.repo_root) / source) for _, source, _, _ in EXACT_BUNDLE}
            runtime = build_runtime_release(policy, args.repo_commit, blobs)
            _write_exclusive_outside_repo(args.output, args.repo_root, canonical_runtime_release_bytes(runtime)); return 0
        runtime = parse_runtime_release(_read(args.runtime))
        blobs = None if args.repo_root is None else {source: _read(Path(args.repo_root) / source) for _, source, _, _ in EXACT_BUNDLE}
        verify_runtime_release(policy, runtime, blobs); return 0
    except ManifestError as error:
        print(f"ERROR[{error.exit_code}]: {error}", file=sys.stderr); return error.exit_code
    except (KeyboardInterrupt, SystemExit): raise
    except Exception:
        print("ERROR[70]: internal/resource failure", file=sys.stderr); return 70


if __name__ == "__main__": raise SystemExit(main())


__all__ = ["parse_source_policy", "canonical_source_policy_bytes", "source_policy_sha256", "build_runtime_release", "canonical_runtime_release_bytes", "parse_runtime_release", "runtime_release_sha256", "verify_runtime_release", "ManifestError", "ManifestSchemaError", "ManifestHashError", "ManifestMissingError", "main"]
