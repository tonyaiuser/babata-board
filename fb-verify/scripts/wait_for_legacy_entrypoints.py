#!/usr/bin/env python3
"""Drain verifier entrypoints that started before the stable deploy gate."""

import argparse
import os
import pathlib
import re
import subprocess
import sys
import time


ENTRYPOINTS = (
    "deployment_entrypoint.sh",
    "run_daily_fb_verify.sh",
    "run_nightly_single_page_fb_verify.sh",
    "sync_deploy.sh",
)


def process_table():
    completed = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        try:
            rows.append((int(fields[0]), int(fields[1]), fields[2]))
        except ValueError:
            continue
    return rows


def ancestor_pids(rows):
    parents = {pid: ppid for pid, ppid, _ in rows}
    ancestors = {os.getpid()}
    current = os.getppid()
    while current > 0 and current not in ancestors:
        ancestors.add(current)
        current = parents.get(current, 0)
    return ancestors


def legacy_candidates(rows, deploy_roots, source_roots):
    excluded = ancestor_pids(rows)
    release_prefixes = [root + os.sep + "releases" + os.sep for root in deploy_roots]
    stable_prefixes = [root + os.sep for root in deploy_roots]
    source_syncs = [root + os.sep + "sync_deploy.sh" for root in source_roots]
    found = []
    for pid, _ppid, command in rows:
        if pid in excluded:
            continue
        deploy_entry = (
            (
                any(prefix in command for prefix in release_prefixes)
                or any(prefix in command for prefix in stable_prefixes)
            )
            and any(name in command for name in ENTRYPOINTS)
        )
        source_deploy = any(path in command for path in source_syncs)
        # launchd plists and operator docs commonly use ``cd ROOT &&
        # ./run_daily_fb_verify.sh``.  ps sees that relative executable rather
        # than an absolute prefix, so recognize it explicitly.  This is
        # intentionally conservative: a non-ancestor process claiming one of
        # these uniquely named entrypoints is drained instead of allowing a
        # release switch while it may still acquire an old mkdir lock.
        relative_entry = any(
            re.search(r"(?:^|[\s;&|])(?:\./)?" + re.escape(name) + r"(?:\s|$)", command)
            for name in ENTRYPOINTS
        )
        if deploy_entry or source_deploy or relative_entry:
            found.append((pid, command))
    return found


def write_test_ready(path):
    """Durably publish the test rendezvous only from an active drain wait."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write("ready\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--deploy-root", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)
    deploy_roots = {
        os.path.abspath(args.deploy_root), str(pathlib.Path(args.deploy_root).resolve())
    }
    source_roots = {
        os.path.abspath(args.source_root), str(pathlib.Path(args.source_root).resolve())
    }

    ready_raw = os.environ.get("FB_VERIFY_TEST_DRAIN_READY_FILE", "")
    ready = (
        pathlib.Path(ready_raw)
        if os.environ.get("FB_VERIFY_TEST_MODE") == "1" and ready_raw
        else None
    )
    ready_published = False

    deadline = time.monotonic() + args.timeout
    clear_rounds = 0
    last = []
    while time.monotonic() < deadline:
        rows = process_table()
        last = legacy_candidates(rows, deploy_roots, source_roots)
        if not last:
            clear_rounds += 1
            if clear_rounds >= 3:
                return 0
        else:
            clear_rounds = 0
            # This test-only signal is a synchronization guarantee, not an
            # early "drain helper started" marker.  Publishing it only after
            # we found a non-ancestor legacy candidate and verified the gate
            # still exists means a test may safely assert that the deployer is
            # alive, the stable entrypoints return 75, and the switch cannot
            # yet occur.  Production has no test environment and never takes
            # this branch.
            if ready is not None and not ready_published:
                gate = pathlib.Path(args.deploy_root) / ".deployment.gate"
                if os.path.lexists(gate):
                    write_test_ready(ready)
                    ready_published = True
        time.sleep(0.05)
    details = "; ".join(f"pid={pid} {command}" for pid, command in last)
    print(f"legacy FB verifier entrypoints did not drain: {details}", file=sys.stderr)
    return 75


if __name__ == "__main__":
    raise SystemExit(main())
