#!/usr/bin/env python3
"""Run one bounded pipeline step in its own process group.

The parent daily runner intentionally remains outside that group: timing out a
slow image fetch must never terminate its lock cleanup or FB verification work.
Child stdout/stderr are relayed immediately so stderr heartbeats remain visible
in launchd logs even though the shell later validates the captured stdout.
"""

import argparse
import math
import os
import signal
import subprocess
import sys
import threading
import time

MIN_TIMEOUT_SECONDS = 0.05
MAX_TIMEOUT_SECONDS = 3600
MIN_GRACE_SECONDS = 0
MAX_GRACE_SECONDS = 60
DAILY_MIN_TIMEOUT_SECONDS = 60
DAILY_MAX_TIMEOUT_SECONDS = 1200
DAILY_MIN_GRACE_SECONDS = 1
DAILY_MAX_GRACE_SECONDS = 30


def relay(source, destination):
    while True:
        # BufferedReader.read(size) may wait for size bytes or EOF. read1()
        # returns the bytes currently available from one raw read, which keeps
        # flushed stderr heartbeats visible while the child is still alive.
        chunk = source.read1(8192)
        if not chunk:
            return
        destination.buffer.write(chunk)
        destination.buffer.flush()


def process_group_exists(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Existing but not signalable is still an occupied PGID.
        return True
    return True


def process_group_has_live_members(pgid):
    """Probe a process group without reaping its session leader.

    killpg(..., 0) deliberately sees the unreaped zombie leader, which keeps
    the PGID identity pinned but cannot tell whether any runnable descendant
    remains.  macOS ps exposes PGID and process state without waitpid(), so we
    can distinguish an all-zombie group from one that still needs escalation.
    Only an observed target group whose every member is a zombie is considered
    quiescent. Missing, malformed or failed observations are conservatively
    treated as live.
    """
    try:
        completed = subprocess.run(
            ["/bin/ps", "-axo", "pgid=,stat="],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return True
    if completed.returncode != 0:
        return True
    saw_target_group = False
    for row in completed.stdout.splitlines():
        if not row.strip():
            continue
        fields = row.split(None, 1)
        if len(fields) != 2:
            return True
        try:
            row_pgid = int(fields[0])
        except ValueError:
            return True
        state = fields[1].strip()
        if not state:
            return True
        if row_pgid != pgid:
            continue
        saw_target_group = True
        if not state.startswith("Z"):
            return True
    return not saw_target_group


def terminate_process_group(process, grace_seconds):
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return

    deadline = time.monotonic() + grace_seconds
    needs_kill = True
    while True:
        if not process_group_has_live_members(pgid):
            needs_kill = False
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.05, remaining))
    if needs_kill:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    # Keep the session leader unreaped from the first group signal through the
    # final group disposition. Its zombie PID pins the PGID against reuse.
    process.wait()


def bounded_finite(parser, name, value, minimum, maximum):
    if not math.isfinite(value) or not minimum <= value <= maximum:
        parser.error(f"{name} must be finite and in [{minimum:g}, {maximum:g}] seconds")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--grace-seconds", type=float, default=10)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--daily-policy", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    bounded_finite(
        parser, "timeout", args.timeout_seconds, MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS
    )
    bounded_finite(parser, "grace", args.grace_seconds, MIN_GRACE_SECONDS, MAX_GRACE_SECONDS)
    if args.daily_policy:
        bounded_finite(
            parser,
            "daily image timeout",
            args.timeout_seconds,
            DAILY_MIN_TIMEOUT_SECONDS,
            DAILY_MAX_TIMEOUT_SECONDS,
        )
        bounded_finite(
            parser,
            "daily image grace",
            args.grace_seconds,
            DAILY_MIN_GRACE_SECONDS,
            DAILY_MAX_GRACE_SECONDS,
        )
    if args.validate_only:
        if args.command:
            parser.error("--validate-only does not accept a command")
        return 0
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")

    requested_signal = [None]

    def request_shutdown(signum, _frame):
        # Signal handlers only record the first request. Process-group I/O,
        # waiting and escalation stay in the ordinary main-loop context.
        if requested_signal[0] is None:
            requested_signal[0] = signum

    handled_signals = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    old_handlers = {signum: signal.getsignal(signum) for signum in handled_signals}
    for signum in handled_signals:
        signal.signal(signum, request_shutdown)

    process = None
    stdout_thread = None
    stderr_thread = None
    timed_out = False
    interrupted_signal = None
    try:
        process = subprocess.Popen(
            args.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout_thread = threading.Thread(target=relay, args=(process.stdout, sys.stdout), daemon=True)
        stderr_thread = threading.Thread(target=relay, args=(process.stderr, sys.stderr), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        deadline = time.monotonic() + args.timeout_seconds
        while True:
            if requested_signal[0] is not None:
                interrupted_signal = requested_signal[0]
                print(
                    f"[watchdog] received signal {interrupted_signal}; "
                    "terminating image child process group only",
                    file=sys.stderr,
                    flush=True,
                )
                terminate_process_group(process, args.grace_seconds)
                break
            child_status = process.poll()
            # A handler may run while poll() observes/reaps a natural exit.
            # The recorded external signal still owns the wrapper's outcome.
            if requested_signal[0] is not None:
                interrupted_signal = requested_signal[0]
                break
            if child_status is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                print(
                    f"[watchdog] timeout after {args.timeout_seconds:.1f}s; "
                    "terminating image child process group only",
                    file=sys.stderr,
                    flush=True,
                )
                terminate_process_group(process, args.grace_seconds)
                break
            # Sleep rather than wait(timeout): wait may reap a natural exit at
            # the same instant an external signal is recorded, losing the
            # leader identity before signal handling gets priority.
            time.sleep(min(remaining, 0.05))
    except BaseException:
        if process is not None and process.poll() is None:
            terminate_process_group(process, args.grace_seconds)
        raise
    finally:
        # After wait()/terminate_process_group() the child has closed its ends;
        # let relay threads drain the final buffered summary before closing.
        if stdout_thread is not None:
            stdout_thread.join(timeout=2)
        if stderr_thread is not None:
            stderr_thread.join(timeout=2)
        if process is not None and process.stdout:
            process.stdout.close()
        if process is not None and process.stderr:
            process.stderr.close()
        for signum, old_handler in old_handlers.items():
            signal.signal(signum, old_handler)

    # Once the custom handlers are restored no later signal can update this
    # flag. This final read closes the tiny race between the last loop check
    # and a simultaneous natural child exit.
    if interrupted_signal is None and requested_signal[0] is not None:
        interrupted_signal = requested_signal[0]
    if interrupted_signal is not None:
        return 128 + interrupted_signal
    if timed_out:
        return 124
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
