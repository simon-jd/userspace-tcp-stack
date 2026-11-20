"""Exec one timed application in its container and reap it with Linux wait4."""

import glob
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def listen_ready(pid, backend, port):
    if backend == "utcp":
        for path in glob.glob(f"/proc/{pid}/fdinfo/*"):
            try:
                if "iff:\tutcp0\n" in Path(path).read_text():
                    return True
            except FileNotFoundError:
                continue
        return False
    sockets = set()
    for path in Path(f"/proc/{pid}/fd").iterdir():
        try:
            socket = os.readlink(path)
            if socket.startswith("socket:["):
                sockets.add(socket[8:-1])
        except FileNotFoundError:
            continue
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        parts = line.split()
        if parts[3] == "0A" and int(parts[1].split(":")[1], 16) == port and parts[9] in sockets:
            return True
    return False


def run(directory, role, timeout, argv, backend=None, port=None):
    start = time.monotonic_ns()
    timed_out = False
    with (directory / f"{role}.stdout").open("wb") as stdout, \
         (directory / f"{role}.stderr").open("wb") as stderr:
        child = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
        affinity = sorted(os.sched_getaffinity(child.pid))

        def kill_on_timeout(_signum, _frame):
            nonlocal timed_out
            timed_out = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        signal.signal(signal.SIGALRM, kill_on_timeout)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            if backend:
                while not (observed := os.wait4(child.pid, os.WNOHANG))[0]:
                    if listen_ready(child.pid, backend, port):
                        # TUN attachment precedes completion of stack listen setup.
                        if backend == "utcp":
                            time.sleep(0.1)
                        (directory / "listener.ready").write_text(f"{child.pid} {backend}\n")
                        break
                    time.sleep(0.01)
                if not observed[0]:
                    observed = os.wait4(child.pid, 0)
            else:
                observed = os.wait4(child.pid, 0)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        _, raw, usage = observed
        child.returncode = os.waitstatus_to_exitcode(raw)
    data = {"argv": argv, "pid": child.pid, "status": child.returncode, "timed_out": timed_out,
            "user_s": usage.ru_utime, "sys_s": usage.ru_stime, "max_rss_kib": usage.ru_maxrss,
            "voluntary_ctxt": usage.ru_nvcsw, "involuntary_ctxt": usage.ru_nivcsw,
            "affinity": affinity, "wall_ns": time.monotonic_ns() - start}
    (directory / f"{role}.usage.json").write_text(json.dumps(data) + "\n")
    return child.returncode


if __name__ == "__main__":
    directory, role, timeout, *argv = sys.argv[1:]
    backend, port = (argv.pop(0), int(argv.pop(0))) if role == "recv" else (None, None)
    status = run(Path(directory), role, float(timeout), argv, backend, port)
    sys.exit(status if status >= 0 else 128 - status)
