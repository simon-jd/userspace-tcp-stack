#!/usr/bin/env python3
"""Exercise the held echo client over real Linux sockets inside an isolated container."""

import json
import select
import selectors
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main(binary, corrupt):
    with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        args = [binary, "--backend", "kernel", "--connect", f"127.0.0.1:{port}",
                "--connections", "4", "--concurrency", "4", "--open-batch", "1",
                "--size", "64", "--count", "1", "--rate", "100",
                "--load-control", directory, "--load-report"]
        with subprocess.Popen(args, stdout=subprocess.PIPE, bufsize=0) as client:
            try:
                exercise(client, Path(directory), listener, corrupt)
            finally:
                if client.poll() is None:
                    client.kill()


def exercise(client, control, listener, corrupt):
    with selectors.DefaultSelector() as selector:
        selector.register(client.stdout, selectors.EVENT_READ)

        def wait_for(phase):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if not selector.select(timeout=max(0, deadline - time.monotonic())):
                    break
                raw = client.stdout.readline()
                assert raw, f"client ended before phase {phase}"
                event = json.loads(raw)
                if event.get("phase") == phase or event.get("ev") == phase:
                    return event
            raise AssertionError(f"no client report for {phase}")

        assert wait_for("baseline")["open"] == 0
        (control / "open").touch()
        peers = []
        try:
            for _ in range(4):
                connection, _ = listener.accept()
                connection.settimeout(5)
                peers.append(connection)
            idle = wait_for("idle")
            assert idle["established"] == 4 and idle["requests_started"] == 0

            # One full report later, all sockets must still be idle and open.
            held = wait_for("idle")
            assert held["established"] == 4 and held["requests_started"] == 0
            assert not select.select(peers, [], [], 0)[0], "socket became readable before active gate"
            (control / "active").touch()
            for connection in peers:
                request = bytearray()
                while len(request) < 64:
                    part = connection.recv(64 - len(request))
                    assert part, "client closed before sending a complete request"
                    request.extend(part)
                if corrupt:
                    request[0] ^= 0xff
                    connection.sendall(request)
                    summary = wait_for("summary")
                    assert not summary["ok"] and summary["mismatches"] == 1
                    assert summary["requests_ok"] == 0 and client.wait(timeout=5) == 1
                    return
                connection.sendall(request)

            drained = wait_for("drained")
            assert drained["established"] == 4 and drained["requests_ok"] == 4
            assert not select.select(peers, [], [], 0)[0], "socket closed before release gate"
            (control / "close").touch()
            summary = wait_for("summary")
            assert summary["ok"] and summary["connections_ok"] == 4
            assert summary["bytes"] == 256 and summary["latency_p50_ns"] > 0
            assert all(peer.recv(1) == b"" for peer in peers)
            assert client.wait(timeout=5) == 0
        finally:
            for connection in peers:
                connection.close()


if __name__ == "__main__":
    main(sys.argv[1], corrupt=False)
    main(sys.argv[1], corrupt=True)
