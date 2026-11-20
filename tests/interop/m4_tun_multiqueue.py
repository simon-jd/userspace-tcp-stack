"""Check bytes and same-device FD attachments on an isolated Linux TUN."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import socket
import sys
from threading import Barrier
from time import monotonic, sleep

FLOWS = 8
BYTES = 196_691
IDLE_SECONDS = 7


def exchange(sock, phase, flow, gate):
    payload = hashlib.shake_256(f"{phase}/{flow}".encode()).digest(BYTES)
    # All sockets have established before phase one, and all start sending
    # together again after the idle interval.
    gate.wait(timeout=3)
    sock.sendall(payload)
    received = bytearray()
    while len(received) < len(payload):
        chunk = sock.recv(len(payload) - len(received))
        assert chunk, "unexpected EOF"
        received.extend(chunk)
    assert received == payload
    return hashlib.sha256(received).hexdigest()


def exercise(pid, port, count):
    info = Path(f"/proc/{pid}/fdinfo")
    fds = sorted(int(fd.name) for fd in info.iterdir()
                 if ("iff:\tutcp0" in fd.read_text().splitlines()))
    ifindex = socket.if_nametoindex("utcp0")
    tun_rx = sorted(p.name for p in Path("/sys/class/net/utcp0/queues").glob("rx-*"))
    tun_tx = sorted(p.name for p in Path("/sys/class/net/utcp0/queues").glob("tx-*"))
    flags = int(Path("/sys/class/net/utcp0/tun_flags").read_text(), 16)
    assert bool(flags & 0x0100) == (count != "default"), hex(flags)
    expected = 1 if count == "default" else int(count)
    assert len(fds) == len(tun_rx) == len(tun_tx) == expected, (fds, tun_rx, tun_tx)
    print(json.dumps({"count": count, "ifindex": ifindex, "fds": fds,
                      "rx_queues": tun_rx, "tx_queues": tun_tx,
                      "tun_flags": hex(flags)}), flush=True)

    socks = []
    try:
        for i in range(FLOWS):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socks.append(sock)
            sock.settimeout(5)
            sock.bind(("198.18.0.1", 32000 + (port - 5125) * FLOWS + i))
            sock.connect(("198.18.0.2", port))
        tuples = [(sock.getsockname(), sock.getpeername()) for sock in socks]

        with ThreadPoolExecutor(max_workers=FLOWS) as pool:
            for phase in (1, 2):
                gate = Barrier(FLOWS)
                done = [pool.submit(exchange, sock, phase, i, gate)
                        for i, sock in enumerate(socks)]
                digests = [job.result() for job in done]
                assert tuples == [(sock.getsockname(), sock.getpeername()) for sock in socks]
                print(json.dumps({"phase": phase, "tuples": tuples,
                                  "bytes_per_flow": BYTES, "sha256": digests}), flush=True)
                if phase == 1:
                    idle_started = monotonic()
                    sleep(IDLE_SECONDS)
                    print(json.dumps({"idle_seconds": monotonic() - idle_started}), flush=True)
        for sock in socks:
            sock.shutdown(socket.SHUT_WR)
            assert not sock.recv(1)
    finally:
        for sock in socks:
            sock.close()


def verify(prefix, mode, count):
    app = json.loads(Path(prefix + ".app").read_text())
    stats = json.loads(Path(prefix + ".stats").read_text())
    features = dict(line.strip().split(": ", 1) for line in
                    Path(prefix + ".features").read_text().splitlines() if ": " in line)
    expected = 1 if count == "default" else int(count)
    assert app["accepted"] == app["closed"] == FLOWS, app
    assert app["errors"] == 0 and app["bytes"] == 2 * FLOWS * BYTES, app
    assert stats["dev_tun_offload"] == mode
    assert stats["dev_vnet_hdr_size"] == (0 if mode == "legacy" else 10)
    assert stats["dev_rx_vnet_drops"] == stats["dev_rx_errors"] == stats["dev_tx_errors"] == 0
    assert stats["TcpInCsumErrors"] == 0
    assert features["tx-checksum-ip-generic"].split()[0] == ("off" if mode == "legacy" else "on")
    assert features["tx-tcp-segmentation"].split()[0] == ("on" if mode == "tcpv4" else "off")
    assert bool(stats["dev_rx_csum_valid"] + stats["dev_rx_csum_partial"]) == (mode != "legacy")
    assert bool(stats["dev_tx_csum_partial"]) == (mode != "legacy")
    assert stats["dev_tun_multi_queue"] == (count != "default")
    assert stats["dev_tun_ifindex"] > 0
    assert stats["dev_tun_queues"] == expected
    for direction in ("rx", "tx"):
        queues = [stats[f"dev_{direction}_queue_{i}_datagrams"] for i in range(expected)]
        assert sum(queues) == stats[f"dev_{direction}_datagrams"]
        assert sum(dgrams > 0 for dgrams in queues) >= min(expected, 2), queues
    print(json.dumps({"summary": app, **{k: v for k, v in stats.items() if k.startswith("dev_")}}))


if __name__ == "__main__":
    if sys.argv[1] == "exercise":
        exercise(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    elif sys.argv[1] == "verify":
        verify(*sys.argv[2:])

