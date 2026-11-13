#!/usr/bin/env python3
"""HTTP/1.1 test server for utcp-http-get (DESIGN §9, m1-apps test 3).

Serves the files under --root in framings nginx does not produce:
  /chunked/NAME  Transfer-Encoding: chunked, chunk sizes from a seeded random
                 sequence (1 byte to 64 KiB), chunk extensions (token and
                 quoted-string values) on every chunk and on the last chunk,
                 and two trailer fields.
  /close/NAME    no Content-Length or Transfer-Encoding: the body ends when
                 the server closes the connection (RFC 9112 §6.3 item 8).
  /redirect/NAME 302 with Location: /chunked/NAME.
  /continue/NAME a 100 Continue interim response, then the chunked body.
Anything else is 404. Every response closes the connection.

With --dns-port P it also answers DNS A queries on UDP port P for any name
with --dns-addr (a stub for utcp-http-get --dns), the answer name written as
a compression pointer to the question (RFC 1035 §4.1.4).
"""
import argparse
import os
import random
import socket
import socketserver
import struct
import threading


def read_head(sock):
    data = b""
    while b"\r\n\r\n" not in data and b"\n\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > 65536:
            return None
    return data


class Handler(socketserver.BaseRequestHandler):
    def send_chunked(self, body, seed):
        rng = random.Random(seed)
        out = self.request
        pos = 0
        n = 0
        while pos < len(body):
            size = min(len(body) - pos, rng.choice([1, 2, 7, 100, 1000, 4096, 65536, rng.randint(1, 65536)]))
            # RFC 9112 §7.1.1: chunk-ext = *( BWS ";" BWS name [ BWS "=" BWS value ] )
            ext = f';n={n};note="chunk \\"{n}\\""' if n % 2 == 0 else f" ; plain ; w = {n}"
            out.sendall(b"%x%s\r\n" % (size, ext.encode()) + body[pos:pos + size] + b"\r\n")
            pos += size
            n += 1
        out.sendall(b'0;last="yes"\r\nX-Chunks: %d\r\nX-Trailer-Two: done\r\n\r\n' % n)

    def handle(self):
        head = read_head(self.request)
        if head is None:
            return
        line = head.split(b"\n", 1)[0].strip().decode("latin-1")
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "GET":
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        path = parts[1]
        kind, _, name = path.lstrip("/").partition("/")
        file = os.path.join(self.server.root, os.path.basename(name))
        if kind not in ("chunked", "close", "redirect", "continue") or not os.path.isfile(file):
            self.request.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        if kind == "redirect":
            self.request.sendall(b"HTTP/1.1 302 Found\r\nLocation: /chunked/%s\r\nContent-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n" % name.encode())
            return
        with open(file, "rb") as f:
            body = f.read()
        if kind == "close":
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                                 b"Connection: close\r\n\r\n")
            self.request.sendall(body)
            return
        if kind == "continue":
            self.request.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                             b"Transfer-Encoding: chunked\r\nTrailer: X-Chunks, X-Trailer-Two\r\n"
                             b"Connection: close\r\n\r\n")
        self.send_chunked(body, len(body))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def dns_server(port, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    ip = socket.inet_aton(addr)
    while True:
        q, peer = s.recvfrom(512)
        if len(q) < 12:
            continue
        qid, flags, qd = struct.unpack("!HHH", q[:6])
        # The question: labels to the zero octet, then QTYPE and QCLASS.
        i = 12
        while i < len(q) and q[i] != 0:
            i += 1 + q[i]
        question = q[12:i + 5]
        qtype = struct.unpack("!H", q[i + 1:i + 3])[0] if i + 3 <= len(q) else 0
        answers = b""
        if qtype == 1:
            answers = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + ip
        resp = struct.pack("!HHHHHH", qid, 0x8180, 1, 1 if answers else 0, 0, 0) + question + answers
        s.sendto(resp, peer)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--root", required=True)
    ap.add_argument("--dns-port", type=int, default=0)
    ap.add_argument("--dns-addr", default="127.0.0.1")
    a = ap.parse_args()
    if a.dns_port:
        threading.Thread(target=dns_server, args=(a.dns_port, a.dns_addr), daemon=True).start()
    srv = Server(("0.0.0.0", a.port), Handler)
    srv.root = a.root
    srv.serve_forever()


if __name__ == "__main__":
    main()
