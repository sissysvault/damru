#!/usr/bin/env python3
"""DNS -> DoH forwarder that tunnels queries via an HTTP CONNECT proxy.

Listens on a UDP port for standard DNS wire-format queries. For each query,
opens a TLS tunnel to 1.1.1.1:443 THROUGH the supplied HTTP proxy, sends the
query as a DoH POST, and returns the answer. Connections are short-lived
and spawned one-per-query (threaded) so a slow proxy doesn't block others.

Purpose: prevent DNS from leaking the host's real geo. Without this, an
Android container that boots with 1.1.1.1/8.8.8.8 as resolvers sends DNS
queries straight from the host IP, while HTTPS traffic claims to be in a
different country through the proxy. This routes DNS through the SAME
upstream proxy so both exit from the same geo.

Minimal deps (stdlib + http.client + ssl). Intended to be spawned per
capture session by damru/app.py._start_capture, killed on _stop_capture.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import socket
import socketserver
import ssl
import struct
import sys
import threading
import urllib.parse


DOH_HOST = "1.1.1.1"
DOH_PATH = "/dns-query"
PROXY_TIMEOUT = 8.0


def _doh_via_proxy(wire_query: bytes, proxy_host: str, proxy_port: int,
                   proxy_auth: str | None) -> bytes:
    """Send `wire_query` to Cloudflare DoH via HTTP CONNECT proxy.

    Returns DNS wire-format response bytes.
    """
    raw = socket.create_connection((proxy_host, proxy_port), timeout=PROXY_TIMEOUT)
    try:
        req = f"CONNECT {DOH_HOST}:443 HTTP/1.1\r\nHost: {DOH_HOST}:443\r\n"
        if proxy_auth:
            token = base64.b64encode(proxy_auth.encode("utf-8")).decode("ascii")
            req += f"Proxy-Authorization: Basic {token}\r\n"
        req += "\r\n"
        raw.sendall(req.encode("ascii"))

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = raw.recv(1024)
            if not chunk:
                raise RuntimeError("proxy closed during CONNECT")
            resp += chunk
            if len(resp) > 8192:
                raise RuntimeError("CONNECT response too large")
        status_line = resp.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        if " 200 " not in status_line:
            raise RuntimeError(f"CONNECT failed: {status_line}")

        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(raw, server_hostname=DOH_HOST)

        http_req = (
            f"POST {DOH_PATH} HTTP/1.1\r\n"
            f"Host: {DOH_HOST}\r\n"
            "Content-Type: application/dns-message\r\n"
            "Accept: application/dns-message\r\n"
            f"Content-Length: {len(wire_query)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii") + wire_query
        tls.sendall(http_req)

        data = b""
        while True:
            try:
                chunk = tls.recv(4096)
            except ssl.SSLError:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break

        header_end = data.find(b"\r\n\r\n")
        if header_end < 0:
            raise RuntimeError("no HTTP header in DoH response")
        header = data[:header_end].decode("ascii", errors="replace")
        body = data[header_end + 4:]
        if " 200 " not in header.split("\r\n", 1)[0]:
            raise RuntimeError(f"DoH HTTP error: {header.splitlines()[0]}")
        return body
    finally:
        try:
            raw.close()
        except Exception:
            pass


def _servfail(tx_id: bytes, question: bytes) -> bytes:
    """Minimal DNS SERVFAIL reply preserving the original transaction id."""
    flags = 0x8182  # response, SERVFAIL
    header = tx_id + struct.pack("!HHHHH", flags, 1, 0, 0, 0)
    return header + question


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        wire_query, sock = self.request
        if len(wire_query) < 12:
            return
        tx_id = wire_query[:2]
        try:
            answer = _doh_via_proxy(
                wire_query,
                self.server.proxy_host,
                self.server.proxy_port,
                self.server.proxy_auth,
            )
            if len(answer) >= 2:
                answer = tx_id + answer[2:]
            sock.sendto(answer, self.client_address)
        except Exception as exc:
            print(f"[dns-doh] query failed: {exc}", file=sys.stderr, flush=True)
            sock.sendto(_servfail(tx_id, wire_query[12:]), self.client_address)


class _ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:5553",
                    help="host:port to bind (UDP)")
    ap.add_argument("--proxy", required=True,
                    help="upstream HTTP proxy URL (http://[user:pass@]host:port)")
    args = ap.parse_args()

    host, _, port_s = args.listen.rpartition(":")
    port = int(port_s)
    parsed = urllib.parse.urlparse(args.proxy)
    if parsed.scheme not in {"http", "https"}:
        print(f"unsupported proxy scheme: {parsed.scheme}", file=sys.stderr)
        return 2
    proxy_host = parsed.hostname
    proxy_port = parsed.port or 80
    proxy_auth = None
    if parsed.username:
        user = urllib.parse.unquote(parsed.username)
        pw = urllib.parse.unquote(parsed.password or "")
        proxy_auth = f"{user}:{pw}"

    server = _ThreadedUDPServer((host, port), DNSHandler)
    server.proxy_host = proxy_host
    server.proxy_port = proxy_port
    server.proxy_auth = proxy_auth
    print(f"[dns-doh] listening {host}:{port} -> DoH via {proxy_host}:{proxy_port}",
          file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
