"""Transparent SNI-sniffing forwarding proxy.

Sits in front of an upstream HTTP/SOCKS5 proxy and relays bytes untouched
(no TLS interception, so certificate pinning is irrelevant). It peeks the TLS
ClientHello (or HTTP Host header) to record the destination host, then dials the
upstream proxy and pipes the connection.

This gives proxy egress + per-request visibility at the same time, for every
app on the device, with no per-app code. Point the device at it either via the
Android system proxy or via a container iptables DNAT for TCP 80/443.

Usage:
    python -m damru.sni_proxy \
        --listen 0.0.0.0:8899 \
        --upstream socks5://user:pass@host:59101 \
        --log flows.jsonl

Output: one JSON object per connection/request with host, port, bytes, duration.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import ssl
import struct
import re
import sys
import time
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse


# ── TLS ClientHello SNI parser ───────────────────────────────────────

def parse_sni(data: bytes) -> Optional[str]:
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        # TLS record header: type(1) version(2) length(2)
        if data[5] != 0x01:  # handshake type: ClientHello
            return None
        p = 9  # skip record(5)+handshake type(1)+handshake len(3)
        p += 2 + 32  # client_version + random
        sid_len = data[p]
        p += 1 + sid_len
        cs_len = struct.unpack("!H", data[p:p + 2])[0]
        p += 2 + cs_len
        cm_len = data[p]
        p += 1 + cm_len
        ext_total = struct.unpack("!H", data[p:p + 2])[0]
        p += 2
        end = min(len(data), p + ext_total)
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", data[p:p + 4])
            p += 4
            if etype == 0x0000:  # server_name
                # list length(2), name type(1), name len(2), name
                if p + 5 <= len(data):
                    nlen = struct.unpack("!H", data[p + 3:p + 5])[0]
                    return data[p + 5:p + 5 + nlen].decode("ascii", "ignore")
                return None
            p += elen
    except Exception:
        return None
    return None


_DOMAIN_RE = re.compile(rb'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}', re.I)


def sniff_host_any(data: bytes) -> Optional[str]:
    """Fallback: find the plaintext SNI/domain in a ClientHello/HTTP head.

    Works across ClientHello layouts and TLS extensions without decrypting.
    """
    if not data:
        return None
    if data[:1] == b"\x16":
        # Prefer a real SNI extension parse, then fall back to domain scan.
        sni = parse_sni(data)
        if sni:
            return sni
        for m in _DOMAIN_RE.finditer(data):
            cand = m.group(0).decode("ascii", "ignore").lower()
            if cand in ("h2", "http/1.1"):
                continue
            # Skip cipher/ALPN artefacts: require a dot and a TLD-looking suffix
            if "." in cand and not cand.endswith(".local"):
                return cand
        return None
    return parse_http_host(data)


def parse_http_host(data: bytes) -> Optional[str]:
    try:
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        for line in head.split("\r\n")[1:]:
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip().split(":")[0]
    except Exception:
        return None
    return None


# ── Upstream dialing ────────────────────────────────────────────────

async def dial_socks5(up: dict, host: str, port: int) -> Optional[asyncio.StreamReader]:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(up["host"], up["port"]), timeout=15)
        user, pwd = up.get("user") or "", up.get("pass") or ""
        if user:
            w.write(b"\x05\x01\x02"); await w.drain()
            resp = await r.readexactly(2)
            if resp[1] == 0x02:
                u = user.encode(); p = pwd.encode()
                w.write(bytes([1, len(u)]) + u + bytes([len(p)]) + p); await w.drain()
                await r.readexactly(2)
        else:
            w.write(b"\x05\x01\x00"); await w.drain()
            await r.readexactly(2)
        hb = host.encode()
        w.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", port)); await w.drain()
        resp = await r.readexactly(4)
        if resp[1] != 0:
            w.close(); return None
        atyp = resp[3]
        if atyp == 1:
            await r.readexactly(4 + 2)
        elif atyp == 3:
            ln = (await r.readexactly(1))[0]; await r.readexactly(ln + 2)
        elif atyp == 4:
            await r.readexactly(16 + 2)
        return r, w
    except Exception:
        return None


async def dial_http(up: dict, host: str, port: int) -> Optional[Tuple]:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(up["host"], up["port"]), timeout=15)
        auth = ""
        if up.get("user"):
            import base64
            token = base64.b64encode(f"{up['user']}:{up['pass']}".encode()).decode()
            auth = f"Proxy-Authorization: Basic {token}\r\n"
        w.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n".encode())
        await w.drain()
        line = await r.readline()
        if b" 200" not in line:
            w.close(); return None
        while True:
            h = await r.readline()
            if h in (b"\r\n", b"\n", b""):
                break
        return r, w
    except Exception:
        return None


async def dial_direct(host: str, port: int) -> Optional[Tuple]:
    try:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=15)
    except Exception:
        return None


# ── Relay ───────────────────────────────────────────────────────────

class Logger:
    def __init__(self, path: Optional[str]):
        self.path = path
        self.lock = asyncio.Lock()

    async def write(self, obj: dict) -> None:
        if not self.path:
            return
        obj["ts"] = time.time()
        line = json.dumps(obj, ensure_ascii=False)
        async with self.lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 upstream: dict, log: Logger, sniff_ms: int = 1200) -> None:
    peer = writer.get_extra_info("peername")
    start = time.time()
    try:
        await log.write({"event": "accept", "peer": peer})
        head = b""
        deadline = time.time() + (sniff_ms / 1000)
        while len(head) < 8192:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            head += chunk
            if parse_sni(head) or parse_http_host(head) or head.upper().startswith(b"CONNECT "):
                break
        is_connect = head.upper().startswith(b"CONNECT ")
        host = parse_sni(head) or parse_http_host(head) or sniff_host_any(head)
        port = 443 if (head[:1] == b"\x16") else 80
        if is_connect and b" " in head:
            target = head.split()[1].decode(errors="replace")
            if ":" in target:
                host, p = target.rsplit(":", 1)
                if p.isdigit():
                    port = int(p)
        if not host:
            await log.write({"event": "no_host", "peer": peer, "head_hex": head[:64].hex()})
            writer.close()
            return

        up = upstream
        if up["scheme"] == "socks5":
            conn = await dial_socks5(up, host, port)
        elif up["scheme"] in ("http", "https"):
            conn = await dial_http(up, host, port)
        else:
            conn = await dial_direct(host, port)
        if not conn:
            await log.write({"event": "dial_failed", "host": host, "port": port, "peer": peer})
            writer.close()
            return
        r2, w2 = conn
        up_bytes = down_bytes = 0

        if is_connect:
            # HTTP proxy client: acknowledge the tunnel, then relay raw bytes.
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
        elif head:
            w2.write(head); await w2.drain(); up_bytes += len(head)

        async def pump(src, dst, counter):
            nonlocal up_bytes, down_bytes
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    if counter == "up":
                        up_bytes += len(chunk)
                    else:
                        down_bytes += len(chunk)
            except Exception:
                pass

        await asyncio.gather(pump(reader, w2, "up"), pump(r2, writer, "down"))
        await log.write({"event": "flow", "host": host, "port": port, "peer": peer,
                         "up": up_bytes, "down": down_bytes,
                         "ms": int((time.time() - start) * 1000)})
    except Exception as exc:
        try:
            await log.write({"event": "error", "peer": peer, "err": str(exc)[:160]})
        except Exception:
            pass
    finally:
        try: writer.close()
        except Exception: pass
        try:
            w2.close()
        except Exception:
            pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="damru.sni_proxy")
    ap.add_argument("--listen", default="0.0.0.0:8899")
    ap.add_argument("--upstream", default="direct", help="socks5://user:pass@host:port | http://... | direct")
    ap.add_argument("--log", default="flows.jsonl")
    args = ap.parse_args(argv)

    lh, lp = args.listen.rsplit(":", 1)
    u = urlparse(args.upstream if "://" in args.upstream else "direct://")
    upstream = {
        "scheme": u.scheme or "direct",
        "host": u.hostname or "",
        "port": u.port or 0,
        "user": u.username or "",
        "pass": u.password or "",
    }
    log = Logger(args.log)

    async def run():
        server = await asyncio.start_server(
            lambda r, w: handle(r, w, upstream, log), lh, int(lp))
        print(f"SNI proxy on {lh}:{lp} -> {upstream['scheme']} {upstream['host']}:{upstream['port']}", flush=True)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
