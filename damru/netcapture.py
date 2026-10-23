"""Universal app traffic visibility for a Redroid/ADB device.

Two modes, both app-agnostic (no per-app hooks, no injected code):

  proxy  Start a logging proxy on the host and make it the device's global
         HTTP proxy. Every app that honours the Android system proxy flows
         through it. HTTPS is observed at CONNECT level (host:port); with
         --decrypt, mitmproxy's CA is trusted and full URLs/headers are logged.

  pcap   Capture packets on the device's host interface (docker veth / docker0)
         with tcpdump and summarise DNS queries, TLS SNI and HTTP requests with
         tshark. Works even for apps that ignore the system proxy, but if an
         upstream proxy is active the destinations are inside its tunnel.

Usage:
    python -m damru.netcapture --serial 127.0.0.1:5600 --mode proxy --seconds 40
    python -m damru.netcapture --mode pcap --seconds 30 --out ./netcap

Outputs (in --out):
    network.txt   human-readable summary
    flows.jsonl   (proxy) one JSON object per request/CONNECT
    capture.pcap  (pcap) raw capture
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .adb import ADB
from .utils import logger

ADDON = r'''
import json, time
from mitmproxy import http, ctx

OUT = __OUT__

def _emit(kind, **kw):
    kw.update({"kind": kind, "ts": time.time()})
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(kw, ensure_ascii=False) + "\n")

class Recorder:
    def request(self, flow: http.HTTPFlow):
        _emit("request", method=flow.request.method, scheme=flow.request.scheme,
              host=flow.request.pretty_host, port=flow.request.port,
              path=flow.request.path,
              headers={k: v for k, v in flow.request.headers.items()
                       if k.lower() in ("user-agent","accept","accept-language","content-type","referer","x-requested-with")})
    def response(self, flow: http.HTTPFlow):
        _emit("response", host=flow.request.pretty_host, path=flow.request.path,
              status=flow.response.status_code, bytes=len(flow.response.content or b""))

addons = [Recorder()]
'''


def _adb_shell(serial: Optional[str], *args: str, timeout: int = 20) -> str:
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def _device_gateway(serial: Optional[str]) -> str:
    out = _adb_shell(serial, "shell", "ip", "route")
    for line in out.splitlines():
        if line.startswith("default via "):
            return line.split()[2]
    return "172.17.0.1"


def _container_ip(serial: Optional[str]) -> str:
    out = _adb_shell(serial, "shell", "ip", "-4", "addr", "show")
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet ") and "127.0.0.1" not in line:
            return line.split()[1].split("/")[0]
    return ""


class ProxyCapture:
    def __init__(self, serial: Optional[str], out_dir: Path, port: int = 8899, decrypt: bool = False):
        self.serial = serial
        self.out = out_dir
        self.port = port
        self.decrypt = decrypt
        self.proc: Optional[subprocess.Popen] = None
        self.prev_proxy: Optional[str] = None

    def start(self) -> None:
        if shutil.which("mitmdump") is None:
            raise RuntimeError("mitmdump not found - pip install mitmproxy")
        flows = self.out / "flows.jsonl"
        flows.write_text("", encoding="utf-8")
        addon = self.out / "_netcap_addon.py"
        addon.write_text(ADDON.replace("__OUT__", json.dumps(str(flows))), encoding="utf-8")
        confdir = self.out / "mitm-conf"
        confdir.mkdir(exist_ok=True)
        self.proc = subprocess.Popen(
            ["mitmdump", "-q", "--listen-host", "0.0.0.0", "--listen-port", str(self.port),
             "--set", f"confdir={confdir}", "-s", str(addon)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.2)
        self.prev_proxy = _adb_shell(self.serial, "shell", "settings", "get", "global", "http_proxy").strip()
        gw = _device_gateway(self.serial)
        _adb_shell(self.serial, "shell", "settings", "put", "global", "http_proxy", f"{gw}:{self.port}")
        _adb_shell(self.serial, "shell", "settings", "put", "global", "global_http_proxy_host", gw)
        _adb_shell(self.serial, "shell", "settings", "put", "global", "global_http_proxy_port", str(self.port))
        logger.info("Proxy capture on %s:%d (device proxy set)", gw, self.port)

    def stop(self) -> None:
        if self.prev_proxy is not None and self.prev_proxy not in ("", "null", ":0"):
            _adb_shell(self.serial, "shell", "settings", "put", "global", "http_proxy", self.prev_proxy)
        else:
            _adb_shell(self.serial, "shell", "settings", "put", "global", "http_proxy", ":0")
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()


class PcapCapture:
    def __init__(self, serial: Optional[str], out_dir: Path, iface: str = "any", bpf: str = ""):
        self.serial = serial
        self.out = out_dir
        self.iface = iface
        self.bpf = bpf
        self.proc: Optional[subprocess.Popen] = None
        self.pcap = out_dir / "capture.pcap"

    def start(self) -> None:
        ip = _container_ip(self.serial)
        bpf = self.bpf or (f"host {ip} and not port 5555" if ip else "not port 5555")
        self.proc = subprocess.Popen(
            ["tcpdump", "-i", self.iface, "-s", "0", "-U", "-w", str(self.pcap), bpf],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.8)
        cur_proxy = _adb_shell(self.serial, "shell", "settings", "get", "global", "http_proxy").strip()
        if cur_proxy not in ("", "null", ":0"):
            logger.warning(
                "Device HTTP proxy is set (%s). App destinations will appear only as the "
                "proxy endpoint inside the tunnel; clear it (settings put global http_proxy :0) "
                "or use --mode proxy for per-request visibility.", cur_proxy,
            )
        logger.info("Packet capture on %s [%s] -> %s", self.iface, bpf, self.pcap)

    def stop(self) -> None:
        if self.proc:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=6)
            except Exception:
                self.proc.kill()


def _tshark(pcap: Path, args: list[str]) -> str:
    try:
        r = subprocess.run(["tshark", "-r", str(pcap), *args], capture_output=True, text=True, timeout=120)
        return r.stdout
    except Exception:
        return ""


def report_pcap(pcap: Path, out_dir: Path) -> str:
    dns = sorted({l.strip() for l in _tshark(pcap, ["-Y", "dns.flags.response==0", "-T", "fields", "-e", "dns.qry.name"]).splitlines() if l.strip()})
    sni = sorted({l.strip() for l in _tshark(pcap, ["-Y", "tls.handshake.extensions_server_name", "-T", "fields", "-e", "tls.handshake.extensions_server_name"]).splitlines() if l.strip()})
    http = sorted({l.strip() for l in _tshark(pcap, ["-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.request.method", "-e", "http.request.uri"]).splitlines() if l.strip()})
    conv = _tshark(pcap, ["-q", "-z", "conv,tcp"]).strip()
    lines = ["=== DNS queries ===", *dns, "", "=== TLS SNI (HTTPS hosts) ===", *sni, "", "=== HTTP requests ===", *http, "", "=== TCP conversations ===", conv]
    text = "\n".join(lines)
    (out_dir / "network.txt").write_text(text, encoding="utf-8")
    return text


def report_proxy(flows_file: Path, out_dir: Path) -> str:
    hosts: dict[str, int] = {}
    reqs: list[str] = []
    if flows_file.exists():
        for line in flows_file.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except Exception:
                continue
            host = r.get("host") or ""
            if host:
                hosts[host] = hosts.get(host, 0) + 1
            if r.get("kind") == "request":
                reqs.append(f"{r.get('method')} {r.get('scheme')}://{host}{r.get('path')} -> {r.get('status','')}")
    lines = ["=== Hosts contacted (app) ==="]
    for h, n in sorted(hosts.items(), key=lambda kv: -kv[1]):
        lines.append(f"{n:6d}  {h}")
    lines += ["", "=== Requests ===", *reqs]
    text = "\n".join(lines)
    (out_dir / "network.txt").write_text(text, encoding="utf-8")
    return text


def _launch(serial: Optional[str], package: Optional[str]) -> None:
    if not package:
        return
    out = _adb_shell(serial, "shell", "cmd", "package", "resolve-activity", "--brief", package)
    activity = (out.strip().splitlines() or [""])[-1].strip()
    if activity:
        _adb_shell(serial, "shell", "am", "force-stop", package)
        _adb_shell(serial, "shell", "am", "start", "-W", "-n", activity, timeout=40)
        logger.info("Launched %s", activity)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="damru.netcapture", description="Universal app traffic visibility")
    ap.add_argument("--serial", "-s", default=None)
    ap.add_argument("--mode", choices=["proxy", "pcap"], default="proxy")
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--out", "-o", default="netcap")
    ap.add_argument("--package", "-p", default=None, help="optional app to launch during capture")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--iface", default="any")
    ap.add_argument("--bpf", default="")
    ap.add_argument("--decrypt", action="store_true", help="proxy mode: also decrypt HTTPS (needs trusted mitm CA)")
    args = ap.parse_args(argv)

    out_dir = Path(args.out).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    cap = ProxyCapture(args.serial, out_dir, args.port, args.decrypt) if args.mode == "proxy" \
        else PcapCapture(args.serial, out_dir, args.iface, args.bpf)
    cap.start()
    try:
        _launch(args.serial, args.package)
        logger.info("Capturing for %ds - use the app now", args.seconds)
        time.sleep(args.seconds)
    finally:
        cap.stop()

    text = report_proxy(out_dir / "flows.jsonl", out_dir) if args.mode == "proxy" \
        else report_pcap(out_dir / "capture.pcap", out_dir)
    print(text)
    print(f"\nSaved: {out_dir / 'network.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
