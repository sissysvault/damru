"""StealthApp - OS-level stealth identity for a third-party Android app.

Uses the same device/system layers as the browser path (props, GPU, CPU,
display, fonts, timezone/locale, sensors, proxy GeoIP) but targets an app
package instead of Chrome. The app is preloaded with the minimal libfakemem
(RAM/CPU only) because Cronet/OkHttp-based apps crash under the full
openat/uname interposition.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import asyncio
import base64
import os
import signal
import subprocess
import time
from pathlib import Path

from .adb import ADB
from .profile_apply import AppliedDeviceProfile, force_device_profile
from .utils import logger


@dataclass
class StealthAppResult:
    package: str
    serial: str
    activity: str
    profile: AppliedDeviceProfile


class StealthApp:
    """Apply a native-device stealth profile to an installed Android app."""

    def __init__(
        self,
        package: str,
        device: Optional[str] = None,
        serial: Optional[str] = None,
        proxy: Optional[str] = None,
        http_proxy: Optional[str] = None,
        timezone: Optional[str] = None,
        locale: Optional[str] = None,
        apply_memory: bool = True,
        apply_gpu: bool = True,
        launch: bool = True,
        har: Optional[str] = None,
        netcap: bool = False,
    ):
        self.package = package
        self.device = device or "random"
        self.serial = serial
        self.proxy = proxy
        self.http_proxy = http_proxy
        self.timezone = timezone
        self.locale = locale
        self.apply_memory = apply_memory
        self.apply_gpu = apply_gpu
        self.launch = launch
        self.har = har
        self.netcap = netcap
        self._mitm: Optional[subprocess.Popen] = None
        self._fwd: Optional[subprocess.Popen] = None
        self._serial_resolved: Optional[str] = None
        self._container_ip: str = ""
        self._prev_proxy: str = ""
        self._rules: list[str] = []

    # ── HAR capture (one-stop, app-agnostic) ─────────────────────────
    def _sh(self, *args: str, timeout: int = 30) -> str:
        cmd = ["adb"] + (["-s", self._serial_resolved] if self._serial_resolved else []) + list(args)
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
        except Exception:
            return ""

    def _host_gateway(self) -> str:
        for line in self._sh("shell", "ip", "route").splitlines():
            if line.startswith("default via "):
                return line.split()[2]
        return "172.17.0.1"

    def _detect_container_ip(self) -> str:
        for line in self._sh("shell", "ip", "-4", "addr", "show").splitlines():
            line = line.strip()
            if line.startswith("inet ") and "127.0.0.1" not in line:
                return line.split()[1].split("/")[0]
        return ""

    def _install_ca(self) -> None:
        cert = Path(os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem"))
        if not cert.exists():
            try:
                subprocess.run(["mitmdump", "--listen-port", "8099", "-q"], timeout=3,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        if not cert.exists():
            raise RuntimeError("mitmproxy CA not found")
        self._sh("push", str(cert), "/data/local/tmp/mitm.pem")
        script = (
            "mkdir -p /data/local/tmp/cacerts; "
            "cp -f /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacerts/ 2>/dev/null || true; "
            "cp -f /data/local/tmp/mitm.pem /data/local/tmp/cacerts/c8750f0d.0; "
            "chmod 644 /data/local/tmp/cacerts/*; "
            "mount --bind /data/local/tmp/cacerts /apex/com.android.conscrypt/cacerts || true"
        )
        tmp = Path("/tmp/_damru_ca.sh"); tmp.write_text("#!/system/bin/sh\n" + script + "\n")
        self._sh("push", str(tmp), "/data/local/tmp/_damru_ca.sh")
        self._sh("shell", "su", "0", "sh", "/data/local/tmp/_damru_ca.sh")

    async def _start_capture(self) -> None:
        assert self.har
        har_path = Path(self.har).expanduser()
        har_path.parent.mkdir(parents=True, exist_ok=True)
        self._install_ca()
        env = dict(os.environ, DAMRU_HAR_OUT=str(har_path))
        self._mitm = subprocess.Popen(
            ["mitmdump", "--mode", "regular", "--listen-host", "0.0.0.0",
             "--listen-port", "8080", "-q", "-s",
             str(Path(__file__).with_name("har_addon.py"))],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        self._fwd = subprocess.Popen(
            ["python3", "-m", "damru.sni_proxy", "--listen", "0.0.0.0:8899",
             "--via", "127.0.0.1:8080", "--log", str(har_path.with_suffix(".flows.jsonl"))],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(1.2)
        self._container_ip = self._detect_container_ip()
        gw = self._host_gateway()
        # System proxy is the simplest full-coverage egress (Cronet honors it).
        prev = self._sh("shell", "settings", "get", "global", "http_proxy").strip()
        self._prev_proxy = prev if prev not in ("", "null", ":0") else ""
        self._sh("shell", "settings", "put", "global", "http_proxy", f"{gw}:8080")
        logger.info("App HAR capture -> %s (device proxy %s:8080)", har_path, gw)

    async def _stop_capture(self) -> None:
        if self._container_ip:
            for port in ("443", "80"):
                subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-s",
                                self._container_ip, "-p", "tcp", "--dport", port,
                                "-j", "DNAT", "--to-destination", "172.17.0.1:8899"], check=False)
        if self._mitm:
            self._mitm.send_signal(signal.SIGINT)
            try:
                self._mitm.wait(timeout=8)
            except Exception:
                self._mitm.kill()
        if self._fwd:
            self._fwd.terminate()
        # restore/clear device proxy
        self._sh("shell", "settings", "put", "global", "http_proxy", self._prev_proxy or ":0")
        logger.info("App HAR saved -> %s", self.har)

    async def __aenter__(self) -> "StealthAppResult":
        self._serial_resolved = self.serial
        if self.har:
            adb = ADB(self.serial) if self.serial else ADB()
            await adb.ensure_server()
            self._serial_resolved = self.serial or await adb.detect_device()
        # Apply profile first (it sets the SOCKS5 bridge as system proxy), then
        # start capture, which overrides the proxy to point at mitmproxy. Order
        # matters: the capture must be the final proxy writer.
        result = await self.apply(launch=(not self.har) and self.launch)
        if self.har:
            await self._start_capture()
            if self.launch:
                result.activity = await self.launch_app()
        return result

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.har:
            try:
                await self._stop_capture()
            except Exception as e:
                logger.warning("HAR stop failed: %s", e)

    async def launch_app(self, package: Optional[str] = None) -> str:
        """Resolve and start the app, return the activity component."""
        package = package or self.package
        adb = ADB(self._serial_resolved) if self._serial_resolved else ADB()
        out = await adb.shell(f"cmd package resolve-activity --brief {package}", allow_failure=True)
        activity = (out.strip().splitlines() or [""])[-1].strip()
        if activity:
            await adb.shell(f"am force-stop {package}", allow_failure=True)
            await adb.shell(f"am start -W -n {activity}", allow_failure=True)
            logger.info("Launched %s (%s)", package, activity)
        else:
            logger.warning("Could not resolve launch activity for %s", package)
        return activity

    async def apply(self, launch: Optional[bool] = None) -> StealthAppResult:
        adb = ADB(self.serial) if self.serial else ADB()
        await adb.ensure_server()
        serial = self.serial or await adb.detect_device()
        adb.serial = serial

        profile = await force_device_profile(
            serial,
            self.device,
            proxy=self.proxy,
            http_proxy=self.http_proxy,
            timezone=self.timezone,
            locale=self.locale,
            configure_chrome=False,
            browser_package=self.package,
            clear_chrome=False,
            apply_cpu=True,
            apply_gpu=self.apply_gpu,
            apply_memory=self.apply_memory,
            minimal_preload=True,
            netcap_preload=self.netcap,
        )

        activity = ""
        if self.har:
            # stop first so every connection is created after the capture proxy
            try:
                adb0 = ADB(self._serial_resolved) if self._serial_resolved else ADB()
                await adb0.shell(f"am force-stop {self.package}", allow_failure=True)
            except Exception:
                pass
        if (self.launch if launch is None else launch):
            out = await adb.shell(
                f"cmd package resolve-activity --brief {self.package}",
                allow_failure=True,
            )
            activity = (out.strip().splitlines() or [""])[-1].strip()
            if activity:
                await adb.shell(f"am force-stop {self.package}", allow_failure=True)
                await adb.shell(
                    f"am start -W -n {activity}",
                    allow_failure=True,
                )
                logger.info("Launched %s (%s)", self.package, activity)
            else:
                logger.warning("Could not resolve launch activity for %s", self.package)

        return StealthAppResult(
            package=self.package,
            serial=serial,
            activity=activity,
            profile=profile,
        )
