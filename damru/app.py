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

    def _apply_battery_spoof(self, reset_stats: bool = False) -> None:
        """Present a realistic, clock-driven discharging/charging battery.

        Chrome's navigator.getBattery() reads BatteryService, so this is done
        at the OS level (no JS). Values come from damru.battery: a deterministic
        24h cycle (overnight USB charge -> daytime drain), so the level drifts
        like a real phone instead of static random numbers.
        Disable with DAMRU_BATTERY_SPOOF=0.
        """
        if os.environ.get("DAMRU_BATTERY_SPOOF", "1") == "0":
            return
        from .battery import state as battery_state, adb_commands
        st = battery_state()
        # the device may be mid-restart after profile/GPU apply: wait and retry
        for _ in range(5):
            try:
                self._sh("wait-for-device", timeout=20)
                ready = self._sh("shell", "getprop", "sys.boot_completed", timeout=8).strip()
            except Exception:
                ready = ""
            if ready == "1":
                break
            time.sleep(3)
        for attempt in range(3):
            if reset_stats and attempt == 0:
                self._sh("shell", "dumpsys batterystats --reset", timeout=15)
            for c in adb_commands(st):
                self._sh("shell", c, timeout=10)
            try:
                out = self._sh("shell", "dumpsys battery", timeout=10)
            except Exception:
                out = ""
            if ("level: %d" % st["level"]) in out:
                logger.info("Battery: %d%% %s (%.1f C, %.2f Ah)",
                            st["level"],
                            "charging(usb)" if st["charging"] else "discharging",
                            st["temperature_c"], st["counter_uah"] / 1e6)
                return
            time.sleep(4)
        logger.warning("Battery spoof could not be verified on device")

    async def _battery_keepalive(self) -> None:
        """Re-apply the clock-derived battery so the level keeps drifting."""
        try:
            while True:
                await asyncio.sleep(120)
                try:
                    self._apply_battery_spoof()
                except Exception as exc:  # pragma: no cover - best effort
                    logger.debug("Battery keepalive failed: %s", exc)
        except asyncio.CancelledError:
            pass

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
        # unique temp file: a fixed /tmp path breaks when a previous run left
        # it root-owned ("Permission denied: /tmp/_damru_ca.sh")
        import tempfile
        cache = Path(os.path.expanduser("~/.cache/damru"))
        try:
            cache.mkdir(parents=True, exist_ok=True)
        except Exception:
            cache = Path(tempfile.gettempdir())
        fd, tmp_name = tempfile.mkstemp(prefix="damru_ca_", suffix=".sh", dir=str(cache))
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write("#!/system/bin/sh\n" + script + "\n")
            self._sh("push", tmp_name, "/data/local/tmp/_damru_ca.sh")
            self._sh("shell", "su", "0", "sh", "/data/local/tmp/_damru_ca.sh")
        finally:
            try:
                os.unlink(tmp_name)
            except Exception:
                pass

    async def _start_capture(self) -> None:
        assert self.har
        har_path = Path(self.har).expanduser()
        har_path.parent.mkdir(parents=True, exist_ok=True)
        self._install_ca()
        env = dict(os.environ, DAMRU_HAR_OUT=str(har_path))
        self._mitm = subprocess.Popen(
            ["mitmdump", "--mode", "regular", "--listen-host", "0.0.0.0",
             "--set", "http2=false",
             "--listen-port", "8080", "-q", "-s",
             str(Path(__file__).with_name("har_addon.py"))],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        await asyncio.sleep(1.2)
        self._container_ip = self._detect_container_ip()
        gw = self._host_gateway()
        # Transparent interception: DNAT container TCP 80/443 into the SNI
        # forwarder, which relays to mitmproxy. No system proxy is set, so
        # apps see a clean direct network (no proxy/VPN artifacts) and cold
        # starts do not stall behind a proxy they must negotiate.
        self._fwd = subprocess.Popen(
            ["python3", "-m", "damru.sni_proxy", "--listen", "0.0.0.0:8899",
             "--via", "127.0.0.1:8080", "--log", str(har_path.with_suffix(".flows.jsonl"))],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(1.0)
        self._sh("shell", "settings", "put", "global", "http_proxy", ":0")
        # apps may resolve AAAA and reach the web over IPv6, which would
        # bypass the IPv4-only DNAT rules and vanish from the capture.
        self._sh("shell", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1",
                 timeout=8)
        self._sh("shell", "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1",
                 timeout=8)
        # fresh capture session: truncate the streaming files so the HAR and
        # the live streams reflect exactly this run, not previous ones
        for suffix in (".jsonl", ".events.jsonl"):
            try:
                open(str(har_path) + suffix, "w").close()
            except Exception:
                pass
        if self._container_ip:
            for port in ("443", "80"):
                subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-s",
                                self._container_ip, "-p", "tcp", "--dport", port,
                                "-j", "DNAT", "--to-destination", f"172.17.0.1:8899"], check=False)
            # Cronet apps (Reddit) fetch their APIs over QUIC/HTTP3 (UDP 443),
            # which bypasses the TCP DNAT entirely and leaves the HAR with
            # empty bodies. Drop UDP 443 so they fall back to visible TCP.
            subprocess.run(["iptables", "-I", "FORWARD", "1", "-s",
                            self._container_ip, "-p", "udp", "--dport", "443",
                            "-j", "DROP"], check=False)
        logger.info("App HAR capture -> %s (transparent DNAT -> 8899 -> mitm 8080)", har_path)

    async def _stop_capture(self) -> None:
        if self._container_ip:
            subprocess.run(["iptables", "-D", "FORWARD", "-s",
                            self._container_ip, "-p", "udp", "--dport", "443",
                            "-j", "DROP"], check=False)
            for port in ("443", "80"):
                subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-s",
                                self._container_ip, "-p", "tcp", "--dport", port,
                                "-j", "DNAT", "--to-destination", "172.17.0.1:8899"], check=False)
        if self._mitm:
            self._mitm.send_signal(signal.SIGINT)
            try:
                self._mitm.wait(timeout=12)
            except Exception:
                self._mitm.send_signal(signal.SIGINT)
                try:
                    self._mitm.wait(timeout=5)
                except Exception:
                    self._mitm.kill()
                    self._mitm.wait(timeout=5)
        if self._fwd:
            self._fwd.terminate()
        self._sh("shell", "settings", "put", "global", "http_proxy", self._prev_proxy or ":0")
        self._repair_har()
        logger.info("App HAR saved -> %s", self.har)

    def _repair_har(self) -> None:
        """Ensure the HAR file is complete JSON; rebuild it from the addon's
        streaming .jsonl if mitmdump was killed mid-write."""
        import json
        try:
            with open(self.har, "r", encoding="utf-8") as f:
                json.load(f)
            return
        except FileNotFoundError:
            pass
        except Exception:
            logger.warning("HAR truncated at teardown; rebuilding from .jsonl")
        entries = []
        try:
            with open(str(self.har) + ".jsonl", "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        entries.append(json.loads(ln))
                    except Exception:
                        pass
        except FileNotFoundError:
            return
        if not entries:
            return
        with open(self.har, "w", encoding="utf-8") as f:
            json.dump({"log": {"version": "1.2",
                               "creator": {"name": "damru-netcap", "version": "1.1"},
                               "entries": entries}}, f, ensure_ascii=False)

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
            self._battery_task = asyncio.create_task(self._battery_keepalive())
        return result

    async def __aexit__(self, exc_type, exc, tb) -> None:
        task = getattr(self, "_battery_task", None)
        if task is not None:
            task.cancel()
            try:
                await task
            except Exception:
                pass
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

        if self.har:
            # capture runs: clock-driven, realistic battery state
            self._apply_battery_spoof(reset_stats=True)
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
