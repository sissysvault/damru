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

    async def apply(self) -> StealthAppResult:
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
        )

        activity = ""
        if self.launch:
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
