"""Virtual touchscreen daemon manager + humanized tap/swipe via sendevent.

Replaces `adb shell input tap/swipe` for the native-app path. Two problems that
solves:

1. The only input device on a redroid worker is called `redroid vinput`. Any
   app that reads `InputDevice.getName()` on the resulting MotionEvent sees
   that exact string and knows it's an emulator. We register our own uinput
   device with a realistic touchscreen name (goodix_ts by default) and route
   events through it instead.

2. `input tap X Y` fires ACTION_DOWN and ACTION_UP in the same frame with no
   movement. Real finger taps are a DOWN, a short hold with sub-pixel drift,
   then an UP. We emit the full sequence ourselves with jitter.

Usage (orchestrator side):
    from damru.uinput_touch import UinputTouch
    t = UinputTouch(serial="127.0.0.1:5607")
    await t.ensure()        # pushes binary, starts daemon, creates /dev/input node
    t.tap(500, 800)          # humanized tap
    t.swipe((500, 2000), (500, 1000), duration_ms=350)
"""
from __future__ import annotations

import os
import random
import subprocess
import time
from pathlib import Path
from typing import Optional

# Realistic touchscreen names seen on common Android phones. Pick one per
# container; the choice is stable per serial so it doesn't change mid-session.
_TOUCH_NAMES = (
    "goodix_ts",
    "NVTCapacitiveTouchScreen",
    "ft5x06_ts",
    "synaptics_dsx",
    "fts_ts",
    "himax-touchscreen",
)

_DEVICE_BINARY = "/data/local/tmp/damru_uinput_touch"
_DEVICE_LOG = "/data/local/tmp/damru_uinput_touch.log"
_HOST_BINARY = "/root/.cache/damru-native/damru_uinput_touch_x86_64"

# Linux input event codes we send.
_EV_SYN = 0
_EV_KEY = 1
_EV_ABS = 3
_SYN_REPORT = 0
_BTN_TOUCH = 330
_BTN_TOOL_FINGER = 325
_ABS_X = 0x00
_ABS_Y = 0x01
_ABS_MT_SLOT = 0x2f
_ABS_MT_TOUCH_MAJOR = 0x30
_ABS_MT_POSITION_X = 0x35
_ABS_MT_POSITION_Y = 0x36
_ABS_MT_TRACKING_ID = 0x39
_ABS_MT_PRESSURE = 0x3a


def _pick_name(serial: str) -> str:
    """Deterministic touchscreen name per serial — stays stable across restarts."""
    idx = abs(hash(("damru-ts", serial))) % len(_TOUCH_NAMES)
    return _TOUCH_NAMES[idx]


class UinputTouch:
    """Per-serial virtual multitouch device + event sender."""

    def __init__(self, serial: str, width: int = 1080, height: int = 2400):
        self.serial = serial
        self.width = width
        self.height = height
        self.name = _pick_name(serial)
        self.event_node: Optional[str] = None
        self._next_tracking_id = 1

    # ---- adb helpers (thin wrappers to keep the module self-contained) ----
    def _sh(self, cmd: str, timeout: float = 10.0) -> str:
        r = subprocess.run(
            ["adb", "-s", self.serial, "shell", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return (r.stdout or "").strip()

    def _push(self, local: str, remote: str) -> None:
        subprocess.run(
            ["adb", "-s", self.serial, "push", local, remote],
            capture_output=True, text=True, timeout=30,
        )

    # ---- daemon lifecycle ----
    def ensure(self, host_binary: str = _HOST_BINARY) -> bool:
        """Push binary, start daemon, mknod the /dev/input/event node.

        Idempotent: if an event node is already active with the correct name,
        we just discover and reuse it. Returns True on success.
        """
        self.event_node = self._find_existing()
        if self.event_node:
            return True

        if not Path(host_binary).is_file():
            raise FileNotFoundError(
                f"uinput binary not built at {host_binary}; run gcc -static "
                f"-O2 -o {host_binary} native/uinput_touchscreen.c"
            )

        # Push binary (idempotent — overwrites existing)
        self._push(host_binary, _DEVICE_BINARY)
        self._sh(f"chmod 0755 {_DEVICE_BINARY}")

        # Launch daemon in background
        launch = (
            f"nohup {_DEVICE_BINARY} "
            f"--name {self.name} "
            f"--width {self.width} "
            f"--height {self.height} "
            f">{_DEVICE_LOG} 2>&1 &"
        )
        self._sh(launch)

        # Wait up to ~3s for the kernel to register the device + sysfs entry
        for _ in range(30):
            time.sleep(0.1)
            self.event_node = self._find_existing()
            if self.event_node:
                break
        if not self.event_node:
            raise RuntimeError(
                f"uinput daemon started but /dev/input node never appeared; "
                f"check {_DEVICE_LOG}"
            )

        # Make sure the character device node exists (ueventd may not auto-create)
        self._ensure_dev_node()
        return True

    def _find_existing(self) -> Optional[str]:
        """Return the /dev/input/eventN path for our device, or None."""
        out = self._sh(
            'for d in /sys/class/input/event*; do '
            '  n=$(cat $d/device/name 2>/dev/null); '
            f'  if [ "$n" = "{self.name}" ]; then '
            '    echo "${d##*/}"; '
            '  fi; '
            'done'
        )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("event"):
                return f"/dev/input/{line}"
        return None

    def _ensure_dev_node(self) -> None:
        if not self.event_node:
            return
        basename = self.event_node.rsplit("/", 1)[-1]
        out = self._sh(
            f'if [ ! -e {self.event_node} ]; then '
            f'  d=$(cat /sys/class/input/{basename}/dev); '
            f'  major=${{d%:*}}; minor=${{d#*:}}; '
            f'  mknod {self.event_node} c $major $minor && '
            f'  chmod 0660 {self.event_node} && '
            f'  chown root:input {self.event_node} 2>/dev/null || '
            f'  chown root:system {self.event_node} 2>/dev/null; '
            f'fi; '
            f'ls {self.event_node} 2>/dev/null'
        )
        if not out:
            raise RuntimeError(f"failed to create {self.event_node}")

    # ---- event helpers ----
    def _send(self, batch: list[tuple[int, int, int]]) -> None:
        """Emit a list of (type, code, value) events in one shell round-trip."""
        if not self.event_node:
            raise RuntimeError("ensure() not called")
        script = "; ".join(
            f"sendevent {self.event_node} {t} {c} {v}"
            for t, c, v in batch
        )
        self._sh(script, timeout=5.0)

    def _down(self, x: int, y: int) -> None:
        tid = self._next_tracking_id
        self._next_tracking_id = (self._next_tracking_id % 65535) + 1
        pressure = random.randint(80, 160)
        major = random.randint(8, 18)
        self._send([
            (_EV_ABS, _ABS_MT_SLOT, 0),
            (_EV_ABS, _ABS_MT_TRACKING_ID, tid),
            (_EV_KEY, _BTN_TOUCH, 1),
            (_EV_KEY, _BTN_TOOL_FINGER, 1),
            (_EV_ABS, _ABS_MT_POSITION_X, x),
            (_EV_ABS, _ABS_MT_POSITION_Y, y),
            (_EV_ABS, _ABS_X, x),
            (_EV_ABS, _ABS_Y, y),
            (_EV_ABS, _ABS_MT_TOUCH_MAJOR, major),
            (_EV_ABS, _ABS_MT_PRESSURE, pressure),
            (_EV_SYN, _SYN_REPORT, 0),
        ])

    def _move(self, x: int, y: int) -> None:
        self._send([
            (_EV_ABS, _ABS_MT_POSITION_X, x),
            (_EV_ABS, _ABS_MT_POSITION_Y, y),
            (_EV_ABS, _ABS_X, x),
            (_EV_ABS, _ABS_Y, y),
            (_EV_SYN, _SYN_REPORT, 0),
        ])

    def _up(self) -> None:
        self._send([
            (_EV_ABS, _ABS_MT_TRACKING_ID, -1),
            (_EV_KEY, _BTN_TOUCH, 0),
            (_EV_KEY, _BTN_TOOL_FINGER, 0),
            (_EV_SYN, _SYN_REPORT, 0),
        ])

    # ---- public API ----
    def tap(self, x: int, y: int) -> None:
        """Humanized tap: down, 70-180ms hold with 2-3px drift, up."""
        jx = x + random.randint(-4, 4)
        jy = y + random.randint(-4, 4)
        self._down(jx, jy)
        hold_ms = random.randint(70, 180)
        # ~3 micro-moves during the hold
        steps = random.randint(2, 4)
        for _ in range(steps):
            time.sleep(hold_ms / 1000.0 / (steps + 1))
            self._move(jx + random.randint(-2, 2), jy + random.randint(-2, 2))
        time.sleep(hold_ms / 1000.0 / (steps + 1))
        self._up()

    def swipe(self, start: tuple[int, int], end: tuple[int, int],
              duration_ms: int = 350) -> None:
        """Humanized swipe with ease-in/ease-out curve and jitter."""
        x1, y1 = start
        x2, y2 = end
        steps = max(8, duration_ms // 16)  # ~60fps
        self._down(x1 + random.randint(-2, 2), y1 + random.randint(-2, 2))
        for i in range(1, steps):
            # ease-in-out cubic
            t = i / steps
            eased = 3 * t * t - 2 * t * t * t
            x = int(x1 + (x2 - x1) * eased) + random.randint(-2, 2)
            y = int(y1 + (y2 - y1) * eased) + random.randint(-2, 2)
            self._move(x, y)
            time.sleep(duration_ms / 1000.0 / steps)
        self._move(x2 + random.randint(-2, 2), y2 + random.randint(-2, 2))
        self._up()
