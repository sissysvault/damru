"""Deterministic battery model: real device behaviour derived from the clock.

Android's BatteryService (which Chrome's navigator.getBattery() reads) exposes
level, charging state, temperature, charge counter and health. We model a
realistic 24h cycle instead of random values:

  00:00-01:45  charging  (40% -> 100%, USB plugged)
  01:45-23:59  discharging (100% -> 18%)

Level therefore drifts continuously during a session. Deterministic: same
clock -> same values (no randomness).
"""
from __future__ import annotations

import math
import time

CAPACITY_UAH = 5_050_000          # Pixel 8 Pro: 5050 mAh
CHARGE_START_MIN = 0              # 00:00
CHARGE_END_MIN = 105              # 01:45
LEVEL_AT_CHARGE_START = 40
LEVEL_AT_CHARGE_END = 100
LEVEL_AT_DAY_END = 18


def _minutes_of_day(ts: float) -> float:
    lt = time.localtime(ts)
    return lt.tm_hour * 60 + lt.tm_min + lt.tm_sec / 60.0


def state(now: float | None = None) -> dict:
    """Battery state for a given wall-clock time (deterministic)."""
    now = time.time() if now is None else now
    mins = _minutes_of_day(now)

    if mins < CHARGE_END_MIN:  # overnight charge
        frac = (mins - CHARGE_START_MIN) / float(CHARGE_END_MIN - CHARGE_START_MIN)
        level = LEVEL_AT_CHARGE_START + frac * (LEVEL_AT_CHARGE_END - LEVEL_AT_CHARGE_START)
        charging = True
    else:                      # daytime discharge
        span = 1440.0 - CHARGE_END_MIN
        frac = (mins - CHARGE_END_MIN) / span
        level = LEVEL_AT_CHARGE_END - frac * (LEVEL_AT_CHARGE_END - LEVEL_AT_DAY_END)
        charging = False

    level = max(1, min(100, int(round(level))))
    # temperature: diurnal curve (~28-30.5 C), +3 C while charging
    temp_c = 28.0 + 1.5 * math.sin(2 * math.pi * (mins / 1440.0)) + (3.0 if charging else 0.0)
    counter = int(CAPACITY_UAH * level / 100.0)

    return {
        "level": level,
        "charging": charging,
        "status": 2 if charging else 3,       # 2=charging, 3=discharging
        "ac": 1 if charging else 0,
        "usb": 1 if charging else 0,
        "wireless": 0,
        "present": 1,
        "health": 2,                          # good
        "scale": 100,
        "temp_tenths": int(round(temp_c * 10)),
        "counter_uah": counter,
        "temperature_c": round(temp_c, 1),
    }


def adb_commands(st: dict) -> list[str]:
    """dumpsys battery commands for the modelled state (fields Android accepts)."""
    return [
        "dumpsys battery set -f present %d" % st["present"],
        "dumpsys battery set -f level %d" % st["level"],
        "dumpsys battery set -f status %d" % st["status"],
        "dumpsys battery set -f health %d" % st["health"],
        "dumpsys battery set -f ac %d" % st["ac"],
        "dumpsys battery set -f usb %d" % st["usb"],
        "dumpsys battery set -f wireless %d" % st["wireless"],
        "dumpsys battery set -f temp %d" % st["temp_tenths"],
        "dumpsys battery set -f counter %d" % st["counter_uah"],
    ]
