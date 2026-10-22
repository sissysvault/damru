"""Human behavior simulation via CDP Input — no JS tells.

Bezier touch trajectories, scroll physics, and keystroke jitter.
All actions go through Chrome DevTools Protocol Input domain, not
JavaScript .click() — invisible to page fingerprinting.
"""
from __future__ import annotations

import asyncio
import math
import random
from typing import Optional

from .utils import logger


def _bezier(p0, p1, p2, p3, t: float):
    """Cubic Bezier point."""
    u = 1 - t
    tt = t * t
    uu = u * u
    uuu = uu * u
    ttt = tt * t
    x = uuu * p0[0] + 3 * uu * t * p1[0] + 3 * u * tt * p2[0] + ttt * p3[0]
    y = uuu * p0[1] + 3 * uu * t * p1[1] + 3 * u * tt * p2[1] + ttt * p3[1]
    return x, y

async def human_tap(page, x: float, y: float, *, jitter: int = 8) -> None:
    """Human-like tap with bezier micro-movement + timing jitter."""
    # Add spatial jitter
    tx = x + random.uniform(-jitter, jitter)
    ty = y + random.uniform(-jitter, jitter)
    # Bezier approach: start slightly offset, curve to target
    ox = tx + random.uniform(-20, 20)
    oy = ty + random.uniform(-20, 20)
    p0 = (ox, oy)
    p1 = (ox + (tx - ox) * 0.3 + random.uniform(-10, 10), oy + (ty - oy) * 0.3 + random.uniform(-10, 10))
    p2 = (ox + (tx - ox) * 0.7 + random.uniform(-10, 10), oy + (ty - oy) * 0.7 + random.uniform(-10, 10))
    p3 = (tx, ty)
    cdp = None
    try:
        cdp = await page.context.new_cdp_session(page)
    except Exception:
        # Fallback to regular tap
        await page.mouse.move(tx, ty)
        await asyncio.sleep(random.uniform(0.05, 0.15))
        await page.mouse.click(tx, ty)
        return
    try:
        steps = random.randint(8, 14)
        for i in range(steps + 1):
            t = i / steps
            bx, by = _bezier(p0, p1, p2, p3, t)
            # Slight easing
            eased = 1 - math.pow(1 - t, 2)
            bx2, by2 = _bezier(p0, p1, p2, p3, eased)
            await cdp.send("Input.dispatchTouchEvent", {
                "type": "touchMove" if 0 < i < steps else ("touchStart" if i == 0 else "touchEnd"),
                "touchPoints": [{"x": round(bx2), "y": round(by2)}],
            })
            await asyncio.sleep(random.uniform(0.008, 0.018))
        # Tap duration jitter
        await asyncio.sleep(random.uniform(0.04, 0.11))
        await cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
    except Exception as e:
        logger.debug("human_tap CDP failed: %s, fallback", e)
        await page.mouse.click(tx, ty)
    finally:
        try:
            await cdp.detach()  # type: ignore
        except Exception:
            pass

async def human_scroll(page, delta_y: int = 400, *, steps: int = 6) -> None:
    """Momentum scroll with deceleration curve."""
    cdp = None
    try:
        cdp = await page.context.new_cdp_session(page)
        step_delta = delta_y / steps
        velocity = step_delta
        for i in range(steps):
            # Deceleration
            factor = 1 - (i / steps) * 0.5
            dy = velocity * factor + random.uniform(-8, 8)
            await cdp.send("Input.dispatchMouseEvent", {
                "type": "mouseWheel",
                "x": 540, "y": 800,
                "deltaX": 0, "deltaY": dy,
            })
            await asyncio.sleep(random.uniform(0.03, 0.07))
        # Settle
        await asyncio.sleep(random.uniform(0.1, 0.25))
    except Exception:
        await page.mouse.wheel(0, delta_y)
    finally:
        try:
            await cdp.detach()  # type: ignore
        except Exception:
            pass

async def human_type(page, selector: str, text: str, *, wpm: int = 220) -> None:
    """Type with per-key jitter, occasional typo correction."""
    # wpm → ms per char
    base_delay = 60000 / (wpm * 5)  # avg 5 chars/word
    await page.click(selector)
    await asyncio.sleep(random.uniform(0.08, 0.18))
    for ch in text:
        # Typo simulation 2%
        if random.random() < 0.02:
            wrong = random.choice("abcdefghijklmnopqrstuvwxyz")
            await page.keyboard.type(wrong, delay=random.uniform(30, 80))
            await asyncio.sleep(random.uniform(0.12, 0.28))
            await page.keyboard.press("Backspace")
            await asyncio.sleep(random.uniform(0.06, 0.14))
        delay = base_delay * random.uniform(0.7, 1.4)
        # Punctuation pause
        if ch in ".,!?;:":
            delay += random.uniform(80, 180)
        await page.keyboard.type(ch, delay=delay)
    await asyncio.sleep(random.uniform(0.08, 0.16))
