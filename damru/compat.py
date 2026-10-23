"""Playwright-on-Android compatibility shims.

Chrome on Android exposes CDP over a Unix socket, but several Playwright
operations assume desktop Chrome behaviour and hang or fail:

  * page.screenshot()  waits for fonts/layout and can hang (Page.captureScreenshot
    with fromSurface=true stalls on Redroid). We fall back to fromSurface=false.
  * page.set_content() waits for a 'load' event that never fires for injected
    documents. We fall back to CDP Page.setDocumentContent.
  * page.wait_for_load_state() can wait forever after SPA navigations.
  * page.goto() occasionally reports a timeout even though the document loaded.

Everything here is CDP/engine level - no JS is injected into the page.
"""
from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import Any, Optional

from .utils import logger


def _extract_path(args: tuple, kwargs: dict) -> Optional[str]:
    path = kwargs.get("path")
    if path is None and args:
        first = args[0]
        if isinstance(first, (str, Path)):
            path = first
    return str(path) if path else None


def install_page_compat(page: Any) -> None:
    """Idempotently make a Playwright Page behave on Android Chrome."""
    if getattr(page, "_damru_compat", False):
        return

    context = page.context

    async def _cdp():
        return await context.new_cdp_session(page)

    # ---- screenshot -------------------------------------------------------
    original_screenshot = page.screenshot

    async def screenshot(*args, **kwargs):
        try:
            return await asyncio.wait_for(original_screenshot(*args, **kwargs), timeout=6.0)
        except Exception as exc:
            logger.debug("Native screenshot failed (%s); using CDP capture", exc)
        fmt = kwargs.get("type") or "png"
        try:
            cdp = await _cdp()
            res = await cdp.send(
                "Page.captureScreenshot",
                {"format": fmt, "fromSurface": False, "captureBeyondViewport": False},
            )
            await cdp.detach()
            data = base64.b64decode(res.get("data", ""))
            path = _extract_path(args, kwargs)
            if path:
                Path(path).write_bytes(data)
                return None
            return data
        except Exception as exc:
            logger.warning("CDP screenshot failed: %s", exc)
            raise

    # ---- set_content ------------------------------------------------------
    original_set_content = page.set_content

    async def set_content(html: str, **kwargs):
        try:
            return await asyncio.wait_for(original_set_content(html, **kwargs), timeout=6.0)
        except Exception as exc:
            logger.debug("Native set_content failed (%s); using CDP", exc)
        cdp = await _cdp()
        try:
            tree = await cdp.send("Page.getFrameTree")
            frame_id = tree["frameTree"]["frame"]["id"]
            await cdp.send("Page.setDocumentContent", {"frameId": frame_id, "html": html})
        finally:
            await cdp.detach()

    # ---- wait_for_load_state ---------------------------------------------
    original_wait = page.wait_for_load_state

    async def wait_for_load_state(*args, **kwargs):
        timeout = kwargs.pop("timeout", 8000)
        try:
            return await asyncio.wait_for(original_wait(*args, **kwargs), timeout=timeout / 1000.0)
        except Exception:
            return None

    # ---- goto -------------------------------------------------------------
    original_goto = page.goto

    async def goto(url: str, **kwargs):
        last: Optional[Exception] = None
        for attempt in range(2):
            try:
                return await original_goto(url, **kwargs)
            except Exception as exc:
                last = exc
                msg = str(exc)
                if "ERR_ABORTED" in msg:
                    return None
                if attempt == 0:
                    await asyncio.sleep(0.3)
        raise last  # type: ignore[misc]

    for name, fn in (
        ("screenshot", screenshot),
        ("set_content", set_content),
        ("wait_for_load_state", wait_for_load_state),
        ("goto", goto),
    ):
        try:
            setattr(page, name, fn)
        except Exception:
            pass
    try:
        setattr(page, "_damru_compat", True)
    except Exception:
        pass
