"""HAR 1.2 recorder for Playwright sessions (one-stop, no proxy/mitm).

Attach it to a BrowserContext; every request/response on every page (including
pages opened later) is captured with the same fields Playwright's network view
exposes: URL, method, request/response headers, POST data, response body,
request/response cookies, status, timings and server IP.

Usage:
    from damru.har_recorder import HARRecorder
    har = HARRecorder(context, "out.har")
    await har.start()
    ...
    await har.stop()          # writes the .har file

Or simply: AsyncDamru(..., har="out.har")
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import parse_qsl, urlsplit

_TEXTUAL_PREFIX = ("text/", "application/json", "application/javascript",
                   "application/xml", "application/x-www-form-urlencoded",
                   "application/graphql", "application/protobuf", "application/x-protobuf")

MAX_BODY = 2_000_000


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int((ts % 1) * 1000):03d}Z"


def _header_list(headers: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": k, "value": v} for k, v in headers.items()]


def _is_textual(mime: str) -> bool:
    base = (mime or "").split(";")[0].strip().lower()
    return base.startswith("text/") or any(base.startswith(p) for p in _TEXTUAL_PREFIX) or "json" in base


class HARRecorder:
    def __init__(self, context: Any, path: str):
        self.context = context
        self.path = path
        self._entries: list[dict] = []
        self._pending: dict[int, dict] = {}
        self._tasks: set[asyncio.Task] = set()
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        for page in list(self.context.pages):
            self._attach(page)
        self.context.on("page", self._attach)

    def _attach(self, page: Any) -> None:
        page.on("request", lambda req: self._spawn(self._on_request(req)))
        page.on("requestfinished", lambda req: self._spawn(self._on_finished(req)))
        page.on("requestfailed", lambda req: self._spawn(self._on_failed(req)))

    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ── handlers ─────────────────────────────────────────────────────
    async def _on_request(self, request: Any) -> None:
        try:
            headers = await request.all_headers()
        except Exception:
            headers = dict(request.headers)
        post = None
        try:
            if request.post_data is not None:
                post = {"mimeType": headers.get("content-type", ""), "text": request.post_data}
                try:
                    raw = request.post_data_buffer
                    if raw is not None:
                        post["size"] = len(raw)
                        if not _is_textual(post["mimeType"]):
                            post["text"] = base64.b64encode(raw[:MAX_BODY]).decode("ascii")
                            post["encoding"] = "base64"
                except Exception:
                    pass
        except Exception:
            post = None
        self._pending[id(request)] = {
            "started": time.time(),
            "request": {
                "method": request.method,
                "url": request.url,
                "headers": _header_list(headers),
                "postData": post,
                "started": time.time(),
            },
        }

    async def _on_finished(self, request: Any) -> None:
        state = self._pending.pop(id(request), None)
        if state is None:
            return
        response = None
        try:
            response = await request.response()
        except Exception:
            pass
        entry = await self._build_entry(request, response, state, error=None)
        self._entries.append(entry)

    async def _on_failed(self, request: Any) -> None:
        state = self._pending.pop(id(request), None)
        if state is None:
            return
        try:
            failure = request.failure or "request failed"
        except Exception:
            failure = "request failed"
        entry = await self._build_entry(request, None, state, error=str(failure))
        self._entries.append(entry)

    async def _build_entry(self, request: Any, response: Any, state: dict, error: Optional[str]) -> dict:
        req = state["request"]
        started = state["started"]
        now = time.time()

        # request cookies (context-level cookies applicable to the URL)
        req_cookies = []
        try:
            for c in await self.context.cookies(request.url):
                req_cookies.append({"name": c.get("name", ""), "value": c.get("value", "")})
        except Exception:
            pass

        initiator_headers = dict((h["name"].lower(), h["value"]) for h in req["headers"])
        cookie_header = initiator_headers.get("cookie")
        if cookie_header and not req_cookies:
            for part in cookie_header.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    req_cookies.append({"name": k.strip(), "value": v.strip()})

        query = [{"name": k, "value": v} for k, v in parse_qsl(urlsplit(req["url"]).query, keep_blank_values=True)]

        entry: dict = {
            "startedDateTime": _iso(started),
            "time": int((now - started) * 1000),
            "request": {
                "method": req["method"],
                "url": req["url"],
                "httpVersion": "",
                "headers": req["headers"],
                "queryString": query,
                "cookies": req_cookies,
                "headersSize": -1,
                "bodySize": (req["postData"] or {}).get("size", 0),
            },
            "cache": {},
            "timings": {"send": 0, "wait": int((now - started) * 1000), "receive": 0},
        }
        if req.get("postData"):
            entry["request"]["postData"] = req["postData"]

        if response is not None:
            try:
                headers = await response.all_headers()
            except Exception:
                headers = dict(response.headers)
            mime = headers.get("content-type", "")
            body_bytes = b""
            try:
                body_bytes = await response.body()
            except Exception:
                pass
            content: dict = {"size": len(body_bytes), "mimeType": mime}
            if body_bytes:
                sample = body_bytes[:MAX_BODY]
                if _is_textual(mime):
                    content["text"] = sample.decode("utf-8", "replace")
                else:
                    content["text"] = base64.b64encode(sample).decode("ascii")
                    content["encoding"] = "base64"
            resp_cookies = []
            for h in headers.items():
                if h[0].lower() == "set-cookie":
                    for part in str(h[1]).split("\n"):
                        if "=" in part:
                            kv = part.split(";", 1)[0]
                            k, v = kv.split("=", 1)
                            resp_cookies.append({"name": k.strip(), "value": v.strip()})
            server_ip = ""
            try:
                addr = await response.server_addr()
                if addr:
                    server_ip = addr.get("ipAddress", "") if isinstance(addr, dict) else str(addr)
            except Exception:
                pass
            entry["response"] = {
                "status": response.status,
                "statusText": response.status_text,
                "httpVersion": "",
                "headers": _header_list(headers),
                "cookies": resp_cookies,
                "content": content,
                "redirectURL": headers.get("location", ""),
                "headersSize": -1,
                "bodySize": len(body_bytes),
            }
            entry["serverIPAddress"] = server_ip
            try:
                timing = request.timing
                if isinstance(timing, dict) and timing.get("responseEnd") is not None:
                    send = max(0, timing.get("requestStart", 0))
                    wait = max(0, timing.get("responseStart", 0) - timing.get("requestStart", 0))
                    recv = max(0, timing.get("responseEnd", 0) - timing.get("responseStart", 0))
                    entry["timings"] = {"send": int(send), "wait": int(wait), "receive": int(recv)}
                    entry["time"] = int(timing.get("responseEnd", entry["time"]))
            except Exception:
                pass
        else:
            entry["response"] = {
                "status": 0, "statusText": "", "httpVersion": "",
                "headers": [], "cookies": [],
                "content": {"size": 0, "mimeType": ""},
                "redirectURL": "", "headersSize": -1, "bodySize": 0,
                "_error": error or "no response",
            }
        return entry

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        # let in-flight handlers finish
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "damru-playwright", "version": "1.0"},
                "pages": [],
                "entries": self._entries,
            }
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(har, f, ensure_ascii=False)
        self._entries = []
