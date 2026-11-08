"""Live network stream over a running HAR capture (Playwright-style).

The mitm HAR addon appends, in real time:
  <har>.jsonl        one full HAR entry the moment each flow completes
                     (method, url, headers, payload, response status,
                     response headers, Set-Cookie, decompressed body)
  <har>.events.jsonl one small event per flow start/response/error
                     ({"kind","id","ts","method","url"[,"status"]})

This module tails those files so OS-input automation (adb taps/typing)
can gate each UI step on real network confirmation, exactly like
Playwright's page.on('request') / page.wait_for_response() — with no
per-app hooks and no traffic modification.

Usage:
    ns = NetStream("/home/x/damru-work/har/signup-live.har")
    tap(ui.continue_button)                       # human UI action
    r = ns.wait_for_response(".*api/v1/register.*", timeout=30)
    if r and r["response"]["status"] == 200: ...  # proceed; else retry/abort
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Callable, Optional, Pattern


class NetStream:
    """Tail a live damru capture. Safe to start before mitmdump exists.

    `pattern` in wait_* is matched with `re.search` against each event URL
    (mnemonic: same semantics as Playwright's URL-pattern predicates).
    """

    def __init__(self, har_path: str | Path, poll: float = 0.25):
        self.har = str(har_path)
        self.events_path = self.har + ".events.jsonl"
        self.entries_path = self.har + ".jsonl"
        self.poll = poll
        self._event_pos = 0
        self._entry_pos = 0
        # remember file positions across restarts of the producing process:
        # start at current end so we only see events from now on, but if the
        # events file doesn't exist yet (capture not armed), start at 0.
        if os.path.exists(self.events_path):
            self._event_pos = os.path.getsize(self.events_path)
        if os.path.exists(self.entries_path):
            self._entry_pos = os.path.getsize(self.entries_path)

    # -- internal: incremental readers ------------------------------------
    def _read_new(self, path: str, seek: int) -> tuple[int, list[str]]:
        if not os.path.exists(path):
            return seek, []
        with open(path, "r", encoding="utf-8") as f:
            f.seek(seek)
            lines = f.read().splitlines()
            seek = f.tell()
        return seek, [ln for ln in lines if ln.strip()]

    def _new_events(self) -> list[dict]:
        self._event_pos, lines = self._read_new(self.events_path, self._event_pos)
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except Exception:
                pass
        return out

    def _new_entries(self) -> list[dict]:
        self._entry_pos, lines = self._read_new(self.entries_path, self._entry_pos)
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except Exception:
                pass
        return out

    # -- public API ----------------------------------------------------------
    def wait_for_request(self, pattern: str | Pattern,
                         timeout: float = 30.0) -> Optional[dict]:
        """Return the first new request event whose URL matches `pattern`."""
        return self._wait_event("request", pattern, timeout)

    def wait_for_response(self, pattern: str | Pattern,
                          timeout: float = 30.0,
                          predicate: Optional[Callable[[dict], bool]] = None,
                          with_entry: bool = True) -> Optional[dict | tuple]:
        """Wait for a flow whose URL matches `pattern` to complete.

        Returns the full HAR entry (request+response+payload+cookies). If
        `predicate` is given it is applied to candidate events (e.g. status).
        If `with_entry` is False, returns the event instead (available even
        if body capture is disabled).
        """
        if isinstance(pattern, str):
            rx = re.compile(pattern)
        else:
            rx = pattern
        deadline = time.time() + timeout
        while time.time() < deadline:
            for ev in self._new_events():
                if ev.get("kind") in ("response", "error") and rx.search(ev.get("url", "")):
                    if predicate and not predicate(ev):
                        continue
                    if not with_entry:
                        return ev
                    ent = self._entry_for(ev, deadline)
                    return ent if ent is not None else ev
            time.sleep(self.poll)
        return None

    def _entry_for(self, ev: dict, deadline: float) -> Optional[dict]:
        """Find the full HAR entry produced by the flow that emitted `ev`.

        The addon writes an event line and then the entry line for the same
        flow back-to-back (same process, same hook), so once the response
        event is read the matching entry is the next entries-JSONL line(s)
        with the same method+url. Latest match wins (covers same-URL retries).
        """
        best = None
        while time.time() < deadline:
            ents = self._new_entries()
            for ent in ents:
                req = ent.get("request", {})
                if req.get("method") == ev.get("method") and req.get("url") == ev.get("url"):
                    best = ent
            if best is not None:
                return best
            time.sleep(min(self.poll, 0.1))
        return best

    def _wait_event(self, kind: str, pattern: str | Pattern,
                    timeout: float) -> Optional[dict]:
        if isinstance(pattern, str):
            rx = re.compile(pattern)
        else:
            rx = pattern
        deadline = time.time() + timeout
        while time.time() < deadline:
            for ev in self._new_events():
                if ev.get("kind") == kind and rx.search(ev.get("url", "")):
                    return ev
            time.sleep(self.poll)
        return None

    def drain(self) -> list[dict]:
        """Consume and return all unread events (for event-driven loops)."""
        return self._new_events()
