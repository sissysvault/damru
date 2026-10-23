"""Reddit app API client (persisted-query GraphQL), replayed from a captured HAR.

The Reddit Android app talks JSON GraphQL to https://gql-fed.reddit.com/ using
Apollo persisted queries:

    POST https://gql-fed.reddit.com/
    authorization: Bearer <reddit token>          # captured from the app
    content-type: application/json
    {"operationName":"GetAccount","variables":{...},
     "extensions":{"persistedQuery":{"version":1,"sha256Hash":"<hash>"}}}

Responses are gzip-encoded JSON. This module replays those operations with the
same headers so Damru app automation can be driven from the API layer.

Capture the token + ops first:
    async with StealthApp("com.reddit.frontpage", har="reddit.har"): ...
    then damru.reddit_api.load_capture("reddit.har") -> token + op hashes
"""
from __future__ import annotations

import gzip
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

ENDPOINT = "https://gql-fed.reddit.com/"
DEFAULT_UA = "Reddit/Version 2026.42.0/Build 2642001/Android 14"


@dataclass
class GqlOp:
    operationName: str
    sha256Hash: str
    variables_sample: dict


def load_ops(path: str) -> dict[str, GqlOp]:
    d = json.load(open(path, encoding="utf-8"))
    out: dict[str, GqlOp] = {}
    for o in d.get("ops", []):
        out[o["operationName"]] = GqlOp(o["operationName"], o["sha256Hash"], o.get("variables_sample") or {})
    return out


def load_token(path: str) -> str:
    raw = open(path, encoding="utf-8").read().strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:]
    return raw


class RedditAPI:
    def __init__(self, token: str, ops: Optional[dict[str, GqlOp]] = None,
                 proxy: Optional[str] = None, user_agent: str = DEFAULT_UA,
                 impersonate: str = "chrome136", extra_headers: Optional[dict] = None):
        self.token = token
        self.ops = ops or {}
        self.proxy = proxy
        self.user_agent = user_agent
        self.impersonate = impersonate
        self.extra_headers = extra_headers or {}

    def _headers(self) -> dict[str, str]:
        h = {
            "authorization": f"bearer {self.token}",
            "content-type": "application/json",
            "user-agent": self.user_agent,
            "accept-encoding": "gzip",
            "x-reddit-retry": "attempt=0, max=0",
            "requesttimestamp": str(int(time.time() * 1000)),
        }
        for k, v in self.extra_headers.items():
            if k.lower() not in ("host", "content-length", "accept-encoding"):
                h[k] = v
        return h

    def _proxies(self) -> Optional[dict]:
        if not self.proxy:
            return None
        p = self.proxy if "://" in self.proxy else f"http://{self.proxy}"
        if p.startswith("socks5://"):
            p = p.replace("socks5://", "socks5h://")
        return {"http": p, "https": p}

    def gql(self, operation: str, variables: Optional[dict] = None,
            sha256: Optional[str] = None, timeout: int = 20) -> Any:
        op = self.ops.get(operation)
        h = sha256 or (op.sha256Hash if op else None)
        if not h:
            raise ValueError(f"no persisted-query hash for {operation}")
        body = {
            "operationName": operation,
            "variables": variables if variables is not None else (op.variables_sample if op else {}),
            "extensions": {"persistedQuery": {"version": 1, "sha256Hash": h}},
        }
        payload = json.dumps(body)
        try:
            # Browser TLS/JA3 impersonation — Reddit's edge (Fastly) rejects
            # Python's default TLS fingerprint with a 403 HTML page.
            from curl_cffi import requests as creq
            sess = creq.Session(impersonate=self.impersonate)
            proxies = None
            if self.proxy:
                p_ = self.proxy if "://" in self.proxy else f"http://{self.proxy}"
                proxies = {"http": p_, "https": p_}
            r = sess.post(ENDPOINT, headers=self._headers(), data=payload,
                          proxies=proxies, timeout=timeout)
        except ImportError:
            import requests
            r = requests.post(ENDPOINT, headers=self._headers(), data=payload,
                              proxies=self._proxies(), timeout=timeout)
        raw = r.content
        if raw[:2] == b"\x1f\x8b" or "gzip" in r.headers.get("content-encoding", ""):
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        try:
            return json.loads(raw)
        except Exception:
            return {"_status": r.status_code, "_raw": raw[:400].decode("utf-8", "replace")}

    # convenience wrappers for captured operations
    def get_account(self) -> Any:
        return self.gql("GetAccount")

    def badge_count(self) -> Any:
        return self.gql("BadgeCountV2")
