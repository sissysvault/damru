"""mitmproxy addon: write a HAR 1.2 file equivalent to Playwright's network HAR.

Captures per flow:
  request: method, url, httpVersion, headers, queryString, cookies, postData
  response: status, statusText, httpVersion, headers, cookies (Set-Cookie),
            content (text or base64), redirectURL, sizes
  timings: send / wait / receive, total time, server IP
Also records failed flows with status 0 and an error string.
"""
import base64
import json
import os
import time

from mitmproxy import http

OUT = os.environ.get("DAMRU_HAR_OUT", "capture.har")
_entries = []

_TEXTUAL = ("text/", "application/json", "application/javascript", "application/xml",
            "application/x-www-form-urlencoded", "application/graphql", "application/protobuf")

MAX_BODY = int(os.environ.get("DAMRU_HAR_MAX_BODY", "2000000"))


def _iso(ts):
    if not ts:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + (".%03dZ" % int((ts % 1) * 1000))


def _headers(msg):
    return [{"name": k, "value": v} for k, v in msg.headers.items()]


def _multi(view):
    try:
        return [{"name": k, "value": v} for k, v in view.items(multi=True)]
    except TypeError:
        try:
            return [{"name": k, "value": v} for k, v in view.items()]
        except Exception:
            return []


def _body(msg, mime):
    raw = msg.raw_content or b""
    out = {"size": len(raw), "mimeType": mime}
    if not raw:
        return out
    sample = raw[:MAX_BODY]
    base = mime.split(";")[0].strip().lower()
    textual = base.startswith("text/") or any(base.startswith(t) for t in _TEXTUAL) or "json" in base
    if textual:
        try:
            out["text"] = sample.decode("utf-8", "replace")
        except Exception:
            out["text"] = ""
    else:
        out["text"] = base64.b64encode(sample).decode("ascii")
        out["encoding"] = "base64"
    if len(raw) > MAX_BODY:
        out["comment"] = f"truncated at {MAX_BODY} bytes"
    return out


class HARRecorder:
    def response(self, flow: http.HTTPFlow):
        self._record(flow)

    def error(self, flow: http.HTTPFlow):
        self._record(flow, error=str(flow.error)[:300] if flow.error else "error")

    def _record(self, flow, error=""):
        req = flow.request
        resp = flow.response
        rs = req.timestamp_start or time.time()
        re_ = req.timestamp_end or rs
        ps = (resp.timestamp_start if resp else None) or re_
        pe = (resp.timestamp_end if resp else None) or ps
        total = max(0, int((pe - rs) * 1000))

        req_mime = req.headers.get("content-type", "")
        entry = {
            "startedDateTime": _iso(rs),
            "time": total,
            "request": {
                "method": req.method,
                "url": req.pretty_url,
                "httpVersion": req.http_version or "HTTP/1.1",
                "headers": _headers(req),
                "queryString": _multi(req.query),
                "cookies": _multi(req.cookies),
                "headersSize": -1,
                "bodySize": len(req.raw_content or b""),
            },
            "cache": {},
            "timings": {
                "send": max(0, int((re_ - rs) * 1000)),
                "wait": max(0, int((ps - re_) * 1000)),
                "receive": max(0, int((pe - ps) * 1000)),
            },
            "serverIPAddress": (flow.server_conn.peername[0] if flow.server_conn and flow.server_conn.peername else ""),
        }
        if req.raw_content:
            entry["request"]["postData"] = _body(req, req_mime)

        if resp is not None:
            resp_mime = resp.headers.get("content-type", "")
            entry["response"] = {
                "status": resp.status_code,
                "statusText": resp.reason or "",
                "httpVersion": resp.http_version or "HTTP/1.1",
                "headers": _headers(resp),
                "cookies": _multi(resp.cookies),
                "content": _body(resp, resp_mime),
                "redirectURL": resp.headers.get("location", ""),
                "headersSize": -1,
                "bodySize": len(resp.raw_content or b""),
            }
        else:
            entry["response"] = {
                "status": 0, "statusText": "", "httpVersion": "",
                "headers": [], "cookies": [],
                "content": {"size": 0, "mimeType": ""},
                "redirectURL": "", "headersSize": -1, "bodySize": 0,
                "_error": error or "no response",
            }
        _entries.append(entry)
        # Stream each entry so a hard kill can never lose the capture; the HAR is
        # rebuilt from this file if the process does not shut down cleanly.
        try:
            with open(OUT + ".jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def done(self):
        har = {"log": {"version": "1.2",
                       "creator": {"name": "damru-netcap", "version": "1.1"},
                       "entries": _entries}}
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(har, f, ensure_ascii=False)
        print(f"HAR written: {OUT} ({len(_entries)} entries)", flush=True)


addons = [HARRecorder()]
