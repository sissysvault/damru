"""mitmproxy addon: write a HAR 1.2 file equivalent to Playwright's network HAR.

Captures per flow:
  request: method, url, httpVersion, headers, queryString, cookies, postData
  response: status, statusText, httpVersion, headers, cookies (Set-Cookie),
            content (text or base64), redirectURL, sizes
  timings: send / wait / receive, total time, server IP
Also records failed flows with status 0 and an error string.
"""
import base64
import gzip
import json
import zlib
import os
import time

from mitmproxy import http

OUT = os.environ.get("DAMRU_HAR_OUT", "capture.har")
_entries = []

_TEXTUAL = ("text/", "application/json", "application/javascript", "application/xml",
            "application/x-www-form-urlencoded", "application/graphql", "application/protobuf")

MAX_BODY = int(os.environ.get("DAMRU_HAR_MAX_BODY", "2000000"))


def _jsonsafe(o):
    """json.dumps(ensure_ascii=False) raises on lone surrogates, which mitm
    produces for binary header/cookie bytes (surrogateescape). One poisoned
    Set-Cookie value silently killed whole entries (except: pass) and
    truncated the final HAR write. Clean every string before dumping."""
    if isinstance(o, str):
        try:
            o.encode("utf-8")
            return o
        except UnicodeEncodeError:
            return o.encode("utf-8", "replace").decode("utf-8", "replace")
    if isinstance(o, dict):
        return {k: _jsonsafe(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_jsonsafe(v) for v in o]
    return o


def _iso(ts):
    if not ts:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + (".%03dZ" % int((ts % 1) * 1000))


def _headers(msg):
    return [{"name": k, "value": v} for k, v in msg.headers.items()]


def _multi(view):
    """Cookie/query multi-views. mitm may yield (name, value) tuples, plain
    strings, or Cookie/CookieAttrs objects; every shape became a str, since
    a stray CookieAttrs object raised TypeError in json.dumps and killed the
    whole entry (register/auth flows carry these rich cookies)."""
    out = []
    try:
        items = list(view.items(multi=True))
    except TypeError:
        try:
            items = list(view.items())
        except Exception:
            return []
    except Exception:
        return []
    for it in items:
        if isinstance(it, tuple) and len(it) == 2:
            out.append({"name": str(it[0]), "value": str(it[1])})
        elif isinstance(it, str):
            out.append({"name": it, "value": ""})
        else:
            nm = getattr(it, "name", None)
            if nm is None:
                nm = getattr(it, "key", None)
            vl = getattr(it, "value", None)
            if nm is not None:
                out.append({"name": str(nm), "value": str(vl) if vl is not None else ""})
    return out


def _decompress(msg, raw):
    """Undo gzip/deflate/br content-encoding so bodies are readable in the HAR."""
    enc = (msg.headers.get("content-encoding", "") or "").lower()
    try:
        if "gzip" in enc or raw[:2] == b"\x1f\x8b":
            return gzip.decompress(raw)
        if "deflate" in enc:
            try:
                return zlib.decompress(raw)
            except Exception:
                return zlib.decompress(raw, -15)
        if "br" in enc:
            try:
                import brotli  # optional
                return brotli.decompress(raw)
            except Exception:
                return raw
    except Exception:
        return raw
    return raw


def _body(msg, mime):
    raw = _decompress(msg, msg.raw_content or b"")
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
    # Live request/response event stream (Playwright-style in-flight
    # visibility), separate from the HAR entries so the HAR rebuild from
    # OUT.jsonl stays untouched. Consumers tail this with damru.netstream.
    def request(self, flow: http.HTTPFlow):
        self._event("request", flow)

    def response(self, flow: http.HTTPFlow):
        self._event("response", flow)
        self._record(flow)

    def error(self, flow: http.HTTPFlow):
        self._event("error", flow)
        self._record(flow, error=str(flow.error)[:300] if flow.error else "error")

    def _event(self, kind, flow):
        ev = {"kind": kind, "id": flow.id,
              "ts": flow.request.timestamp_start or time.time(),
              "method": flow.request.method, "url": flow.request.pretty_url}
        if flow.response is not None:
            ev["status"] = flow.response.status_code
        elif kind == "error":
            ev["status"] = 0
        try:
            with open(OUT + ".events.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(_jsonsafe(ev), ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass

    def _record(self, flow, error=""):
        try:
            self._record_opts(flow, error)
        except Exception as exc:
            # a malformed view (query strings, cookies, odd content-encoding)
            # must never lose the whole entry: emit a minimal one and log it
            entry = {"startedDateTime": _iso(time.time()), "time": 0,
                     "request": {"method": flow.request.method,
                                 "url": flow.request.pretty_url,
                                 "httpVersion": flow.request.http_version or "",
                                 "headers": [], "queryString": [], "cookies": [],
                                 "headersSize": -1, "bodySize": 0},
                     "response": {"status": (flow.response.status_code
                                             if flow.response is not None else 0),
                                  "statusText": "", "httpVersion": "",
                                  "headers": [], "cookies": [],
                                  "content": {"size": 0, "mimeType": ""},
                                  "redirectURL": "", "headersSize": -1, "bodySize": 0},
                     "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
                     "_record_error": str(exc)[:200]}
            _entries.append(entry)
            try:
                with open(OUT + ".jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps(_jsonsafe(entry), ensure_ascii=False, default=str) + "\n")
            except Exception:
                pass

    def _record_opts(self, flow, error=""):
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
                f.write(json.dumps(_jsonsafe(entry), ensure_ascii=False, default=str) + "\n")
        except Exception as _e:
            with open(OUT + ".jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps({"_dump_error": str(_e)[:120],
                                    "url": req.pretty_url}, ensure_ascii=True, default=str) + "\n")
        

    def done(self):
        har = {"log": {"version": "1.2",
                       "creator": {"name": "damru-netcap", "version": "1.1"},
                       "entries": _entries}}
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(_jsonsafe(har), f, ensure_ascii=False, default=str)
        print(f"HAR written: {OUT} ({len(_entries)} entries)", flush=True)


addons = [HARRecorder()]
