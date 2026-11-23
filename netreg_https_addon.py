"""
netreg_https_addon.py -- mitmproxy addon that records each intercepted
request/response as ONE JSON line, for NetworkRegulator's HTTPS content view.

====================  OWN-NETWORK / AUTHORIZED USE ONLY  ====================
This is loaded by mitmdump only while the user has confirmed they own / are
authorized to test the network and has turned HTTPS inspection on. It sees
decrypted content for the one target device whose traffic is redirected to the
proxy (see netreg_https.py). Use on your own network only.
============================================================================

mitmdump loads this with `-s netreg_https_addon.py`. It appends JSONL to the
file named by the NETREG_HTTPS_LOG environment variable (netreg_https.py sets
it), which the GUI tails and parses with netreg_https.parse_flow_line.

It is deliberately conservative: it records metadata (who/what/host/path/
status/size/type) always, and only a short readable SNIPPET of textual bodies,
capped in length, so the log stays small and isn't a full content dump.
"""
import json
import os
import time

SNIPPET_MAX = 240          # chars of a textual body we keep
_TEXTUAL = ("text/", "application/json", "application/xml",
            "application/javascript", "application/x-www-form-urlencoded",
            "application/graphql")


def _log_path():
    return os.environ.get("NETREG_HTTPS_LOG", "")


def _is_textual(content_type: str) -> bool:
    ct = (content_type or "").split(";")[0].strip().lower()
    return any(ct.startswith(t) or ct == t for t in _TEXTUAL)


def _snippet(body: bytes, content_type: str) -> str:
    if not body or not _is_textual(content_type):
        return ""
    try:
        text = body[:SNIPPET_MAX * 4].decode("utf-8", "replace")
    except Exception:
        return ""
    # collapse whitespace so one request is one readable line
    text = " ".join(text.split())
    return text[:SNIPPET_MAX]


def _write(record: dict):
    path = _log_path()
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def response(flow):  # mitmproxy calls this when a response is complete
    try:
        req = flow.request
        resp = flow.response
        ct = ""
        if resp and resp.headers:
            ct = resp.headers.get("content-type", "")
        record = {
            "ts": time.time(),
            "client": flow.client_conn.peername[0] if flow.client_conn
                      and flow.client_conn.peername else "",
            "method": req.method,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "path": req.path,
            "status": resp.status_code if resp else 0,
            "content_type": ct.split(";")[0].strip(),
            "req_bytes": len(req.raw_content or b"") if req.raw_content else 0,
            "resp_bytes": len(resp.raw_content or b"") if resp
                          and resp.raw_content else 0,
            "snippet": _snippet(resp.raw_content if resp else b"", ct),
        }
    except Exception as e:
        record = {"ts": time.time(), "error": f"{type(e).__name__}: {e}"}
    _write(record)
