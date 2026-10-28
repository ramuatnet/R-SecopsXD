#!/usr/bin/env python3
"""rsec-engine — Python data plane for R-SecopsXD (v2 Phase 0-py / T4.1-py).

JSON-RPC daemon over newline-delimited stdio (engine/proto/v1.md).
Stdlib-only: asyncio + http.client. Honors the platform invariants:

  I1  all HTTP passes the scope/safety envelope carried in each request
  I2  scope origins enforced on EVERY redirect hop (manual redirect handling)
  I4  secrets redacted on capture (headers + body excerpts)
  I10 budget: max_requests enforced for the engine lifetime

The control plane (TS) supplies the scope/safety envelope per request, so the
safety policy is set — and audited — by the control plane, not the engine.
Rust migration later replaces this process behind the identical protocol.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import re
import sys
import threading
import time
import urllib.parse
import uuid

ENGINE = "rsec-engine-py"
VERSION = "0.1.1-py2"
MAX_BODY_BYTES = 256 * 1024
MAX_REDIRECT_HOPS_DEFAULT = 5

REDACT_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie",
                  "x-api-key", "x-auth-token", "x-session-token", "x-csrf-token"}

REDACT_BODY_PATTERNS = [
    (re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}", re.I), "Bearer [REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "[REDACTED-API-KEY]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b"), "[REDACTED-JWT]"),
]


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in REDACT_HEADERS:
            cut = v.find("=")
            out[k] = (v[: cut + 1] if cut >= 0 else "") + "[REDACTED]"
        else:
            out[k] = v
    return out


def redact_text(text: str, max_len: int = 2048) -> str:
    for pattern, repl in REDACT_BODY_PATTERNS:
        text = pattern.sub(repl, text)
    if len(text) > max_len:
        text = text[:max_len] + f"…[truncated {len(text) - max_len}]"
    return text


class ScopeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def parse_origin(origin: str) -> tuple[str, str, int]:
    u = urllib.parse.urlsplit(origin)
    scheme = u.scheme.lower()
    if scheme not in ("http", "https"):
        raise ScopeError("bad_request", f"origin must be http(s), got {u.scheme!r}")
    port = u.port or (443 if scheme == "https" else 80)
    return scheme, u.hostname.lower(), port


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = rate_per_sec
        self.burst = burst
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> float:
        """Reserve one token; returns seconds to wait before the request."""
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= 1:
                self.tokens -= 1
                return 0.0
            return (1 - self.tokens) / self.rate


class EngineState:
    def __init__(self):
        self.buckets: dict[str, TokenBucket] = {}
        self.bucket_lock = threading.Lock()
        self.requests_sent = 0
        self.max_requests_hit = False

    def bucket_for(self, key: str, rate: float, burst: int) -> TokenBucket:
        with self.bucket_lock:
            b = self.buckets.get(key)
            if b is None:
                b = TokenBucket(rate, burst)
                self.buckets[key] = b
            return b


STATE = EngineState()


def scoped_url(raw_url: str, scope: dict) -> urllib.parse.SplitResult:
    u = urllib.parse.urlsplit(raw_url)
    if u.scheme not in ("http", "https"):
        raise ScopeError("scope_blocked", f"blocked non-http(s) scheme: {u.scheme!r}")
    if u.username or u.password:
        raise ScopeError("scope_blocked", "blocked URL with embedded credentials")
    host = (u.hostname or "").lower()
    port = u.port or (443 if u.scheme == "https" else 80)
    allowed = False
    for origin in scope.get("origins", []):
        s, oh, op = parse_origin(origin)
        if host == oh and port == op:
            allowed = True
            break
    if not allowed:
        raise ScopeError("scope_blocked", f"out-of-scope request blocked: {host}:{port} not in {scope.get('origins')}")
    return u


def http_request(method: str, url: str, scope: dict, safety: dict, budget: dict,
                 headers: dict[str, str] | None = None,
                 body: str | None = None, content_type: str | None = None) -> dict:
    """Single hop — manual redirect handling lives in http_get/http_post."""
    hop_scope = dict(scope)
    hop_scope["origins"] = scope.get("origins", [])
    scoped_url(url, hop_scope)  # raises ScopeError when out of scope

    rate = float(safety.get("rate_per_sec", 10))
    burst = int(safety.get("burst", 20))
    u = urllib.parse.urlsplit(url)
    key = f"{u.scheme}://{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"

    bucket = STATE.bucket_for(key, rate, burst)
    delay = bucket.take()
    if delay > 0:
        time.sleep(delay)

    if STATE.max_requests_hit:
        raise ScopeError("budget_exhausted", "engine request budget exhausted")
    STATE.requests_sent += 1
    max_req = int(budget.get("max_requests", 0) or 0)
    if max_req > 0 and STATE.requests_sent > max_req:
        STATE.max_requests_hit = True
        raise ScopeError("budget_exhausted", f"engine request budget exhausted (max_requests={max_req})")

    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.hostname, u.port or (443 if u.scheme == "https" else 80), timeout=15)
    send_headers = {"User-Agent": "R-SecopsXD-Engine/0.1 (authorized scan)", "Accept": "*/*"}
    if headers:
        send_headers.update(headers)
    if body is not None and content_type:
        send_headers["Content-Type"] = content_type
    payload = body.encode("utf8") if body is not None else None
    try:
        conn.request(method, url, body=payload, headers=send_headers)
        res = conn.getresponse()
        raw = res.read(MAX_BODY_BYTES + 1)
        truncated = len(raw) > MAX_BODY_BYTES
        body_text = raw[:MAX_BODY_BYTES].decode("utf8", "replace")
        resp_headers = {k: v for k, v in res.getheaders()}
        return {
            "status": res.status,
            "headers": redact_headers(resp_headers),
            "request_headers": redact_headers(send_headers),
            "body": redact_text(body_text),
            "truncated": truncated or len(raw) > MAX_BODY_BYTES,
            "location": resp_headers.get("location"),
        }
    finally:
        conn.close()


def do_http(method: str, params: dict) -> dict:
    scope = params.get("scope", {})
    safety = params.get("safety", {})
    budget = params.get("budget", {})
    args = params.get("args", {})
    url = args["url"]
    headers = args.get("headers") or {}
    body = args.get("body")
    content_type = args.get("content_type")
    max_hops = int(scope.get("max_redirect_hops", MAX_REDIRECT_HOPS_DEFAULT))
    allowed_methods = {"GET", "HEAD", "POST"}
    if method not in allowed_methods:
        raise ScopeError("safety_blocked", f"method {method} not permitted by platform policy")

    chain: list[str] = []
    started = time.monotonic()
    for hop in range(max_hops + 1):
        hop_res = http_request(method, url, scope, safety, budget, headers, body, content_type)
        location = hop_res.get("location")
        if not (300 <= hop_res["status"] < 400 and location):
            return {
                "status": hop_res["status"],
                "headers": hop_res["headers"],
                "request_headers": hop_res.get("request_headers", {}),
                "body": hop_res["body"],
                "final_url": url,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "truncated": hop_res["truncated"],
                "redirect_chain": chain,
                "evidence_ref": None,
            }
        chain.append(url)
        if hop >= max_hops:
            raise ScopeError("scope_blocked", f"too many redirects (>{max_hops})")
        url = urllib.parse.urljoin(url, location)  # next hop re-validated by scoped_url
    raise ScopeError("scope_blocked", "unreachable")


def do_recon(params: dict) -> dict:
    origin = params["scope"]["origins"][0]
    root = do_http("GET", origin + "/", params["scope"], params.get("safety", {}), params.get("budget", {}))
    tech: list[str] = []
    server = root["headers"].get("server")
    if server:
        tech.append(f"server:{server}")
    powered = root["headers"].get("x-powered-by")
    if powered:
        tech.append(f"x-powered-by:{powered}")
    return {"headers": root["headers"], "body_excerpt": root["body"][:400], "tech": tech}


async def handle_request(msg: dict) -> dict:
    mid = msg.get("id")
    method = msg.get("method", "")
    params = msg.get("params", {}) or {}
    try:
        if method == "ping":
            return {"id": mid, "result": {"pong": True, "engine": ENGINE, "version": VERSION}}
        if method.startswith("http."):
            verb = method.split(".", 1)[1].upper()
            if verb not in ("GET", "HEAD", "POST"):
                raise ScopeError("safety_blocked", f"method {verb} not permitted by platform policy")
            if verb in ("POST",) and "body" not in (params.get("args") or {}):
                raise ScopeError("bad_request", "http.post requires args.body")
            return {"id": mid, "result": do_http(verb, params)}
        if method == "recon":
            return {"id": mid, "result": do_recon(params)}
        if method == "shutdown":
            return {"id": mid, "result": {"ok": True}}
        return {"id": mid, "error": {"code": "bad_request", "message": f"unknown method: {method}"}}
    except ScopeError as e:
        return {"id": mid, "error": {"code": e.code, "message": str(e)}}
    except Exception as e:  # noqa: BLE001 — engine must never die on a request
        return {"id": mid, "error": {"code": "internal", "message": f"{type(e).__name__}: {e}"}}


async def main() -> None:
    loop = asyncio.get_running_loop()
    shutdown = asyncio.Event()

    def read_stdin_lines():
        for line in sys.stdin:
            yield line

    async def process(line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return  # malformed frame: ignored (control plane owns framing health)
        resp = await handle_request(msg)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        if msg.get("method") == "shutdown":
            shutdown.set()

    reader = asyncio.to_thread  # placeholder to keep flake lint quiet
    del reader

    queue: asyncio.Queue[str] = asyncio.Queue()

    def pump_stdin() -> None:
        try:
            for line in read_stdin_lines():
                loop.call_soon_threadsafe(queue.put_nowait, line)
        except Exception:
            pass
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, "__EOF__")

    threading.Thread(target=pump_stdin, daemon=True).start()

    while True:
        line = await queue.get()
        if line == "__EOF__":
            break
        await process(line)
        if shutdown.is_set():
            break


if __name__ == "__main__":
    asyncio.run(main())
