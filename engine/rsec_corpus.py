"""rsec-corpus — replayable corpus store + recursive crawl (v2 Phase 4-py).

T4.3 corpus store: content-addressed request/response pairs on disk, indexed
    by (method, url-hash). Append-only; integrity via sha256.
T4.4 replay: deterministic re-issue + status/header/body-hash diff.
T4.5 recursive crawler: BFS + JS-route extraction (regex), bounded; discovers
    routes a plain href crawl misses (SPA fixture tested).
"""
from __future__ import annotations

import asyncio
import hashlib
import http.client
import json
import re
import time
import urllib.parse
from pathlib import Path

MAX_BODY = 256 * 1024
ROUTE_PATTERNS = [
    re.compile(r"(?:fetch|axios|\burl)\s*[(=:]\s*[`\"']([^`\"'()\s]+)[`\"']"),
    re.compile(r"[`\"'](\/api\/[A-Za-z0-9_\-/.{}$]+)[`\"']"),
    re.compile(r"[`\"'](\/v[0-9][A-Za-z0-9_\-/.{}$]*)[\"']"),
]


def sha(data: str) -> str:
    return hashlib.sha256(data.encode("utf8")).hexdigest()


class CorpusStore:
    """T4.3 — content-addressed request/response pairs on disk."""

    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.json"
        self.index: dict[str, dict] = {}
        if self.index_path.exists():
            self.index = json.loads(self.index_path.read_text(encoding="utf8"))

    def _save_index(self) -> None:
        self.index_path.write_text(json.dumps(self.index, indent=1), encoding="utf8")

    def put(self, method: str, url: str, status: int, headers: dict, body: str) -> str:
        body_hash = sha(body)
        entry = {
            "method": method.upper(),
            "url": url,
            "status": status,
            "headers": headers,
            "body_hash": body_hash,
            "body_bytes": len(body.encode("utf8")),
        }
        key = f"{method.upper()}:{sha(url)}:{sha(body + url)}"
        ref = sha(json.dumps(entry, sort_keys=True))
        self.index[key] = {**entry, "ref": ref}
        body_file = self.root / f"{ref}.body"
        if not body_file.exists():
            body_file.write_text(body, encoding="utf8")
        self._save_index()
        return ref

    def entries(self) -> list[dict]:
        return list(self.index.values())

    def body_for(self, ref: str) -> str | None:
        f = self.root / f"{ref}.body"
        return f.read_text(encoding="utf8") if f.exists() else None


def fetch_one(method: str, url: str, headers: dict | None = None,
              body: str | None = None, timeout: float = 15.0) -> dict:
    """Single hop — no auto redirects (each hop is re-issued explicitly)."""
    u = urllib.parse.urlsplit(url)
    cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = cls(u.hostname, u.port or (443 if u.scheme == "https" else 80), timeout=timeout)
    request_target = (u.path or "/") + (("?" + u.query) if u.query else "")
    try:
        conn.request(method, request_target, body=body.encode("utf8") if body else None,
                     headers=headers or {"User-Agent": "R-SecopsXD-Corpus/0.1"})
        res = conn.getresponse()
        raw = res.read(MAX_BODY)
        return {
            "status": res.status,
            "headers": {k: v for k, v in res.getheaders()},
            "body": raw.decode("utf8", "replace"),
            "location": res.getheader("location"),
        }
    finally:
        conn.close()


async def replay(store: CorpusStore, scope_origins: list[str],
                 max_hops: int = 5) -> dict:
    """T4.4 — deterministic re-issue of every corpus entry + status/hash diff.

    Returns {entries: [{url, replayed_status, original_status, body_changed}],
    changed_count}. Out-of-scope entries are skipped (counted, not followed).
    """
    results: list[dict] = []
    changed = 0
    skipped = 0
    for entry in store.entries():
        url = entry["url"]
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        in_scope = any(
            host == (urllib.parse.urlsplit(o).hostname or "").lower() for o in scope_origins
        )
        if not in_scope:
            skipped += 1
            continue
        try:
            res = await asyncio.to_thread(fetch_one, entry["method"], url)
        except Exception as e:  # noqa: BLE001
            results.append({"url": url, "error": str(e)})
            continue
        # redirect hops: follow manually within scope, bounded
        hops = 0
        while 300 <= res["status"] < 400 and res.get("location") and hops < max_hops:
            nxt = urllib.parse.urljoin(url, res["location"])
            try:
                res = await asyncio.to_thread(fetch_one, "GET", nxt)
                url = nxt
                hops += 1
            except Exception as e:  # noqa: BLE001
                results.append({"url": nxt, "error": str(e)})
                break
        else:
            body_changed = sha(res["body"]) != entry["body_hash"]
            status_changed = res["status"] != entry["status"]
            if body_changed or status_changed:
                changed += 1
            results.append({
                "url": url,
                "replayed_status": res["status"],
                "original_status": entry["status"],
                "body_changed": body_changed,
                "status_changed": status_changed,
            })
    return {"entries": results, "changed_count": changed, "skipped_out_of_scope": skipped}


def extract_routes(bundle: str) -> list[str]:
    """JS-route extraction (shared by the recursive crawler)."""
    out: list[str] = []
    seen: set[str] = set()
    for pattern in ROUTE_PATTERNS:
        for m in pattern.finditer(bundle):
            raw = m.group(1).strip()
            if raw.startswith("/") and not raw.startswith("//") and raw not in seen:
                seen.add(raw)
                out.append(raw)
    return out


async def crawl(origin: str, max_pages: int = 30, timeout: float = 15.0,
                signal=None) -> dict:
    """T4.5 — recursive crawler: BFS over hrefs + JS-route extraction.

    Discovers routes a plain href crawl misses (SPA fixture tested).
    Bounded: max_pages, per-request timeout, same-origin only.
    """
    origin_u = urllib.parse.urlsplit(origin)
    base = f"{origin_u.scheme}://{origin_u.netloc}"
    queue: list[str] = [origin + ("/" if not origin.endswith("/") else "")]
    seen: set[str] = set()
    pages: list[dict] = []
    js_routes: set[str] = set()
    while queue and len(pages) < max_pages:
        if signal is not None and hasattr(signal, "is_set") and signal.is_set():
            break
        url = queue.pop(0)
        norm = urllib.parse.urlsplit(url)
        if f"{norm.scheme}://{norm.netloc}{norm.path}" in seen:
            continue
        seen.add(f"{norm.scheme}://{norm.netloc}{norm.path}")
        try:
            res = await asyncio.to_thread(fetch_one, "GET", url, None, None, timeout)
        except Exception:  # noqa: BLE001
            continue
        if 300 <= res["status"] < 400 and res.get("location"):
            nxt = urllib.parse.urljoin(url, res["location"])
            if urllib.parse.urlsplit(nxt).netloc == origin_u.netloc:
                queue.append(nxt)
            continue
        body = res["body"]
        pages.append({"url": url, "status": res["status"], "body_bytes": len(body)})
        # Script-src bundles: fetch same-origin .js and extract routes from them
        # (SPA route discovery — hrefs never reference these).
        for src in re.findall(r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', body, re.I):
            su = urllib.parse.urljoin(url, src)
            su_u = urllib.parse.urlsplit(su)
            if su_u.netloc != origin_u.netloc or not su_u.path.endswith(".js"):
                continue
            if su in seen:
                continue
            seen.add(su)
            try:
                bres = await asyncio.to_thread(fetch_one, "GET", su, None, None, timeout)
            except Exception:  # noqa: BLE001
                continue
            if bres["status"] == 200:
                for route in extract_routes(bres["body"]):
                    ru = urllib.parse.urljoin(su, route)
                    ru_u = urllib.parse.urlsplit(ru)
                    if ru_u.netloc == origin_u.netloc and ru_u.path not in js_routes:
                        js_routes.add(ru_u.path)
                        if len(pages) + len(queue) < max_pages:
                            queue.append(f"{ru_u.scheme}://{ru_u.netloc}{ru_u.path}")
        for route in extract_routes(body):
            absu = urllib.parse.urljoin(url, route)
            ru = urllib.parse.urlsplit(absu)
            if ru.netloc == origin_u.netloc and ru.path not in js_routes:
                js_routes.add(ru.path)
                if len(pages) + len(queue) < max_pages:
                    queue.append(f"{ru.scheme}://{ru.netloc}{ru.path}")
        hrefs = re.findall(r"<a\s[^>]*href\s*=\s*[\"']([^\"'#]+)[\"']", body, re.I)
        for h in hrefs:
            au = urllib.parse.urljoin(url, h)
            au_u = urllib.parse.urlsplit(au)
            if au_u.netloc == origin_u.netloc and au_u.scheme in ("http", "https"):
                queue.append(au)

    return {
        "pages": pages,
        "js_routes": sorted(js_routes)[:MAX_BODY and 60],
        "crawled": len(pages),
    }
