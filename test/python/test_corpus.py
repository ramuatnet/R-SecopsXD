"""Tests for engine/rsec_corpus.py (T4.3 corpus store, T4.4 replay, T4.5 recursive crawl).

Runs against a local HTTP server (stdlib) — SPA fixture included to prove
JS-route discovery finds routes an href crawl misses.
"""
import asyncio
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import sys as _sys, os as _os
_sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..'))
from engine.rsec_corpus import CorpusStore, crawl, extract_routes, replay


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        return

    def do_GET(self):  # noqa: N802
        p = self.path.split("?")[0]
        if p == "/":
            body = ('<script src="/app.js"></script><a href="/pricing">Pricing</a>'
                    '<a href="/blog">Blog</a>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
            return
        if p == "/app.js":
            body = 'fetch("/api/internal/users");fetch("/api/orders");var x=1;'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
            return
        if p in ("/pricing", "/blog", "/api/internal/users", "/api/orders"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"hello")
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_extract_routes():
    bundle = 'fetch("/api/a");axios.get("/api/b");var u="/v2/c";fetch("https://cdn.example/x");'
    routes = extract_routes(bundle)
    assert "/api/a" in routes and "/api/b" in routes and "/v2/c" in routes
    assert not any("cdn.example" in r for r in routes)


def test_corpus_store_roundtrip_and_integrity():
    with tempfile.TemporaryDirectory() as d:
        store = CorpusStore(d)
        ref1 = store.put("GET", "http://t/a", 200, {"server": "test"}, "body-one")
        ref2 = store.put("GET", "http://t/a", 200, {"server": "test"}, "body-one")
        assert ref1 == ref2, "same content = same ref"
        assert store.body_for(ref1) == "body-one"
        entries = store.entries()
        assert len(entries) == 1
        assert entries[0]["body_hash"] == __import__("hashlib").sha256(b"body-one").hexdigest()


def test_replay_flags_changed_content_and_skips_out_of_scope():
    hits = {"count": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_GET(self):  # noqa: N802
            hits["count"] += 1
            if self.path == "/changed":
                body = f"changed-{hits['count']}"
            else:
                body = "stable"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        with tempfile.TemporaryDirectory() as d:
            store = CorpusStore(d)
            store.put("GET", f"http://127.0.0.1:{port}/stable", 200, {}, "stable")
            store.put("GET", f"http://127.0.0.1:{port}/changed", 200, {}, "changed-0")
            store.put("GET", "http://other.example/x", 200, {}, "out-of-scope")
            result = asyncio.run(replay(store, [f"http://127.0.0.1:{port}"]))
            assert result["skipped_out_of_scope"] == 1
            assert result["changed_count"] == 1, "changed content must be flagged"
            entry = next(e for e in result["entries"] if e["url"].endswith("/stable"))
            assert entry["replayed_status"] == 200 and not entry["body_changed"]
    finally:
        server.shutdown()
        t.join(timeout=2)


def test_recursive_crawl_discovers_js_routes_missed_by_href():
    with tempfile.TemporaryDirectory() as d:
        server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            result = asyncio.run(crawl(f"http://127.0.0.1:{port}", max_pages=10))
            paths = [p["url"].split(str(port))[-1] for p in result["pages"]]
            assert "/pricing" in paths, "href link crawled"
            # the differentiator: JS-only routes discovered via bundle extraction
            assert any("/api/internal/users" in pth for pth in paths), \
                "JS-discovered route must be crawled (href crawl misses it)"
            assert "/api/orders" in "".join(result["js_routes"]) or any(
                "/api/orders" in pth for pth in paths)
            assert result["crawled"] <= 10
        finally:
            server.shutdown()
            t.join(timeout=2)


def test_crawl_bounded_by_max_pages():
    body = "".join(f'<a href="/p{i}">x</a>' for i in range(30))
    handler = type("H", (BaseHTTPRequestHandler,), {
        "log_message": lambda self, *a: None,
        "do_GET": lambda self: (
            self.send_response(200),
            self.send_header("Content-Type", "text/html"),
            self.send_header("Content-Length", str(len(body))),
            self.end_headers(),
            self.wfile.write(body.encode()),
        ),
    })
    server = HTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        result = asyncio.run(crawl(f"http://127.0.0.1:{port}", max_pages=5))
        assert result["crawled"] <= 5, "I10: bounded by max_pages"
    finally:
        server.shutdown()
        t.join(timeout=2)

# ---- stdlib runner shim (pytest optional) ----
if __name__ == "__main__":
    import unittest
    import sys

    class CorpusTests(unittest.TestCase):
        def test_extract(self):
            test_extract_routes()

        def test_store(self):
            test_corpus_store_roundtrip_and_integrity()

        def test_replay(self):
            test_replay_flags_changed_content_and_skips_out_of_scope()

        def test_crawl(self):
            test_recursive_crawl_discovers_js_routes_missed_by_href()

        def test_bounded(self):
            test_crawl_bounded_by_max_pages()

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CorpusTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
