"""Offline smoke tests: no network, no LLM, no real packages needed.

    python -m unittest test_pipeline -v
"""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from cache_db import CacheDB
from function_resolver import (
    FunctionResolver, Resolution, VulnSymbol, extract_fix_diff_urls,
    normalize_llm_functions, parse_diff_symbols,
)
from library_graph import LibraryGraphStore, build_graph
from openvex import build_openvex
from reachability_engine import ReachabilityEngine, build_project_index

DIFF = textwrap.dedent('''\
    diff --git a/src/requests/sessions.py b/src/requests/sessions.py
    index 111..222 100644
    --- a/src/requests/sessions.py
    +++ b/src/requests/sessions.py
    @@ -100,7 +100,8 @@ class SessionRedirectMixin:
         def resolve_redirects(self, resp, req):
             hist = []
    -        url = resp.headers["location"]
    +        url = self.get_redirect_target(resp)
    +        self._check(url)
             return url
    @@ -300,3 +301,6 @@ class Session:
    +    def _check(self, url):
    +        return url
    diff --git a/tests/test_sessions.py b/tests/test_sessions.py
    --- a/tests/test_sessions.py
    +++ b/tests/test_sessions.py
    @@ -1,3 +1,4 @@
    +def test_x():
    +    pass
''')


def write(root: Path, rel: str, body: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body), encoding="utf-8")


REQUESTS_SRC = {
    "requests/__init__.py": "from .api import get\nfrom .sessions import Session\n",
    "requests/api.py": "from . import sessions\n\ndef get(url):\n    return request('get', url)\n\n"
                       "def request(method, url):\n    s = sessions.Session()\n    return s.request(method, url)\n",
    "requests/sessions.py": (
        "class Session:\n"
        "    def request(self, method, url):\n        return self.send(url)\n"
        "    def send(self, url):\n        return self.resolve_redirects(url)\n"
        "    def resolve_redirects(self, url):\n        return url\n"
    ),
}
YAML_SRC = {
    "yaml/__init__.py": (
        "def load(stream, Loader):\n    return Loader(stream)\n"
        "def safe_load(stream):\n    return load(stream, object)\n"
        "def unsafe_load(stream):\n    return load(stream, object)\n"
    ),
}
PILLOW_SRC = {
    "PIL/__init__.py": "",
    "PIL/Image.py": "def open(p):\n    return p\ndef danger(p):\n    return p\n",
}


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "demo_app"
        write(self.root, "app/__init__.py", "")
        write(self.root, "app/helpers.py", '''
            import requests

            def fetch(url):
                s = requests.Session()
                return s.get(url)
        ''')
        write(self.root, "app/main.py", '''
            import yaml
            from app import helpers

            def run(url):
                return helpers.fetch(url)

            if __name__ == "__main__":
                run("http://example.com")
                yaml.safe_load("a: 1")
        ''')
        write(self.root, "app/images.py", '''
            import PIL.Image

            def pick(name):
                return getattr(PIL.Image, name)("x")
        ''')
        write(self.root, "tests/test_ignored.py", "import flask\nflask.Flask(__name__)\n")
        self.cache = CacheDB(Path(self.tmp.name) / "cache.db")
        self.index = build_project_index(self.root)

    def tearDown(self) -> None:
        self.cache.close()
        self.tmp.cleanup()

    def provider(self, sources):
        build = lambda *_: (sources, [], False)
        store = LibraryGraphStore(self.cache, fetcher=build)
        return lambda: store.get("x", "1")

    def classify(self, package, funcs, conf, sources=None, **engine_kw):
        finding = {"id": f"TEST-{package}", "package": package, "version": "1", "aliases": [], "summary": "s"}
        res = Resolution(funcs, conf, "fix_commit_diff" if conf >= 0.8 else "llm")
        provider = self.provider(sources) if sources is not None else None
        return ReachabilityEngine(self.index, **engine_kw).classify(finding, res, provider)

    # ------------------------------------------------------------- diff parsing
    def test_diff_parser_finds_modified_functions_and_skips_tests_and_new_helpers(self) -> None:
        syms = parse_diff_symbols(DIFF)
        self.assertEqual([(s.module_hint, s.qualname) for s in syms],
                         [("requests.sessions", "SessionRedirectMixin.resolve_redirects")])

    def test_fix_url_extraction_from_references_and_git_ranges(self) -> None:
        finding = {
            "references": [{"type": "WEB", "url": "https://example.com"},
                           {"type": "FIX", "url": "https://github.com/psf/requests/commit/abcdef1234567"}],
            "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/psf/requests",
                                      "events": [{"fixed": "0123456789abcdef0123456789abcdef01234567"}]}]}],
        }
        urls = [u for u, _ in extract_fix_diff_urls(finding)]
        self.assertEqual(len(urls), 2)
        self.assertTrue(all(u.endswith(".diff") for u in urls))

    def test_llm_output_is_sanitised(self) -> None:
        raw = ['yaml.load()', {"name": "Session.send"}, "rm -rf /", "`os.system`", "yaml.load"]
        self.assertEqual(normalize_llm_functions(raw), ["yaml.load", "Session.send", "os.system"])
        self.assertEqual(normalize_llm_functions('{"functions": ["a.b"]}'), ["a.b"])

    # ------------------------------------------------------------- cache reuse
    def test_cached_mapping_avoids_network_and_llm(self) -> None:
        res = Resolution([VulnSymbol("load", "load", "yaml", "fix_commit_diff")], 0.9, "fix_commit_diff")
        self.cache.put_function_map("GHSA-1", "PyYAML", res.to_dict())

        class Boom:
            def get(self, *a, **k): raise AssertionError("network used despite cache")

        def llm(*a): raise AssertionError("LLM used despite cache")
        resolver = FunctionResolver(self.cache, http=Boom(), llm_fn=llm)
        out = resolver.resolve({"id": "GHSA-1", "package": "pyyaml"})   # different spelling, same key
        self.assertTrue(out.from_cache)
        self.assertEqual(out.functions[0].name, "load")

    def test_unresolved_is_cached_only_when_every_source_was_tried(self) -> None:
        resolver = FunctionResolver(self.cache, llm_fn=lambda *a: [], offline=True)
        self.assertEqual(resolver.resolve({"id": "A", "package": "p"}).source, "none")
        self.assertIsNone(self.cache.get_function_map("A", "p"))        # offline: not cached
        online = FunctionResolver(self.cache, llm_fn=lambda *a: [])
        online.resolve({"id": "B", "package": "p"})
        self.assertIsNotNone(self.cache.get_function_map("B", "p"))     # fully tried: cached

    # ------------------------------------------------------------- verdicts
    def test_reachable_through_helper_chain_into_library_internals(self) -> None:
        v = self.classify("requests", [VulnSymbol("resolve_redirects", "Session.resolve_redirects", "requests.sessions")],
                          0.9, REQUESTS_SRC)
        self.assertEqual(v.verdict, "reachable")
        text = v.evidence["call_path_text"]
        self.assertIn("app.main:<module>", text)
        self.assertIn("app.helpers:fetch", text)
        self.assertIn("resolve_redirects (VULNERABLE)", text)

    def test_direct_call_is_reachable_without_library_source(self) -> None:
        v = self.classify("pyyaml", [VulnSymbol("safe_load", "safe_load", "yaml")], 0.55)
        self.assertEqual(v.verdict, "reachable")
        self.assertEqual(v.evidence["method"], "direct_symbol_match")

    def test_not_reachable_when_function_never_reached(self) -> None:
        v = self.classify("pyyaml", [VulnSymbol("unsafe_load", "unsafe_load", "yaml")], 0.9, YAML_SRC)
        self.assertEqual(v.verdict, "not_reachable", v.reason)

    def test_llm_mapping_cannot_certify_absence(self) -> None:
        v = self.classify("pyyaml", [VulnSymbol("unsafe_load", "unsafe_load", "yaml")], 0.55, YAML_SRC)
        self.assertEqual(v.verdict, "uncertain")
        self.assertIn("low-confidence", v.reason)

    def test_unmapped_advisory_is_uncertain(self) -> None:
        self.assertEqual(self.classify("requests", [], 0.1, REQUESTS_SRC).verdict, "uncertain")

    def test_dynamic_getattr_blocks_not_reachable(self) -> None:
        v = self.classify("pillow", [VulnSymbol("danger", "danger", "PIL.Image")], 0.9, PILLOW_SRC)
        self.assertEqual(v.verdict, "uncertain")
        self.assertEqual(v.evidence["dynamic_features"][0]["kind"], "getattr_dynamic")

    def test_unimported_package_is_uncertain_unless_assumed_direct(self) -> None:
        sym = [VulnSymbol("x", "x", "flask")]
        self.assertEqual(self.classify("flask", sym, 0.9).verdict, "uncertain")     # tests/ are excluded, no import
        self.assertEqual(self.classify("flask", sym, 0.9, assume_direct_deps=True).verdict, "not_reachable")

    def test_openvex_contains_only_not_reachable(self) -> None:
        keep = self.classify("pyyaml", [VulnSymbol("unsafe_load", "unsafe_load", "yaml")], 0.9, YAML_SRC)
        drop = self.classify("requests", [], 0.1, REQUESTS_SRC)
        doc = build_openvex([keep.to_dict(), drop.to_dict()], project_name="demo_app")
        self.assertEqual(doc["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertEqual(len(doc["statements"]), 1)
        st = doc["statements"][0]
        self.assertEqual(st["status"], "not_affected")
        self.assertEqual(st["justification"], "vulnerable_code_not_in_execute_path")
        self.assertEqual(st["products"][0]["subcomponents"][0]["@id"], "pkg:pypi/pyyaml@1")


if __name__ == "__main__":
    unittest.main()