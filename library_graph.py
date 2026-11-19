"""Static call graph of a *dependency* (the pinned library version), no install.

Why this exists
---------------
Project code rarely calls the vulnerable function directly:
``requests.get() -> Session.request() -> Session.send() -> resolve_redirects()``.
Looking only at the project's own AST would wrongly call that "not reachable".
So we download the pinned release from PyPI (free), read the ``.py`` files
**in memory** (zip/tar, never extracted to disk, never imported, never
installed) and build an over-approximate name-based call graph with ``ast``.

Over-approximation means: when unsure, add an edge. The graph can therefore
report a path that does not really exist (a false positive, flagged as
heuristic) but it must not miss a real one - and every def that uses dynamic
dispatch (``getattr(x, name)``, ``eval``, ``import_module(var)``) is flagged so
the engine can answer ``uncertain`` instead of ``not_reachable``.
"""

from __future__ import annotations

import ast
import io
import logging
import tarfile
import zipfile
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

import requests

from cache_db import CacheDB, normalize_package

log = logging.getLogger(__name__)

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"
HTTP_TIMEOUT_S = 30
MAX_ARCHIVE_BYTES = 30_000_000
MAX_PY_FILES = 5_000
MAX_PY_FILE_BYTES = 1_500_000
MAX_TOTAL_SOURCE_BYTES = 60_000_000

_EXCLUDED_DIRS = {
    "tests", "test", "testing", "docs", "doc", "examples", "example",
    "benchmarks", "scripts", "tools", "build", "dist", "__pycache__", ".github",
}
_EXCLUDED_TOP_FILES = {"setup.py", "conftest.py", "noxfile.py", "tasks.py", "fabfile.py"}


# --------------------------------------------------------------------------- #
# Downloading and reading the release (in memory only)
# --------------------------------------------------------------------------- #
def _pick_artifact(urls: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Prefer a pure-Python wheel, then an sdist, then any wheel."""
    def ok(u: dict[str, Any]) -> bool:
        return 0 < int(u.get("size") or 0) <= MAX_ARCHIVE_BYTES

    wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel" and ok(u)]
    sdists = [u for u in urls if u.get("packagetype") == "sdist" and ok(u)]
    pure = [u for u in wheels if u.get("filename", "").endswith("-none-any.whl")]
    for group in (pure, sdists, wheels):
        if group:
            return group[0]
    return None


def _clean_member_path(name: str, strip_first: bool) -> Optional[list[str]]:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if ".." in parts:
        return None                                   # path traversal: ignore
    if strip_first:
        parts = parts[1:]                             # sdist: "pkg-1.0/..."
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return None
    if parts[0].endswith((".dist-info", ".data", ".egg-info")):
        return None
    if any(p in _EXCLUDED_DIRS for p in parts[:-1]):
        return None
    if len(parts) == 1 and parts[0] in _EXCLUDED_TOP_FILES:
        return None
    return parts


def read_python_sources(blob: bytes, filename: str) -> Optional[tuple[dict[str, str], list[str], bool]]:
    """Return ``({archive_path: source}, extra_top_levels, truncated)`` or None on a bad archive."""
    sources: dict[str, str] = {}
    extra_tops: list[str] = []
    truncated = False
    total = 0
    try:
        if filename.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.flag_bits & 0x1:
                        continue
                    if info.filename.endswith(".dist-info/top_level.txt") and info.file_size < 10_000:
                        extra_tops += zf.read(info).decode("utf-8", "replace").split()
                        continue
                    if not info.filename.endswith(".py"):
                        continue
                    parts = _clean_member_path(info.filename, strip_first=False)
                    if not parts:
                        continue
                    if info.file_size > MAX_PY_FILE_BYTES:
                        truncated = True
                        continue
                    if len(sources) >= MAX_PY_FILES or total + info.file_size > MAX_TOTAL_SOURCE_BYTES:
                        return sources, extra_tops, True
                    total += info.file_size
                    sources["/".join(parts)] = zf.read(info).decode("utf-8", "replace")
        else:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
                for member in tf:
                    if not member.isfile() or not member.name.endswith(".py"):
                        continue
                    parts = _clean_member_path(member.name, strip_first=True)
                    if not parts:
                        continue
                    if member.size > MAX_PY_FILE_BYTES:
                        truncated = True
                        continue
                    if len(sources) >= MAX_PY_FILES or total + member.size > MAX_TOTAL_SOURCE_BYTES:
                        return sources, extra_tops, True
                    total += member.size
                    fh = tf.extractfile(member)
                    sources["/".join(parts)] = (fh.read() if fh else b"").decode("utf-8", "replace")
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError) as exc:
        log.warning("  could not read release archive %s: %s", filename, exc)
        return None
    return sources, extra_tops, truncated


def fetch_library_sources(
    session: requests.Session, package: str, version: str
) -> Optional[tuple[dict[str, str], list[str], bool]]:
    """Download the pinned release from PyPI and return its Python sources (or None)."""
    try:
        meta = session.get(PYPI_JSON_URL.format(package=package, version=version), timeout=HTTP_TIMEOUT_S)
        if meta.status_code != 200:
            log.warning("  PyPI metadata HTTP %s for %s==%s", meta.status_code, package, version)
            return None
        artifact = _pick_artifact(meta.json().get("urls") or [])
        if not artifact:
            log.warning("  no suitable release file for %s==%s", package, version)
            return None
        resp = session.get(artifact["url"], timeout=HTTP_TIMEOUT_S)
        if resp.status_code != 200 or len(resp.content) > MAX_ARCHIVE_BYTES:
            return None
        return read_python_sources(resp.content, artifact.get("filename", artifact["url"]))
    except (requests.RequestException, ValueError) as exc:
        log.warning("  library download failed for %s==%s: %s", package, version, exc)
        return None


# --------------------------------------------------------------------------- #
# Building the graph
# --------------------------------------------------------------------------- #
class _LibModuleVisitor(ast.NodeVisitor):
    """Collects, per module-level function/method, the *names* it calls or passes along.

    * calls inside nested functions/lambdas are attributed to the enclosing def;
    * code at module/class level goes to a pseudo-def ``<module>`` (import-time code);
    * ``Name``/``Attribute`` arguments and decorators count as references so
      callbacks (``executor.submit(fn)``) are not lost.
    """

    def __init__(self, module: str, is_pkg: bool) -> None:
        self.module, self.is_pkg = module, is_pkg
        self.recs: dict[str, dict[str, Any]] = {}
        self.class_stack: list[str] = []
        self.func_depth = 0
        self.cur = self._new_rec("<module>", "<module>", 1)

    def _new_rec(self, qual: str, name: str, line: int) -> dict[str, Any]:
        rec = {"m": self.module, "q": qual, "n": name, "l": line, "c": set(), "i": set(), "d": False}
        self.recs[f"{self.module}:{qual}"] = rec
        return rec

    # -- helpers
    @staticmethod
    def _name_of(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Call):
            node = node.func
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _ref(self, node: ast.AST) -> None:
        n = self._name_of(node)
        if n:
            self.cur["c"].add(n)

    def _abs_module(self, node: ast.ImportFrom) -> Optional[str]:
        if node.level == 0:
            return node.module or ""
        pkg = self.module.split(".") if self.is_pkg else self.module.split(".")[:-1]
        drop = node.level - 1
        if drop > len(pkg):
            return None
        base = pkg[: len(pkg) - drop]
        if node.module:
            base += node.module.split(".")
        return ".".join(base)

    # -- definitions
    def _function(self, node: ast.AST) -> None:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for dec in node.decorator_list:
            self._ref(dec)
            self.visit(dec)
        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
            self.visit(default)
        if self.func_depth == 0:
            qual = ".".join(self.class_stack + [node.name])
            prev, self.cur = self.cur, self._new_rec(qual, node.name, node.lineno)
            self.func_depth += 1
            for stmt in node.body:
                self.visit(stmt)
            self.func_depth -= 1
            self.cur = prev
        else:                                    # nested def: attribute to the outer def
            self.func_depth += 1
            for stmt in node.body:
                self.visit(stmt)
            self.func_depth -= 1

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for dec in node.decorator_list:
            self._ref(dec)
            self.visit(dec)
        for base in node.bases:
            self.visit(base)
        if self.func_depth == 0:
            self.class_stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        if self.func_depth == 0:
            self.class_stack.pop()

    # -- imports / calls
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.cur["i"].add(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = self._abs_module(node)
        if base is None:
            return
        self.cur["i"].add(base)
        for alias in node.names:
            self.cur["i"].add(f"{base}.{alias.name}" if base else alias.name)

    def visit_Call(self, node: ast.Call) -> None:
        self._ref(node.func)
        func = node.func
        args = node.args
        second_const = len(args) >= 2 and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str)
        first_const = bool(args) and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str)
        if isinstance(func, ast.Name):
            if func.id in ("eval", "exec") or (func.id == "getattr" and len(args) >= 2 and not second_const):
                self.cur["d"] = True
            if func.id == "__import__" and not first_const:
                self.cur["d"] = True
        elif isinstance(func, ast.Attribute) and func.attr == "import_module" and not first_const:
            self.cur["d"] = True
        for arg in list(args) + [kw.value for kw in node.keywords]:
            if isinstance(arg, (ast.Name, ast.Attribute)):
                self._ref(arg)
        self.generic_visit(node)


@dataclass
class LibReach:
    reached: bool = False
    path: list[str] = field(default_factory=list)      # def keys, entry -> vulnerable
    entry: str = ""                                    # seed name/module that started the path
    visited: int = 0
    dynamic_nodes: list[str] = field(default_factory=list)


def _mod_match(a: str, b: str) -> bool:
    return a == b or a.endswith("." + b) or b.endswith("." + a)


class LibraryGraph:
    """Name-based, over-approximate call graph of one library release."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.package: str = data.get("package", "")
        self.version: str = data.get("version", "")
        self.top_levels: list[str] = list(data.get("top_levels", []))
        self.truncated: bool = bool(data.get("truncated", False))
        self.unparsed: list[str] = list(data.get("unparsed", []))
        self.modules: dict[str, dict[str, Any]] = data.get("modules", {})
        self.defs: dict[str, dict[str, Any]] = data.get("defs", {})
        self.by_name: dict[str, list[str]] = defaultdict(list)
        for key, rec in self.defs.items():
            if rec["q"] == "<module>":
                continue
            self.by_name[rec["n"]].append(key)
            if rec["n"] == "__init__" and "." in rec["q"]:
                self.by_name[rec["q"].split(".")[-2]].append(key)   # Class(...) -> Class.__init__

    # ---------------------------------------------------------------- (de)serialise
    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package, "version": self.version, "top_levels": self.top_levels,
            "truncated": self.truncated, "unparsed": self.unparsed,
            "modules": self.modules, "defs": self.defs,
        }

    # ---------------------------------------------------------------- queries
    def find_targets(self, name: str, qualname: str, module_hint: str) -> tuple[set[str], str]:
        """Defs in this release matching a vulnerable symbol. Returns ``(keys, precision)``."""
        cands = [k for k in self.by_name.get(name, []) if self.defs[k]["n"] == name]
        exact = [
            k for k in cands
            if (not qualname or self.defs[k]["q"].endswith(qualname))
            and (not module_hint or _mod_match(self.defs[k]["m"], module_hint))
        ]
        if exact:
            return set(exact), "exact"
        return set(cands), "name"

    def unparsed_near(self, module_hints: Iterable[str]) -> list[str]:
        """Modules that failed to parse and could contain a vulnerable symbol."""
        hints = [h for h in module_hints if h]
        if not hints:
            return list(self.unparsed)
        return [m for m in self.unparsed if any(_mod_match(m, h) for h in hints)]

    def reach(self, entry_names: Iterable[str], entry_modules: Iterable[str], targets: set[str]) -> LibReach:
        """BFS from project-facing entry points to any target def."""
        parent: dict[str, Optional[str]] = {}
        seed_of: dict[str, str] = {}
        queue: deque[str] = deque()

        def seed(key: str, label: str) -> None:
            if key not in parent:
                parent[key] = None
                seed_of[key] = label
                queue.append(key)

        for name in sorted(set(entry_names)):
            for key in self.by_name.get(name, []):
                seed(key, name)
        for mod in sorted(set(entry_modules)):
            key = f"{mod}:<module>"
            if key in self.defs:
                seed(key, mod)

        while queue:
            cur = queue.popleft()
            if cur in targets:
                path, node = [], cur
                while node is not None:
                    path.append(node)
                    node = parent[node]
                path.reverse()
                return LibReach(True, path, seed_of[path[0]], len(parent))
            rec = self.defs[cur]
            for callee in rec["c"]:
                for nxt in self.by_name.get(callee, ()):
                    if nxt not in parent:
                        parent[nxt] = cur
                        seed_of[nxt] = seed_of[cur]
                        queue.append(nxt)
            for mod in rec["i"]:
                nxt = f"{mod}:<module>"
                if nxt in self.defs and nxt not in parent:
                    parent[nxt] = cur
                    seed_of[nxt] = seed_of[cur]
                    queue.append(nxt)

        dynamic = sorted(k for k in parent if self.defs[k]["d"])
        return LibReach(False, [], "", len(parent), dynamic)


def build_graph(
    sources: dict[str, str],
    package: str,
    version: str,
    extra_top_levels: Iterable[str] = (),
    truncated: bool = False,
) -> LibraryGraph:
    """Parse every module with ``ast`` and assemble the graph."""
    defs: dict[str, dict[str, Any]] = {}
    modules: dict[str, dict[str, Any]] = {}
    unparsed: list[str] = []
    top_levels: set[str] = set(extra_top_levels)

    for path, text in sorted(sources.items()):
        parts = path[:-3].split("/")
        is_pkg = parts[-1] == "__init__"
        if is_pkg:
            parts = parts[:-1]
        if not parts:
            continue
        module = ".".join(parts)
        top_levels.add(parts[0])      # excluded files (setup.py, tests/, ...) were already dropped
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            unparsed.append(module)
            continue
        visitor = _LibModuleVisitor(module, is_pkg)
        visitor.visit(tree)
        modules[module] = {"file": path, "pkg": is_pkg}
        for key, rec in visitor.recs.items():
            defs[key] = rec

    graph = LibraryGraph({
        "package": package, "version": version,
        "top_levels": sorted(top_levels), "truncated": truncated,
        "unparsed": unparsed, "modules": modules, "defs": defs,
    })
    # Prune to what can matter: keep only callee names that exist in this library
    # and imports of modules that exist in it; make sets JSON-friendly.
    known_names = set(graph.by_name)
    for rec in graph.defs.values():
        rec["c"] = sorted(n for n in rec["c"] if n in known_names)
        rec["i"] = sorted(m for m in rec["i"] if m in graph.modules)
    return graph


# --------------------------------------------------------------------------- #
# Cache-aware access
# --------------------------------------------------------------------------- #
class LibraryGraphStore:
    """Returns a LibraryGraph for ``package==version``: memory -> cache.db -> PyPI."""

    def __init__(
        self,
        cache: CacheDB,
        *,
        http: Optional[requests.Session] = None,
        offline: bool = False,
        fetcher: Optional[Callable[[str, str], Optional[tuple[dict[str, str], list[str], bool]]]] = None,
    ) -> None:
        self.cache = cache
        self.http = http or requests.Session()
        self.offline = offline
        self.fetcher = fetcher or (lambda p, v: fetch_library_sources(self.http, p, v))
        self._memo: dict[tuple[str, str], Optional[LibraryGraph]] = {}

    def get(self, package: str, version: str) -> Optional[LibraryGraph]:
        key = (normalize_package(package), version)
        if key in self._memo:
            return self._memo[key]
        graph: Optional[LibraryGraph] = None
        cached = self.cache.get_library_graph(package, version)
        if cached is not None:
            graph = LibraryGraph(cached)
        elif not self.offline:
            fetched = self.fetcher(package, version)
            if fetched is not None:                        # failures are not cached
                sources, extra_tops, truncated = fetched
                graph = build_graph(sources, package, version, extra_tops, truncated)
                self.cache.put_library_graph(package, version, graph.to_dict())
        self._memo[key] = graph
        return graph