"""Static reachability engine: is the vulnerable code reachable from this project?

Everything here is pure ``ast`` / text analysis. Target code is never imported,
executed or installed.

Pipeline
--------
1. ``build_project_index``   parse every project ``.py`` once and record:
      imports, every call/attribute reference (with its resolved dotted target),
      project-internal call edges, and dynamic-feature sites.
2. ``ReachabilityEngine.classify`` combines that index with the advisory's
      vulnerable functions (function_resolver) and, when available, the
      dependency's own call graph (library_graph) to produce a verdict.

Verdict policy (safety first - a false ``not_reachable`` is the one error we
must never make):

``reachable``      a call path exists: project code -> ... -> vulnerable function.
``not_reachable``  the package IS imported and mapped functions are known with high
                   confidence, the dependency's call graph was fully analysed,
                   no path exists and NO dynamic feature could hide one.
                   (If the package is never imported at all, this is only
                   claimed when ``assume_direct_deps`` is switched on, because it
                   could still be used through another dependency.)
``uncertain``      everything else: unmapped advisory, ``getattr``/``importlib``/
                   ``eval``/``exec``/plugin loading near package use, unparsable
                   files, missing library source, low-confidence mapping, calls
                   through untyped objects that might reach the vulnerable code.
"""

from __future__ import annotations

import ast
import logging
import os
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from cache_db import normalize_package
from function_resolver import Resolution, VulnSymbol
from library_graph import LibraryGraph

log = logging.getLogger(__name__)

MAX_FILE_BYTES = 2_000_000
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "virtualenv", "node_modules", "__pycache__",
    "site-packages", "build", "dist", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".idea", ".vscode",
}
TEST_DIRS = {"tests", "test", "testing"}

# PyPI distribution name (normalised) -> import names, where they differ.
IMPORT_NAME_ALIASES: dict[str, list[str]] = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"], "opencv-python": ["cv2"], "opencv-python-headless": ["cv2"],
    "python-dateutil": ["dateutil"], "pyjwt": ["jwt"], "protobuf": ["google"],
    "pycryptodome": ["Crypto"], "pycryptodomex": ["Cryptodome"], "attrs": ["attr", "attrs"],
    "python-dotenv": ["dotenv"], "msgpack-python": ["msgpack"], "mysqlclient": ["MySQLdb"],
    "psycopg2-binary": ["psycopg2"], "pyopenssl": ["OpenSSL"], "python-jose": ["jose"],
    "setuptools": ["setuptools", "pkg_resources"], "pyserial": ["serial"],
    "ruamel-yaml": ["ruamel"], "djangorestframework": ["rest_framework"],
    "django-cors-headers": ["corsheaders"], "google-auth": ["google"],
    "python-multipart": ["multipart"], "pymongo": ["pymongo", "bson", "gridfs"],
    "markdown2": ["markdown2"], "pyzmq": ["zmq"], "pywin32": ["win32api", "win32con", "pywintypes"],
}

IMPORT_CALLS = {"importlib.import_module", "importlib.__import__"}
PLUGIN_CALLS = {
    "importlib.util.spec_from_file_location", "importlib.util.module_from_spec",
    "importlib.util.spec_from_loader", "importlib.reload", "runpy.run_path", "runpy.run_module",
    "pkgutil.iter_modules", "pkgutil.walk_packages", "importlib.metadata.entry_points",
    "importlib_metadata.entry_points", "pkg_resources.iter_entry_points",
    "pkg_resources.load_entry_point",
}
ATTR_LOOKUP_CALLS = {"operator.attrgetter", "operator.methodcaller"}

# Confidence assigned to verdicts (multiplied by mapping confidence where noted).
CONF_DIRECT_MATCH = 1.0        # x mapping confidence
CONF_LIBRARY_PATH = 0.85       # x mapping confidence (heuristic over-approximate graph)
CONF_NOT_REACHABLE = 0.9       # x mapping confidence
CONF_NOT_IMPORTED = 0.6        # assume_direct_deps only
CONF_UNCERTAIN = 0.3


# --------------------------------------------------------------------------- #
# Records produced by the AST pass
# --------------------------------------------------------------------------- #
@dataclass
class ImportRecord:
    file: str
    line: int
    module: str                       # absolute dotted module ("" if unresolvable)
    names: tuple[str, ...] = ()       # from-import names ("*" for star)
    relative: bool = False

    @property
    def root(self) -> str:
        return self.module.split(".")[0].lower() if self.module else ""


@dataclass
class Usage:
    """A call (or non-call reference) to something, as seen in project code."""

    file: str
    line: int
    code: str
    caller: str                       # "module:qualname" or "module:<module>"
    path: Optional[str]               # resolved dotted origin, e.g. "requests.Session.get"
    attr: Optional[str]               # last name (for unresolved receivers)
    kind: str                         # "call" | "ref"
    bare: bool = False                # call through a plain name, not an attribute


@dataclass
class DynamicFeature:
    file: str
    line: int
    kind: str                         # eval_exec | getattr_dynamic | dynamic_import | plugin_loading | namespace_lookup
    code: str
    caller: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "file": self.file, "line": self.line, "code": self.code}


@dataclass
class DefInfo:
    key: str
    file: str
    line: int
    name: str


# --------------------------------------------------------------------------- #
# Per-file AST analysis
# --------------------------------------------------------------------------- #
def _dotted_text(node: ast.AST) -> Optional[str]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_const_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


class ModuleAnalyzer(ast.NodeVisitor):
    """Walks one module, resolving names to dotted origins via imports + simple type tracking.

    Resolution handles ``import a.b as c``, ``from a import b as c``, relative
    imports, ``x = pkg.Class()`` (then ``x.method`` -> ``pkg.Class.method``),
    ``self.attr = pkg.Class()``, ``with pkg.open() as f``, annotated parameters
    (``def f(s: requests.Session)``) and ``getattr(obj, "literal")``.
    """

    def __init__(self, relpath: str, module: str, is_package: bool, source_lines: list[str]) -> None:
        self.relpath, self.module, self.is_package, self.lines = relpath, module, is_package, source_lines
        self.aliases: dict[str, str] = {}
        self.var_scopes: list[dict[str, str]] = [{}]
        self.scope: list[str] = []          # class + function names, for qualnames
        self.func_stack: list[str] = []     # qualnames of enclosing functions
        self.imports: list[ImportRecord] = []
        self.usages: list[Usage] = []
        self.dynamic: list[DynamicFeature] = []
        self.defs: list[DefInfo] = []

    # ---------------------------------------------------------------- helpers
    @property
    def caller(self) -> str:
        return f"{self.module}:{self.func_stack[-1] if self.func_stack else '<module>'}"

    def _code(self, node: ast.AST) -> str:
        try:
            return self.lines[node.lineno - 1].strip()[:200]  # type: ignore[attr-defined]
        except (IndexError, AttributeError):
            return ""

    def _dyn(self, kind: str, node: ast.AST) -> None:
        self.dynamic.append(DynamicFeature(self.relpath, getattr(node, "lineno", 0), kind, self._code(node), self.caller))

    def _use(self, node: ast.AST, path: Optional[str], attr: Optional[str], kind: str, bare: bool = False) -> None:
        self.usages.append(Usage(self.relpath, getattr(node, "lineno", 0), self._code(node), self.caller, path, attr, kind, bare))

    def _descend(self, node: ast.AST) -> None:
        """Visit only the parts of a resolved chain that may hide further calls."""
        if isinstance(node, ast.Attribute):
            self._descend(node.value)
        elif isinstance(node, ast.Name):
            return
        else:
            self.visit(node)

    # ---------------------------------------------------------------- resolution
    def _static_import_target(self, call: ast.Call) -> Optional[str]:
        func = call.func
        is_import_fn = (isinstance(func, ast.Name) and func.id == "__import__" and "__import__" not in self.aliases) or (
            self.resolve(func) in IMPORT_CALLS
        )
        if is_import_fn and call.args and _is_const_str(call.args[0]):
            value = call.args[0].value  # type: ignore[attr-defined]
            return value if not value.startswith(".") else None
        return None

    def resolve(self, node: ast.AST) -> Optional[str]:
        """Dotted origin of an expression, or None if unknown."""
        if isinstance(node, ast.Name):
            for scope in reversed(self.var_scopes):
                if node.id in scope:
                    return scope[node.id]
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            text = _dotted_text(node)
            if text:
                for scope in reversed(self.var_scopes):
                    if text in scope:
                        return scope[text]
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2 and _is_const_str(node.args[1]):
                base = self.resolve(node.args[0])
                return f"{base}.{node.args[1].value}" if base else None  # type: ignore[attr-defined]
            static = self._static_import_target(node)
            if static:
                return static
            return self.resolve(func)       # instance-of / result-of: origin = callee
        if isinstance(node, ast.Await):
            return self.resolve(node.value)
        return None

    def _bind(self, target: ast.AST, origin: Optional[str]) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind(elt, origin)
        elif isinstance(target, ast.Name):
            if origin:
                self.var_scopes[-1][target.id] = origin
        elif isinstance(target, ast.Attribute):
            text = _dotted_text(target)
            if origin and text:
                scope = self.var_scopes[0] if text.startswith("self.") else self.var_scopes[-1]
                scope[text] = origin
            self._descend(target.value)
        elif isinstance(target, ast.Starred):
            self._bind(target.value, origin)
        else:
            self.visit(target)

    # ---------------------------------------------------------------- definitions
    def _function(self, node: ast.AST) -> None:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for dec in node.decorator_list:
            self.visit(dec)
        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
            self.visit(default)
        qual = ".".join(self.scope + [node.name])
        self.defs.append(DefInfo(f"{self.module}:{qual}", self.relpath, node.lineno, node.name))

        scope_vars: dict[str, str] = {}
        all_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        if node.args.vararg:
            all_args.append(node.args.vararg)
        if node.args.kwarg:
            all_args.append(node.args.kwarg)
        for arg in all_args:
            if arg.annotation is not None:
                self.visit(arg.annotation)
                origin = self.resolve(arg.annotation)
                if origin:
                    scope_vars[arg.arg] = origin       # typed parameter keeps its origin
        self.scope.append(node.name)
        self.func_stack.append(qual)
        self.var_scopes.append(scope_vars)
        for stmt in node.body:
            self.visit(stmt)
        self.var_scopes.pop()
        self.func_stack.pop()
        self.scope.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expr in list(node.decorator_list) + list(node.bases) + [k.value for k in node.keywords]:
            self.visit(expr)
        self.scope.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.scope.pop()

    # ---------------------------------------------------------------- imports
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(ImportRecord(self.relpath, node.lineno, alias.name))
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                root = alias.name.split(".")[0]
                self.aliases[root] = root

    def _absolute_module(self, node: ast.ImportFrom) -> Optional[str]:
        if node.level == 0:
            return node.module or ""
        pkg = self.module.split(".") if self.is_package else self.module.split(".")[:-1]
        drop = node.level - 1
        if drop > len(pkg):
            return None
        base = pkg[: len(pkg) - drop]
        if node.module:
            base += node.module.split(".")
        return ".".join(base)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = self._absolute_module(node)
        if base is None:
            return
        names = tuple(a.name for a in node.names)
        self.imports.append(ImportRecord(self.relpath, node.lineno, base, names, node.level > 0))
        for alias in node.names:
            if alias.name != "*":
                self.aliases[alias.asname or alias.name] = f"{base}.{alias.name}" if base else alias.name

    # ---------------------------------------------------------------- statements
    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        origin = self.resolve(node.value)
        for target in node.targets:
            self._bind(target, origin)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        origin = (self.resolve(node.value) if node.value is not None else None) or self.resolve(node.annotation)
        self._bind(node.target, origin)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind(item.optional_vars, self.resolve(item.context_expr))
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._bind(node.target, self.resolve(node.iter))
        for stmt in node.body + node.orelse:
            self.visit(stmt)

    visit_AsyncFor = visit_For  # type: ignore[assignment]

    # ---------------------------------------------------------------- expressions
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        path = self.resolve(func)
        self._check_dynamic_call(node, path)
        if isinstance(func, ast.Name):
            attr: Optional[str] = func.id
        elif isinstance(func, ast.Attribute):
            attr = func.attr
        else:
            attr = None
        self._use(node, path, attr, "call", bare=isinstance(func, ast.Name))
        if path is not None:
            self._descend(func)
        else:
            self.visit(func)
        for arg in node.args:
            self.visit(arg)
        for kw in node.keywords:
            self.visit(kw.value)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if not isinstance(node.ctx, ast.Load):
            self.generic_visit(node)
            return
        path = self.resolve(node)
        if path is not None:
            self._use(node, path, node.attr, "ref")
            self._descend(node.value)
        else:
            self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            path = self.resolve(node)
            if path is not None:
                self._use(node, path, node.id, "ref")

    def visit_Subscript(self, node: ast.Subscript) -> None:
        value = node.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in ("globals", "locals", "vars"):
            self._dyn("namespace_lookup", node)
        self.generic_visit(node)

    # ---------------------------------------------------------------- dynamic features
    def _check_dynamic_call(self, node: ast.Call, path: Optional[str]) -> None:
        func, args = node.func, node.args
        first_const = bool(args) and _is_const_str(args[0])

        if isinstance(func, ast.Name):
            fid = func.id
            if fid in ("eval", "exec") and fid not in self.aliases:
                self._dyn("eval_exec", node)
                return
            if fid == "getattr" and "getattr" not in self.aliases:
                if len(args) >= 2 and not _is_const_str(args[1]):
                    self._dyn("getattr_dynamic", node)
                return
            if fid == "__import__" and "__import__" not in self.aliases:
                self._import_call(node, first_const)
                return
        if path in IMPORT_CALLS:
            self._import_call(node, first_const)
        elif path in PLUGIN_CALLS:
            self._dyn("plugin_loading", node)
        elif path in ATTR_LOOKUP_CALLS and args and not first_const:
            self._dyn("getattr_dynamic", node)

    def _import_call(self, node: ast.Call, first_const: bool) -> None:
        if first_const:
            module = node.args[0].value  # type: ignore[attr-defined]
            if not module.startswith("."):
                self.imports.append(ImportRecord(self.relpath, node.lineno, module))
                return
        self._dyn("dynamic_import", node)


# --------------------------------------------------------------------------- #
# Project index
# --------------------------------------------------------------------------- #
def iter_python_files(root: Path, include_tests: bool):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.endswith(".egg-info")
            and not (Path(dirpath) / d / "pyvenv.cfg").exists()          # virtualenv with an odd name
            and (include_tests or d.lower() not in TEST_DIRS)
        ]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            if not include_tests and (name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"):
                continue
            path = Path(dirpath) / name
            if not path.is_symlink():
                yield path


def _module_name(rel: str, strip_src: bool, root_name: str) -> tuple[str, bool]:
    parts = rel[:-3].split("/")
    if strip_src and parts[0] == "src":
        parts = parts[1:]
    is_pkg = parts[-1] == "__init__"
    if is_pkg:
        parts = parts[:-1]
    return (".".join(parts) if parts else root_name), is_pkg


class ProjectIndex:
    """Everything the engine needs to know about the target project."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.modules: set[str] = set()
        self.module_files: dict[str, str] = {}
        self.imports: list[ImportRecord] = []
        self.usages: list[Usage] = []
        self.dynamic: list[DynamicFeature] = []
        self.defs: dict[str, DefInfo] = {}
        self.unparsed: list[str] = []                  # relative paths that failed to parse
        self.files_scanned = 0
        self.edges: dict[str, dict[str, Usage]] = defaultdict(dict)
        self.reverse: dict[str, list[str]] = defaultdict(list)
        self.by_name: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------ internal graph
    def internal_root(self, name: str) -> bool:
        return name.split(".")[0] in {m.split(".")[0] for m in self.modules}

    def _internal_keys(self, path: str) -> Optional[list[str]]:
        """Project defs a dotted path points to; None if the path is not project-internal."""
        parts = path.split(".")
        for i in range(len(parts), 0, -1):
            mod = ".".join(parts[:i])
            if mod in self.modules:
                rem = ".".join(parts[i:])
                keys = []
                for cand in ((rem, rem + ".__init__") if rem else ()):
                    key = f"{mod}:{cand}"
                    if key in self.defs:
                        keys.append(key)
                return keys
        return None

    def build_edges(self) -> None:
        for key, d in self.defs.items():
            self.by_name[d.name].append(key)
            parts = key.split(":", 1)[1].split(".")
            if parts[-1] == "__init__" and len(parts) >= 2:
                self.by_name[parts[-2]].append(key)
        for u in self.usages:
            if u.kind != "call":
                continue
            keys = self._internal_keys(u.path) if u.path else None
            if u.path and keys is None:
                continue                              # call into an external package
            if not keys and u.attr:
                keys = self.by_name.get(u.attr, [])   # unresolved receiver: match by name (over-approximate)
            for callee in keys or []:
                if callee not in self.edges[u.caller]:
                    self.edges[u.caller][callee] = u
                    self.reverse[callee].append(u.caller)

    def file_and_line(self, key: str) -> tuple[str, int]:
        d = self.defs.get(key)
        if d:
            return d.file, d.line
        return self.module_files.get(key.split(":", 1)[0], "?"), 1

    def root_chain(self, key: str) -> list[str]:
        """Shortest chain ``root -> ... -> key`` of project callers (BFS over reverse edges)."""
        parent: dict[str, Optional[str]] = {key: None}
        queue: deque[str] = deque([key])
        found = key
        while queue:
            cur = queue.popleft()
            if cur.endswith(":<module>") or not self.reverse.get(cur):
                found = cur
                break
            for caller in self.reverse[cur]:
                if caller not in parent:
                    parent[caller] = cur
                    queue.append(caller)
        chain, node = [], found
        while node is not None:
            chain.append(node)
            node = parent.get(node)
        return chain

    def unparsed_mentioning(self, roots: set[str]) -> list[str]:
        if not roots or not self.unparsed:
            return []
        pattern = re.compile(r"\b(?:import|from)\s+(?:%s)\b" % "|".join(re.escape(r) for r in sorted(roots)), re.I)
        hits = []
        for rel in self.unparsed:
            try:
                text = (self.root / rel).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                hits.append(rel)                      # cannot even read it: assume the worst
                continue
            if pattern.search(text):
                hits.append(rel)
        return hits


def build_project_index(root: Path | str, include_tests: bool = False) -> ProjectIndex:
    root = Path(root).resolve()
    index = ProjectIndex(root)
    strip_src = (root / "src").is_dir() and not (root / "src" / "__init__.py").exists()
    files = sorted(iter_python_files(root, include_tests))

    entries = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        module, is_pkg = _module_name(rel, strip_src, root.name)
        index.modules.add(module)
        index.module_files.setdefault(module, rel)
        entries.append((path, rel, module, is_pkg))

    for path, rel, module, is_pkg in entries:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("file too large")
            data = path.read_bytes()
            tree = ast.parse(data)
        except (SyntaxError, ValueError, RecursionError, MemoryError, OSError) as exc:
            log.debug("cannot parse %s: %s", rel, exc)
            index.unparsed.append(rel)
            continue
        analyzer = ModuleAnalyzer(rel, module, is_pkg, data.decode("utf-8", "replace").splitlines())
        analyzer.visit(tree)
        index.files_scanned += 1
        index.imports += analyzer.imports
        index.usages += analyzer.usages
        index.dynamic += analyzer.dynamic
        for d in analyzer.defs:
            index.defs[d.key] = d
    index.build_edges()
    return index


# --------------------------------------------------------------------------- #
# Package <-> import-name mapping
# --------------------------------------------------------------------------- #
def package_import_roots(package: str, graph: Optional[LibraryGraph]) -> set[str]:
    """Lower-cased top-level import names that refer to this PyPI distribution."""
    base = normalize_package(package)
    roots = {base.replace("-", "_"), base.replace("-", "")}
    for prefix in ("python-", "py-"):
        if base.startswith(prefix):
            roots.add(base[len(prefix):].replace("-", "_"))
    roots |= {a.lower() for a in IMPORT_NAME_ALIASES.get(base, [])}
    if graph:
        roots |= {t.lower() for t in graph.top_levels}
    return roots


# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #
@dataclass
class Verdict:
    id: str
    package: str
    version: str
    aliases: list[str]
    summary: str
    verdict: str                      # reachable | not_reachable | uncertain
    confidence: float
    reason: str
    function_mapping: dict[str, Any]
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "package": self.package, "version": self.version,
            "aliases": self.aliases, "summary": self.summary,
            "verdict": self.verdict, "confidence": round(self.confidence, 2), "reason": self.reason,
            "function_mapping": self.function_mapping, "evidence": self.evidence,
        }


def _symbol_matches_path(sym: VulnSymbol, path: str) -> Optional[str]:
    """Does a resolved project target (``requests.sessions.Session.send``) name this symbol?

    Returns ``"exact"`` (module/class hint also agrees), ``"name"`` (only the
    function name agrees) or None.
    """
    segments = path.split(".")
    if segments[-1] != sym.name:
        return None
    hints = [h for h in sym.module_hint.split(".") if h and h != "src"]
    classes = sym.qualname.split(".")[:-1]
    if classes and classes[-1] in segments[:-1]:
        return "exact"
    if hints and hints[-1] in segments[:-1]:
        return "exact"
    return "name" if (hints or classes) else "exact"


class ReachabilityEngine:
    """Classifies one advisory against the indexed project."""

    def __init__(
        self,
        index: ProjectIndex,
        *,
        assume_direct_deps: bool = False,
        min_mapping_confidence: float = 0.8,
    ) -> None:
        self.index = index
        self.assume_direct_deps = assume_direct_deps
        self.min_mapping_confidence = min_mapping_confidence

    # ------------------------------------------------------------------ public
    def classify(
        self,
        finding: dict[str, Any],
        resolution: Resolution,
        graph_provider: Optional[Callable[[], Optional[LibraryGraph]]] = None,
    ) -> Verdict:
        idx = self.index
        package = finding.get("package", "")
        symbols = resolution.functions

        memo: dict[str, Optional[LibraryGraph]] = {}

        def graph() -> Optional[LibraryGraph]:
            if "g" not in memo:
                memo["g"] = graph_provider() if graph_provider else None
            return memo["g"]

        roots = package_import_roots(package, None)
        pkg_imports = self._package_imports(roots)
        if not pkg_imports and graph_provider:
            g = graph()                       # the real top-level module names may differ from the PyPI name
            if g:
                roots = package_import_roots(package, g)
                pkg_imports = self._package_imports(roots)

        evidence: dict[str, Any] = {
            "package_import_roots": sorted(roots),
            "package_imports": [
                {"file": i.file, "line": i.line, "module": i.module} for i in pkg_imports[:10]
            ],
        }

        def done(verdict: str, confidence: float, reason: str, **extra: Any) -> Verdict:
            return self._make(finding, resolution, verdict, confidence, reason, {**evidence, **extra})

        # ---------- A. package never imported by project code --------------------
        if not pkg_imports:
            dyn_imports = [d.to_dict() for d in idx.dynamic if d.kind in ("dynamic_import", "plugin_loading")]
            unparsed = idx.unparsed_mentioning(roots)
            if dyn_imports or unparsed:
                return done(
                    "uncertain", CONF_UNCERTAIN,
                    "Package is not imported statically, but the project uses dynamic imports/plugin loading "
                    "or has unparsable files that could load it.",
                    dynamic_features=dyn_imports[:10], unparsed_files=unparsed[:10],
                )
            if self.assume_direct_deps:
                return done(
                    "not_reachable", CONF_NOT_IMPORTED,
                    "No project file imports this package (assuming it is only a direct dependency; "
                    "indirect use through other libraries was NOT analysed).",
                    method="package_not_imported",
                )
            return done(
                "uncertain", CONF_UNCERTAIN,
                "Package is not imported by project code, but it may be a transitive dependency reached through "
                "other libraries. Re-run with --assume-direct-deps to treat unused packages as not_reachable.",
                method="package_not_imported",
            )

        # ---------- B. package is imported ---------------------------------------
        pkg_files = {i.file for i in pkg_imports}
        star_files = {i.file for i in pkg_imports if "*" in i.names}
        pkg_usages = [u for u in idx.usages if u.path and u.path.split(".")[0].lower() in roots
                      and not idx.internal_root(u.path)]
        ambiguous = [
            u for u in idx.usages
            if u.file in pkg_files and u.kind == "call" and u.path is None and u.attr
            and (not u.bare or u.file in star_files)
        ]
        dyn_here = [d for d in idx.dynamic if d.file in pkg_files]
        evidence["package_usage_sites"] = len(pkg_usages)

        if not symbols:
            return done(
                "uncertain", CONF_UNCERTAIN,
                "No vulnerable function could be mapped from the advisory, so absence of a call cannot be proven.",
                dynamic_features=[d.to_dict() for d in dyn_here[:10]],
            )

        # ---------- B1. direct call of a vulnerable symbol -----------------------
        direct = self._direct_matches(pkg_usages, symbols)
        if direct:
            usage, sym, precision = direct
            steps = self._chain_to(usage, [], sym)
            return done(
                "reachable",
                min(0.98, resolution.confidence * CONF_DIRECT_MATCH * (1.0 if precision == "exact" else 0.9)),
                f"Project code references {usage.path} ({usage.file}:{usage.line}), which is the vulnerable "
                f"function {sym.qualname}.",
                method="direct_symbol_match", match_precision=precision,
                call_path=steps, call_path_text=self._path_text(steps),
            )

        # ---------- B2. through the dependency's own call graph -------------------
        g = graph()
        if g is None or g.truncated:
            why = "library source unavailable (offline or download failed)" if g is None else "library source too large to analyse fully"
            return done(
                "uncertain", CONF_UNCERTAIN,
                f"The vulnerable function is not called directly, but it may be reached through the library's "
                f"internal calls and the {why}.",
                method="no_library_graph", dynamic_features=[d.to_dict() for d in dyn_here[:10]],
            )

        targets: set[str] = set()
        for sym in symbols:
            keys, _ = g.find_targets(sym.name, sym.qualname, sym.module_hint)
            targets |= keys
        if not targets:
            return done(
                "uncertain", CONF_UNCERTAIN,
                f"Mapped function(s) not found in {package}=={finding.get('version')} source; mapping may be wrong.",
                method="symbol_not_in_library",
            )

        entry_names, usage_by_entry = set(), {}
        for u in pkg_usages:
            for seg in u.path.split(".")[1:]:                 # type: ignore[union-attr]
                entry_names.add(seg)
                usage_by_entry.setdefault(seg, u)
        entry_modules, import_by_module = set(), {}
        for imp in pkg_imports:
            parts = imp.module.split(".")
            for n in range(1, len(parts) + 1):
                entry_modules.add(".".join(parts[:n]))
                import_by_module.setdefault(".".join(parts[:n]), imp)
            for name in imp.names:
                if name != "*":
                    entry_modules.add(f"{imp.module}.{name}")
                    import_by_module.setdefault(f"{imp.module}.{name}", imp)

        res = g.reach(entry_names, entry_modules, targets)
        if res.reached:
            steps = self._library_steps(res, g, usage_by_entry, import_by_module)
            sym_key = res.path[-1]
            return done(
                "reachable", resolution.confidence * CONF_LIBRARY_PATH,
                f"Project code calls into {package}, whose internal calls lead to the vulnerable function "
                f"{g.defs[sym_key]['q']} (heuristic, over-approximate library call graph).",
                method="library_call_graph", call_path=steps, call_path_text=self._path_text(steps),
            )

        amb_names = {u.attr for u in ambiguous if u.attr}
        amb = g.reach(amb_names, set(), targets) if amb_names else None
        if amb and amb.reached:
            site = next((u for u in ambiguous if u.attr == g.defs[amb.path[0]]["n"] or u.attr == amb.entry), ambiguous[0])
            return done(
                "uncertain", 0.4,
                f"`{site.code}` ({site.file}:{site.line}) calls a method on an object whose type could not be "
                f"determined; if it is a {package} object it reaches the vulnerable function.",
                method="untyped_receiver", ambiguous_site={"file": site.file, "line": site.line, "code": site.code},
            )

        # ---------- B3. nothing found: can we really certify absence? -------------
        blockers: list[str] = []
        extra: dict[str, Any] = {}
        if dyn_here:
            blockers.append("dynamic Python features appear in files that use the package")
            extra["dynamic_features"] = [d.to_dict() for d in dyn_here[:10]]
        lib_dyn = sorted(set(res.dynamic_nodes) | set(amb.dynamic_nodes if amb else []))
        if lib_dyn:
            blockers.append("the library's reachable code uses dynamic dispatch (getattr/eval/import_module)")
            extra["library_dynamic_defs"] = lib_dyn[:10]
        unparsed = idx.unparsed_mentioning(roots)
        if unparsed:
            blockers.append("some project files could not be parsed")
            extra["unparsed_files"] = unparsed[:10]
        if g.unparsed_near(s.module_hint for s in symbols):
            blockers.append("the library module holding the vulnerable code could not be parsed")
        if resolution.confidence < self.min_mapping_confidence:
            blockers.append(
                f"the function mapping is low-confidence ({resolution.source}, {resolution.confidence:.2f}); "
                "it can prove reachability but cannot certify absence"
            )
        if blockers:
            return done("uncertain", CONF_UNCERTAIN, "No call path found, but " + "; and ".join(blockers) + ".",
                        method="library_call_graph", **extra)

        return done(
            "not_reachable", min(0.95, resolution.confidence * CONF_NOT_REACHABLE),
            f"{package} is used, but no call path from project code reaches the vulnerable function(s) "
            f"{', '.join(s.qualname for s in symbols)}; no dynamic feature could hide one.",
            method="library_call_graph",
            analysis={"library_defs": len(g.defs), "library_nodes_visited": res.visited,
                      "project_files_scanned": idx.files_scanned},
        )

    # ------------------------------------------------------------------ helpers
    def _package_imports(self, roots: set[str]) -> list[ImportRecord]:
        return [i for i in self.index.imports if not i.relative and i.root in roots and not self.index.internal_root(i.module)]

    def _direct_matches(self, usages: list[Usage], symbols: list[VulnSymbol]):
        best = None
        for u in usages:
            if not u.path:
                continue
            for sym in symbols:
                precision = _symbol_matches_path(sym, u.path)
                if precision is None:
                    continue
                rank = (0 if u.kind == "call" else 1, 0 if precision == "exact" else 1)
                if best is None or rank < best[0]:
                    best = (rank, (u, sym, precision))
        return best[1] if best else None

    def _chain_to(self, usage: Usage, lib_steps: list[dict[str, Any]], sym: Optional[VulnSymbol]) -> list[dict[str, Any]]:
        """Project-side evidence: root -> helper -> ... -> caller -> library call."""
        idx = self.index
        chain = idx.root_chain(usage.caller)
        steps: list[dict[str, Any]] = []
        for n, key in enumerate(chain):
            if n == 0:
                f, line = idx.file_and_line(key)
                steps.append({"kind": "entry", "symbol": key, "file": f, "line": line})
            else:
                u = idx.edges.get(chain[n - 1], {}).get(key)
                steps.append({
                    "kind": "project_call", "caller": chain[n - 1], "callee": key,
                    "file": u.file if u else None, "line": u.line if u else None, "code": u.code if u else "",
                })
        steps.append({
            "kind": "library_call", "caller": usage.caller, "target": usage.path or usage.attr,
            "file": usage.file, "line": usage.line, "code": usage.code,
        })
        steps += lib_steps
        if sym is not None and not lib_steps:
            steps.append({"kind": "vulnerable_function", "symbol": sym.qualname, "module_hint": sym.module_hint})
        return steps

    def _library_steps(self, res, g: LibraryGraph, usage_by_entry, import_by_module) -> list[dict[str, Any]]:
        lib_steps = []
        for n, key in enumerate(res.path):
            rec = g.defs[key]
            last = n == len(res.path) - 1
            lib_steps.append({
                "kind": "vulnerable_function" if last else "library_internal",
                "symbol": key.replace(":", "."), "file": g.modules.get(rec["m"], {}).get("file", ""), "line": rec["l"],
            })
        usage = usage_by_entry.get(res.entry)
        if usage is not None:
            return self._chain_to(usage, lib_steps, None)
        imp = import_by_module.get(res.entry)
        if imp is not None:     # reached through import-time code only
            fake = Usage(imp.file, imp.line, f"import {imp.module}", f"{self._module_of(imp.file)}:<module>", imp.module, None, "ref")
            return self._chain_to(fake, lib_steps, None)
        return lib_steps

    def _module_of(self, rel: str) -> str:
        for mod, f in self.index.module_files.items():
            if f == rel:
                return mod
        return rel

    @staticmethod
    def _path_text(steps: list[dict[str, Any]]) -> str:
        parts = []
        for s in steps:
            k = s["kind"]
            if k == "entry":
                parts.append(f"{s['symbol']} ({s['file']}:{s['line']})")
            elif k == "project_call":
                parts.append(f"{s['callee']} [called at {s['file']}:{s['line']}]")
            elif k == "library_call":
                parts.append(f"{s['target']} [{s['file']}:{s['line']}]")
            elif k == "library_internal":
                parts.append(s["symbol"])
            else:
                parts.append(f"{s['symbol']} (VULNERABLE)")
        return " -> ".join(parts)

    @staticmethod
    def _make(finding, resolution: Resolution, verdict: str, confidence: float, reason: str, evidence) -> Verdict:
        return Verdict(
            id=finding.get("id", ""), package=finding.get("package", ""), version=finding.get("version", ""),
            aliases=list(finding.get("aliases") or []), summary=finding.get("summary", "") or "",
            verdict=verdict, confidence=confidence, reason=reason,
            function_mapping={
                "source": resolution.source, "confidence": resolution.confidence,
                "functions": [f.to_dict() for f in resolution.functions],
                "fix_commits": resolution.evidence, "from_cache": resolution.from_cache, "note": resolution.note,
            },
            evidence=evidence,
        )