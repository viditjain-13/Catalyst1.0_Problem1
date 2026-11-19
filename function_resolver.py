"""Advisory -> vulnerable-function resolution.

Strategy (cheapest / most reliable first), with results cached in cache.db:

1. Deterministic: find GitHub fix-commit URLs in the advisory (``references`` and
   OSV ``affected[].ranges`` of type GIT), download the ``.diff`` and work out
   which *existing* functions the fix modified.            -> confidence 0.9
2. Fallback: ask the free LLM (``free_llm.infer_functions_from_advisory``).
                                                              -> confidence 0.55
3. Nothing found: empty function list, confidence 0.1. The engine treats this
   as ``uncertain`` - an unmapped advisory is NEVER ``not_reachable``.

Nothing from the target project is touched here; only public advisory data and
GitHub diffs (plain text) are downloaded and parsed with regexes.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Optional

import requests

from cache_db import CacheDB

log = logging.getLogger(__name__)

DIFF_CONFIDENCE = 0.9
LLM_CONFIDENCE = 0.55
UNRESOLVED_CONFIDENCE = 0.1

MAX_FIX_URLS = 4            # fix commits examined per advisory
MAX_DIFF_BYTES = 2_000_000  # ignore absurdly large diffs
HTTP_TIMEOUT_S = 20
MAX_LLM_FUNCTIONS = 10


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class VulnSymbol:
    """One function believed to contain the vulnerability.

    ``name``         bare function name, e.g. ``resolve_redirects``
    ``qualname``     ``Class.method`` when known, else the bare name
    ``module_hint``  dotted module (from the diff's file path or the LLM), may be ""
    ``origin``       ``fix_commit_diff`` | ``llm``
    """

    name: str
    qualname: str = ""
    module_hint: str = ""
    origin: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnSymbol":
        return cls(
            name=data["name"],
            qualname=data.get("qualname", "") or data["name"],
            module_hint=data.get("module_hint", ""),
            origin=data.get("origin", ""),
        )


@dataclass
class Resolution:
    functions: list[VulnSymbol] = field(default_factory=list)
    confidence: float = UNRESOLVED_CONFIDENCE
    source: str = "none"             # fix_commit_diff | llm | none
    evidence: list[str] = field(default_factory=list)   # fix-commit URLs used
    note: str = ""
    from_cache: bool = False         # not persisted

    def to_dict(self) -> dict[str, Any]:
        return {
            "functions": [f.to_dict() for f in self.functions],
            "confidence": self.confidence,
            "source": self.source,
            "evidence": self.evidence,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Resolution":
        return cls(
            functions=[VulnSymbol.from_dict(f) for f in data.get("functions", [])],
            confidence=float(data.get("confidence", UNRESOLVED_CONFIDENCE)),
            source=data.get("source", "none"),
            evidence=list(data.get("evidence", [])),
            note=data.get("note", ""),
        )


# --------------------------------------------------------------------------- #
# Step 1a: locate fix commits
# --------------------------------------------------------------------------- #
_COMMIT_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?"
    r"/(?:pull/\d+/commits|commit)/([0-9a-fA-F]{7,40})"
)
_PR_RE = re.compile(r"https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)/pull/(\d+)(?:[/?#]|$)")
_REPO_RE = re.compile(r"https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def extract_fix_diff_urls(finding: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``[(diff_url, human_url), ...]`` for likely fix commits, best first."""
    ordered: dict[str, str] = {}

    refs = [r for r in (finding.get("references") or []) if isinstance(r, (dict, str))]
    # FIX-typed references first, then everything else.
    refs.sort(key=lambda r: 0 if isinstance(r, dict) and r.get("type") == "FIX" else 1)
    for ref in refs:
        url = ref.get("url", "") if isinstance(ref, dict) else ref
        is_fix = isinstance(ref, dict) and ref.get("type") == "FIX"
        m = _COMMIT_RE.search(url or "")
        if m:
            owner, repo, sha = m.groups()
            ordered.setdefault(
                f"https://github.com/{owner}/{repo}/commit/{sha}.diff",
                f"https://github.com/{owner}/{repo}/commit/{sha}",
            )
            continue
        m = _PR_RE.search(url or "")
        if m and is_fix:  # PRs are noisy; only trust them when typed as FIX
            owner, repo, num = m.groups()
            ordered.setdefault(
                f"https://github.com/{owner}/{repo}/pull/{num}.diff",
                f"https://github.com/{owner}/{repo}/pull/{num}",
            )

    # OSV GIT ranges: {"type": "GIT", "repo": "https://github.com/o/r", "events": [{"fixed": sha}]}
    for affected in finding.get("affected") or []:
        for rng in (affected or {}).get("ranges") or []:
            if rng.get("type") != "GIT":
                continue
            m = _REPO_RE.match(rng.get("repo", "") or "")
            if not m:
                continue
            owner, repo = m.groups()
            for event in rng.get("events") or []:
                sha = event.get("fixed")
                if sha and re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
                    ordered.setdefault(
                        f"https://github.com/{owner}/{repo}/commit/{sha}.diff",
                        f"https://github.com/{owner}/{repo}/commit/{sha}",
                    )
    return list(ordered.items())


def fetch_diff(session: requests.Session, diff_url: str) -> tuple[Optional[str], bool]:
    """Download a diff. Returns ``(text_or_None, transient_error)``."""
    try:
        resp = session.get(diff_url, timeout=HTTP_TIMEOUT_S, headers={"Accept": "text/plain"})
    except requests.RequestException as exc:
        log.warning("  diff fetch failed (%s): %s", diff_url, exc)
        return None, True
    if resp.status_code in (404, 410, 451):
        return None, False          # permanently gone: not worth retrying
    if resp.status_code != 200:
        log.warning("  diff fetch HTTP %s (%s)", resp.status_code, diff_url)
        return None, True           # rate limit / server error: transient
    if len(resp.content) > MAX_DIFF_BYTES:
        return None, False
    return resp.text, False


# --------------------------------------------------------------------------- #
# Step 1b: diff -> modified functions
# --------------------------------------------------------------------------- #
_DIFF_FILE_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_CLASS_RE = re.compile(r"^(\s*)class\s+([A-Za-z_]\w*)")
_HDR_DEF_RE = re.compile(r"(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_HDR_CLASS_RE = re.compile(r"class\s+([A-Za-z_]\w*)")

_NON_PRODUCTION_DIRS = {
    "test", "tests", "testing", "docs", "doc", "examples", "example", "benchmarks",
}


def is_test_path(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    return (
        any(p in _NON_PRODUCTION_DIRS for p in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name in ("conftest.py", "tests.py")
    )


def module_hint_from_path(path: str) -> str:
    """``src/requests/sessions.py`` -> ``requests.sessions``."""
    parts = path[:-3].split("/") if path.endswith(".py") else path.split("/")
    if "src" in parts:
        parts = parts[len(parts) - parts[::-1].index("src"):]   # after the last 'src'
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(p for p in parts if p)


def _indent(text: str) -> int:
    expanded = text.expandtabs(4)
    return len(expanded) - len(expanded.lstrip())


def _enclosing_symbol(lines: list[tuple[str, str]], i: int) -> Optional[tuple[str, Optional[str], int]]:
    """Find the outermost ``def`` (and its class) enclosing hunk line ``i``.

    Walks upwards through the hunk, tracking shrinking indentation, so
    ``if``/``for``/``with`` blocks are stepped over until a ``def`` is found.
    Returns ``(function_name, class_name_or_None, index_of_def_line)``.
    """
    chain: list[tuple[str, str, int]] = []        # innermost -> outermost
    text_i = lines[i][1].expandtabs(4)
    m = _DEF_RE.match(text_i)
    if m:
        chain.append(("def", m.group(2), i))
    cur = _indent(text_i)
    for j in range(i - 1, -1, -1):
        t = lines[j][1].expandtabs(4)
        if not t.strip():
            continue
        ind = _indent(t)
        if ind >= cur:
            continue
        dm, cm = _DEF_RE.match(t), _CLASS_RE.match(t)
        if dm:
            chain.append(("def", dm.group(2), j))
        elif cm:
            chain.append(("class", cm.group(2), j))
        cur = ind

    defs = [c for c in chain if c[0] == "def"]
    if not defs:
        return None
    outer = defs[-1]                               # nested helpers roll up to their parent
    after_outer = chain[chain.index(outer) + 1:]
    cls = next((c[1] for c in after_outer if c[0] == "class"), None)
    return outer[1], cls, outer[2]


def _symbols_from_hunk(path: str, header: str, lines: list[tuple[str, str]]) -> list[VulnSymbol]:
    module = module_hint_from_path(path)
    header_def = _HDR_DEF_RE.match(header)
    header_cls = _HDR_CLASS_RE.match(header)
    found: list[VulnSymbol] = []

    for i, (kind, text) in enumerate(lines):
        if kind == " " or not text.strip() or text.lstrip().startswith("#"):
            continue                                # only real code changes count
        hit = _enclosing_symbol(lines, i)
        if hit:
            name, cls, def_idx = hit
            if lines[def_idx][0] == "+":
                continue                            # helper *added* by the fix: not in the vulnerable version
            if not cls and header_cls and _indent(lines[def_idx][1]) > 0:
                cls = header_cls.group(1)           # git hunk header usually names the class
        elif header_def and _indent(text) > 0:
            name, cls = header_def.group(1), None   # def line is above the hunk context
        else:
            continue
        if name.startswith("test_") or name == "test":
            continue
        found.append(
            VulnSymbol(
                name=name,
                qualname=f"{cls}.{name}" if cls else name,
                module_hint=module,
                origin="fix_commit_diff",
            )
        )
    return found


def parse_diff_symbols(diff_text: str) -> list[VulnSymbol]:
    """Extract the (non-test) Python functions modified by a unified diff."""
    symbols: dict[tuple[str, str], VulnSymbol] = {}
    state = {"path": "", "skip": True, "in_hunk": False, "header": "", "lines": []}

    def flush() -> None:
        if not state["skip"] and state["lines"]:
            for sym in _symbols_from_hunk(state["path"], state["header"], state["lines"]):
                symbols.setdefault((sym.module_hint, sym.qualname), sym)
        state["lines"] = []

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            flush()
            state["in_hunk"] = False
            m = _DIFF_FILE_RE.match(raw)
            state["path"] = m.group(2) if m else ""
            state["skip"] = not state["path"].endswith(".py") or is_test_path(state["path"])
        elif raw.startswith("@@"):
            flush()
            state["in_hunk"] = True
            parts = raw.split("@@", 2)
            state["header"] = parts[2].strip() if len(parts) == 3 else ""
        elif state["in_hunk"]:
            if raw == "":
                state["lines"].append((" ", ""))
            elif raw[0] in " +-":
                state["lines"].append((raw[0], raw[1:]))
            # "\ No newline at end of file" and similar are ignored
    flush()
    return list(symbols.values())


# --------------------------------------------------------------------------- #
# Step 2: LLM fallback
# --------------------------------------------------------------------------- #
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


def load_llm_function() -> Optional[Callable[[str, str, str], Any]]:
    """Import ``infer_functions_from_advisory`` from free_llm.py (optional)."""
    try:
        from free_llm import infer_functions_from_advisory  # type: ignore
        return infer_functions_from_advisory
    except Exception as exc:  # ImportError, missing key handling at import time, ...
        log.warning("free_llm.infer_functions_from_advisory unavailable (%s); LLM fallback disabled", exc)
        return None


def normalize_llm_functions(raw: Any) -> list[str]:
    """Coerce whatever the LLM helper returns into a clean list of dotted names.

    Accepts a list of strings, a list of dicts, a dict with a ``functions`` key,
    a JSON string or a comma/newline separated string. Anything that is not a
    plain (dotted) Python identifier is discarded, so LLM output can never inject
    anything but a name into the pipeline.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = re.split(r"[,\n;]", raw)
    if isinstance(raw, dict):
        for key in ("functions", "vulnerable_functions", "symbols"):
            if key in raw:
                raw = raw[key]
                break
        else:
            return []
    if not isinstance(raw, (list, tuple)):
        return []

    names: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            item = item.get("qualified_name") or item.get("function") or item.get("name")
        if not isinstance(item, str):
            continue
        item = item.strip().strip("`'\" ")
        item = re.sub(r"\(.*\)$", "", item)          # "load()" -> "load"
        if _IDENT_RE.match(item) and item not in names:
            names.append(item)
    return names[:MAX_LLM_FUNCTIONS]


def symbol_from_dotted(text: str, origin: str) -> VulnSymbol:
    """``requests.sessions.Session.resolve_redirects`` -> module/class/name parts."""
    parts = text.split(".")
    name, rest, classes = parts[-1], parts[:-1], []
    while rest and rest[-1][:1].isupper():
        classes.insert(0, rest.pop())
    return VulnSymbol(
        name=name,
        qualname=".".join(classes + [name]),
        module_hint=".".join(rest),
        origin=origin,
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
class FunctionResolver:
    """Resolve (advisory, package) -> vulnerable functions, using cache.db."""

    def __init__(
        self,
        cache: CacheDB,
        *,
        http: Optional[requests.Session] = None,
        llm_fn: Optional[Callable[[str, str, str], Any]] = None,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        self.cache = cache
        self.http = http or requests.Session()
        self.llm_fn = llm_fn
        self.offline = offline
        self.refresh = refresh
        self.stats = {"cache_hit": 0, "fix_commit_diff": 0, "llm": 0, "unresolved": 0}

    def resolve(self, finding: dict[str, Any]) -> Resolution:
        advisory_id = finding.get("id", "")
        package = finding.get("package", "")

        if not self.refresh:
            cached = self.cache.get_function_map(advisory_id, package)
            if cached is not None:
                self.stats["cache_hit"] += 1
                result = Resolution.from_dict(cached)
                result.from_cache = True
                return result

        transient_error = False

        # ---- 1. deterministic: fix-commit diffs --------------------------------
        symbols: dict[tuple[str, str], VulnSymbol] = {}
        used_urls: list[str] = []
        if not self.offline:
            for diff_url, page_url in extract_fix_diff_urls(finding)[:MAX_FIX_URLS]:
                text, transient = fetch_diff(self.http, diff_url)
                transient_error |= transient
                found = parse_diff_symbols(text) if text else []
                if found:
                    used_urls.append(page_url)
                    for sym in found:
                        symbols.setdefault((sym.module_hint, sym.qualname), sym)
        if symbols:
            result = Resolution(list(symbols.values()), DIFF_CONFIDENCE, "fix_commit_diff", used_urls)
            self.cache.put_function_map(advisory_id, package, result.to_dict())
            self.stats["fix_commit_diff"] += 1
            return result

        # ---- 2. fallback: free LLM ---------------------------------------------
        llm_attempted = False
        if self.llm_fn is not None and not self.offline:
            llm_attempted = True
            try:
                raw = self.llm_fn(package, finding.get("summary", ""), finding.get("details", ""))
            except Exception as exc:
                log.warning("  LLM call failed for %s: %s", advisory_id, exc)
                transient_error, raw = True, None
            names = normalize_llm_functions(raw)
            if names:
                result = Resolution(
                    [symbol_from_dotted(n, "llm") for n in names],
                    LLM_CONFIDENCE,
                    "llm",
                    [],
                    note="No fix-commit diff yielded functions; names inferred by LLM from advisory text.",
                )
                self.cache.put_function_map(advisory_id, package, result.to_dict())
                self.stats["llm"] += 1
                return result

        # ---- 3. unresolved -----------------------------------------------------
        result = Resolution(
            [], UNRESOLVED_CONFIDENCE, "none", [],
            note="Could not map this advisory to any function. Treated as uncertain, never not_reachable.",
        )
        self.stats["unresolved"] += 1
        # Cache the negative result only if every source was really tried and none
        # failed transiently; otherwise a network blip would stick forever.
        if not self.offline and llm_attempted and not transient_error:
            self.cache.put_function_map(advisory_id, package, result.to_dict())
        return result