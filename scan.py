#!/usr/bin/env python3
"""End-to-end Python vulnerability reachability scan.

    python scan.py C:\\path\\to\\target_project

Steps
-----
1. OSV           run osv_checker.py on the target's requirements.txt   -> osv_vulnerabilities.json
                 (skip with --from-osv FILE to reuse an existing file)
2. Index         parse the target's .py files with ``ast`` (never executed)
3. Resolve       advisory -> vulnerable functions (cache.db, fix diffs, LLM fallback)
4. Classify      reachable / not_reachable / uncertain, with call-path evidence
5. Write         verdicts.json and report.openvex.json

Safety: no target code is executed or imported, and nothing is pip-installed.
Dependency releases are only *downloaded and read in memory* for static analysis.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from cache_db import CacheDB
from function_resolver import FunctionResolver, load_llm_function
from library_graph import LibraryGraphStore
from openvex import build_openvex, write_openvex
from reachability_engine import ReachabilityEngine, build_project_index

log = logging.getLogger("scan")

LIMITATIONS = [
    "Only Python source files (.py) of the project are analysed; notebooks and non-Python code are not.",
    "Test files are excluded unless --include-tests is given.",
    "Dependency call graphs are name-based over-approximations built from the pinned release's source.",
    "Packages never imported by project code may still be used via other dependencies (see --assume-direct-deps).",
    "Compiled extension modules (C/Rust) cannot be analysed statically.",
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Which vulnerability alerts actually affect a Python project?")
    p.add_argument("target", type=Path, help="target project directory (or its requirements.txt)")
    p.add_argument("--from-osv", type=Path, metavar="FILE",
                   help="use an existing osv_vulnerabilities.json instead of running the OSV checker")
    p.add_argument("--osv-output", type=Path, default=Path("osv_vulnerabilities.json"))
    p.add_argument("--out-dir", type=Path, default=Path("."), help="where verdicts.json / report.openvex.json go")
    p.add_argument("--cache", type=Path, default=Path("cache.db"))
    p.add_argument("--offline", action="store_true",
                   help="no network: use cache.db only (uncached advisories become uncertain)")
    p.add_argument("--no-llm", action="store_true", help="disable the free-LLM fallback")
    p.add_argument("--no-library-graph", action="store_true",
                   help="do not download dependency source (verdicts stay uncertain unless a direct call is found)")
    p.add_argument("--assume-direct-deps", action="store_true",
                   help="treat packages never imported by project code as not_reachable "
                        "(unsafe for transitive dependencies; off by default)")
    p.add_argument("--min-mapping-confidence", type=float, default=0.8,
                   help="minimum function-mapping confidence required to claim not_reachable (default 0.8, "
                        "i.e. fix-commit-derived only; LLM mappings can prove reachable but not unreachable)")
    p.add_argument("--include-tests", action="store_true", help="also analyse test files")
    p.add_argument("--refresh", action="store_true", help="ignore cached function mappings")
    p.add_argument("--project-name", help="product name used in the OpenVEX file (default: target folder name)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def load_findings(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list of findings")
    seen: set[tuple[str, str, str]] = set()
    findings = []
    for item in data:
        key = (item.get("id", ""), item.get("package", ""), item.get("version", ""))
        if not all(key) or key in seen:
            continue
        seen.add(key)
        findings.append(item)
    return findings

def print_summary(report: dict) -> None:
    """Pretty stdlib-only terminal summary of the verdicts report."""
    import os, sys, textwrap
    verdicts = report.get("verdicts", [])
    counts = (report.get("metadata") or {}).get("counts", {})
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if color and os.name == "nt":
        os.system("")  # enable ANSI on Windows consoles
    codes = {"reachable": "31", "not_reachable": "32", "uncertain": "33"}

    def paint(text: str, verdict: str) -> str:
        return f"\033[{codes.get(verdict, '0')}m{text}\033[0m" if color else text

    bar = "=" * 78
    print(f"\n{bar}\n VULNERABILITY REACHABILITY SUMMARY\n{bar}")
    print(f" Total findings : {len(verdicts)}")
    for k in ("reachable", "not_reachable", "uncertain"):
        print(f" {paint(k.ljust(14), k)} : {counts.get(k, sum(1 for v in verdicts if v['verdict'] == k))}")
    print("-" * 78)
    order = {"reachable": 0, "uncertain": 1, "not_reachable": 2}
    for v in sorted(verdicts, key=lambda x: (order.get(x["verdict"], 3), x["id"])):
        ev = v.get("evidence") or {}
        head = f"{v['id']}  {v['package']}@{v['version']}  ->  {paint(v['verdict'].upper(), v['verdict'])}  (conf {v['confidence']:.2f})"
        print(head)
        if v["verdict"] == "reachable":
            label, text = "Call path", ev.get("call_path_text") or v.get("reason", "")
        else:
            label, text = "Reason", v.get("reason", "")
        print(textwrap.fill(f"{label}: {text}", width=76, initial_indent="   ", subsequent_indent="      "))
        print()
    print(bar)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")

    target = args.target.resolve()
    project_dir = target.parent if target.is_file() else target
    if not target.exists():
        log.error("target not found: %s", target)
        return 2

    # ---- 1. OSV ---------------------------------------------------------------
    if args.from_osv:
        osv_path = args.from_osv
    else:
        osv_path = args.osv_output
        if args.offline:
            log.error("--offline needs --from-osv (the OSV query requires the network)")
            return 2
        import osv_checker
        code = osv_checker.main([str(target), "-o", str(osv_path)])
        if code == 2:
            return 2
        if code == 1:
            log.warning("OSV check was incomplete for some packages; results may miss vulnerabilities.")
    try:
        findings = load_findings(osv_path)
    except (OSError, ValueError) as exc:
        log.error("cannot read %s: %s", osv_path, exc)
        return 2
    log.info("\n%d advisory record(s) to analyse", len(findings))

    # ---- 2. index the project -------------------------------------------------
    index = build_project_index(project_dir, include_tests=args.include_tests)
    log.info("Indexed %d Python file(s) (%d unparsable), %d imports, %d dynamic-feature site(s)",
             index.files_scanned, len(index.unparsed), len(index.imports), len(index.dynamic))

    # ---- 3/4. resolve + classify ----------------------------------------------
    http = requests.Session()
    http.headers["User-Agent"] = "local-vuln-reachability-scanner/0.1"
    verdicts: list[dict[str, Any]] = []
    with CacheDB(args.cache) as cache:
        resolver = FunctionResolver(
            cache, http=http, offline=args.offline, refresh=args.refresh,
            llm_fn=None if args.no_llm else load_llm_function(),
        )
        store = LibraryGraphStore(cache, http=http, offline=args.offline)
        engine = ReachabilityEngine(
            index, assume_direct_deps=args.assume_direct_deps,
            min_mapping_confidence=args.min_mapping_confidence,
        )
        for finding in findings:
            resolution = resolver.resolve(finding)
            provider = None if args.no_library_graph else (
                lambda f=finding: store.get(f["package"], f["version"])
            )
            verdict = engine.classify(finding, resolution, provider).to_dict()
            verdicts.append(verdict)
            log.info("[%-13s] %-22s %s==%s  (conf %.2f, mapping: %s)",
                     verdict["verdict"], verdict["id"], verdict["package"], verdict["version"],
                     verdict["confidence"], resolution.source + (" cached" if resolution.from_cache else ""))
        stats = dict(resolver.stats)

    # ---- 5. write outputs -----------------------------------------------------
    args.out_dir.mkdir(parents=True, exist_ok=True)
    counts = Counter(v["verdict"] for v in verdicts)
    report = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": str(project_dir),
            "counts": {k: counts.get(k, 0) for k in ("reachable", "not_reachable", "uncertain")},
            "total": len(verdicts),
            "function_resolution": stats,
            "options": {
                "assume_direct_deps": args.assume_direct_deps, "include_tests": args.include_tests,
                "offline": args.offline, "library_graph": not args.no_library_graph,
                "min_mapping_confidence": args.min_mapping_confidence,
            },
            "limitations": LIMITATIONS,
        },
        "verdicts": verdicts,
    }
    verdicts_path = args.out_dir / "verdicts.json"
    verdicts_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    vex = build_openvex(verdicts, project_name=args.project_name or project_dir.name)
    vex_path = args.out_dir / "report.openvex.json"
    write_openvex(vex_path, vex)

    log.info("\nreachable: %d | not_reachable: %d | uncertain: %d",
             counts.get("reachable", 0), counts.get("not_reachable", 0), counts.get("uncertain", 0))
    log.info("Wrote %s and %s (%d not_affected statement(s))", verdicts_path, vex_path, len(vex["statements"]))
    print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())