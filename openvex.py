"""OpenVEX (v0.2.0) output: one ``not_affected`` statement per ``not_reachable`` verdict.

Spec: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md

Modelling choice: the *product* is the scanned project and the vulnerable
dependency is its *subcomponent*. That makes the claim exactly what the
analysis proves ("this project is not affected via this dependency") instead of
the false global claim "requests 2.19.0 is not affected".

Only ``not_reachable`` verdicts become statements. ``reachable`` and
``uncertain`` alerts are deliberately omitted: VEX is an assertion, and we do
not assert anything we have not proven.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
JUSTIFICATION = "vulnerable_code_not_in_execute_path"


def pypi_purl(package: str, version: str) -> str:
    """Package URL for a PyPI release (name normalised per the purl spec)."""
    name = re.sub(r"[-_.]+", "-", package).lower()
    return f"pkg:pypi/{quote(name, safe='')}@{quote(version, safe='')}"


def _impact_statement(v: dict[str, Any], project: str) -> str:
    funcs = ", ".join(f["qualname"] for f in v["function_mapping"]["functions"]) or "n/a"
    src = v["function_mapping"]["source"]
    method = v["evidence"].get("method", "static analysis")
    return (
        f"Static analysis of {project} (Python AST, no code executed) found no call path to the vulnerable "
        f"code in {v['package']} {v['version']} (functions: {funcs}; mapping source: {src}; method: {method}; "
        f"confidence {v['confidence']:.2f}). {v['reason']}"
    )


def build_openvex(
    verdicts: Iterable[dict[str, Any]],
    *,
    project_name: str,
    author: str = "local-vuln-reachability-scanner",
    role: str = "Automated reachability analysis",
    tooling: str = "local-vuln-reachability-scanner (Python ast + OSV)",
) -> dict[str, Any]:
    statements: list[dict[str, Any]] = []
    for v in sorted(verdicts, key=lambda x: (x["id"], x["package"], x["version"])):
        if v["verdict"] != "not_reachable":
            continue
        vuln: dict[str, Any] = {
            "@id": f"https://osv.dev/vulnerability/{quote(v['id'], safe='')}",
            "name": v["id"],
        }
        if v.get("aliases"):
            vuln["aliases"] = list(v["aliases"])
        if v.get("summary"):
            vuln["description"] = v["summary"]
        statements.append({
            "vulnerability": vuln,
            "products": [{
                "@id": f"pkg:generic/{quote(project_name, safe='')}",
                "subcomponents": [{"@id": pypi_purl(v["package"], v["version"])}],
            }],
            "status": "not_affected",
            "justification": JUSTIFICATION,
            "impact_statement": _impact_statement(v, project_name),
        })

    digest = hashlib.sha256(json.dumps(statements, sort_keys=True).encode("utf-8")).hexdigest()[:32]
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://openvex.dev/docs/public/vex-{digest}",
        "author": author,
        "role": role,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": 1,
        "tooling": tooling,
        "statements": statements,
    }


def write_openvex(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")