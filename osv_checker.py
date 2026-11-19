#!/usr/bin/env python3
"""OSV vulnerability checker for pinned PyPI dependencies.

Reads ``package==version`` pins from a target project's requirements.txt
(text parsing only: no code from the target is executed and nothing is
pip-installed), queries the free OSV API, and writes one JSON record per
vulnerability to ``osv_vulnerabilities.json`` for downstream function-mapping
and reachability modules.

Output record schema (list of objects)::

    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "package": "requests",
      "version": "2.19.0",
      "aliases": ["CVE-2018-18074"],       # [] if missing
      "summary": "...",                     # "" if missing
      "details": "...",                     # "" if missing
      "references": [{"type": "FIX", "url": "https://..."}],  # [] if missing
      # Optional passthrough fields, present only when OSV provides them:
      "published", "modified", "withdrawn", "severity", "affected",
      "related", "database_specific"
    }

Usage (PowerShell, inside the .venv)::

    python osv_checker.py                      # ./requirements.txt
    python osv_checker.py C:\\path\\to\\project  # <dir>\\requirements.txt
    python osv_checker.py C:\\path\\to\\reqs.txt --output osv_vulnerabilities.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_OUTPUT = Path("osv_vulnerabilities.json")
DEFAULT_TIMEOUT_S = 20.0

# OSV fields that downstream modules (function mapping, reachability) may use.
# Copied through unchanged when present.
PASSTHROUGH_KEYS: tuple[str, ...] = (
    "published",
    "modified",
    "withdrawn",
    "severity",
    "affected",
    "related",
    "database_specific",
)

# name[extras] == version [; environment marker]
PIN_RE = re.compile(
    r"""^
    (?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)
    (?:\[[^\]]*\])?                      # optional extras, e.g. requests[security]
    \s*==\s*
    (?P<version>[A-Za-z0-9][A-Za-z0-9._!+-]*)
    \s*(?:;.*)?$                         # optional environment marker
    """,
    re.VERBOSE,
)

Pin = tuple[str, str]


# --------------------------------------------------------------------------- #
# requirements.txt parsing (pure text, never executes anything)
# --------------------------------------------------------------------------- #
def read_text_robust(path: Path) -> str:
    """Read a text file, handling the UTF-16 files PowerShell's `>` often creates."""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def parse_pinned_requirements(req_path: Path) -> tuple[list[Pin], list[str]]:
    """Extract unique (package, exact_version) pairs from a requirements file.

    Returns ``(pins, skipped)``. ``skipped`` lists entries that were NOT scanned
    (unpinned specifiers, ``-r`` includes, URLs, ...) so the caller can warn.
    """
    pins: dict[Pin, None] = {}  # dict keeps order and de-duplicates
    skipped: list[str] = []

    # Join backslash line continuations (used with --hash lines).
    logical_lines: list[str] = []
    buffer = ""
    for raw_line in read_text_robust(req_path).splitlines():
        stripped = raw_line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        logical_lines.append(buffer + stripped)
        buffer = ""
    if buffer:
        logical_lines.append(buffer)

    for raw_line in logical_lines:
        line = re.sub(r"(^|\s)#.*$", "", raw_line).strip()  # drop comments
        if not line:
            continue
        if line.startswith("-"):
            if re.match(r"^(-r|--requirement|-c|--constraint)\b", line):
                skipped.append(f"{line} (included file not followed)")
            continue  # other pip options (--index-url, ...) are irrelevant
        line = re.split(r"\s--", line, maxsplit=1)[0].strip()  # drop --hash=...

        match = PIN_RE.match(line)
        if match:
            pins[(match.group("name"), match.group("version"))] = None
        else:
            skipped.append(line)

    return list(pins), skipped


# --------------------------------------------------------------------------- #
# OSV API
# --------------------------------------------------------------------------- #
def build_session() -> requests.Session:
    """HTTP session that retries transient failures (POST is idempotent here)."""
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"POST"}),
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": "local-vuln-reachability-scanner/0.1"})
    return session


def fetch_osv_vulns(
    session: requests.Session,
    package: str,
    version: str,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> list[dict[str, Any]]:
    """Return all OSV records for one PyPI package version (follows pagination)."""
    payload: dict[str, Any] = {
        "package": {"name": package, "ecosystem": "PyPI"},
        "version": version,
    }
    vulns: list[dict[str, Any]] = []
    while True:
        response = session.post(OSV_QUERY_URL, json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        vulns.extend(data.get("vulns") or [])
        next_token = data.get("next_page_token")
        if not next_token:
            return vulns
        payload["page_token"] = next_token


def build_finding(package: str, version: str, vuln: dict[str, Any]) -> dict[str, Any]:
    """Normalize one OSV record, keeping all metadata downstream stages need."""
    references = [r for r in (vuln.get("references") or []) if isinstance(r, (dict, str))]
    finding: dict[str, Any] = {
        "id": vuln.get("id", ""),
        "package": package,
        "version": version,
        "aliases": vuln.get("aliases") or [],
        "summary": vuln.get("summary") or "",
        "details": vuln.get("details") or "",
        "references": references,
    }
    for key in PASSTHROUGH_KEYS:
        if key in vuln:
            finding[key] = vuln[key]
    return finding


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def resolve_requirements_path(target: Path) -> Path:
    """Accept either a project directory or a direct path to a requirements file."""
    return target if target.is_file() else target / "requirements.txt"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        type=Path,
        help="project directory containing requirements.txt, or the file itself (default: .)",
    )
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT,
                        help=f"output JSON path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                        help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT_S:g})")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    # Avoid UnicodeEncodeError on Windows consoles (cp1252) for odd package names.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    args = parse_args(argv)
    req_file = resolve_requirements_path(args.target)

    if not req_file.is_file():
        print(f"ERROR: no requirements file found at: {req_file}", file=sys.stderr)
        return 2

    pins, skipped = parse_pinned_requirements(req_file)
    for entry in skipped:
        print(f"WARNING: not scanned (not an exact pin): {entry}", file=sys.stderr)
    if not pins:
        print("ERROR: no exact 'package==version' entries found.", file=sys.stderr)
        return 2

    findings: list[dict[str, Any]] = []
    failed: list[str] = []

    with build_session() as session:
        for package, version in pins:
            label = f"{package}=={version}"
            try:
                vulns = fetch_osv_vulns(session, package, version, timeout=args.timeout)
            except requests.exceptions.Timeout:
                print(f"{label}: ERROR timed out after {args.timeout:g}s", file=sys.stderr)
                failed.append(label)
                continue
            except requests.exceptions.HTTPError as exc:
                print(f"{label}: ERROR HTTP {exc.response.status_code}", file=sys.stderr)
                failed.append(label)
                continue
            except (requests.exceptions.RequestException, ValueError) as exc:
                print(f"{label}: ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
                failed.append(label)
                continue

            print(f"{label}: {len(vulns)} vulnerability record(s) found")
            findings.extend(build_finding(package, version, v) for v in vulns)

    findings.sort(key=lambda f: (f["package"].lower(), f["version"], f["id"]))

    try:
        args.output.write_text(
            json.dumps(findings, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"ERROR: could not write {args.output}: {exc}", file=sys.stderr)
        return 2

    affected_pkgs = len({(f["package"], f["version"]) for f in findings})
    print(
        f"\nSaved {len(findings)} total finding(s) across {affected_pkgs} "
        f"vulnerable package version(s) (of {len(pins)} scanned) to {args.output}"
    )

    if failed:
        print(
            f"WARNING: {len(failed)} package(s) could not be checked, so the output is "
            f"INCOMPLETE: {', '.join(failed)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())