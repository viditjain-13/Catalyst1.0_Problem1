import json
import re
import sys
from pathlib import Path
import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def parse_pinned_requirements(req_path: Path) -> list[tuple[str, str]]:
    """Extracts (package_name, exact_version) pairs from requirements.txt."""
    packages = []
    for raw_line in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.-]+)$", line)
        if match:
            packages.append((match.group(1), match.group(2)))
    return packages


def fetch_osv_vulns(package: str, version: str) -> list[dict]:
    """Queries OSV API for all known PyPI vulnerabilities in one package version."""
    payload = {
        "package": {
            "name": package,
            "ecosystem": "PyPI",
        },
        "version": version,
    }
    response = requests.post(OSV_QUERY_URL, json=payload, timeout=20)
    response.raise_for_status()
    data = response.json()
    return data.get("vulns", [])


def main():
    target_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    req_file = target_dir / "requirements.txt"

    if not req_file.exists():
        print(f"No requirements.txt found at: {req_file}")
        return

    pins = parse_pinned_requirements(req_file)
    if not pins:
        print("No exact 'package==version' entries found in requirements.txt.")
        return

    all_findings = []
    for pkg, ver in pins:
        vulns = fetch_osv_vulns(pkg, ver)
        print(f"{pkg}=={ver}: {len(vulns)} vulnerability record(s) found")
        for v in vulns:
            finding = {
                "package": pkg,
                "version": ver,
                "id": v.get("id"),
                "aliases": v.get("aliases", []),
                "summary": v.get("summary", ""),
                "references": [r.get("url") for r in v.get("references", []) if r.get("url")],
            }
            all_findings.append(finding)

    out_file = Path("osv_vulnerabilities.json")
    out_file.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
    print(f"\nSaved {len(all_findings)} total findings to {out_file}")


if __name__ == "__main__":
    main()