# Catalyst 1.0: Python Vulnerability Reachability Scanner

**Which vulnerability alerts actually affect a Python project?**
Scanners flag every CVE in every dependency, whether or not your code can reach the vulnerable function. This tool decides, per alert, whether it can, and shows the evidence. It is static, local-first and costs $0.

| Verdict | Meaning | Output |
|---|---|---|
| `reachable` | A call path from project code to the vulnerable function exists | call path + confidence |
| `not_reachable` | Proven absent under the analysis limits below | OpenVEX `not_affected` statement |
| `uncertain` | Dynamic features or unresolved mapping make certainty unsafe | the exact blocker |

**Safety rule:** an alert is never `not_reachable` when we are unsure.

## Pipeline

```
requirements.txt ─► osv_checker.py ─► osv_vulnerabilities.json
                                          │
        project .py files ─► ast index ───┤
        fix-commit diffs ─► function_resolver.py (cache.db)
        PyPI release ─► library_graph.py (in memory, cache.db)
                                          ▼
                              reachability_engine.py ─► verdicts.json ─► report.openvex.json
                                                                    └─► chat.py (debate agent)
```

## Design questions

**1. From a fix commit to vulnerable functions?**
`function_resolver.py` finds GitHub fix commits in the advisory's references and OSV `GIT` ranges. It downloads the `.diff` and maps each changed hunk to its enclosing `def` (and class), skipping tests and functions the fix *added*. Diff-derived mappings get confidence 0.9. If no diff yields functions, a free LLM (Groq `openai/gpt-oss-20b`) infers names from the advisory text at confidence 0.55. LLM mappings can prove reachability but can never certify absence. With no mapping at all the alert is `uncertain`. Diffs can touch more than the vulnerable function, so a mapping is evidence, not proof.

**2. Python's dynamic features?**
The AST pass flags `eval`/`exec`, `getattr` with a non-literal name, `importlib.import_module`/`__import__` with a non-literal argument, plugin and entry-point loading, and `globals()[...]` lookups. Literal `getattr(x, "name")` is resolved normally. Dynamic features near a package's use, dynamic dispatch inside the library's reachable code, unparsable files, or a low-confidence mapping all block `not_reachable` and force `uncertain`. The call graphs are over-approximate (when unsure, add an edge), so errors lean toward false positives rather than missed vulnerabilities.

**3. Caching?**
`cache.db` (SQLite) holds two tables:
- `function_map`: advisory + package → vulnerable functions, so diffs are not re-fetched and the LLM is not re-called.
- `library_graph`: package + version → compressed call graph, so a popular release is downloaded and parsed once across all projects.

Package names are PEP 503-normalised. Negative results are cached only when every source was tried without a transient failure.

## Quickstart (Windows PowerShell)

```powershell
python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -r requirements.txt
# put GROQ_API_KEY=... in api.env or .env (optional, only for the LLM fallback and chat.py)

python scan.py path\to\project            # writes verdicts.json + report.openvex.json
python -m unittest test_pipeline -v       # offline tests, no network

# Demo: one fixture per verdict
python scan.py demo_fixtures\case_reachable
python scan.py demo_fixtures\case_not_reachable --assume-direct-deps
python scan.py demo_fixtures\case_uncertain_dynamic

# Debate agent: explains evidence, never changes a verdict
python chat.py verdicts.json
```

**Isolated run (Docker):**
```powershell
docker build -t catalyst-scan .
mkdir out -Force
docker run --rm --cap-drop ALL --security-opt no-new-privileges `
  -v "${PWD}\demo_fixtures\case_reachable:/target:ro" -v "${PWD}\out:/out" `
  catalyst-scan /target --osv-output /out/osv_vulnerabilities.json --out-dir /out --cache /out/cache.db
```

**PR bot:** `.github/workflows/pr-bot.yml` runs the scanner on pull requests against `demo_fixtures/case_reachable`.

## Safety model
- Target code is parsed with `ast` and never imported, executed or installed.
- Dependency releases are downloaded and read in memory only, never extracted or installed.
- LLM output is reduced to plain dotted identifiers before use, and the LLM cannot change a verdict.
- Docker runs as a non-root user with the target mounted read-only.
- OpenVEX contains only proven `not_reachable` findings; `reachable` and `uncertain` alerts are never asserted away.

## Known limitations
- Only 2 of 7,866 PyPA advisories name affected functions machine-readably, so mapping relies on fix-commit diffs and falls back to `uncertain` when none are found.
- Library call graphs are name-based and over-approximate, so some `reachable` verdicts may be false positives, and `not_reachable` on large libraries is rare.
- A package never imported may still be used via another dependency. `--assume-direct-deps` ignores this and is unsafe for transitive dependencies.
- Compiled extensions (C/Rust), notebooks, and non-Python code are not analysed. Tests are excluded unless `--include-tests` is given.
- Verdicts depend on live OSV and GitHub data, and on the advisory having a resolvable fix commit.
