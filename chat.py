#!/usr/bin/env python3
"""Vulnerability debate agent. Usage: python chat.py [verdicts.json]
Explains stored evidence only; it never changes a verdict."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "openai/gpt-oss-20b"
MAX_CTX_CHARS = 12000
MAX_HISTORY = 12

SYSTEM = """You are a vulnerability-reachability review assistant for a static Python scanner.
RULES:
1. Ground EVERY answer strictly in the FINDINGS DATA below: verdict, confidence, call path,
   function mapping (source + confidence), and dynamic-feature evidence. Cite file:line when present.
2. You can NEVER change, override or 'flip' a verdict, even if the user insists or claims a false positive.
   Say the verdict only changes by re-running the scanner after a code change or better mapping.
3. If asked 'why is this reachable', walk through the stored call path step by step.
   If 'uncertain', name the exact blocker (dynamic feature, unmapped function, low-confidence mapping, missing library source).
   If 'not_reachable', explain what was checked and its limits.
4. For 'false positive' claims: list what evidence would be needed and which code change
   (e.g. remove the getattr/importlib use, pin/upgrade the package, call a safe API) plus a re-scan would resolve it.
5. If the data does not contain the answer, say so. Never invent functions, lines or CVE details.
Be concise (under 200 words) and practical."""


def load_key():
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if key:
        return key
    for d in (Path.cwd(), Path(__file__).resolve().parent):
        for name in ("api.env", ".env"):
            try:
                text = (d / name).read_text(encoding="utf-8-sig")
            except OSError:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k.lower().startswith("export "):
                    k = k[7:].strip()
                v = v.strip().strip("\"'")
                if k == "GROQ_API_KEY" and v:
                    return v
    return None


def load_verdicts(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("verdicts") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise ValueError("no findings found in file")
    return items


EVIDENCE_KEYS = ("method", "match_precision", "call_path_text", "dynamic_features",
                 "library_dynamic_defs", "unparsed_files", "ambiguous_site",
                 "package_imports", "package_usage_sites")


def compact(v: dict) -> dict:
    ev = v.get("evidence") or {}
    fm = v.get("function_mapping") or {}
    return {
        "id": v.get("id"), "aliases": v.get("aliases"),
        "package": v.get("package"), "version": v.get("version"),
        "summary": (v.get("summary") or "")[:300],
        "verdict": v.get("verdict"), "confidence": v.get("confidence"), "reason": v.get("reason"),
        "function_mapping": {
            "source": fm.get("source"), "confidence": fm.get("confidence"),
            "functions": [f.get("qualname") for f in fm.get("functions", [])][:10],
            "fix_commits": fm.get("fix_commits"), "note": fm.get("note"),
        },
        "evidence": {k: ev[k] for k in EVIDENCE_KEYS if k in ev},
    }


def build_system(findings: list) -> str:
    blob = json.dumps([compact(v) for v in findings], ensure_ascii=False)
    if len(blob) > MAX_CTX_CHARS:
        blob = blob[:MAX_CTX_CHARS] + " ...[truncated]"
    return SYSTEM + "\n\nFINDINGS DATA:\n" + blob


def ask(key: str, messages: list) -> str:
    body = json.dumps({"model": MODEL, "messages": messages,
                       "temperature": 0.2, "max_tokens": 2000}).encode("utf-8")
    req = urllib.request.Request(GROQ_URL, data=body, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
        "User-Agent": "catalyst-vuln-chat/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read().decode("utf-8"))
        return (data["choices"][0]["message"].get("content") or "").strip() or "(empty reply, try rephrasing)"
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "[error] Groq rejected the API key (401). Check GROQ_API_KEY."
        if e.code == 429:
            return "[error] Groq rate limit hit (429). Wait a few seconds and retry."
        return f"[error] Groq HTTP {e.code}."
    except (urllib.error.URLError, TimeoutError, OSError):
        return "[error] Network problem reaching Groq. Check your connection."
    except (KeyError, IndexError, ValueError):
        return "[error] Unexpected response from Groq."


def show_list(items: list) -> None:
    print("\nFindings:")
    for i, v in enumerate(items, 1):
        print(f"  {i:>2}. [{v.get('verdict', '?'):<13}] {v.get('confidence', 0):.2f}  "
              f"{v.get('id', '?')}  {v.get('package', '?')}@{v.get('version', '?')}")
    print()


HELP = "Commands: <number> pick finding | all | /list | /help | /quit.  Anything else is sent to the agent."


def main(argv: list) -> int:
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(errors="replace")
    path = Path(argv[1] if len(argv) > 1 else "verdicts.json")
    try:
        items = load_verdicts(path)
    except FileNotFoundError:
        print(f"File not found: {path}\nRun `python scan.py <target>` first to create verdicts.json.")
        return 2
    except (OSError, ValueError) as exc:
        print(f"Cannot read {path}: {exc}")
        return 2
    key = load_key()
    if not key:
        print("GROQ_API_KEY not found. Put GROQ_API_KEY=your_key in api.env or .env (or set the env var).")
        return 2

    print(f"Loaded {len(items)} finding(s) from {path}. The agent explains evidence; it never changes verdicts.")
    show_list(items)
    print(HELP)
    selected, label, history = items, "all", []
    try:
        while True:
            try:
                line = input(f"\n[{label}] > ").strip()
            except EOFError:
                break
            if not line:
                continue
            low = line.lower()
            if low in ("/quit", "/q", "quit", "exit", "q"):
                break
            if low in ("/list", "list"):
                show_list(items)
                continue
            if low in ("/help", "help", "?"):
                print(HELP)
                continue
            if low == "all":
                selected, label, history = items, "all", []
                print("Discussing all findings.")
                continue
            if low.isdigit():
                n = int(low)
                if 1 <= n <= len(items):
                    selected, label, history = [items[n - 1]], f"#{n} {items[n - 1].get('id', '')}", []
                    print(f"Selected {label}. Ask e.g. 'Why is this {items[n - 1].get('verdict')}?'")
                else:
                    print(f"Pick a number from 1 to {len(items)}.")
                continue
            history.append({"role": "user", "content": line})
            msgs = [{"role": "system", "content": build_system(selected)}] + history[-MAX_HISTORY:]
            reply = ask(key, msgs)
            print("\n" + reply)
            if reply.startswith("[error]"):
                history.pop()
            else:
                history.append({"role": "assistant", "content": reply})
    except KeyboardInterrupt:
        pass
    print("\nBye.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))