import json
import os
from pathlib import Path
import requests

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-oss-20b"


def get_groq_api_key() -> str:
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if key:
        return key

    env_file = Path(__file__).resolve().parent / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == "GROQ_API_KEY":
                return v.strip().strip('"').strip("'")
    return ""


def ask_open_weight_llm(system_prompt: str, user_prompt: str, model: str = DEFAULT_MODEL) -> str:
    api_key = get_groq_api_key()
    if not api_key:
        return ""

    resp = requests.post(
        GROQ_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "temperature": 0.1,
            "max_tokens": 500,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def infer_functions_from_advisory(pkg: str, summary: str, details: str) -> list[str]:
    prompt = (
        f"PyPI package: {pkg}\n"
        f"Summary: {summary}\n"
        f"Details: {details[:1500]}\n\n"
        "Return ONLY a JSON array of affected Python function or method names "
        '(e.g., ["full_load", "load"]). If unknown, return [].'
    )
    raw = ask_open_weight_llm(
        "You are a Python security parser. Output a valid JSON array of strings only.",
        prompt,
    )
    if not raw:
        return []
    try:
        start, end = raw.find("["), raw.rfind("]") + 1
        return json.loads(raw[start:end]) if start != -1 and end > start else []
    except Exception:
        return []