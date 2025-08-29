#!/usr/bin/env python3
"""
Run Experiment C: Generator with ICL exemplars, plus lint and LLM-as-judge.

Inputs:
- --prompts: generator prompts JSONL ({cwe_target, shots, prompt, seeds})
- --model: gpt4o | claude-3.5-haiku | together:<model_id>
- --out-dir: directory to write generated code files and logs
- --limit: optional cap on number of prompts processed
- --judge-model: model for judging realism/consistency (default: gpt4o)

Outputs:
- <out-dir>/gen.jsonl: rows {cwe_target, shots, model, raw, code_path, lint_pass, judge:{realism, consistency}}
- <out-dir>/metrics.json: aggregate metrics for Table C1/C2
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Providers loaded lazily

def call_openai(prompt: str) -> str:
    from openai import OpenAI  # type: ignore
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)
    sys_msg = (
        "You must return a single valid Verilog code block, no extra text or fencing outside."
    )
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=1100,
    )
    return resp.choices[0].message.content or ""


def call_claude(prompt: str) -> str:
    import anthropic  # type: ignore
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    client = anthropic.Anthropic(api_key=api_key)
    sys_msg = (
        "Return only a single valid Verilog code block (no prose)."
    )
    msg = client.messages.create(
        model="claude-3-5-haiku-latest",
        max_tokens=1100,
        temperature=0.3,
        system=sys_msg,
        messages=[{"role": "user", "content": prompt}],
    )
    parts = []
    for block in getattr(msg, "content", []) or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", ""))
    return "".join(parts)


def call_together(prompt: str, model_id: str) -> str:
    from together import Together  # type: ignore
    api_key = os.getenv("TOGETHER_API_KEY")
    if not api_key:
        raise RuntimeError("TOGETHER_API_KEY not set")
    client = Together(api_key=api_key)
    sys_msg = "Return only a single valid Verilog code block (no prose)."
    # Backoff + retry for rate limit / overload
    delay = 20.0
    max_retries = 6
    for attempt in range(max_retries):
        try:
            # Truncate overly long prompts to fit model context limits
            if len(prompt) > 8000:
                prompt = prompt[-8000:]
            resp = client.chat.completions.create(
                model=model_id,
                messages=[{"role": "system", "content": sys_msg}, {"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=700,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            msg = str(e).lower()
            if ("429" in msg) or ("rate limit" in msg) or ("503" in msg) or ("overload" in msg) or ("8193" in msg) or ("max_new_tokens" in msg):
                time.sleep(delay)
                delay = min(90.0, delay * 1.7)
                continue
            raise
    # If all retries exhausted
    return ""


def extract_code(text: str) -> str:
    # Prefer ```verilog fenced
    m = re.search(r"```verilog\s*([\s\S]*?)```", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\s*([\s\S]*?)```", text)
    if m:
        return m.group(1).strip()
    return text.strip()


def run_verilator_lint(code: str) -> bool:
    # Check verilator availability
    try:
        subprocess.run(["verilator", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except Exception:
        return False
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "gen.v"
        path.write_text(code)
        cmd = ["verilator", "--lint-only", "-Wall", str(path)]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.returncode == 0


def judge_with_openai(code: str, cwe_target: str) -> Tuple[bool, bool]:
    from openai import OpenAI  # type: ignore
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return False, False
    client = OpenAI(api_key=api_key)
    sys_msg = (
        "You are judging Verilog vulnerability examples. Return JSON only with keys: realism_pass, consistency_pass."
    )
    user = (
        "Evaluate the following Verilog snippet for two criteria:\n"
        f"1) realism_pass: realistic and coherent RTL that compiles/lints (True/False).\n"
        f"2) consistency_pass: does it implement CWE {cwe_target} pattern and include a top comment like // CWE: {cwe_target}? (True/False).\n\n"
        "Return JSON only.\n\n"
        f"```verilog\n{code}\n```\n"
    )
    try:
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": sys_msg}, {"role": "user", "content": user}],
            temperature=0.0,
            max_tokens=100,
            response_format={"type": "json_object"},
        )
        txt = resp.choices[0].message.content or "{}"
        obj = json.loads(txt)
        return bool(obj.get("realism_pass")), bool(obj.get("consistency_pass"))
    except Exception:
        return False, False


def tokenize(code: str) -> List[str]:
    # Simple whitespace tokenization
    return re.findall(r"\w+|\S", code)


def compute_entropy(codes: List[str]) -> float:
    # Shannon entropy over token distribution (natural log)
    from math import log
    from collections import Counter
    tokens: List[str] = []
    for c in codes:
        tokens.extend(tokenize(c))
    if not tokens:
        return 0.0
    cnt = Counter(tokens)
    total = sum(cnt.values())
    ent = 0.0
    for v in cnt.values():
        p = v / total
        if p > 0:
            ent -= p * log(p)
    return ent


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prompts", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--judge-model", default="gpt4o")
    ap.add_argument("--resume", action="store_true", default=False, help="Append to existing gen.jsonl and skip already processed prompts")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    gen_log_path = out_dir / "gen.jsonl"
    processed_offset = 0
    if args.resume and gen_log_path.exists():
        with gen_log_path.open("r", encoding="utf-8") as f:
            for processed_offset, _ in enumerate(f, start=1):
                pass
    gen_log = gen_log_path.open("a", encoding="utf-8")

    # Load prompts
    rows = []
    with open(args.prompts, "r", encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    # Apply resume offset
    if processed_offset > 0:
        rows = rows[processed_offset:]
    # Apply limit on the remaining rows
    if args.limit:
        rows = rows[: args.limit]

    codes_for_entropy: List[str] = []
    total = 0
    lint_pass = 0
    realism_pass = 0
    consistency_pass = 0

    for rec in rows:
        total += 1
        cwe_target = rec.get("cwe_target")
        prompt = rec.get("prompt")
        shots = rec.get("shots")
        # Call model
        if args.model == "gpt4o":
            text = call_openai(prompt)
        elif args.model == "claude-3.5-haiku":
            text = call_claude(prompt)
        elif args.model.startswith("together:"):
            text = call_together(prompt, args.model.split(":", 1)[1])
        else:
            text = ""
        code = extract_code(text)
        codes_for_entropy.append(code)
        # Lint
        lint_ok = run_verilator_lint(code)
        if lint_ok:
            lint_pass += 1
        # Judge
        rp, cp = (False, False)
        if args.judge_model == "gpt4o":
            rp, cp = judge_with_openai(code, cwe_target)
        realism_pass += 1 if rp else 0
        consistency_pass += 1 if cp else 0
        # Save code file
        # Sanitize model id for filesystem
        model_tag = args.model.replace(":", "_").replace("/", "-")
        code_path = out_dir / f"{model_tag}_{cwe_target}_{shots}_{total}.v"
        code_path.write_text(code)
        gen_log.write(json.dumps({
            "cwe_target": cwe_target,
            "shots": shots,
            "model": args.model,
            "raw": text,
            "code_path": str(code_path),
            "lint_pass": lint_ok,
            "judge": {"realism": rp, "consistency": cp}
        }) + "\n")
        # Throttle Together models to stay under model-specific limits
        if args.model.startswith("together:"):
            time.sleep(22.0)

    gen_log.close()

    # Recompute aggregate metrics over entire gen.jsonl
    agg_total = 0
    agg_lint = 0
    agg_real = 0
    agg_cons = 0
    agg_codes: List[str] = []
    try:
        with gen_log_path.open("r", encoding="utf-8") as f:
            for line in f:
                obj = json.loads(line)
                agg_total += 1
                if obj.get("lint_pass"):
                    agg_lint += 1
                j = obj.get("judge", {})
                if j.get("realism"):
                    agg_real += 1
                if j.get("consistency"):
                    agg_cons += 1
                cp = obj.get("code_path")
                if cp and Path(cp).exists():
                    try:
                        agg_codes.append(Path(cp).read_text())
                    except Exception:
                        pass
    except Exception:
        pass

    metrics = {
        "model": args.model,
        "shots": None,
        "generated": agg_total,
        "lint_pass_rate": (agg_lint / agg_total) * 100 if agg_total else 0.0,
        "injection_realism": (agg_real / agg_total) * 100 if agg_total else 0.0,
        "label_consistency": (agg_cons / agg_total) * 100 if agg_total else 0.0,
        "diversity_entropy": compute_entropy(agg_codes),
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
