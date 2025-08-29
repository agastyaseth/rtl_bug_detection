#!/usr/bin/env python3
"""
Run inference from prebuilt prompt JSONL and evaluate basic metrics.

Inputs: JSONL lines with fields {bug_id, prompt, gold: {cwe_id, vulnerable_lines}}
Models: gpt4o (OpenAI), claude-3.5-haiku (Anthropic)
Outputs:
- preds JSONL (one per sample)
- metrics JSON summary (aggregate)
"""
from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import re

try:
    import openai  # type: ignore
except Exception:
    openai = None  # type: ignore

# Anthropic imported lazily inside call to avoid hard dep errors

@dataclass
class Prediction:
    bug_id: int
    raw: str
    parsed_ok: bool
    pred_cwe: Optional[str]
    pred_lines: List[int]
    latency_ms: float


def parse_model_json(text: str) -> Tuple[Optional[str], List[int], bool]:
    """Attempt to parse strict JSON first; fallback regex if needed."""
    # Try to locate a JSON object in text
    json_obj = None
    try:
        json_obj = json.loads(text)
    except Exception:
        # heuristic: find first {...}
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                json_obj = json.loads(m.group(0))
            except Exception:
                json_obj = None
    if isinstance(json_obj, dict):
        cwe = json_obj.get("cwe")
        lines = json_obj.get("lines")
        if isinstance(cwe, str) and isinstance(lines, list):
            norm_lines = [int(x) for x in lines if isinstance(x, int) or (isinstance(x, str) and x.isdigit())]
            # normalize CWE formatting (ensure CWE-####)
            cwe_norm = cwe.strip().upper()
            if not cwe_norm.startswith("CWE-") and re.match(r"^\d+$", cwe_norm):
                cwe_norm = f"CWE-{cwe_norm}"
            return cwe_norm, sorted(set(norm_lines)), True
    # Fallback regex extraction
    cwe_match = re.search(r"CWE-\d+", text, re.IGNORECASE)
    cwe_norm = cwe_match.group(0).upper() if cwe_match else None
    # lines: parse numbers or ranges
    nums = set()
    for a, b in re.findall(r"lines?\s*(\d+)\s*[-–—]\s*(\d+)", text.lower()):
        for v in range(int(a), int(b) + 1):
            nums.add(v)
    for n in re.findall(r"line\s*(\d+)", text.lower()):
        nums.add(int(n))
    return cwe_norm, sorted(nums), False


def window_overlap(pred: List[int], gold: List[int], window: int) -> bool:
    if not pred or not gold:
        return False
    gold_set = set(gold)
    if window <= 0:
        return any(p in gold_set for p in pred)
    # expand gold by window
    expanded = set()
    for g in gold:
        for v in range(g - window, g + window + 1):
            expanded.add(v)
    return any(p in expanded for p in pred)


def precision_recall(pred: List[int], gold: List[int], window: int) -> Tuple[float, float]:
    if not pred:
        return 0.0, 0.0
    if not gold:
        return 0.0, 0.0
    expanded = set()
    for g in gold:
        for v in range(g - window, g + window + 1):
            expanded.add(v)
    pred_set = set(pred)
    tp = len(pred_set & expanded)
    prec = tp / max(1, len(pred_set))
    rec = tp / max(1, len(expanded))  # window-based recall proxy
    return prec, rec


def call_openai_gpt4o(prompt: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    client = openai.OpenAI(api_key=api_key)
    # Strong JSON-only instruction
    system_msg = (
        "You must respond with a single valid JSON object only. "
        "No markdown, no code fences, no explanations. Keys: cwe (string), lines (array of ints), reason (string)."
    )
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": system_msg}, {"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=512,
        response_format={"type": "json_object"},
    )
    return resp.choices[0].message.content or ""


def call_claude_haiku(prompt: str) -> str:
    import anthropic  # type: ignore

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    client = anthropic.Anthropic(api_key=api_key)
    system_msg = (
        "Respond with a single valid JSON object only. "
        "No markdown or extra text. Keys: cwe, lines, reason."
    )
    msg = client.messages.create(
        model="claude-3-5-haiku-latest",
        max_tokens=512,
        temperature=0.0,
        system=system_msg,
        messages=[{"role": "user", "content": prompt}],
    )
    parts = []
    for block in getattr(msg, "content", []) or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", ""))
    return "".join(parts)


def call_together_chat(model_id: str, prompt: str) -> str:
    # Requires: pip install together; env TOGETHER_API_KEY
    from together import Together  # type: ignore

    api_key = os.getenv("TOGETHER_API_KEY")
    if not api_key:
        raise RuntimeError("TOGETHER_API_KEY not set")
    client = Together(api_key=api_key)
    system_msg = (
        "Respond with a single valid JSON object only. No markdown or extra text. Keys: cwe, lines, reason."
    )
    resp = client.chat.completions.create(
        model=model_id,
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt},
        ],
        temperature=0.0,
        max_tokens=512,
        # Some Together models support JSON format; ignored if unsupported
        response_format={"type": "json_object"},
    )
    return resp.choices[0].message.content or ""


def run_eval(prompts_path: Path, model: str, out_preds: Path, out_metrics: Path, limit: Optional[int], window: int) -> None:
    out_preds.parent.mkdir(parents=True, exist_ok=True)
    preds: List[Prediction] = []
    total = 0

    with prompts_path.open("r", encoding="utf-8") as f_in, out_preds.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            if limit is not None and total >= limit:
                break
            total += 1
            rec = json.loads(line)
            bug_id = rec["bug_id"]
            prompt = rec["prompt"]
            gold = rec.get("gold", {})
            t0 = time.time()
            try:
                if model == "gpt4o":
                    text = call_openai_gpt4o(prompt)
                elif model == "claude-3.5-haiku":
                    text = call_claude_haiku(prompt)
                elif model.startswith("together:"):
                    text = call_together_chat(model.split(":", 1)[1], prompt)
                else:
                    raise ValueError(f"Unsupported model: {model}")
            except Exception as e:
                text = f"Error: {e}"
            dt_ms = (time.time() - t0) * 1000.0
            cwe, lines, ok = parse_model_json(text)
            pred = Prediction(
                bug_id=bug_id,
                raw=text,
                parsed_ok=ok,
                pred_cwe=cwe,
                pred_lines=lines,
                latency_ms=dt_ms,
            )
            preds.append(pred)
            out_row = {
                "bug_id": bug_id,
                "raw": text,
                "parsed_ok": ok,
                "pred_cwe": cwe,
                "pred_lines": lines,
                "latency_ms": dt_ms,
                "gold": gold,
            }
            f_out.write(json.dumps(out_row) + "\n")

    # Aggregate metrics
    n = len(preds)
    exact_cwe = 0
    parent_match = 0  # placeholder; parent mapping not provided here
    loc_at_window = 0
    valid = 0
    sum_prec = 0.0
    sum_rec = 0.0
    latencies = []

    for p in preds:
        gold = {}
        # last written gold is in file; but we need it here too; simplest: reread from preds file if needed
        # Instead, re-open prompts to fetch gold by bug_id map
        # Build once outside loop
        latencies.append(p.latency_ms)

    # Build gold map
    gold_map: Dict[int, Dict] = {}
    with prompts_path.open("r", encoding="utf-8") as f_in:
        for line in f_in:
            rec = json.loads(line)
            gold_map[rec["bug_id"]] = rec["gold"]

    for p in preds:
        g = gold_map.get(p.bug_id, {})
        g_cwe = (g.get("cwe_id") or "").strip().upper()
        g_lines = g.get("vulnerable_lines") or []
        if p.pred_cwe and g_cwe and p.pred_cwe.upper() == g_cwe:
            exact_cwe += 1
        if window_overlap(p.pred_lines, g_lines, window):
            loc_at_window += 1
        if p.parsed_ok:
            valid += 1
        prec, rec = precision_recall(p.pred_lines, g_lines, window)
        sum_prec += prec
        sum_rec += rec

    metrics = {
        "total": n,
        "exact_cwe_acc": (exact_cwe / n) if n else 0.0,
        "loc@±%d" % window: (loc_at_window / n) if n else 0.0,
        "precision_avg": (sum_prec / n) if n else 0.0,
        "recall_avg": (sum_rec / n) if n else 0.0,
        "pass@1": (valid / n) if n else 0.0,
        "latency_ms_mean": (sum(latencies) / n) if n else 0.0,
    }

    out_metrics.parent.mkdir(parents=True, exist_ok=True)
    out_metrics.write_text(json.dumps(metrics, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prompts", required=True)
    ap.add_argument("--model", required=True, help='Model id: gpt4o | claude-3.5-haiku | together:<model_id>')
    ap.add_argument("--out-preds", required=True)
    ap.add_argument("--out-metrics", required=True)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--window", type=int, default=10, help="localization window size")
    args = ap.parse_args()

    run_eval(
        Path(args.prompts),
        args.model,
        Path(args.out_preds),
        Path(args.out_metrics),
        args.limit,
        args.window,
    )


if __name__ == "__main__":
    main()
