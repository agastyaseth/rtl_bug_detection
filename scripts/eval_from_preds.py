#!/usr/bin/env python3
"""
Evaluate detector predictions JSONL against prompt gold using a localization window.

Inputs:
- --prompts: JSONL with {bug_id, gold:{cwe_id, vulnerable_lines}}
- --preds: JSONL with {bug_id, pred_cwe, pred_lines, parsed_ok, latency_ms, gold:...}
- --window: int (e.g., 10 or 25)
Outputs:
- --out: metrics JSON
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple


def window_overlap(pred: List[int], gold: List[int], window: int) -> bool:
    if not pred or not gold:
        return False
    expanded = set()
    for g in gold:
        for v in range(g - window, g + window + 1):
            expanded.add(v)
    return any(p in expanded for p in pred)


def precision_recall(pred: List[int], gold: List[int], window: int) -> Tuple[float, float]:
    if not pred or not gold:
        return 0.0, 0.0
    expanded = set()
    for g in gold:
        for v in range(g - window, g + window + 1):
            expanded.add(v)
    pred_set = set(pred)
    tp = len(pred_set & expanded)
    prec = tp / max(1, len(pred_set))
    rec = tp / max(1, len(expanded))
    return prec, rec


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prompts", required=True)
    ap.add_argument("--preds", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--window", type=int, default=10)
    args = ap.parse_args()

    # Build gold map
    gold_map: Dict[int, Dict] = {}
    with open(args.prompts, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            gold_map[rec["bug_id"]] = rec.get("gold", {})

    # Read preds
    preds = []
    with open(args.preds, "r", encoding="utf-8") as f:
        for line in f:
            preds.append(json.loads(line))

    n = len(preds)
    exact_cwe = 0
    loc_hits = 0
    pass1 = 0
    sum_prec = 0.0
    sum_rec = 0.0
    latencies = []

    for p in preds:
        bug_id = p["bug_id"]
        g = gold_map.get(bug_id, {})
        g_cwe = (g.get("cwe_id") or "").strip().upper()
        g_lines = g.get("vulnerable_lines") or []
        cwe = (p.get("pred_cwe") or "").strip().upper()
        lines = p.get("pred_lines") or []
        if cwe and g_cwe and cwe == g_cwe:
            exact_cwe += 1
        if window_overlap(lines, g_lines, args.window):
            loc_hits += 1
        if p.get("parsed_ok"):
            pass1 += 1
        pr, rc = precision_recall(lines, g_lines, args.window)
        sum_prec += pr
        sum_rec += rc
        lat = p.get("latency_ms")
        if isinstance(lat, (int, float)):
            latencies.append(float(lat))

    metrics = {
        "total": n,
        "exact_cwe_acc": (exact_cwe / n) if n else 0.0,
        f"loc@±{args.window}": (loc_hits / n) if n else 0.0,
        "precision_avg": (sum_prec / n) if n else 0.0,
        "recall_avg": (sum_rec / n) if n else 0.0,
        "pass@1": (pass1 / n) if n else 0.0,
        "latency_ms_mean": (sum(latencies) / len(latencies)) if latencies else 0.0,
    }

    Path(args.out).write_text(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
