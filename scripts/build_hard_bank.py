#!/usr/bin/env python3
"""
Build a hard-example ICL bank from prediction results.

Criteria (hard if any):
- Wrong CWE classification
- Missed localization at ±10 window
- Unparseable output (parsed_ok=False)

Input files:
- --prompts: JSONL prompts with {bug_id, prompt, gold:{cwe_id, vulnerable_lines}}
- --preds: one or more prediction JSONLs with {bug_id, pred_cwe, pred_lines, parsed_ok, ...}
- --k-per-cwe: number of examples to select per gold CWE
Output:
- --out: JSON list of exemplars [{bug_id, cwe_id, prompt, gold_vulnerable_lines}]
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


def load_prompts_map(path: Path) -> Dict[int, Dict]:
    m: Dict[int, Dict] = {}
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            m[rec["bug_id"]] = rec
    return m


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prompts", required=True)
    ap.add_argument("--preds", nargs="+", required=True)
    ap.add_argument("--k-per-cwe", type=int, default=3)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    prompts_map = load_prompts_map(Path(args.prompts))

    # Gather failures per gold CWE
    by_cwe: Dict[str, List[Tuple[float, Dict]]] = {}

    for preds_path in args.preds:
        with open(preds_path, "r", encoding="utf-8") as f:
            for line in f:
                p = json.loads(line)
                bug_id = p["bug_id"]
                rec = prompts_map.get(bug_id)
                if not rec:
                    continue
                gold = rec.get("gold", {})
                gold_cwe = (gold.get("cwe_id") or "").strip().upper()
                gold_lines = gold.get("vulnerable_lines") or []
                pred_cwe = (p.get("pred_cwe") or "").strip().upper()
                pred_lines = p.get("pred_lines") or []
                parsed_ok = bool(p.get("parsed_ok"))

                wrong_cwe = int(not pred_cwe or (gold_cwe and pred_cwe != gold_cwe))
                miss_loc = int(not window_overlap(pred_lines, gold_lines, 10))
                unparsed = int(not parsed_ok)
                hardness = wrong_cwe * 2 + miss_loc + unparsed
                # Only consider as hard if any criteria triggered
                if hardness <= 0:
                    continue
                by_cwe.setdefault(gold_cwe, []).append((hardness, {
                    "bug_id": bug_id,
                    "gold_cwe": gold_cwe,
                    "prompt": rec.get("prompt", ""),
                    "gold_vulnerable_lines": gold_lines,
                    "hardness": hardness,
                }))

    exemplars: List[Dict] = []
    for cwe_id, items in by_cwe.items():
        # sort by hardness desc
        items.sort(key=lambda x: x[0], reverse=True)
        for _, ex in items[: args.k_per_cwe]:
            exemplars.append(ex)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(exemplars, f, indent=2)


if __name__ == "__main__":
    main()
