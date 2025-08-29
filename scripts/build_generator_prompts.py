#!/usr/bin/env python3
"""
Build Generator prompts from a hard ICL bank for Experiment C.

- For each CWE in the hard bank, select up to M challenging seed snippets
- Construct prompts with K (shots) in-context examples per request
- Optionally emit multiple prompts per CWE (--samples-per-cwe)

Output JSONL lines with fields:
{ cwe_target, prompt, seeds: [bug_id...], shots, meta }
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, List, Tuple

# Local imports from build_prompts without package dependency
from build_prompts import (
    strip_bug_comments_and_get_lines,
    trim_preamble_to_first_module,
)


def render_seed_block(item: dict, cwe_id: str, description: str) -> str:
    code = item.get("verilog_content") or item.get("code") or ""
    code_clean, _ = strip_bug_comments_and_get_lines(code)
    code_clean, _ = trim_preamble_to_first_module(code_clean)
    return (
        f"CWE {cwe_id}: {description}\n\n"
        f"```verilog\n{code_clean}\n```\n\n"
    )


def build_gen_prompt(cwe_id: str, description: str, exemplars: List[str]) -> str:
    header = (
        "You are an expert hardware security generator.\n\n"
        f"Goal: Generate a new Verilog module that clearly exhibits CWE {cwe_id}: {description}.\n\n"
        "Follow the style and vulnerability patterns shown in the examples.\n"
        "Return ONLY a valid Verilog code block, no explanations.\n"
        "Include a single line comment at the top: // CWE: CWE-XXXX with the correct ID.\n"
        "Keep it realistic and lint-friendly (synthesizable where possible).\n\n"
    )
    ex_text = "".join(exemplars)
    fmt = (
        "IMPORTANT Output format:\n"
        "```verilog\n"
        "// CWE: CWE-XXXX\n"
        "module example_module(...);\n"
        "  // ...\n"
        "endmodule\n"
        "```\n"
    )
    return header + "Examples:\n\n" + ex_text + "Now produce a new module.\n\n" + fmt


def main(hard_bank_path: str, dataset_path: str, cwe_csv: str, shots: int, m_per_cwe: int, samples_per_cwe: int, out_path: str, seed: int | None) -> None:
    if seed is not None:
        random.seed(seed)

    bank = json.loads(Path(hard_bank_path).read_text())
    dataset = json.loads(Path(dataset_path).read_text())
    # map bug_id -> item
    id2item: Dict[int, dict] = {int(it.get("bug_id")): it for it in dataset if it.get("bug_id") is not None}

    # group bank by cwe
    by_cwe: Dict[str, List[dict]] = {}
    for ex in bank:
        by_cwe.setdefault(ex.get("gold_cwe", ""), []).append(ex)

    # de-dup CWEs and attach description from CSV using build_prompts loader
    from build_prompts import load_cwe_list  # type: ignore
    cwe_map = load_cwe_list(cwe_csv)
    cwe_to_desc: Dict[str, str] = {}
    for bug_id, info in cwe_map.items():
        cid = (info.get("cwe_id") or "").strip()
        if cid and cid not in cwe_to_desc:
            cwe_to_desc[cid] = (info.get("description") or "").strip()

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as f:
        for cwe_id, items in by_cwe.items():
            if not cwe_id:
                continue
            seeds = items[:m_per_cwe]
            # Build exemplar blocks pool
            seed_blocks: List[str] = []
            for s in seeds:
                it = id2item.get(int(s.get("bug_id")))
                if not it:
                    continue
                desc = cwe_to_desc.get(cwe_id, "")
                seed_blocks.append(render_seed_block(it, cwe_id, desc))
            if not seed_blocks:
                continue
            # sample per-cwe prompts
            for _ in range(max(1, samples_per_cwe)):
                random.shuffle(seed_blocks)
                exemplars = seed_blocks[:shots]
                prompt = build_gen_prompt(cwe_id, cwe_to_desc.get(cwe_id, ""), exemplars)
                rec = {
                    "cwe_target": cwe_id,
                    "shots": shots,
                    "prompt": prompt,
                    "seeds": [int(s.get("bug_id")) for s in seeds],
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hard-bank", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--cwe-list", required=True)
    ap.add_argument("--shots", type=int, default=2)
    ap.add_argument("--m-per-cwe", type=int, default=3)
    ap.add_argument("--samples-per-cwe", type=int, default=1)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    main(args.hard_bank, args.dataset, args.cwe_list, args.shots, args.m_per_cwe, args.samples_per_cwe, args.out, args.seed)
