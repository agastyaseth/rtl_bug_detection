#!/usr/bin/env python3
"""
Build complete Detector prompts with optional in-context examples from the dataset.

- Loads buggy RTL dataset JSON
- Loads CWE CSV (tolerant parser in baseline_framework.load_cwe_list)
- For each sample, strips lines with `// BUG` and records vulnerable line numbers
- Constructs prompts embedding CWE-ID and description and K in-context examples
- Writes JSONL with records: {bug_id, prompt, gold: {cwe_id, vulnerable_lines}}
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

# Local CSV loader to avoid importing modules with side-effects
def load_cwe_list(cwe_list_path: str) -> Dict[int, Dict[str, str]]:
    cwe_dict: Dict[int, Dict[str, str]] = {}
    with open(cwe_list_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            bug_id_raw = (row.get('Bug ID') or '').strip()
            cwe_id = (row.get('CWE-ID') or '').strip()
            description = (row.get('Description') or '').strip()
            justification = (row.get('Justification') or '').strip() if 'Justification' in row else ''
            if not bug_id_raw or not cwe_id:
                continue
            try:
                bug_id = int(bug_id_raw)
            except ValueError:
                continue
            cwe_dict[bug_id] = {
                'cwe_id': cwe_id,
                'description': description,
                'justification': justification,
            }
    return cwe_dict


def strip_bug_comments_and_get_lines(verilog: str) -> Tuple[str, List[int]]:
    """Remove only the BUG/vulnerability comment text, keep the line to preserve numbering.

    Returns cleaned code and 1-based indices of lines that had BUG/vulnerability markers.
    """
    lines = verilog.splitlines()
    kept: List[str] = []
    bug_lines: List[int] = []
    for idx, line in enumerate(lines, start=1):
        lower = line.lower()
        if "//" in line and ("bug" in lower or "vulnerability" in lower):
            bug_lines.append(idx)
            # Strip the trailing comment starting at //
            cpos = line.find("//")
            cleaned = line[:cpos].rstrip()
            kept.append(cleaned)
        else:
            kept.append(line)
    return "\n".join(kept), bug_lines


def trim_preamble_to_first_module(verilog: str) -> Tuple[str, int]:
    """Trim lines before the first 'module' declaration to reduce license/preamble noise.

    Returns the trimmed code and the number of lines removed (offset) so that
    callers can adjust line-number annotations accordingly.
    """
    lines = verilog.splitlines()
    first_mod_idx = None
    for idx, line in enumerate(lines, start=1):
        if line.strip().lower().startswith("module ") or line.strip().lower().startswith("module\t"):
            first_mod_idx = idx
            break
    if first_mod_idx is None:
        return verilog, 0
    # Keep from first_mod_idx to end
    trimmed = "\n".join(lines[first_mod_idx - 1 :])
    return trimmed, first_mod_idx - 1


def choose_icl_examples(dataset: List[dict], k: int, exclude_bug_id: int) -> List[dict]:
    chosen: List[dict] = []
    for item in dataset:
        if len(chosen) >= k:
            break
        if item.get("bug_id") == exclude_bug_id:
            continue
        chosen.append(item)
    return chosen


def choose_icl_from_bank(dataset_map: Dict[int, dict], bank: List[Dict], k: int, exclude_bug_id: int) -> List[dict]:
    """Choose up to k exemplars from hard bank, approximately class-balanced.

    Falls back to simple first-k if balancing is not possible.
    """
    if k <= 0 or not bank:
        return []
    # Group bank entries by gold_cwe
    by_cwe: Dict[str, List[Dict]] = {}
    for ex in bank:
        by_cwe.setdefault(ex.get("gold_cwe", ""), []).append(ex)
    # Round-robin pick
    picked: List[dict] = []
    cwes = [c for c in by_cwe.keys() if c]
    idx = 0
    while len(picked) < k and cwes:
        cwe = cwes[idx % len(cwes)]
        bucket = by_cwe.get(cwe, [])
        while bucket and len(picked) < k:
            ex = bucket.pop(0)
            bug_id = ex.get("bug_id")
            if bug_id == exclude_bug_id:
                continue
            item = dataset_map.get(bug_id)
            if item:
                picked.append(item)
                break
        idx += 1
        # Remove empty buckets
        cwes = [c for c in cwes if by_cwe.get(c)]
    # Fallback: fill remaining from sequential bank
    if len(picked) < k:
        for ex in bank:
            bug_id = ex.get("bug_id")
            if bug_id == exclude_bug_id:
                continue
            item = dataset_map.get(bug_id)
            if item and item not in picked:
                picked.append(item)
                if len(picked) >= k:
                    break
    return picked[:k]


def render_example_block(item: dict, cwe_info: Dict) -> str:
    code = item.get("verilog_content") or item.get("code") or ""
    code_clean, bug_lines = strip_bug_comments_and_get_lines(code)
    code_clean, pre_offset = trim_preamble_to_first_module(code_clean)
    adj_lines = [ln - pre_offset for ln in bug_lines if ln > pre_offset]
    cwe_id = cwe_info.get("cwe_id", "")
    desc = cwe_info.get("description", "")
    just = cwe_info.get("justification", "")
    return (
        f"CWE {cwe_id}: {desc}\n\n"
        f"```verilog\n{code_clean}\n```\n\n"
        f"Vulnerable lines: {adj_lines}\n\n"
        + (f"Justification: {just}\n\n" if just else "")
    )


def build_prompt(sample: dict, references: List[Tuple[str, str]], icl_blocks: List[str]) -> str:
    rtl = sample.get("verilog_content") or sample.get("code") or ""
    code_clean, bug_lines = strip_bug_comments_and_get_lines(rtl)
    code_clean, _ = trim_preamble_to_first_module(code_clean)
    header = (
        "You are a hardware security expert specializing in identifying CWE vulnerabilities in RTL code.\n\n"
        "Task:\n- Select the exact CWE-ID from the reference list.\n- Localize the vulnerable lines (1-based indices).\n- Return JSON only: {\"cwe\":\"CWE-####\",\"lines\":[...],\"reason\":\"one sentence\"}.\n\n"
    )

    # Build references section with all CWEs
    ref_lines = ["References (CWE-ID: description):\n"]
    for cid, desc in references:
        ref_lines.append(f"- {cid}: {desc}")
    ref_text = "\n".join(ref_lines) + "\n\n"

    icl_text = "".join(icl_blocks)

    example_format = '{"cwe":"CWE-####","lines":[1,2,3],"reason":"one sentence"}'
    query = (
        "Analyze the following RTL and respond as JSON only in the format: "
        + example_format
        + "\n\nRTL to analyze:\n\n"
        + f"```verilog\n{code_clean}\n```\n"
    )

    return header + ref_text + ("Example:\n\n" + icl_text if icl_text else "") + query


def main(dataset_path: str, cwe_csv: str, out_jsonl: str, shots: int, icl_bank_path: str | None) -> None:
    dataset = json.loads(Path(dataset_path).read_text())
    cwe_map = load_cwe_list(cwe_csv)
    dataset_map: Dict[int, dict] = {int(it.get("bug_id")): it for it in dataset if it.get("bug_id") is not None}
    bank: List[Dict] = []
    if icl_bank_path:
        try:
            bank = json.loads(Path(icl_bank_path).read_text())
        except Exception:
            bank = []
    # Build de-duplicated references list sorted by CWE-ID
    cid_to_desc: Dict[str, str] = {}
    for _bug_id, info in cwe_map.items():
        cid = (info.get("cwe_id") or "").strip()
        if not cid:
            continue
        desc = (info.get("description") or "").strip()
        if cid not in cid_to_desc and desc:
            cid_to_desc[cid] = desc
        elif cid not in cid_to_desc:
            cid_to_desc[cid] = desc
    refs: List[Tuple[str, str]] = sorted(cid_to_desc.items(), key=lambda x: x[0])

    out = Path(out_jsonl)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as f:
        for item in dataset:
            bug_id = item.get("bug_id")
            if bug_id is None:
                continue
            cwe_info = cwe_map.get(bug_id, {"cwe_id": "", "description": ""})
            if bank:
                icl_items = choose_icl_from_bank(dataset_map, bank, max(0, shots), bug_id)
            else:
                icl_items = choose_icl_examples(dataset, max(0, shots), bug_id)
            icl_blocks = [render_example_block(x, cwe_map.get(x.get("bug_id"), {})) for x in icl_items]
            prompt = build_prompt(item, refs, icl_blocks)
            # Record gold vulnerable lines relative to the cleaned code that is shown
            code_raw = item.get("verilog_content") or item.get("code") or ""
            code_clean_gold, gold_lines = strip_bug_comments_and_get_lines(code_raw)
            code_clean_gold, pre_offset = trim_preamble_to_first_module(code_clean_gold)
            gold_lines = [ln - pre_offset for ln in gold_lines if ln > pre_offset]
            rec = {
                "bug_id": bug_id,
                "prompt": prompt,
                "gold": {
                    "cwe_id": cwe_info.get("cwe_id", ""),
                    "vulnerable_lines": gold_lines,
                },
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--cwe-list", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--shots", type=int, default=0)
    ap.add_argument("--icl-bank", dest="icl_bank", default=None, help="Optional hard ICL bank JSON to sample examples from")
    args = ap.parse_args()
    main(args.dataset, args.cwe_list, args.out, args.shots, args.icl_bank)
