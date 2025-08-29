#!/usr/bin/env python3
"""
Validation Agent (Compile Assurance) using Verilator + GPT-4o repair.

- Scans generator outputs under results/gen_*_s{2,4,8}/gen.jsonl
- For each sample, runs Verilator (lint-only) on the code
- If fails, tries up to K=3 repairs via GPT-4o using Verilator errors
- Aggregates Table E metrics per (model, shots) into results/table_E.csv

Env:
- OPENAI_API_KEY must be set

Notes:
- Only compile assurance is enforced. Realism/consistency are handled in Experiment C metrics.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------- Utilities ----------------------

def run_verilator_lint(code_text: str) -> Tuple[bool, str]:
    """Run Verilator lint-only on provided Verilog code. Returns (pass, stderr)."""
    try:
        subprocess.run(["verilator", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except Exception:
        return False, "Verilator not installed"
    with tempfile.TemporaryDirectory() as td:
        vpath = Path(td) / "module.v"
        vpath.write_text(code_text)
        p = subprocess.run(["verilator", "--lint-only", "-Wall", str(vpath)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ok = p.returncode == 0
        err = (p.stderr or b"").decode("utf-8", errors="ignore")
        return ok, err


def extract_code_block(text: str) -> str:
    # Prefer fenced verilog code
    m = re.search(r"```verilog\s*([\s\S]*?)```", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\s*([\s\S]*?)```", text)
    if m:
        return m.group(1).strip()
    return text.strip()


# ---------------------- GPT-4o repair ----------------------

def call_gpt4o_repair(original_code: str, error_snippet: str, cwe_tag: str) -> str:
    from openai import OpenAI  # type: ignore
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return ""
    client = OpenAI(api_key=api_key)
    system = (
        "You are a senior Verilog engineer. Fix compile/lint errors only. "
        "Preserve the vulnerability and top comment `// CWE: {cwe}` if present. "
        "Make the minimal necessary edits. Return ONLY a valid Verilog code block."
    ).replace("{cwe}", cwe_tag)
    user = (
        "Original code:\n```verilog\n" + original_code + "\n```\n\n"+
        "Verilator errors (trimmed):\n" + error_snippet[:1500] + "\n\n"+
        "Return the repaired code as a single Verilog code block."
    )
    try:
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.0,
            max_tokens=1200,
        )
        return extract_code_block(resp.choices[0].message.content or "")
    except Exception:
        return ""


# ---------------------- Agent core ----------------------

@dataclass
class SampleResult:
    model: str
    shots: int
    inputs: int
    pass_at_1: int
    needed_repair: int
    repaired_success: int
    attempts_sum: int


def process_gen_dir(gen_dir: Path, k_max: int, out_root: Path, verbose: bool = False) -> Tuple[List[Dict], SampleResult]:
    # Parse model/shots from dir name: gen_<model>_sX
    name = gen_dir.name  # e.g., gen_gpt4o_s2
    shots = 0
    mshots = re.search(r"_s(\d+)$", name)
    if mshots:
        shots = int(mshots.group(1))
    model = name.replace("gen_", "").rsplit("_s", 1)[0]

    gen_log = gen_dir / "gen.jsonl"
    if not gen_log.exists():
        return [], SampleResult(model, shots, 0, 0, 0, 0, 0)

    out_dir = out_root / f"repaired_{name}"
    out_dir.mkdir(parents=True, exist_ok=True)
    agent_log_path = out_dir / "agent_log.jsonl"
    agent_log = agent_log_path.open("w", encoding="utf-8")

    total = 0
    pass_at_1 = 0
    needed_repair = 0
    repaired_success = 0
    attempts_sum = 0

    with gen_log.open("r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            total += 1
            code_path = rec.get("code_path")
            cwe_target = rec.get("cwe_target") or ""
            raw_code = Path(code_path).read_text() if code_path and Path(code_path).exists() else (rec.get("raw") or "")

            # Ensure we have code text
            code_text = extract_code_block(raw_code) if "```" in raw_code else raw_code

            ok, err = run_verilator_lint(code_text)
            if ok:
                pass_at_1 += 1
                if verbose:
                    print(f"[PASS@1] {name} sample#{total}")
                agent_log.write(json.dumps({
                    "model": model,
                    "shots": shots,
                    "status": "pass_at_1",
                    "code_path": code_path,
                }) + "\n")
                continue

            # Attempt repairs
            needed_repair += 1
            attempts = 0
            repaired = False
            current = code_text
            while attempts < k_max and not repaired:
                attempts += 1
                repair = call_gpt4o_repair(current, err, cwe_target)
                if not repair:
                    if verbose:
                        print(f"[ATTEMPT {attempts}] No repair content returned; retrying...")
                    continue
                ok2, err2 = run_verilator_lint(repair)
                if ok2:
                    repaired = True
                    repaired_success += 1
                    if verbose:
                        print(f"[REPAIRED] {name} sample#{total} in {attempts} attempt(s)")
                    # Write repaired file
                    rp = out_dir / f"{model}_s{shots}_{total}_attempt{attempts}_repaired.v"
                    rp.write_text(repair)
                    agent_log.write(json.dumps({
                        "model": model,
                        "shots": shots,
                        "status": "repaired",
                        "attempts": attempts,
                        "repaired_path": str(rp),
                    }) + "\n")
                else:
                    # update current with best-effort repair (next loop)
                    current = repair
                    err = err2
            attempts_sum += (attempts if repaired else attempts)
            if not repaired:
                if verbose:
                    print(f"[FAILED] {name} sample#{total} after {attempts} attempt(s)")
                agent_log.write(json.dumps({
                    "model": model,
                    "shots": shots,
                    "status": "failed",
                    "attempts": attempts,
                }) + "\n")

    agent_log.close()
    return [], SampleResult(model, shots, total, pass_at_1, needed_repair, repaired_success, attempts_sum)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--k", type=int, default=3, help="Max repair attempts")
    ap.add_argument("--results-root", default="results", help="Path to results directory")
    ap.add_argument("--out-csv", default="results/table_E.csv")
    ap.add_argument("--verbose", action="store_true", default=False)
    args = ap.parse_args()

    results_root = Path(args.results_root)
    out_root = results_root / "validation_agent"
    out_root.mkdir(parents=True, exist_ok=True)

    # Find generator directories
    gen_dirs = sorted([p for p in (results_root).glob("gen_*_s*/") if (p/"gen.jsonl").exists()])

    rows: List[List[str]] = []
    header = [
        "Model","Shots","#Inputs","Compile Pass@1 (%)","Agent Repair Success@≤3 (%)","Final Compile Pass (%)","Mean Attempts"
    ]

    for gd in gen_dirs:
        if args.verbose:
            print(f"[PROCESS] {gd}")
        _, summ = process_gen_dir(gd, args.k, out_root, verbose=args.verbose)
        if summ.inputs == 0:
            continue
        # Compute metrics
        final_pass = summ.pass_at_1 + summ.repaired_success
        pass1_pct = (summ.pass_at_1 / summ.inputs) * 100.0
        repair_den = max(1, summ.needed_repair)
        repair_succ_pct = (summ.repaired_success / repair_den) * 100.0 if summ.needed_repair else 0.0
        final_pass_pct = (final_pass / summ.inputs) * 100.0
        mean_attempts = (summ.attempts_sum / repair_den) if summ.needed_repair else 0.0
        rows.append([
            summ.model,
            str(summ.shots),
            str(summ.inputs),
            f"{pass1_pct:.1f}",
            f"{repair_succ_pct:.1f}",
            f"{final_pass_pct:.1f}",
            f"{mean_attempts:.2f}",
        ])
        if args.verbose:
            print(f"[SUMMARY] model={summ.model} shots={summ.shots} inputs={summ.inputs} pass@1={pass1_pct:.1f}% repair_succ={repair_succ_pct:.1f}% final_pass={final_pass_pct:.1f}% attempts={mean_attempts:.2f}")

    # Write CSV
    csv_path = Path(args.out_csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"Wrote {csv_path}")


if __name__ == "__main__":
    main()
