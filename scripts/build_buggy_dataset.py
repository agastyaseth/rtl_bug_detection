#!/usr/bin/env python3
"""Build a consolidated buggy RTL dataset from HDL cores and CWE CSV.

- Scans HDL cores recursively for files named *_bug<N>.v
- Extracts bug_id from the filename
- Looks up CWE-ID and Description from the CSV (by Bug ID)
- Writes a JSON array to data/buggy_rtl_dataset.json with entries:
  { bug_id, cwe_id, description, filename, verilog_content }
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List
import csv

BUG_FILE_PATTERN = re.compile(r"_bug(\d+)\.v$")


def load_cwe_mapping(csv_path: Path) -> Dict[int, Dict[str, str]]:
    mapping: Dict[int, Dict[str, str]] = {}
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                bug_id = int(row.get("Bug ID", "").strip())
            except Exception:
                continue
            mapping[bug_id] = {
                "cwe_id": (row.get("CWE-ID") or "").strip() or "Unknown",
                "description": (row.get("Description") or "").strip() or "No description available",
            }
    return mapping


def find_buggy_files(cores_dir: Path) -> List[Path]:
    return [p for p in cores_dir.rglob("*.v") if BUG_FILE_PATTERN.search(p.name)]


def build_dataset(cores_dir: Path, cwe_csv: Path) -> List[Dict[str, str]]:
    cwe_map = load_cwe_mapping(cwe_csv)
    dataset: List[Dict[str, str]] = []

    for vf in sorted(find_buggy_files(cores_dir)):
        m = BUG_FILE_PATTERN.search(vf.name)
        if not m:
            continue
        bug_id = int(m.group(1))
        meta = cwe_map.get(bug_id, {"cwe_id": "Unknown", "description": "No description available"})
        try:
            content = vf.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = vf.read_text(encoding="latin-1")
        item = {
            "bug_id": bug_id,
            "cwe_id": meta["cwe_id"],
            "description": meta["description"],
            "filename": str(vf),
            "verilog_content": content,
        }
        dataset.append(item)
    return dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Build buggy RTL dataset from HDL cores and CSV")
    parser.add_argument("--cores-dir", required=True, help="Path to HDL cores root directory (e.g., hdl_cores)")
    parser.add_argument("--csv", required=True, help="Path to CWE CSV (e.g., data/CWE-Buglist - Sheet1.csv)")
    parser.add_argument("--output", default="data/buggy_rtl_dataset.json", help="Output JSON path")
    args = parser.parse_args()

    cores_dir = Path(args.cores_dir)
    csv_path = Path(args.csv)
    output_path = Path(args.output)

    dataset = build_dataset(cores_dir, csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"Wrote {len(dataset)} buggy RTL items to {output_path}")


if __name__ == "__main__":
    main() 