#!/usr/bin/env python3
"""Generate ICL examples from buggy RTL dataset.

This script parses ``data/buggy_rtl_dataset.json`` to construct seed examples
for in-context learning prompts.  Each seed contains the following keys:

* ``cwe_id`` – identifier of the CWE vulnerability
* ``description`` – textual description of the vulnerability
* ``code`` – RTL code snippet demonstrating the bug
* ``bug_location`` – human readable location of the bug within the code

When generating prompts, seeds are shuffled so that each request receives a
representative mix of CWE examples.  The script expects an OpenAI compatible
API and writes the generated examples to
``data/generated_icl_examples.json``.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, List

import openai
from tqdm import tqdm

DATASET_PATH = Path("data/buggy_rtl_dataset.json")
OUTPUT_PATH = Path("data/generated_icl_examples.json")


def load_seeds(path: Path) -> List[Dict[str, str]]:
    """Parse the buggy RTL dataset and construct seed objects."""
    with path.open("r", encoding="utf-8") as f:
        raw_items = json.load(f)

    seeds = []
    for item in raw_items:
        seed = {
            "cwe_id": item.get("cwe_id"),
            "description": item.get("description"),
            "code": item.get("code") or item.get("verilog_content"),
            "bug_location": item.get("bug_location") or item.get("filename"),
        }
        seeds.append(seed)
    return seeds


def build_prompt(seeds: List[Dict[str, str]]) -> str:
    """Build a prompt for the language model using the provided seeds."""
    prompt_lines = [
        "You are an expert in hardware security.\n",
        "Generate a new RTL example that exhibits a security bug similar to the following examples.\n",
    ]

    for seed in seeds:
        prompt_lines.append(f"CWE {seed['cwe_id']}: {seed['description']}\n")
        prompt_lines.append("```verilog\n" + seed["code"] + "\n```\n")
        prompt_lines.append(f"Bug location: {seed['bug_location']}\n\n")

    prompt_lines.append(
        "Return only the new Verilog code with a clear comment marking the BUG location."
    )
    return "".join(prompt_lines)


def call_llm(prompt: str) -> str:
    """Send the prompt to the OpenAI API and return the generated code."""
    response = openai.ChatCompletion.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return response["choices"][0]["message"]["content"]


def generate_examples(num_examples: int, seeds: List[Dict[str, str]], sample_size: int) -> List[Dict[str, str]]:
    """Generate examples by repeatedly sampling seeds and querying the LLM."""
    generated = []
    for _ in tqdm(range(num_examples)):
        random.shuffle(seeds)
        prompt_seeds = seeds[:sample_size]
        prompt = build_prompt(prompt_seeds)
        completion = call_llm(prompt)
        generated.append({"prompt": prompt, "completion": completion})
    return generated


def main(num_examples: int, sample_size: int, seed: int | None) -> None:
    if seed is not None:
        random.seed(seed)

    seeds = load_seeds(DATASET_PATH)
    examples = generate_examples(num_examples, seeds, sample_size)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(examples, f, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num_examples", type=int, default=250, help="Number of examples to generate")
    parser.add_argument(
        "--sample_size",
        type=int,
        default=3,
        help="Number of seed examples to include in each prompt",
    )
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    args = parser.parse_args()

    main(args.num_examples, args.sample_size, args.seed)
