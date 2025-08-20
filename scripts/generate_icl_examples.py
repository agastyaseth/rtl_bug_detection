import argparse
import csv
import json
import os
import random
import time
from typing import List, Dict

from openai import OpenAI
from pydantic import BaseModel
from typing import List
from tqdm import tqdm


class GeneratedExample(BaseModel):
    cwe_id: str
    description: str
    code: str
    bug_location: str


class ExampleBatch(BaseModel):
    examples: List[GeneratedExample]


def load_seed_examples(csv_path: str, limit: int | None = None) -> List[Dict[str, str]]:
    examples: List[Dict[str, str]] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            bug_id = row.get("Bug ID", "").strip()
            cwe_id = row.get("CWE-ID", "").strip()
            desc = row.get("Description", "").strip()
            if bug_id and cwe_id and desc:
                examples.append({"bug_id": bug_id, "cwe_id": cwe_id, "description": desc})
            if limit and len(examples) >= limit:
                break
    return examples


def build_prompt(sample_seeds: List[Dict[str, str]], batch_size: int, unique_cwes: List[str]) -> str:
    seed_text = "\n\n".join(
        f"CWE: {s['cwe_id']}\nDescription: {s['description']}" for s in sample_seeds
    )
    return (
        "You are an expert hardware security engineer.\n"
        "Generate {n} unique buggy RTL code examples in Verilog.\n"
        "For each example, select a CWE ID from the following list: {cwes}.\n"
        "Provide a short description of the bug and the Verilog code snippet.\n"
        "Also indicate the location of the bug within the snippet (line numbers or signal names).\n"
        "Return the results as JSON with a top-level key 'examples' mapping to a list of objects.\n"
        "Each object must have keys: 'cwe_id', 'description', 'code', 'bug_location'.\n"
        "Here are some seed examples for style:\n{seeds}\n"
    ).format(n=batch_size, cwes=", ".join(unique_cwes), seeds=seed_text)


def generate_examples(
    seeds: List[Dict[str, str]],
    total_examples: int,
    batch_size: int,
    model: str,
    output_path: str,
    sleep: float = 1.0,
) -> None:
    client = OpenAI()
    unique_cwes = sorted({s["cwe_id"] for s in seeds})
    results: List[Dict[str, str]] = []
    pbar = tqdm(total=total_examples, desc="Generating examples")
    while len(results) < total_examples:
        remaining = total_examples - len(results)
        cur_batch = min(batch_size, remaining)
        seed_samples = random.sample(seeds, min(len(seeds), 5))
        prompt = build_prompt(seed_samples, cur_batch, unique_cwes)
        try:
            response = client.responses.parse(
                model=model,
                input=[
                    {"role": "system", "content": "Return JSON matching the schema."},
                    {"role": "user", "content": prompt},
                ],
                text_format=ExampleBatch,
            )
            batch = response.output[0].content[0].parsed.examples
            results.extend(batch)
            pbar.update(len(batch))
        except Exception as e:
            print(f"Error during generation: {e}")
        time.sleep(sleep)
    pbar.close()
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([r.model_dump() for r in results[:total_examples]], f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Generate ICL examples using GPT-4o")
    parser.add_argument("--seed_csv", default="data/CWE-Buglist - Sheet1.csv")
    parser.add_argument("--output", default="data/generated_icl_examples.json")
    parser.add_argument("--num_examples", type=int, default=250)
    parser.add_argument("--batch_size", type=int, default=10)
    parser.add_argument("--model", default="gpt-4o")
    args = parser.parse_args()

    seeds = load_seed_examples(args.seed_csv)
    if not seeds:
        raise ValueError("No seed examples found. Check the CSV file.")
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    generate_examples(seeds, args.num_examples, args.batch_size, args.model, args.output)


if __name__ == "__main__":
    main()
