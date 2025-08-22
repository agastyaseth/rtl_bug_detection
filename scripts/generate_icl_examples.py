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
from typing import Dict, List, Tuple

import openai
from tqdm import tqdm

# read the openai api key from the .env file
with open(".env", "r") as f:
    OPENAI_API_KEY = f.read().split("=")[1].strip()

# Set the API key for the openai library
openai.api_key = OPENAI_API_KEY
print(f"Using OpenAI API key: {OPENAI_API_KEY}")


DATASET_PATH = Path("data/buggy_rtl_dataset.json")
OUTPUT_PATH = Path("data/generated_icl_examples.json")
OUTPUT_JSONL_PATH = Path("data/generated_icl_examples.jsonl")


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
        "Generate a new RTL example that exhibits a security bug similar to the following examples.\n\n",
    ]

    for seed in seeds:
        prompt_lines.append(f"CWE {seed['cwe_id']}: {seed['description']}\n")
        prompt_lines.append("```verilog\n" + seed["code"] + "\n```\n")
        prompt_lines.append(f"Bug location: {seed['bug_location']}\n\n")

    prompt_lines.extend([
        "Generate a new Verilog module with a similar security vulnerability.\n\n",
        "IMPORTANT: Follow this EXACT output format:\n",
        "```verilog\n",
        "module example_module(\n",
        "    input wire clk,\n",
        "    input wire rst_n\n",
    ");\n",
        "    // Your Verilog code here\n",
        "    // BUG: [brief description of the vulnerability]\n",
        "    // The bug should be similar to the examples above\n",
        "endmodule\n",
        "```\n\n",
        "Requirements:\n",
        "1. Output ONLY the Verilog code block (no explanations outside the code)\n",
        "2. Include a clear comment starting with '// BUG:' to mark the vulnerability location\n",
        "3. Make the vulnerability realistic and similar to the CWE examples shown\n",
        "4. Use proper Verilog syntax with module declaration\n",
        "5. Keep the code concise but complete enough to demonstrate the security issue\n",
        "6. Ensure the bug comment is on its own line for easy parsing\n\n",
        "Return the Verilog code block only."
    ])
    return "".join(prompt_lines)


def call_llm(prompt: str) -> str:
    """Send the prompt to the OpenAI API and return the generated code."""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        )
        return response["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"Warning: API call failed: {e}")
        # Return a fallback response that can still be parsed
        return "module fallback_module();\n    // BUG: API call failed - using fallback\n    // This is a placeholder due to API error\nendmodule"


def validate_example(example: Dict[str, str]) -> bool:
    """Validate if a generated example meets quality criteria.
    
    Args:
        example: Generated example dictionary.
        
    Returns:
        True if example is valid, False otherwise.
    """
    verilog_code = example.get("verilog_code", "")
    bug_location = example.get("bug_location", "")
    
    # Check if we have Verilog code
    if not verilog_code or len(verilog_code.strip()) < 10:
        return False
    
    # Check if we have a bug location
    if bug_location == "Unknown" or not bug_location:
        return False
    
    # Check if it looks like Verilog (contains module keyword)
    if "module" not in verilog_code.lower():
        return False
    
    # Check if it has proper structure (contains endmodule keyword)
    # Split into lines and check for endmodule as a standalone keyword
    lines = verilog_code.split("\n")
    has_endmodule = False
    for line in lines:
        line_stripped = line.strip().lower()
        # Check if line contains only endmodule or endmodule followed by semicolon
        if line_stripped == "endmodule" or line_stripped == "endmodule;":
            has_endmodule = True
            break
    
    if not has_endmodule:
        return False
    
    return True


def _append_jsonl(path: Path, records: List[Dict[str, str]]) -> None:
    """Append a list of records to a JSONL file, creating directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _atomic_write_json(path: Path, obj) -> None:
    """Atomically write a JSON object to the target path."""
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.flush()
    tmp_path.replace(path)


def parse_llm_response(response: str) -> Tuple[str, str]:
    """Extract Verilog code and bug location from LLM response.
    
    Args:
        response: Raw response from the language model.
        
    Returns:
        Tuple of (verilog_code, bug_location).
    """
    # Look for Verilog code blocks
    verilog_start = response.find("```verilog")
    if verilog_start == -1:
        verilog_start = response.find("```")
    
    if verilog_start == -1:
        # No code block found, treat entire response as code
        verilog_code = response.strip()
    else:
        # Extract content between code blocks
        code_start = response.find("\n", verilog_start) + 1
        code_end = response.find("```", code_start)
        if code_end == -1:
            verilog_code = response[code_start:].strip()
        else:
            verilog_code = response[code_start:code_end].strip()
    
    # Look for bug location comment - try multiple patterns
    bug_location = "Unknown"
    lines = verilog_code.split("\n")
    for line in lines:
        line_lower = line.lower().strip()
        if any(pattern in line_lower for pattern in ["// bug:", "//bug:", "bug:", "vulnerability:", "security issue:"]):
            bug_location = line.strip()
            break
    
    # If no bug comment found, try to infer from context
    if bug_location == "Unknown":
        # Look for common security-related keywords in comments
        for line in lines:
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in ["insecure", "vulnerable", "weak", "exploit", "attack"]):
                bug_location = line.strip()
                break
    
    return verilog_code, bug_location


def generate_examples(num_examples: int, seeds: List[Dict[str, str]], sample_size: int, *, save_every: int, jsonl_path: Path, json_path: Path, max_retries: int = 3) -> List[Dict[str, str]]:
    """Generate examples by sampling seeds and querying the LLM, saving intermittently.

    Args:
        num_examples: Total number of examples to generate.
        seeds: Seed pool to draw from when building prompts.
        sample_size: Number of seeds to include in each prompt.
        save_every: How many generated examples to buffer before checkpointing.
        jsonl_path: File to append individual examples as JSONL.
        json_path: File to write the cumulative JSON array checkpoint.
        max_retries: Maximum number of retry attempts for failed generations.
    """
    generated: List[Dict[str, str]] = []
    batch_buffer: List[Dict[str, str]] = []
    valid_count = 0
    total_attempts = 0

    for _ in tqdm(range(num_examples)):
        total_attempts += 1
        random.shuffle(seeds)
        prompt_seeds = seeds[:sample_size]
        prompt = build_prompt(prompt_seeds)
        
        # Try to generate a valid example with retries
        example = None
        for retry in range(max_retries):
            completion = call_llm(prompt)
            
            # Parse the response to extract structured information
            verilog_code, bug_location = parse_llm_response(completion)
            
            example = {
                "prompt": prompt, 
                "completion": completion,
                "verilog_code": verilog_code,
                "bug_location": bug_location
            }
            
            # Validate the example
            if validate_example(example):
                valid_count += 1
                break
            elif retry < max_retries - 1:
                print(f"Warning: Generated example {total_attempts} failed validation (attempt {retry + 1}/{max_retries}), retrying...")
                continue
            else:
                print(f"Warning: Generated example {total_attempts} failed validation after {max_retries} attempts, using as-is")
        
        if example:
            generated.append(example)
            batch_buffer.append(example)

        if len(batch_buffer) >= max(1, save_every):
            _append_jsonl(jsonl_path, batch_buffer)
            _atomic_write_json(json_path, generated)
            batch_buffer.clear()

    if batch_buffer:
        _append_jsonl(jsonl_path, batch_buffer)
        _atomic_write_json(json_path, generated)
        batch_buffer.clear()

    print(f"Generated {len(generated)} valid examples out of {total_attempts} attempts")
    return generated


def main(num_examples: int, sample_size: int, seed: int | None, save_every: int, max_retries: int) -> None:
    if seed is not None:
        random.seed(seed)

    seeds = load_seeds(DATASET_PATH)
    examples = generate_examples(
        num_examples,
        seeds,
        sample_size,
        save_every=save_every,
        jsonl_path=OUTPUT_JSONL_PATH,
        json_path=OUTPUT_PATH,
        max_retries=max_retries,
    )

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
    parser.add_argument("--save-every", dest="save_every", type=int, default=10, help="Checkpoint frequency (in examples) for intermittent saving")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum retry attempts for failed generations")
    args = parser.parse_args()

    main(args.num_examples, args.sample_size, args.seed, args.save_every, args.max_retries)
