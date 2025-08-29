# Hardware CWE Bug Detection in RTL Files using LLMs

This repository contains code and resources for detecting hardware Common Weakness Enumeration (CWE) bugs in RTL files using Large Language Models (LLMs).

## Project Overview

This research project focuses on detecting hardware security vulnerabilities (CWEs) in RTL files using various LLMs:

1. **Baseline Testing**: Evaluate GPT-4o, Gemma 3 12B, and Llama 4 Scout on their ability to detect hardware bugs in RTL files
2. **Fine-tuning**: Generate a synthetic dataset using GPT-4o and fine-tune Gemma 3 and Llama 4 models to improve detection capabilities

## Repository Structure

```
rtl_bug_detection/
├── data/                      # Dataset files
│   ├── buggy_rtl_dataset.json # Original dataset with buggy RTL files
│   ├── synthetic_dataset/     # Generated synthetic examples
│   └── CWE-Buglist - Sheet1.csv # List of CWE bugs with descriptions
├── models/                    # Model configurations and fine-tuning scripts
│   └── fine_tuning/           # Fine-tuning pipeline for Gemma 3 and Llama 4
├── results/                   # Results from baseline testing and evaluations
├── scripts/                   # Python scripts for various tasks
│   ├── baseline_framework.py  # Framework for baseline testing
│   ├── evaluation_metrics.py  # Metrics for evaluating model performance
│   ├── eval_from_preds.py     # Post-hoc evaluator for saved predictions
│   ├── generate_synthetic_dataset.py # Script to generate synthetic dataset
│   ├── prepare_fine_tuning.py # Script to prepare fine-tuning pipeline
│   ├── run_baseline_tests.py  # Script to run baseline tests
│   ├── build_prompts.py       # Build prompts (refs + examples + cleaned RTL)
│   ├── run_from_prompts.py    # Run models on prebuilt prompts, save preds/metrics
│   └── build_hard_bank.py     # Build hard-example ICL bank from prior runs
└── docs/                      # Documentation
```

## Getting Started

### Prerequisites

- Python 3.8+
- Required packages: `openai`, `transformers`, `torch`, `datasets`, `scikit-learn`, `tqdm`

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/hardware-cwe-detection.git
   cd hardware-cwe-detection
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Baseline Testing

To run baseline tests with GPT-4o (simulation mode):

```bash
python scripts/run_baseline_tests.py --dataset data/buggy_rtl_dataset.json --cwe-list "data/CWE-Buglist - Sheet1.csv" --simulate
```

For actual API-based testing (requires API keys):

```bash
python scripts/run_baseline_tests.py --dataset data/buggy_rtl_dataset.json --cwe-list "data/CWE-Buglist - Sheet1.csv"
```

### Generating Synthetic Dataset

To generate a synthetic dataset for fine-tuning:

```bash
python scripts/generate_synthetic_dataset.py --dataset data/buggy_rtl_dataset.json --cwe-list "data/CWE-Buglist - Sheet1.csv" --num-examples 5
```

### Experiment A — ICL Detector Baselines (0-shot and 2-shot)

This experiment evaluates zero-tune, in-context detection and localization on the RTL dataset.

- Inputs: CEP + HACK@DAC + synthetic (unified in `data/buggy_rtl_dataset.json`)
- Shots: {0, 2}
- Models: OpenAI GPT-4o, Anthropic Claude 3.5 Haiku, optional Together models
- Eval: Exact CWE, Loc@±10 (and optionally ±25), Precision, Recall, Pass@1, Latency

Step 1 — Build prompts (references + trimmed RTL, with optional examples)

```bash
# Zero-shot
python scripts/build_prompts.py \
  --dataset data/buggy_rtl_dataset.json \
  --cwe-list "data/CWE-Buglist - Sheet1.csv" \
  --shots 0 \
  --out data/prompts_full_s0_refs_trim.jsonl

# Two-shot
python scripts/build_prompts.py \
  --dataset data/buggy_rtl_dataset.json \
  --cwe-list "data/CWE-Buglist - Sheet1.csv" \
  --shots 2 \
  --out data/prompts_full_s2_refs_trim.jsonl
```

Step 2 — Run models from prompts

Environment:

```bash
export OPENAI_API_KEY=...         # GPT-4o
export ANTHROPIC_API_KEY=...      # Claude 3.5 Haiku
export TOGETHER_API_KEY=...       # Together (optional)
```

Commands:

```bash
# GPT-4o
python scripts/run_from_prompts.py \
  --prompts data/prompts_full_s0_refs_trim.jsonl \
  --model gpt4o \
  --out-preds results/preds_gpt4o_s0_trim.jsonl \
  --out-metrics results/metrics_gpt4o_s0_trim.json

python scripts/run_from_prompts.py \
  --prompts data/prompts_full_s2_refs_trim.jsonl \
  --model gpt4o \
  --out-preds results/preds_gpt4o_s2_trim.jsonl \
  --out-metrics results/metrics_gpt4o_s2_trim.json

# Claude
python scripts/run_from_prompts.py \
  --prompts data/prompts_full_s0_refs_trim.jsonl \
  --model claude-3.5-haiku \
  --out-preds results/preds_claude_s0_trim.jsonl \
  --out-metrics results/metrics_claude_s0_trim.json

python scripts/run_from_prompts.py \
  --prompts data/prompts_full_s2_refs_trim.jsonl \
  --model claude-3.5-haiku \
  --out-preds results/preds_claude_s2_trim.jsonl \
  --out-metrics results/metrics_claude_s2_trim.json

# Together (optional): meta-llama/Llama-3.3-70B-Instruct-Turbo-Free, openai/gpt-oss-20b
python scripts/run_from_prompts.py \
  --prompts data/prompts_full_s0_refs_trim.jsonl \
  --model together:meta-llama/Llama-3.3-70B-Instruct-Turbo-Free \
  --out-preds results/preds_llama70b_s0_trim_10.jsonl \
  --out-metrics results/metrics_llama70b_s0_trim_10.json \
  --limit 10

python scripts/run_from_prompts.py \
  --prompts data/prompts_full_s0_refs_trim.jsonl \
  --model together:openai/gpt-oss-20b \
  --out-preds results/preds_gptoss20b_s0_trim_10.jsonl \
  --out-metrics results/metrics_gptoss20b_s0_trim_10.json \
  --limit 10
```

Step 3 — Optional re-evaluation with different localization window

```bash
python scripts/eval_from_preds.py \
  --prompts data/prompts_full_s2_refs_trim.jsonl \
  --preds results/preds_gpt4o_s2_trim.jsonl \
  --window 25 \
  --out results/metrics_gpt4o_s2_win25.json
```

Metrics reported per run:
- Exact CWE accuracy (string match to gold `cwe_id`)
- Loc@±N (any predicted line within ±N of any gold vulnerable line)
- Precision/Recall on line localization (window-based)
- Pass@1 (valid JSON output)
- Latency (ms/sample)

### Experiment B — Adversarial Hard-Example Mining (R0→R1→R2)

Goal: Improve detector by seeding ICL with hard examples (failures from previous round).

Round 0 (R0): Run Experiment A and save predictions/metrics.

Build hard-example bank from R0 failures:
```bash
python scripts/build_hard_bank.py \
  --prompts data/prompts_full_s2_refs_trim.jsonl \
  --preds \
    results/preds_gpt4o_s0_trim.jsonl \
    results/preds_claude_s0_trim.jsonl \
    results/preds_gpt4o_s2_trim.jsonl \
    results/preds_claude_s2_trim.jsonl \
  --k-per-cwe 2 \
  --out results/hard_bank_R0.json
```

Round 1 (R1): Rebuild prompts using the hard bank for the in-context examples (class-balanced), then re-run models as in Experiment A. Round 2 (R2): Refresh the bank from R1 failures and repeat.

### Tables

Use the `results/*.json` metrics to assemble tables:
- A1 — One- vs Two-shot (Exact CWE, Loc@±10, Precision, Recall, Pass@1, Latency)
- A2 — Window matching effect (Loc@±10 vs Loc@±25)
- A3 — Prompt style ablation (plain vs hierarchical vs AST/CDFG)
- B1 — Adversarial ICL rounds (R0/R1/R2)
- B2 — Hard bank composition (coverage, entropy, source mix)

### Experiment C — ICL Generator Quality & Diversity

We generate new RTL bugs by prompting with hard exemplars (no SFT). We then lint (Verilator) and judge with an LLM for realism and CWE label consistency, and compute diversity entropy over token distributions.

Build prompts from hard bank:
```bash
python scripts/build_generator_prompts.py \
  --hard-bank results/hard_bank_R1.json \
  --dataset data/buggy_rtl_dataset.json \
  --cwe-list "data/CWE-Buglist - Sheet1.csv" \
  --shots 2 \
  --m-per-cwe 3 \
  --samples-per-cwe 2 \
  --out data/gen_prompts_cwe_s2.jsonl
```

Run generator:
```bash
python scripts/run_generator_icls.py \
  --prompts data/gen_prompts_cwe_s2.jsonl \
  --model gpt4o \
  --out-dir results/gen_gpt4o_s2
```

Results are in CSVs:
- Table C1: results/table_C1_all.csv (aggregated across shots/models)
- Table C2: results/table_C2.csv (coverage vs yield)

### Experiment D — Cross-Play (Gen→Det)

We feed generated examples into the detector with/without hard-ICL and report detector metrics and judge agreement.

Tables:
- Table D1: Cross-Play Matrix (detector accuracy/loc/precision/recall)
- Table D2: Judge Agreement & Justification Quality

### Experiment E — Validation Agent (Compile Assurance)

Ensures each generated RTL module compiles. If Verilator fails, the agent attempts up to K repairs using GPT‑4o with the Verilator error log, preserving the CWE tag and applying minimal edits. No functional equivalence checks are performed here; realism/consistency are handled in Experiment C.

Prerequisites:
- Install Verilator (macOS: `brew install verilator`, or `conda install -c conda-forge verilator`).
- Set `OPENAI_API_KEY`.

Run:
```bash
python scripts/validation_agent.py \
  --k 3 \
  --results-root results \
  --out-csv results/table_E.csv
```

Table E (results/table_E.csv):
- Columns: Model, Shots, #Inputs, Compile Pass@1 (%), Agent Repair Success@≤3 (%), Final Compile Pass (%), Mean Attempts

### Preparing Fine-tuning Pipeline

To prepare the fine-tuning pipeline:

```bash
python scripts/prepare_fine_tuning.py --dataset data/synthetic_dataset/fine_tuning_dataset.json --output-dir models/fine_tuning
```

### Fine-tuning Models

For fine-tuning Gemma 3 12B (requires GPU with 24GB+ VRAM):

```bash
cd models/fine_tuning
python fine_tune_gemma3.py
```

For fine-tuning Llama 4 Scout (requires GPU with 24GB+ VRAM):

```bash
cd models/fine_tuning
python fine_tune_llama4.py
```

## Fine-tuning Requirements

The fine-tuning process requires:

- GPU with at least 24GB VRAM (40GB+ recommended)
- PyTorch 2.0+
- Transformers 4.30+
- PEFT (Parameter-Efficient Fine-Tuning) library
- HuggingFace Datasets
- HuggingFace account with access to the models

## Dataset

The dataset consists of RTL files from the CEP benchmark with manually added hardware security vulnerabilities. Each file is annotated with:

- Bug ID
- CWE ID
- Description of the vulnerability
- Justification for the vulnerability

## Evaluation Metrics

The evaluation framework assesses models on:

- CWE accuracy (exact `cwe_id` match)
- Localization at ±N lines
- Precision/Recall on line localization (window based)
- Pass@1 (valid JSON output)
- Latency (ms/sample)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- CEP benchmark for providing the base RTL files
- OpenAI for GPT-4o
- Google for Gemma 3
- Meta for Llama 4
