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
│   ├── generate_synthetic_dataset.py # Script to generate synthetic dataset
│   ├── prepare_fine_tuning.py # Script to prepare fine-tuning pipeline
│   └── run_baseline_tests.py  # Script to run baseline tests
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

- CWE detection rate
- CWE accuracy
- Line detection rate
- Concept coverage
- Combined score

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- CEP benchmark for providing the base RTL files
- OpenAI for GPT-4o
- Google for Gemma 3
- Meta for Llama 4
