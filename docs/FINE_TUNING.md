# Fine-tuning Instructions

This document provides detailed instructions for fine-tuning the Gemma 3 12B and Llama 4 Scout models on the hardware bug detection task.

## Prerequisites

Before starting the fine-tuning process, ensure you have:

1. **Hardware Requirements**:
   - GPU with at least 24GB VRAM (40GB+ recommended)
   - 16GB+ system RAM
   - 100GB+ free disk space

2. **Software Requirements**:
   - Python 3.8+
   - CUDA 11.8+ and cuDNN
   - All packages listed in `requirements.txt`

3. **Model Access**:
   - HuggingFace account with access to Gemma 3 and Llama 4 models
   - API tokens configured

## Environment Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Login to HuggingFace:
   ```bash
   huggingface-cli login
   ```

## Fine-tuning Process

### Gemma 3 12B

1. Navigate to the fine-tuning directory:
   ```bash
   cd models/fine_tuning
   ```

2. Review and adjust hyperparameters in `gemma3_fine_tuning_config.json` if needed.

3. Run the fine-tuning script:
   ```bash
   python fine_tune_gemma3.py
   ```

4. Monitor training progress:
   ```bash
   tensorboard --logdir=./gemma3_fine_tuned
   ```

### Llama 4 Scout

1. Navigate to the fine-tuning directory:
   ```bash
   cd models/fine_tuning
   ```

2. Review and adjust hyperparameters in `llama4_fine_tuning_config.json` if needed.

3. Run the fine-tuning script:
   ```bash
   python fine_tune_llama4.py
   ```

4. Monitor training progress:
   ```bash
   tensorboard --logdir=./llama4_fine_tuned
   ```

## Fine-tuning Parameters

The fine-tuning process uses Parameter-Efficient Fine-Tuning (PEFT) with LoRA (Low-Rank Adaptation) to efficiently fine-tune large models. Key parameters include:

- **LoRA rank (r)**: Controls the rank of the low-rank matrices (default: 16)
- **LoRA alpha**: Scaling factor for the LoRA updates (default: 32)
- **Learning rate**: Controls the step size during optimization (default: 2e-5)
- **Batch size**: Number of examples processed in each training step (default: 1)
- **Gradient accumulation steps**: Number of steps to accumulate gradients (default: 4)
- **Training epochs**: Number of passes through the training dataset (default: 3)

## Troubleshooting

### Out of Memory Errors

If you encounter CUDA out of memory errors:

1. Reduce batch size or gradient accumulation steps
2. Use a smaller LoRA rank
3. Enable gradient checkpointing
4. Use CPU offloading for optimizer states

### Training Instability

If training is unstable:

1. Reduce learning rate
2. Increase warmup ratio
3. Try different optimizer (AdamW, Lion)
4. Check for NaN values in gradients

## Evaluating Fine-tuned Models

After fine-tuning, evaluate the models using:

```bash
python scripts/run_baseline_tests.py --models gemma3-12b llama4-scout --dataset data/buggy_rtl_dataset.json --cwe-list "data/CWE-Buglist - Sheet1.csv"
```

This will generate evaluation metrics for both fine-tuned models and compare them with the baseline results.
