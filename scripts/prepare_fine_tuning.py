#!/usr/bin/env python3
"""
Fine-tuning Pipeline for Gemma 3 and Llama 4 Models

This script sets up the fine-tuning pipeline for Gemma 3 12B and Llama 4 Scout models
on the hardware bug detection task using the synthetic dataset.
"""

import os
import json
import argparse
import torch
from datetime import datetime
from tqdm import tqdm

# Configuration
DATA_DIR = "../data"
MODELS_DIR = "../models"
SYNTHETIC_DATASET_DIR = os.path.join(DATA_DIR, "synthetic_dataset")
FINE_TUNING_DATASET = os.path.join(SYNTHETIC_DATASET_DIR, "fine_tuning_dataset.json")

# Ensure models directory exists
os.makedirs(MODELS_DIR, exist_ok=True)

def check_gpu_availability():
    """Check if GPU is available for training."""
    if torch.cuda.is_available():
        device_count = torch.cuda.device_count()
        device_names = [torch.cuda.get_device_name(i) for i in range(device_count)]
        print(f"Found {device_count} GPU(s): {', '.join(device_names)}")
        return True
    else:
        print("No GPU available, will use CPU (not recommended for fine-tuning large models)")
        return False

def load_fine_tuning_dataset(dataset_path):
    """Load the fine-tuning dataset."""
    with open(dataset_path, 'r') as f:
        dataset = json.load(f)
    return dataset

def prepare_gemma3_fine_tuning(dataset, output_dir):
    """
    Prepare the fine-tuning pipeline for Gemma 3 12B.
    
    Args:
        dataset: The fine-tuning dataset
        output_dir: Directory to save the fine-tuning configuration
    """
    # Create configuration for Gemma 3 fine-tuning
    config = {
        "model_name": "google/gemma-3-12b",
        "training_config": {
            "per_device_train_batch_size": 1,
            "gradient_accumulation_steps": 4,
            "learning_rate": 2e-5,
            "num_train_epochs": 3,
            "lr_scheduler_type": "cosine",
            "warmup_ratio": 0.03,
            "weight_decay": 0.01,
            "fp16": True,
            "logging_steps": 10,
            "save_steps": 100,
            "eval_steps": 100,
            "save_total_limit": 3,
            "evaluation_strategy": "steps",
            "load_best_model_at_end": True,
            "report_to": "tensorboard"
        },
        "lora_config": {
            "r": 16,
            "lora_alpha": 32,
            "lora_dropout": 0.05,
            "bias": "none",
            "task_type": "CAUSAL_LM",
            "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj"]
        }
    }
    
    # Save configuration
    os.makedirs(output_dir, exist_ok=True)
    config_path = os.path.join(output_dir, "gemma3_fine_tuning_config.json")
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Create fine-tuning script
    script_content = """#!/usr/bin/env python3
# Fine-tuning script for Gemma 3 12B

import os
import json
import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling
)
from peft import LoraConfig, get_peft_model
from datasets import Dataset

# Load configuration
with open("gemma3_fine_tuning_config.json", 'r') as f:
    config = json.load(f)

# Load dataset
with open("fine_tuning_dataset.json", 'r') as f:
    data = json.load(f)

# Convert to HuggingFace dataset
dataset = Dataset.from_dict({
    "input": [item["input"] for item in data],
    "output": [item["output"] for item in data]
})

# Split dataset
dataset = dataset.train_test_split(test_size=0.1)

# Load model and tokenizer
model_name = config["model_name"]
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    torch_dtype=torch.float16,
    device_map="auto"
)

# Prepare LoRA configuration
lora_config = LoraConfig(**config["lora_config"])
model = get_peft_model(model, lora_config)

# Tokenize dataset
def tokenize_function(examples):
    prompts = []
    for i in range(len(examples["input"])):
        prompt = f"Analyze this RTL code for hardware security vulnerabilities:\\n\\n{examples['input'][i]}\\n\\nIdentify any vulnerabilities:"
        response = examples["output"][i]
        prompts.append(f"{prompt} {response}</s>")
    
    return tokenizer(
        prompts,
        truncation=True,
        max_length=2048,
        padding="max_length"
    )

tokenized_dataset = dataset.map(tokenize_function, batched=True)

# Set up training arguments
training_args = TrainingArguments(
    output_dir="./gemma3_fine_tuned",
    **config["training_config"]
)

# Create trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset["train"],
    eval_dataset=tokenized_dataset["test"],
    data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
)

# Train model
trainer.train()

# Save fine-tuned model
model.save_pretrained("./gemma3_fine_tuned")
tokenizer.save_pretrained("./gemma3_fine_tuned")

print("Fine-tuning completed successfully!")
"""
    
    script_path = os.path.join(output_dir, "fine_tune_gemma3.py")
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    # Make script executable
    os.chmod(script_path, 0o755)
    
    return config_path, script_path

def prepare_llama4_fine_tuning(dataset, output_dir):
    """
    Prepare the fine-tuning pipeline for Llama 4 Scout.
    
    Args:
        dataset: The fine-tuning dataset
        output_dir: Directory to save the fine-tuning configuration
    """
    # Create configuration for Llama 4 fine-tuning
    config = {
        "model_name": "meta-llama/Meta-Llama-4-Scout",
        "training_config": {
            "per_device_train_batch_size": 1,
            "gradient_accumulation_steps": 4,
            "learning_rate": 2e-5,
            "num_train_epochs": 3,
            "lr_scheduler_type": "cosine",
            "warmup_ratio": 0.03,
            "weight_decay": 0.01,
            "fp16": True,
            "logging_steps": 10,
            "save_steps": 100,
            "eval_steps": 100,
            "save_total_limit": 3,
            "evaluation_strategy": "steps",
            "load_best_model_at_end": True,
            "report_to": "tensorboard"
        },
        "lora_config": {
            "r": 16,
            "lora_alpha": 32,
            "lora_dropout": 0.05,
            "bias": "none",
            "task_type": "CAUSAL_LM",
            "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj"]
        }
    }
    
    # Save configuration
    os.makedirs(output_dir, exist_ok=True)
    config_path = os.path.join(output_dir, "llama4_fine_tuning_config.json")
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Create fine-tuning script
    script_content = """#!/usr/bin/env python3
# Fine-tuning script for Llama 4 Scout

import os
import json
import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling
)
from peft import LoraConfig, get_peft_model
from datasets import Dataset

# Load configuration
with open("llama4_fine_tuning_config.json", 'r') as f:
    config = json.load(f)

# Load dataset
with open("fine_tuning_dataset.json", 'r') as f:
    data = json.load(f)

# Convert to HuggingFace dataset
dataset = Dataset.from_dict({
    "input": [item["input"] for item in data],
    "output": [item["output"] for item in data]
})

# Split dataset
dataset = dataset.train_test_split(test_size=0.1)

# Load model and tokenizer
model_name = config["model_name"]
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    torch_dtype=torch.float16,
    device_map="auto"
)

# Prepare LoRA configuration
lora_config = LoraConfig(**config["lora_config"])
model = get_peft_model(model, lora_config)

# Tokenize dataset
def tokenize_function(examples):
    prompts = []
    for i in range(len(examples["input"])):
        prompt = f"Analyze this RTL code for hardware security vulnerabilities:\\n\\n{examples['input'][i]}\\n\\nIdentify any vulnerabilities:"
        response = examples["output"][i]
        prompts.append(f"{prompt} {response}</s>")
    
    return tokenizer(
        prompts,
        truncation=True,
        max_length=2048,
        padding="max_length"
    )

tokenized_dataset = dataset.map(tokenize_function, batched=True)

# Set up training arguments
training_args = TrainingArguments(
    output_dir="./llama4_fine_tuned",
    **config["training_config"]
)

# Create trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset["train"],
    eval_dataset=tokenized_dataset["test"],
    data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
)

# Train model
trainer.train()

# Save fine-tuned model
model.save_pretrained("./llama4_fine_tuned")
tokenizer.save_pretrained("./llama4_fine_tuned")

print("Fine-tuning completed successfully!")
"""
    
    script_path = os.path.join(output_dir, "fine_tune_llama4.py")
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    # Make script executable
    os.chmod(script_path, 0o755)
    
    return config_path, script_path

def create_fine_tuning_readme(output_dir):
    """Create a README file with instructions for fine-tuning."""
    readme_content = """# Fine-tuning Instructions for Hardware CWE Bug Detection

This directory contains the fine-tuning pipeline for Gemma 3 12B and Llama 4 Scout models
on the hardware bug detection task.

## Prerequisites

- Python 3.8+
- PyTorch 2.0+
- Transformers 4.30+
- PEFT (Parameter-Efficient Fine-Tuning) library
- HuggingFace Datasets
- At least 24GB GPU VRAM for fine-tuning (preferably 40GB+ for optimal performance)
- HuggingFace account with access to the models

## Setup

1. Install required packages:
   ```
   pip install torch transformers peft datasets accelerate
   ```

2. Log in to HuggingFace:
   ```
   huggingface-cli login
   ```

## Fine-tuning Gemma 3 12B

1. Run the fine-tuning script:
   ```
   python fine_tune_gemma3.py
   ```

2. The fine-tuned model will be saved in the `gemma3_fine_tuned` directory.

## Fine-tuning Llama 4 Scout

1. Run the fine-tuning script:
   ```
   python fine_tune_llama4.py
   ```

2. The fine-tuned model will be saved in the `llama4_fine_tuned` directory.

## Notes

- The fine-tuning process uses LoRA (Low-Rank Adaptation) to efficiently fine-tune the models.
- The configuration parameters can be adjusted in the respective JSON files.
- For production use, consider increasing the number of training epochs and dataset size.
- Monitor the training process using TensorBoard:
  ```
  tensorboard --logdir=./gemma3_fine_tuned
  ```

## Evaluation

After fine-tuning, evaluate the models using the evaluation script:
```
python ../scripts/run_baseline_tests.py --models gemma3-12b llama4-scout
```
"""
    
    readme_path = os.path.join(output_dir, "README.md")
    with open(readme_path, 'w') as f:
        f.write(readme_content)
    
    return readme_path

def create_requirements_file(output_dir):
    """Create a requirements file for fine-tuning."""
    requirements_content = """torch>=2.0.0
transformers>=4.30.0
peft>=0.4.0
datasets>=2.12.0
accelerate>=0.20.0
tensorboard>=2.12.0
huggingface-hub>=0.16.0
scikit-learn>=1.2.0
tqdm>=4.65.0
"""
    
    requirements_path = os.path.join(output_dir, "requirements.txt")
    with open(requirements_path, 'w') as f:
        f.write(requirements_content)
    
    return requirements_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare fine-tuning pipeline for Gemma 3 and Llama 4 models")
    parser.add_argument("--dataset", default=FINE_TUNING_DATASET,
                        help="Path to the fine-tuning dataset JSON file")
    parser.add_argument("--output-dir", default=os.path.join(MODELS_DIR, "fine_tuning"),
                        help="Directory to save the fine-tuning pipeline")
    
    args = parser.parse_args()
    
    # Check GPU availability
    has_gpu = check_gpu_availability()
    
    # Load fine-tuning dataset
    dataset = load_fine_tuning_dataset(args.dataset)
    print(f"Loaded fine-tuning dataset with {len(dataset)} examples")
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Copy fine-tuning dataset to output directory
    output_dataset_path = os.path.join(args.output_dir, "fine_tuning_dataset.json")
    with open(output_dataset_path, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    # Prepare fine-tuning pipeline for Gemma 3
    print("Preparing fine-tuning pipeline for Gemma 3 12B...")
    gemma3_config_path, gemma3_script_path = prepare_gemma3_fine_tuning(dataset, args.output_dir)
    print(f"Gemma 3 fine-tuning configuration saved to: {gemma3_config_path}")
    print(f"Gemma 3 fine-tuning script saved to: {gemma3_script_path}")
    
    # Prepare fine-tuning pipeline for Llama 4
    print("Preparing fine-tuning pipeline for Llama 4 Scout...")
    llama4_config_path, llama4_script_path = prepare_llama4_fine_tuning(dataset, args.output_dir)
    print(f"Llama 4 fine-tuning configuration saved to: {llama4_config_path}")
    print(f"Llama 4 fine-tuning script saved to: {llama4_script_path}")
    
    # Create README and requirements file
    readme_path = create_fine_tuning_readme(args.output_dir)
    requirements_path = create_requirements_file(args.output_dir)
    print(f"README saved to: {readme_path}")
    print(f"Requirements file saved to: {requirements_path}")
    
    print("\nFine-tuning pipeline preparation completed!")
    
    if not has_gpu:
        print("\nWARNING: No GPU detected. Fine-tuning large language models requires significant GPU resources.")
        print("Consider using a machine with at least one high-memory GPU (24GB+ VRAM) for fine-tuning.")
