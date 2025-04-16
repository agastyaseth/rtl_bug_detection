#!/usr/bin/env python3
"""
Baseline Testing Framework for Hardware CWE Bug Detection in RTL Files

This script provides a framework for testing LLM models (GPT-4o, Gemma 3 12B, Llama 4 Scout)
on their ability to detect hardware security vulnerabilities (CWEs) in RTL files.
"""

import os
import json
import time
import argparse
import csv
from datetime import datetime
import openai
import requests
from tqdm import tqdm

# Configuration
RESULTS_DIR = "../results"
DATA_DIR = "../data"
MODELS = ["gpt4o", "gemma3-12b", "llama4-scout"]

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

# Load the buggy RTL dataset
def load_dataset(dataset_path):
    """Load the dataset of buggy RTL files."""
    with open(dataset_path, 'r') as f:
        dataset = json.load(f)
    return dataset

# Load the CWE bug list for reference
def load_cwe_list(cwe_list_path):
    """Load the CWE bug list for reference."""
    cwe_dict = {}
    with open(cwe_list_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Bug ID'] and row['CWE-ID']:
                cwe_dict[int(row['Bug ID'])] = {
                    'cwe_id': row['CWE-ID'],
                    'description': row['Description'],
                    'justification': row['Justification']
                }
    return cwe_dict

# Prompt templates for different models
PROMPT_TEMPLATES = {
    "gpt4o": """You are a hardware security expert specializing in identifying Common Weakness Enumeration (CWE) vulnerabilities in RTL code.

I'll provide you with a Verilog RTL file that contains a hardware security vulnerability. Your task is to:

1. Identify the specific CWE vulnerability in the code
2. Specify the exact line numbers or code sections where the vulnerability exists
3. Explain why this is a vulnerability and how it could be exploited
4. Provide the specific CWE ID (e.g., CWE-1234) that best matches this vulnerability

Here is the RTL code to analyze:

```verilog
{rtl_code}
```

Respond with a structured analysis that clearly identifies the vulnerability, its location, and the corresponding CWE ID.
""",

    "gemma3-12b": """As a hardware security expert, analyze this Verilog RTL code for security vulnerabilities:

```verilog
{rtl_code}
```

Identify:
1. The specific hardware security vulnerability (CWE)
2. The exact line numbers containing the vulnerability
3. Why this is a security issue
4. The specific CWE ID number

Format your response as a structured analysis.
""",

    "llama4-scout": """Analyze the following Verilog RTL code for hardware security vulnerabilities:

```verilog
{rtl_code}
```

Your task:
1. Find any hardware security vulnerability in the code
2. Identify the exact line numbers where the vulnerability exists
3. Explain why it's a vulnerability and potential exploitation
4. Provide the specific CWE ID that matches this vulnerability

Present your findings in a clear, structured format.
"""
}

# Function to call GPT-4o API
def query_gpt4o(rtl_code):
    """Query the GPT-4o API with the RTL code."""
    try:
        # Replace with your actual API key mechanism
        client = openai.OpenAI(api_key="YOUR_API_KEY")
        
        prompt = PROMPT_TEMPLATES["gpt4o"].format(rtl_code=rtl_code)
        
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a hardware security expert specializing in identifying CWE vulnerabilities in RTL code."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=2000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        print(f"Error querying GPT-4o: {e}")
        return f"Error: {str(e)}"

# Placeholder functions for other models
# These would be implemented based on the specific APIs or local model access
def query_gemma3(rtl_code):
    """Query the Gemma 3 12B model with the RTL code."""
    # This would be implemented based on how you access Gemma 3
    prompt = PROMPT_TEMPLATES["gemma3-12b"].format(rtl_code=rtl_code)
    # Placeholder for actual implementation
    return "Gemma 3 12B analysis would appear here"

def query_llama4(rtl_code):
    """Query the Llama 4 Scout model with the RTL code."""
    # This would be implemented based on how you access Llama 4
    prompt = PROMPT_TEMPLATES["llama4-scout"].format(rtl_code=rtl_code)
    # Placeholder for actual implementation
    return "Llama 4 Scout analysis would appear here"

# Function to evaluate model responses
def evaluate_response(response, bug_id, cwe_dict):
    """
    Evaluate the model's response against the ground truth.
    
    Returns a dictionary with evaluation metrics.
    """
    # Get ground truth CWE ID
    ground_truth_cwe = cwe_dict.get(bug_id, {}).get('cwe_id', '')
    
    # Check if the response contains the correct CWE ID
    cwe_detected = ground_truth_cwe in response
    
    # Simple evaluation metrics
    evaluation = {
        'bug_id': bug_id,
        'ground_truth_cwe': ground_truth_cwe,
        'cwe_detected': cwe_detected,
        'response': response
    }
    
    return evaluation

# Main function to run the baseline tests
def run_baseline_tests(dataset, cwe_dict, models=None):
    """Run baseline tests on the specified models."""
    if models is None:
        models = MODELS
    
    results = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for model in models:
        print(f"Testing model: {model}")
        model_results = []
        
        for item in tqdm(dataset, desc=f"Processing with {model}"):
            bug_id = item['bug_id']
            rtl_code = item['verilog_content']
            
            # Query the appropriate model
            if model == "gpt4o":
                response = query_gpt4o(rtl_code)
            elif model == "gemma3-12b":
                response = query_gemma3(rtl_code)
            elif model == "llama4-scout":
                response = query_llama4(rtl_code)
            else:
                raise ValueError(f"Unknown model: {model}")
            
            # Evaluate the response
            evaluation = evaluate_response(response, bug_id, cwe_dict)
            model_results.append(evaluation)
            
            # Add a small delay to avoid rate limiting
            time.sleep(1)
        
        # Calculate overall metrics
        correct_detections = sum(1 for result in model_results if result['cwe_detected'])
        total_samples = len(model_results)
        accuracy = correct_detections / total_samples if total_samples > 0 else 0
        
        # Store results
        results[model] = {
            'accuracy': accuracy,
            'correct_detections': correct_detections,
            'total_samples': total_samples,
            'detailed_results': model_results
        }
        
        # Save results to file
        results_file = os.path.join(RESULTS_DIR, f"{model}_results_{timestamp}.json")
        with open(results_file, 'w') as f:
            json.dump(results[model], f, indent=2)
        
        print(f"{model} accuracy: {accuracy:.2f} ({correct_detections}/{total_samples})")
    
    # Save overall results
    overall_results = {model: {
        'accuracy': results[model]['accuracy'],
        'correct_detections': results[model]['correct_detections'],
        'total_samples': results[model]['total_samples']
    } for model in results}
    
    overall_file = os.path.join(RESULTS_DIR, f"overall_results_{timestamp}.json")
    with open(overall_file, 'w') as f:
        json.dump(overall_results, f, indent=2)
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run baseline tests for hardware CWE bug detection")
    parser.add_argument("--dataset", default=os.path.join(DATA_DIR, "buggy_rtl_dataset.json"),
                        help="Path to the buggy RTL dataset JSON file")
    parser.add_argument("--cwe-list", default=os.path.join(DATA_DIR, "CWE-Buglist - Sheet1.csv"),
                        help="Path to the CWE bug list CSV file")
    parser.add_argument("--models", nargs="+", choices=MODELS, default=MODELS,
                        help="Models to test")
    
    args = parser.parse_args()
    
    # Load dataset and CWE list
    dataset = load_dataset(args.dataset)
    cwe_dict = load_cwe_list(args.cwe_list)
    
    # Run baseline tests
    results = run_baseline_tests(dataset, cwe_dict, args.models)
    
    print("Baseline testing completed.")
