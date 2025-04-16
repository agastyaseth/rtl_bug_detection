#!/usr/bin/env python3
"""
Synthetic Dataset Generator for Hardware CWE Bug Detection

This script generates a synthetic dataset of RTL files with hardware security vulnerabilities
using GPT-4o, to be used for fine-tuning Gemma 3 and Llama 4 models.
"""

import os
import json
import argparse
import csv
from datetime import datetime
import openai
from tqdm import tqdm
import time
import random

# Configuration
DATA_DIR = "../data"
OUTPUT_DIR = "../data/synthetic_dataset"
ORIGINAL_DATASET_PATH = os.path.join(DATA_DIR, "buggy_rtl_dataset.json")
CWE_LIST_PATH = os.path.join(DATA_DIR, "CWE-Buglist - Sheet1.csv")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_dataset(dataset_path):
    """Load the original dataset of buggy RTL files."""
    with open(dataset_path, 'r') as f:
        dataset = json.load(f)
    return dataset

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

def generate_prompt_for_synthetic_data(original_rtl, bug_id, cwe_info):
    """
    Generate a prompt for GPT-4o to create a synthetic RTL file with a similar bug.
    
    Args:
        original_rtl: The original RTL code with a bug
        bug_id: The ID of the bug
        cwe_info: Information about the CWE vulnerability
    
    Returns:
        A prompt for GPT-4o
    """
    cwe_id = cwe_info.get('cwe_id', '')
    description = cwe_info.get('description', '')
    justification = cwe_info.get('justification', '')
    
    prompt = f"""You are a hardware security expert who specializes in creating educational examples of vulnerable RTL code.

I need you to create a new, original Verilog RTL file that contains a hardware security vulnerability similar to the one in the example I'll provide. The vulnerability should be of the same type ({cwe_id}: {description}) but implemented in a different way and in a different context.

Here's information about the vulnerability:
- CWE ID: {cwe_id}
- Description: {description}
- Justification: {justification}

Here's an example of RTL code with this vulnerability:
```verilog
{original_rtl}
```

Please create a new, original RTL module that:
1. Implements a different hardware function (not the same as the example)
2. Contains a similar {cwe_id} vulnerability
3. Includes a comment that clearly marks where the vulnerability is (with "BUG: " prefix)
4. Is well-commented and realistic (as if it could be used in a real hardware design)
5. Is between 100-300 lines of code

The new RTL code should be completely different from the example but demonstrate the same type of security vulnerability.

Return ONLY the Verilog code without any additional explanation.
"""
    
    return prompt

def simulate_gpt4o_response(original_rtl, bug_id, cwe_info):
    """
    Simulate a GPT-4o response for generating synthetic data.
    
    In a real implementation, this would call the OpenAI API.
    """
    # This is just a placeholder for testing the framework
    cwe_id = cwe_info.get('cwe_id', '')
    description = cwe_info.get('description', '')
    
    # Create a simplified module name based on the CWE
    module_name = f"synthetic_{cwe_id.lower().replace('-', '_')}_example"
    
    # Generate a synthetic RTL file with a similar bug
    synthetic_rtl = f"""// Synthetic RTL example demonstrating {cwe_id}: {description}
// Generated for training purposes

module {module_name} (
    input wire clk,
    input wire rst_n,
    input wire [31:0] data_in,
    input wire data_valid,
    output reg [31:0] data_out,
    output reg data_ready
);

    // Internal registers
    reg [31:0] internal_state;
    reg [31:0] key_register;
    reg [3:0] state;
    
    // State definitions
    localparam IDLE = 4'b0000;
    localparam PROCESS = 4'b0001;
    localparam COMPUTE = 4'b0010;
    localparam OUTPUT = 4'b0011;
    
    // Process data based on state
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            data_out <= 32'h0;
            data_ready <= 1'b0;
            internal_state <= 32'h0;
            
            // BUG: {cwe_id} - {description}
            // The key_register is not cleared on reset, potentially exposing
            // sensitive information if the register is reused
            // key_register <= 32'h0;
        end
        else begin
            case (state)
                IDLE: begin
                    if (data_valid) begin
                        internal_state <= data_in;
                        key_register <= data_in ^ 32'hABCD1234; // Simple key derivation
                        state <= PROCESS;
                    end
                end
                
                PROCESS: begin
                    // Process data using the key
                    internal_state <= internal_state ^ key_register;
                    state <= COMPUTE;
                end
                
                COMPUTE: begin
                    // Additional computation
                    internal_state <= {{internal_state[15:0], internal_state[31:16]}};
                    state <= OUTPUT;
                end
                
                OUTPUT: begin
                    data_out <= internal_state;
                    data_ready <= 1'b1;
                    state <= IDLE;
                end
                
                default: state <= IDLE;
            endcase
        end
    end

endmodule
"""
    
    return synthetic_rtl

def generate_synthetic_dataset(original_dataset, cwe_dict, num_examples_per_cwe=5, simulate=True):
    """
    Generate a synthetic dataset of RTL files with hardware security vulnerabilities.
    
    Args:
        original_dataset: The original dataset of buggy RTL files
        cwe_dict: Dictionary of CWE information
        num_examples_per_cwe: Number of synthetic examples to generate per CWE
        simulate: Whether to simulate GPT-4o responses (for testing)
    
    Returns:
        A list of synthetic RTL files with bugs
    """
    synthetic_dataset = []
    
    # Group original examples by CWE ID
    cwe_examples = {}
    for item in original_dataset:
        bug_id = item['bug_id']
        if bug_id in cwe_dict:
            cwe_id = cwe_dict[bug_id]['cwe_id']
            if cwe_id not in cwe_examples:
                cwe_examples[cwe_id] = []
            cwe_examples[cwe_id].append(item)
    
    # Generate synthetic examples for each CWE
    for cwe_id, examples in tqdm(cwe_examples.items(), desc="Generating synthetic examples"):
        # Get a sample of original examples to use as seeds
        seed_examples = examples
        if len(examples) > num_examples_per_cwe:
            seed_examples = random.sample(examples, num_examples_per_cwe)
        
        for i, example in enumerate(seed_examples):
            bug_id = example['bug_id']
            original_rtl = example['verilog_content']
            
            # Generate synthetic examples
            for j in range(num_examples_per_cwe):
                # Generate a prompt for GPT-4o
                prompt = generate_prompt_for_synthetic_data(original_rtl, bug_id, cwe_dict[bug_id])
                
                # Get response from GPT-4o (simulated or real)
                if simulate:
                    synthetic_rtl = simulate_gpt4o_response(original_rtl, bug_id, cwe_dict[bug_id])
                else:
                    # This would call the actual GPT-4o API
                    # client = openai.OpenAI(api_key="YOUR_API_KEY")
                    # response = client.chat.completions.create(
                    #     model="gpt-4o",
                    #     messages=[
                    #         {"role": "system", "content": "You are a hardware security expert."},
                    #         {"role": "user", "content": prompt}
                    #     ],
                    #     temperature=0.7,
                    #     max_tokens=2000
                    # )
                    # synthetic_rtl = response.choices[0].message.content
                    synthetic_rtl = "Not implemented"
                
                # Create a synthetic example
                synthetic_example = {
                    'filename': f"synthetic_{cwe_id.replace('-', '_')}_{i}_{j}.v",
                    'bug_id': f"synthetic_{bug_id}_{i}_{j}",
                    'original_bug_id': bug_id,
                    'cwe_id': cwe_id,
                    'verilog_content': synthetic_rtl
                }
                
                synthetic_dataset.append(synthetic_example)
                
                # Save individual file
                file_path = os.path.join(OUTPUT_DIR, synthetic_example['filename'])
                with open(file_path, 'w') as f:
                    f.write(synthetic_rtl)
                
                # Add a small delay to avoid rate limiting in real implementation
                time.sleep(0.1)
    
    # Save the entire dataset
    dataset_path = os.path.join(OUTPUT_DIR, "synthetic_dataset.json")
    with open(dataset_path, 'w') as f:
        json.dump(synthetic_dataset, f, indent=2)
    
    return synthetic_dataset

def create_fine_tuning_dataset(original_dataset, synthetic_dataset, output_path):
    """
    Create a dataset for fine-tuning in the format expected by the models.
    
    Args:
        original_dataset: The original dataset of buggy RTL files
        synthetic_dataset: The synthetic dataset of buggy RTL files
        output_path: Path to save the fine-tuning dataset
    """
    fine_tuning_data = []
    
    # Process original dataset
    for item in original_dataset:
        example = {
            "input": item['verilog_content'],
            "output": f"This RTL code contains a hardware security vulnerability.\n\nVulnerability: {item.get('cwe_id', 'Unknown CWE')}\n\nExplanation: The code fails to properly handle sensitive information, which could lead to security issues."
        }
        fine_tuning_data.append(example)
    
    # Process synthetic dataset
    for item in synthetic_dataset:
        example = {
            "input": item['verilog_content'],
            "output": f"This RTL code contains a hardware security vulnerability.\n\nVulnerability: {item.get('cwe_id', 'Unknown CWE')}\n\nExplanation: The code contains a {item.get('cwe_id', 'Unknown CWE')} vulnerability that could be exploited by attackers."
        }
        fine_tuning_data.append(example)
    
    # Save the fine-tuning dataset
    with open(output_path, 'w') as f:
        json.dump(fine_tuning_data, f, indent=2)
    
    return fine_tuning_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic dataset for hardware CWE bug detection")
    parser.add_argument("--dataset", default=ORIGINAL_DATASET_PATH,
                        help="Path to the original buggy RTL dataset JSON file")
    parser.add_argument("--cwe-list", default=CWE_LIST_PATH,
                        help="Path to the CWE bug list CSV file")
    parser.add_argument("--num-examples", type=int, default=5,
                        help="Number of synthetic examples to generate per CWE")
    parser.add_argument("--simulate", action="store_true", default=True,
                        help="Simulate GPT-4o responses for testing")
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                        help="Directory to save the synthetic dataset")
    
    args = parser.parse_args()
    
    # Load original dataset and CWE list
    original_dataset = load_dataset(args.dataset)
    cwe_dict = load_cwe_list(args.cwe_list)
    
    # Generate synthetic dataset
    synthetic_dataset = generate_synthetic_dataset(
        original_dataset, cwe_dict, args.num_examples, args.simulate)
    
    # Create fine-tuning dataset
    fine_tuning_path = os.path.join(args.output_dir, "fine_tuning_dataset.json")
    fine_tuning_data = create_fine_tuning_dataset(
        original_dataset, synthetic_dataset, fine_tuning_path)
    
    print(f"Generated {len(synthetic_dataset)} synthetic examples")
    print(f"Created fine-tuning dataset with {len(fine_tuning_data)} examples")
    print(f"Saved to {args.output_dir}")
