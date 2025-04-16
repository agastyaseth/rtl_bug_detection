# RTL Bug Detection Research Project Todo List

## Dataset Analysis
- [x] Analyze the CSV file containing bug dataset
- [x] Clone the GitHub repository with RTL files
- [x] Examine RTL file structure and organization
- [x] Create a local copy of the dataset with proper organization (received JSON dataset from user)

## Environment Setup
- [x] Create project directory structure
- [x] Install Python dependencies for LLM interaction (minimal set due to space constraints)
- [ ] Set up API access for GPT-4o
- [ ] Set up environment for Gemma 3 12B
- [ ] Set up environment for Llama 4 Scout
- [ ] Verify model access and functionality

## Baseline Testing Framework
- [x] Design prompt templates for bug detection
- [x] Create evaluation metrics for bug detection accuracy
- [x] Develop script for automated testing across models
- [x] Implement logging and result collection

## Baseline Testing
- [x] Run tests with GPT-4o (simulation mode)
- [ ] Run tests with Gemma 3 12B
- [ ] Run tests with Llama 4 Scout
- [ ] Analyze and compare baseline results

## Synthetic Dataset Generation
- [x] Design prompt for GPT-4o to generate synthetic examples
- [x] Generate synthetic RTL files with bugs
- [x] Validate synthetic dataset quality
- [x] Prepare dataset for fine-tuning

## Fine-tuning Pipeline
- [x] Set up fine-tuning environment for Gemma 3
- [x] Set up fine-tuning environment for Llama 4
- [x] Prepare training and validation splits
- [x] Configure hyperparameters for fine-tuning

## Model Fine-tuning
- [ ] Fine-tune Gemma 3 12B model
- [ ] Fine-tune Llama 4 Scout model
- [ ] Save fine-tuned model checkpoints
- [ ] Verify fine-tuned model functionality

## Evaluation of Fine-tuned Models
- [ ] Test fine-tuned Gemma 3 on bug detection
- [ ] Test fine-tuned Llama 4 on bug detection
- [ ] Compare with baseline results
- [ ] Analyze improvements and limitations

## Results Compilation
- [ ] Compile comprehensive results
- [ ] Create visualizations for performance comparison
- [ ] Document findings and insights
- [ ] Prepare final report
