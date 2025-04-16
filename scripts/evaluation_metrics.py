#!/usr/bin/env python3
"""
Evaluation Metrics for Hardware CWE Bug Detection

This script defines evaluation metrics for assessing LLM performance
on hardware security vulnerability detection tasks.
"""

import re
import json
from sklearn.metrics import precision_recall_fscore_support

def extract_cwe_id(response):
    """
    Extract CWE ID from model response using regex patterns.
    
    Returns the CWE ID if found, otherwise None.
    """
    # Pattern to match CWE-XXX format
    cwe_pattern = r'CWE-(\d+)'
    matches = re.findall(cwe_pattern, response)
    
    if matches:
        return f"CWE-{matches[0]}"
    return None

def extract_line_numbers(response):
    """
    Extract line numbers mentioned in the response.
    
    Returns a list of line numbers or line ranges.
    """
    # Pattern for line numbers (e.g., "line 123" or "lines 123-456")
    single_line_pattern = r'line\s+(\d+)'
    range_pattern = r'lines?\s+(\d+)\s*[-–—]\s*(\d+)'
    
    single_lines = re.findall(single_line_pattern, response.lower())
    ranges = re.findall(range_pattern, response.lower())
    
    result = [int(line) for line in single_lines]
    for start, end in ranges:
        result.extend(range(int(start), int(end) + 1))
    
    return sorted(set(result))

def evaluate_detailed(response, ground_truth):
    """
    Perform detailed evaluation of model response against ground truth.
    
    Args:
        response: The model's response text
        ground_truth: Dictionary containing ground truth information
            {
                'cwe_id': 'CWE-XXX',
                'vulnerable_lines': [line_numbers],
                'description': 'Description of vulnerability'
            }
    
    Returns:
        Dictionary with detailed evaluation metrics
    """
    # Extract CWE ID from response
    detected_cwe = extract_cwe_id(response)
    cwe_correct = detected_cwe == ground_truth['cwe_id'] if detected_cwe else False
    
    # Extract line numbers from response
    detected_lines = extract_line_numbers(response)
    
    # Check if any of the detected lines are in the ground truth vulnerable lines
    line_overlap = False
    if detected_lines and 'vulnerable_lines' in ground_truth:
        line_overlap = any(line in ground_truth['vulnerable_lines'] for line in detected_lines)
    
    # Check for key vulnerability concepts in the explanation
    key_concepts = []
    if 'key_concepts' in ground_truth:
        for concept in ground_truth['key_concepts']:
            if concept.lower() in response.lower():
                key_concepts.append(concept)
    
    # Calculate concept coverage
    concept_coverage = len(key_concepts) / len(ground_truth.get('key_concepts', [1])) if ground_truth.get('key_concepts') else 0
    
    return {
        'cwe_detected': detected_cwe is not None,
        'cwe_correct': cwe_correct,
        'detected_cwe': detected_cwe,
        'detected_lines': detected_lines,
        'line_overlap': line_overlap,
        'key_concepts_detected': key_concepts,
        'concept_coverage': concept_coverage
    }

def calculate_metrics(evaluations):
    """
    Calculate overall metrics from a list of detailed evaluations.
    
    Args:
        evaluations: List of evaluation dictionaries
    
    Returns:
        Dictionary with overall metrics
    """
    total = len(evaluations)
    cwe_detection_rate = sum(1 for e in evaluations if e['cwe_detected']) / total if total > 0 else 0
    cwe_accuracy = sum(1 for e in evaluations if e['cwe_correct']) / total if total > 0 else 0
    line_detection_rate = sum(1 for e in evaluations if e['line_overlap']) / total if total > 0 else 0
    avg_concept_coverage = sum(e['concept_coverage'] for e in evaluations) / total if total > 0 else 0
    
    # Calculate combined score (weighted average)
    combined_score = (0.4 * cwe_accuracy + 0.3 * line_detection_rate + 0.3 * avg_concept_coverage)
    
    return {
        'total_samples': total,
        'cwe_detection_rate': cwe_detection_rate,
        'cwe_accuracy': cwe_accuracy,
        'line_detection_rate': line_detection_rate,
        'avg_concept_coverage': avg_concept_coverage,
        'combined_score': combined_score
    }

def save_evaluation_results(results, output_file):
    """Save evaluation results to a JSON file."""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    # Example usage
    sample_response = """
    I've analyzed the code and found a vulnerability at lines 345-350.
    This is an instance of CWE-226 (Sensitive Information in Resource Not Removed Before Reuse).
    The code fails to clear sensitive registers before reuse, which could leak previous computation results.
    """
    
    sample_ground_truth = {
        'cwe_id': 'CWE-226',
        'vulnerable_lines': [345, 346, 347, 348, 349, 350],
        'key_concepts': ['clear registers', 'sensitive data', 'reuse']
    }
    
    evaluation = evaluate_detailed(sample_response, sample_ground_truth)
    print(json.dumps(evaluation, indent=2))
    
    metrics = calculate_metrics([evaluation])
    print(json.dumps(metrics, indent=2))
