#!/usr/bin/env python3
"""Enrich the buggy RTL dataset with CWE information from the CSV file."""

import json
import csv
from pathlib import Path


def load_cwe_mapping(csv_path: Path) -> dict:
    """Load CWE mapping from CSV file."""
    cwe_mapping = {}
    
    with csv_path.open('r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            bug_id = int(row['Bug ID'])
            cwe_mapping[bug_id] = {
                'cwe_id': row['CWE-ID'],
                'description': row['Description']
            }
    
    return cwe_mapping


def enrich_dataset(dataset_path: Path, cwe_mapping: dict) -> list:
    """Enrich the dataset with CWE information."""
    with dataset_path.open('r', encoding='utf-8') as f:
        dataset = json.load(f)
    
    enriched_dataset = []
    
    for item in dataset:
        bug_id = item.get('bug_id')
        if bug_id in cwe_mapping:
            # Add CWE information
            item['cwe_id'] = cwe_mapping[bug_id]['cwe_id']
            item['description'] = cwe_mapping[bug_id]['description']
        else:
            # Set default values if no CWE mapping found
            item['cwe_id'] = 'Unknown'
            item['description'] = 'No description available'
        
        enriched_dataset.append(item)
    
    return enriched_dataset


def main():
    """Main function to enrich the dataset."""
    csv_path = Path("data/CWE-Buglist - Sheet1.csv")
    dataset_path = Path("data/buggy_rtl_dataset.json")
    output_path = Path("data/buggy_rtl_dataset_enriched.json")
    
    print("Loading CWE mapping from CSV...")
    cwe_mapping = load_cwe_mapping(csv_path)
    print(f"Loaded {len(cwe_mapping)} CWE mappings")
    
    print("Enriching dataset...")
    enriched_dataset = enrich_dataset(dataset_path, cwe_mapping)
    
    print("Saving enriched dataset...")
    with output_path.open('w', encoding='utf-8') as f:
        json.dump(enriched_dataset, f, indent=2)
    
    print(f"Enriched dataset saved to: {output_path}")
    
    # Show sample of enriched data
    print("\nSample enriched entries:")
    for i, item in enumerate(enriched_dataset[:3]):
        print(f"Bug ID {item['bug_id']}:")
        print(f"  CWE: {item['cwe_id']}")
        print(f"  Description: {item['description'][:100]}...")
        print()


if __name__ == "__main__":
    main() 