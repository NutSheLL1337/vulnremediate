#!/usr/bin/env python3
"""Normalize SARIF outputs (semgrep/trivy) into a unified CSV for analysis.
Usage: python3 normalize_sarif.py --input semgrep.sarif --output results.csv
"""
import json
import argparse
import csv
from pathlib import Path

def parse_sarif(sarif_path):
    data = json.load(open(sarif_path, 'r', encoding='utf-8'))
    results = []
    runs = data.get('runs', [])
    for run in runs:
        tool_name = run.get('tool', {}).get('driver', {}).get('name', 'unknown')
        rules = {r.get('id'): r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
        for res in run.get('results', []):
            rule_id = res.get('ruleId') or (res.get('rule', {}).get('id') if res.get('rule') else None)
            message = res.get('message', {}).get('text', '')
            level = res.get('level', 'warning')
            locations = res.get('locations', [])
            file_path = ''
            start_line = ''
            if locations:
                phys = locations[0].get('physicalLocation', {})
                file_path = phys.get('artifactLocation', {}).get('uri', '')
                region = phys.get('region', {})
                start_line = region.get('startLine', '')
            cwe = ''
            # try to map rule -> properties -> tags or cwe
            rule = rules.get(rule_id, {})
            if rule:
                props = rule.get('properties', {})
                cwe = props.get('tags', [])
            results.append({
                'tool': tool_name,
                'rule_id': rule_id or '',
                'message': message,
                'level': level,
                'file': file_path,
                'start_line': start_line,
                'cwe': ';'.join(cwe) if isinstance(cwe, list) else cwe
            })
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', required=True, help='SARIF input file')
    parser.add_argument('--output', '-o', required=True, help='CSV output file')
    args = parser.parse_args()

    results = parse_sarif(args.input)
    keys = ['tool','rule_id','message','level','file','start_line','cwe']
    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"Wrote {len(results)} results to {args.output}")

if __name__ == '__main__':
    main()
