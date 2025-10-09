#!/usr/bin/env python3
"""
Normalize SARIF outputs (semgrep/trivy/others) into a unified CSV for analysis.
Usage: python3 scripts/normalize_sarif.py --input artifacts/before_fix_semgrep.sarif --output results/semgrep_normalized.csv
"""
import json
import argparse
import csv
from pathlib import Path
import sys

def extract_semgrep_result(res, rules_map):
    rule_id = res.get('ruleId') or (res.get('rule', {}).get('id') if res.get('rule') else '')
    # message may be dict or string
    if isinstance(res.get('message'), dict):
        message = res['message'].get('text','')
    else:
        message = str(res.get('message',''))
    level = res.get('level', res.get('properties', {}).get('severity', '') or 'warning')
    file_path = ''
    start_line = ''
    locations = res.get('locations', []) or []
    if locations:
        phys = locations[0].get('physicalLocation', {}) or {}
        file_path = phys.get('artifactLocation', {}).get('uri', '') or ''
        region = phys.get('region', {}) or {}
        start_line = region.get('startLine', '') or region.get('startColumn', '')
    cwe = ''
    rule = rules_map.get(rule_id, {}) if rules_map else {}
    if rule:
        props = rule.get('properties', {}) or {}
        tags = props.get('tags', [])
        if isinstance(tags, list):
            # join any CWE tags
            cwe = ';'.join([t for t in tags if str(t).upper().startswith('CWE')])
        else:
            cwe = tags or ''
    raw = json.dumps(res, ensure_ascii=False)
    return {
        'id': res.get('id',''),
        'tool': 'semgrep',
        'rule_id': rule_id or '',
        'vulnerability_id': '',
        'package': '',
        'installed_version': '',
        'message': message,
        'severity': level,
        'file': file_path,
        'start_line': start_line,
        'cwe': cwe,
        'raw': raw
    }

def extract_trivy_result(res, tool_name='trivy'):
    props = res.get('properties', {}) or {}
    vuln_id = props.get('vulnerabilityID') or props.get('VulnerabilityID') or props.get('vuln', {}).get('id', '') or res.get('ruleId','')
    package = ''
    installed = ''
    # some Trivy SARIFs include package info in properties.package or properties.pkg
    pkg = props.get('package') or props.get('pkg') or {}
    if isinstance(pkg, dict):
        package = pkg.get('name') or pkg.get('packageName') or pkg.get('PkgName','') or ''
        installed = pkg.get('installedVersion') or pkg.get('version','') or ''
    # fallback property names
    if not package:
        package = props.get('packageName') or props.get('PkgName','') or ''
    severity = props.get('severity') or props.get('severity_label') or res.get('level','') or ''
    if isinstance(res.get('message'), dict):
        message = res['message'].get('text','')
    else:
        message = str(res.get('message',''))
    file_path = ''
    start_line = ''
    locs = res.get('locations') or []
    if locs:
        phys = locs[0].get('physicalLocation', {}) or {}
        file_path = phys.get('artifactLocation', {}).get('uri', '') or ''
        region = phys.get('region', {}) or {}
        start_line = region.get('startLine', '') or region.get('startColumn', '')
    raw = json.dumps(res, ensure_ascii=False)
    return {
        'id': res.get('id',''),
        'tool': tool_name,
        'rule_id': res.get('ruleId',''),
        'vulnerability_id': vuln_id,
        'package': package,
        'installed_version': installed,
        'message': message,
        'severity': severity,
        'file': file_path,
        'start_line': start_line,
        'cwe': '',
        'raw': raw
    }

def parse_sarif(sarif_path):
    p = Path(sarif_path)
    if not p.exists():
        raise FileNotFoundError(f"SARIF file not found: {sarif_path}")
    data = json.load(open(p, 'r', encoding='utf-8'))
    results_out = []
    runs = data.get('runs', [])
    for run in runs:
        tool_name_raw = run.get('tool', {}).get('driver', {}).get('name', '') or ''
        tool_name = str(tool_name_raw).lower()
        rules_list = run.get('tool', {}).get('driver', {}).get('rules', []) or []
        # create map of rule id -> rule details
        rules_map = {}
        for r in rules_list:
            rid = r.get('id') or r.get('name') or ''
            if rid:
                rules_map[rid] = r
        for res in run.get('results', []):
            if 'trivy' in tool_name or 'aqua' in tool_name or 'aquasecurity' in tool_name:
                results_out.append(extract_trivy_result(res, tool_name=tool_name))
            else:
                results_out.append(extract_semgrep_result(res, rules_map))
    return results_out

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', required=True, help='SARIF input file (json)')
    parser.add_argument('--output', '-o', required=True, help='CSV output file')
    args = parser.parse_args()

    inp = Path(args.input)
    out = Path(args.output)
    if not inp.exists():
        print("Input SARIF not found:", inp, file=sys.stderr)
        sys.exit(2)

    try:
        rows = parse_sarif(inp)
    except Exception as e:
        print("Error parsing SARIF:", e, file=sys.stderr)
        raise

    if not rows:
        print("No results extracted from SARIF.")
    fieldnames = ['id','tool','rule_id','vulnerability_id','package','installed_version','message','severity','file','start_line','cwe','raw']
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"Wrote {len(rows)} results to {out}")

if __name__ == '__main__':
    main()

