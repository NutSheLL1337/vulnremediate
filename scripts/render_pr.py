#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
render_pr.py
Проста рендеринг-утиліта: бере CSV та Jinja2-шаблон і генерує PR body (markdown).
Usage:
 python3 scripts/render_pr.py \
   --csv ~/Diplomas/artifacts/semgrep_enriched.csv \
   --template ~/Diplomas/templates/draft_pr.j2 \
   --out ~/Diplomas/artifacts/draft_pr_from_semgrep.md \
   --row 1
"""
import argparse, csv, os
from jinja2 import Template

def read_csv_row(path, rownum):
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, r in enumerate(reader, start=1):
            if i == rownum:
                return r
    return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--csv', required=True)
    p.add_argument('--template', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--row', type=int, default=1)
    args = p.parse_args()

    row = read_csv_row(args.csv, args.row)
    if not row:
        print("Row not found")
        return
    with open(args.template, 'r', encoding='utf-8') as f:
        tpl = Template(f.read())

    # Map fields — підлаштуй під свій CSV
    ctx = {
        'vuln_id': row.get('rule_id') or row.get('cve_id_extracted') or 'UNKNOWN',
        'component_name': row.get('component_name') or row.get('tool') or 'UNMAPPED',
        'component_version': row.get('component_version',''),
        'source_type': row.get('tool','Semgrep/Trivy'),
        'short_description': (row.get('message') or '')[:300],
        'evidence': row.get('message') or '',
        'patch_snippet': row.get('suggested_fix','See comments; no automatic patch provided'),
        'reproduce_command': "semgrep --config p/security-audit --sarif --output=results.sarif ./",
        'reproduce_location': row.get('file',''),
        'expected_outcome': "No sensitive file disclosure; semgrep/trivy should not report same finding.",
        'auto_score': row.get('level','UNKNOWN'),
        'recommendation': "Почати з виправлення app code; паралельно планувати оновлення пакета OS."
    }
    out = tpl.render(**ctx)
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write(out)
    print("Wrote:", args.out)

if __name__ == '__main__':
    main()

