#!/usr/bin/env python3
"""
correlate_sbom_trivy_semgrep.py
Прив'язує Trivy CSV -> SBOM (CycloneDX JSON) та Semgrep CSV -> файли компонентів.
Вихід:
 - trivy_sbom_joined.csv
 - semgrep_enriched.csv
 - prioritized_vulns.csv
 - report.md   (короткий markdown звіт)
Usage:
 python3 correlate_sbom_trivy_semgrep.py \
   --sbom ~/Diplomas/dvwa_sbom_cyclonedx.json \
   --trivy ~/Diplomas/trivy-normalized-from-sarif.csv \
   --semgrep ~/Diplomas/semgrep_dvwa.csv \
   --outdir ~/Diplomas/artifacts
"""
import argparse, json, re, os
from pathlib import Path
import pandas as pd
from collections import defaultdict
from datetime import datetime

CVE_RE = re.compile(r'(CVE-\d{4}-\d{4,7})', flags=re.IGNORECASE)

def load_sbom(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    comps = []
    for c in data.get('components', []) if data else []:
        name = c.get('name') or ''
        version = c.get('version') or ''
        purl = c.get('purl') or ''
        # collect possible identifiers (externalReferences)
        refs = []
        for er in c.get('externalReferences', []) if c.get('externalReferences') else []:
            if er.get('url'): refs.append(er.get('url'))
            if er.get('type'): refs.append(er.get('type'))
        comps.append({
            'name': name,
            'version': version,
            'purl': purl,
            'refs': refs,
            'raw': c
        })
    return comps

def build_sbom_indices(components):
    by_name = defaultdict(list)
    by_name_version = {}
    by_purl = {}
    for c in components:
        key_nv = f"{c['name'].lower()}=={c['version']}" if c['version'] else c['name'].lower()
        by_name[c['name'].lower()].append(c)
        by_name_version[key_nv] = c
        if c['purl']:
            by_purl[c['purl']] = c
    return by_name, by_name_version, by_purl

def read_csv_try(path):
    # try to read with utf-8, fallback
    try:
        return pd.read_csv(path, encoding='utf-8')
    except Exception as e:
        print(f"Warning: Could not read CSV with UTF-8, trying latin-1. Error: {e}")
        return pd.read_csv(path, encoding='latin-1')

def find_cve_in_text(text):
    if not isinstance(text, str): return None
    m = CVE_RE.search(text)
    return m.group(1).upper() if m else None

import re
import difflib

def extract_possible_names_from_row(row):
    """Збираємо можливі текстові кандидати для імен пакету з рядка Trivy."""
    texts = []
    # common columns that might exist in Trivy CSV
    for c in ['pkgName', 'package', 'target', 'artifact', 'vulnerability_id', 'rule_id', 'message', 'title', 'file', 'name']:
        if c in row.index:
            val = row.get(c, '')
            if isinstance(val, str) and val.strip():
                texts.append(val.strip())
    # join other columns too (safe)
    texts.append(' '.join(str(row.get(c, '')) for c in row.index if row.get(c, '') is not None))
    return ' '.join(texts)

PACKAGE_RE = re.compile(r'Package:\s*([^\s,;]+)', flags=re.IGNORECASE)
PKG_SIMPLE_RE = re.compile(r'([A-Za-z0-9_\-+.]+)')  # fallback to token extraction

def match_trivy_row_to_sbom(row, sbom_indices):
    by_name, by_name_version, by_purl = sbom_indices

    combined_text = extract_possible_names_from_row(row)
    combined_text_low = combined_text.lower()

    # 1) try to find explicit purl anywhere in text
    for purl, comp in by_purl.items():
        if purl and purl in combined_text:
            return comp, 'purl'

    # 2) regex extract "Package: X" or similar patterns
    m = PACKAGE_RE.search(combined_text)
    if m:
        pkg = m.group(1)
        # try direct name match
        comp_list = by_name.get(pkg.lower())
        if comp_list:
            return comp_list[0], 'package_regex'
        # try fuzzy match
        close = difflib.get_close_matches(pkg.lower(), list(by_name.keys()), n=1, cutoff=0.75)
        if close:
            return by_name[close[0]][0], 'package_regex_fuzzy'

    # 3) exact name + version if row contains version-like substring
    # try to detect "name@version" or "name==version"
    for comp in by_name_version.values():
        n = comp['name'].lower()
        v = comp.get('version','')
        if n and n in combined_text_low:
            if v and v in combined_text:
                return comp, 'name+version'
            elif not v:
                return comp, 'name_only_exact'

    # 4) look for tokens in the text that match SBOM names
    for nm, comps in by_name.items():
        if nm and nm in combined_text_low:
            return comps[0], 'name_in_text'

    # 5) fallback: try to extract simple token candidates and fuzzy match
    tokens = re.findall(PKG_SIMPLE_RE, combined_text)
    # prioritize longer tokens
    tokens_sorted = sorted(set(tokens), key=lambda s: -len(s))
    sbom_names = list(by_name.keys())
    for tok in tokens_sorted:
        tok_low = tok.lower()
        if tok_low in by_name:
            return by_name[tok_low][0], 'token_exact'
        close = difflib.get_close_matches(tok_low, sbom_names, n=1, cutoff=0.80)
        if close:
            return by_name[close[0]][0], 'token_fuzzy'

    # nothing matched
    return None, None


    # 1) try purl match in any textual column
    combined_text = ' '.join(str(row.get(c, '')) for c in row.index if row.get(c, '') is not None)
    for purl, comp in by_purl.items():
        if purl and purl in combined_text:
            return comp, 'purl'

    # 2) try exact name + version anywhere in combined text
    for comp in by_name_version.values():
        name = comp['name'].lower()
        version = comp.get('version','')
        if name and name in combined_text.lower():
            if version and version in combined_text:
                return comp, 'name+version'
            elif not version and f" {name} " in combined_text.lower():
                return comp, 'name_only_from_exact_key'

    # 3) fallback: name-only heuristic (lowercase)
    for nm, comps in by_name.items():
        if nm and nm in combined_text.lower():
            return comps[0], 'name_fuzzy'

    return None, None



def map_semgrep_to_component(sem_row, sbom_indices):
    # try to map by filepath heuristics
    path = str(sem_row.get('file','') or '')
    path_low = path.lower()
    by_name, by_name_version, by_purl = sbom_indices
    # common package directories: node_modules, vendor, site-packages, composer, gems
    # try to extract token after node_modules/
    m = re.search(r'node_modules/([^/]+)/?', path_low)
    if m:
        pkg = m.group(1)
        comps = by_name.get(pkg)
        if comps:
            return comps[0], 'node_modules'
    m2 = re.search(r'vendor/([^/]+)/?', path_low)
    if m2:
        pkg = m2.group(1)
        comps = by_name.get(pkg)
        if comps:
            return comps[0], 'vendor'
    # fallback: scan SBOM names in path
    for nm, comps in by_name.items():
        if nm and nm in path_low:
            return comps[0], 'path_match'
    return None, None

def normalize_level(level):
    if not isinstance(level, str): return ''
    lvl = level.strip().lower()
    if lvl in ('critical','crit'): return 'CRITICAL'
    if lvl in ('high',): return 'HIGH'
    if lvl in ('medium','med'): return 'MEDIUM'
    if lvl in ('low',): return 'LOW'
    if lvl in ('info','informational'): return 'INFO' # Add INFO if present
    return level.upper() # Keep others as is, e.g., 'UNKNOWN'

def severity_weight(lv):
    weights = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0} # Added INFO
    return weights.get(lv, 0) # Default to 0 for UNKNOWN or INFO

def main(args):
    sbom_path = Path(args.sbom)
    trivy_csv = Path(args.trivy)
    semgrep_csv = Path(args.semgrep) if args.semgrep else None
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("[*] Loading SBOM:", sbom_path)
    components = load_sbom(sbom_path)
    sbom_indices = build_sbom_indices(components)

    print("[*] Reading Trivy CSV:", trivy_csv)
    df_trivy = read_csv_try(trivy_csv)
    df_trivy.fillna('', inplace=True)

    matched_rows = []
    unmatched = []
    for _, r in df_trivy.iterrows():
        comp, how = match_trivy_row_to_sbom(r, sbom_indices)
        cve = None
        # check rule_id or message for CVE
        if 'rule_id' in r.index and isinstance(r['rule_id'], str):
            cve = find_cve_in_text(r['rule_id'])
        if not cve: # if not found in rule_id, try other common columns
            cve = find_cve_in_text(str(r.get('vulnerability_id', '') or r.get('title','') or r.get('message','') or r.get('file','')))
        
        found = {}
        if comp:
            found = {'component_name': comp['name'], 'component_version': comp.get('version',''), 'component_purl': comp.get('purl',''), 'match_how': how}
            matched_rows.append({**r.to_dict(), **found, 'cve_id_extracted': cve or ''})
        else:
            # Ensure unmatched rows still have component fields so downstream grouping won't fail
            unmatched.append({**r.to_dict(), 'cve_id_extracted': cve or '', 'component_name': 'UNMAPPED', 'component_version': '', 'component_purl': '', 'match_how': ''})

    df_matched = pd.DataFrame(matched_rows)
    df_unmatched = pd.DataFrame(unmatched)
    joined_path = outdir / 'trivy_sbom_joined.csv'
    # Ensure CSV is written with UTF-8
    df_out = pd.concat([df_matched, df_unmatched], sort=False).fillna('')
    df_out.to_csv(joined_path, index=False, encoding='utf-8')
    print(f"[*] Wrote Trivy->SBOM joined table: {joined_path}  (matched: {len(df_matched)}, unmatched: {len(df_unmatched)})")

    # Semgrep mapping
    sem_out_path = outdir / 'semgrep_enriched.csv'
    if semgrep_csv and semgrep_csv.exists():
        print("[*] Reading Semgrep CSV:", semgrep_csv)
        df_s = read_csv_try(semgrep_csv)
        df_s.fillna('', inplace=True)
        enriched = []
        for _, r in df_s.iterrows():
            comp, how = map_semgrep_to_component(r, sbom_indices)
            if comp:
                enriched.append({**r.to_dict(), 'component_name': comp['name'], 'component_version': comp.get('version',''), 'match_how': how})
            else:
                enriched.append({**r.to_dict(), 'component_name': 'APPLICATION_CODE', 'component_version': '', 'match_how': 'direct_code_file'}) # If no component, mark as app code
        pd.DataFrame(enriched).to_csv(sem_out_path, index=False, encoding='utf-8')
        print(f"[*] Wrote Semgrep enriched: {sem_out_path}")

    # Prioritization: aggregate by component
    df_join = df_out.copy()
    # normalize severity (try columns 'level' or 'severity')
    if 'level' in df_join.columns:
        df_join['level_norm'] = df_join['level'].apply(normalize_level)
    elif 'severity' in df_join.columns:
        df_join['level_norm'] = df_join['severity'].apply(normalize_level)
    else: # Default if no known severity column exists
        df_join['level_norm'] = 'UNKNOWN'

    # group by component
    grouped = []
    # Collect all unique component names from matched Trivy results and Semgrep
    components_seen = set(df_join['component_name'].unique())
    if semgrep_csv and semgrep_csv.exists():
        df_semgrep_enriched = pd.read_csv(sem_out_path, encoding='utf-8') # Reload enriched semgrep
        components_seen.update(df_semgrep_enriched['component_name'].unique())
    
    # Also add any components from the original SBOM that might not have vulnerabilities
    for comp in components:
        components_seen.add(comp['name'])

    for cname in sorted(list(components_seen)):
        # Process Trivy vulnerabilities for this component
        dfc_trivy = df_join[df_join['component_name'] == cname]
        
        # Process Semgrep findings for this component
        dfc_semgrep = pd.DataFrame() # Initialize empty
        if semgrep_csv and semgrep_csv.exists():
            dfc_semgrep = df_semgrep_enriched[df_semgrep_enriched['component_name'] == cname]

        all_vulns_for_comp = []
        all_severities_for_comp = []

        # From Trivy results
        if not dfc_trivy.empty:
            all_vulns_for_comp.extend(dfc_trivy.get('rule_id', dfc_trivy.get('cve_id_extracted', '')).astype(str).tolist())
            all_severities_for_comp.extend(dfc_trivy.get('level_norm', []).tolist())

        # From Semgrep results
        if not dfc_semgrep.empty:
            all_vulns_for_comp.extend(dfc_semgrep.get('rule_id', dfc_semgrep.get('message', '')).astype(str).tolist()) # Semgrep rule_id is usually a good identifier
            semgrep_levels = dfc_semgrep.get('level', dfc_semgrep.get('severity', '')).apply(normalize_level).tolist()
            all_severities_for_comp.extend(semgrep_levels)
        
        # Filter out empty strings from vulnerability identifiers
        all_vulns_for_comp = [v for v in all_vulns_for_comp if v and v.lower() != 'nan']
        all_severities_for_comp = [s for s in all_severities_for_comp if s and s.lower() != 'nan']

        cversion = ''
        if cname != 'UNMAPPED' and cname != 'APPLICATION_CODE' and not dfc_trivy.empty:
            cversion = dfc_trivy.iloc[0].get('component_version','')
        elif cname != 'UNMAPPED' and cname != 'APPLICATION_CODE' and not dfc_semgrep.empty:
            cversion = dfc_semgrep.iloc[0].get('component_version','')
        # Try to get version from SBOM if component name exists but no vulns
        else:
            for comp_item in components:
                if comp_item['name'] == cname:
                    cversion = comp_item['version']
                    break


        # compute score: max severity weight * (1 + count/5)
        max_sev = 'UNKNOWN'
        if all_severities_for_comp:
            sev_list_clean = [s for s in all_severities_for_comp if isinstance(s,str) and s]
            if sev_list_clean:
                max_sev = sorted(sev_list_clean, key=lambda x: severity_weight(x), reverse=True)[0]
        
        count_vulns = len(all_vulns_for_comp)
        score = severity_weight(max_sev) * (1 + count_vulns/5) if max_sev!='UNKNOWN' else (1 + count_vulns/5)
        
        grouped.append({
            'component_name': cname,
            'component_version': cversion,
            'vuln_count': count_vulns,
            'max_severity': max_sev,
            'score': round(score,2),
            'cve_list': ';'.join(list(set(all_vulns_for_comp))) # Use set to get unique vulns
        })
    
    df_prior = pd.DataFrame(grouped).sort_values(['score','vuln_count'], ascending=[False, False])
    prior_path = outdir / 'prioritized_vulns.csv'
    df_prior.to_csv(prior_path, index=False, encoding='utf-8')
    print(f"[*] Wrote prioritized vulnerabilities: {prior_path}")

    # Minimal markdown report
    report = []
    report.append(f"# Vulnerability correlation report\nGenerated: {datetime.utcnow().isoformat()}Z\n")
    report.append(f"## Summary\n- SBOM components: {len(components)}\n- Trivy rows: {len(df_trivy)}\n- Matched Trivy->SBOM: {len(df_matched)}\n- Unmatched Trivy rows: {len(df_unmatched)}\n\n")
    if semgrep_csv and semgrep_csv.exists():
        report.append(f"- Semgrep findings: {len(df_s)}\n")
        report.append(f"- Semgrep findings mapped to components: {len(df_semgrep_enriched[df_semgrep_enriched['component_name'] != 'APPLICATION_CODE'])}\n")
        report.append(f"- Semgrep findings in app code: {len(df_semgrep_enriched[df_semgrep_enriched['component_name'] == 'APPLICATION_CODE'])}\n\n")

    report.append("## Top components by score (including application code)\n")
    report.append(df_prior.head(10).to_markdown(index=False))
    report.append("\n\n## Notes\n- Matching is heuristic. Please manually validate unmatched rows (in `trivy_sbom_joined.csv`).\n- For application code issues (Semgrep, `component_name: APPLICATION_CODE`), check `semgrep_enriched.csv` for file/line info.\n")
    report_path = outdir / 'report.md'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))
    print(f"[*] Wrote markdown report: {report_path}")
    print("[*] Done.")

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--sbom', required=True)
    p.add_argument('--trivy', required=True)
    p.add_argument('--semgrep', required=False)
    p.add_argument('--outdir', required=False, default='~/Diplomas/artifacts')
    args = p.parse_args()
    args.outdir = os.path.expanduser(args.outdir)
    main(args)
