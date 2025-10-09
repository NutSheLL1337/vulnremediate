#!/usr/bin/env python3
"""
scripts/generate_sql_patches.py

Простий автогенератор патчів для Semgrep findings (SQLi) — бере CSV, знаходить перший рядок з hint про SQL concat/mysqli_query і генерує patch у patches/sql_fix_<n>.diff
"""
import csv, re, sys, os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "results" / "correlated_findings.csv" / "semgrep_enriched.csv"
TEMPLATES = ROOT / "templates"
PATCHES = ROOT / "patches" / "autofix_sql"
PATCHES.mkdir(parents=True, exist_ok=True)

env = Environment(loader=FileSystemLoader(str(TEMPLATES)))
tpl = env.get_template("patch_sqli.j2")

def guess_conn_var(file_text):
    # very small heuristic: find $conn or $link or $mysqli
    m = re.search(r"\$(conn|link|mysqli)\b", file_text)
    return f"${m.group(1)}" if m else "$conn"

def extract_vuln_info(row):
    # expected columns include file,start_line,rule_id,message etc.
    # fallback by index if headers unknown
    keys = {k.lower():k for k in row.keys()}
    file = row.get(keys.get('file','file'), row.get('file','')).strip()
    start = row.get(keys.get('start_line','start_line'), row.get('start_line','')).strip()
    msg = row.get(keys.get('message','message'), row.get('message','')).strip()
    rule = row.get(keys.get('rule_id','rule_id'), row.get('rule_id','')).strip()
    return file, int(start) if start else None, rule, msg

def make_patch_for_row(row, idx):
    file, start_line, rule, msg = extract_vuln_info(row)
    if not file or not start_line:
        return None
    fpath = ROOT / file
    if not fpath.exists():
        # try relative to dvwa-src
        alt = ROOT / "dvwa-src" / file
        if alt.exists():
            fpath = alt
        else:
            print("File not found:", file)
            return None
    text = fpath.read_text(encoding='utf-8', errors='ignore').splitlines()
    # pick the vulnerable line (start_line is 1-indexed)
    vuln_line = text[start_line-1].strip()
    # simple heuristics: find variables inside vuln_line that come from $_GET/$_POST/$_REQUEST
    binds = re.findall(r"\$_(GET|POST|REQUEST)\[['\"]?([A-Za-z0-9_]+)['\"]?\]", vuln_line)
    bind_vars = []
    for src, name in binds:
        # declare var $name = $_GET['name']; but we will assume variable exists; use $name
        bind_vars.append(f"${name}")
    if not bind_vars:
        # try extracting variables like $id used in concatenation
        vars_in_line = re.findall(r"(\$[A-Za-z_][A-Za-z0-9_]*)", vuln_line)
        # exclude $conn-like names
        vars_in_line = [v for v in vars_in_line if v not in ('$conn','$link','$mysqli')]
        if vars_in_line:
            bind_vars = [vars_in_line[-1]]
    if not bind_vars:
        # fallback: create $param
        bind_vars = ["$param"]
    bind_types = "s" * len(bind_vars)
    bind_vars_str = ", ".join(bind_vars)
    # create prepared_sql by replacing php variables and interpolations with ?
    prepared_sql = re.sub(r"\$\w+|\.\s*['\"][^'\"]*['\"]\s*\.?", "?", vuln_line)
    # better: try to find the quoted SQL inside vuln_line
    m = re.search(r"([\"'])(SELECT|INSERT|UPDATE|DELETE)[\s\S]*\1", vuln_line, re.IGNORECASE)
    if m:
        candidate_sql = m.group(0).strip('\'"')
        # replace variables in candidate_sql with ?
        candidate_sql = re.sub(r"\$\w+", "?", candidate_sql)
        prepared_sql = candidate_sql
    # guess connection var from whole file
    conn_var = guess_conn_var("\n".join(text))
    patch_text = tpl.render(file=str(file), vulnerable_line=vuln_line, conn_var=conn_var,
                            prepared_sql=prepared_sql.replace('"','\\"'), bind_types=bind_types, bind_vars=bind_vars_str)
    out = PATCHES / f"sql_fix_{idx}.diff"
    out.write_text(patch_text, encoding='utf-8')
    print("Wrote patch:", out)
    return out

def main():
    if not CSV.exists():
        print("CSV not found:", CSV)
        sys.exit(1)
    with open(CSV, newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        count = 0
        for i,row in enumerate(reader, start=1):
            # quick filter: rule mentions 'sql' or message contains 'SELECT' or 'mysqli_query'
            text = " ".join(row.get(k,"") for k in row.keys())
            if re.search(r"sql|select|mysqli_query|mysql_query|prepare|execute", text, re.IGNORECASE):
                p = make_patch_for_row(row, i)
                if p:
                    count += 1
                    # break after first patch for demo
                    break
        if count==0:
            print("No SQL-like findings auto-detected.")
        else:
            print("Generated", count, "patch(es) in", PATCHES)

if __name__ == "__main__":
    main()
