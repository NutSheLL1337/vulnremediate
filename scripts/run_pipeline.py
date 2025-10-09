#!/usr/bin/env python3
# scripts/run_pipeline.py - improved (handles empty SBOM + correct render_pr args)

import os, sys, subprocess, argparse, shutil, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
ARTIFACTS_DEFAULT = ROOT / "artifacts"
RESULTS = ROOT / "results"
PATCHES = ROOT / "patches"
TEMPLATES = ROOT / "templates"

def run_cmd(cmd, cwd=None, env=None):
    print(">>> RUN:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=cwd or ROOT, env=env or os.environ)
    if res.returncode != 0:
        print(f"Command failed: {' '.join(cmd)} (exit {res.returncode})")
    return res.returncode

def find_file(dirpath, candidates):
    dirpath = Path(dirpath)
    for name in candidates:
        p = dirpath / name
        if p.exists():
            return p
    # try fuzzy
    for name in candidates:
        part = name.split('.')[0]
        for f in dirpath.glob(f"*{part}*"):
            return f
    return None

def is_valid_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = f.read().strip()
            if not data:
                return False
            json.loads(data)
        return True
    except Exception as e:
        print("JSON validation failed for", path, ":", e)
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", default=str(ARTIFACTS_DEFAULT))
    parser.add_argument("--repo", required=False, help="owner/repo (for PR creation)")
    parser.add_argument("--create-pr", action="store_true")
    parser.add_argument("--semgrep-file", default="", help="force semgrep file path")
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts)
    if not artifacts_dir.exists():
        print("Artifacts dir not found:", artifacts_dir)
        sys.exit(1)

    RESULTS.mkdir(parents=True, exist_ok=True)
    PATCHES.mkdir(parents=True, exist_ok=True)

    semgrep_candidates = [
        "semgrep_before_fix.sarif", "semgrep_after_fix.sarif", "semgrep.sarif",
        "before_fix_semgrep.sarif", "semgrep_before_fix.sarif.sarif"
    ]
    trivy_candidates = ["trivy-dvwa-results.sarif", "trivy.sarif", "trivy-results.sarif"]
    sbom_candidates = ["sbom_dvwa_cyclonedx.json", "dvwa_sbom_cyclonedx.json", "sbom.cdx.json"]

    semgrep_file = Path(args.semgrep_file) if args.semgrep_file else find_file(artifacts_dir, semgrep_candidates)
    trivy_file = find_file(artifacts_dir, trivy_candidates)
    sbom_file = find_file(artifacts_dir, sbom_candidates)

    print("Found semgrep file:", semgrep_file)
    print("Found trivy file:", trivy_file)
    print("Found sbom file:", sbom_file)

    unified_csv = RESULTS / "unified_findings.csv"

    # Normalize step (if semgrep SARIF present) OR fallback to existing CSVs in artifacts
    if semgrep_file and semgrep_file.exists() and semgrep_file.suffix in [".sarif", ".json"]:
        print("Normalizing SARIF ->", unified_csv)
        rc = run_cmd([sys.executable, str(SCRIPTS / "normalize_sarif.py"),
                      "--input", str(semgrep_file), "--output", str(unified_csv)])
        if rc != 0:
            print("normalize_sarif.py failed; checking for existing CSV fallbacks")
    else:
        print("No semgrep SARIF found or invalid. Trying CSV fallbacks in artifacts/")
    # Fallbacks if normalized file is empty/not created
    if not unified_csv.exists() or unified_csv.stat().st_size == 0:
        candidates_csv = ["semgrep_enriched.csv", "semgrep_before_fix.csv", "semgrep_after_fix.csv", "vulnerabilities.csv"]
        found = None
        for f in candidates_csv:
            p = artifacts_dir / f
            if p.exists() and p.stat().st_size > 0:
                found = p
                break
        if found:
            print("Using fallback semgrep CSV:", found)
            shutil.copy(found, unified_csv)
        else:
            print("No semgrep results available (normalized or fallback). Aborting.")
            sys.exit(1)

    # Correlate step: ensure SBOM is valid JSON; otherwise skip correlation
    correlated_csv = RESULTS / "correlated_findings.csv"
    if sbom_file and sbom_file.exists() and is_valid_json(sbom_file):
        correlate_cmd = [sys.executable, str(SCRIPTS / "correlate_sbom_trivy_semgrep.py"),
                         "--semgrep", str(unified_csv), "--out", str(correlated_csv)]
        if trivy_file:
            correlate_cmd += ["--trivy", str(trivy_file)]
        correlate_cmd += ["--sbom", str(sbom_file)]
        rc = run_cmd(correlate_cmd)
        if rc != 0:
            print("Correlation failed; falling back to unified CSV")
            if correlated_csv.exists():
                correlated_csv.unlink()
    else:
        print("SBOM missing or invalid JSON -> skipping correlation, using unified CSV as correlated_findings.csv")
        if not correlated_csv.exists() or correlated_csv.stat().st_size == 0:
            shutil.copy(unified_csv, correlated_csv)

    # Render PRs: render_pr expects --csv, --template, --out
    csv_for_render = correlated_csv if correlated_csv.exists() and correlated_csv.stat().st_size > 0 else unified_csv
    # choose template — use draft_pr.j2 if exists, else require user template
    template_choice = Path(TEMPLATES) / "draft_pr.j2"
    if not template_choice.exists():
        # fallback to pr_template.j2
        template_choice = Path(TEMPLATES) / "pr_template.j2"
    if not template_choice.exists():
        print("No templates found in", TEMPLATES, "expected draft_pr.j2 or pr_template.j2")
        sys.exit(1)

    render_cmd = [sys.executable, str(SCRIPTS / "render_pr.py"),
                  "--csv", str(csv_for_render),
                  "--template", str(template_choice),
                  "--out", str(PATCHES)]
    # optionally only render a single row? render_pr supports --row <N>
    if args.create_pr:
        if not args.repo:
            print("To create PRs you must pass --repo owner/repo")
            sys.exit(2)
        if not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"):
            print("GH_TOKEN or GITHUB_TOKEN env required to create PRs. Set secret and retry.")
            sys.exit(2)
        render_cmd += ["--create-pr", "--repo", args.repo]
    else:
        render_cmd += ["--dry-run"]

    rc = run_cmd(render_cmd)
    if rc != 0:
        print("render_pr.py failed (rc)", rc)

    print("\n=== SUMMARY ===")
    print("Semgrep:", semgrep_file)
    print("Trivy:", trivy_file)
    print("SBOM:", sbom_file)
    print("Unified CSV:", unified_csv.exists(), unified_csv)
    print("Correlated CSV:", correlated_csv.exists(), correlated_csv)
    print("Patches dir:", PATCHES)
    for p in sorted(PATCHES.glob("*")):
        print(" -", p.name)
    print("\nPipeline finished.")

if __name__ == "__main__":
    main()
