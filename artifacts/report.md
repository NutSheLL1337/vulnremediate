# Vulnerability correlation report
Generated: 2025-09-29T16:36:35.199902Z

## Summary
- SBOM components: 9680
- Trivy rows: 1576
- Matched Trivy->SBOM: 1576
- Unmatched Trivy rows: 0


- Semgrep findings: 38

- Semgrep findings mapped to components: 38

- Semgrep findings in app code: 0


## Top components by score (including application code)

| component_name    | component_version   |   vuln_count | max_severity   |   score | cve_list   |
|:------------------|:--------------------|-------------:|:---------------|--------:|:-----------|
| /bin/bash         |                     |            0 | UNKNOWN        |       1 |            |
| /bin/bunzip2      |                     |            0 | UNKNOWN        |       1 |            |
| /bin/bzdiff       |                     |            0 | UNKNOWN        |       1 |            |
| /bin/bzexe        |                     |            0 | UNKNOWN        |       1 |            |
| /bin/bzgrep       |                     |            0 | UNKNOWN        |       1 |            |
| /bin/bzip2recover |                     |            0 | UNKNOWN        |       1 |            |
| /bin/bzmore       |                     |            0 | UNKNOWN        |       1 |            |
| /bin/cat          |                     |            0 | UNKNOWN        |       1 |            |
| /bin/chgrp        |                     |            0 | UNKNOWN        |       1 |            |
| /bin/chmod        |                     |            0 | UNKNOWN        |       1 |            |


## Notes
- Matching is heuristic. Please manually validate unmatched rows (in `trivy_sbom_joined.csv`).
- For application code issues (Semgrep, `component_name: APPLICATION_CODE`), check `semgrep_enriched.csv` for file/line info.
