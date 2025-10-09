# Vulnerability correlation report
Generated: 2025-10-02T10:04:41.497210Z

## Summary
- SBOM components: 23
- Trivy rows: 1576
- Matched Trivy->SBOM: 0
- Unmatched Trivy rows: 1576


- Semgrep findings: 37

- Semgrep findings mapped to components: 0

- Semgrep findings in app code: 37


## Top components by score (including application code)

| component_name                                                            | component_version   |   vuln_count | max_severity   |   score | cve_list   |
|:--------------------------------------------------------------------------|:--------------------|-------------:|:---------------|--------:|:-----------|
| /home/vboxuser/Diplomas/dvwa-src/.github/workflows/codeql-analysis.yml    |                     |            0 | UNKNOWN        |       1 |            |
| /home/vboxuser/Diplomas/dvwa-src/.github/workflows/docker-image.yml       |                     |            0 | UNKNOWN        |       1 |            |
| /home/vboxuser/Diplomas/dvwa-src/.github/workflows/pytest.yml             |                     |            0 | UNKNOWN        |       1 |            |
| /home/vboxuser/Diplomas/dvwa-src/.github/workflows/shiftleft-analysis.yml |                     |            0 | UNKNOWN        |       1 |            |
| /home/vboxuser/Diplomas/dvwa-src/.github/workflows/vulnerable.yml         |                     |            0 | UNKNOWN        |       1 |            |
| /home/vboxuser/Diplomas/dvwa-src/vulnerabilities/api/composer.lock        |                     |            0 | UNKNOWN        |       1 |            |
| ShiftLeftSecurity/scan-action                                             | master              |            0 | UNKNOWN        |       1 |            |
| actions/checkout                                                          | v3                  |            0 | UNKNOWN        |       1 |            |
| docker/login-action                                                       | v1                  |            0 | UNKNOWN        |       1 |            |
| github/codeql-action/analyze                                              | v2                  |            0 | UNKNOWN        |       1 |            |


## Notes
- Matching is heuristic. Please manually validate unmatched rows (in `trivy_sbom_joined.csv`).
- For application code issues (Semgrep, `component_name: APPLICATION_CODE`), check `semgrep_enriched.csv` for file/line info.
