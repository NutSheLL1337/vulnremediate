#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Activte venv if exists
if [ -f .venv/bin/activate ]; then
  echo "Activating venv..."
  source .venv/bin/activate
fi

ARTIFACTS_DIR="${1:-artifacts}"
REPO="${2:-}"  # optional owner/repo if you want to create PRs
CREATE_PR="${3:-}" # pass "create" to create PRs

if [ "$CREATE_PR" = "create" ] && [ -z "$REPO" ]; then
  echo "Usage: $0 [artifacts_dir] owner/repo create"
  exit 1
fi

if [ "$CREATE_PR" = "create" ]; then
  python3 scripts/run_pipeline.py --artifacts "$ARTIFACTS_DIR" --create-pr --repo "$REPO"
else
  python3 scripts/run_pipeline.py --artifacts "$ARTIFACTS_DIR"
fi
