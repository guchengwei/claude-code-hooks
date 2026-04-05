#!/usr/bin/env bash
set -euo pipefail

failed=0

if [ -f package.json ]; then
  npm test --silent || failed=1
fi
if [ -f pyproject.toml ] || [ -f requirements.txt ]; then
  pytest --tb=short -q || failed=1
fi
if [ -f go.mod ]; then
  go test ./... || failed=1
fi
if [ -f Cargo.toml ]; then
  cargo test || failed=1
fi

if [ "$failed" -eq 1 ]; then
  echo "Tests are failing. Fix all test failures before creating a PR." >&2
  exit 2
fi
exit 0
