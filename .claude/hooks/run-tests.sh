#!/usr/bin/env bash
set -euo pipefail

[ -f package.json ] && npm test --silent 2>&1 | tail -5
[ -f pyproject.toml ] && pytest --tb=short -q 2>&1 | tail -5
[ -f go.mod ] && go test ./... 2>&1 | tail -5
[ -f Cargo.toml ] && cargo test 2>&1 | tail -5
exit 0
