#!/usr/bin/env bash
set -euo pipefail

if [ -f package.json ]; then
  if command -v npm &>/dev/null; then
    npm test --silent 2>&1 | tail -5
  else
    echo "[hooks] npm not found — skipping tests" >&2
  fi
fi

if [ -f pyproject.toml ]; then
  if command -v pytest &>/dev/null; then
    pytest --tb=short -q 2>&1 | tail -5
  else
    echo "[hooks] pytest not found — skipping tests" >&2
  fi
fi

if [ -f go.mod ]; then
  if command -v go &>/dev/null; then
    go test ./... 2>&1 | tail -5
  else
    echo "[hooks] go not found — skipping tests" >&2
  fi
fi

if [ -f Cargo.toml ]; then
  if command -v cargo &>/dev/null; then
    cargo test 2>&1 | tail -5
  else
    echo "[hooks] cargo not found — skipping tests" >&2
  fi
fi

exit 0
