#!/usr/bin/env bash
set -euo pipefail
file=$(jq -r '.tool_input.file_path // ""')
[ -z "$file" ] && exit 0

case "$file" in
  *.js|*.ts|*.jsx|*.tsx)
    command -v npx &>/dev/null && npx eslint --fix "$file" 2>&1 | tail -10 ;;
  *.py)
    command -v ruff &>/dev/null && ruff check --fix "$file" 2>&1 | tail -10 ;;
esac
exit 0
