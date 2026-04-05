#!/usr/bin/env bash
set -euo pipefail
file=$(jq -r '.tool_input.file_path // ""')
[ -z "$file" ] && exit 0

case "$file" in
  *.js|*.ts|*.jsx|*.tsx|*.json|*.css|*.html|*.md)
    command -v npx &>/dev/null && npx prettier --write "$file" 2>/dev/null ;;
  *.py)
    command -v black &>/dev/null && black "$file" 2>/dev/null ;;
  *.go)
    command -v gofmt &>/dev/null && gofmt -w "$file" ;;
  *.rs)
    command -v rustfmt &>/dev/null && rustfmt "$file" 2>/dev/null ;;
esac
exit 0
