#!/usr/bin/env bash

# Best-effort Stop hook: skip silently when git prerequisites are missing.
# Never exits non-zero — a failing Stop hook would surface errors in the Claude session.

git rev-parse --git-dir &>/dev/null || exit 0

# Fall back to a dummy identity so commits work until the user configures their own
git config user.email &>/dev/null || git config --local user.email "claude-code@localhost"
git config user.name  &>/dev/null || git config --local user.name  "Claude Code"

git add -A || { echo "[auto-commit] git add failed, skipping" >&2; exit 0; }

if ! git diff --cached --quiet; then
  git commit -m "chore(ai): apply Claude edit" || true
fi

exit 0
