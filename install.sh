#!/usr/bin/env bash
set -eu

if [ "$#" -gt 0 ] && [ "${1:-}" != "--help" ]; then
  printf '%s\n' "install.sh no longer accepts installation targets." >&2
fi

printf '%s\n' \
  "Coding Agent Hooks is now distributed by agent-native package managers." \
  "" \
  "Claude Code:" \
  "  /plugin marketplace add guchengwei/claude-code-hooks" \
  "  /plugin install coding-agent-hooks@coding-agent-hooks" \
  "" \
  "Codex:" \
  "  codex plugin marketplace add guchengwei/claude-code-hooks" \
  "  codex plugin add coding-agent-hooks@coding-agent-hooks" \
  "" \
  "Gemini CLI:" \
  "  gemini extensions install https://github.com/guchengwei/claude-code-hooks" \
  "" \
  "No files were changed. See README.md for configuration and migration details."
