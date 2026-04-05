#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse args
GLOBAL=false
TARGET_DIR="."

while [[ $# -gt 0 ]]; do
  case "$1" in
    --global) GLOBAL=true; shift ;;
    *) TARGET_DIR="$1"; shift ;;
  esac
done

if $GLOBAL; then
  TARGET_DIR="$HOME"
fi

CLAUDE_DIR="$TARGET_DIR/.claude"
HOOKS_DIR="$CLAUDE_DIR/hooks"

echo "=== Claude Code Hooks Installer ==="
echo ""

# Create directories
mkdir -p "$HOOKS_DIR"

# Copy hook scripts
echo "Copying hook scripts..."
cp "$SCRIPT_DIR/.claude/hooks/"*.sh "$HOOKS_DIR/"
chmod +x "$HOOKS_DIR/"*.sh
echo "  Installed $(ls "$HOOKS_DIR/"*.sh | wc -l | tr -d ' ') hook scripts"

# Copy settings.json
echo "Copying settings.json..."
if [ -f "$CLAUDE_DIR/settings.json" ]; then
  read -rp "  settings.json already exists. Overwrite? [y/N]: " overwrite
  if [[ "$overwrite" =~ ^[Yy]$ ]]; then
    cp "$SCRIPT_DIR/.claude/settings.json" "$CLAUDE_DIR/settings.json"
    echo "  Overwritten."
  else
    echo "  Skipped (keeping existing settings.json)."
  fi
else
  cp "$SCRIPT_DIR/.claude/settings.json" "$CLAUDE_DIR/settings.json"
  echo "  Done."
fi

# Detect languages
echo ""
echo "Detecting project languages..."
LANGUAGES=()

[ -f "$TARGET_DIR/package.json" ] && LANGUAGES+=("node")
{ [ -f "$TARGET_DIR/pyproject.toml" ] || [ -f "$TARGET_DIR/requirements.txt" ]; } && LANGUAGES+=("python")
[ -f "$TARGET_DIR/go.mod" ] && LANGUAGES+=("go")
[ -f "$TARGET_DIR/Cargo.toml" ] && LANGUAGES+=("rust")

if [ "${#LANGUAGES[@]}" -eq 0 ]; then
  echo "  No languages detected."
  read -rp "  Which languages will you use? (comma-separated: node,python,go,rust,skip): " lang_input
  if [ "$lang_input" != "skip" ] && [ -n "$lang_input" ]; then
    IFS=',' read -ra LANGUAGES <<< "$lang_input"
  fi
fi

if [ "${#LANGUAGES[@]}" -gt 0 ]; then
  echo "  Languages: ${LANGUAGES[*]}"
fi

# Install tools per language
install_if_missing() {
  local cmd="$1"
  local install_cmd="$2"
  local label="$3"
  if ! command -v "$cmd" &>/dev/null; then
    read -rp "  $label ($cmd) not found. Install? [Y/n]: " answer
    if [[ ! "$answer" =~ ^[Nn]$ ]]; then
      echo "  Running: $install_cmd"
      eval "$install_cmd"
    fi
  else
    echo "  $label ($cmd) -- already installed"
  fi
}

echo ""
for lang in "${LANGUAGES[@]+"${LANGUAGES[@]}"}"; do
  lang=$(echo "$lang" | tr -d ' ')
  case "$lang" in
    node)
      echo "Setting up Node.js tools..."
      install_if_missing "prettier" "npm i -g prettier" "Formatter"
      install_if_missing "eslint" "npm i -g eslint" "Linter"
      ;;
    python)
      echo "Setting up Python tools..."
      install_if_missing "black" "pip install black" "Formatter"
      install_if_missing "ruff" "pip install ruff" "Linter"
      install_if_missing "pytest" "pip install pytest" "Test runner"
      ;;
    go)
      echo "Setting up Go tools..."
      install_if_missing "golangci-lint" "go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" "Linter"
      ;;
    rust)
      echo "Setting up Rust tools..."
      echo "  rustfmt and clippy are built-in with rustup"
      ;;
  esac
done

# Update .gitignore
if [ -f "$TARGET_DIR/.gitignore" ]; then
  if ! grep -q ".claude/command-log.txt" "$TARGET_DIR/.gitignore"; then
    echo ".claude/command-log.txt" >> "$TARGET_DIR/.gitignore"
    echo ""
    echo "Added .claude/command-log.txt to .gitignore"
  fi
elif [ ! "$GLOBAL" = true ]; then
  echo ".claude/command-log.txt" > "$TARGET_DIR/.gitignore"
  echo ""
  echo "Created .gitignore with .claude/command-log.txt"
fi

# Summary
echo ""
echo "=== Installation Complete ==="
echo ""
echo "Installed hooks:"
echo "  PreToolUse:"
echo "    - block-dangerous.sh  (blocks rm -rf, force push, DROP TABLE, etc.)"
echo "    - protect-files.sh    (blocks edits to .env, locks, keys)"
echo "    - log-commands.sh     (audit log of all commands)"
echo "    - require-tests-for-pr.sh (gates PR creation on passing tests)"
echo "  PostToolUse:"
echo "    - format-file.sh      (auto-format by file extension)"
echo "    - lint-file.sh        (auto-lint by file extension)"
echo "    - run-tests.sh        (runs all detected test suites)"
echo "  Stop:"
echo "    - auto-commit.sh      (auto-commits on task completion)"
echo ""
echo "Start Claude Code with: claude"
