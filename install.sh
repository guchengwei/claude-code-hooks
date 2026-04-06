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
  if ! command -v jq &>/dev/null; then
    echo "Error: jq is required for --global installs. Install it with 'apt install jq' or 'brew install jq'." >&2
    exit 1
  fi
fi

# Canonicalize TARGET_DIR for self-detection (skip if directory doesn't exist yet)
if [ -d "$TARGET_DIR" ]; then
  CANONICAL_TARGET="$(realpath "$TARGET_DIR" 2>/dev/null || (cd -P "$TARGET_DIR" 2>/dev/null && pwd))"
  if [ -n "$CANONICAL_TARGET" ] && [ "$CANONICAL_TARGET" = "$SCRIPT_DIR" ]; then
    echo "Error: Cannot install into the hooks repo itself." >&2
    echo "Run install.sh from your target project directory:" >&2
    echo "  cd /path/to/your-project && $SCRIPT_DIR/install.sh ." >&2
    exit 1
  fi
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

# Copy/merge settings.json
echo "Copying settings.json..."
if [ -f "$CLAUDE_DIR/settings.json" ]; then
  if command -v jq &>/dev/null; then
    if ! jq empty "$CLAUDE_DIR/settings.json" 2>/dev/null; then
      echo "  Existing settings.json is malformed — cannot merge."
      overwrite=""
      [ -t 0 ] && read -rp "  Overwrite with bundled settings.json? [y/N]: " overwrite
      if [[ "$overwrite" =~ ^[Yy]$ ]]; then
        cp "$SCRIPT_DIR/.claude/settings.json" "$CLAUDE_DIR/settings.json"
        echo "  Overwritten."
      else
        echo "  Skipped (keeping existing settings.json)."
      fi
    else
      echo "  Existing settings.json found — merging hooks..."
      merged=$(jq -s '
        def merge_hooks(a; b):
          (a + b) | group_by(.matcher) | map(
            { matcher: .[0].matcher, hooks: (map(.hooks) | add | unique) }
          );
        .[0] as $existing | .[1] as $new |
        $existing | .hooks = (
          ($existing.hooks // {}) + {
            PreToolUse:  merge_hooks(($existing.hooks.PreToolUse  // []);  ($new.hooks.PreToolUse  // [])),
            PostToolUse: merge_hooks(($existing.hooks.PostToolUse // []); ($new.hooks.PostToolUse // [])),
            Stop:        merge_hooks(($existing.hooks.Stop        // []);  ($new.hooks.Stop        // []))
          }
        )
      ' "$CLAUDE_DIR/settings.json" "$SCRIPT_DIR/.claude/settings.json")
      echo "$merged" > "$CLAUDE_DIR/settings.json"
      echo "  Merged."
    fi
  else
    echo "  (jq not found — cannot auto-merge)"
    overwrite=""
    [ -t 0 ] && read -rp "  Overwrite existing settings.json? [y/N]: " overwrite
    if [[ "$overwrite" =~ ^[Yy]$ ]]; then
      cp "$SCRIPT_DIR/.claude/settings.json" "$CLAUDE_DIR/settings.json"
      echo "  Overwritten."
    else
      echo "  Skipped (keeping existing settings.json)."
    fi
  fi
else
  cp "$SCRIPT_DIR/.claude/settings.json" "$CLAUDE_DIR/settings.json"
  echo "  Done."
fi

# Rewrite relative hook paths to absolute for global installs
if $GLOBAL; then
  rewrite_global_paths "$CLAUDE_DIR/settings.json" "$HOME"
  echo "  Rewrote hook paths to absolute (global install)."
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
  if [ -t 0 ]; then
    read -rp "  Which languages will you use? (comma-separated: node,python,go,rust,skip): " lang_input
    if [ "$lang_input" != "skip" ] && [ -n "$lang_input" ]; then
      IFS=',' read -ra LANGUAGES <<< "$lang_input"
    fi
  fi
else
  echo "  Detected: ${LANGUAGES[*]}"
  if [ -t 0 ]; then
    read -rp "  Add more languages? (comma-separated: node,python,go,rust, or press Enter to skip): " lang_extra
    if [ -n "$lang_extra" ]; then
      IFS=',' read -ra EXTRA <<< "$lang_extra"
      for lang in "${EXTRA[@]}"; do
        lang=$(echo "$lang" | tr -d ' ')
        # avoid duplicates
        if [[ ! " ${LANGUAGES[*]} " =~ " ${lang} " ]]; then
          LANGUAGES+=("$lang")
        fi
      done
    fi
  fi
fi

if [ "${#LANGUAGES[@]}" -gt 0 ]; then
  echo "  Languages: ${LANGUAGES[*]}"
fi

# Rewrite relative hook paths to absolute in settings.json (required for --global)
rewrite_global_paths() {
  local file="$1"
  local home_dir="$2"
  jq --arg home "$home_dir" '
    .hooks |= with_entries(
      .value |= map(
        .hooks |= map(
          if (.command // "") | startswith(".claude/hooks/")
          then .command = ($home + "/.claude/hooks/" +
                 (.command | ltrimstr(".claude/hooks/")))
          else .
          end
        )
      )
    )
  ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

# Install tools per language
# python_install_package: cascade installer for PEP 668 systems.
# Assumes binary name == package name (valid for black, ruff, pytest).
python_install_package() {
  local pkg="$1"
  local label="$2"

  # Check if already installed in active venv
  if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/$pkg" ]; then
    echo "  $label ($pkg) -- already installed (venv)"
    return
  fi

  # Check system PATH
  if command -v "$pkg" &>/dev/null; then
    echo "  $label ($pkg) -- already installed"
    return
  fi

  # Prompt (skip in non-interactive environments)
  local answer=""
  [ -t 0 ] && read -rp "  $label ($pkg) not found. Install? [Y/n]: " answer
  if [[ "$answer" =~ ^[Nn]$ ]]; then
    echo "  WARNING: $pkg not installed. To enable:" >&2
    echo "    Ubuntu: apt install pipx && pipx install $pkg" >&2
    echo "    macOS:  brew install pipx && pipx install $pkg" >&2
    return
  fi

  # Try venv pip
  if [ -n "${VIRTUAL_ENV:-}" ]; then
    if "$VIRTUAL_ENV/bin/pip" install "$pkg" 2>/dev/null; then
      echo "  $label ($pkg) -- installed via venv pip"
      return
    fi
  fi

  # Try uv
  if command -v uv &>/dev/null; then
    if uv tool install "$pkg" 2>/dev/null; then
      echo "  $label ($pkg) -- installed via uv"
      return
    fi
  fi

  # Try pipx
  if command -v pipx &>/dev/null; then
    if pipx install "$pkg" 2>/dev/null; then
      echo "  $label ($pkg) -- installed via pipx"
      return
    fi
  fi

  # All attempts failed
  echo "  WARNING: $pkg not installed. To enable:" >&2
  echo "    Ubuntu: apt install pipx && pipx install $pkg" >&2
  echo "    macOS:  brew install pipx && pipx install $pkg" >&2
}

install_if_missing() {
  local cmd="$1"
  local install_cmd="$2"
  local label="$3"
  if ! command -v "$cmd" &>/dev/null; then
    answer=""
    [ -t 0 ] && read -rp "  $label ($cmd) not found. Install? [Y/n]: " answer
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
      python_install_package "black" "Formatter"
      python_install_package "ruff" "Linter"
      python_install_package "pytest" "Test runner"
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

# Update .gitignore (skip for --global to avoid silently writing ~/.gitignore)
if ! $GLOBAL; then
  if [ -f "$TARGET_DIR/.gitignore" ]; then
    if ! grep -q ".claude/command-log.txt" "$TARGET_DIR/.gitignore"; then
      echo ".claude/command-log.txt" >> "$TARGET_DIR/.gitignore"
      echo ""
      echo "Added .claude/command-log.txt to .gitignore"
    fi
  else
    echo ".claude/command-log.txt" > "$TARGET_DIR/.gitignore"
    echo ""
    echo "Created .gitignore with .claude/command-log.txt"
  fi
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
