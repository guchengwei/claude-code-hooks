# Requirements: Installer UX Fixes

**Date:** 2026-04-06  
**Status:** Ready for planning  
**Scope:** Standard

---

## Problem

Six user-facing issues degrade the out-of-box experience:

1. The README quickstart contains a `<your-username>` placeholder that breaks the copy-paste install flow.
2. The global install (`--global`) silently fails because `settings.json` uses relative hook paths that resolve against the current working directory at runtime, not against `~/.claude/`.
3. The Python tool installer calls `pip install` directly, which is blocked on systems using externally-managed Python environments (PEP 668).
4. `run-tests.sh` (and other hook scripts) call test runners and formatters without checking if they exist, causing hook errors on projects where those tools aren't installed.
5. Cloning the repo and opening Claude Code inside it activates the repo's own hooks on itself, and running `install.sh .` from inside the repo installs into the repo rather than a target project.
6. `auto-commit.sh` (Stop hook) uses `set -euo pipefail` with no prerequisites check — it aborts if the current directory is not a git repo, if git identity is not configured, or if commit signing (e.g., `commit.gpgsign=true` with a key tied to gh auth) fails. The hook is meant to be best-effort but behaves as hard-required.

---

## Goals

- Users can follow the README quickstart without editing the URL.
- Global installs produce hooks that actually fire in every project.
- Python tool installation succeeds or fails with a clear, actionable message on modern Linux/macOS.
- Hook scripts degrade gracefully (visible notice, not an error) when a tool is absent.
- Users are protected from accidentally installing into the hooks repo itself.
- `auto-commit.sh` is best-effort: it commits when possible, skips gracefully when prerequisites are missing, and never interrupts a Claude Code session with an error.

---

## Non-Goals

- Auto-installing uv or pipx without user involvement (we won't run `apt install pipx` or `curl uv`). We will suggest the install command in the warning message, but not execute it.
- Supporting Python versions < 3.8.
- Changing hook behavior beyond graceful tool-absence handling.
- Fixing the fork-based update path (tracking upstream after forking is out of scope).

---

## Requirements

### 1. README: Fix canonical repo URL

**File:** `README.md`

Replace:

```
git clone https://github.com/<your-username>/claude-code-hooks ~/claude-code-hooks
```

With:

```
git clone https://github.com/guchengwei/claude-code-hooks ~/claude-code-hooks
```

Add a note after the clone line that users who want to customize hooks should fork first, then clone their fork instead.

**Acceptance criteria:**

- No placeholder text (`<...>`) remains in the quickstart section.
- The clone URL is copy-pasteable and points to the real repo.

---

### 2. Global install: generate absolute-path settings.json

**File:** `install.sh`

When `--global` is passed, after writing `~/.claude/settings.json` (whether via simple copy or jq merge), apply a second jq pass that rewrites all `.hooks[][][].command` values from relative to absolute paths.

The rewrite rule: any command starting with `.claude/hooks/` becomes `$HOME/.claude/hooks/<filename>`, with `$HOME` expanded to the actual home directory path at install time (e.g., `/home/nvidia/.claude/hooks/...`). Do not write shell variables like `$HOME` literally into JSON.

This second pass must run for **both** code paths:

- No existing settings.json → copy bundled file → rewrite paths
- Existing settings.json → jq merge → rewrite paths

**Implementation note:** The existing jq merge produces a merged document. The path rewrite is a separate subsequent operation on the merged output. Use `jq` to walk all `command` values and replace relative paths.

**Acceptance criteria:**

- After `install.sh --global`, all hook `command` values in `~/.claude/settings.json` are absolute paths (e.g., `/home/nvidia/.claude/hooks/block-dangerous.sh`).
- Re-running `install.sh --global` does not create duplicate hook entries (existing absolute paths are recognized as already-absolute and not re-prefixed).
- Opening Claude Code in any arbitrary directory causes global hooks to fire.

---

### 3. Python tool install: cascaded strategy

**File:** `install.sh` — Python section (currently lines 151–155)

Replace the bare `pip install` calls with a new `python_install_package` function that replaces the calls to `install_if_missing` for the Python block. The function preserves the existing interactive Y/n prompt behavior (gated on `[ -t 0 ]`). It tries in order:

1. **In venv** — if `$VIRTUAL_ENV` is set, use `pip install <package>` (safe, isolated)
2. **uv** — if `uv` is on PATH, use `uv tool install <package>`
3. **pipx** — if `pipx` is on PATH, use `pipx install <package>`
4. **Warn and suggest** — print a message: `"<package> not installed. To enable: run 'apt install pipx && pipx install <package>' (Ubuntu) or 'brew install pipx && pipx install <package>' (macOS), then re-run this installer."`

Apply this cascade to: `black`, `ruff`, `pytest`.

**Note:** `install_if_missing` for non-Python languages (Node: npm, Go: go, Rust: cargo) is unchanged; those tools ship with their respective toolchains and are not subject to PEP 668.

**Acceptance criteria:**

- Running `install.sh` on a system with externally-managed Python (no active venv, no uv, no pipx) prints a clear, actionable warning rather than a pip error.
- Running with an active venv installs into that venv.
- Running with uv or pipx available uses the appropriate tool.
- The Y/n install prompt is preserved for interactive sessions.

---

### 4. Hook scripts: guard tool existence before invoking

**Files:** `.claude/hooks/run-tests.sh`, `.claude/hooks/format-file.sh`, `.claude/hooks/lint-file.sh`

Each tool invocation must be guarded with a `command -v` check. If the tool is absent, print a one-line notice to stderr and skip silently (exit 0). Do not silently succeed with no output — the notice distinguishes "skipped because tool missing" from "ran and passed."

**Pattern for run-tests.sh:**

```bash
if [ -f pyproject.toml ]; then
  if command -v pytest &>/dev/null; then
    pytest --tb=short -q 2>&1 | tail -5
  else
    echo "[hooks] pytest not found — skipping Python tests" >&2
  fi
fi
```

Apply tool guards to:

- `run-tests.sh`: `pytest` (Python), `npm` (Node), `go` (Go), `cargo` (Rust)
- `format-file.sh`: `npx`/prettier (JS/TS), `black` (Python), `gofmt` (Go), `rustfmt` (Rust)
- `lint-file.sh`: `eslint` (JS/TS), `ruff` (Python)

**Note on `set -euo pipefail`:** If a tool is present but the invocation fails (e.g., tests fail, lint errors found), the hook should exit non-zero — that is the intended behavior. The guard only prevents the "command not found" case from erroring. Do not change `set -euo pipefail`.

**Acceptance criteria:**

- On a Python project with `pyproject.toml` but no `pytest` installed, the hook prints a skip notice to stderr and exits 0.
- On a JS project with no `npx` installed, format-file.sh exits 0 with a skip notice.
- When the tool is present and succeeds, behavior is unchanged.
- When the tool is present and fails (e.g., tests fail), the hook exits non-zero as before.

---

### 5. Installer: detect and warn on self-installation

**File:** `install.sh`, `README.md`

**Installer guard:** At the start of `install.sh`, before any installation steps, check whether `TARGET_DIR` resolves to the same directory as `SCRIPT_DIR`. If they are the same, print a clear warning and abort:

```
ERROR: You are installing into the hooks repo itself.
Run install.sh from your target project directory:
  cd /path/to/your-project
  ~/claude-code-hooks/install.sh .
```

**README guidance:** Add a note in the Quick Start section explaining that the repo directory should not be opened in Claude Code directly — the hooks are meant to be installed into other projects.

**Acceptance criteria:**

- Running `./install.sh .` from within the cloned repo prints the error and exits non-zero without modifying any files.
- Running `install.sh .` from a different directory proceeds normally.
- README Quick Start includes a note warning against opening the hooks repo in Claude Code.

---

### 6. auto-commit.sh: best-effort commit with prerequisite guards

**File:** `.claude/hooks/auto-commit.sh`

Make the Stop hook resilient to missing prerequisites. The hook should:

1. Check `git rev-parse --git-dir` — skip entirely if not inside a git repository
2. Check `git config user.email` — skip if git identity is not configured
3. Remove `set -euo pipefail` — the hook is a best-effort automation, not a gating check
4. Wrap `git commit` in `|| true` — commit failure (signing error, gh auth expired, pre-commit hook failure) is non-fatal and should not surface as a Stop hook error

The hook must still avoid creating empty commits (the existing `git diff --cached --quiet` guard is preserved).

**Acceptance criteria:**

- Running Claude Code in a non-git directory: Stop hook exits 0, no error shown
- Running with no `git config user.email`: Stop hook exits 0, no error shown
- Running with `commit.gpgsign=true` and an unavailable signing key: Stop hook exits 0 (commit silently skipped)
- Normal operation (git repo, identity set, no signing issues): auto-commit behaves as before

---

## Success Criteria

- A user on a clean Ubuntu 24.04 (externally-managed Python, no pipx/uv) can clone the repo, run `install.sh` against a target project, and see clear output — no pip errors. Python hook tools will not be auto-installed, but the user receives an actionable message telling them exactly what to run.
- A user running `install.sh --global` sees hooks fire when Claude Code is opened in an unrelated project directory.
- The README quickstart works end-to-end by copy-paste.
- A user who accidentally runs `install.sh` from within the repo gets a clear error instead of corrupting the repo's own hook config.
