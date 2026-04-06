---
title: "fix: Installer UX Issues (URL, global paths, Python cascade, hook guards, self-install)"
type: fix
status: completed
date: 2026-04-06
origin: docs/brainstorms/installer-ux-fixes-requirements.md
---

# fix: Installer UX Issues

## Overview

Six bugs degrade the out-of-box experience for new users. This plan fixes them in a single focused pass: a placeholder README URL, silent global-install failure (relative hook paths never resolve outside `$HOME`), `pip install` failures on PEP 668 systems, missing tool-existence guards in `run-tests.sh`, accidental self-installation when running from inside the repo, and `auto-commit.sh` hard-aborting when git prerequisites (repo, identity, signing key) are missing.

## Problem Frame

See origin document for full context. Summary:

- `README.md` has a `<your-username>` placeholder in the clone URL
- `install.sh --global` copies `settings.json` with relative hook paths (`.claude/hooks/...`), which only resolve relative to the current working directory — so hooks never fire globally
- Python tools are installed with bare `pip install`, blocked by PEP 668 on modern Ubuntu/macOS
- `run-tests.sh` calls `pytest`/`npm`/`go`/`cargo` without checking if they exist; `set -euo pipefail` causes hard abort when the binary is missing
- Running `install.sh .` from inside the cloned repo installs into the repo itself
- `auto-commit.sh` has `set -euo pipefail` and no prerequisite checks — aborts (non-zero Stop hook exit) if not in a git repo, git identity is missing, or commit signing fails (e.g., `commit.gpgsign=true` with a gh-auth-dependent key)

## Requirements Trace

- R1. README clone URL is copy-pasteable and contains no placeholders
- R2. `install.sh --global` writes absolute hook paths in `~/.claude/settings.json`; hooks fire in any project directory
- R3. Python tool installation succeeds or produces an actionable warning on PEP 668 systems
- R4. Hook scripts exit 0 with a stderr notice (not an error) when a required tool is absent
- R5. Running `install.sh .` from inside the repo aborts with a clear message
- R6. `auto-commit.sh` is best-effort: skips when prerequisites are missing, never aborts a Claude session with an error

## Scope Boundaries

- `format-file.sh` and `lint-file.sh` already have `command -v` guards — they are out of scope for Unit 4
- Node, Go, Rust tool installers (`install_if_missing` calls) are unchanged — PEP 668 is Python-specific
- No changes to hook logic or behavior beyond tool-absence handling
- Fork-based update path is out of scope
- `lint-file.sh` missing Go linter invocation (`golangci-lint` installed but never called) is out of scope

## Context & Research

### Relevant Code and Patterns

- `install.sh:1-22` — arg parsing; `SCRIPT_DIR` set via `BASH_SOURCE[0]`; `TARGET_DIR` defaults to `.`, overridden to `$HOME` for `--global`
- `install.sh:125-139` — `install_if_missing(cmd, install_cmd, label)`: `command -v` check, tty-gated Y/n prompt, `eval "$install_cmd"`. Default is install (empty answer = yes)
- `install.sh:151-155` — three Python `install_if_missing` calls: `black`, `ruff`, `pytest`
- `install.sh:38-83` — four settings.json write branches: (A) no existing file → copy; (B) valid JSON exists → jq merge; (C) malformed JSON → prompt overwrite; (D) no jq → prompt overwrite
- `install.sh:168-177` — `.gitignore` update appends `.claude/command-log.txt` to `$TARGET_DIR/.gitignore`; runs even for `--global` (writes to `~/.gitignore`)
- `.claude/hooks/run-tests.sh` — no `command -v` guards; `set -euo pipefail` active; missing binary causes hard abort before `exit 0`
- `.claude/hooks/format-file.sh`, `lint-file.sh` — already guard each arm with `command -v ... &>/dev/null &&`; silently skip absent tools
- `.claude/settings.json` — all `command` values use relative paths (`.claude/hooks/...`)

### Key Edge Cases from Flow Analysis

- **Four settings.json write paths** — path rewriting must apply after all four, not just the merge branch
- **jq absent for `--global`** — rewrite requires jq; abort `--global` with a message if jq is not available
- **Python cascade must not rely on global `set -e` for fallthrough** — each install attempt must use `if ! <cmd>; then` to trap failures explicitly; the active global `set -euo pipefail` would abort the installer on any failed `eval` or command if not wrapped
- **Venv check** — when `$VIRTUAL_ENV` is set, check `$VIRTUAL_ENV/bin/<tool>` directly and use `$VIRTUAL_ENV/bin/pip install`; do not rely on system pip
- **Idempotent path rewrite** — anchor match to `startswith(".claude/hooks/")` so a second run does not double-prefix already-absolute paths
- **`$HOME` with spaces** — pass via `--arg home "$HOME"` in jq, never inline shell interpolation
- **Symlink resolution** — canonicalize `TARGET_DIR` with `realpath` and fall back to `cd -P ... && pwd` when `realpath` is absent (macOS without coreutils)
- **`.gitignore` for `--global`** — skip the `.gitignore` write step when `$GLOBAL=true`; writing to `~/.gitignore` silently is an unexpected side effect

## Key Technical Decisions

- **All four settings.json write paths → single post-write rewrite function**: rather than modifying each branch, add a `rewrite_global_paths` function called once after the settings block when `$GLOBAL=true`. This is the lowest-risk change — existing branch logic is untouched.
- **Abort `--global` if jq absent**: jq is already required for the merge path; making it a hard requirement for `--global` is consistent and prevents silent partial installs.
- **Python cascade uses explicit `if !` branching, not `set -e` suppression**: avoids global changes to error-handling mode; each install attempt is independently wrapped.
- **`$VIRTUAL_ENV/bin/pip` for venv install path**: more reliable than system `pip` inside an activated venv, avoids PEP 668 edge cases where distros patch pip even inside venvs.
- **`run-tests.sh` guard emits a stderr notice**: aligns with R4 requirement; distinguishes "skipped" from "passed" in hook output.
- **Self-detection uses `realpath` with `cd -P` fallback**: covers symlink edge cases without requiring coreutils on macOS.

## Open Questions

### Resolved During Planning

- **jq required for `--global`?** Yes — abort with message if jq absent. Consistent with existing merge dependency. (see origin: docs/brainstorms/installer-ux-fixes-requirements.md)
- **Python cascade error trapping**: Use `if ! <cmd> 2>/dev/null; then` for each install attempt. `set -e` remains active globally — this is safe because bash does **not** trigger `set -e` for commands inside an `if` conditional. The cascade works precisely because failures inside `if !` are explicitly tested and do not reach the global error handler.
- **Venv detection**: `$VIRTUAL_ENV` set → check `$VIRTUAL_ENV/bin/<tool>` directly; install via `$VIRTUAL_ENV/bin/pip`.
- **`.gitignore` for `--global`**: Skip entirely. Writing to `~/.gitignore` silently is unexpected.
- **Idempotency of path rewrite**: Match `.command | startswith(".claude/hooks/")` — already-absolute paths never match.

### Deferred to Implementation

- Exact jq expression for path rewrite — implementer validates against live settings.json structure. Directional sketch provided in Unit 5.
- Whether `run-tests.sh` should suppress test failure output on PostToolUse or just exit non-zero — current behavior (propagate failures) is intentional; only the "tool absent" case changes.

## High-Level Technical Design

> _This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce._

**Path rewrite flow (Unit 5):**

```
install.sh --global
  │
  ├── [existing] settings.json copy/merge block (4 branches)
  │     writes ~/.claude/settings.json with relative paths
  │
  └── [new] if $GLOBAL && jq present:
        rewrite_global_paths "$CLAUDE_DIR/settings.json" "$HOME"
          │
          └── jq --arg home "$HOME" '
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
              '
```

**Python cascade (Unit 3):**

```
python_install_package(pkg, label):
  $VIRTUAL_ENV set AND $VIRTUAL_ENV/bin/$pkg exists? → print "already installed (venv)", return
  command -v $pkg succeeds (system PATH)? → print "already installed", return
  interactive prompt [Y/n]? → N → return

  $VIRTUAL_ENV set?
    try $VIRTUAL_ENV/bin/pip install $pkg → success → return
                                          → fail → fall through

  uv available?
    try uv tool install $pkg → success → return
                              → fail → fall through

  pipx available?
    try pipx install $pkg → success → return
                           → fail → fall through

  print WARNING: "<pkg> not installed. To enable:"
        "  Ubuntu: apt install pipx && pipx install <pkg>"
        "  macOS:  brew install pipx && pipx install <pkg>"
```

## Implementation Units

- [ ] **Unit 1: Fix README URL and add usage guidance**

**Goal:** Replace `<your-username>` placeholder with the real repo URL; add fork note and warning against opening the repo in Claude Code.

**Requirements:** R1

**Dependencies:** None

**Files:**

- Modify: `README.md`

**Approach:**

- Replace clone URL with `https://github.com/guchengwei/claude-code-hooks`
- Add one-line fork note after the clone line: users who want to customize should fork first
- Add a note in the Quick Start section that the hooks repo directory itself should not be opened in Claude Code — run install.sh from the target project

**Patterns to follow:**

- `README.md` existing style (code blocks for commands, inline notes after steps)

**Test scenarios:**

- Test expectation: none — documentation-only change with no runtime behavior

**Verification:**

- `grep -n "your-username" README.md` returns no results
- Clone URL in README matches `git remote get-url origin`

---

- [ ] **Unit 2: Self-installation detection and `.gitignore` global skip**

**Goal:** Abort `install.sh` when `TARGET_DIR` resolves to the repo itself; skip `.gitignore` write for `--global`.

**Requirements:** R5

**Dependencies:** None (modifies top and bottom of `install.sh`)

**Files:**

- Modify: `install.sh`

**Approach:**

- After computing `TARGET_DIR` (line ~18), canonicalize it: try `realpath "$TARGET_DIR"` first; fall back to `(cd -P "$TARGET_DIR" 2>/dev/null && pwd)` for macOS without coreutils
- If canonicalization returns empty (directory does not yet exist), skip the self-detection check entirely — `mkdir -p` will create it later and it cannot be the repo root
- Compare canonicalized `TARGET_DIR` against `SCRIPT_DIR`; if equal, print error message and `exit 1`
- Error message should include the correct invocation: `cd /path/to/your-project && ~/claude-code-hooks/install.sh .`
- `.gitignore` block (lines 168-177): wrap in `if ! $GLOBAL; then ... fi` — skip entirely for global installs

**Patterns to follow:**

- `install.sh:4` — `SCRIPT_DIR` already uses the `cd + pwd` pattern for canonicalization
- Existing `[ -t 0 ]` guard style for conditional behavior

**Test scenarios:**

- Happy path: running `install.sh .` from `/tmp/myproject` proceeds normally (SCRIPT_DIR ≠ TARGET_DIR)
- Self-detection: running `install.sh .` from the repo root prints error and exits non-zero without creating any files
- Self-detection with relative path: `install.sh ../claude-code-hooks` from a sibling directory is also caught after canonicalization
- Global skip: running `install.sh --global` does not create or modify `~/.gitignore`
- Symlink: `TARGET_DIR` is a symlink pointing to the repo — canonicalization resolves it and triggers self-detection

**Verification:**

- Running `./install.sh .` from repo root exits non-zero with message containing the correct invocation
- Running `install.sh --global` leaves `~/.gitignore` unchanged

---

- [ ] **Unit 3: Python install cascade**

**Goal:** Replace bare `pip install` calls for Python tools with a cascaded installer that works on PEP 668 systems.

**Requirements:** R3

**Dependencies:** None (self-contained change to the Python install block)

**Files:**

- Modify: `install.sh`

**Approach:**

- Define a new `python_install_package(pkg, label)` function that replaces the three `install_if_missing` calls for the Python block
- Cascade order: `$VIRTUAL_ENV` set AND `$VIRTUAL_ENV/bin/<pkg>` exists → already installed in venv, return; system `command -v <pkg>` succeeds → already installed, return; prompt Y/n; `$VIRTUAL_ENV` set → venv pip; `uv` available → uv tool install; `pipx` available → pipx install; warn+suggest
- **Venv check is authoritative when `$VIRTUAL_ENV` is set**: check `$VIRTUAL_ENV/bin/<pkg>` before `command -v`. CI pipelines and tools like Poetry/Hatch set `$VIRTUAL_ENV` without activating it (no PATH update), so `command -v` would miss venv-installed packages.
- Each install attempt uses `if ! <cmd> 2>/dev/null; then` — never relies on `set -e` for cascade flow control
- On the warn path, print two-line suggestion with Ubuntu and macOS commands
- The `install_if_missing` function and its usage for Node/Go/Rust are unchanged
- **Assumption:** `python_install_package` assumes binary name equals package name (valid for `black`, `ruff`, `pytest`). Document this as a known limitation if the function is reused.

**Patterns to follow:**

- `install.sh:125-139` — `install_if_missing`: tty-gated Y/n prompt pattern (`[ -t 0 ] && read -rp ...`), default-yes logic (`[[ ! "$answer" =~ ^[Nn]$ ]]`)
- `install.sh:4` — `SCRIPT_DIR` cd+pwd pattern for robust path handling

**Test scenarios:**

- Happy path (venv): `$VIRTUAL_ENV` set, `$VIRTUAL_ENV/bin/black` exists → prints "already installed (venv)", no install
- Happy path (uv): no venv, `uv` on PATH → `uv tool install black` succeeds → prints success
- Happy path (pipx): no venv, no uv, `pipx` on PATH → `pipx install black` succeeds → prints success
- Externally-managed (Ubuntu 24.04 baseline): no venv, no uv, no pipx → prints warning with `apt install pipx` suggestion
- Venv install: `$VIRTUAL_ENV` set but `black` missing from it → `$VIRTUAL_ENV/bin/pip install black` succeeds
- uv network failure: `uv tool install black` exits non-zero → falls through to pipx check (does not abort installer)
- Non-interactive (CI, piped stdin): Y/n prompt is skipped; cascade runs automatically
- User declines (answers N): skips cascade and prints warn+suggest without attempting any install

**Verification:**

- On a system with only pipx available, `install.sh` completes without error and black/ruff/pytest are found in `pipx` list
- On a system with externally-managed Python and no uv/pipx, `install.sh` completes and prints actionable warnings (no pip errors in stdout/stderr)

---

- [ ] **Unit 4: `run-tests.sh` tool-existence guards**

**Goal:** Add `command -v` guards to all four test runner invocations in `run-tests.sh`; emit a stderr notice when skipping.

**Requirements:** R4

**Dependencies:** None (standalone file change)

**Files:**

- Modify: `.claude/hooks/run-tests.sh`
- Test: not applicable — hook behavior is tested manually or by running `claude` in a test project

**Approach:**

- For each manifest/runner pair (`package.json`/`npm`, `pyproject.toml`/`pytest`, `go.mod`/`go`, `Cargo.toml`/`cargo`), replace the single `&&`-chained line with an `if/else` block:
  - `if` manifest file exists AND `command -v <runner>` succeeds → run the test command
  - `else if` manifest exists but runner absent → `echo "[hooks] <runner> not found — skipping tests" >&2`
  - manifest absent → continue to next pair silently (no output)
- `set -euo pipefail` remains unchanged — if the tool IS found and tests fail, the hook still exits non-zero
- **Known pre-existing behavior:** `pytest ... 2>&1 | tail -5` with `pipefail` — `tail` always exits 0, so test failures are currently silently swallowed by the pipe. This is pre-existing and out of scope for this unit; do not change the pipe pattern.
- The existing `exit 0` at end of script is preserved

**Patterns to follow:**

- `.claude/hooks/format-file.sh` — already uses `command -v <tool> &>/dev/null &&` per arm; this is the established pattern
- The stderr notice format `[hooks] <msg>` is consistent with how hook output is typically distinguished from program output

**Test scenarios:**

- Happy path: `pyproject.toml` present, `pytest` on PATH → pytest runs, output truncated to 5 lines, exit code propagated
- Skip with notice: `pyproject.toml` present, `pytest` not on PATH → stderr notice emitted, exit 0
- No manifest: no `pyproject.toml` → nothing runs, no output, exit 0
- Failure propagation: `pytest` found but tests fail → hook exits non-zero (unchanged behavior)
- Multiple languages: project has both `package.json` and `pyproject.toml`, both tools present → both run

**Verification:**

- In a Python project without pytest installed: hook exits 0 and `[hooks] pytest not found` appears in stderr
- In a Python project with pytest installed and passing tests: hook exits 0 with test output
- In a Python project with pytest installed and failing tests: hook exits non-zero

---

- [ ] **Unit 5: Global install absolute path rewriting**

**Goal:** After writing `~/.claude/settings.json` for a global install, rewrite all relative hook command paths to absolute paths using `$HOME`.

**Requirements:** R2

**Dependencies:** Unit 2 (the self-detection logic sets up canonical `SCRIPT_DIR`/`TARGET_DIR` handling; also `.gitignore` skip is bundled there)

**Files:**

- Modify: `install.sh`

**Approach:**

- Add a `rewrite_global_paths(file, home_dir)` function that runs a jq in-place transform
- The transform matches `command` values starting with `.claude/hooks/` and replaces that prefix with `$home_dir/.claude/hooks/`
- Use `--arg home "$home_dir"` to pass the path; never interpolate `$HOME` directly into the jq program string
- Idempotency: the `startswith(".claude/hooks/")` guard means already-absolute paths are never touched
- **jq guard is a top-level early exit**: the jq availability check must occur at the very start of the `--global` code path — before `mkdir`, before any `cp`, before the settings block. Placement: immediately after `TARGET_DIR` is set to `$HOME` (around line 18). If `command -v jq` fails at that point, print the error and `exit 1`. Do NOT place this check inside `rewrite_global_paths` — by the time that function is called, files have already been written.
- After the entire settings.json block (all four branches have run and the file is on disk), call `rewrite_global_paths "$CLAUDE_DIR/settings.json" "$HOME"` if `$GLOBAL=true` (jq is guaranteed present by the early exit above)

**Directional jq sketch** _(directional guidance only)_:

```
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
```

**Patterns to follow:**

- `install.sh:52-66` — existing jq merge uses `jq -s` and pipes to a variable before writing; same pattern (write to `.tmp`, then `mv`) is safer than in-place with `sponge`
- `install.sh:39-41` — `jq empty` validity check pattern; same idiom for jq availability check

**Test scenarios:**

- Happy path: `install.sh --global` on clean system → `~/.claude/settings.json` written with all `command` values as absolute paths (e.g., `/home/nvidia/.claude/hooks/block-dangerous.sh`)
- Idempotency: running `install.sh --global` twice → paths are not double-prefixed on second run
- Merge path: existing `~/.claude/settings.json` with custom hooks → merged result has absolute paths for all bundled hooks, custom hooks preserved
- jq absent: `install.sh --global` without jq → exits with actionable message before writing any files
- `$HOME` with spaces: home directory path containing spaces → paths in JSON are correctly quoted and functional
- Malformed existing settings: branch C (overwrite after malformed) → rewrite pass still runs on the overwritten file

**Verification:**

- `jq '.hooks | .. | objects | select(has("command")) | .command' ~/.claude/settings.json` returns only absolute paths
- Opening Claude Code in `/tmp/testproject` (unrelated directory) triggers `block-dangerous.sh` on a `Bash` tool use

- [ ] **Unit 6: `auto-commit.sh` best-effort hardening**

**Goal:** Make the Stop hook resilient to missing git prerequisites; prevent it from surfacing errors in the Claude Code session when conditions for committing aren't met.

**Requirements:** R6

**Dependencies:** None (standalone file change)

**Files:**

- Modify: `.claude/hooks/auto-commit.sh`

**Approach:**

- Remove `set -euo pipefail` — the hook is best-effort automation, not a gating check
- Add `git rev-parse --git-dir &>/dev/null || exit 0` as the first guard — skip entirely if not in a git repo
- Add `git config user.email &>/dev/null || exit 0` as the second guard — skip if git identity is not configured
- Wrap `git commit` in `|| true` so signing failures, pre-commit hook failures, or auth errors are non-fatal
- Preserve the `git diff --cached --quiet` guard to avoid empty commits
- `git add -A` must be explicitly error-handled: use `git add -A || { echo "[auto-commit] git add failed, skipping" >&2; exit 0; }` — silent failure here could leave a stale partial staging that persists across sessions and causes a phantom commit of wrong content

**Patterns to follow:**

- `.claude/hooks/run-tests.sh` after Unit 4 — same philosophy of graceful skip with guard checks

**Test scenarios:**

- Not a git repo: running Stop hook in `/tmp` exits 0 with no output
- No git identity (`git config user.email` unset): hook exits 0, no commit attempted
- Valid git repo with identity, no staged changes: hook exits 0, no commit (empty-commit guard preserves this)
- Valid git repo with identity and staged changes: `git add -A && git commit` runs, commit is created
- Commit signing failure (`commit.gpgsign=true`, key unavailable): `git commit` fails, `|| true` catches it, hook exits 0

**Verification:**

- `cd /tmp && claude` (or simulate Stop hook call) exits 0 without error output
- In a project with `commit.gpgsign=true` and no signing key: Stop event produces no error

---

## System-Wide Impact

- **Interaction graph:** `run-tests.sh` is a PostToolUse hook on `Write|Edit` — the guard change affects every file edit in any project with a test manifest. Format/lint hooks are unchanged.
- **Error propagation:** Tool-absent case now exits 0 (skip with notice) instead of non-zero (abort). Tool-present-but-failing still exits non-zero and surfaces to Claude Code as a hook error — this is intentional.
- **State lifecycle risks:** The `.tmp` → `mv` pattern for path rewriting is atomic on POSIX systems. Interrupted installs leave a `.tmp` file but do not corrupt the live `settings.json`.
- **Unchanged invariants:** `install_if_missing` function and all non-Python install calls are untouched. Project-scope install (no `--global`) writes settings.json with relative paths unchanged.
- **Integration coverage:** Global hook firing requires verifying end-to-end with a live Claude Code session in a directory that does not contain its own `.claude/settings.json`.

## Risks & Dependencies

| Risk                                                                                                      | Mitigation                                                                                                             |
| --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| jq `.hooks` structure changes in future settings.json versions                                            | Path rewrite targets known structure; new event types not in bundled file are unaffected (preserved by `with_entries`) |
| `realpath` absent on macOS without coreutils                                                              | `cd -P ... && pwd` fallback always present in bash                                                                     |
| `$VIRTUAL_ENV` set but venv deleted/corrupted                                                             | `$VIRTUAL_ENV/bin/pip` check will fail; cascade falls through to uv/pipx naturally                                     |
| `uv tool install` and `pipx install` silently succeed but install to PATH not visible to hooks at runtime | Out of scope — same issue exists for existing `npm i -g` path; users must ensure PATH is configured                    |
| Python cascade changes the interactive prompt behavior unexpectedly                                       | New function mirrors `install_if_missing` prompt logic exactly; only the install command differs                       |

## Documentation / Operational Notes

- After this fix, global install requires `jq`. The README should note this dependency in the prerequisites section (can be added to Unit 1).
- The `.gitignore` skip for `--global` means command logs in globally-installed projects will not be gitignored automatically. Users who want this must add `.claude/command-log.txt` to their project's `.gitignore` manually.

## Sources & References

- **Origin document:** [docs/brainstorms/installer-ux-fixes-requirements.md](docs/brainstorms/installer-ux-fixes-requirements.md)
- Related code: `install.sh:38-83` (settings.json logic), `install.sh:125-139` (`install_if_missing`), `.claude/hooks/run-tests.sh`
- PEP 668: [https://peps.python.org/pep-0668/](https://peps.python.org/pep-0668/) — externally-managed Python environments
