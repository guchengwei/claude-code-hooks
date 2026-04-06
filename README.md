# Claude Code Hooks Starter Kit

Drop-in hooks for Claude Code that enforce code quality, block dangerous commands, and automate common tasks. Works with Node.js, Python, Go, and Rust projects.

## Prerequisites

- **bash** 4+
- **jq** — required for `--global` installs and settings merging (`apt install jq` / `brew install jq`)

## Quick Start

```bash
# Clone this repo (fork first if you want to customize hooks)
git clone https://github.com/guchengwei/claude-code-hooks ~/claude-code-hooks

# Install into your project — run from inside your project, not from this repo
cd /path/to/your-project
~/claude-code-hooks/install.sh .

# Or install globally (applies to all projects; requires jq)
~/claude-code-hooks/install.sh --global

# Start Claude Code
claude
```

> **Note:** Do not open the `claude-code-hooks` directory itself in Claude Code. Run `install.sh` from your target project directory.

## What's Included

| Hook                      | Type                     | What It Does                                                                           |
| ------------------------- | ------------------------ | -------------------------------------------------------------------------------------- |
| `block-dangerous.sh`      | PreToolUse (Bash)        | Blocks `rm -rf`, `git reset --hard`, `git push --force`, `DROP TABLE`, piped curl/wget |
| `protect-files.sh`        | PreToolUse (Edit/Write)  | Blocks edits to `.env`, lock files, `.pem`, `.key`, `secrets/`                         |
| `require-tests-for-pr.sh` | PreToolUse (PR creation) | Runs all test suites before allowing PR creation                                       |
| `format-file.sh`          | PostToolUse (Write/Edit) | Auto-formats files by extension (prettier, black, gofmt, rustfmt)                      |
| `lint-file.sh`            | PostToolUse (Write/Edit) | Auto-lints files by extension (eslint, ruff)                                           |
| `run-tests.sh`            | PostToolUse (Write/Edit) | Runs all detected test suites after each edit                                          |
| `log-commands.sh`         | PreToolUse (Bash)        | Logs all commands with timestamps to `.claude/command-log.txt`                         |
| `auto-commit.sh`          | Stop                     | Auto-commits all changes when Claude stops                                             |

## Multi-Language Support

The installer auto-detects your project's languages and configures the right tools:

| Language | Formatter | Linter        | Test Runner |
| -------- | --------- | ------------- | ----------- |
| Node.js  | prettier  | eslint        | npm test    |
| Python   | black     | ruff          | pytest      |
| Go       | gofmt     | golangci-lint | go test     |
| Rust     | rustfmt   | clippy        | cargo test  |

For multi-language projects (e.g. Node + Python), all tools are configured simultaneously. Hook scripts dispatch by file extension.

## Blank Projects

If no language markers are found, the installer asks which languages you plan to use and sets up tools accordingly. Choose "skip" to install only safety hooks.

## Customization

### Disable a specific hook

Remove or comment out the corresponding entry in `.claude/settings.json`.

### Add your own patterns to block-dangerous.sh

Edit `.claude/hooks/block-dangerous.sh` and add patterns to the `dangerous_patterns` array.

### Add protected files

Edit `.claude/hooks/protect-files.sh` and add patterns to the `protected` array.

## How Hooks Work

- **PreToolUse**: Runs before Claude performs an action. Exit code 2 blocks the action.
- **PostToolUse**: Runs after Claude performs an action. Used for formatting, linting, testing.
- **Stop**: Runs when Claude finishes a task. Used for auto-committing.

Configuration lives in `.claude/settings.json`. See [Claude Code Hooks Documentation](https://docs.anthropic.com/en/docs/claude-code/hooks) for details.

## Credits

Based on [8 Claude Code Hooks That Automate What You Keep Forgetting](https://x.com/zodchiii/status/2040000216456143002) by @zodchiii.
