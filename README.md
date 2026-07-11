# Coding Agent Hooks

Portable safety policies and opt-in quality automation for coding agents.

The project uses one policy runtime with thin adapters for each agent. Claude Code, Codex, and VS Code share a plugin package; Gemini CLI uses the same runtime through its extension hook format.

## Supported agents

| Agent | Packaging | Status |
| --- | --- | --- |
| Claude Code | Plugin marketplace | Supported |
| Codex | Plugin marketplace | Supported |
| VS Code agents / Copilot | Claude-compatible agent plugin | Supported preview |
| Gemini CLI | Gemini extension | Supported |
| Other agents | Canonical JSON command interface | Adapter-ready |

The runtime currently requires Python 3.10+ and a POSIX-compatible environment such as macOS, Linux, WSL, or Git Bash.

## Install

### Claude Code

```text
/plugin marketplace add guchengwei/claude-code-hooks
/plugin install coding-agent-hooks@coding-agent-hooks
```

Claude Code copies the plugin into its cache and keeps marketplace installations updateable. See the [Claude Code marketplace documentation](https://code.claude.com/docs/en/plugin-marketplaces).

### Codex

```bash
codex plugin marketplace add guchengwei/claude-code-hooks
codex plugin add coding-agent-hooks@coding-agent-hooks
```

Codex asks users to review and trust plugin hooks before running them.

### Gemini CLI

```bash
gemini extensions install https://github.com/guchengwei/claude-code-hooks
```

Restart Gemini CLI after installing or updating the extension.

### Local development

```bash
claude --plugin-dir ./plugins/coding-agent-hooks
codex plugin marketplace add .
gemini extensions link .
```

## Safe defaults

The installed plugin:

- blocks clear destructive commands such as recursive forced deletion, `git reset --hard`, forced pushes, and piping remote downloads into a shell;
- protects `.git/`, environment files, private keys, and `secrets/` paths;
- keeps direct filesystem-write tool targets inside the canonical Git workspace
  root (or the event working directory when no Git root exists);
- allows lockfile changes;
- does not install dependencies;
- does not run formatters, linters, or tests unless configured and explicitly
  trusted for the repository;
- does not change Git identity, stage files, commit, push, or open pull requests;
- does not write command or transcript logs.

These checks are guardrails, not a security sandbox. The direct-file boundary
does not contain shell commands or code executed by quality hooks. Keep the
agent's native approval and sandbox controls enabled.

## Workspace preflight and strict mode

Before launching an agent, inspect the current context:

```bash
plugins/coding-agent-hooks/bin/agent-hooks doctor --cwd "$PWD"
```

`doctor` checks that the working directory exists, is not `/`, `/root`, or the
current home directory, is inside a Git repository or worktree, and that the
trust store is outside the workspace. It also reports an effective root user
where the platform exposes that information. A reminder about the native
sandbox is always shown because a lifecycle hook cannot prove sandbox status.
Use `doctor --strict` to make a root effective user fail the preflight too.

The optional strict mutation profile rejects direct filesystem mutations from
root/home, a non-repository directory, or an effective root process. Enable it
declaratively with `"strict_workspace": true` under `safety`, or for a managed
launch with:

```bash
export AGENT_HOOKS_STRICT_WORKSPACE=1
```

The environment variable accepts `1/true/yes/on` and `0/false/no/off`. An
invalid value fails closed for direct mutations. An existing repository config
that is malformed, unreadable, or fails schema validation likewise blocks
direct filesystem mutations while leaving read-only events available with a
warning. Strict mode is off by default, so ordinary container environments that
intentionally run as root do not start failing silently. Hook handling remains
non-interactive.

For stronger isolation, use a dedicated non-root user where practical and an
isolated worktree or ephemeral clone. Mount only the project, not the host home,
SSH agent, cloud credentials, or Docker socket. Apply network allowlists and
CPU, memory, process, and runtime limits. A container with the host Docker
socket is not a meaningful security boundary. Shell commands still require the
agent's native sandbox; for untrusted code, use a hardened container or VM.

## Repository configuration

Add `.agent-hooks.json` at the repository root to extend protected paths or opt into file-scoped quality commands:

```json
{
  "version": 1,
  "safety": {
    "additional_protected_paths": ["production/**"],
    "strict_workspace": false
  },
  "quality": {
    "after_write": [
      {
        "name": "format-python",
        "include": ["*.py"],
        "command": ["python3", "-m", "ruff", "format", "{file}"],
        "timeout": 30
      }
    ]
  }
}
```

Quality commands are argument arrays, not shell strings. `{file}` and `{cwd}` are replaced before execution. Commands run from the event's repository working directory.
The [`examples/` workflow](examples/README.md) shows how to activate the bundled
example safely.

Declarative safety settings such as `additional_protected_paths` take effect
immediately. Repository-defined `quality.after_write` commands are skipped until
you explicitly trust their execution-bearing configuration. After reviewing the
file, run the exact trust command shown in the hook's skip warning. From a source
checkout, the equivalent command is:

```bash
plugins/coding-agent-hooks/bin/agent-hooks trust --repository "$PWD"
```

An explicitly supplied configuration requires the same recorded trust:

```bash
plugins/coding-agent-hooks/bin/agent-hooks trust \
  --repository /path/to/repository \
  --config /path/to/repository/agent-hooks.json
```

Trust is bound to the repository's canonical path and a SHA-256 digest of the
effective `quality.after_write` entries. Changing a command, include pattern,
name, timeout, or hook order makes the quality configuration untrusted until you
review and trust it again. Changing only declarative safety paths does not revoke
quality trust or prevent the new protections from applying.

Revoke trust at any time:

```bash
plugins/coding-agent-hooks/bin/agent-hooks untrust --repository "$PWD"
```

The trust store contains digests, not raw commands. It is written outside the
repository at `$XDG_CONFIG_HOME/agent-hooks/trusted-repositories.json` (or
`~/.config/agent-hooks/trusted-repositories.json`).
`AGENT_HOOKS_TRUST_STORE` can override that location for isolated tests or
managed deployments, but a location inside the repository is refused. Missing
or malformed trust state disables executable quality hooks without disabling
default or declarative safety rules. Trust-store updates use atomic replacement;
the file is mode `0600` on POSIX systems and otherwise relies on the platform's
best-effort per-user file protection.

This gate prevents a cloned repository from silently triggering its configured
quality commands. It is not a sandbox or a boundary against malicious code with
the same user identity: a process that can modify the external trust store can
bypass it. Run `trust` yourself outside agent-controlled execution, and keep the
agent's native approval, sandbox, and least-privilege controls enabled.

For `filesystem_write` events, every reported path is resolved relative to the
event working directory. Existing symlinks in the path are followed even when
the final descendants do not yet exist. Absolute paths, `..` traversal, symlink
escapes, and resolution failures outside the canonical workspace are denied.
Multi-file operations and `apply_patch` move destinations use the same check.
After-tool events with an outside target return feedback and do not run quality
commands; that feedback does not claim the already-attempted write was undone.
For patch events, boundary targets and quality targets are intentionally
separate: pre-tool policy and post-tool boundary checks retain deletes, move
sources, and move destinations, while post-tool quality commands receive only
surviving add/update paths and move destinations. A delete-only patch therefore
runs no quality command but is still workspace-checked.

This boundary applies only when an adapter reports direct-file targets. It
cannot constrain arbitrary paths embedded in `shell_execute`, subprocesses,
MCP servers, compilers, or repository code. Those remain the responsibility of
the native OS/container/VM sandbox.

## Portable interface

Agents without a bundled adapter can send normalized JSON to the runtime:

```bash
printf '%s' '{
  "schema": "agent-hooks/v1",
  "event": "before_tool",
  "cwd": "/path/to/project",
  "agent": "custom-agent",
  "tool": {
    "name": "shell",
    "effect": "shell_execute",
    "command": "git status"
  }
}' | plugins/coding-agent-hooks/bin/agent-hooks handle --adapter canonical
```

`tool.effect` is the stable shared-policy contract. Its valid values are:

- `filesystem_write` — a tool that creates, edits, moves, or deletes files;
- `shell_execute` — a tool that executes or monitors a shell command;
- `read_only` — a known non-mutating read or search tool;
- `unknown` — a tool without a recognized side effect.

Bundled adapters classify their platform-specific tool aliases at the outer
seam, before shared policy evaluation. Canonical callers should supply an
explicit effect. For backward compatibility, a missing or invalid effect is
classified from a known tool name and then from payload shape. An explicit
`unknown` also uses this fallback when the payload contains side-effect evidence:
an unknown tool with `command` is treated as `shell_execute`, while one with
`file` or `files` is treated as `filesystem_write`. Known read-only tools may
still read protected paths. Unknown tools without a command or file target remain
`unknown` and are allowed, so unrelated lifecycle events and MCP pings are not
blanket-blocked.

The canonical adapter returns:

- exit `0` with `{"decision":"allow"}`; or
- exit `2` with `{"decision":"deny","message":"..."}`.

Claude Code, Codex, VS Code, and Gemini adapters translate their lifecycle payloads and decision formats at the outer seam.

## Architecture

```text
agent payload
    -> adapter normalization
    -> canonical event
    -> shared safety and quality policy
    -> canonical decision
    -> agent-specific response
```

Distribution metadata lives outside the policy implementation:

- `.claude-plugin/marketplace.json` — Claude Code marketplace
- `.agents/plugins/marketplace.json` — Codex marketplace
- `plugins/coding-agent-hooks/` — shared Claude/Codex/VS Code plugin
- `gemini-extension.json` and `hooks/hooks.json` — Gemini extension adapter

## Migrating from `install.sh`

`install.sh` is retained only as a migration notice. It no longer copies hooks into projects, merges agent settings, installs developer tools, or changes Git configuration. Install from the appropriate marketplace or extension manager instead.

## Development

```bash
python3 -m unittest discover -s tests
python3 /home/nvidia/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/coding-agent-hooks
```

## License

MIT
