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
- allows lockfile changes;
- does not install dependencies;
- does not run formatters, linters, or tests unless configured;
- does not change Git identity, stage files, commit, push, or open pull requests;
- does not write command or transcript logs.

These checks are guardrails, not a security sandbox. Keep the agent's native approval and sandbox controls enabled.

## Repository configuration

Add `.agent-hooks.json` at the repository root to extend protected paths or opt into file-scoped quality commands:

```json
{
  "version": 1,
  "safety": {
    "additional_protected_paths": ["production/**"]
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

Only enable repository-defined quality commands in repositories you trust: they execute local programs with your user permissions.

## Portable interface

Agents without a bundled adapter can send normalized JSON to the runtime:

```bash
printf '%s' '{
  "schema": "agent-hooks/v1",
  "event": "before_tool",
  "cwd": "/path/to/project",
  "agent": "custom-agent",
  "tool": {"name": "shell", "command": "git status"}
}' | plugins/coding-agent-hooks/bin/agent-hooks handle --adapter canonical
```

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
