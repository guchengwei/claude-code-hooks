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
- does not run formatters, linters, or tests unless configured and explicitly
  trusted for the repository;
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
