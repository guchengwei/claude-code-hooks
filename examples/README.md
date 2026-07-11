# Repository configuration example

Copy `agent-hooks.json` to `.agent-hooks.json` at the root of the repository.
Its declarative `safety.additional_protected_paths` rule applies immediately.
The example leaves `safety.strict_workspace` off. Set it to `true` only when
the agent is launched as a non-root user from a Git repository/worktree.
The `quality.after_write` command remains disabled until you review the copied
file and explicitly trust it.

For a source checkout of this project, run:

```bash
plugins/coding-agent-hooks/bin/agent-hooks trust --repository /path/to/repository
```

When the plugin is installed elsewhere, use the exact runtime path printed in
the hook's "Skipped untrusted repository quality commands" warning. Re-run the
trust command after changing any `quality.after_write` entry. Revoke it with:

```bash
plugins/coding-agent-hooks/bin/agent-hooks untrust --repository /path/to/repository
```

Trust records live outside the repository and contain the repository's
canonical path plus a digest of the executable configuration. This prevents
silent execution from an unreviewed repository config; it does not constrain a
process running as the same user that can modify the external trust store. Keep
the coding agent's sandbox and approval controls enabled.

Before launching an agent, run `agent-hooks doctor --cwd /path/to/repository`.
For stronger isolation, use an ephemeral clone or worktree with a project-only
mount, no host home/credential or Docker-socket mounts, and network/resource
limits. The direct-file path guard does not contain shell commands; keep the
native agent sandbox enabled.
