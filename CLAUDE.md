# Coding Agent Hooks

This repository contains a portable hook runtime with adapters for Claude Code, Codex, VS Code, and Gemini CLI.

## Hooks Overview

- **Safety**: shared destructive-command and protected-path policies
- **Quality**: opt-in, repository-configured commands scoped by changed file
- **Adapters**: agent-specific event normalization and response rendering

## Usage

Install the plugin or extension using the agent-native commands in `README.md`. Do not restore the legacy copy-and-merge installer.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues; external pull requests are not a triage surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the five default triage labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. See `docs/agents/domain.md`.
