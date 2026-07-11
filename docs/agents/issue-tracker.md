# Issue tracker: GitHub

Issues and PRDs for this repository live as GitHub issues. Use the `gh` CLI for operations.

## Conventions

- Create: `gh issue create --title "..." --body "..."`
- Read: `gh issue view <number> --comments`
- List: `gh issue list --state open --json number,title,body,labels,comments`
- Comment: `gh issue comment <number> --body "..."`
- Add or remove labels: `gh issue edit <number> --add-label "..."` or `--remove-label "..."`
- Close: `gh issue close <number> --comment "..."`

Infer the repository from `git remote -v`; `gh` does this automatically inside the clone.

## Pull requests as a triage surface

External pull requests are not a request or triage surface. Do not include them in the issue triage queue.

## Skill operations

When a skill says “publish to the issue tracker,” create a GitHub issue.

When a skill says “fetch the relevant ticket,” run:

`gh issue view <number> --comments`

## Wayfinding operations

A wayfinding map is one GitHub issue with child issues representing its tickets.

- Label maps with `wayfinder:map`.
- Label child tickets with `wayfinder:<type>`.
- Prefer GitHub sub-issues and native issue dependencies.
- If those features are unavailable, use task lists and `Blocked by: #<number>` lines.
- Claim a ticket with `gh issue edit <number> --add-assignee @me`.
- Resolve it by commenting with the result and closing the issue.
