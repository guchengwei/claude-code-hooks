# Domain docs

This is a single-context repository.

## Before exploring

Read these sources when they exist:

- `CONTEXT.md` at the repository root
- Relevant architectural decisions under `docs/adr/`

If either source is absent, proceed silently. Domain-modeling workflows create them when terminology or decisions are resolved.

## Expected layout

```
/
├── CONTEXT.md
├── docs/
│   └── adr/
└── source directories
```

## Vocabulary

Use domain terms as defined in `CONTEXT.md` in issue titles, implementation plans, tests, and code.

If a needed concept is absent, reconsider whether it belongs to the domain or record the gap for domain-modeling work.

## Architectural decisions

If proposed work conflicts with an existing ADR, identify the conflict explicitly instead of silently overriding the decision.
