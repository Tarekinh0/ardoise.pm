---
description: Permet à l'Orchestrateur d'affiner le backlog (YAML, roadmap, risques) sans toucher au code applicatif.
agent: ardoise-orchestrator
---

# /ardoise-backlog-refine

Allows the Orchestrator to refine the backlog (YAML, roadmap, risks) without touching application code.

## Usage
```
/ardoise-backlog-refine [args]
```

## Workflow

1. Read `@docs/implementation/backlog/ardoise-v1-backlog.yaml`.
2. Read `@docs/implementation/backlog/ardoise-v1-roadmap.md`.
3. Apply the requested changes:
   - Update item statuses (DRAFT → READY, READY → IN_PROGRESS, etc.).
   - Update dependencies.
   - Update or add risk entries.
   - Add new backlog items.
4. Ensure the YAML remains valid.
5. Never modify application code (`cmd/`, `internal/`, `pkg/`).

Respect the Definition of Ready and Definition of Done at all times.
