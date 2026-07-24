---
description: Affiche l'état macro du projet avec Risk Reconciliation obligatoire.
agent: ardoise-orchestrator
---

# /ardoise-backlog-status

Displays the macro status of the Ardoise project, including mandatory risk reconciliation.

## Workflow

1. Read `@docs/implementation/backlog/ardoise-v1-backlog.yaml`.
2. Read `@docs/implementation/backlog/ardoise-v1-roadmap.md`.
3. Generate a macro status report:
   - **Next READY item**: The next item that can be started.
   - **BLOCKED items**: List of BLOCKED items with reasons (dependencies, missing inputs).
   - **WAITING_INPUT items**: Items waiting for human decisions or inputs.
   - **IN_PROGRESS items**: Currently active sprints.
   - **DONE items**: Completed items.
4. Summarize progress against the roadmap phases.
5. Highlight any stalled or at-risk items.

## Risk Reconciliation (mandatory)

6. Cross-reference the risk register (`risks:` block in YAML) against all sprint closures:
   - **Orphaned risks**: Risks accepted but never assigned to a resolving sprint.
   - **Dangling risks**: Risks deferred to sprints that have been completed but were not addressed.
   - **Missing risks**: Risks present in closure documents but absent from the central register.
7. Flag any drift between `ardoise-v1-backlog.yaml` and `ardoise-risk-register.md`.
