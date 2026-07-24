---
description: Liste les commandes disponibles et explique brièvement le workflow Ardoise.
agent: ardoise-orchestrator
---

# /ardoise-help

Displays all available Ardoise commands and explains the governance workflow.

## Available Commands

| Command | Description |
|---------|-------------|
| `/ardoise-next` | Find the next READY backlog item and launch a sprint |
| `/ardoise-sprint <ID>` | Start a full sprint cycle (grill-me → Design → DevSecOps → Peer → CISO/DPO → QA/Release → Integration → Closure) |
| `/ardoise-backlog-status` | Show macro project status with risk reconciliation |
| `/ardoise-backlog-refine` | Refine the backlog (YAML, roadmap, risks) |
| `/ardoise-gate` | Final validation gate before merging changes |
| `/ardoise-help` | Show this help |

## Governance Workflow

Ardoise uses a strict multi-agent model with a document-clerk orchestrator:

1. **Backlog refinement**: Items are drafted and refined in the canonical backlog.
2. **Status check**: Use `/ardoise-backlog-status` to see what's next.
3. **Launch sprint**: `/ardoise-next` finds the next READY item and starts the sprint.
4. **Sprint execution** (8 steps via `/ardoise-sprint`):
   - Grill-me interview (human design choices)
   - DPO + CISO write requirements
   - DevSecOps implements with tests
   - Peer Reviewer blank-slate code review (loop until MERGE_READY)
   - CISO + DPO security & data protection review
   - QA + Release quality & supply chain validation
   - Integration test (blind + analysed mode, encryption, TLS, ICAP)
   - Orchestrator writes closure (summary, not judgment)
5. **Final validation**: `/ardoise-gate` ensures nothing was missed before merging.

## Finding Resolution Rule

Every finding MUST be fixed or explicitly accepted by the reviewer who raised it. Orchestrator cannot override verdicts — regardless of severity.

## Project

Ardoise is an ephemeral text exchange service (pastebin interne) for administration teams. The same binary runs as client (`ardoise push`/`ardoise get`) and server (`ardoise serve`).

- Language: Go (static compilation, no runtime deps)
- Platform: Linux
- Key concerns: encryption (AES-256-GCM), TLS 1.3/mTLS, ICAP analysis, ANSSI-PA-022 compliance, II 901/IGI 1300, reproducible builds
