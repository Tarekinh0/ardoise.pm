---
description: Lance un cycle complet de story Ardoise — grill-me → DPO/CISO → DevSecOps → Peer → CISO/DPO → QA/Release → Integration → Closure.
agent: ardoise-orchestrator
---

# /ardoise-sprint

Start a full sprint cycle for an Ardoise backlog item.

## Usage
```
/ardoise-sprint <ID>
```
Example: `/ardoise-sprint ARDOISE-0001`

## Mandatory Context
- `@AGENTS.md`
- `@docs/dat.md`
- `@docs/man.md`
- `@docs/implementation/backlog/ardoise-v1-backlog.yaml`
- `@docs/implementation/backlog/ardoise-v1-roadmap.md`

First, show current git status (`git status`).

## Workflow (8 steps — strictly sequential per AGENTS.md)

1. **Story Init**: Orchestrator uses the **grill-me** skill to interview the human about design choices, tradeoffs, and boundaries. Then writes `story.md` in `docs/implementation/sprints/<ID>/`.

2. **Design**: 
   - Invoke `ardoise-dpo` → `dpo-requirements.md`
   - Invoke `ardoise-ciso` → `ciso-requirements.md`
   - If either returns BLOCKED, produce `closure.md` with verdict BLOCKED and stop. Orchestrator may negotiate using cross-sprint context only.

3. **Implementation**: Invoke `ardoise-devsecops` with `story.md` + `dpo-requirements.md` + `ciso-requirements.md` + git diff. Writes code, tests, and `dev-notes.md`. Orchestrator provides zero code guidance.

4. **Peer Review**: Invoke `ardoise-peer-reviewer` with `story.md` + git diff only (blank-slate). No `dev-notes.md`, no requirements docs. If REJECT or FIX_AND_RESUBMIT, return to step 3. Loop 3→4 until MERGE_READY.

5. **Security & Data Protection Review**:
   - Invoke `ardoise-ciso` → `ciso-review.md` (story.md + git diff only)
   - Invoke `ardoise-dpo` → `dpo-review.md` (story.md + git diff only)
   - If BLOCKED by either, return to step 3. Orchestrator may negotiate using cross-sprint context only — never code.

6. **Quality & Release Validation**:
   - Invoke `ardoise-qa` → `qa-review.md` (story.md + git diff only)
   - Invoke `ardoise-release` → `release-review.md` if CI/CD, build, packaging, or release artifacts are affected (story.md + git diff only)
   - If BLOCKED by either, return to step 3.

7. **Integration Test**: Invoke `ardoise-integration-tester` with `story.md` + binary artifact + test instructions. Deploys the binary, runs blind and analysed mode tests, validates encryption, TLS, ICAP, marquage, journalisation, and purge. Writes `integration-test-report.md`. If BLOCKED, returns to step 3 and re-enters the full pipeline (steps 3→4→5→6→7).

8. **Closure**: Read all verdicts. If ALL gates say PASS (or MERGE_READY), produce `closure.md` — a summary, not a judgment. Update the risk register and backlog:
   - If PASS: set `status: DONE`, record `last_sprint_folder` and evidence
   - If BLOCKED: set `status: BLOCKED` and record `blocked_reason`
   - Extract findings, cross-reference risks, add new risks (MEDIUM+ or 2+ reviewers), sync `ardoise-risk-register.md`

## Reviewer Input Contract

Every reviewer receives exactly: `story.md` + git diff. Nothing else. No `dev-notes.md`, no code excerpts, no orchestration hints. (Peer Reviewer also receives existing `integration-test-report.md` on fix iterations.)

## Finding Resolution Rule

Every finding MUST be either fixed by DevSecOps or explicitly accepted by the reviewer who raised it. Orchestrator cannot accept on a reviewer's behalf — regardless of severity.

Never modify ADRs to make a story pass.
