# Ardoise V1 — Risk Register

**Canonical source**: `docs/implementation/backlog/ardoise-v1-backlog.yaml` (`risks:` block)
**Last updated**: 2026-07-24
**This file**: Human-readable mirror. Keep in sync with the YAML.

---

## R-001 — Cleartext window in analysed mode during ICAP analysis

| Property | Value |
|---|---|
| **Severity** | MEDIUM |
| **Source** | `docs/dat.md` Annexe A.3-1 |
| **Origin sprint** | ARDOISE-0005 (Analysed Mode) |
| **Resolution** | **Accepted residual** — Architecture (ADR-004, ADR-011) |

**Description**: In analysed mode, content is in cleartext in server memory
during the ICAP analysis window. A server compromise during this window
exposes contents in transit.

**Mitigations**:
- ICAP timeout bounds the cleartext window
- No cleartext written to disk at any point
- Server hardening per PA-022 (HE-1)
- Key erased from server memory after response

**Acceptance rationale**: This is a structural property of R58 compliance.
An ICAP-gated system *must* see cleartext to submit it for analysis.
The alternative (no analysis) is not compliant with R58. The window is
minimized by design and documented for the homologation dossier.

---

## R-002 — Go GC may retain key material copies despite explicit erasure

| Property | Value |
|---|---|
| **Severity** | LOW |
| **Source** | `docs/dat.md` Annexe A.3-2 |
| **Origin sprint** | ARDOISE-0002 (Blind Mode) |
| **Resolution** | **Accepted residual** — Architecture (Annexe B, hygiene memoire) |

**Description**: Go's garbage collector does not guarantee absence of
residual copies of key material after explicit zeroing.

**Mitigations**:
- Key material handled in dedicated `[]byte` buffers, never converted to `string`
- Explicit zeroing after use (best-effort)
- Environment hardening: server on dedicated admin infrastructure (HE-1),
  client on hardened admin workstations (HE-2)

**Acceptance rationale**: Complete memory hygiene in a GC language is
impractical. The established mitigations represent the industry best
practice for Go cryptographic applications. Residual risk is low given
the hardened deployment environment.

---

## R-003 — Identifier transmission channel is out of scope

| Property | Value |
|---|---|
| **Severity** | MEDIUM |
| **Source** | `docs/dat.md` Annexe A.3-3 |
| **Origin sprint** | ARDOISE-0002 (Blind Mode) |
| **Resolution** | **Accepted residual** — Architecture (Annexe A.3-3) |

**Description**: The channel by which the emitter transmits the identifier
to the recipient is outside the product's perimeter. An intercepted
identifier grants content access until expiry.

**Mitigations**:
- CHIF-1 (password complement) neutralizes this risk: two secrets required
- TTL bounds limit the exposure window
- Burn-after-reading destroys content after first access
- Manual section warns users: "L'identifiant contient la cle... il se
  transmet par un canal maitrise"

**Acceptance rationale**: The product cannot control human communication
channels. It provides warnings, short TTL defaults, and optional password
protection. The residual risk is a user responsibility documented in the manual.

---

## R-004 — Client cache survival after server destruction (CACHE-2, CACHE-3)

| Property | Value |
|---|---|
| **Severity** | MEDIUM |
| **Source** | `docs/dat.md` Annexe A.3-4, ADR-013 |
| **Origin sprint** | ARDOISE-0007 (Client Features) |
| **Resolution** | **Accepted residual** — Architecture (ADR-013, §5.9) |

**Description**: When client-side caching is enabled (CACHE-2, CACHE-3),
content survives on the recipient's host after server-side destruction.
The disappearance guarantee then depends on host expiry enforcement and
hardening (HE-2).

**Mitigations**:
- Cache contains only ciphertext (key stays in identifier, never written)
- CACHE-2 enforces expiry aligned with ardoise TTL
- Server must explicitly authorize caching (ADR-013)
- CACHE-3 excluded from regulated contexts (§6.1, §6.2)

**Acceptance rationale**: The cache enables a valuable ergonomic property
(server-side burn-after-reading without data loss on replay) while
introducing no new secret at rest. The residual risk is bounded and
documented. Regulated deployments can disable caching entirely (CACHE-1).

---

## R-005 — Declarative identification (AUTH-4) is forgeable

| Property | Value |
|---|---|
| **Severity** | MEDIUM |
| **Source** | `docs/dat.md` Annexe A.3-5, ADR-005, ADR-009 |
| **Origin sprint** | ARDOISE-0004 (Transport & Auth) |
| **Resolution** | **Accepted residual** — Architecture (ADR-005, ADR-009) |

**Description**: Under AUTH-4, the identity recorded in journals is
self-declared by the client and not verified. Any client authorized to
reach the instance can falsify their identity.

**Mitigations**:
- AUTH-4 restricted to blind mode on air-gapped, filtered admin networks
- Journals explicitly mark AUTH-4 entries as "declarative" (ADR-005)
- Not admissible in regulated contexts (II 901 minimum: AUTH-3; IGI 1300 minimum: AUTH-2)
- Network access control serves as the de facto barrier (HE-1, HE-4)

**Acceptance rationale**: AUTH-4 exists as the lowest-cost deployment
option for entities without PKI or identity services. It is explicitly
documented as non-authenticating and excluded from regulated contexts.
The graduated options matrix (§5.2) lets each entity choose the level
appropriate to their risk analysis.

---

## R-006 — Qindu AGPL-3.0 license incompatibility

| Property | Value |
|---|---|
| **Severity** | **HIGH** |
| **Source** | `docs/dat.md` ADR-012 |
| **Origin sprint** | ARDOISE-0007 (Client Features) |
| **Resolution** | **Pending legal** — dual-license bridge required |
| **Blocks** | ARDOISE-0007 (secrets detection feature) |

**Description**: The Qindu secrets-detection engine is licensed AGPL-3.0,
which requires derivative works to also be AGPL-3.0. This is incompatible
with Ardoise's Apache 2.0 + Commons Clause license (ADR-012). Until a
dual-license bridge is established by the rights holder, the Qindu engine
cannot be incorporated into the Ardoise binary under the project license.

**Mitigations**:
- Rights holder is the same author (tarek) — no third-party negotiation needed
- The feature can be implemented with a stub/interface until the bridge is resolved
- Sprint ARDOISE-0007 can proceed with the secrets detection interface and
  a no-op backend, with Qindu integration gated on license resolution

**Acceptance rationale**: Not yet accepted — this is a blocking risk for
the full secrets detection feature. The sprint can partially proceed
(interface, CLI flags, modes) without the actual detection engine.

---

## R-007 — ADR-014(b) double approbation deferred to V2

| Property | Value |
|---|---|
| **Severity** | LOW |
| **Source** | `docs/dat.md` ADR-014, `docs/man.md` FONCTIONS RESERVEES |
| **Origin sprint** | N/A (not in V1) |
| **Resolution** | **Deferred to V2** — Sprint planning (2026-07-24) |

**Description**: Double approbation (four-eyes content release, requiring
two distinct authenticated identities to approve before content is served)
is documented as a reserved feature and proposed in ADR-014 but explicitly
excluded from V1 scope.

**Impact**: No two-person release enforcement exists in V1. A single
authorized user can retrieve any ardoise for which they possess the
identifier (and meet --pour restrictions if configured).

**Acceptance rationale**: The feature adds significant server-side
complexity (approval workflow, state management, journal extension)
for a narrow use case. It is explicitly documented as reserved/under
study. V1 focuses on the core pastebin functionality with cryptographic
and access-control protections.

---

## Risk Matrix

| Risk | Severity | Status | Blocks Sprint |
|---|---|---|---|
| R-001 | MEDIUM | Accepted | — |
| R-002 | LOW | Accepted | — |
| R-003 | MEDIUM | Accepted | — |
| R-004 | MEDIUM | Accepted | — |
| R-005 | MEDIUM | Accepted | — |
| R-006 | **HIGH** | Pending | ARDOISE-0007 |
| R-007 | LOW | Deferred (V2) | — |

---

## Reconciliation Notes

- **All risks sourced from** `docs/dat.md` Annexe A.3 (risques residuels acceptes)
  and architectural decisions (ADR-012, ADR-014).
- **R-006 is the only HIGH severity risk** and the only one blocking a sprint.
  It requires action before the Qindu engine can be integrated.
- **No risks have been added from sprint closures** — no sprints have been
  executed yet. This register will be updated at each sprint closure per
  the Risk Register Governance rules in `AGENTS.md`.
- **No orphaned or dangling risks exist** — the project is in pre-implementation.
