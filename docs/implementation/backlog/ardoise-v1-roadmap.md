# Ardoise V1 — Roadmap

**Canonical backlog**: `docs/implementation/backlog/ardoise-v1-backlog.yaml`
**Last updated**: 2026-07-24

---

## Overview

Ardoise V1 delivers a complete ephemeral text exchange service deployable as
an OCI container on Red Hat OpenStack. The same statically-linked Go binary
runs as client (`ardoise push`/`ardoise get`) and server (`ardoise serve`).

Two operational modes are delivered:
- **Blind mode**: end-to-end encryption — the server never sees cleartext.
- **Analysed mode**: ICAP analysis before encryption — for environments
  requiring content inspection (R58 compliance).

Ten sprints are organized into four phases.

---

## Phase 1: Core (Sprints 1–4)
**Delivers**: A working blind-mode pastebin with full lifecycle management,
TLS transport, and authenticated access.

| Sprint | Name | Key Deliverable |
|---|---|---|
| ARDOISE-0001 | Foundation | Go scaffold, TOML config, CLI, HTTP skeleton, --verifier, --politique, info |
| ARDOISE-0002 | Blind Mode | AES-256-GCM, Argon2id, CHIF-2/5/MD, push/get, identifier format, fingerprint |
| ARDOISE-0003 | Store & Lifecycle | RET-1/2/3, TTL-1/2/3, expiry sweep, burn-after-read, code 5 |
| ARDOISE-0004 | Transport & Auth | TLS-1/2/3, AUTH-1/2/3/4, mTLS, PKCS#11, tokens, code 6 |

Sprints 3 and 4 are parallelizable after Sprint 2.

**End-of-phase milestone**: A user can push encrypted text, get it back, and
have it automatically expire. Access is authenticated and TLS-protected.
The instance configuration is inspectable via `ardoise info`.

---

## Phase 2: Security Modes (Sprints 5–6)
**Delivers**: The second operational mode (analysed), journalisation, and
sensitivity marking. Regulatory compliance surface (II 901, IGI 1300).

| Sprint | Name | Key Deliverable |
|---|---|---|
| ARDOISE-0005 | Analysed Mode | ICAP client (RFC 3507), ANA-1/2, CHIF-4, fail-closed, R56, code 7 |
| ARDOISE-0006 | Journal & Marquage | JOURN-1/2/3/4, chainage, MARQ-1/2, metadata-only per ADR-005 |

**End-of-phase milestone**: Both operational modes work. In analysed mode,
content is submitted to ICAP before acceptance; in blind mode, the server
remains cryptographically blind. All operations are journaled with metadata
(never content), and sensitivity marking is automatic.

---

## Phase 3: Client & Advanced (Sprints 7–8)
**Delivers**: Client-side hardening, local cache, destinataires, and
multi-recipient encryption (ADR-014(a)).

| Sprint | Name | Key Deliverable |
|---|---|---|
| ARDOISE-0007 | Client Features | ANA-3 (secrets detection), CACHE-1/2/3, --pour, --verifier-empreinte, purge |
| ARDOISE-0008 | Multi-Recipient | ADR-014(a): key wrapping per recipient, server key registry, IGC integration |

**End-of-phase milestone**: The client detects secrets before push, caches
encrypted content locally (when allowed), restricts access to designated
recipients, and supports cryptographic multi-recipient encryption when a
key directory is available.

---

## Phase 4: Production (Sprints 9–10)
**Delivers**: Container image, CI/CD, supply chain security, reproducible
builds, offline distribution.

| Sprint | Name | Key Deliverable |
|---|---|---|
| ARDOISE-0009 | Container | Dockerfile (UBI micro, non-root, read-only rootfs), docker-compose, CI/CD |
| ARDOISE-0010 | Supply Chain | DIST-1/2, reproducible builds, binary signing, SBOM, SLSA, cosign, offline install |

**End-of-phase milestone**: V1 is shippable. The container image passes
security scans, the binary is signed with verifiable provenance, and the
entire product can be installed offline from a signed tarball.

---

## Sprint Dependency Graph

```
ARDOISE-0001 (Foundation)
    │
ARDOISE-0002 (Blind Mode)
    │
    ├── ARDOISE-0003 (Store & Lifecycle) ──┐
    │                                       │
    ├── ARDOISE-0004 (Transport & Auth) ────┤
    │                                       │
    └───────────────────────────────────────┤
                                            │
                                    ARDOISE-0005 (Analysed Mode)
                                            │
                                    ARDOISE-0006 (Journal & Marquage)
                                            │
                                    ARDOISE-0007 (Client Features)
                                            │
                                    ARDOISE-0008 (Multi-Recipient)
                                            │
                                    ARDOISE-0009 (Container)
                                            │
                                    ARDOISE-0010 (Supply Chain)
```

Sprints 0003 and 0004 are parallelizable.

---

## Deferred to V2

| Item | Reference |
|---|---|
| Double approbation (four-eyes release) | ADR-014(b), PO-6, R-007 |
| Threshold secret sharing (Shamir) | ADR-014 — explicitly excluded |
| AUTH-2 enforcement for IGI 1300 (AUTH-3 transitory) | §6.2 — transitory exception |
| Additional ICAP analysis engines beyond REQMOD | ADR-011 |

---

## Risk Summary

Seven risks are tracked in the central register. See `ardoise-risk-register.md`.

| Risk | Severity | Status |
|---|---|---|
| R-001 — Cleartext window (analysed mode) | MEDIUM | Accepted residual |
| R-002 — Go GC key material retention | LOW | Accepted residual |
| R-003 — Identifier transmission channel | MEDIUM | Accepted residual |
| R-004 — Client cache survival | MEDIUM | Accepted residual |
| R-005 — Declarative identification forgeable | MEDIUM | Accepted residual |
| R-006 — Qindu AGPL-3.0 license bridge | HIGH | Pending legal |
| R-007 — Double approbation deferred | LOW | Deferred to V2 |
