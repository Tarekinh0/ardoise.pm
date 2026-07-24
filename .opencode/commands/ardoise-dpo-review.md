---
description: Revue DPO/protection des données du diff courant.
agent: ardoise-dpo
subtask: true
---

# /ardoise-dpo-review

DPO data protection review of the current diff. Verifies encryption integrity, key management, and data minimization.

## Mandatory Context
- `@docs/dat.md` (sections 9-10 for ADRs)
- `@docs/man.md`
- `@AGENTS.md`

## Workflow

1. Show `git diff --stat`.
2. Show `git diff`.
3. Analyze the diff for data protection concerns:
   - **Encryption**: AES-256-GCM with unique keys? `crypto/rand` for key/nonce generation?
   - **Key lifecycle**: Generation → usage → explicit erasure complete? No key material in logs?
   - **Blind mode**: Is cleartext encrypted before any network I/O? Server never sees cleartext?
   - **Analysed mode**: Is cleartext window bounded by ICAP timeout? Key erased from server after encryption?
   - **Logs**: Any content, keys, or identifiers in log messages? Only metadata journaled?
   - **Cache**: Does cache contain only encrypted blobs without keys? Policy respected?
   - **Marquage**: Automatic? Correct level? Never dependent on emitter discipline?
   - **TTL**: Enforced server-side? Expiry guarantees destruction?
   - **Test data**: Any real identifiers with embedded keys in test fixtures?
4. Produce verdict: **PASS** or **BLOCKED** only.
5. If BLOCKED, list the specific blocking points with references to ADRs or ANSSI-PA-022 recommendations.
