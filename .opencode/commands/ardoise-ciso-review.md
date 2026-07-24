---
description: Revue CISO du diff courant.
agent: ardoise-ciso
subtask: true
---

# /ardoise-ciso-review

CISO security review of the current diff. Verifies security properties and ADR compliance.

## Mandatory Context
- `@docs/dat.md` (sections 9-10 for ADRs)
- `@docs/man.md`
- `@AGENTS.md`

## Workflow

1. Show `git diff --stat`.
2. Show `git diff`.
3. Analyze the diff for security:
   - **TLS**: Any changes to TLS configuration, mTLS, certificate validation, or épinglage?
   - **Crypto**: Any new cryptographic operations? Correct algorithms (AES-256-GCM, Argon2id) and key sizes?
   - **Key handling**: Is key material properly managed (`[]byte`, explicit erasure, no string conversion)?
   - **ICAP**: Changes to ICAP integration? Fail-closed enforced?
   - **Auth**: Changes to authentication mechanisms? AUTH-1 through AUTH-4 correctly implemented?
   - **Input validation**: New parsers or protocol handlers? Fuzzing needed?
   - **Memory**: Any risk of key material or cleartext being written to disk or swap?
   - **Dependencies**: New Go modules? Known vulnerabilities?
   - **CI/CD**: Changes to workflows? Secrets exposure?
   - **Network surface**: Any new listeners or endpoints?
4. Produce a short threat model if the change touches critical surfaces.
5. Identify unmet security requirements or missing tests.
6. Produce verdict: **PASS** or **BLOCKED** only.
