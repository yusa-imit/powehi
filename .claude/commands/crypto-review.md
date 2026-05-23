---
description: Trigger a mandatory crypto review on specified files or the current branch diff. Delegates to crypto-reviewer agent.
arguments:
  - name: target
    description: File paths or "branch" to review current branch diff
    optional: true
---

# Crypto Review

Perform a mandatory cryptographic review.

## Steps

1. Determine the review target:
   - If `$ARGUMENTS` specifies files, review those files
   - If `$ARGUMENTS` is "branch" or empty, review `git diff main...HEAD` for crypto-related changes
2. Identify all files touching cryptographic code:
   - Files importing `openmls`, `opaque-ke`, or RustCrypto crates
   - Files in `crates/powehi-crypto/`
   - Files containing key generation, encryption, decryption, signing, or verification
3. Delegate to `crypto-reviewer` agent with the identified diffs
4. Report the VERDICT (pass / fail / needs-rework) and all findings
5. If fail or needs-rework, list required changes and route back to crypto-lead

## Non-negotiable
- This review cannot be skipped for any crypto-touching code
- "Trust me" is not an acceptable justification — demand RFC citations
