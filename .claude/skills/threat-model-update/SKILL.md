---
name: threat-model-update
description: Run a threat-model check on a proposed change and, if it shifts the security posture, update prd.md §3 and record an ADR. Use before merging any architectural change or new metadata exposure.
---

# Threat model update

Gate for architectural changes (operating principle: architecture changes must pass `threat-model-checker`).

## Steps
1. Gather the change: `git diff main...HEAD` (or the proposed design note).
2. Delegate to `threat-model-checker`. It returns an IMPACT MATRIX over T1–T7 (prd.md §3.1) + any newly server-visible metadata + a verdict (green / yellow / red).
3. Act on the verdict:
   - **green**: no doc change needed; proceed.
   - **yellow**: the change is acceptable but exposes something new or shifts a boundary → update prd.md §3.3 (metadata exposure limits) and/or §3.5 (multi-region threats). Then proceed.
   - **red**: block. The change weakens defense against a threat tier. Redesign and re-run.
4. If a real decision was made (e.g., accepting a new metadata leak with mitigation), add an ADR under `docs/decisions/NNNN-<slug>.md` and append to prd.md §16.7 change log (delegate to `doc-syncer`).

## Especially check (prd.md §3)
- T3 (malicious server operator): does the server now know something it didn't before?
- T7 (regional jurisdiction attacker): does cross-region forwarding now carry more than ciphertext envelopes + public KeyPackages?
- The "Out of Scope" list (§3.2): did anything silently move into it without justification?

## Done when
- `threat-model-checker` verdict is green, or yellow with the doc update applied.
- Any accepted trade-off is captured in an ADR + §16.7.
