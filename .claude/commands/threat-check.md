---
description: Run a threat model check on the current branch changes. Delegates to threat-model-checker agent to verify no degradation of security posture.
arguments:
  - name: scope
    description: "all" for full check, or specific area (e.g., "metadata", "auth", "storage")
    optional: true
---

# Threat Model Check

Verify that current changes do not weaken the Powehi threat model.

## Steps

1. Read the threat model from `/docs/prd.md` (threat tiers T1-T6)
2. Gather changes:
   - If on a feature branch: `git diff main...HEAD`
   - If scope is specified, focus on that area
3. Delegate to `threat-model-checker` agent with the changes and threat model context
4. Report the results:
   - IMPACT MATRIX for T1-T6
   - Any new metadata exposed
   - VERDICT: green / yellow / red
5. If yellow: list documentation updates needed
6. If red: block and explain what must be redesigned

## When to use
- Before any architectural change is merged
- After adding new API endpoints that handle user data
- After modifying authentication or authorization flows
- After changing what the server can observe about users
