---
description: Start a development phase. Reads the phase DoD from prd.md, creates tasks, and delegates to the appropriate domain leads.
arguments:
  - name: phase_number
    description: Phase number (1-6)
---

# Start Phase $ARGUMENTS

You are beginning Phase $ARGUMENTS of the Powehi project.

## Steps

1. Read `/docs/prd.md` and find the Phase $ARGUMENTS Definition of Done (DoD)
2. Read `/docs/phases/phase-$ARGUMENTS/STATUS.md` to understand current state
3. Decompose the DoD into concrete, actionable tasks
4. For each task, determine the responsible domain lead:
   - Crypto/MLS/OPAQUE -> crypto-lead
   - Rust backend -> backend-lead
   - React frontend -> frontend-lead
   - Infrastructure -> infra-lead
5. Create a task list with dependencies
6. Present the plan to the user for approval before delegating
7. After approval, update STATUS.md to "In Progress" and begin delegation

## Important
- Default to single agent for tasks completable in <20 tool calls
- Crypto tasks MUST go through crypto-reviewer before completion
- Architectural changes MUST go through threat-model-checker
