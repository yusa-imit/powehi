---
name: add-mls-test
description: Add an MLS security-invariant test (forward secrecy, post-compromise security, epoch ordering, KeyPackage single-use) using openmls. Use after MLS group/epoch code changes, before crypto-reviewer.
---

# Add an MLS invariant test

Delegate to `test-author` (or `mls-engineer` if the test needs new test harness plumbing). Crypto output still requires a `crypto-reviewer` pass afterwards (rule: crypto code is incomplete without review).

## Invariants worth a test (prd.md §1.3, §5.2)
- **Forward Secrecy**: after an epoch advances (commit), secrets from the prior epoch cannot decrypt messages of the new epoch; and corrupting the *current* ratchet key must still leave already-decrypted prior messages intact.
- **Post-Compromise Security**: after a member self-update commit, an attacker holding the pre-update leaf secret can no longer read new messages.
- **Epoch ordering / serialization**: two concurrent commits at the same epoch — only the first is accepted, the second gets CONFLICT (prd.md §4A.5, §5.4).
- **KeyPackage single-use**: consuming a KeyPackage twice fails; pool count decrements (prd.md §5.2.1, §10.1).
- **Welcome round-trip**: Alice creates a 2-member group, Bob processes the Welcome, both derive the same epoch secret.

## Rules
- Use the `openmls` API as-is. Never reach into private state to "force" a scenario — drive it through real commits/welcomes.
- Prefer `proptest` for round-trip properties (encrypt→decrypt over random plaintext/epoch sequences).
- Do NOT assert by exfiltrating plaintext through logs (rule: `no-plaintext-logging`). Assert on returned values.

## Done when
- `cargo nextest run -p powehi-crypto-wasm` (or the relevant crate) passes.
- The test names the RFC 9420 section it exercises in a comment.
- `crypto-reviewer` has been run on the diff.
