# ADR-0001: MLS (RFC 9420) over Signal Protocol

## Status: Accepted

## Context
E2EE messaging requires a group key agreement protocol. The two main candidates are:
- Signal Protocol (Double Ratchet + Sender Keys)
- MLS (Messaging Layer Security, RFC 9420)

## Decision
Use MLS (RFC 9420) via the `openmls` Rust crate.

## Rationale
- **Licensing**: Signal Protocol reference implementation is AGPLv3 (copyleft). openmls is MIT/Apache.
- **WASM compatibility**: openmls compiles cleanly to wasm32-unknown-unknown. libsignal has C dependencies.
- **Standards-based**: MLS is an IETF RFC with formal security proofs. More future-proof.
- **Group efficiency**: MLS scales O(log n) for group operations vs O(n) for Sender Keys.
- **PQ readiness**: MLS ciphersuite negotiation makes PQ migration (ML-KEM) a ciphersuite swap.

## Consequences
- Must implement MLS Delivery Service (fan-out, ordering)
- More complex group state management (epochs, TreeKEM)
- Smaller ecosystem/community than Signal Protocol
