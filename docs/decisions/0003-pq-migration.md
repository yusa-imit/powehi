# ADR-0003: Post-Quantum Migration Path (ML-KEM-768 + ML-DSA-65)

## Status: Proposed

## Context

Powehi uses MLS (RFC 9420) via `openmls` for group key agreement.  The default
ciphersuite today is `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, which
relies on X25519 (ECDH) for key encapsulation and Ed25519 for signatures.

Both algorithms are broken by Shor's algorithm on a sufficiently large quantum
computer (CRQC — Cryptographically Relevant Quantum Computer).  NIST
standardised three post-quantum algorithms in August 2024:

| Standard | Algorithm | Purpose |
|---|---|---|
| FIPS 203 | ML-KEM (CRYSTALS-Kyber) | Key encapsulation (replaces ECDH / X25519) |
| FIPS 204 | ML-DSA (CRYSTALS-Dilithium) | Signatures (replaces Ed25519 in MLS credentials) |
| FIPS 205 | SLH-DSA (SPHINCS+) | Stateless hash-based signatures (fallback) |

For OPAQUE (RFC 9807) the key-exchange component is X25519-RISTRETTO255 OPRF;
migration to an ML-KEM variant is tracked by the CFRG OPAQUE PQ draft.

## Decision

When `openmls` adds a `MLS_128_MLKEM768_AES128GCM_SHA256_MlDsa65` ciphersuite
(tracking: https://github.com/openmls/openmls/issues), Powehi will migrate in
three phases:

### Phase A — Hybrid dual-ciphersuite (add ML-KEM, keep X25519)
- New groups are created with the ML-KEM ciphersuite.
- Existing groups continue on X25519 until all members have migrated.
- KeyPackages advertise both ciphersuites; the MLS Welcome message selects the
  strongest suite both parties support.
- Transition window: 90 days from the `openmls` stable release.

### Phase B — Deprecate X25519 ciphersuite (warn + log)
- New registrations reject X25519-only KeyPackages.
- Existing X25519 groups receive an in-band migration notice.
- OPAQUE migration follows the CFRG PQ-OPAQUE draft once a stable crate exists.

### Phase C — X25519 removed
- Only ML-KEM-768 KeyPackages accepted.
- Server-side enforcement in `powehi-domain` `KeyPackage::validate()`.

## Implementation notes

- `powehi-crypto-wasm` (`wasm_exports.rs`): add `create_group_pq()` alongside
  `create_group()` in Phase A; swap the default in Phase B.
- `powehi-domain`: `CipherSuite` enum extended; `KeyPackage::validate()` gated.
- Migration is transparent to the application layer (MLS handles rekeying).
- All changes MUST pass the `crypto-reviewer` agent gate before merge.
- `deny.toml` will be updated to require `ml-kem` and `ml-dsa` once added.

## OPAQUE PQ path

`opaque-ke 4.x` (the RFC 9807 stable release) introduces a PQ-hybrid mode using
X25519+ML-KEM-768 for the OPRF key exchange.  Upgrade Powehi's `opaque-ke`
dependency from `3.0` → `4.x` when it stabilises (tracking issue in
`.claude/rules/crypto-libraries-pinned.md`).

## Rationale

- **Harvest-now-decrypt-later** attacks on long-lived E2EE messages are already
  occurring.  Proactive migration is warranted even before a CRQC exists.
- ML-KEM-768 targets NIST Security Level 3 (comparable to AES-192 classical
  security), matching the 128-bit classical baseline of the current ciphersuite.
- Dual-ciphersuite period avoids a hard flag-day cutover.

## Consequences

- `wasm` binary size will increase (~30–40 KB) when ML-KEM is added.
- WASM bundle budget (currently 553 KB) must be re-evaluated at Phase A.
- Users on very old / limited clients may need a web-based client update before
  Phase C removes X25519 support.
