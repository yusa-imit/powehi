# ADR-0003: Post-Quantum Migration Path (ML-KEM-768 + ML-DSA-65)

## Status: Active

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

## Current Implementation (Phase B Interim)

ML-KEM-768 is already deployed as a **Powehi-specific KeyPackage extension**
(extension type `POWEHI_PQ_KEM_EXT_TYPE`).  This is distinct from a native MLS
PQ ciphersuite — it runs alongside the classical X25519 MLS layer.

### What is live today

| Component | File | Status |
|---|---|---|
| ML-KEM-768 keygen / encap / decap | `crates/client/powehi-crypto-wasm/src/kem.rs` | **Deployed** |
| NIST ACVP FIPS 203 §6.2/§6.3 conformance KAT | `kem.rs` (cfg(test)) | **Passing** |
| PQ extension embed in KeyPackage | `wasm_exports.rs` `pq_build_payload` | **Deployed** |
| PQ encap key extraction + signature verification | `wasm_exports.rs` `mls_pq_extract_and_verify_encap_key` | **Deployed** |
| PQ shared-secret binding (HKDF-SHA256) | `wasm_exports.rs` `mls_pq_derive_binding` | **Deployed** |
| AcceptInviteModal PQ init send | `app/src/components/AcceptInviteModal.tsx` | **Deployed** |
| useMessages pq_init envelope handler | `app/src/hooks/useMessages.ts` | **Deployed** |

### Wire format of the PQ extension

Each KeyPackage carries a `POWEHI_PQ_KEM_EXT_TYPE` extension with a
`1,248`-byte payload:

```
bytes [0..1183]    — ML-KEM-768 encapsulation key  (1,184 bytes, FIPS 203 §5)
bytes [1184..1247] — Ed25519 signature over encap key (64 bytes; signer = MLS identity key)
```

The Ed25519 signature binds the ML-KEM key to the device's MLS credential,
preventing key substitution attacks.

### PQ binding derivation

When the initiator encapsulates to a peer's ML-KEM key:

```
shared_secret ← ml_kem_768_decapsulate(dk, ct)        // 32 bytes
binding ← HKDF-SHA256(
    ikm  = shared_secret,
    salt = None (all-zero, per RFC 5869 §3.3),
    info = b"powehi-pq-binding-v1" || group_id_utf8,
    L    = 8
)
binding_hex ← hex(binding)   // 16-char string displayed as safety number
```

Domain label `"powehi-pq-binding-v1"` is fixed; a breaking change requires a
new label.

### Opaque-handle invariant

The raw ML-KEM-768 decapsulation key (2,400 bytes) **never crosses the WASM-JS
boundary**.  It lives in `KEM_DECAP_KEYS` (thread-local `HashMap`) and is
accessed only by opaque string handle.  The handle is rotated after use and the
map entry is zeroized on drop.

---

## Decision

When `openmls` adds a stable `MLS_128_MLKEM768_AES128GCM_SHA256_MlDsa65`
ciphersuite, Powehi will complete the migration in three additional phases:

### Phase A — Native MLS PQ ciphersuite (dual-mode)

**Trigger:** `openmls` publishes a semver-stable release containing
`CiphersuiteName::MLS_128_MLKEM768_AES128GCM_SHA256_MlDsa65` (or the IANA
name once assigned).  The release must carry no open crypto-reviewer
objections.

**Changes required:**

1. **`Cargo.toml`** — bump `openmls` version; update `deny.toml` to require
   `ml-kem` and `ml-dsa` crates.
2. **`crates/client/powehi-crypto-wasm/src/wasm_exports.rs`** — add
   `create_group_pq(identity_id, group_id)` export alongside `create_group()`.
   New groups created by devices that hold a PQ-capable KeyPackage use the PQ
   ciphersuite.
3. **`crates/client/powehi-crypto-wasm/src/mls_group.rs`** — pass
   `MLS_128_MLKEM768_AES128GCM_SHA256_MlDsa65` to `MlsGroup::builder()` when
   PQ mode is active.
4. **`powehi-domain` `KeyPackage::validate()`** — accept both ciphersuites;
   reject neither.
5. **`powehi-rest-api` `KeyPackageService::upload()`** — log ciphersuite family
   (classical/pq) as an opaque metric label (no key material).
6. **Database** — `key_packages.data` column is `BYTEA` (unbounded); no schema
   change required.  Monitor average row size; a PQ KeyPackage is ~2,400 bytes
   (vs ~500 bytes classical).
7. **Client UI** — show "PQ-protected" badge when the active group uses the PQ
   ciphersuite.

**Rollout:** feature flag `POWEHI_PQ_MLS_NATIVE_ENABLED=true` (server env var).
Roll out to 1% → 10% → 100% of new group creations over 14 days.

**Rollback:** set `POWEHI_PQ_MLS_NATIVE_ENABLED=false`; server stops producing
PQ Welcome messages.  Existing PQ groups continue functioning; no decryption
regression.

**Transition window:** 90 days from `openmls` stable release.

---

### Phase B — Deprecate X25519 ciphersuite (warn + block new registrations)

**Trigger:** ≥ 95% of active sessions (last-seen within 30 days) are running
a client version that includes Phase A code.  Measured via `device_last_seen`
in Postgres + ciphersuite label in `key_packages.metadata` (opaque metric, no
content).

**Changes required:**

1. **`powehi-domain` `KeyPackage::validate()`** — return
   `DomainError::Validation("classical_ciphersuite_deprecated")` for new
   X25519-only uploads.  Existing stored packages remain valid.
2. **`powehi-rest-api` upload handler** — map deprecation error → HTTP 422 with
   body `{ "code": "classical_ciphersuite_deprecated" }`.
3. **In-band notice** — send an MLS Application message of type
   `{ "type": "system_notice", "code": "pq_migration_required" }` to groups
   that still have classical-only members.
4. **OPAQUE PQ** — the base `opaque-ke` `4.x` (RFC 9807) upgrade already landed
   (2026-07-19); this phase adopts its PQ-hybrid OPRF (X25519+ML-KEM-768) if
   stable by this phase.  All changes pass `crypto-reviewer` before merge.

**Rollback:** revert `validate()` change; classical uploads re-accepted.

---

### Phase C — X25519 fully removed

**Trigger:** ≤ 0.1% of active sessions (last-seen within 7 days) hold a
classical-only KeyPackage in the server store.  Confirmed by ops dashboard
query on `key_packages` table.

**Changes required:**

1. **`powehi-domain` `KeyPackage::validate()`** — hard-reject any non-PQ
   ciphersuite at parse time.
2. **`powehi-rest-api`** — remove all classical-ciphersuite code paths; update
   OpenAPI spec.
3. **`powehi-crypto-wasm`** — remove `create_group()` (classical) export alias;
   `create_group_pq()` becomes the only path.
4. **`deny.toml`** — add `deny = ["x25519-dalek"]` guard (safety net; openmls
   may still depend on it for signature verification of old groups during
   migration — audit before adding).
5. **DB cleanup** — scheduled job deletes `key_packages` rows with
   `ciphersuite = 'classical'` after 30-day grace period.

**Rollback:** Phase C is **irreversible** without a new client release.  Only
enter Phase C after a coordinated announcement and version-enforced client
upgrade gate.

---

## Size impact and budget

| Item | Classical | Phase A PQ | Delta |
|---|---|---|---|
| ML-KEM-768 encap key | 32 B (X25519) | 1,184 B | +1,152 B |
| ML-KEM-768 ciphertext (Welcome) | 32 B | 1,088 B | +1,056 B |
| ML-DSA-65 signature | 64 B (Ed25519) | 3,293 B | +3,229 B |
| ML-DSA-65 public key | 32 B | 1,952 B | +1,920 B |
| KeyPackage total (approx.) | ~500 B | ~8,000 B | ~16× |
| WASM binary increase | — | +30–40 KB (est.) | budgeted |

WASM bundle budget (current: 553 KB gz) must be re-validated at Phase A.
IndexedDB `key_packages` table row size limit: none (Dexie stores Uint8Array).
KeyPackage rotation interval may be reduced to limit store size growth.

---

## Implementation checklist

- [ ] **Phase A** — openmls PQ ciphersuite stable; dual-mode group creation
- [ ] **Phase A** — `create_group_pq()` WASM export + crypto-reviewer pass
- [ ] **Phase A** — `KeyPackage::validate()` dual-accept
- [ ] **Phase A** — feature flag `POWEHI_PQ_MLS_NATIVE_ENABLED`
- [ ] **Phase A** — WASM bundle size re-validated (< 800 KB gz)
- [ ] **Phase B** — 95% session threshold confirmed in metrics
- [ ] **Phase B** — classical upload deprecation (422)
- [ ] **Phase B** — in-band migration notice messages
- [x] **Base** — `opaque-ke` 3.0 → 4.0.1 RFC 9807 stable upgrade (done 2026-07-19)
- [ ] **Phase B** — `opaque-ke 4.x` PQ-hybrid OPRF (X25519+ML-KEM-768) upgrade (if stable)
- [ ] **Phase C** — 0.1% threshold confirmed
- [ ] **Phase C** — hard-reject classical + DB cleanup job
- [ ] **Phase C** — client version gate enforced

---

## OPAQUE PQ path

`opaque-ke 4.x` is the RFC 9807 stable release.  The base version upgrade —
`opaque-ke` `3.0` (draft-irtf-cfrg-opaque-16) → `4.0.1` (RFC 9807 stable) — is
**DONE** (2026-07-19): the server adapter and WASM client now run byte-for-byte
RFC 9807 on the same Ristretto255 + TripleDH(SHA-512) + Argon2id suite.  This
was independent of the PQ gate — it is just the RFC-stable base OPAQUE version,
not PQ-hybrid OPAQUE.

The separate, still-future upgrade is `opaque-ke` 4.x's **PQ-hybrid OPRF**
(X25519+ML-KEM-768 for the OPRF key exchange).  Adopting the PQ-hybrid ciphersuite
is a **Phase B item** and remains gated on the Phase B trigger; it will pass
`crypto-reviewer` before merge.

---

## Rationale

- **Harvest-now-decrypt-later** attacks on long-lived E2EE messages are already
  occurring.  Proactive migration is warranted even before a CRQC exists.
- ML-KEM-768 targets NIST Security Level 3 (comparable to AES-192 classical
  security), matching the 128-bit classical baseline of the current ciphersuite.
- Deploying ML-KEM-768 as a KeyPackage extension today (Phase B interim)
  protects the key-exchange component of group invites against retroactive
  decryption without waiting for `openmls` to ship a native PQ ciphersuite.
- Dual-ciphersuite period avoids a hard flag-day cutover.

## Consequences

- WASM binary size increases ~30–40 KB at Phase A (already `ml-kem` crate is
  compiled in for the extension layer; the native ciphersuite adds ML-DSA-65).
- KeyPackage store (Postgres + IndexedDB) row sizes grow ~16× at Phase A.
  Monitor and adjust rotation frequency accordingly.
- Users on very old / limited clients may need a forced web-reload before Phase C
  removes X25519 support.
- All crypto changes at each phase gate through the `crypto-reviewer` agent.
