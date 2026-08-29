# ADR-0004: Media-Key Local Persistence (sender/receiver symmetry)

## Status: Active

## Context

prd.md §9.2 media attachments are encrypted client-side with a fresh
AES-256-GCM key per attachment. The ciphertext goes to Cloudflare R2; the raw
32-byte key travels to the peers inside the MLS-encrypted application message
(RFC 9420 §6.3.1), never to the server.

Since cycle 309 both media paths use the opaque-handle pattern: the raw key
lives in the WASM thread-local `MEDIA_KEYS: RefCell<HashMap<String,
Zeroizing<[u8; 32]>>>` and JS only ever holds a string handle. But the two
directions are **not** symmetric, and that asymmetry has produced a
user-visible defect that has been deferred for roughly 30 cycles:

| | Sender (outgoing) | Receiver (incoming) |
|---|---|---|
| Where the key is born | inside WASM (`media_encrypt`) | inside the MLS-decrypted JSON payload, i.e. **in JS memory** |
| Does raw key enter JS? | **No** — only `mediaKeyHandle` | **Yes**, once, then `media_import_key(k)` + `k.fill(0)` |
| Persisted to Dexie? | **No** — `persistOutgoing` has no key to pass, so `MessageRow.mediaJson` is `undefined` | **Yes** — `persistIncoming` writes the same payload verbatim into `mediaJson` |
| Survives a reload? | **No** — permanent `"Image attachment"` placeholder | **Yes** — row rehydrates, blob is re-fetched from R2 and re-decrypted |

Relevant code:

| Concern | File |
|---|---|
| `MEDIA_KEYS` map, `media_encrypt`, `media_import_key`, `media_drop_key` | `crates/client/powehi-crypto-wasm/src/wasm_exports.rs` |
| Shared send/receive pipeline (`encryptAndSendMedia`, `downloadAndDecryptMedia`) | `app/src/lib/mediaTransfer.ts` |
| Sender hook | `app/src/hooks/useMediaSend.ts` |
| Dexie write path | `app/src/hooks/usePersistentMessages.ts` |
| At-rest field encryption (`mediaJson` is in the encrypted-field list) | `app/src/db/encrypted-db.ts` |
| `dbKey` derivation from the OPAQUE `export_key` | `app/src/workers/crypto.worker.ts` (`deriveDbKey`) |

The consequence is that a user's own sent photos/videos/voice notes are lost
from their own history on every reload, while the recipient keeps them. Because
`MessageRow.mediaJson` is already encrypted at rest by `EncryptedPowehiDb` under
`dbKey` (HKDF from the OPAQUE `export_key`, RFC 9807), the storage location for
the fix already exists and is already trusted with exactly this class of secret
— it is only the sender-side *key availability* that is missing.

Two directions were considered:

- **Option A** — add a one-shot WASM export that hands the raw key to JS at
  persist time only, mirroring what the receive path already does.
- **Option B** — add a WASM-side key-wrap primitive that seals a `MEDIA_KEYS`
  entry against a session-derived local secret without the raw key ever reaching
  JS, and persist the wrapped blob instead.

## Decision

**Option A.** Add a single new WASM export:

```rust
media_export_key_for_storage(media_key_handle: &str) -> { mediaKey: Uint8Array }
```

with these properties:

1. **Consuming (one-shot).** The entry is `remove`d from `MEDIA_KEYS` before the
   JS value is constructed. Its `Zeroizing<[u8; 32]>` buffer is zeroed on drop,
   so no WASM-side copy outlives the exported JS copy, and a second export of the
   same handle fails with `"unknown media key handle"`. Failure while building
   the JS object therefore *loses* the key rather than duplicating it — the
   caller degrades to the pre-ADR-0004 "no persisted payload" behaviour.
2. **Opt-in at the call site.** `encryptAndSendMedia` only calls it when the
   caller passes `{ exportKeyForPersistence: true }`, and `useMediaSend` only
   passes that when a `persistOutgoing` sink actually exists. Call sites with no
   persistence target (message forwarding in `ChatLayout.tsx`) never receive raw
   key bytes at all.
3. **Called last.** The export happens after `mediaMessageCreate*` and after the
   envelope has been accepted by the Delivery Service, so the handle has no
   remaining use. The existing `finally { mediaDropKey(handle) }` stays in place
   and becomes an idempotent no-op.
4. **Zeroed immediately on the JS side.** The `Uint8Array` that crosses the
   worker boundary is `fill(0)`-ed in a `finally` as soon as it has been copied
   into the payload's `number[]` — the same discipline `downloadAndDecryptMedia`
   already applies after `media_import_key`.
5. **No new primitive, no new secret.** No KDF, no wrap key, no ciphersuite
   change. The persisted bytes land in `MessageRow.mediaJson`, the same
   already-encrypted-at-rest field the receive path uses.

Non-goals for this ADR: the §9.4.1 thumbnail key (outgoing rows persist without
an inline thumbnail; `MediaPayload.thumbnail` is optional and the full blob is
re-fetched from R2 on rehydration) and the forwarding call site in
`ChatLayout.tsx`, which keeps its placeholder-only persistence.

## Rationale

### Security-equivalence argument (why Option A does not weaken anything)

The threat this could plausibly introduce is "raw AES-256-GCM media key present
in JS heap" and "raw AES-256-GCM media key at rest in IndexedDB". Both already
exist, for the *same key*, on the receive side, and were accepted by
crypto-reviewer in cycle 309 (and again for `mediaJson` when it was added):

- **In-JS-heap exposure.** The receiver's copy of the key is in JS memory
  unavoidably — it arrives inline in the MLS-decrypted JSON, which is the wire
  format. The sender's newly-created window is *equivalent*, not shorter: the
  transient `Uint8Array` returned by `mediaExportKeyForStorage` is zeroed in a
  `finally` immediately after serialisation, but the `number[]` it is copied into
  survives as `MessageRow.mediaJson`, which `persistOutgoing` puts straight into
  React state (`usePersistentMessages.ts`'s `setRows`) and which rehydrates into a
  live `MediaPayload` on every render — the same lifetime the receiver's copy
  already has. Only the short-lived wire-format `Uint8Array` transport buffer is
  actually shorter-lived on the sender path; the key material's total residency
  in JS memory is the same on both paths.
- **At-rest exposure.** Identical: the same `mediaJson` field, the same
  `EncryptedPowehiDb` AES-GCM-256 field encryption, the same `dbKey`.
- **Attacker capability required.** An adversary who can read JS heap or drive
  the WASM exports (i.e. script execution in the origin) can already call
  `media_encrypt`/`media_import_key`/`media_decrypt_with_handle` directly and
  recover every plaintext. This export gives such an adversary nothing new.
- **Server visibility.** Unchanged and zero. Nothing new is transmitted; the
  export is purely local and post-send.

Every key that this export can produce is a key the *recipients* of that same
message already hold in the clear. Persisting the sender's own copy therefore
does not extend the key's blast radius to any party that did not already have it.

### Why not Option B

Option B (WASM-side wrap against a session-derived local secret) would need a
wrapping-key source, a wrap format, and a re-wrap/rotation story on
`export_key` change — i.e. new key-derivation design, which is exactly the kind
of bespoke construction the project's non-negotiables push back on. It would buy
a strictly *smaller* improvement than it looks: the wrapping key itself would
have to be derivable in the same session from the same `export_key` that already
protects `mediaJson`, so an attacker positioned to read the decrypted
`mediaJson` today would be positioned to unwrap tomorrow. The residual gain is
only the in-JS-heap window, which the receive path already concedes for the same
key. Not worth a new primitive.

### Rejected sub-options

- **Returning base64 instead of `Uint8Array`.** A JS string is immutable and
  cannot be zeroed; `Uint8Array` keeps the `fill(0)` discipline available. Byte
  array wins, and it mirrors `media_import_key`'s input type exactly.
- **Non-consuming (peek) export.** Allows unbounded copies of the same key into
  JS. The consuming variant is strictly tighter and costs nothing, because the
  handle's last use is already the export.

## Consequences

- A sent attachment now re-renders after reload, from the sender's own Dexie row
  (`MediaImage` → `downloadAndDecryptMedia` → R2 GET → AES-GCM decrypt), exactly
  like a received one. `ChatLayout`'s rehydration path already validated
  `mediaJson` with the shared `isValidMediaPayload` predicate regardless of
  direction, so no rendering change was needed.
- `MessageRow.mediaJson` is now sensitive on **both** incoming and outgoing rows.
  Its at-rest encryption (already in `EncryptedPowehiDb`'s encrypted-field list)
  is now load-bearing in both directions; it must never be moved out of that list.
- Deleting a media message locally still leaves the R2 blob and the recipients'
  copies of the key untouched — unchanged by this ADR, and the reason local
  deletion is not a confidentiality control.
- Rows written by pre-ADR-0004 client builds have no `mediaJson` and keep
  rehydrating as their placeholder text. There is no backfill: the key for those
  attachments is gone from every local store. Accepted.
- Outgoing rows carry no `thumbnail`, so a rehydrated sent image fetches the full
  blob rather than showing the inline 64×64 preview first. Cosmetic; tracked as a
  follow-up together with the cycle-309 thumbnail note.
- `ChatLayout`'s forward flow still persists a placeholder only. Follow-up.
- The sender now re-fetches their own R2 blob on rehydration, which fires
  `POST /v1/media/:id/confirm-download`. This is already an anticipated case
  server-side: `MediaService::confirm_download` short-circuits when the
  confirmer is the uploader, and `run_gc_batched` excludes the uploader from
  `required_ackers` — so no ack is recorded and blob GC eligibility is
  unaffected. Verified, not assumed.
- Any future change that makes `media_export_key_for_storage` non-consuming, or
  that widens its call sites, must re-run `crypto-reviewer` — the
  security-equivalence argument above depends on the one-shot, opt-in,
  called-last properties.
