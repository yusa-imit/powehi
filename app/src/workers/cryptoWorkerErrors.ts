/**
 * Sentinel error strings shared across the main-thread/worker boundary.
 *
 * Deliberately its own module with NO side effects and NO dependency on
 * `crypto.worker.ts`: that file's last line is a top-level `Comlink.expose(api)`,
 * which runs unconditionally on import. A *value* import of anything from
 * `crypto.worker.ts` into main-thread code (as opposed to `import type`, which
 * TypeScript erases) drags that side effect into the main-thread bundle too —
 * exposing the crypto API's entire postMessage RPC surface on `window` itself
 * (crypto-reviewer F1). Every main-thread caller of these constants MUST import
 * them from here, never from `crypto.worker.ts` directly.
 */

/**
 * The literal error message `MlsError::OwnCommit` (Rust) surfaces as, across
 * the Comlink boundary, when a Commit passed to `mlsProcessCommit` or
 * `mlsInspectCommit` hashes to the exact bytes of a commit THIS device
 * previously confirmed/merged itself — this crate's own hash-verified
 * post-merge tracking. Pinned on the Rust side by `mls_group.rs`'s
 * `own_commit_error_display_matches_ts_sentinel` test — keep both in sync if
 * either changes.
 *
 * SAFE to treat as "already applied locally, nothing to merge, ack" — see
 * `MLS_OWN_COMMIT_PENDING_ERROR` below for the OTHER own-commit signal, which
 * is NOT safe to treat this way.
 */
export const MLS_OWN_COMMIT_ERROR = "mls own commit error";

/**
 * The literal error message `MlsError::OwnCommitPending` (Rust) surfaces as,
 * across the Comlink boundary, when a Commit passed to `mlsProcessCommit` or
 * `mlsInspectCommit` triggers openmls's OWN pre-merge "this came from my own
 * leaf" signal (`ValidationError::CannotDecryptOwnMessage` /
 * `StageCommitError::OwnCommit`). Pinned on the Rust side by
 * `mls_group.rs`'s `own_commit_pending_error_display_matches_ts_sentinel`
 * test — keep both in sync if either changes.
 *
 * UNLIKE `MLS_OWN_COMMIT_ERROR`, this signal is NOT verified by this crate —
 * it is openmls's own leaf-index-based detection, which is authenticated
 * only by an epoch-shared AEAD key (`sender_data_secret`), not by the
 * claimed sender's signature key, so it is forgeable by any current group
 * member (see `MlsError::OwnCommitPending`'s doc comment in `mls_group.rs`
 * for the full argument). A caller MUST NOT auto-ack an envelope solely
 * because it rejected with this message: in the genuine case (a real
 * pre-confirm echo of this device's own staged commit) the commit is NOT yet
 * merged locally, so acking would delete the Delivery Service's only copy
 * before this device ever applies it; in the forged case, acking would
 * delete a message that was never this device's own commit at all. Treat it
 * like any other rejection — do not ack, log a content-free diagnostic.
 */
export const MLS_OWN_COMMIT_PENDING_ERROR = "mls own commit pending error";
