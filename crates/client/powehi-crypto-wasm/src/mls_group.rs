// MLS group operations (RFC 9420) using openmls 0.8.
//
// No cryptographic primitives are implemented here. All MLS state machine and
// crypto work is delegated to the audited `openmls` crate, with the audited
// `openmls_rust_crypto` provider supplying the native RustCrypto backend
// (HPKE, AEAD, signatures, RNG, key storage). On wasm32 the same provider is
// used with openmls's `js` feature for WASM-safe time/rng shims.
//
// MVP ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519. PQ-hybrid is a
// later phase (see CLAUDE.md ciphersuite migration note); the ciphersuite is
// centralized in [`CIPHERSUITE`] so the migration is a one-line change here.

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use openmls::prelude::{tls_codec::Deserialize as _, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// MVP ciphersuite. Migration to a PQ-hybrid suite happens here in Phase B.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Convenience alias for the native provider. On both native and wasm32 the
/// RustCrypto provider is used; the wasm32 difference is purely openmls's `js`
/// feature (configured in Cargo.toml), not a different provider type.
pub type Provider = OpenMlsRustCrypto;

/// Errors surfaced by the MLS group operations.
///
/// Variants are coarse and content-free: no plaintext, ciphertext, or key
/// material is ever embedded in an error (rule: no-plaintext-logging).
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    /// Signature key pair generation or storage failed.
    #[error("mls signature key error")]
    SignatureKey,
    /// KeyPackage construction failed.
    #[error("mls key package error")]
    KeyPackage,
    /// Group creation failed.
    #[error("mls group creation error")]
    GroupCreation,
    /// Adding a member / committing failed.
    #[error("mls membership error")]
    Membership,
    /// Encrypting an application message failed.
    #[error("mls encrypt error")]
    Encrypt,
    /// Decrypting / processing an incoming message failed.
    #[error("mls decrypt error")]
    Decrypt,
    /// Serializing or deserializing a wire message failed.
    #[error("mls codec error")]
    Codec,
    /// A processed message was not an application message as expected.
    #[error("mls unexpected message type")]
    UnexpectedMessage,
    /// Serializing, deserializing, or restoring persisted provider state failed,
    /// or a state lock was poisoned. Content-free by construction: the persisted
    /// bytes are ciphertext / key material and are never embedded in the error
    /// (rule: no-plaintext-logging).
    #[error("mls persistence error")]
    Persistence,
    /// [`confirm_remove_member`] or [`abort_remove_member`] was called with no
    /// commit currently staged (either none was ever staged, or a prior
    /// [`confirm_remove_member`] call already consumed it — see
    /// `confirm_remove_member`'s doc comment for why a failed merge also lands
    /// here rather than leaving a false-success retry path). Distinct from
    /// [`MlsError::Membership`] so a caller can tell "nothing to do" apart from
    /// "the operation itself failed".
    #[error("mls no pending commit error")]
    NoPendingCommit,
    /// [`stage_remove_member`] was called while the group's pending-proposal
    /// store already contained a queued proposal. Committing in that state
    /// would fold the queued proposal into the Remove commit, silently
    /// changing group membership/state beyond the single target the caller
    /// asked to remove — see `stage_remove_member`'s doc comment.
    #[error("mls pending proposals error")]
    PendingProposals,
}

/// A freshly generated MLS identity: the public credential bound to a signature
/// public key, plus the signature key pair held by the owner.
pub struct Identity {
    /// Public credential + signature public key (sent to peers / the DS).
    pub credential_with_key: CredentialWithKey,
    /// Owner's signature key pair (private; never leaves the client).
    pub signer: SignatureKeyPair,
}

/// Generate a basic credential and Ed25519 signature key pair for `identity`.
///
/// The signature key pair is stored in the provider's key store so openmls can
/// retrieve the private key during group operations.
pub fn generate_identity(
    identity: &[u8],
    provider: &impl OpenMlsProvider,
) -> Result<Identity, MlsError> {
    let credential = BasicCredential::new(identity.to_vec());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|_| MlsError::SignatureKey)?;
    signer
        .store(provider.storage())
        .map_err(|_| MlsError::SignatureKey)?;
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    Ok(Identity {
        credential_with_key,
        signer,
    })
}

/// Generate an MLS identity using a **deterministic** Ed25519 signing keypair —
/// the §8.5 Recovery Mechanism entry point.
///
/// Unlike [`generate_identity`], which mints a fresh keypair from the provider's
/// CSPRNG, this function reuses an externally derived keypair (e.g. derived from
/// a BIP-39 recovery phrase via `recovery::derive_signing_keypair`).  The
/// resulting MLS signing public key is therefore reproducible from the recovery
/// phrase alone.
///
/// `private_key` is 32 bytes of Ed25519 secret-scalar seed (RFC 8032 §5.1.5);
/// `public_key` is the matching 32-byte verification key (RFC 8032 §5.1.5).
/// Both are sourced from `recovery::derive_signing_keypair` — never from the
/// JS / network boundary.  The private bytes are passed by `&[u8; 32]`
/// reference and immediately moved into the openmls key store; this function
/// does NOT extend the lifetime of the secret beyond its own scope, but the
/// caller MUST hold the secret in a `Zeroizing` wrapper so the source buffer
/// is wiped on drop.
pub fn generate_identity_from_keypair(
    identity: &[u8],
    private_key: &[u8; 32],
    public_key: &[u8; 32],
    provider: &impl OpenMlsProvider,
) -> Result<Identity, MlsError> {
    // Verify that `public_key` matches the Ed25519 verifying key derived from
    // `private_key`.  `SignatureKeyPair::from_raw` accepts any byte pair without
    // internal consistency checks; a mismatch would silently produce signatures
    // that peers cannot verify (the stored public key would not match the actual
    // signing key).  This check closes that gap.
    let expected_pub = Ed25519SigningKey::from_bytes(private_key)
        .verifying_key()
        .to_bytes();
    if &expected_pub != public_key {
        return Err(MlsError::SignatureKey);
    }
    let credential = BasicCredential::new(identity.to_vec());
    let signer = SignatureKeyPair::from_raw(
        CIPHERSUITE.signature_algorithm(),
        private_key.to_vec(),
        public_key.to_vec(),
    );
    signer
        .store(provider.storage())
        .map_err(|_| MlsError::SignatureKey)?;
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    Ok(Identity {
        credential_with_key,
        signer,
    })
}

/// Extension type ID for the Powehi PQ KEM extension.
///
/// 0xF001 is in the private-use range 0xF000–0xFFFF defined by RFC 9420 §17.3.
/// Wire format: `encap_key (1184 bytes) || signature (64 bytes)`.
/// The signature covers `SIGN_DOMAIN || 0x00 || encap_key` (see `kem_credential.rs`).
pub const POWEHI_PQ_KEM_EXT_TYPE: u16 = 0xF001;

/// Byte lengths of the PQ extension payload components.
pub const PQ_EXT_ENCAP_KEY_LEN: usize = 1184; // ML-KEM-768 encapsulation key (FIPS 203 §2.4)
pub const PQ_EXT_SIG_LEN: usize = 64; // Ed25519 signature
pub const PQ_EXT_PAYLOAD_LEN: usize = PQ_EXT_ENCAP_KEY_LEN + PQ_EXT_SIG_LEN; // 1248 bytes total

/// Build a [`KeyPackage`] (as a [`KeyPackageBundle`]) for a user. The bundle's
/// private material is stored in the provider; share `bundle.key_package()`
/// with peers so they can add this user to a group.
pub fn generate_key_package(
    identity: &Identity,
    provider: &impl OpenMlsProvider,
) -> Result<KeyPackageBundle, MlsError> {
    KeyPackage::builder()
        .build(
            CIPHERSUITE,
            provider,
            &identity.signer,
            identity.credential_with_key.clone(),
        )
        .map_err(|_| MlsError::KeyPackage)
}

/// Build a [`KeyPackage`] with the Powehi PQ KEM extension attached (prd.md §5.3 Phase B).
///
/// `pq_payload` must be exactly [`PQ_EXT_PAYLOAD_LEN`] bytes:
/// `encap_key (1184 bytes) || signature (64 bytes)`.
/// The extension type [`POWEHI_PQ_KEM_EXT_TYPE`] (0xF001) is in the RFC 9420 §17.3
/// private-use range.  The leaf node capabilities are set to declare support for
/// this extension type so that `KeyPackageIn::validate()` does not reject it.
///
/// **Interoperability**: peers that do not implement prd.md §5.3 Phase B will receive
/// this KeyPackage and attempt to validate it.  Because 0xF001 is in the private-use
/// range (RFC 9420 §17.3), RFC-compliant implementations MUST treat unknown extension
/// types as opaque and MAY accept them; openmls does accept them when they appear in
/// leaf node capabilities.  Peers that pre-date Phase B should still accept this
/// KeyPackage via `add_members` — see `test_add_member_with_pq_extended_key_package_succeeds`.
pub fn generate_key_package_with_pq_ext(
    identity: &Identity,
    provider: &impl OpenMlsProvider,
    pq_payload: &[u8],
) -> Result<KeyPackageBundle, MlsError> {
    if pq_payload.len() != PQ_EXT_PAYLOAD_LEN {
        return Err(MlsError::KeyPackage);
    }
    let pq_extension = Extension::Unknown(
        POWEHI_PQ_KEM_EXT_TYPE,
        UnknownExtension(pq_payload.to_vec()),
    );
    let kp_extensions =
        Extensions::<KeyPackage>::single(pq_extension).map_err(|_| MlsError::KeyPackage)?;
    // Declare support for our private-use extension type in leaf node capabilities.
    // openmls validate() requires every KeyPackage extension type to appear in the
    // leaf node's capabilities.extensions list (RFC 9420 §7.1 invariant).
    let capabilities = Capabilities::new(
        None, // versions: use default
        None, // ciphersuites: use default
        Some(&[ExtensionType::Unknown(POWEHI_PQ_KEM_EXT_TYPE)]),
        None, // proposals: use default
        None, // credentials: use default
    );
    KeyPackage::builder()
        .key_package_extensions(kp_extensions)
        .leaf_node_capabilities(capabilities)
        .build(
            CIPHERSUITE,
            provider,
            &identity.signer,
            identity.credential_with_key.clone(),
        )
        .map_err(|_| MlsError::KeyPackage)
}

/// Create a new MLS group with `creator` as the sole member.
pub fn create_group(
    creator: &Identity,
    provider: &impl OpenMlsProvider,
) -> Result<MlsGroup, MlsError> {
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        // Ratchet-tree extension keeps Welcome messages self-contained, which is
        // what the worker/DS need (no out-of-band tree distribution).
        .use_ratchet_tree_extension(true)
        // Explicitly retain zero past epochs: forward secrecy requires that
        // stale-epoch key material is deleted immediately after an epoch advance.
        // If out-of-order delivery requires a wider window in the future, this
        // MUST be re-evaluated through the threat-model-checker first.
        .max_past_epochs(0)
        .build();
    MlsGroup::new(
        provider,
        &creator.signer,
        &config,
        creator.credential_with_key.clone(),
    )
    .map_err(|_| MlsError::GroupCreation)
}

/// Encrypt `plaintext` as an MLS application message and return the serialized
/// wire bytes (`MlsMessageOut`). The caller must hold the matching `signer`.
pub fn encrypt_message(
    group: &mut MlsGroup,
    signer: &SignatureKeyPair,
    plaintext: &[u8],
    provider: &impl OpenMlsProvider,
) -> Result<Vec<u8>, MlsError> {
    let out = group
        .create_message(provider, signer, plaintext)
        .map_err(|_| MlsError::Encrypt)?;
    out.to_bytes().map_err(|_| MlsError::Codec)
}

/// Decrypt a serialized MLS application message and return the plaintext.
///
/// Forward secrecy: openmls rejects ciphertext whose epoch no longer has key
/// material in the group's secret tree; such attempts return [`MlsError::Decrypt`].
pub fn decrypt_message(
    group: &mut MlsGroup,
    ciphertext: &[u8],
    provider: &impl OpenMlsProvider,
) -> Result<Vec<u8>, MlsError> {
    let message = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(|_| MlsError::Codec)?;
    let protocol_message: ProtocolMessage = message
        .try_into_protocol_message()
        .map_err(|_| MlsError::Codec)?;
    // Mirror of the guard in `process_incoming_commit`: reject a misrouted
    // Commit BEFORE `process_message` decrypts it, rather than after. See
    // that function's doc comment for the RFC 9420 §6.3.2 citation.
    if protocol_message.content_type() != ContentType::Application {
        return Err(MlsError::UnexpectedMessage);
    }
    let processed = group
        .process_message(provider, protocol_message)
        .map_err(|_| MlsError::Decrypt)?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
        _ => Err(MlsError::UnexpectedMessage),
    }
}

/// Add `member_kp` to `group`, committing and merging the change locally. This
/// advances the group to the next epoch. Returns the serialized `Welcome`
/// message that the new member needs to join (via [`join_group`]).
pub fn add_member(
    group: &mut MlsGroup,
    signer: &SignatureKeyPair,
    member_kp: KeyPackage,
    provider: &impl OpenMlsProvider,
) -> Result<Vec<u8>, MlsError> {
    let (_commit, welcome, _group_info) = group
        .add_members(provider, signer, &[member_kp])
        .map_err(|_| MlsError::Membership)?;
    group
        .merge_pending_commit(provider)
        .map_err(|_| MlsError::Membership)?;
    let welcome_bytes = welcome.to_bytes().map_err(|_| MlsError::Codec)?;
    Ok(welcome_bytes)
}

/// Stage / confirm / abort a member removal.
///
/// # Why this is three functions, not one
/// [`create_group`] / [`join_group`] configure `max_past_epochs(0)`: forward
/// secrecy requires stale-epoch key material to be deleted the instant the
/// epoch advances. A consequence of that same setting is that once a client
/// merges a commit, there is NO way back — if the commit turns out to be one
/// no peer actually accepted (lost race, rejected by the Delivery Service,
/// network partition, ...), the client's local epoch has moved on and its old
/// epoch's key material is already gone, permanently wedging the group for
/// that client. A single "remove + immediately merge" call (the prior shape
/// of this function) therefore had no way to recover from a commit that never
/// made it to the group. Splitting the operation into stage / confirm / abort
/// lets the caller defer the merge until the Delivery Service has actually
/// accepted the commit, and cleanly back out (via [`abort_remove_member`]) if
/// it did not.
///
/// # Post-Compromise Security (PCS)
/// Once [`confirm_remove_member`] merges the commit, the group advances to
/// the next epoch, which is what actually restores PCS for a
/// compromised/evicted device:
/// - RFC 9420 §12.1.3 (Remove) requires the target leaf to be non-blank
///   *before* the proposal is applied (rejecting removal of an
///   already-removed/unknown member — confirmed against the vendored
///   `PublicGroup` proposal validation, which rejects an `UnknownMemberRemoval`
///   when the target leaf is already blank); applying the proposal then
///   blanks that leaf, which is the genuine-removal post-state.
/// - RFC 9420 §12.4 (Commit) requires a Commit containing a Remove, Update,
///   External Init, or GroupContextExtensions proposal to include a `path`
///   (`UpdatePath`), which re-keys every node on the committer's direct path
///   using fresh HPKE key pairs (a Remove is in this required-path set; PSK
///   and ReInit proposals are not, but those are irrelevant here since this
///   function only ever commits a single Remove). Because the removed leaf
///   sits outside the (new) group's copath after removal, it is structurally
///   excluded from ever learning the updated path secrets. This re-keying —
///   not merely epoch staleness — is the actual mechanism that restores PCS:
///   it ensures the evicted device gains nothing even if it later receives
///   and fully processes the exact commit that evicts it (see
///   `test_mls_remove_member_restores_pcs`).
///
/// # Status: primitive now exists — the consumer loop still does not
/// The peer-side commit-processing **primitive** now exists:
/// [`process_incoming_commit`] in this module, exported to WASM as
/// `mls_process_commit` and to the frontend as `mlsProcessCommit`. What is
/// still missing is the **consumer loop**, not the primitive:
/// `app/src/hooks/useMessages.ts` still only handles Application-type
/// envelopes and `app/src/hooks/useWelcomePoller.ts` still only handles
/// Welcome messages, so both still ack-and-drop every Commit envelope —
/// nothing in the **running application** consumes a Commit produced here
/// yet. The PCS property `test_mls_remove_member_restores_pcs` proves holds
/// **inside that unit test** (where a second in-test `MlsGroup` handle stands
/// in for "a peer"), not yet for the deployed application. Do not wire this
/// export into any production UI or broadcast flow until BOTH (a) a real
/// epoch-reconciliation design exists (see `prior_epoch` below) AND (b) a
/// commit-processing **consumer loop** is wired into the poller — the
/// primitive half of (b) is done; what remains is the wiring, which
/// additionally needs a way to recognise and SKIP a Commit the caller's OWN
/// device sent. (This `(a)/(b)` pair is this section's own list, naming what
/// blocks wiring [`stage_remove_member`] into production; it is distinct from
/// the `(a)/(b)/(c)` list in [`process_incoming_commit`]'s own doc comment,
/// which enumerates what that primitive itself still leaves open.) Note that
/// item (c) of [`process_incoming_commit`]'s doc comment documents a further
/// hazard that wiring must handle: a staged-but-unconfirmed local commit is
/// silently discarded when an incoming commit is merged, so a staged Remove
/// can quietly evaporate. Wiring the consumer loop is a separate, materially
/// larger follow-up — explicitly out of scope for this change, and no part
/// of that wiring is built here.
///
/// Two further preconditions a future wiring pass MUST resolve, beyond this
/// section's (a)/(b) above (crypto-reviewer, this pass): (c) the
/// pending-commit state persists into serialized provider state
/// (`export_provider_state` /
/// `restore_provider_state`) with no JS-side record of "a stage is
/// outstanding" — a reload between stage and confirm/abort restores a group
/// wedged in `PendingCommit` with nothing aware it must call
/// [`abort_remove_member`] to un-wedge it; (d) the WASM export's caller
/// contract ("every successful stage call must be followed by exactly one of
/// confirm/abort") has no rollback if [`stage_remove_member`] itself succeeds
/// in-memory but the JS-side Dexie persist that must follow it
/// (`SYNC_FLUSH_ARG_METHODS` in `useCryptoWorker.ts`) then fails — the
/// in-memory pending commit is left staged even though the JS call the caller
/// sees rejected.
///
/// # `prior_epoch` — local bookkeeping only, NOT a server epoch
/// `prior_epoch` is the group's **local** MLS epoch immediately before the
/// staged operation, returned purely for the caller's own bookkeeping and for
/// a possible future commit-broadcast / epoch-reconciliation design. It is
/// **not currently validated against anything server-side** and **must not**
/// be passed as `sendCommit`'s `expected_epoch`: the server's `groups.epoch`
/// counter (`crates/domain/powehi-domain/src/group.rs`, starts at `Epoch(0)`)
/// is never advanced by the member-add flow
/// (`crates/application/powehi-application/src/group_service.rs::add_member`
/// only touches `group_members.joined_at_epoch`) — the only thing that bumps
/// it is `messaging_service.rs::send_commit`'s compare-and-swap, and no
/// production frontend code calls `sendCommit` at all today. A caller's local
/// MLS epoch and the server's counter therefore diverge from the very first
/// add, and reconciling them is explicitly out of scope for this change — a
/// follow-up design is required before `prior_epoch` can be used for any
/// server-side precondition.
///
/// # Caller contract
/// `leaf_index` MUST be a leaf index the caller read from this same `group`'s
/// own `members()` roster — never a value derived from server-reported data.
/// The self-removal check below is this function's **only** protection
/// against committing a self-Remove: openmls's own proposal validation
/// (confirmed against the vendored `PublicGroup` validation path) checks
/// in-tree/non-blank/duplicate-target only and does not independently reject
/// a committer removing its own leaf. Do not treat this check as optional
/// caller-contract sugar safe to drop in a refactor — removing it would let a
/// self-Remove commit through openmls unrejected. It is surfaced as
/// [`MlsError::Membership`] (matching this module's coarse, content-free error
/// convention); it is NOT input validation for untrusted data. The
/// `mls_remove_member_stage` WASM export in `wasm_exports.rs` is the layer
/// that documents and enforces the provenance requirement for any JS caller.
///
/// Every caller MUST call exactly one of [`confirm_remove_member`] /
/// [`abort_remove_member`] for every `Ok` return of this function — leaving a
/// commit permanently staged blocks every subsequent group operation that
/// requires the group to be operational (see below).
///
/// # What a pending (staged, unmerged) commit blocks
/// Empirically confirmed against the vendored openmls 0.8.1 source
/// (`openmls-0.8.1/src/group/mls_group/membership.rs`,
/// `openmls-0.8.1/src/group/mls_group/mod.rs`):
/// - [`MlsGroup::remove_members`] and [`MlsGroup::add_members`] both open with
///   `self.is_operational()?`, which returns
///   `Err(MlsGroupStateError::PendingCommit)` whenever a commit is already
///   staged. A second `stage_remove_member` (or an add) while one is pending
///   is therefore rejected outright — see
///   `test_mls_remove_member_second_stage_while_pending_rejected`.
/// - [`MlsGroup::create_message`] (used by [`encrypt_message`]) is **NOT**
///   gated by `is_operational()`. It only checks `self.is_active()` (false
///   only once the group is `Inactive`, e.g. after processing a commit that
///   removes the caller's own leaf — a `PendingCommit` state is still
///   "active") and that the *proposal store* (a separate queue from the
///   pending-commit slot the commit-builder path used here writes to) is
///   empty. In practice this means `encrypt_message` still succeeds while a
///   commit produced by `stage_remove_member` is pending, because it encrypts
///   under the still-current (pre-commit) epoch's keys — it does not "jump
///   ahead" to the pending epoch. This is pinned in
///   `test_mls_remove_member_reject_out_of_range_or_blank_leaf_does_not_wedge_group`.
pub fn stage_remove_member(
    group: &mut MlsGroup,
    signer: &SignatureKeyPair,
    leaf_index: u32,
    provider: &impl OpenMlsProvider,
) -> Result<(Vec<u8>, u64), MlsError> {
    if leaf_index == group.own_leaf_index().u32() {
        return Err(MlsError::Membership);
    }
    // `remove_members` commits via `commit_builder()`, whose proposal store
    // consumption defaults to folding in EVERY currently-queued proposal
    // (confirmed against the vendored `CommitBuilder` source) — not just Add
    // proposals. The store is filled either by this module's own standalone
    // `propose_*` calls (none exist today) or by proposals *received* from
    // peers and queued via `store_pending_proposal` (not called by anything
    // in this codebase today, but will be once a commit-processing consumer
    // exists — see this function's "Status" section above). A non-empty
    // store here would silently fold an unrelated queued proposal (another
    // Remove, an Update, a GroupContextExtensions change, ...) into what the
    // caller believes is a single-target eviction. Reject up front rather
    // than relying on inspecting the resulting commit after the fact.
    if group.pending_proposals().next().is_some() {
        return Err(MlsError::PendingProposals);
    }
    let prior_epoch = group.epoch().as_u64();
    let (commit, welcome, _group_info) = group
        .remove_members(provider, signer, &[LeafNodeIndex::new(leaf_index)])
        .map_err(|_| MlsError::Membership)?;
    // Defense in depth for the check above: `remove_members`'s own doc states
    // the returned Welcome is `Some` only when the proposal store contained
    // Add proposals at commit time, which the `pending_proposals()` guard
    // above should have already caught. `debug_assert!` alone is NOT the
    // enforcement here — it is compiled out of release/wasm builds — so the
    // `if welcome.is_some()` branch below is the actual, unconditional
    // safety net if the guard above is ever wrong or bypassed.
    debug_assert!(
        welcome.is_none(),
        "remove_members produced an unexpected Welcome despite an empty pending-proposal store \
         — see stage_remove_member's doc comment"
    );
    if welcome.is_some() {
        let _ = group.clear_pending_commit(provider.storage());
        return Err(MlsError::Membership);
    }
    let commit_bytes = commit.to_bytes().map_err(|_| MlsError::Codec)?;
    Ok((commit_bytes, prior_epoch))
}

/// Merge the commit staged by [`stage_remove_member`], advancing the group to
/// the next epoch. See [`stage_remove_member`]'s doc comment for the full
/// stage/confirm/abort contract, the PCS mechanism, and the current
/// out-of-scope status of any production wiring.
///
/// Callers must only call this after the Delivery Service has confirmed the
/// staged commit was accepted by the group — merging a commit no peer ever
/// accepted permanently wedges the group for this client (see
/// [`stage_remove_member`]'s doc comment on `max_past_epochs(0)`).
///
/// Returns [`MlsError::NoPendingCommit`] if no commit is currently staged —
/// this is a REQUIRED gate, not a nicety: the vendored `merge_pending_commit`
/// implementation transitions its internal state to `Operational` *before*
/// attempting the merge, so on a merge failure there is no staged commit left
/// to retry — without this gate, a caller retrying after a failed merge would
/// silently get `Ok(())` from a call that merged nothing, a false success for
/// the exact operation whose entire purpose is restoring PCS.
pub fn confirm_remove_member(
    group: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
) -> Result<(), MlsError> {
    if group.pending_commit().is_none() {
        return Err(MlsError::NoPendingCommit);
    }
    group
        .merge_pending_commit(provider)
        .map_err(|_| MlsError::Membership)
}

/// Discard the commit staged by [`stage_remove_member`] without merging it,
/// returning the group to its pre-stage state (the removed member is still a
/// member; the epoch has not advanced). See [`stage_remove_member`]'s doc
/// comment for the full stage/confirm/abort contract.
///
/// Callers use this when the Delivery Service rejects (or never confirms) the
/// staged commit, to un-wedge the group for further use rather than leaving a
/// permanently pending commit blocking every future `stage_remove_member` /
/// `add_members` call.
///
/// Returns [`MlsError::NoPendingCommit`] if no commit is currently staged,
/// rather than the silent no-op `Ok(())` `clear_pending_commit` itself would
/// return in that state — see [`confirm_remove_member`]'s doc comment for why
/// this codebase treats "nothing to do" as caller-visible here.
///
/// Caveat (currently unreachable): the `pending_commit().is_some()` gate
/// above also passes for `PendingCommitState::External`, a state this module
/// never produces (no `external_commit`/`join_by_external_commit` call exists
/// anywhere in this codebase today). `clear_pending_commit` returns `Ok(())`
/// without clearing anything in that specific state, so if external commits
/// are ever adopted, this function would need to special-case it to avoid
/// reporting a false success.
pub fn abort_remove_member(
    group: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
) -> Result<(), MlsError> {
    if group.pending_commit().is_none() {
        return Err(MlsError::NoPendingCommit);
    }
    group
        .clear_pending_commit(provider.storage())
        .map_err(|_| MlsError::Membership)
}

/// Process a Commit produced by a peer (e.g. [`stage_remove_member`] +
/// [`confirm_remove_member`], or a raw `add_members`/`remove_members` call)
/// and merge it into this `group`, advancing the local epoch.
///
/// # What this is — the missing half of the stage/confirm/abort trio
/// [`stage_remove_member`] / [`confirm_remove_member`] / [`abort_remove_member`]
/// are the **committer's** side of an MLS Remove. Every OTHER member of the
/// group has to independently process the exact same Commit bytes and merge
/// them into their own local `MlsGroup` handle, or the group FORKS: the
/// committer's local epoch advances (new ratchet tree, new epoch secrets) and
/// every bystander's local epoch does not, so from that instant every
/// application message the committer sends fails to decrypt for every
/// bystander, and vice versa — not a transient glitch, a permanent divergence
/// for that client (see [`stage_remove_member`]'s doc comment on why
/// `max_past_epochs(0)` makes this unrecoverable once either side moves on).
/// This function is that missing consumer-side primitive: call it once per
/// peer, per Commit received, to keep that peer's local epoch in lock-step
/// with the group.
///
/// # Return value
/// Returns the **new, post-merge local epoch** (`group.epoch().as_u64()`
/// after [`MlsGroup::merge_staged_commit`] returns), so a caller can compare
/// it against whatever epoch it independently expected.
///
/// # Self-eviction: `Ok` does not mean "still in the group"
/// If `commit_bytes` is the Commit that removes the CALLER's own leaf,
/// `merge_staged_commit` still returns `Ok` — and, per the vendored openmls
/// 0.8.1 `processing.rs` implementation, flips the group to
/// `MlsGroupState::Inactive` internally (the `RemoveOperation::WeWereRemovedBy`
/// path; see `test_mls_remove_member_restores_pcs`'s bob-processes-his-own-
/// eviction assertions for the sibling behaviour from the committer side of
/// this exact codepath). This function still returns `Ok(new_epoch)` in that
/// case — it does **not** special-case or report the eviction. Callers MUST
/// separately check `group.is_active()` (or otherwise detect eviction) after
/// calling this; this primitive has no opinion on what a caller does with
/// that information.
///
/// # Misrouting a non-Commit message: rejected cleanly, before any decrypt
/// RFC 9420 §6.3.2 defines `content_type` as a CLEARTEXT field of
/// `PrivateMessage` — it is readable via [`ProtocolMessage::content_type`]
/// without decrypting anything (confirmed against the vendored
/// `openmls-0.8.1` source: `framing/private_message_in.rs` and the public
/// `ProtocolMessage::content_type()` in `framing/message_in.rs`). This
/// function checks that field and returns [`MlsError::UnexpectedMessage`]
/// BEFORE ever calling [`MlsGroup::process_message`] on anything that is not
/// a Commit. openmls's `process_message` itself decrypts unconditionally
/// whenever it IS called — on this group's `max_past_epochs(0)`
/// configuration, decrypting an Application-type envelope consumes/blanks
/// its sender-ratchet secret as a side effect of decryption itself, which
/// would otherwise be destructive — but the guard above means that path is
/// never reached for a misrouted Application message, so misrouting here is
/// a normal, non-destructive rejection: the same ciphertext still decrypts
/// correctly via a subsequent, correctly-routed [`decrypt_message`] call. See
/// `test_process_incoming_commit_rejects_application_message`, which pins
/// this non-destructive behaviour (reject here, then successfully recover the
/// plaintext via `decrypt_message`). [`decrypt_message`] carries the mirror
/// guard for the opposite direction (a Commit misrouted there).
///
/// # Still out of scope (parallel to [`stage_remove_member`]'s "Status" section)
/// (a) **Epoch reconciliation.** The `u64` this function returns is the
///     LOCAL MLS epoch, not the server's `groups.epoch` counter — and the two
///     diverge from the very first member add in this codebase (see
///     [`stage_remove_member`]'s `# prior_epoch` section, and the divergence
///     analysis above `MlsRemoveStageResult` in
///     `app/src/workers/crypto.worker.ts`). Reconciling the two remains a
///     separate follow-up; do not treat this return value as authoritative
///     against any server-side epoch.
/// (b) **Not wired into any poller/consumer loop.** `app/src/hooks/useMessages.ts`
///     and `app/src/hooks/useWelcomePoller.ts` still ack-and-drop every Commit
///     envelope today — nothing calls this function in the running
///     application. Wiring it in is a deliberate separate follow-up, in part
///     because the consumer loop needs a way to recognise and SKIP a Commit
///     the caller's OWN device produced (re-processing an already-merged
///     commit), which this primitive has no opinion on either.
/// (c) **Interaction with a locally staged-but-unconfirmed commit — verified,
///     not guessed.** Per the vendored openmls-0.8.1 source
///     (`src/group/mls_group/processing.rs`), `merge_staged_commit` ends by
///     calling `clear_pending_commit` (the "Delete a potential pending
///     commit" step), and `process_message` / `unprotect_message` gate only
///     on `self.is_active()`, NOT `self.is_operational()` — so a commit
///     pending from this module's own [`stage_remove_member`] call does NOT
///     block this function, and openmls handles the combination without
///     corrupting state. The consequence the WIRING follow-up must handle:
///     the caller's OWN staged commit is SILENTLY DISCARDED by the call —
///     e.g. a staged Remove of a compromised device can quietly evaporate
///     without ever taking effect, and the caller's later
///     [`confirm_remove_member`] call then returns
///     [`MlsError::NoPendingCommit`] with no other signal that anything went
///     wrong. See `test_process_incoming_commit_silently_drops_receivers_own_staged_commit`,
///     which pins this exact behaviour. No guard is added here deliberately:
///     dropping the losing side of this race is the correct MLS resolution
///     (only one Commit per epoch can ever win); detecting the loss and
///     re-staging the caller's own operation is the consumer loop's job, not
///     this primitive's.
/// (d) **No policy-inspection point before merge — this is a blocking gap for
///     wiring, not a nice-to-have.** This function unconditionally merges ANY
///     validly-framed Commit: it never exposes the `StagedCommit`'s add/remove
///     proposals or the committer's identity to the caller before calling
///     [`MlsGroup::merge_staged_commit`]. There is no point in this call chain
///     where a caller could implement an authorization check (e.g. "only an
///     admin may remove members") before the merge happens. Concretely: wiring
///     this primitive into a real consumer loop AS-IS means any authenticated
///     group member can silently evict or add members from every bystander's
///     perspective, with no application-level veto point anywhere in the path.
///     Safe wiring requires changing this function's signature/contract to
///     expose the staged-commit contents for inspection before the merge is
///     performed — wiring this primitive into a consumer loop requires that
///     inspection point to exist first, which is not yet done.
/// (e) **No support for proposal-by-reference (RFC 9420 §12.4).** This
///     function treats `ProcessedMessageContent::ProposalMessage` as
///     [`MlsError::UnexpectedMessage`] rather than calling
///     [`MlsGroup::store_pending_proposal`]. A Commit that references a
///     previously-sent standalone Proposal (`ProposalOrRef::Reference`) will
///     therefore fail validation for a bystander calling this function, even
///     though the same Commit might succeed for the committer using this
///     codebase's own commit-construction paths. This only "works" today
///     because [`stage_remove_member`]/[`add_member`] (this module's own
///     commit-construction paths) always produce Commits with INLINE
///     proposals (`ProposalOrRef::Proposal`), never references — a peer or a
///     future proposal-queueing feature that uses references would break
///     against this function as written.
/// (f) **[`MlsError::Decrypt`] collapses distinct openmls signals into one
///     opaque error — a blocking precondition for wiring.** The `_ =>` /
///     `.map_err(|_| MlsError::Decrypt)` on `process_message` above discards
///     which of several distinct openmls-internal signals actually occurred,
///     including `StageCommitError::OwnCommit` (openmls's own, already-built-
///     in detection that a commit was produced by the caller's own leaf),
///     genuine validation failures, wrong-epoch commits, and
///     `NoPastEpochData` (a direct consequence of this group's
///     `max_past_epochs(0)` setting). A future consumer-loop wiring pass MUST
///     be able to distinguish "this was my own commit, skip it" from "this is
///     a genuine merge failure, that's a group fork" — silently treating a
///     real merge failure as an ignorable own-commit would BE the permanent
///     fork this primitive exists to prevent. This error-variant granularity
///     is therefore a blocking precondition for wiring, not a nice-to-have.
pub fn process_incoming_commit(
    group: &mut MlsGroup,
    commit_bytes: &[u8],
    provider: &impl OpenMlsProvider,
) -> Result<u64, MlsError> {
    let message = MlsMessageIn::tls_deserialize_exact(commit_bytes).map_err(|_| MlsError::Codec)?;
    let protocol_message: ProtocolMessage = message
        .try_into_protocol_message()
        .map_err(|_| MlsError::Codec)?;
    // RFC 9420 §6.3.2: `content_type` is a cleartext field of `PrivateMessage`,
    // readable via `ProtocolMessage::content_type()` without decrypting. Gate
    // on it BEFORE calling `process_message`, which decrypts unconditionally
    // and, on this group's `max_past_epochs(0)` configuration, would otherwise
    // consume the sender-ratchet secret for a misrouted Application message
    // even though this function goes on to reject it.
    if protocol_message.content_type() != ContentType::Commit {
        return Err(MlsError::UnexpectedMessage);
    }
    let processed = group
        .process_message(provider, protocol_message)
        .map_err(|_| MlsError::Decrypt)?;
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(provider, *staged)
                .map_err(|_| MlsError::Membership)?;
            Ok(group.epoch().as_u64())
        }
        _ => Err(MlsError::UnexpectedMessage),
    }
}

/// Join a group from a serialized `Welcome` message produced by [`add_member`].
pub fn join_group(
    welcome_bytes: &[u8],
    provider: &impl OpenMlsProvider,
) -> Result<MlsGroup, MlsError> {
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(0)
        .build();
    let message =
        MlsMessageIn::tls_deserialize_exact(welcome_bytes).map_err(|_| MlsError::Codec)?;
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err(MlsError::Codec),
    };
    let staged = StagedWelcome::new_from_welcome(provider, &config, welcome, None)
        .map_err(|_| MlsError::Membership)?;
    staged
        .into_group(provider)
        .map_err(|_| MlsError::Membership)
}

/// On-disk / at-rest envelope for [`export_provider_state`] /
/// [`import_provider_state`]. Bundles a monotonic `generation` counter INSIDE
/// the serialized bytes (not passed alongside them) so a replayed old blob
/// necessarily replays its own old generation — a caller cannot swap the
/// generation number independently of the ciphertext/key material it
/// describes. See [`import_provider_state`]'s freshness-gate doc for why this
/// matters (nonce-reuse risk from resuming the ratchet at an already-used
/// position).
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedProviderState {
    /// Format version. Only `1` is currently accepted.
    version: u16,
    /// Monotonic generation counter, minted by the caller at export time.
    generation: u64,
    /// The provider's raw `MemoryStorage` key/value map.
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Current [`PersistedProviderState::version`].
const PROVIDER_STATE_VERSION: u16 = 1;

/// Serialize the provider's entire storage backend to a self-contained byte blob
/// for at-rest persistence (e.g. the frontend's `GroupRow.mlsStateB64` Dexie
/// field).
///
/// # What is captured
/// [`Provider`] (`OpenMlsRustCrypto`) keeps **all** MLS group state — ratchet
/// tree, epoch secrets, the message-secrets store, resumption PSKs, group config,
/// leaf nodes, group state, and stored signature key pairs — in a single
/// `HashMap<Vec<u8>, Vec<u8>>` behind an `RwLock` inside its `MemoryStorage`
/// backend. Serializing that map is therefore sufficient to reconstruct every
/// group the provider knows about via [`openmls::group::MlsGroup::load`]; no
/// separate serialization of an `MlsGroup` is needed.
///
/// # Generation / freshness
/// `generation` is a caller-minted monotonic counter (e.g. incremented on every
/// successful export) bundled *inside* the serialized bytes via
/// `PersistedProviderState`. [`import_provider_state`] rejects any blob whose
/// bundled generation is less than the caller-supplied `min_generation`,
/// preventing a stale (but validly-AEAD-authenticated-at-rest) snapshot from
/// being replayed to resume the ratchet at an already-used position.
///
/// # Serialization format
/// `serde_json` encoding of `PersistedProviderState`; `pairs` is a JSON array
/// of `[key, value]` pairs, where each key/value is a JSON array of byte values
/// (`serde_json` renders `Vec<u8>` as a number array). This is chosen over a
/// JSON object because the map keys are opaque, frequently non-UTF-8 byte
/// strings that openmls constructs internally and cannot be used as JSON object
/// keys without an extra encoding step. The pair-array form round-trips
/// arbitrary bytes losslessly with no added dependency.
///
/// # Security
/// The returned bytes contain **live key material and ciphertext** (epoch
/// secrets, signature private keys, the message-secrets store). Treat them as
/// secret: they MUST only ever be written to the client-side encrypted store,
/// never logged, and never sent to the server. The error path is content-free
/// (rule: no-plaintext-logging).
pub fn export_provider_state(provider: &Provider, generation: u64) -> Result<Vec<u8>, MlsError> {
    let values = provider
        .storage()
        .values
        .read()
        .map_err(|_| MlsError::Persistence)?;
    // The struct owns its fields, so pairs must be cloned out of the RwLock
    // guard; the guard itself is dropped at the end of this block. No secret
    // bytes are logged or otherwise observed along the way.
    let pairs: Vec<(Vec<u8>, Vec<u8>)> =
        values.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let state = PersistedProviderState {
        version: PROVIDER_STATE_VERSION,
        generation,
        pairs,
    };
    serde_json::to_vec(&state).map_err(|_| MlsError::Persistence)
}

/// Reconstruct a [`Provider`] from bytes produced by [`export_provider_state`].
///
/// Builds a fresh `Provider::default()` and repopulates its `MemoryStorage`
/// backend with the deserialized key/value map. The returned provider is ready
/// to serve [`openmls::group::MlsGroup::load`] for any group the original
/// provider held, and to continue encrypt/decrypt/commit operations from the
/// persisted epoch. On success, also returns the bundled `generation` so the
/// caller can persist it as the new floor for the next `min_generation`.
///
/// # Freshness gate
/// `min_generation` is the last-known generation the caller has already
/// consumed (or `0` on first load). If the blob's bundled `generation` is
/// strictly less than `min_generation`, this returns [`MlsError::Persistence`]
/// without touching anything else. AEAD-at-rest (the caller's AES-GCM
/// encrypted-store layer) gives *integrity* — it proves the bytes were not
/// tampered with — but not *freshness*: an attacker (or a buggy caller) who
/// replays an old, validly-encrypted snapshot could otherwise resume the
/// message-secrets ratchet at an already-used position, which is a nonce-reuse
/// risk for the AEAD scheme MLS uses internally. Binding `generation` inside
/// the signed/encrypted envelope and rejecting stale values closes that gap.
///
/// # Signing keys
/// Signature key pairs stored via `signer.store(..)` are included in the exported
/// map, so a reloaded provider can sign. Independently, the §8.5 recovery path
/// ([`generate_identity_from_keypair`]) can always re-derive the same signer from
/// the recovery phrase, so a caller is never dependent on this blob for the
/// signing key alone.
///
/// # Errors
/// Returns [`MlsError::Persistence`] on malformed input, an unsupported
/// `version`, a stale `generation`, or a poisoned state lock. No
/// `unwrap`/`expect` is used in this function itself, so bytes that are not a
/// well-formed `PersistedProviderState` can never panic *here*, and no
/// partial state is ever installed on any error path (the fresh `Provider` is
/// only returned after every prior check succeeds).
///
/// **This does NOT make the function safe to call on untrusted bytes.** This
/// function only validates the outer envelope shape (version, generation,
/// pair-array); it does not validate the inner entity values openmls itself
/// stored (tree, group context, transcript hash, signature key pairs, ...).
/// `openmls_memory_storage::MemoryStorage`'s own reads (reached via the
/// intended follow-up call, [`openmls::group::MlsGroup::load`]) use
/// `serde_json::from_slice(..).unwrap()` internally on those inner values — a
/// well-formed envelope with a *corrupted* inner value therefore panics inside
/// openmls, not here (see
/// `test_import_well_formed_but_corrupt_value_panics_in_openmls_load`, which
/// documents this instead of hiding it). In WASM a panic aborts/poisons the
/// whole crypto-worker instance. Callers (crypto-worker glue) MUST therefore
/// only ever pass bytes that have already round-tripped through an
/// authenticated decryption step (e.g. the AES-GCM field-level decryption
/// `encrypted-db.ts` performs before this blob would ever reach Rust) — never
/// raw bytes sourced from an untrusted or unauthenticated channel.
pub fn import_provider_state(
    bytes: &[u8],
    min_generation: u64,
) -> Result<(Provider, u64), MlsError> {
    let state: PersistedProviderState =
        serde_json::from_slice(bytes).map_err(|_| MlsError::Persistence)?;
    if state.version != PROVIDER_STATE_VERSION {
        return Err(MlsError::Persistence);
    }
    if state.generation < min_generation {
        return Err(MlsError::Persistence);
    }
    let provider = Provider::default();
    {
        let mut values = provider
            .storage()
            .values
            .write()
            .map_err(|_| MlsError::Persistence)?;
        *values = state.pairs.into_iter().collect();
    }
    Ok((provider, state.generation))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a group, encrypt "hello", and decrypt it as a second member;
    /// assert the recovered plaintext matches.
    #[test]
    fn test_mls_create_encrypt_decrypt_roundtrip() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();

        // Bob publishes a KeyPackage; Alice creates the group and adds Bob.
        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome, &bob_provider).unwrap();

        // Both members must share the same epoch authenticator after the join.
        assert_eq!(
            alice_group.epoch_authenticator().as_slice(),
            bob_group.epoch_authenticator().as_slice(),
            "alice and bob must agree on the epoch after join"
        );

        // Alice encrypts; Bob decrypts.
        let plaintext = b"hello";
        let ciphertext =
            encrypt_message(&mut alice_group, &alice.signer, plaintext, &alice_provider).unwrap();
        let recovered = decrypt_message(&mut bob_group, &ciphertext, &bob_provider).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);

        // The wire bytes must not contain the plaintext (sanity: it is encrypted).
        assert!(
            !contains_subslice(&ciphertext, plaintext),
            "ciphertext must not leak the plaintext"
        );
    }

    /// Forward secrecy: a ciphertext created in epoch N cannot be decrypted by a
    /// member after the group advances past that epoch. We capture a ciphertext,
    /// advance the epoch by adding a new member, then assert the stale ciphertext
    /// no longer decrypts.
    #[test]
    fn test_mls_forward_secrecy() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let charlie = generate_identity(b"charlie", &charlie_provider).unwrap();

        // Alice creates the group and adds Bob (epoch advances to include Bob).
        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome, &bob_provider).unwrap();

        let epoch_before = bob_group.epoch();

        // Alice sends a message in the current epoch. Capture the ciphertext but
        // do NOT let Bob process it yet.
        let secret = b"epoch-0 secret";
        let stale_ciphertext =
            encrypt_message(&mut alice_group, &alice.signer, secret, &alice_provider).unwrap();

        // Advance the epoch: Alice adds Charlie and merges the commit. Bob then
        // processes the same commit so his group also moves to the new epoch.
        let charlie_kp = generate_key_package(&charlie, &charlie_provider).unwrap();
        let (commit, _welcome2, _gi) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[charlie_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();

        let commit_bytes = commit.to_bytes().unwrap();
        let commit_in = MlsMessageIn::tls_deserialize_exact(&commit_bytes).unwrap();
        let commit_pm: ProtocolMessage = commit_in.try_into_protocol_message().unwrap();
        let processed = bob_group.process_message(&bob_provider, commit_pm).unwrap();
        if let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() {
            bob_group
                .merge_staged_commit(&bob_provider, *staged)
                .unwrap();
        } else {
            panic!("expected a staged commit message");
        }

        let epoch_after = bob_group.epoch();
        assert_ne!(
            epoch_before, epoch_after,
            "epoch must advance after adding a member"
        );

        // The stale (epoch N) ciphertext must NOT decrypt now that Bob is in the
        // next epoch — forward secrecy: old epoch key material is gone.
        let result = decrypt_message(&mut bob_group, &stale_ciphertext, &bob_provider);
        assert!(
            result.is_err(),
            "stale-epoch ciphertext must not decrypt after the epoch advances"
        );
    }

    /// Removing a member restores Post-Compromise Security (PCS): after alice
    /// removes bob and the commit is merged/processed, bob's stale-epoch group
    /// handle can no longer read new group traffic, while a member who DID
    /// process the removal commit (charlie) can. Also proves the roster no
    /// longer lists bob.
    #[test]
    fn test_mls_remove_member_restores_pcs() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let charlie = generate_identity(b"charlie", &charlie_provider).unwrap();

        // Alice creates the group and adds bob via the raw openmls call (not
        // add_member) so we retain the commit alongside the welcome.
        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let (_commit1, welcome1, _gi1) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[bob_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();
        let welcome1_bytes = welcome1.to_bytes().unwrap();
        let mut bob_group = join_group(&welcome1_bytes, &bob_provider).unwrap();

        // Alice adds charlie next; this advances the epoch again, so bob's
        // handle (created from the first welcome) is now one epoch behind
        // unless he processes this second commit too.
        let charlie_kp = generate_key_package(&charlie, &charlie_provider).unwrap();
        let (commit2, welcome2, _gi2) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[charlie_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();
        let welcome2_bytes = welcome2.to_bytes().unwrap();
        let mut charlie_group = join_group(&welcome2_bytes, &charlie_provider).unwrap();

        // Feed bob the charlie-add commit so his handle stays current.
        let commit2_bytes = commit2.to_bytes().unwrap();
        let commit2_in = MlsMessageIn::tls_deserialize_exact(&commit2_bytes).unwrap();
        let commit2_pm: ProtocolMessage = commit2_in.try_into_protocol_message().unwrap();
        let processed2 = bob_group
            .process_message(&bob_provider, commit2_pm)
            .unwrap();
        if let ProcessedMessageContent::StagedCommitMessage(staged) = processed2.into_content() {
            bob_group
                .merge_staged_commit(&bob_provider, *staged)
                .unwrap();
        } else {
            panic!("expected a staged commit message");
        }

        // Prove bob is a genuinely working member pre-removal.
        let pre_removal_msg = b"pre-removal hello";
        let pre_removal_ct = encrypt_message(
            &mut alice_group,
            &alice.signer,
            pre_removal_msg,
            &alice_provider,
        )
        .unwrap();
        let pre_removal_pt =
            decrypt_message(&mut bob_group, &pre_removal_ct, &bob_provider).unwrap();
        assert_eq!(pre_removal_pt.as_slice(), pre_removal_msg);

        // Find bob's leaf index from alice's roster — never hardcode a literal.
        let bob_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present in alice's roster before removal");

        let epoch_before = alice_group.epoch().as_u64();
        let charlie_epoch_before = charlie_group.epoch().as_u64();

        let (commit_bytes, prior_epoch) =
            stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider)
                .unwrap();
        assert_eq!(
            prior_epoch, epoch_before,
            "prior_epoch must be the group's epoch before the removal commit"
        );
        confirm_remove_member(&mut alice_group, &alice_provider)
            .expect("staged removal commit must merge cleanly");

        // Charlie processes the removal commit.
        let commit_in = MlsMessageIn::tls_deserialize_exact(&commit_bytes).unwrap();
        let commit_pm: ProtocolMessage = commit_in.try_into_protocol_message().unwrap();
        let processed = charlie_group
            .process_message(&charlie_provider, commit_pm)
            .unwrap();
        if let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() {
            charlie_group
                .merge_staged_commit(&charlie_provider, *staged)
                .unwrap();
        } else {
            panic!("expected a staged commit message");
        }

        assert!(
            alice_group.epoch().as_u64() > epoch_before,
            "alice's epoch must advance after the removal commit"
        );
        assert!(
            charlie_group.epoch().as_u64() > charlie_epoch_before,
            "charlie's epoch must advance after processing the removal commit"
        );
        assert_eq!(
            alice_group.epoch_authenticator().as_slice(),
            charlie_group.epoch_authenticator().as_slice(),
            "alice and charlie must agree on the epoch after the removal commit"
        );

        // PCS: alice encrypts a NEW message post-removal.
        let post_removal_msg = b"post-removal secret";
        let post_removal_ct = encrypt_message(
            &mut alice_group,
            &alice.signer,
            post_removal_msg,
            &alice_provider,
        )
        .unwrap();

        // Charlie (who processed the removal) can still read new traffic.
        let charlie_pt =
            decrypt_message(&mut charlie_group, &post_removal_ct, &charlie_provider).unwrap();
        assert_eq!(charlie_pt.as_slice(), post_removal_msg);

        // Bob (whose handle never processed the removal commit) cannot read
        // new-epoch traffic — this is the PCS property: a device evicted from
        // the group loses access to future messages the moment the removal
        // commit is merged by the remaining members, regardless of any key
        // material bob's stale handle still holds.
        let bob_result = decrypt_message(&mut bob_group, &post_removal_ct, &bob_provider);
        assert!(
            bob_result.is_err(),
            "post-removal ciphertext must not decrypt for a removed member — this is the \
             Post-Compromise Security (PCS) property that removal is meant to provide"
        );

        // The assertion above (stale bob_group can't decrypt) is explained by
        // epoch staleness alone: bob_group never processed the removal
        // commit, so it would fail to decrypt post_removal_ct even if alice
        // had merely added a 4th member instead of removing bob. It does not
        // isolate the removal. The real PCS claim is stronger: a removed
        // device gains nothing even when it DOES receive and process the
        // exact commit that evicts it — which is what happens on a real
        // network, since the DS broadcasts the removal commit to the whole
        // prior epoch's membership, bob included. So here bob processes his
        // own eviction commit and must still be locked out of new traffic.
        // This also doubles as self-eviction coverage for
        // [`process_incoming_commit`] itself (it previously had none): bob's
        // handle processes the exact commit that evicts him via the same
        // primitive a real peer consumer loop would call.
        process_incoming_commit(&mut bob_group, &commit_bytes, &bob_provider).expect(
            "bob must be able to process the commit that removes him from the group, and \
             merging a self-removing commit must succeed and flip the group inactive",
        );
        assert!(
            !bob_group.is_active(),
            "bob's handle must be deactivated (openmls MlsGroupState::Inactive) once it has \
             merged the commit that removes its own leaf — RemoveOperation::WeWereRemovedBy"
        );
        let bob_post_eviction_result =
            decrypt_message(&mut bob_group, &post_removal_ct, &bob_provider);
        assert!(
            bob_post_eviction_result.is_err(),
            "bob must still be unable to decrypt post-removal ciphertext even after processing \
             the exact commit that evicted him. NOTE: this assertion alone does not isolate PCS \
             from mere epoch staleness the way the comment above once claimed — openmls's \
             is_active() guard rejects any decrypt attempt on an Inactive group before key \
             material is ever consulted, so this failure is consistent with (but does not prove) \
             the RFC 9420 §12.4.3.1 path-secret exclusion being the real mechanism. The PCS \
             mechanism itself is argued from the RFC text and vendored openmls source in this \
             function's doc comment, not proven end-to-end by this specific assertion."
        );

        // Bob is gone from the roster.
        assert!(
            alice_group.members().all(|m| m.index.u32() != bob_leaf),
            "bob's leaf index must no longer be present in the roster after removal"
        );
    }

    /// [`stage_remove_member`] rejects removing the caller's own leaf index as
    /// a pre-flight caller-contract guard: the epoch must NOT advance, and no
    /// commit is even staged — proving the check happens before any commit is
    /// created (not a post-hoc rollback that would otherwise leave the group
    /// wedged in `PendingCommit` state).
    #[test]
    fn test_mls_remove_member_rejects_self_removal() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let _welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();

        let epoch_before = alice_group.epoch().as_u64();
        let own_leaf = alice_group.own_leaf_index().u32();
        let result =
            stage_remove_member(&mut alice_group, &alice.signer, own_leaf, &alice_provider);
        assert!(matches!(result, Err(MlsError::Membership)));
        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_before,
            "self-removal must be rejected before any commit is created — epoch must not advance"
        );
        assert!(
            alice_group.pending_commit().is_none(),
            "self-removal must be rejected before any commit is even staged"
        );
    }

    /// Issue #2's actual motivating scenario: a 1:1 chat evicting a
    /// compromised device. Only 3-person groups were previously covered by
    /// [`test_mls_remove_member_restores_pcs`]; this pins the 2-person case,
    /// where removal leaves exactly one member (the remover) in the group.
    #[test]
    fn test_mls_remove_member_two_person_group() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome, &bob_provider).unwrap();

        // Find bob's leaf index from alice's roster — never hardcode a literal.
        let bob_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present in alice's roster before removal");

        let epoch_before = alice_group.epoch().as_u64();
        let (commit_bytes, prior_epoch) =
            stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider)
                .unwrap();
        assert_eq!(prior_epoch, epoch_before);
        confirm_remove_member(&mut alice_group, &alice_provider)
            .expect("staged removal commit must merge cleanly");

        assert!(
            alice_group.epoch().as_u64() > epoch_before,
            "epoch must advance after the removal commit is confirmed"
        );
        let roster: Vec<u32> = alice_group.members().map(|m| m.index.u32()).collect();
        assert_eq!(
            roster,
            vec![alice_group.own_leaf_index().u32()],
            "alice must be the sole remaining member of a 2-person group after removing bob"
        );

        // Alice encrypts post-removal traffic.
        let post_removal_msg = b"post-removal secret";
        let post_removal_ct = encrypt_message(
            &mut alice_group,
            &alice.signer,
            post_removal_msg,
            &alice_provider,
        )
        .unwrap();

        // Bob's stale handle cannot decrypt, even before processing his own eviction.
        assert!(
            decrypt_message(&mut bob_group, &post_removal_ct, &bob_provider).is_err(),
            "bob must not be able to decrypt post-removal traffic with his stale handle"
        );

        // Bob processes his own eviction commit — still cannot decrypt afterwards
        // (mirrors the stronger PCS proof in test_mls_remove_member_restores_pcs).
        let commit_in = MlsMessageIn::tls_deserialize_exact(&commit_bytes).unwrap();
        let commit_pm: ProtocolMessage = commit_in.try_into_protocol_message().unwrap();
        let processed = bob_group
            .process_message(&bob_provider, commit_pm)
            .expect("bob must be able to process the commit that removes him");
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                bob_group
                    .merge_staged_commit(&bob_provider, *staged)
                    .expect("merging a self-removing commit must succeed");
            }
            _ => panic!("expected a staged commit message"),
        }
        assert!(!bob_group.is_active(), "bob's handle must be deactivated");
        assert!(
            decrypt_message(&mut bob_group, &post_removal_ct, &bob_provider).is_err(),
            "bob must still be unable to decrypt post-removal ciphertext after processing his \
             own eviction commit — this is the PCS property, not mere epoch staleness"
        );
    }

    /// Pins openmls's ACTUAL observed behavior (empirically confirmed against
    /// openmls 0.8.1) for an out-of-range or blank leaf index: rejection
    /// happens inside `remove_members`'s proposal-validation / commit-build
    /// path (before `stage_commit` ever returns a staged commit), NOT after
    /// any merge. Both cases — a leaf index past the end of the tree, and a
    /// leaf index that is blank because that member was already removed —
    /// are rejected as `Err(MlsError::Membership)`, the epoch never advances,
    /// no commit is ever staged, and critically, the group is NOT left
    /// wedged: a subsequent valid operation succeeds afterwards.
    #[test]
    fn test_mls_remove_member_reject_out_of_range_or_blank_leaf_does_not_wedge_group() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let _welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();

        // Case 1: leaf index past the end of the tree (2-member group only
        // has indices 0 and 1).
        let out_of_range_leaf = alice_group.members().count() as u32 + 10;
        let epoch_before = alice_group.epoch().as_u64();
        let result = stage_remove_member(
            &mut alice_group,
            &alice.signer,
            out_of_range_leaf,
            &alice_provider,
        );
        assert!(
            matches!(result, Err(MlsError::Membership)),
            "an out-of-range leaf index must be rejected as MlsError::Membership"
        );
        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_before,
            "epoch must not advance for a rejected out-of-range removal"
        );
        assert!(
            alice_group.pending_commit().is_none(),
            "no commit may be left staged for a rejected out-of-range removal"
        );
        // Group is not wedged: a subsequent valid operation still works.
        let msg = b"still usable after out-of-range rejection";
        encrypt_message(&mut alice_group, &alice.signer, msg, &alice_provider)
            .expect("group must remain usable after a rejected out-of-range removal");

        // Case 2: a leaf index that is blank because that member was already
        // removed. Remove bob for real first (stage + confirm), then attempt
        // to remove him again via his now-blank leaf index.
        let bob_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present before removal");
        let (_commit, _prior) =
            stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider)
                .unwrap();
        confirm_remove_member(&mut alice_group, &alice_provider).unwrap();
        assert!(
            alice_group.members().all(|m| m.index.u32() != bob_leaf),
            "bob must no longer be in the roster after the first, successful removal"
        );

        let epoch_before2 = alice_group.epoch().as_u64();
        let result2 =
            stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider);
        assert!(
            matches!(result2, Err(MlsError::Membership)),
            "removing an already-blank leaf index must be rejected as MlsError::Membership"
        );
        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_before2,
            "epoch must not advance for a rejected blank-leaf removal"
        );
        assert!(
            alice_group.pending_commit().is_none(),
            "no commit may be left staged for a rejected blank-leaf removal"
        );
        // Group is not wedged: a fresh, valid stage+confirm still works.
        let bob_kp2 = generate_key_package(&bob, &bob_provider).unwrap();
        add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp2.key_package().clone(),
            &alice_provider,
        )
        .expect("group must remain usable after a rejected blank-leaf removal");
    }

    /// Pins openmls's ACTUAL observed behavior (empirically confirmed against
    /// openmls 0.8.1) when staging a removal while a different pending commit
    /// already exists: `remove_members` opens with `self.is_operational()?`,
    /// which returns `Err(MlsGroupStateError::PendingCommit)` whenever a
    /// commit is already staged — surfaced here as `Err(MlsError::Membership)`.
    /// Then proves the abort path un-wedges the group: after
    /// [`abort_remove_member`], a fresh commit can be staged and merged.
    #[test]
    fn test_mls_remove_member_second_stage_while_pending_rejected() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let charlie = generate_identity(b"charlie", &charlie_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let charlie_kp = generate_key_package(&charlie, &charlie_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        add_member(
            &mut alice_group,
            &alice.signer,
            charlie_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();

        let bob_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present before removal");
        let charlie_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"charlie")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("charlie must be present before removal");

        // Stage a removal of bob — leaves a pending commit.
        stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider).unwrap();
        assert!(
            alice_group.pending_commit().is_some(),
            "a commit must be staged after the first stage_remove_member call"
        );

        // Attempt to stage a second removal (of charlie) while the first is
        // still pending — openmls's is_operational() guard must reject this.
        let epoch_before = alice_group.epoch().as_u64();
        let second_result = stage_remove_member(
            &mut alice_group,
            &alice.signer,
            charlie_leaf,
            &alice_provider,
        );
        assert!(
            matches!(second_result, Err(MlsError::Membership)),
            "staging a second removal while one is pending must be rejected \
             (openmls MlsGroupStateError::PendingCommit)"
        );
        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_before,
            "epoch must not advance when the second stage attempt is rejected"
        );

        // Abort the first staged removal — this must un-wedge the group.
        abort_remove_member(&mut alice_group, &alice_provider)
            .expect("aborting the pending commit must succeed");
        assert!(
            alice_group.pending_commit().is_none(),
            "no commit may remain staged after abort_remove_member"
        );
        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_before,
            "epoch must still not have advanced after abort"
        );
        assert!(
            alice_group.members().any(|m| m.index.u32() == bob_leaf),
            "bob must still be a member after the aborted removal"
        );

        // The group can now go on to stage + merge a fresh commit successfully.
        let (_commit, _prior) = stage_remove_member(
            &mut alice_group,
            &alice.signer,
            charlie_leaf,
            &alice_provider,
        )
        .unwrap();
        confirm_remove_member(&mut alice_group, &alice_provider)
            .expect("a fresh removal after abort must merge cleanly");
        assert!(
            alice_group.members().all(|m| m.index.u32() != charlie_leaf),
            "charlie must be removed after the post-abort fresh removal is confirmed"
        );
    }

    /// The abort path proper: staging a removal and then aborting it must
    /// leave the group exactly as if the removal had never been attempted —
    /// epoch unchanged, the removed member still present in the roster, no
    /// commit left staged — and prove the group is fully usable afterwards
    /// (it can stage+confirm a fresh removal and continue encrypting /
    /// decrypting normally). This is the "not wedged" proof for the abort path.
    #[test]
    fn test_mls_remove_member_abort_restores_group_to_usable_state() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome, &bob_provider).unwrap();

        let bob_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present before removal");

        let epoch_before = alice_group.epoch().as_u64();
        stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider).unwrap();
        assert!(alice_group.pending_commit().is_some());

        abort_remove_member(&mut alice_group, &alice_provider)
            .expect("abort must succeed on a freshly staged commit");

        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_before,
            "epoch must not advance after an aborted removal"
        );
        assert!(
            alice_group.members().any(|m| m.index.u32() == bob_leaf),
            "bob must still be in the roster after an aborted removal"
        );
        assert!(
            alice_group.pending_commit().is_none(),
            "no commit may remain staged after abort_remove_member"
        );

        // Fully usable afterwards: normal encrypt/decrypt still works...
        let msg = b"still usable after abort";
        let ct = encrypt_message(&mut alice_group, &alice.signer, msg, &alice_provider).unwrap();
        let pt = decrypt_message(&mut bob_group, &ct, &bob_provider).unwrap();
        assert_eq!(pt.as_slice(), msg);

        // ...and a fresh stage+confirm removal of the same member succeeds.
        let (_commit, _prior) =
            stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider)
                .unwrap();
        confirm_remove_member(&mut alice_group, &alice_provider)
            .expect("a fresh removal after abort must merge cleanly");
        assert!(
            alice_group.members().all(|m| m.index.u32() != bob_leaf),
            "bob must be removed after the post-abort fresh removal is confirmed"
        );
    }

    /// crypto-reviewer finding F1: [`confirm_remove_member`] with no commit
    /// ever staged for this group must reject with
    /// [`MlsError::NoPendingCommit`], not silently succeed. Before this fix,
    /// `confirm_remove_member` called `merge_pending_commit` unconditionally,
    /// which is a documented no-op-returning-`Ok` on an `Operational` group.
    #[test]
    fn test_mls_remove_member_confirm_without_stage_rejected() {
        let alice_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();

        let epoch_before = alice_group.epoch().as_u64();
        let result = confirm_remove_member(&mut alice_group, &alice_provider);
        assert!(
            matches!(result, Err(MlsError::NoPendingCommit)),
            "confirming with nothing staged must reject as NoPendingCommit, not succeed"
        );
        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_before,
            "epoch must not advance for a rejected no-op confirm"
        );
    }

    /// crypto-reviewer finding F1: [`abort_remove_member`] with no commit
    /// ever staged for this group must reject with
    /// [`MlsError::NoPendingCommit`], not silently succeed via
    /// `clear_pending_commit`'s own documented no-op-on-`Operational` behavior.
    #[test]
    fn test_mls_remove_member_abort_without_stage_rejected() {
        let alice_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();

        let result = abort_remove_member(&mut alice_group, &alice_provider);
        assert!(
            matches!(result, Err(MlsError::NoPendingCommit)),
            "aborting with nothing staged must reject as NoPendingCommit, not succeed"
        );
    }

    /// crypto-reviewer finding F1: confirming twice in a row — the second
    /// call has nothing left to merge, since the first call already merged
    /// and cleared the pending commit — must reject as
    /// [`MlsError::NoPendingCommit`] rather than silently returning `Ok(())`
    /// again (a false-success retry that would previously have masked a
    /// caller bug or a legitimate "already confirmed" race).
    #[test]
    fn test_mls_remove_member_confirm_twice_second_call_rejected() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let bob_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present before removal");

        stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider).unwrap();
        confirm_remove_member(&mut alice_group, &alice_provider)
            .expect("first confirm must succeed");

        let epoch_after_first_confirm = alice_group.epoch().as_u64();
        let second_result = confirm_remove_member(&mut alice_group, &alice_provider);
        assert!(
            matches!(second_result, Err(MlsError::NoPendingCommit)),
            "a second confirm with nothing left staged must reject as NoPendingCommit"
        );
        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_after_first_confirm,
            "a rejected second confirm must not advance the epoch again"
        );
    }

    /// crypto-reviewer finding F2: [`stage_remove_member`] must reject when
    /// the group's pending-proposal store already contains a queued proposal
    /// (here, a standalone self-Update queued via `propose_self_update`,
    /// empirically confirmed to populate the same `pending_proposals()` store
    /// `remove_members`'s commit-builder consumes) rather than silently
    /// folding it into the Remove commit. Also proves the rejection doesn't
    /// wedge the group: a fresh removal succeeds once the offending proposal
    /// is gone (achieved here by creating a brand-new group state instead of
    /// draining the proposal store, since this module exposes no standalone
    /// "clear proposals" primitive).
    #[test]
    fn test_mls_remove_member_rejects_when_proposals_are_pending() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let bob_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present before removal");

        // Queue a standalone proposal without committing it — simulates a
        // proposal received from a peer and queued via `store_pending_proposal`
        // (this module's own future commit-processing consumer), which
        // `stage_remove_member`'s doc comment identifies as the real-world
        // source of a contaminated proposal store.
        alice_group
            .propose_self_update(
                &alice_provider,
                &alice.signer,
                LeafNodeParameters::default(),
            )
            .expect("queuing a standalone self-update proposal must succeed");
        assert!(
            alice_group.pending_proposals().next().is_some(),
            "the proposal store must be non-empty after propose_self_update"
        );

        let epoch_before = alice_group.epoch().as_u64();
        let result =
            stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider);
        assert!(
            matches!(result, Err(MlsError::PendingProposals)),
            "staging a removal with a non-empty proposal store must reject as PendingProposals"
        );
        assert_eq!(
            alice_group.epoch().as_u64(),
            epoch_before,
            "epoch must not advance for a rejected contaminated-store removal"
        );
        assert!(
            alice_group.pending_commit().is_none(),
            "no commit may be staged for a rejected contaminated-store removal"
        );

        // While the queued (uncommitted) proposal remains, `encrypt_message`
        // itself also refuses to run — confirming the reviewer's finding that
        // `create_message`'s "proposal store must be empty" precondition
        // (distinct from `is_operational()`, which only guards a *staged
        // commit*) applies here too. This is expected, not a wedge: the fix
        // is to resolve the proposal (commit it or clear it), not to force
        // messaging through with mixed pending state.
        let msg_while_pending = b"must not encrypt while a proposal is queued";
        assert!(
            encrypt_message(
                &mut alice_group,
                &alice.signer,
                msg_while_pending,
                &alice_provider
            )
            .is_err(),
            "encrypt_message must refuse to run while the proposal store is non-empty"
        );

        // The group is not permanently wedged: once the offending proposal is
        // cleared, both messaging and a fresh stage+confirm removal work again.
        alice_group
            .clear_pending_proposals(alice_provider.storage())
            .expect("clearing the pending proposal must succeed");
        assert!(
            alice_group.pending_proposals().next().is_none(),
            "the proposal store must be empty after clear_pending_proposals"
        );
        let msg = b"still usable once the queued proposal is cleared";
        encrypt_message(&mut alice_group, &alice.signer, msg, &alice_provider)
            .expect("group must be usable again once the contaminating proposal is cleared");
        let (_commit, _prior) =
            stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider)
                .expect("a fresh removal must succeed once the proposal store is clear");
        confirm_remove_member(&mut alice_group, &alice_provider)
            .expect("the fresh removal must merge cleanly");
        assert!(
            alice_group.members().all(|m| m.index.u32() != bob_leaf),
            "bob must be removed once the contaminated-store removal is retried cleanly"
        );
    }

    /// Full persist -> reload -> continue-messaging round trip for provider state.
    ///
    /// Alice is created from a **fixed seed** via [`generate_identity_from_keypair`]
    /// so the same signing key is reproducible after "reload" (the §8.5 recovery
    /// path), mirroring how the frontend re-derives the signer from the recovery
    /// phrase. We prove pre-export state works (alice -> bob message), export
    /// alice's provider state, then **drop the original provider and group
    /// entirely** so nothing but the exported bytes can be used for
    /// reconstruction. After importing into a fresh provider and reloading the
    /// group via [`MlsGroup::load`], a *new* message encrypted from the reloaded
    /// group still decrypts for bob — proving the ratchet/epoch state survived the
    /// round trip.
    #[test]
    fn test_provider_state_export_import_roundtrip() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();

        // Fixed seed for alice so the signer is reproducible post-reload.
        let alice_priv: [u8; 32] = [7u8; 32];
        let alice_pub: [u8; 32] = Ed25519SigningKey::from_bytes(&alice_priv)
            .verifying_key()
            .to_bytes();
        let alice =
            generate_identity_from_keypair(b"alice", &alice_priv, &alice_pub, &alice_provider)
                .unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome, &bob_provider).unwrap();

        // Prove the pre-export state works: alice -> bob message round-trips.
        let msg1 = b"before export";
        let ct1 = encrypt_message(&mut alice_group, &alice.signer, msg1, &alice_provider).unwrap();
        assert_eq!(
            decrypt_message(&mut bob_group, &ct1, &bob_provider)
                .unwrap()
                .as_slice(),
            msg1
        );

        // Capture the group id, then export and destroy every original handle.
        let alice_group_id = alice_group.group_id().clone();
        let exported = export_provider_state(&alice_provider, 1).unwrap();
        drop(alice_group);
        drop(alice_provider);

        // Reconstruct purely from the exported bytes.
        let (new_provider, generation) = import_provider_state(&exported, 1).unwrap();
        assert_eq!(generation, 1, "bundled generation must round-trip");
        let alice2 =
            generate_identity_from_keypair(b"alice", &alice_priv, &alice_pub, &new_provider)
                .unwrap();
        let mut reloaded = MlsGroup::load(new_provider.storage(), &alice_group_id)
            .unwrap()
            .expect("group must be present in the reloaded provider state");

        // A NEW message from the reloaded group must still decrypt for bob.
        let msg2 = b"after reload";
        let ct2 = encrypt_message(&mut reloaded, &alice2.signer, msg2, &new_provider).unwrap();
        assert_eq!(
            decrypt_message(&mut bob_group, &ct2, &bob_provider)
                .unwrap()
                .as_slice(),
            msg2
        );
    }

    /// [`import_provider_state`] must reject malformed input with
    /// [`MlsError::Persistence`] rather than panicking (no `unwrap`/`expect` on
    /// the deserialization path in lib code).
    #[test]
    fn test_import_provider_state_rejects_garbage() {
        let garbage: &[u8] = b"\x00 not json at all \xff\xfe {[";
        assert!(matches!(
            import_provider_state(garbage, 0),
            Err(MlsError::Persistence)
        ));
        // Empty input is also malformed JSON, not a panic.
        assert!(matches!(
            import_provider_state(b"", 0),
            Err(MlsError::Persistence)
        ));
    }

    /// [`import_provider_state`] rejects a well-formed but *stale* blob: the
    /// bundled `generation` is strictly less than the caller-supplied
    /// `min_generation`. This is the freshness gate that prevents replaying an
    /// old (but validly AEAD-authenticated-at-rest) snapshot to resume the
    /// message-secrets ratchet at an already-used position.
    #[test]
    fn test_import_provider_state_rejects_stale_generation() {
        let alice_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let _alice_group = create_group(&alice, &alice_provider).unwrap();

        let exported = export_provider_state(&alice_provider, 5).unwrap();
        assert!(matches!(
            import_provider_state(&exported, 6),
            Err(MlsError::Persistence)
        ));
        // Exactly-equal generation is accepted (not strictly stale).
        assert!(import_provider_state(&exported, 5).is_ok());
    }

    /// Documents (rather than hides) a known panic surface: a byte blob that is a
    /// *well-formed* `[key, value]` pair array (so [`import_provider_state`]
    /// itself returns `Ok`) but carries a corrupted value under a real openmls
    /// storage key still panics — inside openmls's own `MemoryStorage` read path,
    /// not in this crate — the moment [`openmls::group::MlsGroup::load`] tries to
    /// deserialize that entity. See the security note on [`import_provider_state`]:
    /// this is why callers must only ever feed it bytes that already passed
    /// through an authenticated decryption step, never raw/untrusted bytes.
    #[test]
    fn test_import_well_formed_but_corrupt_value_panics_in_openmls_load() {
        let alice_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let alice_group = create_group(&alice, &alice_provider).unwrap();
        let alice_group_id = alice_group.group_id().clone();

        let exported = export_provider_state(&alice_provider, 1).unwrap();
        let mut state: PersistedProviderState = serde_json::from_slice(&exported).unwrap();
        assert!(
            !state.pairs.is_empty(),
            "a freshly created group must have persisted at least one storage entry"
        );
        // Corrupt every stored value's bytes (still valid JSON at the outer
        // envelope level, so import_provider_state succeeds) so whichever
        // entity MlsGroup::load reads first is guaranteed to be corrupt.
        for (_key, value) in state.pairs.iter_mut() {
            *value = b"not a valid openmls entity".to_vec();
        }
        let corrupted = serde_json::to_vec(&state).unwrap();

        // Also acceptable: import itself rejects the corrupt blob cleanly.
        let Ok((new_provider, _generation)) = import_provider_state(&corrupted, 0) else {
            return;
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MlsGroup::load(new_provider.storage(), &alice_group_id)
        }));
        assert!(
            result.is_err(),
            "corrupt inner values are currently expected to panic inside openmls's \
             MemoryStorage read path, not return a clean Err — if this assertion \
             starts failing (openmls now returns Err instead), the security note \
             on import_provider_state should be relaxed to match"
        );
    }

    /// Bystander (non-removed, non-committer) processes a Remove commit via
    /// [`process_incoming_commit`]: the returned epoch matches the
    /// committer's epoch, the epoch authenticators cryptographically agree,
    /// the removed member is gone from the bystander's own roster view, and
    /// a post-commit message round-trips end to end through the bystander's
    /// merged state.
    #[test]
    fn test_process_incoming_commit_bystander_tracks_remove_commit_epoch() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let charlie = generate_identity(b"charlie", &charlie_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let (_commit1, welcome1, _gi1) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[bob_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();
        let mut bob_group = join_group(&welcome1.to_bytes().unwrap(), &bob_provider).unwrap();

        let charlie_kp = generate_key_package(&charlie, &charlie_provider).unwrap();
        let (commit2, welcome2, _gi2) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[charlie_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();
        let mut charlie_group =
            join_group(&welcome2.to_bytes().unwrap(), &charlie_provider).unwrap();

        // Keep bob current with the charlie-add commit (bystander duty, using
        // the function under test).
        let new_epoch_for_bob =
            process_incoming_commit(&mut bob_group, &commit2.to_bytes().unwrap(), &bob_provider)
                .expect("bob must be able to process the charlie-add commit");
        assert_eq!(new_epoch_for_bob, alice_group.epoch().as_u64());

        let bob_leaf = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present in alice's roster before removal");

        let (commit_bytes, _prior_epoch) =
            stage_remove_member(&mut alice_group, &alice.signer, bob_leaf, &alice_provider)
                .unwrap();
        confirm_remove_member(&mut alice_group, &alice_provider)
            .expect("staged removal commit must merge cleanly");

        let charlie_epoch_before = charlie_group.epoch().as_u64();
        let returned_epoch =
            process_incoming_commit(&mut charlie_group, &commit_bytes, &charlie_provider)
                .expect("charlie (bystander) must be able to process alice's removal commit");

        assert_eq!(
            returned_epoch,
            alice_group.epoch().as_u64(),
            "the returned epoch must be the committer's new epoch"
        );
        assert_eq!(
            charlie_group.epoch().as_u64(),
            alice_group.epoch().as_u64(),
            "charlie's local epoch must now match alice's"
        );
        assert!(
            charlie_group.epoch().as_u64() > charlie_epoch_before,
            "charlie's epoch must have strictly advanced"
        );
        assert_eq!(
            alice_group.epoch_authenticator().as_slice(),
            charlie_group.epoch_authenticator().as_slice(),
            "alice and charlie must cryptographically agree on the new epoch"
        );
        assert!(
            charlie_group.members().all(|m| m.index.u32() != bob_leaf),
            "bob must no longer be in charlie's roster view after merging the removal commit"
        );

        // End-to-end: alice encrypts post-removal, charlie decrypts using the
        // state process_incoming_commit just merged.
        let post_removal_msg = b"post-removal to charlie";
        let post_removal_ct = encrypt_message(
            &mut alice_group,
            &alice.signer,
            post_removal_msg,
            &alice_provider,
        )
        .unwrap();
        let recovered =
            decrypt_message(&mut charlie_group, &post_removal_ct, &charlie_provider).unwrap();
        assert_eq!(recovered.as_slice(), post_removal_msg);
    }

    /// Bystander processes an Add commit via [`process_incoming_commit`]: the
    /// returned epoch matches the committer's epoch, epoch authenticators
    /// agree, and a post-add message decrypts for the bystander.
    #[test]
    fn test_process_incoming_commit_bystander_tracks_add_commit_epoch() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let charlie = generate_identity(b"charlie", &charlie_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome1 = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome1, &bob_provider).unwrap();

        // Alice adds charlie via the raw openmls call, retaining the commit.
        let charlie_kp = generate_key_package(&charlie, &charlie_provider).unwrap();
        let (commit2, _welcome2, _gi2) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[charlie_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();

        let bob_epoch_before = bob_group.epoch().as_u64();
        let returned_epoch =
            process_incoming_commit(&mut bob_group, &commit2.to_bytes().unwrap(), &bob_provider)
                .expect("bob (bystander) must be able to process alice's add commit");

        assert_eq!(returned_epoch, alice_group.epoch().as_u64());
        assert_eq!(bob_group.epoch().as_u64(), alice_group.epoch().as_u64());
        assert!(bob_group.epoch().as_u64() > bob_epoch_before);
        assert_eq!(
            alice_group.epoch_authenticator().as_slice(),
            bob_group.epoch_authenticator().as_slice(),
            "alice and bob must cryptographically agree on the new epoch"
        );

        let post_add_msg = b"post-add to bob";
        let post_add_ct = encrypt_message(
            &mut alice_group,
            &alice.signer,
            post_add_msg,
            &alice_provider,
        )
        .unwrap();
        let recovered = decrypt_message(&mut bob_group, &post_add_ct, &bob_provider).unwrap();
        assert_eq!(recovered.as_slice(), post_add_msg);
    }

    /// Malformed wire bytes (too-short garbage and an empty slice) must be
    /// rejected as [`MlsError::Codec`], and the rejection must not wedge the
    /// group — the epoch stays put and a subsequent real operation still
    /// works.
    #[test]
    fn test_process_incoming_commit_rejects_garbage_bytes() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome, &bob_provider).unwrap();

        let epoch_before = bob_group.epoch().as_u64();

        let garbage = [0xffu8; 64];
        let result = process_incoming_commit(&mut bob_group, &garbage, &bob_provider);
        assert!(matches!(result, Err(MlsError::Codec)));

        let empty_result = process_incoming_commit(&mut bob_group, &[], &bob_provider);
        assert!(matches!(empty_result, Err(MlsError::Codec)));

        assert_eq!(
            bob_group.epoch().as_u64(),
            epoch_before,
            "epoch must be unchanged after rejecting malformed commit bytes"
        );

        // Group remains usable: a real application message still round-trips.
        let msg = b"still usable after garbage rejection";
        let ct = encrypt_message(&mut alice_group, &alice.signer, msg, &alice_provider).unwrap();
        let pt = decrypt_message(&mut bob_group, &ct, &bob_provider).unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    /// [`process_incoming_commit`] rejects an application message with
    /// [`MlsError::UnexpectedMessage`] — the mirror image of
    /// [`decrypt_message`] rejecting a Commit.
    ///
    /// This ALSO pins the non-destructive rejection documented in
    /// [`process_incoming_commit`]'s doc comment: the `content_type` guard
    /// added there rejects a misrouted Application-type envelope BEFORE
    /// `process_message` is ever called, so `process_message` never
    /// decrypts it and the sender-ratchet secret for that message's
    /// generation is never consumed. The SAME ciphertext must therefore
    /// still decrypt correctly, and to the ORIGINAL plaintext, via a
    /// subsequent, correctly-routed [`decrypt_message`] call — proving the
    /// guard prevented any destructive state mutation. See the doc comments
    /// on `process_incoming_commit` (this module), `mls_process_commit`
    /// (`wasm_exports.rs`), and `mlsProcessCommit`
    /// (`app/src/workers/crypto.worker.ts`).
    #[test]
    fn test_process_incoming_commit_rejects_application_message() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome, &bob_provider).unwrap();

        let plaintext = b"hello";
        let ciphertext =
            encrypt_message(&mut alice_group, &alice.signer, plaintext, &alice_provider).unwrap();

        let result = process_incoming_commit(&mut bob_group, &ciphertext, &bob_provider);
        assert!(matches!(result, Err(MlsError::UnexpectedMessage)));

        // Non-destructive rejection: the SAME ciphertext, routed correctly
        // this time through decrypt_message, must now SUCCEED — the guard in
        // process_incoming_commit rejected the misrouted message before
        // process_message was ever called, so the ratchet secret for this
        // message's generation was never consumed. Checking the recovered
        // plaintext (not just `is_ok()`) rules out a false pass from some
        // other decrypt path succeeding without actually recovering the
        // original message.
        let second_attempt = decrypt_message(&mut bob_group, &ciphertext, &bob_provider).expect(
            "misrouting into process_incoming_commit must not consume the ratchet \
                     secret — a correctly-routed decrypt_message retry on the same bytes \
                     must still succeed",
        );
        assert_eq!(
            second_attempt.as_slice(),
            plaintext,
            "decrypt_message must recover the exact original plaintext after the misrouted \
             process_incoming_commit call was cleanly rejected by the content-type guard"
        );
    }

    /// Mirror of [`test_process_incoming_commit_rejects_application_message`]:
    /// a real Commit message routed into [`decrypt_message`] must be rejected
    /// by that function's own `content_type` guard — cleanly, and without
    /// being silently processed or destructively consumed — rather than
    /// reaching `process_message` at all.
    #[test]
    fn test_decrypt_message_rejects_commit_message() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();
        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let charlie = generate_identity(b"charlie", &charlie_provider).unwrap();
        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let charlie_kp = generate_key_package(&charlie, &charlie_provider).unwrap();

        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let welcome1 = add_member(
            &mut alice_group,
            &alice.signer,
            bob_kp.key_package().clone(),
            &alice_provider,
        )
        .unwrap();
        let mut bob_group = join_group(&welcome1, &bob_provider).unwrap();

        // A real Commit, produced by adding charlie.
        let (commit, _welcome, _group_info) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[charlie_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();
        let commit_bytes = commit.to_bytes().unwrap();

        let epoch_before = bob_group.epoch().as_u64();
        let result = decrypt_message(&mut bob_group, &commit_bytes, &bob_provider);
        assert!(matches!(result, Err(MlsError::UnexpectedMessage)));
        assert_eq!(
            bob_group.epoch().as_u64(),
            epoch_before,
            "a Commit misrouted into decrypt_message must not be processed or merged — \
             bob's epoch must be unchanged"
        );

        // Non-destructive: the same Commit, routed correctly this time
        // through process_incoming_commit, must still succeed.
        let new_epoch =
            process_incoming_commit(&mut bob_group, &commit_bytes, &bob_provider).unwrap();
        assert_eq!(
            new_epoch,
            alice_group.epoch().as_u64(),
            "a Commit rejected by decrypt_message's guard must still merge successfully via \
             a correctly-routed process_incoming_commit retry on the same bytes"
        );
    }

    /// THE IMPORTANT ONE — pins the open question for the consumer-wiring
    /// follow-up (item (c) of [`process_incoming_commit`]'s doc comment).
    ///
    /// Charlie stages his own Remove of bob via [`stage_remove_member`] but
    /// does NOT confirm it, so `charlie_group.pending_commit().is_some()`.
    /// Meanwhile alice independently stages+confirms her own Remove of bob
    /// (chosen here — rather than an Add of a 4th member — because it is the
    /// commit that actually exercises the race charlie's own pending Remove
    /// is trying to perform; either shape would work for pinning (c), but
    /// this one doubles as "two different members racing to remove the same
    /// target"). Charlie then processes alice's commit via
    /// [`process_incoming_commit`].
    ///
    /// VERIFIED observed behaviour (openmls 0.8.1): the call returns `Ok`;
    /// charlie's epoch advances to match alice's; charlie's own staged commit
    /// is silently cleared (`pending_commit()` becomes `None`); and a
    /// subsequent [`confirm_remove_member`] on charlie's now-empty pending
    /// slot returns `Err(MlsError::NoPendingCommit)` — proving charlie's
    /// staged removal silently evaporated with no error anywhere in the
    /// call chain. This is exactly the hazard the consumer-loop follow-up
    /// must detect and handle (e.g. by re-staging charlie's removal after
    /// noticing the loss) — no guard is added here on purpose, since
    /// dropping the losing side of an MLS commit race is the CORRECT
    /// protocol resolution; only re-staging is the consumer loop's job.
    #[test]
    fn test_process_incoming_commit_silently_drops_receivers_own_staged_commit() {
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();

        let alice = generate_identity(b"alice", &alice_provider).unwrap();
        let bob = generate_identity(b"bob", &bob_provider).unwrap();
        let charlie = generate_identity(b"charlie", &charlie_provider).unwrap();

        let bob_kp = generate_key_package(&bob, &bob_provider).unwrap();
        let mut alice_group = create_group(&alice, &alice_provider).unwrap();
        let (_commit1, welcome1, _gi1) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[bob_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();
        let mut bob_group = join_group(&welcome1.to_bytes().unwrap(), &bob_provider).unwrap();

        let charlie_kp = generate_key_package(&charlie, &charlie_provider).unwrap();
        let (commit2, welcome2, _gi2) = alice_group
            .add_members(
                &alice_provider,
                &alice.signer,
                &[charlie_kp.key_package().clone()],
            )
            .unwrap();
        alice_group.merge_pending_commit(&alice_provider).unwrap();
        let mut charlie_group =
            join_group(&welcome2.to_bytes().unwrap(), &charlie_provider).unwrap();

        // Keep bob current with the charlie-add commit.
        process_incoming_commit(&mut bob_group, &commit2.to_bytes().unwrap(), &bob_provider)
            .unwrap();

        let bob_leaf_for_charlie = charlie_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present in charlie's roster before removal");

        // Charlie stages his own removal of bob but does NOT confirm it.
        let (_charlie_commit_bytes, _charlie_prior_epoch) = stage_remove_member(
            &mut charlie_group,
            &charlie.signer,
            bob_leaf_for_charlie,
            &charlie_provider,
        )
        .expect("charlie must be able to stage a removal of bob");
        assert!(
            charlie_group.pending_commit().is_some(),
            "charlie must have a commit staged before processing alice's commit"
        );

        // Meanwhile, alice independently stages + confirms her OWN removal of
        // bob — a different, already-merged commit that reaches charlie as an
        // incoming commit.
        let bob_leaf_for_alice = alice_group
            .members()
            .find(|m| {
                BasicCredential::try_from(m.credential.clone())
                    .map(|basic| basic.identity() == b"bob")
                    .unwrap_or(false)
            })
            .map(|m| m.index.u32())
            .expect("bob must be present in alice's roster before removal");
        let (alice_commit_bytes, _alice_prior_epoch) = stage_remove_member(
            &mut alice_group,
            &alice.signer,
            bob_leaf_for_alice,
            &alice_provider,
        )
        .unwrap();
        confirm_remove_member(&mut alice_group, &alice_provider)
            .expect("alice's removal commit must merge cleanly");

        // Charlie processes alice's commit while his own removal is still
        // staged (unconfirmed).
        let result =
            process_incoming_commit(&mut charlie_group, &alice_commit_bytes, &charlie_provider);

        // VERIFIED: openmls accepts the call (does not reject it because a
        // local commit is pending) rather than rejecting it outright.
        let new_epoch = result.expect(
            "openmls accepts processing an incoming commit even while a local commit is \
             pending — see process_incoming_commit's doc comment item (c)",
        );
        assert_eq!(
            new_epoch,
            alice_group.epoch().as_u64(),
            "charlie's new epoch must match alice's after merging her commit"
        );
        assert_eq!(charlie_group.epoch().as_u64(), alice_group.epoch().as_u64());

        // VERIFIED: charlie's own staged commit was silently cleared by the
        // merge, not preserved for a later retry.
        assert!(
            charlie_group.pending_commit().is_none(),
            "charlie's own staged removal must have been silently cleared by merging \
             alice's incoming commit — this is the hazard item (c) documents"
        );

        // VERIFIED: a subsequent confirm on charlie's now-empty pending slot
        // fails with NoPendingCommit, with no other signal that charlie's
        // staged removal ever evaporated.
        let confirm_result = confirm_remove_member(&mut charlie_group, &charlie_provider);
        assert!(
            matches!(confirm_result, Err(MlsError::NoPendingCommit)),
            "confirming charlie's silently-dropped staged commit must fail as \
             NoPendingCommit — proving the staged removal evaporated with no other signal"
        );
    }

    /// Naive substring check used only to sanity-assert ciphertext does not
    /// contain the plaintext. Not security-critical.
    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
