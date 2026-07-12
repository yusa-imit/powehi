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
/// [`PersistedProviderState`]. [`import_provider_state`] rejects any blob whose
/// bundled generation is less than the caller-supplied `min_generation`,
/// preventing a stale (but validly-AEAD-authenticated-at-rest) snapshot from
/// being replayed to resume the ratchet at an already-used position.
///
/// # Serialization format
/// `serde_json` encoding of [`PersistedProviderState`]; `pairs` is a JSON array
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
/// well-formed [`PersistedProviderState`] can never panic *here*, and no
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
