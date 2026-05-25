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
