// OPAQUE-3DH client flows using opaque-ke 4.0.1 (RFC 9807, stable release).
//
// opaque-ke 4.0.1 implements the published RFC 9807 (OPAQUE). References to
// "RFC 9807" in this file are exact. The 3.x -> 4.x bump made the AKE hash an
// explicit ciphersuite parameter (`TripleDh<KeGroup, Hash>`) and added an rng
// argument to `ClientLogin::finish`; neither changes the wire format for the
// Ristretto255 + SHA-512 suite used here.
//
// No cryptographic primitives are implemented here. Every operation delegates
// to the audited `opaque-ke` crate. The ciphersuite is Ristretto255 (OPRF +
// key exchange group), TripleDH key exchange, and Argon2id as the key
// stretching function (KSF). This must stay consistent with the server-side
// adapter in `crates/adapters/outbound/powehi-opaque`.
//
// Security: the server NEVER receives the user's password or the export key.
// The export key is derived client-side and is used to wrap the user's local
// secret material (e.g. MLS signature keys) before any upload.

use argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::errors::ProtocolError;
use opaque_ke::rand::{CryptoRng, RngCore};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult, ClientRegistration,
    ClientRegistrationFinishParameters, ClientRegistrationFinishResult, CredentialResponse,
    RegistrationResponse,
};

/// OPAQUE ciphersuite for Powehi: Ristretto255 + TripleDH + Argon2id KSF
/// (RFC 9807 / opaque-ke 4.0.1).
///
/// This must stay byte-for-byte consistent with the server-side ciphersuite,
/// otherwise registration and login messages will not interoperate.
/// OPAQUE identity binding: `Identifiers::default()` leaves idU/idS unbound
/// from the envelope AKE transcript. This is a deliberate MVP choice;
/// channel binding via identifiers is planned for Phase 3 (server-side adapter).
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

/// Length of the durable OPAQUE export-key prefix we expose as the local secret
/// wrapping key. The full OPRF hash output (SHA-512 for Ristretto255) is longer;
/// we surface a 32-byte prefix suitable for an AEAD/KDF key.
pub const EXPORT_KEY_LEN: usize = 32;

/// Errors surfaced by the OPAQUE client flows.
///
/// Variants are intentionally coarse: no plaintext, password, or key material
/// is ever included in an error value (rule: no-plaintext-logging). The inner
/// `ProtocolError` is never propagated verbatim to avoid leaking oracles.
#[derive(Debug, thiserror::Error)]
pub enum OpaqueError {
    /// A protocol step failed (malformed message, MAC mismatch, wrong password).
    #[error("opaque protocol error")]
    Protocol,
    /// A wire message could not be deserialized into the expected type.
    #[error("opaque deserialization error")]
    Deserialize,
}

impl From<ProtocolError> for OpaqueError {
    fn from(_: ProtocolError) -> Self {
        OpaqueError::Protocol
    }
}

/// Step 1 of registration (client). Returns the client state to persist and the
/// serialized `RegistrationRequest` to send to the server.
pub fn registration_start<R: RngCore + CryptoRng>(
    password: &[u8],
    rng: &mut R,
) -> Result<(ClientRegistration<DefaultCipherSuite>, Vec<u8>), OpaqueError> {
    let start = ClientRegistration::<DefaultCipherSuite>::start(rng, password)?;
    let message = start.message.serialize().to_vec();
    Ok((start.state, message))
}

/// Step 3 of registration (client). Consumes the persisted client state, the
/// password, and the server's serialized `RegistrationResponse`. Returns the
/// full result (carrying `export_key`) plus the serialized `RegistrationUpload`
/// message to send to the server.
///
/// API note: opaque-ke 4.0.1 requires the password again at the finish step
/// (it re-runs the KSF), so this signature carries `password` and an `rng`.
pub fn registration_finish<R: RngCore + CryptoRng>(
    client_state: ClientRegistration<DefaultCipherSuite>,
    password: &[u8],
    server_message: &[u8],
    rng: &mut R,
) -> Result<(ClientRegistrationFinishResult<DefaultCipherSuite>, Vec<u8>), OpaqueError> {
    let response = RegistrationResponse::<DefaultCipherSuite>::deserialize(server_message)
        .map_err(|_| OpaqueError::Deserialize)?;
    let result = client_state.finish(
        rng,
        password,
        response,
        ClientRegistrationFinishParameters::default(),
    )?;
    let upload = result.message.serialize().to_vec();
    Ok((result, upload))
}

/// Step 1 of login (client). Returns the client login state to persist and the
/// serialized `CredentialRequest` to send to the server.
pub fn login_start<R: RngCore + CryptoRng>(
    password: &[u8],
    rng: &mut R,
) -> Result<(ClientLogin<DefaultCipherSuite>, Vec<u8>), OpaqueError> {
    let start = ClientLogin::<DefaultCipherSuite>::start(rng, password)?;
    let message = start.message.serialize().to_vec();
    Ok((start.state, message))
}

/// Step 3 of login (client). Consumes the persisted login state, the password,
/// and the server's serialized `CredentialResponse`. Returns the `export_key`
/// truncated to [`EXPORT_KEY_LEN`] bytes — the durable secret used to wrap local
/// key material. A wrong password fails with [`OpaqueError::Protocol`].
///
/// API note: opaque-ke 4.0.1 requires the password and an `rng` at finish
/// (`ClientLogin::finish` gained an rng parameter in 4.x). Use
/// [`login_finish_full`] when the AKE `session_key` or the
/// `CredentialFinalization` message are also needed.
pub fn login_finish<R: RngCore + CryptoRng>(
    client_login: ClientLogin<DefaultCipherSuite>,
    password: &[u8],
    server_message: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, OpaqueError> {
    let result = login_finish_full(client_login, password, server_message, rng)?;
    // Index into the GenericArray directly (avoids the deprecated as_slice).
    Ok(result.export_key[..EXPORT_KEY_LEN].to_vec())
}

/// Step 3 of login (client), returning the full result so callers can access
/// the `session_key`, `export_key`, and the `CredentialFinalization` message
/// (`result.message`) that must be sent to the server to complete the AKE.
pub fn login_finish_full<R: RngCore + CryptoRng>(
    client_login: ClientLogin<DefaultCipherSuite>,
    password: &[u8],
    server_message: &[u8],
    rng: &mut R,
) -> Result<ClientLoginFinishResult<DefaultCipherSuite>, OpaqueError> {
    let response = CredentialResponse::<DefaultCipherSuite>::deserialize(server_message)
        .map_err(|_| OpaqueError::Deserialize)?;
    let result = client_login.finish(
        rng,
        password,
        response,
        ClientLoginFinishParameters::default(),
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::rand::rngs::OsRng;
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };

    // ---- server-side simulation (delegates entirely to opaque-ke) ----

    fn server_register(
        setup: &ServerSetup<DefaultCipherSuite>,
        identity: &[u8],
        client_request_bytes: &[u8],
    ) -> Vec<u8> {
        let request =
            RegistrationRequest::<DefaultCipherSuite>::deserialize(client_request_bytes).unwrap();
        ServerRegistration::<DefaultCipherSuite>::start(setup, request, identity)
            .unwrap()
            .message
            .serialize()
            .to_vec()
    }

    fn server_store_password_file(client_upload_bytes: &[u8]) -> Vec<u8> {
        let upload =
            RegistrationUpload::<DefaultCipherSuite>::deserialize(client_upload_bytes).unwrap();
        ServerRegistration::<DefaultCipherSuite>::finish(upload)
            .serialize()
            .to_vec()
    }

    #[allow(clippy::type_complexity)]
    fn server_login_start(
        setup: &ServerSetup<DefaultCipherSuite>,
        identity: &[u8],
        password_file_bytes: &[u8],
        client_request_bytes: &[u8],
    ) -> (ServerLogin<DefaultCipherSuite>, Vec<u8>) {
        let mut rng = OsRng;
        let password_file =
            ServerRegistration::<DefaultCipherSuite>::deserialize(password_file_bytes).unwrap();
        let request =
            CredentialRequest::<DefaultCipherSuite>::deserialize(client_request_bytes).unwrap();
        let start = ServerLogin::start(
            &mut rng,
            setup,
            Some(password_file),
            request,
            identity,
            ServerLoginParameters::default(),
        )
        .unwrap();
        let message = start.message.serialize().to_vec();
        (start.state, message)
    }

    fn server_login_finish(
        state: ServerLogin<DefaultCipherSuite>,
        client_finalization_bytes: &[u8],
    ) -> Vec<u8> {
        let finalization =
            CredentialFinalization::<DefaultCipherSuite>::deserialize(client_finalization_bytes)
                .unwrap();
        state
            .finish(finalization, ServerLoginParameters::default())
            .unwrap()
            .session_key
            .to_vec()
    }

    /// Full client<->server OPAQUE round-trip. Asserts:
    ///  - the AKE session keys derived independently by client and server match,
    ///  - the registration export key equals the login export key (proves the
    ///    same password produced the same durable secret).
    #[test]
    fn test_opaque_registration_login_roundtrip() {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
        let identity = b"alice@powehi.test";
        let password = b"correct horse battery staple";

        // --- Registration ---
        let (reg_state, reg_request) = registration_start(password, &mut rng).unwrap();
        let reg_response = server_register(&server_setup, identity, &reg_request);
        let (reg_finish, reg_upload) =
            registration_finish(reg_state, password, &reg_response, &mut rng).unwrap();
        let password_file = server_store_password_file(&reg_upload);

        // --- Login ---
        let (login_state, login_request) = login_start(password, &mut rng).unwrap();
        let (server_login_state, login_response) =
            server_login_start(&server_setup, identity, &password_file, &login_request);
        let login_full = login_finish_full(login_state, password, &login_response, &mut rng)
            .expect("login with correct password must succeed");
        let finalization = login_full.message.serialize().to_vec();
        let server_session_key = server_login_finish(server_login_state, &finalization);

        // AKE session keys must match between client and server.
        // (Slice via indexing to avoid the deprecated GenericArray::as_slice.)
        assert_eq!(
            &login_full.session_key[..],
            server_session_key.as_slice(),
            "client/server OPAQUE session keys must agree"
        );

        // The durable export key must be identical across registration and login.
        assert_eq!(
            &reg_finish.export_key[..],
            &login_full.export_key[..],
            "export key must be stable for the same password"
        );

        // Sanity: export key is long enough for the wrapping-key prefix.
        assert!(login_full.export_key.len() >= EXPORT_KEY_LEN);
    }

    /// A login attempt with the wrong password must fail (client-side MAC
    /// verification rejects the server response) — it must NOT silently produce
    /// a key that matches the server.
    #[test]
    fn test_opaque_wrong_password_fails() {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
        let identity = b"bob@powehi.test";
        let real_password = b"s3cr3t-passphrase";
        let wrong_password = b"not-the-password";

        // Register with the real password.
        let (reg_state, reg_request) = registration_start(real_password, &mut rng).unwrap();
        let reg_response = server_register(&server_setup, identity, &reg_request);
        let (_reg_finish, reg_upload) =
            registration_finish(reg_state, real_password, &reg_response, &mut rng).unwrap();
        let password_file = server_store_password_file(&reg_upload);

        // Attempt login with the wrong password — must be rejected client-side.
        let (login_state, login_request) = login_start(wrong_password, &mut rng).unwrap();
        let (_server_login_state, login_response) =
            server_login_start(&server_setup, identity, &password_file, &login_request);
        let result = login_finish(login_state, wrong_password, &login_response, &mut rng);

        assert!(
            result.is_err(),
            "login with the wrong password must be rejected client-side"
        );
    }
}
