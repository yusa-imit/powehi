//! OPAQUE server-side adapter (RFC 9807 / opaque-ke 3.x).
//!
//! Ciphersuite: Ristretto255 OPRF + TripleDH key exchange + Argon2id KSF.
//! This MUST stay byte-for-byte consistent with the client-side suite in
//! `crates/client/powehi-crypto-wasm/src/opaque.rs`.
//!
//! Security properties:
//! - No password, export_key, session_key, or password-file bytes are ever
//!   logged (rule: no-plaintext-logging).
//! - All OPAQUE errors are collapsed to opaque DomainError variants.
//! - Unknown-user `login_start` produces a synthetic KE2 (RFC 9807 §6.1/§6.3)
//!   so callers cannot distinguish "user exists" from "user does not exist".
//! - Pending login states are keyed by a server-issued random nonce (not
//!   user_identity), preventing cross-session hijack (R-1/R-2).
//!
//! Known limitations (tracked for Phase 5):
//! - `ServerSetup` is regenerated on startup; all stored `opaque_password_file`
//!   records become invalid after a restart. Production must load from secure
//!   key storage. A startup guard is required before any production deploy.
//! - `Identifiers` are not bound in the AKE transcript (Y-4); both client and
//!   server use `default()`. This is deferred to a joint client+server fix.
//!
//! NOTE: opaque-ke 3.0 implements draft-irtf-cfrg-opaque-16, not RFC 9807
//! byte-for-byte. Upgrade to opaque-ke 4.x tracked in crypto-libraries-pinned.md.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use powehi_domain::error::DomainError;
use powehi_port_outbound::opaque::OpaqueServerPort;
use rand::rngs::OsRng;

/// OPAQUE ciphersuite — must match the client (powehi-crypto-wasm/src/opaque.rs).
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

const PENDING_TTL: Duration = Duration::from_secs(300);

struct PendingLogin {
    state: ServerLogin<DefaultCipherSuite>,
    created_at: Instant,
    /// Server-bound user identity stored at login_start; returned by login_finish
    /// so the caller never uses a client-supplied value as the session subject.
    user_identity: Vec<u8>,
}

/// Server-side OPAQUE adapter. Holds the ServerSetup keypair and a short-lived
/// map of in-flight login states keyed by server-issued nonce (not user UUID).
pub struct OpaqueServer {
    setup: ServerSetup<DefaultCipherSuite>,
    pending: Mutex<HashMap<Vec<u8>, PendingLogin>>,
}

impl OpaqueServer {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
        Self {
            setup,
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn lock_pending(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, PendingLogin>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Default for OpaqueServer {
    fn default() -> Self {
        Self::new()
    }
}

impl OpaqueServerPort for OpaqueServer {
    fn registration_start(&self, ke1: &[u8], user_identity: &[u8]) -> Result<Vec<u8>, DomainError> {
        let request = RegistrationRequest::<DefaultCipherSuite>::deserialize(ke1)
            .map_err(|_| DomainError::InvalidInput("opaque: bad registration request".into()))?;
        let result =
            ServerRegistration::<DefaultCipherSuite>::start(&self.setup, request, user_identity)
                .map_err(|_| DomainError::Internal("opaque: registration_start failed".into()))?;
        Ok(result.message.serialize().to_vec())
    }

    fn registration_finish(&self, upload: &[u8]) -> Result<Vec<u8>, DomainError> {
        let upload = RegistrationUpload::<DefaultCipherSuite>::deserialize(upload)
            .map_err(|_| DomainError::InvalidInput("opaque: bad registration upload".into()))?;
        let password_file = ServerRegistration::<DefaultCipherSuite>::finish(upload);
        Ok(password_file.serialize().to_vec())
    }

    fn login_start(
        &self,
        password_file: Option<&[u8]>,
        ke1: &[u8],
        user_identity: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, DomainError> {
        let mut rng = OsRng;
        let pf = match password_file {
            Some(bytes) => {
                let record = ServerRegistration::<DefaultCipherSuite>::deserialize(bytes)
                    .map_err(|_| DomainError::Internal("opaque: bad password file".into()))?;
                Some(record)
            }
            None => None, // unknown user: synthetic KE2 (RFC 9807 §6.1/§6.3)
        };
        let request = CredentialRequest::<DefaultCipherSuite>::deserialize(ke1)
            .map_err(|_| DomainError::InvalidInput("opaque: bad credential request".into()))?;
        let result = ServerLogin::start(
            &mut rng,
            &self.setup,
            pf,
            request,
            user_identity,
            ServerLoginStartParameters::default(),
        )
        .map_err(|_| DomainError::Internal("opaque: login_start failed".into()))?;

        let ke2 = result.message.serialize().to_vec();
        let mut pending = self.lock_pending();
        let now = Instant::now();
        pending.retain(|_, v| now.duration_since(v.created_at) < PENDING_TTL);
        pending.insert(
            nonce.to_vec(),
            PendingLogin {
                state: result.state,
                created_at: now,
                user_identity: user_identity.to_vec(),
            },
        );
        Ok(ke2)
    }

    fn login_finish(&self, nonce: &[u8], ke3: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DomainError> {
        let entry = {
            let mut pending = self.lock_pending();
            // Check TTL before consuming the entry (Y-1: TTL check must precede remove).
            match pending.get(nonce) {
                None => return Err(DomainError::Unauthorized),
                Some(e) if Instant::now().duration_since(e.created_at) >= PENDING_TTL => {
                    pending.remove(nonce);
                    return Err(DomainError::Unauthorized);
                }
                Some(_) => pending.remove(nonce).expect("just verified presence"),
            }
        };
        let finalization = CredentialFinalization::<DefaultCipherSuite>::deserialize(ke3)
            .map_err(|_| DomainError::Unauthorized)?;
        let result = entry
            .state
            .finish(finalization)
            .map_err(|_| DomainError::Unauthorized)?;
        // Return (session_key, bound_user_identity) — caller uses the identity
        // as the session subject, never a client-supplied value.
        Ok((result.session_key.to_vec(), entry.user_identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters,
    };

    const TEST_NONCE: &[u8] = b"test-nonce-32-bytes-random-uuid!";

    fn full_registration(server: &OpaqueServer, identity: &[u8], password: &[u8]) -> Vec<u8> {
        let mut rng = OsRng;
        let start = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
        let ke1 = start.message.serialize().to_vec();
        let ke2 = server.registration_start(&ke1, identity).unwrap();
        let ke2_msg =
            opaque_ke::RegistrationResponse::<DefaultCipherSuite>::deserialize(&ke2).unwrap();
        let finish = start
            .state
            .finish(
                &mut rng,
                password,
                ke2_msg,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let upload = finish.message.serialize().to_vec();
        server.registration_finish(&upload).unwrap()
    }

    #[test]
    fn registration_start_produces_valid_ke2() {
        let server = OpaqueServer::new();
        let mut rng = OsRng;
        let start = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, b"password").unwrap();
        let ke1 = start.message.serialize().to_vec();
        let ke2 = server.registration_start(&ke1, b"alice").unwrap();
        assert!(!ke2.is_empty());
    }

    #[test]
    fn registration_finish_produces_password_file() {
        let server = OpaqueServer::new();
        let pf = full_registration(&server, b"alice", b"correct horse battery staple");
        assert!(!pf.is_empty());
    }

    #[test]
    fn login_roundtrip_session_keys_match() {
        let server = OpaqueServer::new();
        let identity = b"bob@powehi.test";
        let password = b"s3cr3t-passphrase";
        let password_file = full_registration(&server, identity, password);

        let mut rng = OsRng;
        let login_start = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password).unwrap();
        let ke1 = login_start.message.serialize().to_vec();
        let ke2 = server
            .login_start(Some(&password_file), &ke1, identity, TEST_NONCE)
            .unwrap();
        let ke2_msg =
            opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(&ke2).unwrap();
        let finish = login_start
            .state
            .finish(password, ke2_msg, ClientLoginFinishParameters::default())
            .unwrap();
        let client_session_key: Vec<u8> = finish.session_key[..].to_vec();
        let ke3 = finish.message.serialize().to_vec();
        let (server_session_key, bound_identity) = server.login_finish(TEST_NONCE, &ke3).unwrap();

        assert_eq!(
            client_session_key, server_session_key,
            "client and server session keys must agree"
        );
        assert_eq!(
            bound_identity, identity,
            "bound identity must match login_start input"
        );
    }

    #[test]
    fn login_wrong_password_rejected_client_side() {
        let server = OpaqueServer::new();
        let identity = b"carol@powehi.test";
        let password_file = full_registration(&server, identity, b"real-password");

        let mut rng = OsRng;
        let login_start =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, b"wrong-password").unwrap();
        let ke1 = login_start.message.serialize().to_vec();
        let ke2 = server
            .login_start(Some(&password_file), &ke1, identity, TEST_NONCE)
            .unwrap();
        let ke2_msg =
            opaque_ke::CredentialResponse::<DefaultCipherSuite>::deserialize(&ke2).unwrap();
        let result = login_start.state.finish(
            b"wrong-password",
            ke2_msg,
            ClientLoginFinishParameters::default(),
        );
        assert!(
            result.is_err(),
            "wrong password must be rejected client-side"
        );
    }

    #[test]
    fn login_finish_without_start_returns_unauthorized() {
        let server = OpaqueServer::new();
        let err = server.login_finish(b"ghost-nonce", &[0u8; 64]);
        assert!(matches!(err, Err(DomainError::Unauthorized)));
    }

    #[test]
    fn unknown_user_synthetic_ke2_is_non_empty() {
        let server = OpaqueServer::new();
        let mut rng = OsRng;
        let login_start = ClientLogin::<DefaultCipherSuite>::start(&mut rng, b"password").unwrap();
        let ke1 = login_start.message.serialize().to_vec();
        // None → unknown user, must still produce a KE2 (R-3)
        let ke2 = server
            .login_start(None, &ke1, b"ghost@powehi.test", TEST_NONCE)
            .unwrap();
        assert!(
            !ke2.is_empty(),
            "unknown-user synthetic ke2 must be non-empty"
        );
    }

    #[test]
    fn bad_ke1_registration_start_returns_invalid_input() {
        let server = OpaqueServer::new();
        let err = server.registration_start(&[0u8; 5], b"alice");
        assert!(matches!(err, Err(DomainError::InvalidInput(_))));
    }

    #[test]
    fn second_login_start_with_same_nonce_overwrites_first() {
        // Document: same nonce → state overwrite (callers must use unique nonces)
        let server = OpaqueServer::new();
        let identity = b"dave@powehi.test";
        let password_file = full_registration(&server, identity, b"pw");
        let mut rng = OsRng;

        let s1 = ClientLogin::<DefaultCipherSuite>::start(&mut rng, b"pw").unwrap();
        let ke1_a = s1.message.serialize().to_vec();
        server
            .login_start(Some(&password_file), &ke1_a, identity, TEST_NONCE)
            .unwrap();

        // Second start with same nonce overwrites
        let s2 = ClientLogin::<DefaultCipherSuite>::start(&mut rng, b"pw").unwrap();
        let ke1_b = s2.message.serialize().to_vec();
        server
            .login_start(Some(&password_file), &ke1_b, identity, TEST_NONCE)
            .unwrap();

        // Only one pending entry for this nonce — the second one
        let count = server.lock_pending().len();
        assert_eq!(count, 1, "same nonce → single pending entry");
    }
}
