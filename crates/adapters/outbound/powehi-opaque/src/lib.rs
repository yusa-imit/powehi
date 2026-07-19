//! OPAQUE server-side adapter (RFC 9807 / opaque-ke 4.x).
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
//! NOTE: opaque-ke 4.0.1 implements the published RFC 9807 (OPAQUE) stable
//! release. In 4.x the AKE hash is an explicit ciphersuite parameter
//! (`TripleDh<KeGroup, Hash>`); for the Ristretto255 suite this is SHA-512,
//! matching the value opaque-ke 3.x derived implicitly — so the wire format
//! is unchanged. This suite MUST match the client (powehi-crypto-wasm).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use powehi_domain::error::DomainError;
use powehi_port_outbound::opaque::OpaqueServerPort;
use rand::rngs::OsRng;

/// OPAQUE ciphersuite — must match the client (powehi-crypto-wasm/src/opaque.rs).
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
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
            ServerLoginParameters::default(),
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
            .finish(finalization, ServerLoginParameters::default())
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
            .finish(
                &mut rng,
                password,
                ke2_msg,
                ClientLoginFinishParameters::default(),
            )
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
            &mut rng,
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

/// Cross-version interop regression test (closes crypto-reviewer YELLOW, cycle 318).
///
/// When the 3.0 -> 4.0.1 upgrade landed, the wire-format-compatibility claim was
/// proven only by source inspection — no stored blob was ever round-tripped. This
/// module supplies that missing evidence with a real fixture captured from the
/// pre-migration ciphersuite, and in doing so surfaced a concrete finding (see
/// [`v3_server_setup_is_not_loadable_under_v4`]).
///
/// ## Result summary
/// - The per-user password-file blob (`ServerRegistration`, the record stored in
///   Postgres) IS byte-compatible: a 3.0.0-serialized record deserializes cleanly
///   under 4.0.1. See [`v3_password_file_deserializes_under_v4`].
/// - The server long-term `ServerSetup` (OPRF seed + AKE keypair) is NOT
///   wire-compatible across the 3.0 -> 4.0.1 boundary (both are 128 bytes, but
///   4.0.1 rejects the 3.0 layout with `SerializationError`). See
///   [`v3_server_setup_is_not_loadable_under_v4`].
///
/// ## Why this is a *deserialize-only* proof (documented follow-up gap)
/// A full login round-trip against the stored password file is impossible across
/// this version boundary: at login, opaque-ke re-derives the user's OPRF key from
/// `ServerSetup.oprf_seed` + credential identifier, so a valid login needs the
/// *original* `ServerSetup`. Because the 3.0 `ServerSetup` cannot be loaded under
/// 4.0.1, there is no way to reproduce the OPRF key that sealed the fixture's
/// envelope, and thus no way to open it. Password-file portability is therefore
/// *necessary but not sufficient* for a live-data migration — the `ServerSetup`
/// must also be portable (or every user must re-register). This is a smaller
/// follow-up gap: a within-version full login round trip is already covered by
/// `tests::login_roundtrip_session_keys_match`; what remains untestable here is a
/// cross-version *login*, which is blocked by the ServerSetup incompatibility
/// rather than by the password-file format.
///
/// Practical impact today: NONE. Powehi has no production users, and
/// `ServerSetup` is currently regenerated on every startup (a tracked Phase-5
/// limitation), so no persisted `ServerSetup` or password file exists to migrate.
/// The value of this test is forward-looking: the next opaque-ke major bump that
/// touches live password files must carry both a password-file fixture like this
/// one AND an explicit `ServerSetup` migration/re-key story.
///
/// ## How the fixture was generated (reproducible)
/// A throwaway standalone crate (NOT committed; opaque-ke 3.0 is never a
/// dependency of any workspace crate) pinned to `opaque-ke = "3"` (resolved
/// 3.0.0), features `["ristretto255", "argon2"]`, with the EXACT pre-cycle-318
/// ciphersuite from git `548289f^`:
/// ```ignore
/// type OprfCs      = Ristretto255;
/// type KeGroup     = Ristretto255;                       // implicit in 4.x
/// type KeyExchange = key_exchange::tripledh::TripleDh;    // implicit SHA-512
/// type Ksf         = Argon2<'static>;
/// ```
/// A single `ChaCha20Rng::from_seed(SEED)` drove the whole flow so re-running
/// reproduces identical bytes:
///  1. `ServerSetup::new(&mut rng)`               -> `SERVER_SETUP_V3_HEX` (128 B)
///  2. full registration for (USER_IDENTITY, PASSWORD)
///     -> `ServerRegistration::finish(..).serialize()` = `PASSWORD_FILE_V3_HEX` (192 B)
///
/// The generator also self-verified a full 3.x login round-trip before printing,
/// so the password-file fixture is known-good under its own version.
///
/// ```text
/// SEED           = b"powehi-opaque-v3-interop-seed-01"
/// USER_IDENTITY  = b"interop-fixture@powehi.test"
/// PASSWORD       = b"correct horse battery staple v3"
/// ```
///
/// Note: the stored `ServerRegistration` blob is Argon2-parameter-independent
/// (the server never runs the KSF at `registration_finish`), so this fixture is
/// stable regardless of Argon2 default-param drift.
#[cfg(test)]
mod interop_v3 {
    use super::*;

    /// `ServerSetup::<3.x DefaultCipherSuite>::serialize()` — 128 bytes.
    const SERVER_SETUP_V3_HEX: &str = "1363fb84bd5b2df625b5c9bfe22a04e4eb39944bfbe0e54f3de80fb143b9ff5cb20f4162559458f552d0f6a8ea39423d118a2535911dd1e957963bcbe9e34c532cd18d7d450d11655b375d111aa360b625f74b6487309eafca956f3a4f251303b69d15965714bb3a196222fd121fc2cb02af8403acf0e36ab2b43a09465ca10b";

    /// `ServerRegistration::<3.x DefaultCipherSuite>::finish(..).serialize()` — 192 bytes.
    const PASSWORD_FILE_V3_HEX: &str = "de1a876fad96e09911e657c405f445edb0d259487c95603b3855659828d431110f19a7a67d448d0ddb107ae09067da93759a9580d4a9148247e09cdd41c2c234b5cad6826fd958c8572136e78bc425e147a7ef334ee8bce19b8f9aa79824be46bd0755deb098de38c5b1d20e6c2520fdd771cb6fee6d28a81397ba13e7765b08dd019dd60fbb9a2c2aefafb9e9eb8370598cde3ffbc78c0a48a26b474f84188d9baed9f8e36f92d50bc8bbcdcdaf52862d9eb2c048ba8e8e60f76b1f238aadae";

    fn from_hex(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex fixture must have even length"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex in fixture"))
            .collect()
    }

    /// Core proof: a per-user password-file blob serialized by opaque-ke 3.0.0
    /// deserializes cleanly under the current 4.0.1 `DefaultCipherSuite`. This is
    /// the invariant the crypto-reviewer flagged as untested.
    #[test]
    fn v3_password_file_deserializes_under_v4() {
        let bytes = from_hex(PASSWORD_FILE_V3_HEX);
        assert_eq!(
            bytes.len(),
            192,
            "Ristretto255 v3 password-file size (client pubkey 32 + masking key 64 + envelope 96)"
        );
        let record = ServerRegistration::<DefaultCipherSuite>::deserialize(&bytes);
        assert!(
            record.is_ok(),
            "opaque-ke 3.0.0 ServerRegistration blob must deserialize under 4.0.1: {:?}",
            record.err()
        );
    }

    /// Documented finding: the 3.0 `ServerSetup` is NOT loadable under 4.0.1, so a
    /// live-data migration cannot rely on password-file compatibility alone. This
    /// test locks in the current incompatibility; if a future opaque-ke version
    /// makes `ServerSetup` portable, this assertion will fail and force whoever
    /// bumps the dependency to revisit the migration story documented on this
    /// module. (Both blobs are 128 bytes — the divergence is layout, not length.)
    #[test]
    fn v3_server_setup_is_not_loadable_under_v4() {
        let bytes = from_hex(SERVER_SETUP_V3_HEX);
        assert_eq!(bytes.len(), 128, "Ristretto255 v3 ServerSetup size");
        let setup = ServerSetup::<DefaultCipherSuite>::deserialize(&bytes);
        assert!(
            setup.is_err(),
            "expected 3.0 ServerSetup to be REJECTED by 4.0.1 (documented \
             cross-version incompatibility); if this now succeeds, opaque-ke \
             changed and the migration story on `mod interop_v3` must be updated"
        );
    }
}
