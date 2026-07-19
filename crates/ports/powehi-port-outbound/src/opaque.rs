use powehi_domain::error::DomainError;

/// Server-side OPAQUE operations (RFC 9807 / opaque-ke 4.x).
///
/// All methods are sync: OPAQUE is pure CPU crypto with no I/O.
///
/// ## Session binding (R-1/R-2)
/// `login_start` accepts a caller-supplied `nonce` that becomes the key for
/// the pending-login state map. The nonce MUST be a random, server-generated
/// value (e.g. UUID v4 bytes) that is not predictable by the client. The
/// client must return the nonce in `login_finish`; the adapter verifies it
/// and removes the entry atomically, preventing cross-session hijack and
/// trivial DoS via identity overwrite.
///
/// ## Unknown-user synthetic KE2 (R-3)
/// `login_start` accepts `password_file: Option<&[u8]>`. When `None`, the
/// adapter MUST call `ServerLogin::start(..., None, ...)` to produce a
/// synthetic but indistinguishable KE2, preventing user-existence oracles
/// (RFC 9807 §6.1 / §6.3). The caller should still return this KE2 to the
/// client; the AKE will fail client-side on any password.
///
/// Security: these methods MUST NOT log password, export_key, session_key, or
/// any password-file bytes (rule: no-plaintext-logging).
pub trait OpaqueServerPort: Send + Sync {
    /// Registration step 2 (server): consume the client's RegistrationRequest
    /// (KE1) and produce a RegistrationResponse (KE2).
    fn registration_start(&self, ke1: &[u8], user_identity: &[u8]) -> Result<Vec<u8>, DomainError>;

    /// Registration step 4 (server): consume the client's RegistrationUpload
    /// and return the serialized password file to persist on the User record.
    fn registration_finish(&self, upload: &[u8]) -> Result<Vec<u8>, DomainError>;

    /// Login step 2 (server): produce a CredentialResponse (KE2).
    ///
    /// - `password_file`: `Some(bytes)` for a known user; `None` to generate a
    ///   synthetic KE2 that will fail client-side (unknown-user path).
    /// - `nonce`: server-generated random bytes that identify this pending
    ///   login state in the adapter's map.
    fn login_start(
        &self,
        password_file: Option<&[u8]>,
        ke1: &[u8],
        user_identity: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, DomainError>;

    /// Login step 4 (server): consume the client's CredentialFinalization (KE3).
    /// Returns `(session_key, bound_user_identity)` where `bound_user_identity`
    /// is the identity passed to `login_start`. Callers MUST use this identity
    /// as the session subject — never a client-supplied value (security-auditor
    /// finding #1: server-bound session subject).
    fn login_finish(&self, nonce: &[u8], ke3: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DomainError>;
}
