use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for UserId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Handle is stored only as a hash — server never sees the plaintext handle.
#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    /// SHA-256 of the plaintext handle; server never stores the handle itself.
    pub handle_hash: Vec<u8>,
    /// OPAQUE password file (ServerRegistration serialized bytes). Empty until
    /// register_finish completes. Server MUST NOT inspect or log these bytes.
    pub opaque_password_file: Vec<u8>,
    /// Raw 32-byte Ed25519 verifying key deterministically derived from the user's
    /// BIP-39 recovery phrase (prd.md §8.5). Set once at registration. `None` means
    /// the account is not enrolled in phrase-based recovery (registered before this
    /// feature, or opted out) and therefore CANNOT restore via the recovery path —
    /// fail-closed by design. Server never logs or inspects these bytes.
    pub recovery_pubkey: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Debug prints lengths only: the OPAQUE password file is an offline-guessing target and the
/// handle hash and recovery key identify the account.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("handle_hash_len", &self.handle_hash.len())
            .field("opaque_password_file_len", &self.opaque_password_file.len())
            .field("recovery_pubkey_set", &self.recovery_pubkey.is_some())
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl User {
    /// Stub / test constructor — opaque_password_file is empty.
    pub fn new(id: UserId, handle_hash: Vec<u8>) -> Self {
        let now = Utc::now();
        Self {
            id,
            handle_hash,
            opaque_password_file: vec![],
            recovery_pubkey: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Production constructor — created after OPAQUE register_finish.
    pub fn registered(id: UserId, handle_hash: Vec<u8>, opaque_password_file: Vec<u8>) -> Self {
        let now = Utc::now();
        Self {
            id,
            handle_hash,
            opaque_password_file,
            recovery_pubkey: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_is_unique() {
        assert_ne!(UserId::new(), UserId::new());
    }

    #[test]
    fn debug_output_hides_password_file_handle_hash_and_recovery_key() {
        let mut user = User::registered(UserId::new(), vec![0xAB; 32], vec![0xCD; 64]);
        user.recovery_pubkey = Some(vec![0xEF; 32]);
        let out = format!("{user:?}");
        assert!(!out.contains("171, 171"), "handle_hash bytes leaked: {out}");
        assert!(
            !out.contains("205, 205"),
            "password file bytes leaked: {out}"
        );
        assert!(
            !out.contains("239, 239"),
            "recovery key bytes leaked: {out}"
        );
        assert!(!out.contains("opaque_password_file:"), "{out}");
        assert!(out.contains("opaque_password_file_len: 64"), "{out}");
        assert!(out.contains("handle_hash_len: 32"), "{out}");
        assert!(out.contains("recovery_pubkey_set: true"), "{out}");
    }

    #[test]
    fn user_new_sets_timestamps() {
        let user = User::new(UserId::new(), vec![0u8; 32]);
        assert_eq!(user.created_at, user.updated_at);
    }
}
