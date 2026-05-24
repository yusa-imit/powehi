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

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Handle is stored only as a hash — server never sees the plaintext handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    /// SHA-256 of the plaintext handle; server never stores the handle itself.
    pub handle_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(id: UserId, handle_hash: Vec<u8>) -> Self {
        let now = Utc::now();
        Self {
            id,
            handle_hash,
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
    fn user_new_sets_timestamps() {
        let user = User::new(UserId::new(), vec![0u8; 32]);
        assert_eq!(user.created_at, user.updated_at);
    }
}
