use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },
    #[error("region mismatch: operation for {target} routed to {local}")]
    RegionMismatch { target: String, local: String },
    #[error("internal: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_error_display_not_found() {
        let e = DomainError::NotFound("user-123".into());
        assert_eq!(e.to_string(), "not found: user-123");
    }

    #[test]
    fn domain_error_display_epoch_mismatch() {
        let e = DomainError::EpochMismatch {
            expected: 5,
            got: 3,
        };
        assert_eq!(e.to_string(), "epoch mismatch: expected 5, got 3");
    }

    #[test]
    fn domain_error_display_region_mismatch() {
        let e = DomainError::RegionMismatch {
            target: "ap-seoul".into(),
            local: "eu-central".into(),
        };
        assert!(e.to_string().contains("ap-seoul"));
        assert!(e.to_string().contains("eu-central"));
    }

    #[test]
    fn domain_error_is_clone_and_eq() {
        let e1 = DomainError::Unauthorized;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }
}
