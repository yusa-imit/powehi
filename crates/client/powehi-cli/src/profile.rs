//! Profile naming and per-profile data directory layout (prd.md §7A.3).

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Longest accepted profile name, in bytes.
pub const MAX_PROFILE_LEN: usize = 64;

/// Directory under the user data dir that holds all profiles.
const APP_DIR: &str = "powehi";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("must not be empty")]
    Empty,
    #[error("longer than {MAX_PROFILE_LEN} bytes")]
    TooLong,
    #[error(
        "only lowercase ASCII letters, digits, '-' and '_' are allowed; first must be alphanumeric"
    )]
    BadChars,
}

/// Validates a profile name. The name becomes a path component, so anything that could
/// traverse or alias (separators, dots, whitespace, NUL) is rejected.
pub fn validate_name(name: &str) -> Result<(), ProfileError> {
    if name.is_empty() {
        return Err(ProfileError::Empty);
    }
    if name.len() > MAX_PROFILE_LEN {
        return Err(ProfileError::TooLong);
    }
    let first_ok = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest_ok = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(ProfileError::BadChars)
    }
}

/// Resolved on-disk location of one profile. Creating the directory (mode 0700) is the
/// profile store's job (Phase 7.3); resolving is pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePaths {
    pub dir: PathBuf,
}

impl ProfilePaths {
    /// `<base>/powehi/<name>`.
    pub fn resolve(base: &Path, name: &str) -> Result<Self, ProfileError> {
        validate_name(name)?;
        let dir = base.join(APP_DIR).join(name);
        debug_assert!(dir.starts_with(base));
        Ok(Self { dir })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_names() {
        for n in ["default", "work-1", "a_b", "9"] {
            assert_eq!(validate_name(n), Ok(()), "{n}");
        }
    }

    #[test]
    fn rejects_traversal_and_odd_names() {
        for n in [
            "", ".", "..", "../x", "a/b", "a\\b", "-x", "_x", "a b", "a\0b", "é", "Work",
        ] {
            assert!(validate_name(n).is_err(), "{n:?}");
        }
        assert_eq!(
            validate_name(&"a".repeat(MAX_PROFILE_LEN + 1)),
            Err(ProfileError::TooLong)
        );
        assert_eq!(validate_name(&"a".repeat(MAX_PROFILE_LEN)), Ok(()));
    }

    #[test]
    fn resolve_nests_under_base() {
        let p = ProfilePaths::resolve(Path::new("/d"), "work").unwrap();
        assert_eq!(p.dir, Path::new("/d/powehi/work"));
        assert!(ProfilePaths::resolve(Path::new("/d"), "../x").is_err());
    }
}
