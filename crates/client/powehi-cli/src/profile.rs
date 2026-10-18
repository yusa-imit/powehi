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

/// Most profiles `list` reports; a directory with more is cut off, never scanned unbounded.
pub const MAX_LISTED: usize = 256;

/// Writes the names one per line, or only their number when `count` is set.
pub fn write_listing(
    names: &[String],
    count: bool,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    assert!(names.len() <= MAX_LISTED);
    if count {
        return writeln!(out, "{}", names.len());
    }
    for n in names {
        writeln!(out, "{n}")?;
    }
    Ok(())
}

/// Names of the profiles under `<base>/powehi`, sorted. Only directories with a valid
/// profile name count (stray files and odd names are skipped). A missing directory means no
/// profiles yet. Reads names only: never opens a store, so it needs no password.
pub fn list(base: &Path) -> Result<Vec<String>, std::io::Error> {
    let entries = match std::fs::read_dir(base.join(APP_DIR)) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut names = Vec::new();
    for entry in entries.take(MAX_LISTED * 4) {
        let entry = entry?;
        // `file_type` does not follow symlinks, so a link is never listed as a profile.
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if validate_name(&name).is_ok() {
            names.push(name);
        }
    }
    names.sort();
    names.truncate(MAX_LISTED);
    debug_assert!(names.iter().all(|n| validate_name(n).is_ok()));
    Ok(names)
}

#[cfg(test)]
mod tests {
    #[test]
    fn listing_prints_names_or_only_the_count() {
        let names = vec!["a".to_string(), "work".to_string()];
        let (mut full, mut counted) = (Vec::new(), Vec::new());
        write_listing(&names, false, &mut full).unwrap();
        write_listing(&names, true, &mut counted).unwrap();
        assert_eq!(String::from_utf8(full).unwrap(), "a\nwork\n");
        assert_eq!(String::from_utf8(counted).unwrap(), "2\n");
        let mut none = Vec::new();
        write_listing(&[], true, &mut none).unwrap();
        assert_eq!(String::from_utf8(none).unwrap(), "0\n");
    }

    use super::*;

    #[test]
    fn list_missing_dir_is_empty() {
        let d = tempfile::tempdir().unwrap();
        assert!(list(d.path()).unwrap().is_empty());
    }

    #[test]
    fn list_returns_sorted_valid_profile_dirs_only() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join(APP_DIR);
        for n in ["work", "default", "Bad", ".hidden", "a b"] {
            std::fs::create_dir_all(root.join(n)).unwrap();
        }
        std::fs::write(root.join("file"), b"x").unwrap();
        assert_eq!(list(d.path()).unwrap(), ["default", "work"]);
    }

    #[cfg(unix)]
    #[test]
    fn list_skips_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join(APP_DIR);
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        assert_eq!(list(d.path()).unwrap(), ["real"]);
    }

    #[test]
    fn list_is_bounded() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join(APP_DIR);
        for i in 0..MAX_LISTED + 5 {
            std::fs::create_dir_all(root.join(format!("p{i:04}"))).unwrap();
        }
        assert_eq!(list(d.path()).unwrap().len(), MAX_LISTED);
    }

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
