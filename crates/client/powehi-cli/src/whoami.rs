//! `whoami`: prints which account a profile is logged in as (ids only, no secrets or content).

use std::io::Write;

use uuid::Uuid;

/// Writes `profile`, `server`, `user` and `device` as `key: value` lines.
pub fn report(
    profile: &str,
    server: &url::Url,
    user_id: Uuid,
    device_id: Uuid,
    out: &mut impl Write,
) -> std::io::Result<()> {
    assert!(!profile.is_empty());
    assert!(!user_id.is_nil() && !device_id.is_nil());
    writeln!(out, "profile: {profile}")?;
    writeln!(out, "server: {server}")?;
    writeln!(out, "user: {user_id}")?;
    writeln!(out, "device: {device_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_four_lines_and_no_token() {
        let server = url::Url::parse("https://example.test/").unwrap();
        let (u, d) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mut out = Vec::new();
        report("work", &server, u, d, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(
            s,
            format!("profile: work\nserver: https://example.test/\nuser: {u}\ndevice: {d}\n")
        );
    }

    #[test]
    #[should_panic]
    fn nil_user_is_a_contract_violation() {
        let server = url::Url::parse("https://example.test/").unwrap();
        report(
            "work",
            &server,
            Uuid::nil(),
            Uuid::from_u128(2),
            &mut Vec::new(),
        )
        .unwrap();
    }
}
