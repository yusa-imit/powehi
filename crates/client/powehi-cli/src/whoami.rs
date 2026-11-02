//! `whoami`: prints which account a profile is logged in as (ids only, no secrets or content).

use std::io::Write;

use uuid::Uuid;

/// Writes `profile`, `server`, `user` and `device` as `key: value` lines, or as one JSON
/// object with the same keys when `json` is set.
pub fn report(
    profile: &str,
    server: &url::Url,
    user_id: Uuid,
    device_id: Uuid,
    json: bool,
    out: &mut impl Write,
) -> std::io::Result<()> {
    assert!(!profile.is_empty());
    assert!(!user_id.is_nil() && !device_id.is_nil());
    if json {
        let v = serde_json::json!({
            "profile": profile,
            "server": server.as_str(),
            "user": user_id.to_string(),
            "device": device_id.to_string(),
        });
        return writeln!(out, "{v}");
    }
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
        report("work", &server, u, d, false, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(
            s,
            format!("profile: work\nserver: https://example.test/\nuser: {u}\ndevice: {d}\n")
        );
    }

    #[test]
    fn json_is_one_object_line_with_the_same_keys() {
        let server = url::Url::parse("https://example.test/").unwrap();
        let (u, d) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mut out = Vec::new();
        report("work", &server, u, d, true, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.lines().count(), 1);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["profile"], "work");
        assert_eq!(v["server"], "https://example.test/");
        assert_eq!(v["user"], u.to_string());
        assert_eq!(v["device"], d.to_string());
        assert_eq!(v.as_object().unwrap().len(), 4);
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
            false,
            &mut Vec::new(),
        )
        .unwrap();
    }

    mod props {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// Whatever the profile name holds, the JSON report is one line that round-trips
            /// all four fields, and the text report is four `key: value` lines for a plain name.
            #[test]
            fn both_formats_round_trip(
                profile in "[a-zA-Z0-9_.-]{1,32}",
                u in 1u128..,
                d in 1u128..,
            ) {
                let server = url::Url::parse("https://example.test/").unwrap();
                let (u, d) = (Uuid::from_u128(u), Uuid::from_u128(d));
                let mut j = Vec::new();
                report(&profile, &server, u, d, true, &mut j).unwrap();
                prop_assert_eq!(j.iter().filter(|b| **b == b'\n').count(), 1);
                let v: serde_json::Value = serde_json::from_slice(&j).unwrap();
                prop_assert_eq!(v["profile"].as_str(), Some(profile.as_str()));
                let (us, ds) = (u.to_string(), d.to_string());
                prop_assert_eq!(v["user"].as_str(), Some(us.as_str()));
                prop_assert_eq!(v["device"].as_str(), Some(ds.as_str()));
                let mut t = Vec::new();
                report(&profile, &server, u, d, false, &mut t).unwrap();
                let t = String::from_utf8(t).unwrap();
                prop_assert_eq!(t.lines().count(), 4);
                let first = format!("profile: {profile}\n");
                prop_assert!(t.starts_with(&first));
            }

            /// Even a hostile profile string cannot break the JSON report out of one line.
            #[test]
            fn json_stays_one_line_for_any_profile(profile in ".{1,40}") {
                let server = url::Url::parse("https://example.test/").unwrap();
                let mut j = Vec::new();
                report(&profile, &server, Uuid::from_u128(1), Uuid::from_u128(2), true, &mut j)
                    .unwrap();
                prop_assert_eq!(j.iter().filter(|b| **b == b'\n').count(), 1);
                let v: serde_json::Value = serde_json::from_slice(&j).unwrap();
                prop_assert_eq!(v["profile"].as_str(), Some(profile.as_str()));
            }
        }
    }
}
