//! Black-box checks of the `powehi` binary skeleton.

use std::process::Command;

fn powehi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_powehi"))
}

#[test]
fn help_lists_subcommands() {
    let out = powehi().arg("--help").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for c in [
        "status", "register", "login", "whoami", "invite", "send", "inbox", "chat", "verify",
    ] {
        assert!(s.contains(c), "missing {c}");
    }
    assert!(s.contains("--server") && s.contains("--profile"));
}

#[test]
fn invalid_profile_fails_cleanly() {
    let out = powehi()
        .args(["--profile", "../evil", "--data-dir", "/tmp", "status"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid profile name"));
}

#[test]
fn verify_takes_a_conversation_and_an_optional_confirm_flag() {
    let help = powehi().args(["verify", "--help"]).output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--confirm"));
    let missing = powehi().arg("verify").output().unwrap();
    assert!(!missing.status.success());
}

#[test]
fn whoami_without_an_account_fails_with_empty_stdout() {
    let dir = std::env::temp_dir().join(format!("powehi-whoami-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = powehi()
        .args(["--server", "http://127.0.0.1:1", "--data-dir"])
        .arg(&dir)
        .args(["--profile", "ghost", "whoami"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "whoami must print nothing on failure"
    );
    assert!(!out.stderr.is_empty());
}

#[test]
fn completions_prints_a_script_without_touching_the_data_dir() {
    // A relative-free, nonexistent base dir proves no profile/data access happens.
    let out = powehi()
        .args([
            "--data-dir",
            "/nonexistent-powehi-dir",
            "completions",
            "bash",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("powehi") && s.contains("whoami"));
    assert!(!std::path::Path::new("/nonexistent-powehi-dir").exists());
}

#[test]
fn completions_rejects_an_unknown_shell() {
    let out = powehi().args(["completions", "tcsh"]).output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

/// Fresh data dir holding the given profile directories, under `<base>/powehi/<name>`.
fn data_dir_with(tag: &str, profiles: &[&str]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("powehi-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for p in profiles {
        std::fs::create_dir_all(dir.join("powehi").join(p)).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn profiles_out(dir: &std::path::Path, extra: &[&str]) -> std::process::Output {
    powehi()
        .arg("--data-dir")
        .arg(dir)
        .arg("profiles")
        .args(extra)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn profiles_lists_names_count_and_json_through_the_binary() {
    let dir = data_dir_with("profiles", &["bob", "alice"]);
    let plain = profiles_out(&dir, &[]);
    let count = profiles_out(&dir, &["--count"]);
    let json = profiles_out(&dir, &["--json"]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(String::from_utf8_lossy(&plain.stdout), "alice\nbob\n");
    assert_eq!(String::from_utf8_lossy(&count.stdout), "2\n");
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&json.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["name"], "alice");
    assert_eq!(lines[1]["name"], "bob");
}

#[test]
fn profiles_json_with_count_is_rejected_with_empty_stdout() {
    let dir = data_dir_with("profiles-conflict", &["alice"]);
    let out = profiles_out(&dir, &["--json", "--count"]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
fn profiles_on_an_empty_data_dir_prints_zero_or_nothing() {
    let dir = data_dir_with("profiles-empty", &[]);
    let count = profiles_out(&dir, &["--count"]);
    let json = profiles_out(&dir, &["--json"]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(String::from_utf8_lossy(&count.stdout), "0\n");
    assert!(json.status.success() && json.stdout.is_empty());
}

#[test]
fn json_commands_without_an_account_fail_with_empty_stdout() {
    let dir = data_dir_with("json-noacct", &[]);
    for args in [
        &["inbox", "--json"][..],
        &["read", "c1", "--json"][..],
        &["verify", "c1", "--json"][..],
    ] {
        let out = powehi()
            .args(["--server", "http://127.0.0.1:1", "--data-dir"])
            .arg(&dir)
            .args(["--profile", "ghost"])
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "{args:?} must fail without an account"
        );
        assert!(
            out.stdout.is_empty(),
            "{args:?} must print nothing on failure"
        );
        assert!(!out.stderr.is_empty(), "{args:?} must explain on stderr");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
