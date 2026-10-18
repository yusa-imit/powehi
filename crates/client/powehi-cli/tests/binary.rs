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
