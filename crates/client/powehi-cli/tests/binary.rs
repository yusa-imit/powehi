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
        "status", "register", "login", "invite", "send", "inbox", "chat", "verify",
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
fn unimplemented_command_reports_it() {
    let out = powehi()
        .args(["--data-dir", "/tmp", "inbox"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not implemented"));
}
