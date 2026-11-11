//! The binary entry point must disable core dumps before it parses arguments or runs anything
//! that can hold a secret (7.11 F8). The unit tests cover the call; this pins its position.

const MAIN: &str = include_str!("../src/main.rs");

#[test]
fn main_disables_core_dumps_before_parsing_or_running() {
    let hardening = MAIN
        .find("disable_core_dumps()")
        .expect("main must call it");
    let parse = MAIN.find("Cli::parse()").expect("main parses arguments");
    let run = MAIN.find("run(args").expect("main delegates to run");
    assert!(
        hardening < parse,
        "core dumps must be off before argument parsing"
    );
    assert!(parse < run);
}

#[test]
fn main_refuses_to_run_when_hardening_fails() {
    let start = MAIN.find("disable_core_dumps()").unwrap();
    let parse = MAIN.find("Cli::parse()").unwrap();
    let guard = &MAIN[start..parse];
    assert!(
        guard.contains("ExitCode::FAILURE"),
        "failure must abort before any work"
    );
}
