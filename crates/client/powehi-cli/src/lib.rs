//! Powehi terminal client library (prd.md §7A). The `powehi` binary is a thin wrapper.
//!
//! Rules from §7A.3 that shape this crate: no secrets or message bodies in argv (no
//! subcommand takes them as arguments), and nothing here logs content.

#[cfg(unix)]
pub mod auth;
pub mod cli;
#[cfg(unix)]
pub mod identity;
pub mod profile;
#[cfg(unix)]
pub mod prompt;
pub mod status;
#[cfg(unix)]
pub mod store;

use std::path::PathBuf;

use thiserror::Error;

/// Errors surfaced to the user. Messages never contain secrets or message content.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("invalid profile name: {0}")]
    InvalidProfile(#[from] profile::ProfileError),
    #[error("no per-user data directory could be determined; set --data-dir")]
    NoDataDir,
    #[error("status check failed: {0}")]
    Status(#[from] status::StatusError),
    #[cfg(unix)]
    #[error("{0}")]
    Auth(#[from] auth::AuthError),
    #[cfg(unix)]
    #[error("{0}")]
    Identity(#[from] identity::IdentityError),
    #[error("could not start the async runtime")]
    Runtime,
    #[error("`{0}` is not implemented yet")]
    NotImplemented(&'static str),
}

/// Runs a parsed command line. `default_data_dir` is injected (the per-user data dir) so
/// tests stay deterministic.
pub fn run(args: cli::Cli, default_data_dir: Option<PathBuf>) -> Result<(), CliError> {
    let base = args
        .data_dir
        .clone()
        .or(default_data_dir)
        .ok_or(CliError::NoDataDir)?;
    let paths = profile::ProfilePaths::resolve(&base, &args.profile)?;
    debug_assert!(paths.dir.starts_with(&base));
    match args.command {
        cli::Command::Status => run_status(&args.server),
        #[cfg(unix)]
        cli::Command::Register => run_auth(&args.server, &paths, true),
        #[cfg(unix)]
        cli::Command::Login => run_auth(&args.server, &paths, false),
        ref other => Err(CliError::NotImplemented(other.name())),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, CliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CliError::Runtime)
}

/// `register` / `login`: prompts on the TTY, talks OPAQUE to the server, prints only ids.
#[cfg(unix)]
fn run_auth(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    register: bool,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = if register {
        rt.block_on(auth::register(&client, server, paths, &mut prompter))?
    } else {
        rt.block_on(auth::login(&client, server, paths, &mut prompter))?
    };
    println!(
        "{} as device {}",
        if register { "registered" } else { "logged in" },
        session.device_id
    );
    let uploaded = rt.block_on(identity::ensure_key_packages(&client, server, &session))?;
    if uploaded > 0 {
        println!("uploaded {uploaded} key packages");
    }
    Ok(())
}

fn run_status(server: &url::Url) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let s = rt.block_on(status::fetch(&client, server))?;
    println!("server:  {server}");
    println!(
        "health:  {}",
        if s.healthy {
            "ok"
        } else {
            "unexpected response"
        }
    );
    println!("region:  {}", s.region_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn cli(args: &[&str]) -> cli::Cli {
        cli::Cli::try_parse_from(std::iter::once("powehi").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn missing_data_dir_is_an_error() {
        assert!(matches!(
            run(cli(&["status"]), None),
            Err(CliError::NoDataDir)
        ));
    }

    #[test]
    fn bad_profile_beats_not_implemented() {
        let r = run(cli(&["--profile", "..", "status"]), Some("/d".into()));
        assert!(matches!(r, Err(CliError::InvalidProfile(_))));
    }

    #[test]
    fn valid_args_reach_command_dispatch() {
        let r = run(cli(&["inbox"]), Some("/d".into()));
        assert!(matches!(r, Err(CliError::NotImplemented("inbox"))));
    }
}
