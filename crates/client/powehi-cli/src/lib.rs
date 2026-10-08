//! Powehi terminal client library (prd.md §7A). The `powehi` binary is a thin wrapper.
//!
//! Rules from §7A.3 that shape this crate: no secrets or message bodies in argv (no
//! subcommand takes them as arguments), and nothing here logs content.

#[cfg(unix)]
pub mod auth;
pub mod cli;
#[cfg(unix)]
pub mod conversation;
#[cfg(unix)]
pub mod identity;
#[cfg(unix)]
pub mod invite;
pub mod profile;
#[cfg(unix)]
pub mod prompt;
pub mod status;
#[cfg(unix)]
pub mod store;
#[cfg(all(test, unix))]
mod testsrv;
#[cfg(unix)]
pub mod welcome;

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
    Invite(#[from] invite::InviteError),
    #[cfg(unix)]
    #[error("could not read the invite link from stdin")]
    Stdin,
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
        #[cfg(unix)]
        cli::Command::Invite(ref cmd) => run_invite(&args.server, &paths, cmd),
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

/// Seconds between Welcome polls while `invite create --wait` is waiting.
#[cfg(unix)]
const WAIT_POLL_SECS: u64 = 3;

/// `invite create` / `invite redeem`: logs in (password from the TTY) and runs the invite flow.
#[cfg(unix)]
fn run_invite(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    cmd: &cli::InviteCommand,
) -> Result<(), CliError> {
    use std::io::Read as _;
    let rt = runtime()?;
    let client = status::http_client()?;
    // Read the link before the password prompt so a bad paste fails fast.
    let link = match cmd {
        cli::InviteCommand::Redeem => {
            let mut buf = String::new();
            std::io::stdin()
                .take(invite::MAX_LINK_LEN as u64 + 1)
                .read_to_string(&mut buf)
                .map_err(|_| CliError::Stdin)?;
            Some(invite::parse_link(&buf)?)
        }
        cli::InviteCommand::Create { .. } => None,
    };
    let mut prompter = prompt::TtyPrompter;
    let session = rt.block_on(auth::login(&client, server, paths, &mut prompter))?;
    match (cmd, link) {
        (cli::InviteCommand::Create { wait }, _) => {
            let (url, key_ref) = rt.block_on(invite::create(&client, server, &session))?;
            println!("{url}");
            if *wait > 0 {
                let w = u64::from(*wait);
                wait_for_welcome(&rt, &client, server, &session, &key_ref, w)?;
            }
        }
        (cli::InviteCommand::Redeem, Some(link)) => {
            let id = rt.block_on(invite::redeem(&client, server, &session, &link))?;
            println!("conversation {id}");
        }
        (cli::InviteCommand::Redeem, None) => return Err(CliError::Stdin),
    }
    Ok(())
}

/// Polls for the Welcome that consumes the invite's KeyPackage (`key_ref`) for at most `wait`
/// seconds of wall clock and prints the joined conversation.
#[cfg(unix)]
fn wait_for_welcome(
    rt: &tokio::runtime::Runtime,
    client: &reqwest::Client,
    server: &url::Url,
    session: &auth::Session,
    key_ref: &[u8],
    wait: u64,
) -> Result<(), CliError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);
    loop {
        let report = rt.block_on(welcome::join_pending(
            client,
            server,
            session,
            Some(key_ref),
        ))?;
        if let Some(id) = report.joined.first() {
            println!("conversation {id}");
            return Ok(());
        }
        let poll = std::time::Duration::from_secs(WAIT_POLL_SECS);
        if std::time::Instant::now() + poll >= deadline {
            break;
        }
        std::thread::sleep(poll);
    }
    println!("no one has redeemed the invite yet; it stays valid for 24 hours");
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
