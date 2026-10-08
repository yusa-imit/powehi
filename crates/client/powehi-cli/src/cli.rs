//! Command-line surface (prd.md §7A.2). No argument carries a password or message body:
//! passwords come from the TTY, bodies from stdin or the REPL (§7A.3).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use url::Url;

pub const DEFAULT_SERVER: &str = "https://localhost:8443";
pub const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Parser)]
#[command(
    name = "powehi",
    version,
    about = "Powehi E2EE messenger terminal client"
)]
pub struct Cli {
    /// Server base URL.
    #[arg(long, global = true, env = "POWEHI_SERVER", hide_env_values = true, default_value = DEFAULT_SERVER,
          value_parser = parse_server)]
    pub server: Url,

    /// Profile name; each profile has its own encrypted data directory.
    #[arg(long, global = true, env = "POWEHI_PROFILE", hide_env_values = true, default_value = DEFAULT_PROFILE)]
    pub profile: String,

    /// Override the base data directory (default: the per-user data dir).
    #[arg(long, global = true, env = "POWEHI_DATA_DIR", hide_env_values = true,
          value_parser = parse_data_dir)]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show server health and detected region.
    Status,
    /// Register a new account (password read from the TTY).
    Register,
    /// Log in (password read from the TTY).
    Login,
    /// Create or redeem invite links.
    #[command(subcommand)]
    Invite(InviteCommand),
    /// Send a message; the body is read from stdin only.
    Send(ConversationArg),
    /// Fetch, decrypt, store and acknowledge pending messages.
    Inbox,
    /// Interactive chat REPL with realtime delivery.
    Chat(ConversationArg),
    /// Show the Safety Number for a conversation.
    Verify(ConversationArg),
}

#[derive(Debug, Subcommand)]
pub enum InviteCommand {
    /// Create an invite link; with --wait, then wait for the peer's Welcome and join.
    Create {
        /// Seconds to wait for the peer to redeem and send the Welcome (0 = do not wait).
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u32).range(0..=900))]
        wait: u32,
    },
    /// Redeem an invite link (read from stdin, not argv).
    Redeem,
}

#[derive(Debug, Args)]
pub struct ConversationArg {
    /// Conversation reference.
    pub conversation: String,
}

impl Command {
    /// Stable command name for messages and logs (never user content).
    pub fn name(&self) -> &'static str {
        match self {
            Command::Status => "status",
            Command::Register => "register",
            Command::Login => "login",
            Command::Invite(InviteCommand::Create { .. }) => "invite create",
            Command::Invite(InviteCommand::Redeem) => "invite redeem",
            Command::Send(_) => "send",
            Command::Inbox => "inbox",
            Command::Chat(_) => "chat",
            Command::Verify(_) => "verify",
        }
    }
}

/// Data dir must be absolute so secrets never land relative to the CWD.
fn parse_data_dir(s: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(s);
    if p.is_absolute() {
        Ok(p)
    } else {
        Err("must be an absolute path".into())
    }
}

/// True for `localhost` and loopback IPs, the only hosts where cleartext http is allowed.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Accepts https URLs (http only to loopback) with a host and no credentials.
fn parse_server(s: &str) -> Result<Url, String> {
    let url = Url::parse(s).map_err(|e| e.to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("scheme must be http or https".into());
    }
    if url.host_str().is_none() {
        return Err("missing host".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials in the URL are not allowed".into());
    }
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err("http is only allowed for localhost; use https".into());
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("powehi").chain(args.iter().copied()))
    }

    #[test]
    fn defaults() {
        let c = parse(&["status"]).unwrap();
        assert_eq!(c.profile, DEFAULT_PROFILE);
        assert_eq!(c.server.as_str(), "https://localhost:8443/");
        assert!(matches!(c.command, Command::Status));
    }

    #[test]
    fn global_flags_after_subcommand() {
        let c = parse(&[
            "inbox",
            "--profile",
            "work",
            "--server",
            "http://127.0.0.1:1",
        ])
        .unwrap();
        assert_eq!(c.profile, "work");
        assert_eq!(c.server.host_str(), Some("127.0.0.1"));
        assert!(parse(&["--server", "http://[::1]:1", "status"]).is_ok());
        assert!(parse(&["--server", "http://localhost", "status"]).is_ok());
    }

    #[test]
    fn rejects_bad_server_urls() {
        for u in [
            "ftp://h",
            "https://u:p@h",
            "nonsense",
            "file:///x",
            "http://203.0.113.9",
        ] {
            assert!(parse(&["--server", u, "status"]).is_err(), "{u}");
        }
    }

    #[test]
    fn data_dir_must_be_absolute() {
        assert!(parse(&["--data-dir", "rel", "status"]).is_err());
        assert!(parse(&["--data-dir", "/abs", "status"]).is_ok());
    }

    #[test]
    fn send_takes_only_a_conversation_never_a_body() {
        assert!(parse(&["send", "c1"]).is_ok());
        assert!(parse(&["send", "c1", "hello body"]).is_err());
        assert!(parse(&["send"]).is_err());
    }

    #[test]
    fn invite_create_wait_is_bounded_and_redeem_takes_no_link_argument() {
        assert!(parse(&["invite", "create"]).is_ok());
        assert!(parse(&["invite", "create", "--wait", "900"]).is_ok());
        assert!(parse(&["invite", "create", "--wait", "901"]).is_err());
        assert!(parse(&["invite", "redeem"]).is_ok());
        assert!(parse(&["invite", "redeem", "abc.def"]).is_err());
    }

    #[test]
    fn no_password_flag_exists() {
        assert!(parse(&["login", "--password", "x"]).is_err());
        assert!(parse(&["register", "--password", "x"]).is_err());
    }
}
