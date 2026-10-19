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
    Status(StatusArgs),
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
    /// Show stored received messages for a conversation, then remove them from the store.
    Read(ReadArgs),
    /// Interactive chat REPL with realtime delivery.
    Chat(ConversationArg),
    /// Show the Safety Number for a conversation.
    Verify(VerifyArgs),
    /// List the conversations stored in this profile (ids, roles, unread counts).
    Conversations(ConversationsArgs),
    /// List the profile names in the data directory (no password; names only).
    Profiles(ProfilesArgs),
    /// Log in and show the profile, server, user id and device id.
    Whoami(WhoamiArgs),
    /// Print a shell completion script to stdout (no profile or network access).
    Completions(CompletionsArgs),
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Target shell.
    pub shell: clap_complete::Shell,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Print one JSON object instead of `key:  value` lines.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct WhoamiArgs {
    /// Print one JSON object instead of `key: value` lines.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProfilesArgs {
    /// Print only the number of profiles.
    #[arg(long)]
    pub count: bool,
    /// Print one JSON object per profile (`{"name":...}`).
    #[arg(long, conflicts_with = "count")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Conversation id (or a unique prefix of at least 4 characters).
    pub conversation: String,
    /// Record that you compared this safety number (quote it) with your peer; replaces an
    /// earlier confirmation. The number is public, so it may appear in argv.
    #[arg(long, value_name = "NUMBER")]
    pub confirm: Option<String>,
    /// Print one JSON object (conversation, safety_number, status) instead of the text report.
    #[arg(long)]
    pub json: bool,
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
pub struct ConversationsArgs {
    /// List only conversations with unread messages.
    #[arg(long)]
    pub unread: bool,
    /// List only conversations with no unread messages.
    #[arg(long, conflicts_with = "unread")]
    pub read: bool,
    /// List only conversations whose verified Safety Number changed (CHANGED).
    #[arg(long)]
    pub changed: bool,
    /// List only conversations whose Safety Number did not change since you verified it.
    #[arg(long, conflicts_with = "changed")]
    pub unchanged: bool,
    /// List only conversations where you were the creator or the joiner of the invite.
    #[arg(long, value_enum)]
    pub role: Option<crate::conversation::Role>,
    /// Show at most N matching conversations (the first by id).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=10000))]
    pub limit: Option<u32>,
    /// Skip the first N matching conversations (by id); combine with --limit to page.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=10000))]
    pub offset: Option<u32>,
    /// List only conversations whose id starts with this (lowercase hex digits and dashes).
    #[arg(long, value_name = "HEX", value_parser = parse_id_prefix)]
    pub prefix: Option<String>,
    /// List only conversations whose Safety Number you have not confirmed (`verify --confirm`).
    #[arg(long)]
    pub unverified: bool,
    /// List only conversations whose Safety Number you have confirmed (`verify --confirm`).
    #[arg(long, conflicts_with = "unverified")]
    pub verified: bool,
    /// Print only the number of matching conversations.
    #[arg(long)]
    pub count: bool,
    /// Print only the matching conversation ids, one per line.
    #[arg(long, conflicts_with = "count")]
    pub ids: bool,
    /// Print the matching conversations as JSON lines (id, role, unread, changed, verified).
    #[arg(long, conflicts_with_all = ["count", "ids"])]
    pub json: bool,
}

/// Accepts 1..=36 characters of `[0-9a-f-]`, the alphabet of a hyphenated lowercase UUID.
fn parse_id_prefix(s: &str) -> Result<String, String> {
    let ok = (1..=36).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-');
    if ok {
        Ok(s.to_string())
    } else {
        Err("expected 1-36 lowercase hex digits or dashes".to_string())
    }
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    /// Conversation id (or a unique prefix of at least 4 characters).
    pub conversation: String,
    /// Keep the messages in the encrypted store instead of removing them after display.
    #[arg(long)]
    pub keep: bool,
    /// Show only the newest N messages; older ones stay stored untouched.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=10000))]
    pub last: Option<u32>,
}

#[derive(Debug, Args)]
pub struct ConversationArg {
    /// Conversation id (or a unique prefix of at least 4 characters).
    pub conversation: String,
}

impl Command {
    /// Stable command name for messages and logs (never user content).
    pub fn name(&self) -> &'static str {
        match self {
            Command::Status(_) => "status",
            Command::Register => "register",
            Command::Login => "login",
            Command::Invite(InviteCommand::Create { .. }) => "invite create",
            Command::Invite(InviteCommand::Redeem) => "invite redeem",
            Command::Send(_) => "send",
            Command::Inbox => "inbox",
            Command::Read(_) => "read",
            Command::Chat(_) => "chat",
            Command::Verify(_) => "verify",
            Command::Conversations(_) => "conversations",
            Command::Profiles(_) => "profiles",
            Command::Whoami(_) => "whoami",
            Command::Completions(_) => "completions",
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
    fn profiles_json_conflicts_with_count() {
        let c = parse(&["profiles", "--json"]).unwrap();
        assert!(matches!(c.command, Command::Profiles(ref a) if a.json && !a.count));
        assert!(parse(&["profiles", "--json", "--count"]).is_err());
    }

    #[test]
    fn verify_json_flag_combines_with_confirm() {
        let c = parse(&["verify", "abcd"]).unwrap();
        assert!(matches!(c.command, Command::Verify(ref a) if !a.json));
        let c = parse(&["verify", "abcd", "--json", "--confirm", "1 2"]).unwrap();
        assert!(matches!(c.command, Command::Verify(ref a) if a.json && a.confirm.is_some()));
    }

    #[test]
    fn whoami_json_flag() {
        let c = parse(&["whoami"]).unwrap();
        assert!(matches!(c.command, Command::Whoami(ref a) if !a.json));
        let c = parse(&["whoami", "--json"]).unwrap();
        assert!(matches!(c.command, Command::Whoami(ref a) if a.json));
    }

    #[test]
    fn defaults() {
        let c = parse(&["status"]).unwrap();
        assert_eq!(c.profile, DEFAULT_PROFILE);
        assert_eq!(c.server.as_str(), "https://localhost:8443/");
        assert!(matches!(c.command, Command::Status(ref a) if !a.json));
        let c = parse(&["status", "--json"]).unwrap();
        assert!(matches!(c.command, Command::Status(ref a) if a.json));
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
    fn read_last_is_bounded_and_optional() {
        let Command::Read(a) = parse(&["read", "c1"]).unwrap().command else {
            panic!("not read");
        };
        assert_eq!(a.last, None);
        let Command::Read(a) = parse(&["read", "c1", "--last", "5"]).unwrap().command else {
            panic!("not read");
        };
        assert_eq!(a.last, Some(5));
        assert!(parse(&["read", "c1", "--last", "0"]).is_err());
        assert!(parse(&["read", "c1", "--last", "10001"]).is_err());
    }

    #[test]
    fn read_keep_is_opt_in() {
        let Command::Read(a) = parse(&["read", "c1"]).unwrap().command else {
            panic!("not read");
        };
        assert!(!a.keep);
        let Command::Read(a) = parse(&["read", "c1", "--keep"]).unwrap().command else {
            panic!("not read");
        };
        assert!(a.keep);
    }

    #[test]
    fn no_password_flag_exists() {
        assert!(parse(&["login", "--password", "x"]).is_err());
        assert!(parse(&["register", "--password", "x"]).is_err());
    }
}
