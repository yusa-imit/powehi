//! Powehi terminal client library (prd.md §7A). The `powehi` binary is a thin wrapper.
//!
//! Rules from §7A.3 that shape this crate: no secrets or message bodies in argv (no
//! subcommand takes them as arguments), and nothing here logs content. A binary using this
//! crate must call [`hardening::disable_core_dumps`] before touching any secret.

#[cfg(unix)]
pub mod auth;
#[cfg(unix)]
pub mod chat;
pub mod cli;
#[cfg(unix)]
pub mod conversation;
#[cfg(unix)]
pub mod hardening;
#[cfg(unix)]
pub mod identity;
#[cfg(unix)]
pub mod inbox;
#[cfg(unix)]
pub mod invite;
#[cfg(all(test, unix))]
mod live_e2e;
#[cfg(unix)]
pub mod message;
pub mod profile;
#[cfg(unix)]
pub mod prompt;
pub mod status;
#[cfg(unix)]
pub mod store;
#[cfg(all(test, unix))]
mod testsrv;
#[cfg(unix)]
pub mod verify;
#[cfg(unix)]
pub mod welcome;
#[cfg(unix)]
pub mod whoami;
#[cfg(unix)]
pub mod ws;

use std::path::PathBuf;

use thiserror::Error;
#[cfg(unix)]
use zeroize::Zeroizing;

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
    #[error("{0}")]
    Conversation(#[from] conversation::ConversationError),
    #[cfg(unix)]
    #[error("{0}")]
    Message(#[from] message::MessageError),
    #[cfg(unix)]
    #[error("{0}")]
    Verify(#[from] verify::VerifyError),
    #[cfg(unix)]
    #[error("could not read the invite link from stdin")]
    Stdin,
    #[cfg(unix)]
    #[error("could not read the message from stdin")]
    StdinMessage,
    #[cfg(unix)]
    #[error("could not write to stdout; unread messages were kept")]
    Stdout,
    #[cfg(unix)]
    #[error("{0}")]
    Identity(#[from] identity::IdentityError),
    #[cfg(unix)]
    #[error("could not write to stdout")]
    Output,
    #[error("could not list the data directory")]
    DataDirList,
    #[error("could not start the async runtime")]
    Runtime,
    #[cfg(not(unix))]
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
        #[cfg(unix)]
        cli::Command::Inbox => run_inbox(&args.server, &paths),
        #[cfg(unix)]
        cli::Command::Send(ref c) => run_send(&args.server, &paths, &c.conversation),
        #[cfg(unix)]
        cli::Command::Read(ref c) => {
            run_read(&args.server, &paths, &c.conversation, c.keep, c.last)
        }
        #[cfg(unix)]
        cli::Command::Chat(ref c) => run_chat(&args.server, &paths, &c.conversation),
        #[cfg(unix)]
        cli::Command::Verify(ref c) => run_verify(&args.server, &paths, c),
        #[cfg(unix)]
        cli::Command::Conversations(ref a) => run_conversations(&args.server, &paths, a),
        #[cfg(unix)]
        cli::Command::Whoami(a) => run_whoami(&args.server, &args.profile, &paths, a.json),
        cli::Command::Profiles(a) => run_profiles(&base, a.count, a.json),
        #[cfg(not(unix))]
        ref other => Err(CliError::NotImplemented(other.name())),
    }
}

/// `whoami`: logs in (password prompt) and prints the account ids; no token is printed.
#[cfg(unix)]
fn run_whoami(
    server: &url::Url,
    profile: &str,
    paths: &profile::ProfilePaths,
    json: bool,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let s = rt.block_on(auth::login(&client, server, paths, &mut prompter))?;
    whoami::report(
        profile,
        server,
        s.user_id,
        s.device_id,
        json,
        &mut std::io::stdout(),
    )
    .map_err(|_| CliError::Output)
}

/// `profiles`: local directory listing; opens no store and asks for no password.
fn run_profiles(base: &std::path::Path, count: bool, json: bool) -> Result<(), CliError> {
    let names = profile::list(base).map_err(|_| CliError::DataDirList)?;
    profile::write_listing(&names, count, json, &mut std::io::stdout())
        .map_err(|_| CliError::Output)
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

/// `inbox`: logs in, joins pending Welcomes and stores new messages; prints counts only.
#[cfg(unix)]
fn run_inbox(server: &url::Url, paths: &profile::ProfilePaths) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = rt.block_on(auth::login(&client, server, paths, &mut prompter))?;
    let r = rt.block_on(inbox::receive(&client, server, &session))?;
    for id in &r.joined {
        println!("joined conversation {id}");
    }
    for id in &r.pq_bound {
        if let Some(b) = conversation::load(&session.store, id)?
            .as_ref()
            .and_then(|c| c.pq_binding().map(str::to_owned))
        {
            println!("conversation {id}: post-quantum binding {b} (compare with your peer)");
        }
    }
    println!("{} new message(s) stored", r.stored);
    if r.skipped > 0 {
        eprintln!("{} envelope(s) skipped", r.skipped);
    }
    Ok(())
}

/// `send`: body from stdin (never argv), then log in and post it into the conversation.
#[cfg(unix)]
fn run_send(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    reference: &str,
) -> Result<(), CliError> {
    use std::io::Read as _;
    // Read and validate the body before the password prompt so a bad pipe fails fast.
    let mut raw = Zeroizing::new(Vec::with_capacity(message::MAX_BODY_LEN + 3));
    std::io::stdin()
        .take(message::MAX_BODY_LEN as u64 + 3)
        .read_to_end(&mut raw)
        .map_err(|_| CliError::StdinMessage)?;
    message::check_body(&raw)?;
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = rt.block_on(auth::login(&client, server, paths, &mut prompter))?;
    let group_id = message::resolve(&session.store, reference)?;
    if verify::changed_since_verified(&session.store, group_id) {
        eprintln!("{}", verify::CHANGED_WARNING);
    }
    let body = message::check_body(&raw)?;
    rt.block_on(message::send(&client, server, &session, group_id, body))?;
    println!("sent to conversation {group_id}");
    Ok(())
}

/// `read`: shows and removes the stored messages of one conversation. Logging in (OPAQUE)
/// is how the store is opened, so the server sees a login, but no message traffic.
#[cfg(unix)]
fn run_read(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    reference: &str,
    keep: bool,
    last: Option<u32>,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = rt.block_on(auth::login(&client, server, paths, &mut prompter))?;
    let group_id = message::resolve(&session.store, reference)?;
    if verify::changed_since_verified(&session.store, group_id) {
        eprintln!("{}", verify::CHANGED_WARNING);
    }
    let msgs = message::pending(&session.store, group_id)?;
    // Only delete what reached the terminal: a closed pipe must not eat unseen messages.
    let shown = message::newest(&msgs, last.map(|n| n as usize));
    message::show(&session.store, shown, keep, &mut std::io::stdout()).map_err(|e| match e {
        message::ShowError::Output => CliError::Stdout,
        message::ShowError::Discard(e) => CliError::Message(e),
    })?;
    if msgs.is_empty() {
        println!("no new messages");
    }
    Ok(())
}

/// `conversations`: logs in to unlock the store, then lists stored conversation ids and roles.
#[cfg(unix)]
fn run_conversations(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    a: &cli::ConversationsArgs,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = rt.block_on(auth::login(&client, server, paths, &mut prompter))?;
    let unread = message::unread_counts(&session.store)?;
    let (store, out) = (&session.store, &mut std::io::stdout());
    let limit = conversation::Page {
        offset: a.offset.map_or(0, |n| n as usize),
        limit: a.limit.map(|n| n as usize),
        prefix: a.prefix.clone(),
        unverified: a.unverified,
        verified: a.verified,
        read: a.read,
        unchanged: a.unchanged,
    };
    if a.count {
        conversation::count(
            store,
            &unread,
            a.unread,
            a.changed,
            a.role,
            limit.clone(),
            out,
        )?;
    } else if a.ids {
        conversation::ids(
            store,
            &unread,
            a.unread,
            a.changed,
            a.role,
            limit.clone(),
            out,
        )?;
    } else if a.json {
        conversation::json(store, &unread, a.unread, a.changed, a.role, limit, out)?;
    } else {
        conversation::report(store, &unread, a.unread, a.changed, a.role, limit, out)?;
    }
    Ok(())
}

/// `verify`: shows the Safety Number (local computation) and optionally records the comparison.
#[cfg(unix)]
fn run_verify(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    args: &cli::VerifyArgs,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = rt.block_on(auth::login(&client, server, paths, &mut prompter))?;
    let group_id = message::resolve(&session.store, &args.conversation)?;
    let number = verify::number(&session.store, group_id)?;
    let mut state = verify::state(&session.store, group_id, &number)?;
    if let Some(typed) = &args.confirm {
        if state == verify::State::Changed {
            eprintln!(
                "warning: the safety number CHANGED since you last verified this conversation"
            );
        }
        verify::confirm(&session.store, group_id, &number, typed)?;
        state = verify::State::Verified;
    }
    verify::report(&mut std::io::stdout(), group_id, &number, state)
        .map_err(|_| CliError::Stdout)?;
    Ok(())
}

/// `chat`: logs in, then runs the REPL with stdin lines and `/v1/ws` wake-ups as events.
#[cfg(unix)]
fn run_chat(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    reference: &str,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = rt.block_on(auth::login(&client, server, paths, &mut prompter))?;
    let group_id = message::resolve(&session.store, reference)?;
    // The CHANGED alert is printed by `chat::run` itself, at start and after every fetch.
    println!(
        "chat {group_id}: type a line and press Enter; {} to leave",
        chat::QUIT
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let stdin_tx = tx.clone();
    // Detached on purpose: a blocked stdin read must not delay exit.
    std::thread::spawn(move || chat::read_lines(std::io::stdin().lock(), &stdin_tx));
    rt.block_on(async {
        let ws = tokio::spawn(ws::wake_loop(
            server.clone(),
            session.bearer(),
            group_id,
            tx,
            std::time::Duration::from_secs(1),
        ));
        let res = chat::run(
            &client,
            server,
            &session,
            group_id,
            &mut rx,
            &mut std::io::stdout(),
            chat::Polling::default(),
        )
        .await;
        ws.abort();
        res
    })
    .map_err(|_| CliError::Stdout)?;
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
            let (id, pq) = rt.block_on(invite::redeem(&client, server, &session, &link))?;
            println!("conversation {id}");
            print_pq_status(&pq);
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

/// Tells the user what the `pq_init` step achieved. The binding is a comparison value only:
/// message encryption itself stays classical MLS (ADR-0003, prd.md §5.3).
fn print_pq_status(pq: &invite::PqStatus) {
    match pq {
        invite::PqStatus::Bound(b) => {
            println!(
                "post-quantum key exchange completed, binding {b} (messages stay classical MLS)"
            )
        }
        invite::PqStatus::PeerClassical => println!("peer has no post-quantum key; classical only"),
        invite::PqStatus::KeyRejected => eprintln!(
            "warning: the inviter's post-quantum key failed verification and was ignored; \
             the conversation is classical only. Do not trust this invite without checking \
             with the inviter."
        ),
        invite::PqStatus::NotSent => {
            println!("post-quantum key exchange could not be sent; classical only")
        }
    }
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
        let r = run(cli(&["--profile", "..", "verify", "x"]), Some("/d".into()));
        assert!(matches!(r, Err(CliError::InvalidProfile(_))));
    }
}
