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
pub mod pcs;
pub mod pinning;
pub mod profile;
#[cfg(unix)]
pub mod prompt;
#[cfg(unix)]
pub mod requests;
#[cfg(unix)]
pub mod screen;
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
    Request(#[from] requests::RequestError),
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
    if let cli::Command::Completions(ref c) = args.command {
        return run_completions(c.shell);
    }
    let base = args
        .data_dir
        .clone()
        .or(default_data_dir)
        .ok_or(CliError::NoDataDir)?;
    let paths = profile::ProfilePaths::resolve(&base, &args.profile)?;
    debug_assert!(paths.dir.starts_with(&base));
    match args.command {
        cli::Command::Status(a) => run_status(&args.server, a.json),
        #[cfg(unix)]
        cli::Command::Register(ref a) => run_auth(&args.server, &paths, true, a.json),
        #[cfg(unix)]
        cli::Command::Login(ref a) => run_auth(&args.server, &paths, false, a.json),
        #[cfg(unix)]
        cli::Command::Invite(ref cmd) => run_invite(&args.server, &paths, cmd),
        #[cfg(unix)]
        cli::Command::Inbox(a) => run_inbox(&args.server, &paths, a.json),
        #[cfg(unix)]
        cli::Command::Requests(ref a) => run_requests(&args.server, &paths, a.json),
        #[cfg(unix)]
        cli::Command::Accept(ref a) => run_request_answer(&args.server, &paths, &a.request, true),
        #[cfg(unix)]
        cli::Command::Decline(ref a) => run_request_answer(&args.server, &paths, &a.request, false),
        #[cfg(unix)]
        cli::Command::Send(ref c) => run_send(
            &args.server,
            &paths,
            &c.conversation,
            c.json,
            c.allow_changed,
        ),
        #[cfg(unix)]
        cli::Command::Read(ref c) => run_read(&args.server, &paths, c),
        #[cfg(unix)]
        cli::Command::Chat(ref c) => {
            run_chat(&args.server, &paths, &c.conversation, c.allow_changed)
        }
        #[cfg(unix)]
        cli::Command::Verify(ref c) => run_verify(&args.server, &paths, c),
        #[cfg(unix)]
        cli::Command::Conversations(ref a) => run_conversations(&args.server, &paths, a),
        #[cfg(unix)]
        cli::Command::Whoami(a) => run_whoami(&args.server, &args.profile, &paths, a.json),
        cli::Command::Completions(ref c) => run_completions(c.shell),
        cli::Command::Profiles(a) => run_profiles(&base, a.count, a.json),
        #[cfg(not(unix))]
        ref other => Err(CliError::NotImplemented(other.name())),
    }
}

/// `completions`: writes the shell script for the command surface; touches no profile state.
fn run_completions(shell: clap_complete::Shell) -> Result<(), CliError> {
    use clap::CommandFactory;
    let mut cmd = cli::Cli::command();
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut cmd, "powehi", &mut buf);
    assert!(!buf.is_empty());
    std::io::Write::write_all(&mut std::io::stdout(), &buf).map_err(|_| CliError::Output)
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
    let s = login_scoped(&rt, &client, server, paths, &mut prompter)?;
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

/// A logged-in [`auth::Session`] that revokes its bearer token on the server when dropped (8.4).
/// Best effort: a failure is a stderr warning and never changes the exit code.
#[cfg(unix)]
struct LoggedIn<'a> {
    session: auth::Session,
    rt: &'a tokio::runtime::Runtime,
    client: &'a reqwest::Client,
    server: &'a url::Url,
}

#[cfg(unix)]
impl std::ops::Deref for LoggedIn<'_> {
    type Target = auth::Session;
    fn deref(&self) -> &auth::Session {
        &self.session
    }
}

#[cfg(unix)]
impl Drop for LoggedIn<'_> {
    fn drop(&mut self) {
        let done = self.rt.block_on(auth::revoke_session(
            self.client,
            self.server,
            &self.session,
        ));
        if done.is_err() {
            eprintln!("warning: could not end the server session; it expires on its own");
        }
    }
}

/// Logs in and returns a session that is revoked when the command ends.
#[cfg(unix)]
fn login_scoped<'a>(
    rt: &'a tokio::runtime::Runtime,
    client: &'a reqwest::Client,
    server: &'a url::Url,
    paths: &profile::ProfilePaths,
    prompter: &mut dyn prompt::Prompter,
) -> Result<LoggedIn<'a>, CliError> {
    let session = rt.block_on(auth::login(client, server, paths, prompter))?;
    Ok(LoggedIn {
        session,
        rt,
        client,
        server,
    })
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
    json: bool,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = if register {
        rt.block_on(auth::register(&client, server, paths, &mut prompter))?
    } else {
        rt.block_on(auth::login(&client, server, paths, &mut prompter))?
    };
    let session = LoggedIn {
        session,
        rt: &rt,
        client: &client,
        server,
    };
    let uploaded = rt.block_on(identity::ensure_key_packages(&client, server, &session))?;
    write_auth_report(
        &mut std::io::stdout().lock(),
        register,
        session.device_id,
        uploaded,
        json,
    )
    .map_err(|_| CliError::Stdout)
}

/// Writes the `register`/`login` result: text lines, or one JSON object (device id and the
/// number of KeyPackages uploaded; no token or password material).
fn write_auth_report(
    out: &mut impl std::io::Write,
    register: bool,
    device: uuid::Uuid,
    uploaded: u64,
    json: bool,
) -> std::io::Result<()> {
    assert!(!device.is_nil());
    if json {
        let v =
            serde_json::json!({ "device": device.to_string(), "key_packages_uploaded": uploaded });
        return writeln!(out, "{v}");
    }
    writeln!(
        out,
        "{} as device {device}",
        if register { "registered" } else { "logged in" }
    )?;
    if uploaded > 0 {
        writeln!(out, "uploaded {uploaded} key packages")?;
    }
    Ok(())
}

#[cfg(test)]
mod auth_report_tests {
    use super::write_auth_report;

    #[test]
    fn text_matches_legacy_lines() {
        let d = uuid::Uuid::from_u128(7);
        let mut o = Vec::new();
        write_auth_report(&mut o, true, d, 3, false).unwrap();
        assert_eq!(
            String::from_utf8(o).unwrap(),
            format!("registered as device {d}\nuploaded 3 key packages\n")
        );
        let mut o = Vec::new();
        write_auth_report(&mut o, false, d, 0, false).unwrap();
        assert_eq!(
            String::from_utf8(o).unwrap(),
            format!("logged in as device {d}\n")
        );
    }

    #[test]
    fn json_is_one_line_with_two_keys() {
        let d = uuid::Uuid::from_u128(7);
        let mut o = Vec::new();
        write_auth_report(&mut o, false, d, 5, true).unwrap();
        let s = String::from_utf8(o).unwrap();
        assert_eq!(s.lines().count(), 1);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["device"], d.to_string());
        assert_eq!(v["key_packages_uploaded"], 5);
        assert_eq!(v.as_object().unwrap().len(), 2);
    }
}

/// `inbox`: logs in, joins pending Welcomes and stores new messages; prints counts only.
#[cfg(unix)]
fn run_inbox(server: &url::Url, paths: &profile::ProfilePaths, json: bool) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
    let r = rt.block_on(inbox::receive(&client, server, &session))?;
    let mut bindings = Vec::with_capacity(r.pq_bound.len());
    for id in &r.pq_bound {
        if let Some(b) = conversation::load(&session.store, id)?
            .as_ref()
            .and_then(|c| c.pq_binding().map(str::to_owned))
        {
            bindings.push((*id, b));
        }
    }
    if json {
        inbox::report_json(&mut std::io::stdout().lock(), &r, &bindings)
            .map_err(|_| CliError::Stdout)?;
    } else {
        for id in &r.joined {
            println!("joined conversation {id}");
        }
        for (id, b) in &bindings {
            println!("conversation {id}: post-quantum binding {b} (compare with your peer)");
        }
        if r.requests > 0 {
            println!(
                "{} new conversation request(s): `powehi requests`, then `accept` or `decline`",
                r.requests
            );
        }
        if r.commits > 0 {
            println!("{} peer key update(s) applied", r.commits);
        }
        if r.forked > 0 {
            println!(
                "{} peer commit(s) refused: that conversation can no longer be read",
                r.forked
            );
        }
        println!("{} new message(s) stored", r.stored);
    }
    if r.skipped > 0 {
        eprintln!("{} envelope(s) skipped", r.skipped);
    }
    Ok(())
}

/// `requests`: lists pending conversation requests from the profile store.
#[cfg(unix)]
fn run_requests(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    json: bool,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
    let reqs = requests::list(&session.store)?;
    requests::report(
        &mut std::io::stdout().lock(),
        &reqs,
        requests::now_secs(),
        json,
    )
    .map_err(|_| CliError::Output)
}

/// `accept` / `decline`: answers one pending request.
#[cfg(unix)]
fn run_request_answer(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    reference: &str,
    accept: bool,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
    let id = requests::resolve(&session.store, reference)?;
    if accept {
        rt.block_on(requests::accept(&client, server, &session, id))?;
        println!("joined conversation {id}");
    } else {
        rt.block_on(requests::decline(&client, server, &session, id))?;
        println!("declined request {id}");
    }
    Ok(())
}

/// `send`: body from stdin (never argv), then log in and post it into the conversation.
#[cfg(unix)]
fn run_send(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    reference: &str,
    json: bool,
    allow_changed: bool,
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
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
    let group_id = message::resolve(&session.store, reference)?;
    if allow_changed && verify::changed_since_verified(&session.store, group_id) {
        eprintln!("{}", verify::CHANGED_WARNING);
    }
    if !verify::has_confirmation(&session.store, group_id) {
        eprintln!("{}", verify::UNVERIFIED_WARNING);
    }
    let body = message::check_body(&raw)?;
    rt.block_on(message::send_with(
        &client,
        server,
        &session,
        group_id,
        body,
        allow_changed,
    ))?;
    message::write_sent(group_id, json, &mut std::io::stdout()).map_err(|_| CliError::Output)
}

/// `read`: shows and removes the stored messages of one conversation. Logging in (OPAQUE)
/// is how the store is opened, so the server sees a login, but no message traffic.
#[cfg(unix)]
fn run_read(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    c: &cli::ReadArgs,
) -> Result<(), CliError> {
    let (reference, keep, last) = (c.conversation.as_str(), c.keep, c.last);
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
    let group_id = message::resolve(&session.store, reference)?;
    if verify::changed_since_verified(&session.store, group_id) {
        eprintln!("{}", verify::CHANGED_WARNING);
    }
    let msgs = message::pending(&session.store, group_id)?;
    let alt = screen::wanted_on_stdout(c.json);
    let _signals = alt.then(screen::install_signal_restore);
    let _screen = screen::AltScreen::enter(std::io::stdout(), alt).map_err(|_| CliError::Stdout)?;
    // Only delete what reached the terminal: a closed pipe must not eat unseen messages. On the
    // alternate screen the output vanishes on exit, so removal waits for the reader's Enter.
    let window = message::until(message::since(&msgs, c.since), c.until);
    let shown = message::newest(window, last.map(|n| n as usize));
    let show_err = |e| match e {
        message::ShowError::Output => CliError::Stdout,
        message::ShowError::Discard(e) => CliError::Message(e),
    };
    message::show(
        &session.store,
        shown,
        keep || alt,
        c.json,
        &mut std::io::stdout(),
    )
    .map_err(show_err)?;
    if shown.is_empty() && !c.json {
        println!("no new messages");
    }
    if alt {
        println!("-- press Enter to close --");
        let seen = matches!(std::io::stdin().read_line(&mut String::new()), Ok(n) if n > 0);
        drop(_screen);
        if seen && !keep {
            for m in shown {
                message::discard(&session.store, m)?;
            }
        }
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
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
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
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
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
    let mut out = std::io::stdout();
    let written = if args.json {
        verify::report_json(&mut out, group_id, &number, state)
    } else {
        verify::report(&mut out, group_id, &number, state)
    };
    written.map_err(|_| CliError::Stdout)?;
    Ok(())
}

/// `chat`: logs in, then runs the REPL with stdin lines and `/v1/ws` wake-ups as events.
#[cfg(unix)]
fn run_chat(
    server: &url::Url,
    paths: &profile::ProfilePaths,
    reference: &str,
    allow_changed: bool,
) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let mut prompter = prompt::TtyPrompter;
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
    let group_id = message::resolve(&session.store, reference)?;
    let alt = screen::wanted_on_stdout(false);
    let _signals = alt.then(screen::install_signal_restore);
    let _screen = screen::AltScreen::enter(std::io::stdout(), alt).map_err(|_| CliError::Stdout)?;
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
            chat::Options {
                allow_changed,
                ..chat::Options::default()
            },
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
        cli::InviteCommand::Redeem { .. } => {
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
    let session = login_scoped(&rt, &client, server, paths, &mut prompter)?;
    match (cmd, link) {
        (cli::InviteCommand::Create { wait, json }, _) => {
            let (url, key_ref) = rt.block_on(invite::create(&client, server, &session))?;
            invite::write_created(&url, *json, &mut std::io::stdout())
                .map_err(|_| CliError::Output)?;
            if *wait > 0 {
                let w = u64::from(*wait);
                wait_for_welcome(&rt, &client, server, &session, &key_ref, w, *json)?;
            }
        }
        (cli::InviteCommand::Redeem { json }, Some(link)) => {
            let (id, pq) = rt.block_on(invite::redeem(&client, server, &session, &link))?;
            if *json {
                invite::write_redeemed(id, &pq, &mut std::io::stdout())
                    .map_err(|_| CliError::Output)?;
                if matches!(pq, invite::PqStatus::KeyRejected) {
                    print_pq_status(&pq); // the warning goes to stderr, stdout stays JSON
                }
            } else {
                println!("conversation {id}");
                print_pq_status(&pq);
            }
        }
        (cli::InviteCommand::Redeem { .. }, None) => return Err(CliError::Stdin),
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
    json: bool,
) -> Result<(), CliError> {
    let out_err = |_| CliError::Output;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);
    loop {
        let report = rt.block_on(welcome::join_pending(
            client,
            server,
            session,
            Some(key_ref),
        ))?;
        if let Some(id) = report.joined.first() {
            let mut out = std::io::stdout();
            return invite::write_joined(Some(*id), json, &mut out).map_err(out_err);
        }
        let poll = std::time::Duration::from_secs(WAIT_POLL_SECS);
        if std::time::Instant::now() + poll >= deadline {
            break;
        }
        std::thread::sleep(poll);
    }
    invite::write_joined(None, json, &mut std::io::stdout()).map_err(out_err)
}

fn run_status(server: &url::Url, json: bool) -> Result<(), CliError> {
    let rt = runtime()?;
    let client = status::http_client()?;
    let s = rt.block_on(status::fetch(&client, server))?;
    status::write_report(server, &s, json, &mut std::io::stdout()).map_err(|_| CliError::Output)
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
