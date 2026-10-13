//! `powehi chat`: interactive line REPL (prd.md §7A.2, §7.6).
//!
//! One loop reacts to [`Event`]s: typed lines are sent, a wake-up (realtime hint from
//! [`crate::ws`], or a poll tick) triggers a fetch through [`crate::inbox::receive`], and every
//! stored message of the conversation is then shown and removed. Lines come from stdin only
//! (never argv). Errors are reported by category; message text is never logged or echoed
//! back into error output.

use std::io::{BufRead as _, Write};
use std::time::Duration;

use reqwest::Client;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::Session;
use crate::{inbox, message};

/// A line typed by the user that ends the session.
pub const QUIT: &str = "/quit";
/// Events handled per run, a hard bound on the loop.
const MAX_EVENTS: u64 = 10_000_000;

pub enum Event {
    /// A line from the terminal.
    Line(Zeroizing<String>),
    /// New traffic may be waiting (realtime hint, reconnect, or poll tick).
    Wake,
    /// Realtime delivery gave up after its retries; polling continues.
    RealtimeLost,
    /// Input closed.
    Eof,
}

impl std::fmt::Debug for Event {
    /// Variant names only: a line is message plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Event::Line(_) => "Line",
            Event::Wake => "Wake",
            Event::RealtimeLost => "RealtimeLost",
            Event::Eof => "Eof",
        })
    }
}

/// Poll intervals: a safety net while realtime works, a fallback once it is lost.
#[derive(Clone, Copy)]
pub struct Polling {
    pub safety_net: Duration,
    pub fallback: Duration,
}

impl Default for Polling {
    fn default() -> Self {
        Self {
            safety_net: Duration::from_secs(60),
            fallback: Duration::from_secs(5),
        }
    }
}

/// Reads terminal lines on a blocking thread and forwards them. A line longer than the
/// message cap is dropped whole (never buffered unbounded); end of input sends [`Event::Eof`].
pub fn read_lines(mut input: impl std::io::BufRead, tx: &tokio::sync::mpsc::Sender<Event>) {
    loop {
        let mut line = Zeroizing::new(Vec::with_capacity(message::MAX_BODY_LEN + 3));
        let mut limited = std::io::Read::take(&mut input, message::MAX_BODY_LEN as u64 + 3);
        match limited.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if !line.ends_with(b"\n") && line.len() > message::MAX_BODY_LEN {
            // Over the cap: skip through the end of this line in bounded chunks, keeping nothing.
            let mut ended = false;
            while !ended {
                let n = match input.fill_buf() {
                    Ok([]) | Err(_) => break,
                    Ok(buf) => {
                        let n = buf
                            .iter()
                            .position(|&b| b == b'\n')
                            .map_or(buf.len(), |i| i + 1);
                        ended = buf[n - 1] == b'\n';
                        n
                    }
                };
                input.consume(n);
            }
            let too_long = Zeroizing::new("x".repeat(message::MAX_BODY_LEN + 1));
            if tx.blocking_send(Event::Line(too_long)).is_err() {
                return;
            }
            continue;
        }
        let text = Zeroizing::new(String::from_utf8_lossy(&line).into_owned());
        if tx.blocking_send(Event::Line(text)).is_err() {
            return;
        }
    }
    let _ = tx.blocking_send(Event::Eof);
}

/// Runs the REPL until `/quit`, end of input, or a closed output.
pub async fn run(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    events: &mut Receiver<Event>,
    out: &mut impl Write,
    polling: Polling,
) -> std::io::Result<()> {
    let mut realtime = true;
    if sync(client, server, session, group_id, out).await? {
        return Ok(());
    }
    for _ in 0..MAX_EVENTS {
        let wait = if realtime {
            polling.safety_net
        } else {
            polling.fallback
        };
        let event = match timeout(wait, events.recv()).await {
            Err(_) => Event::Wake,
            Ok(Some(e)) => e,
            Ok(None) => Event::Eof,
        };
        match event {
            Event::Eof => return Ok(()),
            Event::Wake => {
                if sync(client, server, session, group_id, out).await? {
                    return Ok(());
                }
            }
            Event::RealtimeLost => {
                realtime = false;
                writeln!(
                    out,
                    "! realtime connection lost; checking every few seconds"
                )?;
                out.flush()?;
            }
            Event::Line(line) => {
                let text = line.trim_end_matches(['\r', '\n']);
                if text == QUIT {
                    return Ok(());
                }
                if text.trim().is_empty() {
                    continue;
                }
                send_line(client, server, session, group_id, text, out).await?;
            }
        }
    }
    Ok(())
}

async fn send_line(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    text: &str,
    out: &mut impl Write,
) -> std::io::Result<()> {
    let result = match message::check_body(text.as_bytes()) {
        Ok(body) => message::send(client, server, session, group_id, body).await,
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        writeln!(out, "! not sent: {e}")?;
        out.flush()?;
    }
    Ok(())
}

/// Fetches, then shows and removes the conversation's stored messages. Returns true when
/// the output is gone and the session should end.
async fn sync(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    out: &mut impl Write,
) -> std::io::Result<bool> {
    if let Err(e) = inbox::receive(client, server, session).await {
        writeln!(out, "! receive failed: {e}")?;
    }
    let Ok(msgs) = message::pending(&session.store, group_id) else {
        writeln!(out, "! could not read stored messages")?;
        return Ok(false);
    };
    for m in &msgs {
        // Only delete what reached the terminal.
        if message::display(out, m).is_err() {
            return Ok(true);
        }
        if message::discard(&session.store, m).is_err() {
            writeln!(out, "! could not remove a shown message from the store")?;
        }
    }
    out.flush()?;
    Ok(false)
}

#[cfg(test)]
mod tests;
