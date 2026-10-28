//! The `powehi tui` event loop over abstract input and output (8.20 slice b2a). Bytes in,
//! keys through the [`Decoder`], [`App::press`], a repaint out. Sending is a callback so the
//! loop is testable without a terminal or a network; message text is handed over zeroizing
//! and never logged.

use std::io::{self, Write};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::input::Decoder;
use super::paint::paint;
use super::{draw, Action, App, Key};

/// Largest screen painted, in cells per side.
const MAX_DIM: u16 = 500;
/// Shown when the send callback fails.
pub const SEND_FAILED: &str = "send failed";
const MIN_W: u16 = 40;
const MIN_H: u16 = 8;

/// One read attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    /// The first `n` bytes of the buffer are input.
    Bytes(usize),
    /// Nothing arrived within the idle timeout.
    Idle,
    /// Input is closed.
    Eof,
}

pub trait Source {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<Poll>;
}

/// Runs until Esc, end of input, or an I/O error. `size` is asked before each repaint.
/// `send` carries out a send; `Err` leaves a notice and keeps the loop going.
pub fn run<S, W, Z, F>(
    app: &mut App,
    src: &mut S,
    out: &mut W,
    mut size: Z,
    mut send: F,
) -> io::Result<()>
where
    S: Source,
    W: Write,
    Z: FnMut() -> (u16, u16),
    F: FnMut(Uuid, &str) -> Result<(), ()>,
{
    let (w, h) = size();
    if w < MIN_W || h < MIN_H {
        // Painting beyond the screen would wrap and scroll the conversation into scrollback.
        return Err(io::Error::other("terminal too small"));
    }
    let mut dec = Decoder::new();
    let mut raw = Zeroizing::new([0u8; 256]);
    let mut keys = Vec::with_capacity(raw.len());
    repaint(app, out, size())?;
    loop {
        keys.clear();
        match src.read(&mut raw[..])? {
            Poll::Eof => return Ok(()),
            Poll::Idle => keys.extend(dec.finish()),
            Poll::Bytes(n) => {
                assert!(n <= raw.len());
                dec.feed(&raw[..n], &mut keys);
                raw[..n].zeroize();
            }
        }
        for key in keys.iter().copied() {
            match app.press(key) {
                Action::None => {}
                Action::Quit => return Ok(()),
                Action::Send { group, text } => match send(group, &text) {
                    Ok(()) => app.push_message(group, "me".into(), text),
                    Err(()) => app.set_notice(SEND_FAILED),
                },
            }
        }
        // Typed text decoded into keys must not linger in the freed buffer.
        keys.fill(Key::Esc);
        repaint(app, out, size())?;
    }
}

fn repaint<W: Write>(app: &App, out: &mut W, (w, h): (u16, u16)) -> io::Result<()> {
    let area = Rect::new(0, 0, w.min(MAX_DIM), h.min(MAX_DIM));
    let mut buf = Buffer::empty(area);
    draw(app, area, &mut buf);
    out.write_all(&paint(&buf))?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::Kind;
    use crate::tui::{Mark, Row};

    struct Script(Vec<Poll2>);
    enum Poll2 {
        Data(&'static [u8]),
        Idle,
    }
    impl Source for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<Poll> {
            if self.0.is_empty() {
                return Ok(Poll::Eof);
            }
            Ok(match self.0.remove(0) {
                Poll2::Data(d) => {
                    buf[..d.len()].copy_from_slice(d);
                    Poll::Bytes(d.len())
                }
                Poll2::Idle => Poll::Idle,
            })
        }
    }

    fn row(mark: Mark) -> Row {
        Row {
            id: Uuid::new_v4(),
            kind: Kind::Pair,
            unread: 0,
            mark,
        }
    }

    fn go(
        app: &mut App,
        script: Vec<Poll2>,
        send: impl FnMut(Uuid, &str) -> Result<(), ()>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        run(app, &mut Script(script), &mut out, || (80, 24), send).unwrap();
        out
    }

    #[test]
    fn typed_line_is_sent_once_and_shown() {
        let r = row(Mark::Verified);
        let id = r.id;
        let mut app = App::new(vec![r]);
        let mut sent = Vec::new();
        let out = go(
            &mut app,
            vec![Poll2::Data(b"hi\r"), Poll2::Data(b"\x1b"), Poll2::Idle],
            |g, t| {
                sent.push((g, t.to_owned()));
                Ok(())
            },
        );
        assert_eq!(sent, vec![(id, "hi".to_owned())]);
        assert!(String::from_utf8_lossy(&out).contains("[me] hi"));
    }

    #[test]
    fn esc_prefix_is_a_sequence_and_idle_esc_quits() {
        let mut app = App::new(vec![row(Mark::Verified)]);
        // ESC then more input: a sequence, not a quit; EOF ends the run.
        go(
            &mut app,
            vec![Poll2::Data(b"\x1b"), Poll2::Data(b"[3~a")],
            |_, _| Ok(()),
        );
        assert_eq!(app.input_len(), 1);
        // A lone ESC followed by an idle tick is the Esc key: the run ends before the 'z'.
        let mut app = App::new(vec![row(Mark::Verified)]);
        go(
            &mut app,
            vec![Poll2::Data(b"\x1b"), Poll2::Idle, Poll2::Data(b"z")],
            |_, _| Ok(()),
        );
        assert_eq!(app.input_len(), 0);
    }

    #[test]
    fn failed_send_sets_a_notice_and_keeps_running() {
        let mut app = App::new(vec![row(Mark::Verified)]);
        let out = go(&mut app, vec![Poll2::Data(b"x\r")], |_, _| Err(()));
        assert_eq!(app.notice(), Some(SEND_FAILED));
        assert!(String::from_utf8_lossy(&out).contains(SEND_FAILED));
    }

    #[test]
    fn changed_conversation_never_reaches_the_send_callback() {
        let mut app = App::new(vec![row(Mark::Changed)]);
        let mut called = false;
        go(&mut app, vec![Poll2::Data(b"x\r")], |_, _| {
            called = true;
            Ok(())
        });
        assert!(!called);
    }

    #[test]
    fn switching_conversation_clears_the_input() {
        let mut app = App::new(vec![row(Mark::Verified), row(Mark::Verified)]);
        go(&mut app, vec![Poll2::Data(b"secret\x1b[B")], |_, _| Ok(()));
        assert_eq!(app.input_len(), 0);
    }

    #[test]
    fn tiny_terminal_is_clamped_not_a_panic() {
        let app = App::new(vec![row(Mark::Verified)]);
        let mut out = Vec::new();
        repaint(&app, &mut out, (1, 1)).unwrap();
        repaint(&app, &mut out, (u16::MAX, u16::MAX)).unwrap();
        assert!(!out.contains(&0x07));
    }

    #[test]
    fn too_small_terminal_is_refused() {
        let mut app = App::new(vec![row(Mark::Verified)]);
        let mut out = Vec::new();
        let r = run(
            &mut app,
            &mut Script(vec![]),
            &mut out,
            || (10, 3),
            |_, _| Ok(()),
        );
        assert!(r.is_err() && out.is_empty());
    }

    #[test]
    fn vanished_selection_drops_the_half_typed_line() {
        let mut app = App::new(vec![row(Mark::Verified), row(Mark::Verified)]);
        app.press(Key::Char('a'));
        app.set_rows(vec![row(Mark::Verified)]);
        assert_eq!(app.input_len(), 0);
    }
}
