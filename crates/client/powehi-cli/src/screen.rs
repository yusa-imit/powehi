//! Alternate screen for `chat` and `read` (8.3, #39-5): the conversation never lands in the
//! terminal scrollback (terminals that log the alternate screen aside). Active only when
//! stdin and stdout are TTYs and `--json` is off; restored on
//! normal exit, error and panic (the guard's `Drop`) and on SIGINT/SIGTERM/SIGHUP/SIGQUIT (an
//! async-signal-safe handler that writes the leave sequence, then re-raises the signal).

use std::io::{self, IsTerminal as _, Write};

/// Switch to the alternate buffer and home the cursor.
pub const ENTER: &[u8] = b"\x1b[?1049h\x1b[H";
/// Switch back to the main buffer; the scrollback is untouched.
pub const LEAVE: &[u8] = b"\x1b[?1049l";

const SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// True when the alternate screen may be used: interactive stdout and no machine output.
pub fn wanted(stdout_is_tty: bool, json: bool) -> bool {
    stdout_is_tty && !json
}

/// [`wanted`] for the real stdout.
/// Stdin must be a TTY too: with piped input a session ends at once and the screen with it.
pub fn wanted_on_stdout(json: bool) -> bool {
    wanted(
        io::stdout().is_terminal() && io::stdin().is_terminal(),
        json,
    )
}

/// Restores the main screen when dropped. Inert (writes nothing) when not active.
pub struct AltScreen<W: Write> {
    out: W,
    active: bool,
}

impl<W: Write> AltScreen<W> {
    /// Enters the alternate screen when `active`; otherwise writes nothing, now or on drop.
    pub fn enter(mut out: W, active: bool) -> io::Result<Self> {
        if active {
            out.write_all(ENTER)?;
            out.flush()?;
        }
        Ok(Self { out, active })
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The wrapped writer, for output that belongs on the (alternate) screen.
    pub fn out(&mut self) -> &mut W {
        &mut self.out
    }
}

impl<W: Write> Drop for AltScreen<W> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.out.write_all(LEAVE);
            let _ = self.out.flush();
            // Half-typed input must not reach the shell's prompt and history.
            // SAFETY: tcflush on a plain fd has no memory-safety preconditions.
            unsafe { libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH) };
        }
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    // SAFETY: write, signal and raise are async-signal-safe; LEAVE is a 'static slice.
    unsafe {
        libc::write(libc::STDOUT_FILENO, LEAVE.as_ptr().cast(), LEAVE.len());
        libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
    }
    crate::tui::term::restore_from_signal();
    // SAFETY: as above.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Restores the default SIGINT/SIGTERM disposition when dropped.
pub struct SignalGuard(());

/// Installs the leave-on-signal handlers for SIGINT and SIGTERM.
pub fn install_signal_restore() -> SignalGuard {
    for sig in SIGNALS {
        // SAFETY: `on_signal` is an `extern "C" fn(c_int)` that only calls async-signal-safe fns.
        unsafe {
            libc::signal(
                sig,
                on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
            )
        };
    }
    SignalGuard(())
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for sig in SIGNALS {
            // SAFETY: resetting to the default disposition is always valid.
            unsafe { libc::signal(sig, libc::SIG_DFL) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_interactive_non_json() {
        assert!(wanted(true, false));
        assert!(!wanted(true, true));
        assert!(!wanted(false, false));
        assert!(!wanted(false, true));
    }

    #[test]
    fn inactive_writes_no_escape_sequences() {
        let mut buf = Vec::new();
        {
            let mut s = AltScreen::enter(&mut buf, false).unwrap();
            assert!(!s.is_active());
            s.out().write_all(b"hello\n").unwrap();
        }
        assert_eq!(buf, b"hello\n");
        assert!(!buf.contains(&0x1b));
    }

    #[test]
    fn active_enters_then_leaves_on_drop() {
        let mut buf = Vec::new();
        {
            let mut s = AltScreen::enter(&mut buf, true).unwrap();
            s.out().write_all(b"x").unwrap();
        }
        assert_eq!(buf, [ENTER, b"x", LEAVE].concat());
    }

    #[test]
    fn leaves_when_the_body_fails() {
        fn body(buf: &mut Vec<u8>) -> Result<(), &'static str> {
            let _s = AltScreen::enter(buf, true).unwrap();
            Err("boom")
        }
        let mut buf = Vec::new();
        assert!(body(&mut buf).is_err());
        assert!(buf.ends_with(LEAVE));
    }

    #[test]
    fn leaves_on_panic() {
        let mut buf = Vec::new();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _s = AltScreen::enter(&mut buf, true).unwrap();
            panic!("boom");
        }));
        assert!(r.is_err());
        assert!(buf.ends_with(LEAVE));
    }

    #[test]
    fn signal_guard_resets_disposition() {
        let g = install_signal_restore();
        drop(g);
        // SAFETY: querying the disposition by installing SIG_DFL and reading the old one.
        let old = unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) };
        assert_eq!(old, libc::SIG_DFL);
    }
}
