//! Raw terminal mode, size and polled reads for the TUI event loop (8.20 slice b2a).
//!
//! [`RawMode`] puts stdin in raw mode and restores the saved settings when dropped. Reads go
//! through `poll(2)` with a short timeout so the loop can tell an idle terminal (a lone ESC is
//! the Esc key) from a closed one.

use std::io;

use super::run::{Poll, Source};

/// Poll timeout: how long a lone ESC waits for the rest of a sequence.
const IDLE_MS: libc::c_int = 100;

/// The settings to restore from a signal handler; set once by [`RawMode::enter`].
static SAVED: std::sync::OnceLock<libc::termios> = std::sync::OnceLock::new();

/// Async-signal-safe: puts back the cooked settings if raw mode was ever entered.
pub fn restore_from_signal() {
    if let Some(saved) = SAVED.get() {
        // SAFETY: tcsetattr is async-signal-safe; `saved` came from tcgetattr on this fd.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, saved) };
    }
}

/// Restores the terminal settings captured by [`RawMode::enter`] when dropped.
pub struct RawMode {
    saved: libc::termios,
}

impl RawMode {
    /// Raw mode on stdin; fails when stdin is not a terminal.
    pub fn enter() -> io::Result<Self> {
        // Output must be a terminal too: the frames carry message plaintext.
        if !io::IsTerminal::is_terminal(&io::stdout()) {
            return Err(io::Error::other("stdout is not a terminal"));
        }
        // SAFETY: termios is plain data; tcgetattr fills it or fails.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `saved` is a valid out-pointer for the call.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let _ = SAVED.set(saved);
        let mut raw = saved;
        // SAFETY: `raw` is a valid termios.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: `raw` is initialised; TCSAFLUSH also drops pending input.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: `saved` came from tcgetattr on the same fd.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &self.saved) };
    }
}

/// Terminal size in cells, `None` when it cannot be read.
pub fn size() -> Option<(u16, u16)> {
    // SAFETY: winsize is plain data; ioctl fills it on success.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes a winsize through the pointer.
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    (rc == 0 && ws.ws_col > 0 && ws.ws_row > 0).then_some((ws.ws_col, ws.ws_row))
}

/// True when the locale names UTF-8. The painter emits raw UTF-8, which is unsafe on a
/// terminal that treats C1 bytes as controls (b1 carry).
pub fn utf8_locale(lc_all: Option<&str>, lc_ctype: Option<&str>, lang: Option<&str>) -> bool {
    let pick = [lc_all, lc_ctype, lang]
        .into_iter()
        .flatten()
        .find(|v| !v.is_empty());
    pick.is_some_and(|v| {
        let v = v.to_ascii_lowercase();
        v.contains("utf-8") || v.contains("utf8")
    })
}

/// [`utf8_locale`] over the process environment.
pub fn utf8_locale_from_env() -> bool {
    let get = |k: &str| std::env::var(k).ok();
    utf8_locale(
        get("LC_ALL").as_deref(),
        get("LC_CTYPE").as_deref(),
        get("LANG").as_deref(),
    )
}

/// Stdin as a [`Source`].
pub struct Stdin;

impl Source for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<Poll> {
        let mut fd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, count 1.
        let rc = unsafe { libc::poll(&mut fd, 1, IDLE_MS) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(Poll::Idle)
            } else {
                Err(e)
            };
        }
        if rc == 0 {
            return Ok(Poll::Idle);
        }
        // SAFETY: `buf` is valid for `buf.len()` writable bytes.
        let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len()) };
        match usize::try_from(n) {
            Ok(0) => Ok(Poll::Eof),
            Ok(n) => Ok(Poll::Bytes(n)),
            Err(_) => Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_precedence_and_spelling() {
        assert!(utf8_locale(None, None, Some("en_US.UTF-8")));
        assert!(utf8_locale(None, Some("ko_KR.utf8"), Some("C")));
        // LC_ALL wins over a UTF-8 LANG.
        assert!(!utf8_locale(Some("C"), None, Some("en_US.UTF-8")));
        // An empty variable is unset.
        assert!(utf8_locale(Some(""), None, Some("en_US.UTF-8")));
        assert!(!utf8_locale(None, None, None));
        assert!(!utf8_locale(None, None, Some("POSIX")));
    }
}
