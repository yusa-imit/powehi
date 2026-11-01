//! Interactive input (prd.md §7A.3): the handle and password are read from the controlling
//! terminal (`/dev/tty`), never from argv, the environment or a pipe on stdin. The password is
//! read with echo off and lives only in `Zeroizing` buffers.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;

use thiserror::Error;
use zeroize::Zeroizing;

/// Longest accepted input line, in bytes.
pub const MAX_LINE_LEN: usize = 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PromptError {
    #[error("no terminal available; run powehi from an interactive shell")]
    NoTty,
    #[error("input is empty")]
    Empty,
    #[error("input is longer than {MAX_LINE_LEN} bytes")]
    TooLong,
    #[error("input is not valid UTF-8")]
    NotUtf8,
    #[error("the two passwords differ")]
    Mismatch,
    #[error("could not read from the terminal")]
    Io,
}

/// Source of the user's handle and password. The TTY implementation is the only production one;
/// tests inject canned answers.
pub trait Prompter {
    /// The (non-secret, echoed) account handle.
    fn handle(&mut self) -> Result<Zeroizing<String>, PromptError>;
    /// The password, echo off. `confirm` asks twice and requires both to match.
    fn password(&mut self, confirm: bool) -> Result<Zeroizing<String>, PromptError>;
    /// Shows the recovery phrase exactly once. It goes to the terminal, never to stdout, so a
    /// redirect or pipe cannot capture it.
    fn show_recovery_phrase(&mut self, phrase: &str) -> Result<(), PromptError>;
    /// Asks whether to convert a profile in the pre-`PHS3` store format (8.8). `Ok(false)` or an
    /// error leaves it untouched; there is no non-interactive way to say yes.
    fn confirm_store_upgrade(&mut self) -> Result<bool, PromptError>;
    /// The existing 24-word recovery phrase, echo off (`restore`, 8.18). It never reaches argv.
    fn recovery_phrase(&mut self) -> Result<Zeroizing<String>, PromptError>;
}

/// Reads from `/dev/tty`.
pub struct TtyPrompter;

struct EchoGuard {
    fd: i32,
    saved: libc::termios,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: `fd` is the tty descriptor, which outlives the guard (see `read_secret`), and `saved` is
        // the termios previously returned by `tcgetattr` on it.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
    }
}

fn open_tty() -> Result<File, PromptError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| PromptError::NoTty)
}

/// Reads one line (without the trailing newline) byte by byte so nothing past it is consumed.
fn read_line(tty: &mut File) -> Result<Zeroizing<String>, PromptError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_LINE_LEN));
    let mut byte = [0u8; 1];
    loop {
        match tty.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if buf.len() >= MAX_LINE_LEN {
                    return Err(PromptError::TooLong);
                }
                buf.push(byte[0]);
            }
            Err(_) => return Err(PromptError::Io),
        }
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    let s = std::str::from_utf8(&buf).map_err(|_| PromptError::NotUtf8)?;
    if s.is_empty() {
        return Err(PromptError::Empty);
    }
    Ok(Zeroizing::new(s.to_owned()))
}

/// Clears `flags` from the terminal's local modes; the returned guard restores the old modes.
fn set_lflag(tty: &File, flags: libc::tcflag_t) -> Result<EchoGuard, PromptError> {
    let fd = tty.as_raw_fd();
    // SAFETY: zeroed termios is a valid out-parameter for `tcgetattr`.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a valid open descriptor owned by `tty`.
    if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
        return Err(PromptError::NoTty);
    }
    let mut quiet = saved;
    quiet.c_lflag &= !flags;
    // SAFETY: as above; `quiet` is a fully initialised termios.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
        return Err(PromptError::NoTty);
    }
    Ok(EchoGuard { fd, saved })
}

fn read_secret(tty: &mut File, label: &str) -> Result<Zeroizing<String>, PromptError> {
    // Echo is off from here on; the guard restores it on every exit path.
    let _guard = set_lflag(tty, libc::ECHO)?;
    let mut out = tty.try_clone().map_err(|_| PromptError::Io)?;
    write!(out, "{label}").map_err(|_| PromptError::Io)?;
    let result = read_line(tty);
    writeln!(out).map_err(|_| PromptError::Io)?;
    result
}

impl Prompter for TtyPrompter {
    fn handle(&mut self) -> Result<Zeroizing<String>, PromptError> {
        let mut tty = open_tty()?;
        write!(tty, "Handle: ").map_err(|_| PromptError::Io)?;
        let line = read_line(&mut tty)?;
        let trimmed = Zeroizing::new(line.trim().to_owned());
        if trimmed.is_empty() {
            return Err(PromptError::Empty);
        }
        Ok(trimmed)
    }

    fn password(&mut self, confirm: bool) -> Result<Zeroizing<String>, PromptError> {
        let mut tty = open_tty()?;
        let first = read_secret(&mut tty, "Password: ")?;
        if confirm {
            let second = read_secret(&mut tty, "Repeat password: ")?;
            if *first != *second {
                return Err(PromptError::Mismatch);
            }
        }
        Ok(first)
    }

    fn show_recovery_phrase(&mut self, phrase: &str) -> Result<(), PromptError> {
        let mut tty = open_tty()?;
        // No echo and no signal keys while the phrase is on screen: Ctrl-C must not skip the
        // scrollback wipe, and stray typing must not echo or reach the parent shell.
        let _guard = set_lflag(&tty, libc::ECHO | libc::ISIG)?;
        // SAFETY: valid tty descriptor; discards input typed ahead of the prompt.
        unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) };
        write!(
            tty,
            "\nRecovery phrase (write it down; it is shown only once and cannot be recovered):\n\n  {phrase}\n\nPress Enter once you have stored it safely..."
        )
        .map_err(|_| PromptError::Io)?;
        // Wait for a full line; on EOF or error keep the phrase on screen and fail.
        let mut byte = [0u8; 1];
        loop {
            match tty.read(&mut byte) {
                Ok(1) if byte[0] == b'\n' => break,
                Ok(1) => {}
                _ => return Err(PromptError::Io),
            }
        }
        // SAFETY: as above; drops anything typed after the Enter so it cannot reach the shell.
        unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) };
        // Clear the screen and scrollback so the phrase does not linger in the terminal.
        write!(tty, "\x1b[2J\x1b[3J\x1b[H").map_err(|_| PromptError::Io)
    }

    fn recovery_phrase(&mut self) -> Result<Zeroizing<String>, PromptError> {
        let mut tty = open_tty()?;
        read_secret(&mut tty, "Recovery phrase: ")
    }

    fn confirm_store_upgrade(&mut self) -> Result<bool, PromptError> {
        let mut tty = open_tty()?;
        write!(
            tty,
            "This profile uses an older store format. Upgrade it now? Answer N if you already upgraded this profile (files may have been deleted). Back up the profile directory first. [y/N] "
        )
        .map_err(|_| PromptError::Io)?;
        match read_line(&mut tty) {
            Ok(answer) => Ok(is_yes(&answer)),
            Err(PromptError::Empty) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Only an explicit `y` or `yes` (any case) confirms.
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Canned answers for tests.
#[cfg(test)]
pub struct ScriptedPrompter {
    pub handle: String,
    pub passwords: Vec<String>,
    pub shown: Vec<String>,
    /// Answer to `confirm_store_upgrade`; `asked_upgrade` counts the questions.
    pub upgrade: bool,
    pub asked_upgrade: usize,
    /// Answers to `recovery_phrase`, consumed front to back.
    pub phrases: Vec<String>,
}

#[cfg(test)]
impl Prompter for ScriptedPrompter {
    fn handle(&mut self) -> Result<Zeroizing<String>, PromptError> {
        Ok(Zeroizing::new(self.handle.clone()))
    }

    fn password(&mut self, _confirm: bool) -> Result<Zeroizing<String>, PromptError> {
        if self.passwords.is_empty() {
            return Err(PromptError::Empty);
        }
        Ok(Zeroizing::new(self.passwords.remove(0)))
    }

    fn show_recovery_phrase(&mut self, phrase: &str) -> Result<(), PromptError> {
        self.shown.push(phrase.to_owned());
        Ok(())
    }

    fn recovery_phrase(&mut self) -> Result<Zeroizing<String>, PromptError> {
        if self.phrases.is_empty() {
            return Err(PromptError::Empty);
        }
        Ok(Zeroizing::new(self.phrases.remove(0)))
    }

    fn confirm_store_upgrade(&mut self) -> Result<bool, PromptError> {
        self.asked_upgrade += 1;
        Ok(self.upgrade)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    /// A regular file stands in for the tty: `read_line` only needs `Read`.
    fn file_with(bytes: &[u8]) -> File {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(bytes).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f
    }

    #[test]
    fn only_an_explicit_yes_confirms_the_upgrade() {
        for yes in ["y", "Y", "yes", " YES "] {
            assert!(is_yes(yes), "{yes}");
        }
        for no in ["", "n", "no", "yep", "ye", "1", "yes please"] {
            assert!(!is_yes(no), "{no}");
        }
    }

    #[test]
    fn reads_one_line_and_consumes_nothing_past_it() {
        let mut f = file_with(b"alice\nsecond\n");
        assert_eq!(*read_line(&mut f).unwrap(), "alice");
        assert_eq!(*read_line(&mut f).unwrap(), "second");
    }

    #[test]
    fn strips_one_trailing_carriage_return_and_accepts_eof_as_end() {
        assert_eq!(*read_line(&mut file_with(b"pw\r\n")).unwrap(), "pw");
        assert_eq!(
            *read_line(&mut file_with(b"no-newline")).unwrap(),
            "no-newline"
        );
    }

    #[test]
    fn rejects_empty_lines_and_eof() {
        for raw in [&b""[..], b"\n", b"\r\n"] {
            assert_eq!(
                read_line(&mut file_with(raw)).unwrap_err(),
                PromptError::Empty
            );
        }
    }

    #[test]
    fn enforces_the_line_length_limit_exactly() {
        let mut ok = vec![b'a'; MAX_LINE_LEN];
        ok.push(b'\n');
        assert_eq!(read_line(&mut file_with(&ok)).unwrap().len(), MAX_LINE_LEN);
        let mut long = vec![b'a'; MAX_LINE_LEN + 1];
        long.push(b'\n');
        assert_eq!(
            read_line(&mut file_with(&long)).unwrap_err(),
            PromptError::TooLong
        );
    }

    #[test]
    fn rejects_invalid_utf8() {
        let r = read_line(&mut file_with(b"\xff\xfe\n"));
        assert_eq!(r.unwrap_err(), PromptError::NotUtf8);
    }

    #[test]
    fn terminal_modes_need_a_real_tty() {
        // A regular file is not a terminal, so echo can never be silently "disabled" on it.
        let f = file_with(b"x");
        assert_eq!(set_lflag(&f, libc::ECHO).err(), Some(PromptError::NoTty));
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Anything that is not y/yes after trim+lowercase never confirms.
            #[test]
            fn is_yes_matches_only_the_two_spellings(s in "\\PC{0,12}") {
                let norm = s.trim().to_ascii_lowercase();
                prop_assert_eq!(is_yes(&s), norm == "y" || norm == "yes");
            }

            /// A line without newline, CR or NUL tricks round-trips and consumes only itself.
            #[test]
            fn read_line_round_trips_valid_lines(
                line in "[^\\r\\n]{1,64}",
                rest in "[a-z]{0,16}",
            ) {
                let raw = format!("{line}\n{rest}");
                let mut f = file_with(raw.as_bytes());
                prop_assert_eq!(&**read_line(&mut f).unwrap(), line.as_str());
                if !rest.is_empty() {
                    prop_assert_eq!(&**read_line(&mut f).unwrap(), rest.as_str());
                }
            }

            /// Any byte soup is either a bounded valid-UTF-8 line or a typed error, never a panic.
            #[test]
            fn read_line_is_total_and_bounded(raw in proptest::collection::vec(any::<u8>(), 0..1100)) {
                match read_line(&mut file_with(&raw)) {
                    Ok(l) => {
                        prop_assert!(!l.is_empty() && l.len() <= MAX_LINE_LEN);
                        prop_assert!(!l.contains('\n'));
                    }
                    Err(e) => prop_assert!(matches!(
                        e,
                        PromptError::Empty | PromptError::TooLong | PromptError::NotUtf8
                    )),
                }
            }
        }
    }
}
