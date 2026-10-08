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
}

/// Canned answers for tests.
#[cfg(test)]
pub struct ScriptedPrompter {
    pub handle: String,
    pub passwords: Vec<String>,
    pub shown: Vec<String>,
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
}
