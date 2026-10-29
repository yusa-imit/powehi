//! Raw terminal bytes to [`Key`]s (8.20 slice b). No terminal access: the event loop feeds
//! whatever `read(2)` returned. A byte state machine with fixed-size state: escape sequences
//! other than Up/Down (CSI of any length, SS3, OSC/DCS/APC/PM/SOS strings) are swallowed whole
//! so a terminal reply or a stray `ESC [ 3 ~` never types into the message line. The partial
//! UTF-8 tail is a fixed array, wiped when it completes, is dropped, or on drop.

use zeroize::Zeroize;

use super::Key;

/// A string sequence (OSC and friends) longer than this is abandoned.
const MAX_STRING: u16 = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Utf8 {
        need: u8,
        len: u8,
    },
    Esc,
    /// `plain`: no parameter or intermediate byte seen yet.
    Csi {
        plain: bool,
    },
    Ss3,
    Str {
        seen: u16,
        esc: bool,
    },
}

/// Incremental decoder.
pub struct Decoder {
    state: State,
    buf: [u8; 4],
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            state: State::Ground,
            buf: [0; 4],
        }
    }

    /// Decodes `bytes` after any carried-over state, appending keys to `out`.
    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<Key>) {
        for &b in bytes {
            self.byte(b, out);
        }
    }

    /// A lone ESC left over after a quiet period is the Esc key.
    pub fn finish(&mut self) -> Option<Key> {
        // Only a bare ESC is resolved by a quiet period; a sequence split by a slow link
        // stays in flight so its tail never types into the message line.
        if self.state == State::Esc {
            self.reset();
            return Some(Key::Esc);
        }
        None
    }

    fn reset(&mut self) {
        self.state = State::Ground;
        self.buf.zeroize();
    }

    fn byte(&mut self, b: u8, out: &mut Vec<Key>) {
        match self.state {
            State::Ground => self.ground(b, out),
            State::Utf8 { need, len } => {
                if (0x80..=0xbf).contains(&b) {
                    self.buf[usize::from(len)] = b;
                    if len + 1 == need {
                        let s = std::str::from_utf8(&self.buf[..usize::from(need)]);
                        // C1 controls (U+0080..U+009F) are dropped like their ASCII kin.
                        let c = s.ok().and_then(|s| s.chars().next());
                        out.extend(c.filter(|c| !c.is_control()).map(Key::Char));
                        self.reset();
                    } else {
                        self.state = State::Utf8 { need, len: len + 1 };
                    }
                } else {
                    // Broken char: drop the partial one, read this byte afresh.
                    self.reset();
                    self.ground(b, out);
                }
            }
            State::Esc => match b {
                b'[' => self.state = State::Csi { plain: true },
                b'O' => self.state = State::Ss3,
                b']' | b'P' | b'_' | b'^' | b'X' => {
                    self.state = State::Str {
                        seen: 0,
                        esc: false,
                    }
                }
                0x1b => {}
                0x00..=0x1f => {
                    self.reset();
                    self.ground(b, out);
                }
                _ => self.reset(), // Alt-key: dropped
            },
            State::Csi { plain } => match b {
                0x20..=0x3f => self.state = State::Csi { plain: false },
                0x40..=0x7e => {
                    match (plain, b) {
                        (true, b'A') => out.push(Key::Up),
                        (true, b'B') => out.push(Key::Down),
                        _ => {}
                    }
                    self.reset();
                }
                _ => {
                    self.reset();
                    self.ground(b, out);
                }
            },
            State::Ss3 => {
                match b {
                    b'A' => out.push(Key::Up),
                    b'B' => out.push(Key::Down),
                    _ => {}
                }
                self.reset();
            }
            State::Str { seen, esc } => match (b, esc) {
                (0x07, _) | (b'\\', true) => self.reset(),
                (0x1b, false) => self.state = State::Str { seen, esc: true },
                (_, true) => {
                    self.reset();
                    self.ground(0x1b, out);
                    self.byte(b, out);
                }
                _ if seen >= MAX_STRING => self.reset(),
                _ => {
                    self.state = State::Str {
                        seen: seen + 1,
                        esc: false,
                    }
                }
            },
        }
    }

    fn ground(&mut self, b: u8, out: &mut Vec<Key>) {
        match b {
            0x1b => self.state = State::Esc,
            b'\r' | b'\n' => out.push(Key::Enter),
            0x7f | 0x08 => out.push(Key::Backspace),
            // Ctrl-C and Ctrl-D quit: raw mode turns off the signal that would do it.
            0x03 | 0x04 => out.push(Key::Esc),
            0x00..=0x1f => {}
            0x20..=0x7e => out.push(Key::Char(char::from(b))),
            0xc2..=0xdf => self.start_utf8(b, 2),
            0xe0..=0xef => self.start_utf8(b, 3),
            0xf0..=0xf4 => self.start_utf8(b, 4),
            _ => {}
        }
    }

    fn start_utf8(&mut self, b: u8, need: u8) {
        self.buf[0] = b;
        self.state = State::Utf8 { need, len: 1 };
    }
}
