//! `powehi tui` view-model and renderer (prd.md §7A.2, 8.20 slice a).
//!
//! [`App`] is a pure state machine: [`App::press`] turns a [`Key`] into an [`Action`] for the
//! caller to carry out, and [`draw`] paints the state into a ratatui [`Buffer`]. Nothing here
//! touches the terminal, the network, or the disk, so message text lives only in memory
//! (wiped on drop) and is never logged. Every string that reaches the buffer passes through
//! [`clean`], so a peer cannot inject terminal control sequences even if an upstream
//! sanitiser were bypassed.

use std::collections::BTreeMap;

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, StatefulWidget, Widget,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub mod input;
pub mod paint;
pub mod rows;
pub mod run;
pub mod sync;
pub mod term;

use crate::conversation::Kind;

/// Conversations listed (matches the store record cap).
pub const MAX_ROWS: usize = crate::store::MAX_RECORDS;
/// Messages kept in memory per conversation; the oldest is dropped (and wiped) beyond this.
pub const MAX_LINES: usize = 500;

/// Verification marker of a conversation (prd.md §5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Verified,
    Unverified,
    /// The verified Safety Number no longer matches: sending is refused.
    Changed,
}

/// One entry of the conversation list. Ids, kinds and counts are not message content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: Uuid,
    pub kind: Kind,
    pub unread: usize,
    pub mark: Mark,
}

/// A terminal key, already decoded by the (later) event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Backspace,
    Esc,
    /// Ctrl-V: open the verify pane for the selected conversation.
    Verify,
    Char(char),
}

/// What the caller must do after a key.
pub enum Action {
    None,
    Quit,
    /// Send `text` to `group`.
    Send {
        group: Uuid,
        text: Zeroizing<String>,
    },
    /// Compute the Safety Number of `group` and show it ([`App::open_verify`]).
    Verify {
        group: Uuid,
    },
    /// The user typed `typed` in the verify pane; confirm it against the current number.
    Confirm {
        group: Uuid,
        typed: String,
    },
}

impl std::fmt::Debug for Action {
    /// Variant names only: `text` is message plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Action::None => "None",
            Action::Quit => "Quit",
            Action::Send { .. } => "Send",
            Action::Verify { .. } => "Verify",
            Action::Confirm { .. } => "Confirm",
        })
    }
}

/// One shown message: a short sender label and its text.
struct Shown {
    who: String,
    text: Zeroizing<String>,
}

/// The verify pane: the number to compare and what the user has typed so far.
struct Pane {
    group: Uuid,
    number: String,
    typed: Zeroizing<String>,
    opened: std::time::Instant,
}

/// Longest line accepted in the verify pane (a Safety Number is 83 characters).
const MAX_TYPED: usize = 100;
/// Shown when the verify pane's input is rejected.
pub const VERIFY_FAILED: &str = "number does not match; not verified";
/// Enter in the verify pane is ignored for this long after it opens, so bytes that arrived
/// together with the opening key (a hostile paste) cannot confirm a number nobody compared.
pub const VERIFY_MIN_OPEN: std::time::Duration = std::time::Duration::from_secs(2);
/// Shown when Enter comes too soon after the pane opened.
pub const VERIFY_TOO_SOON: &str = "compare the number first, then press Enter";
/// Shown when no Safety Number can be computed.
pub const NO_NUMBER: &str = "cannot compute a safety number here";

/// Screen state.
pub struct App {
    verify: Option<Pane>,
    verify_delay: std::time::Duration,
    rows: Vec<Row>,
    selected: usize,
    input: Zeroizing<String>,
    shown: BTreeMap<Uuid, Vec<Shown>>,
    notice: Option<&'static str>,
}

/// Shown when the user tries to send into a CHANGED conversation.
pub const CHANGED_NOTICE: &str = "CHANGED: verify the safety number before sending";
/// Shown when the input line is full.
pub const FULL_NOTICE: &str = "message too long";

impl App {
    /// Builds the screen over `rows` (at most [`MAX_ROWS`], extra rows are dropped).
    pub fn new(mut rows: Vec<Row>) -> Self {
        rows.truncate(MAX_ROWS);
        Self {
            verify: None,
            verify_delay: VERIFY_MIN_OPEN,
            rows,
            selected: 0,
            input: Zeroizing::new(String::with_capacity(crate::message::MAX_BODY_LEN)),
            shown: BTreeMap::new(),
            notice: None,
        }
    }

    pub fn selected_id(&self) -> Option<Uuid> {
        self.rows.get(self.selected).map(|r| r.id)
    }

    pub fn input_len(&self) -> usize {
        self.input.len()
    }

    pub fn notice(&self) -> Option<&'static str> {
        self.notice
    }

    pub fn set_notice(&mut self, notice: &'static str) {
        self.notice = Some(notice);
    }

    /// Replaces the list (keeping the selection on the same conversation when it survives).
    pub fn set_rows(&mut self, mut rows: Vec<Row>) {
        rows.truncate(MAX_ROWS);
        let keep = self.selected_id();
        self.selected = keep
            .and_then(|id| rows.iter().position(|r| r.id == id))
            .unwrap_or(0);
        if keep.is_some() && keep != rows.get(self.selected).map(|r| r.id) {
            // The chat under the cursor vanished: the half-typed line is not for the new one.
            self.input = Zeroizing::new(String::with_capacity(crate::message::MAX_BODY_LEN));
        }
        self.rows = rows;
        if self.verify.as_ref().map(|p| p.group) != self.selected_id() {
            self.verify = None;
        }
        assert!(self.rows.is_empty() || self.selected < self.rows.len());
    }

    /// Opens the verify pane for `group` (the selected conversation) showing `number`.
    pub fn open_verify(&mut self, group: Uuid, number: String) {
        if self.selected_id() != Some(group) {
            return;
        }
        // Whatever was typed for a message is not for this pane.
        self.input = Zeroizing::new(String::with_capacity(crate::message::MAX_BODY_LEN));
        self.verify = Some(Pane {
            group,
            number,
            typed: Zeroizing::new(String::with_capacity(MAX_TYPED)),
            opened: std::time::Instant::now(),
        });
    }

    /// Overrides the minimum time the pane stays open before Enter confirms (tests).
    pub fn set_verify_delay(&mut self, delay: std::time::Duration) {
        self.verify_delay = delay;
    }

    pub fn close_verify(&mut self) {
        self.verify = None;
    }

    pub fn verify_open(&self) -> bool {
        self.verify.is_some()
    }

    fn press_verify(&mut self, key: Key) -> Action {
        let Some(pane) = self.verify.as_mut() else {
            return Action::None;
        };
        if key == Key::Enter && pane.opened.elapsed() < self.verify_delay {
            self.notice = Some(VERIFY_TOO_SOON);
            return Action::None;
        }
        match key {
            Key::Esc => self.verify = None,
            Key::Backspace => {
                pane.typed.pop();
            }
            Key::Char(c) if !c.is_control() && pane.typed.len() + c.len_utf8() <= MAX_TYPED => {
                pane.typed.push(c);
            }
            Key::Enter if !pane.typed.trim().is_empty() => {
                return Action::Confirm {
                    group: pane.group,
                    typed: pane.typed.to_string(),
                };
            }
            _ => {}
        }
        Action::None
    }

    /// Appends a received message to its conversation (bounded; oldest wiped first).
    pub fn push_message(&mut self, group: Uuid, who: String, text: Zeroizing<String>) {
        let list = self.shown.entry(group).or_default();
        if list.len() >= MAX_LINES {
            list.remove(0);
        }
        list.push(Shown { who, text });
        assert!(list.len() <= MAX_LINES);
        if self.selected_id() == Some(group) {
            return;
        }
        if let Some(row) = self.rows.iter_mut().find(|r| r.id == group) {
            row.unread = row.unread.saturating_add(1);
        }
    }

    /// Applies one key. Typing edits the input line; Up/Down switch conversation (clearing
    /// its unread count); Enter sends a non-empty line unless the conversation is CHANGED;
    /// Esc quits.
    pub fn press(&mut self, key: Key) -> Action {
        self.notice = None;
        if self.verify.is_some() {
            return self.press_verify(key);
        }
        match key {
            Key::Verify => {
                return self
                    .selected_id()
                    .map_or(Action::None, |group| Action::Verify { group });
            }
            Key::Esc => return Action::Quit,
            Key::Up => self.step(false),
            Key::Down => self.step(true),
            Key::Backspace => {
                self.input.pop();
            }
            Key::Char(c) if c.is_control() => {}
            Key::Char(c) => {
                if self.input.len() + c.len_utf8() > crate::message::MAX_BODY_LEN {
                    self.notice = Some(FULL_NOTICE);
                } else {
                    self.input.push(c);
                }
            }
            Key::Enter => return self.submit(),
        }
        Action::None
    }

    fn step(&mut self, down: bool) {
        let n = self.rows.len();
        if n == 0 {
            return;
        }
        let before = self.selected;
        self.selected = if down {
            (self.selected + 1) % n
        } else {
            (self.selected + n - 1) % n
        };
        if self.selected != before {
            // A half-typed line (or a paste) must not follow the user into another chat.
            self.input = Zeroizing::new(String::with_capacity(crate::message::MAX_BODY_LEN));
        }
        self.rows[self.selected].unread = 0;
        assert!(self.selected < n);
    }

    fn submit(&mut self) -> Action {
        let Some(row) = self.rows.get(self.selected) else {
            return Action::None;
        };
        if self.input.trim().is_empty() {
            return Action::None;
        }
        if row.mark == Mark::Changed {
            self.notice = Some(CHANGED_NOTICE);
            return Action::None;
        }
        let text = std::mem::replace(
            &mut self.input,
            Zeroizing::new(String::with_capacity(crate::message::MAX_BODY_LEN)),
        );
        Action::Send {
            group: row.id,
            text,
        }
    }
}

/// Replaces every control character with `?` and tabs with a space.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\t' => ' ',
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

fn row_label(row: &Row) -> String {
    let kind = match row.kind {
        Kind::Pair => "pair",
        Kind::Group => "group",
    };
    let mark = match row.mark {
        Mark::Changed => " CHANGED",
        Mark::Unverified => " unverified",
        Mark::Verified => "",
    };
    let unread = if row.unread > 0 {
        format!(" ({})", row.unread)
    } else {
        String::new()
    };
    format!("{} {kind}{unread}{mark}", crate::message::short_id(&row.id))
}

/// Paints the screen: conversation list on the left; messages, input line and a notice on
/// the right. Every cell comes from bounded state; wide or long text is clipped by ratatui.
pub fn draw(app: &App, area: Rect, buf: &mut Buffer) {
    let [side, main] =
        Layout::horizontal([Constraint::Length(30), Constraint::Min(10)]).areas(area);
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|r| {
            let style = if r.mark == Mark::Changed {
                Style::new().add_modifier(Modifier::BOLD | Modifier::REVERSED)
            } else {
                Style::new()
            };
            ListItem::new(Line::styled(clean(&row_label(r)), style))
        })
        .collect();
    let mut state =
        ListState::default().with_selected((!app.rows.is_empty()).then_some(app.selected));
    let list = List::new(items)
        .block(Block::new().borders(Borders::ALL).title("conversations"))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    StatefulWidget::render(list, side, buf, &mut state);

    let [msgs, input, note] = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(main);
    let lines: Vec<Line> = app
        .selected_id()
        .and_then(|id| app.shown.get(&id))
        .map(|v| {
            v.iter()
                .flat_map(|m| {
                    m.text.split('\n').enumerate().map(|(i, l)| {
                        let who = if i == 0 {
                            format!("[{}] ", clean(&m.who))
                        } else {
                            "    ".into()
                        };
                        Line::raw(format!("{who}{}", clean(l)))
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(p) = &app.verify {
        draw_verify(p, msgs, input, buf);
        Paragraph::new("Enter confirm · Esc cancel").render(note, buf);
        return;
    }
    // Show the newest lines: scroll so the tail fits.
    let inner_h = usize::from(msgs.height.saturating_sub(2));
    let skip = u16::try_from(lines.len().saturating_sub(inner_h)).unwrap_or(u16::MAX);
    Paragraph::new(lines)
        .block(Block::new().borders(Borders::ALL).title("messages"))
        .scroll((skip, 0))
        .render(msgs, buf);
    Paragraph::new(format!("> {}", clean(&app.input)))
        .block(Block::new().borders(Borders::ALL).title("message"))
        .render(input, buf);
    Paragraph::new(
        app.notice
            .unwrap_or("Esc quit · Up/Down switch · Enter send · ^V verify"),
    )
    .render(note, buf);
}

/// The verify pane replaces the message and input panes.
fn draw_verify(p: &Pane, msgs: Rect, input: Rect, buf: &mut Buffer) {
    let lines = vec![
        Line::raw("Compare this safety number with your contact over a trusted channel:"),
        Line::raw(""),
        Line::raw(clean(&p.number)),
        Line::raw(""),
        Line::raw("Then type it below to mark the conversation verified."),
    ];
    Paragraph::new(lines)
        .wrap(ratatui::widgets::Wrap { trim: false })
        .block(Block::new().borders(Borders::ALL).title("verify"))
        .render(msgs, buf);
    Paragraph::new(format!("> {}", clean(&p.typed)))
        .block(Block::new().borders(Borders::ALL).title("safety number"))
        .render(input, buf);
}

#[cfg(test)]
mod tests;
