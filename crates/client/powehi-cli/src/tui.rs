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
}

impl std::fmt::Debug for Action {
    /// Variant names only: `text` is message plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Action::None => "None",
            Action::Quit => "Quit",
            Action::Send { .. } => "Send",
        })
    }
}

/// One shown message: a short sender label and its text.
struct Shown {
    who: String,
    text: Zeroizing<String>,
}

/// Screen state.
pub struct App {
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
            rows,
            selected: 0,
            input: Zeroizing::new(String::new()),
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

    /// Replaces the list (keeping the selection on the same conversation when it survives).
    pub fn set_rows(&mut self, mut rows: Vec<Row>) {
        rows.truncate(MAX_ROWS);
        let keep = self.selected_id();
        self.selected = keep
            .and_then(|id| rows.iter().position(|r| r.id == id))
            .unwrap_or(0);
        self.rows = rows;
        assert!(self.rows.is_empty() || self.selected < self.rows.len());
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
        match key {
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
        self.selected = if down {
            (self.selected + 1) % n
        } else {
            (self.selected + n - 1) % n
        };
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
        let text = std::mem::replace(&mut self.input, Zeroizing::new(String::new()));
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
            .unwrap_or("Esc quit · Up/Down switch · Enter send"),
    )
    .render(note, buf);
}

#[cfg(test)]
mod tests;
