//! A ratatui [`Buffer`] as ANSI bytes (8.20 slice b). Only cursor moves and bold/reverse
//! attributes are emitted, so no cell content can start a terminal command: control
//! characters in a symbol become a space.

use ratatui::buffer::Buffer;
use ratatui::style::Modifier;
use ratatui::text::Span;

/// Bytes that repaint the whole of `buf` from the top-left corner.
pub fn paint(buf: &Buffer) -> Vec<u8> {
    let area = buf.area;
    let mut out = Vec::with_capacity(usize::from(area.width) * usize::from(area.height) + 64);
    out.extend_from_slice(b"\x1b[0m");
    for y in 0..area.height {
        out.extend_from_slice(format!("\x1b[{};1H", y + 1).as_bytes());
        let mut attrs = Modifier::empty();
        let mut covered_to = 0u16;
        for x in 0..area.width {
            if x < covered_to {
                continue; // under the right half of a wide glyph
            }
            let cell = &buf[(area.x + x, area.y + y)];
            let want = cell.modifier & (Modifier::BOLD | Modifier::REVERSED);
            if want != attrs {
                out.extend_from_slice(b"\x1b[0m");
                if want.contains(Modifier::BOLD) {
                    out.extend_from_slice(b"\x1b[1m");
                }
                if want.contains(Modifier::REVERSED) {
                    out.extend_from_slice(b"\x1b[7m");
                }
                attrs = want;
            }
            let sym = cell.symbol();
            if sym.is_empty() || sym.chars().any(char::is_control) {
                out.push(b' ');
                continue;
            }
            let width = Span::raw(sym).width().max(1);
            covered_to = x.saturating_add(u16::try_from(width).unwrap_or(1));
            out.extend_from_slice(sym.as_bytes());
        }
        out.extend_from_slice(b"\x1b[0m");
    }
    debug_assert!(!out.contains(&0x07));
    out
}

#[cfg(test)]
mod tests {
    use ratatui::layout::Rect;
    use ratatui::style::Style;

    use super::*;

    fn painted(buf: &Buffer) -> String {
        String::from_utf8(paint(buf)).unwrap()
    }

    #[test]
    fn control_characters_in_a_symbol_become_a_space() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        buf[(0, 0)].set_symbol("\x1b");
        buf[(1, 0)].set_symbol("\x07");
        buf[(2, 0)].set_symbol("a");
        let s = painted(&buf);
        assert!(!s.contains('\x07'));
        assert_eq!(s, "\x1b[0m\x1b[1;1H  a\x1b[0m");
    }

    #[test]
    fn wide_glyph_covers_the_cell_to_its_right() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        buf[(0, 0)].set_symbol("한");
        buf[(2, 0)].set_symbol("b");
        assert_eq!(painted(&buf), "\x1b[0m\x1b[1;1H한b\x1b[0m");
    }

    #[test]
    fn bold_and_reverse_open_and_close_around_the_styled_cell() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        buf[(0, 0)].set_symbol("a");
        buf[(1, 0)].set_symbol("b").set_style(
            Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED | Modifier::DIM),
        );
        buf[(2, 0)].set_symbol("c");
        assert_eq!(
            painted(&buf),
            "\x1b[0m\x1b[1;1Ha\x1b[0m\x1b[1m\x1b[7mb\x1b[0mc\x1b[0m"
        );
    }

    #[test]
    fn rows_are_addressed_one_based_and_attrs_reset_per_row() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 1, 2));
        buf[(0, 0)]
            .set_symbol("x")
            .set_style(Style::default().add_modifier(Modifier::BOLD));
        buf[(0, 1)].set_symbol("y");
        assert_eq!(
            painted(&buf),
            "\x1b[0m\x1b[1;1H\x1b[0m\x1b[1mx\x1b[0m\x1b[2;1Hy\x1b[0m"
        );
    }
}
