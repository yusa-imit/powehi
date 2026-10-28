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
