use super::*;

fn row(mark: Mark) -> Row {
    Row {
        id: Uuid::new_v4(),
        kind: Kind::Pair,
        unread: 0,
        mark,
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn type_str(app: &mut App, s: &str) {
    for c in s.chars() {
        assert!(matches!(app.press(Key::Char(c)), Action::None));
    }
}

fn screen(app: &App, w: u16, h: u16) -> String {
    let area = Rect::new(0, 0, w, h);
    let mut buf = Buffer::empty(area);
    draw(app, area, &mut buf);
    (0..h)
        .map(|y| {
            (0..w)
                .map(|x| buf[(x, y)].symbol().to_owned())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn enter_sends_the_line_and_clears_the_input() {
    let r = row(Mark::Verified);
    let id = r.id;
    let mut app = App::new(vec![r]);
    type_str(&mut app, "hi there");
    match app.press(Key::Enter) {
        Action::Send { group, text } => {
            assert_eq!(group, id);
            assert_eq!(text.as_str(), "hi there");
        }
        other => panic!("expected Send, got {other:?}"),
    }
    assert_eq!(app.input_len(), 0);
}

#[test]
fn empty_or_blank_line_is_not_sent() {
    let mut app = App::new(vec![row(Mark::Verified)]);
    assert!(matches!(app.press(Key::Enter), Action::None));
    type_str(&mut app, "   ");
    assert!(matches!(app.press(Key::Enter), Action::None));
}

#[test]
fn changed_conversation_refuses_send_and_keeps_the_input() {
    let mut app = App::new(vec![row(Mark::Changed)]);
    type_str(&mut app, "x");
    assert!(matches!(app.press(Key::Enter), Action::None));
    assert_eq!(app.notice(), Some(CHANGED_NOTICE));
    assert_eq!(app.input_len(), 1);
    assert!(screen(&app, 80, 12).contains("CHANGED"));
}

#[test]
fn input_is_capped_and_control_keys_are_ignored() {
    let mut app = App::new(vec![row(Mark::Verified)]);
    app.press(Key::Char('\x1b'));
    assert_eq!(app.input_len(), 0);
    for _ in 0..crate::message::MAX_BODY_LEN + 10 {
        app.press(Key::Char('a'));
    }
    assert_eq!(app.input_len(), crate::message::MAX_BODY_LEN);
    assert_eq!(app.notice(), Some(FULL_NOTICE));
    app.press(Key::Backspace);
    assert_eq!(app.input_len(), crate::message::MAX_BODY_LEN - 1);
}

#[test]
fn navigation_wraps_and_clears_unread() {
    let (a, b) = (row(Mark::Verified), row(Mark::Verified));
    let (ida, idb) = (a.id, b.id);
    let mut app = App::new(vec![a, b]);
    app.push_message(idb, "peer".into(), z("hello"));
    assert!(screen(&app, 80, 12).contains("(1)"));
    app.press(Key::Down);
    assert_eq!(app.selected_id(), Some(idb));
    assert!(!screen(&app, 80, 12).contains("(1)"));
    app.press(Key::Down);
    assert_eq!(app.selected_id(), Some(ida));
    app.press(Key::Up);
    assert_eq!(app.selected_id(), Some(idb));
}

#[test]
fn messages_render_with_continuation_indent_and_no_control_chars() {
    let r = row(Mark::Unverified);
    let id = r.id;
    let mut app = App::new(vec![r]);
    app.push_message(id, "peer".into(), z("one\ntwo\x1b[2J"));
    let s = screen(&app, 80, 12);
    assert!(s.contains("[peer] one"));
    assert!(s.contains("unverified"));
    assert!(s.contains("two?[2J"));
    assert!(!s.contains('\x1b'));
}

#[test]
fn history_is_bounded_and_shows_the_newest() {
    let r = row(Mark::Verified);
    let id = r.id;
    let mut app = App::new(vec![r]);
    for i in 0..MAX_LINES + 20 {
        app.push_message(id, "p".into(), z(&format!("m{i}")));
    }
    assert_eq!(app.shown[&id].len(), MAX_LINES);
    let s = screen(&app, 80, 12);
    assert!(s.contains(&format!("m{}", MAX_LINES + 19)));
    assert!(!s.contains("m0 "));
}

#[test]
fn set_rows_keeps_selection_and_esc_quits() {
    let (a, b) = (row(Mark::Verified), row(Mark::Verified));
    let idb = b.id;
    let mut app = App::new(vec![a.clone(), b.clone()]);
    app.press(Key::Down);
    app.set_rows(vec![row(Mark::Verified), b, a]);
    assert_eq!(app.selected_id(), Some(idb));
    assert!(matches!(app.press(Key::Esc), Action::Quit));
}

#[test]
fn debug_of_send_action_hides_the_text() {
    let a = Action::Send {
        group: Uuid::nil(),
        text: z("secret-body"),
    };
    assert!(!format!("{a:?}").contains("secret"));
}

#[test]
fn tiny_and_empty_screens_do_not_panic() {
    let app = App::new(Vec::new());
    for (w, h) in [(0, 0), (1, 1), (5, 3), (40, 4)] {
        let _ = screen(&app, w, h);
    }
}

mod terminal {
    use super::super::input::Decoder;
    use super::super::paint::paint;
    use super::*;

    fn keys(chunks: &[&[u8]]) -> Vec<Key> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        for c in chunks {
            d.feed(c, &mut out);
        }
        out
    }

    #[test]
    fn arrows_enter_backspace_and_text() {
        let k = keys(&[b"hi\x1b[A\x1b[B\x1bOA\r\x7f"]);
        assert_eq!(
            k,
            [
                Key::Char('h'),
                Key::Char('i'),
                Key::Up,
                Key::Down,
                Key::Up,
                Key::Enter,
                Key::Backspace
            ]
        );
    }

    #[test]
    fn sequences_split_across_reads_and_utf8_are_joined() {
        assert_eq!(keys(&[b"\x1b", b"[", b"B"]), [Key::Down]);
        assert_eq!(
            keys(&[&"한".as_bytes()[..1], &"한".as_bytes()[1..]]),
            [Key::Char('한')]
        );
    }

    #[test]
    fn unknown_sequences_type_nothing() {
        // Delete (ESC [ 3 ~), F5 (ESC [ 1 5 ~), Alt-x, then a real key.
        assert_eq!(keys(&[b"\x1b[3~\x1b[15~\x1bxa"]), [Key::Char('a')]);
        assert!(keys(&[b"\x00\x01\x1f"]).is_empty());
    }

    #[test]
    fn ctrl_c_quits_and_lone_escape_needs_finish() {
        assert_eq!(keys(&[b"\x03"]), [Key::Esc]);
        let mut d = Decoder::new();
        let mut out = Vec::new();
        d.feed(b"\x1b", &mut out);
        assert!(out.is_empty());
        assert_eq!(d.finish(), Some(Key::Esc));
        assert_eq!(d.finish(), None);
    }

    #[test]
    fn overlong_sequence_is_dropped_not_buffered() {
        let mut long = vec![0x1b, b'['];
        long.extend(std::iter::repeat_n(b'1', 100));
        long.push(b'~');
        long.push(b'z');
        assert_eq!(keys(&[&long]), [Key::Char('z')]);
    }

    #[test]
    fn paint_has_no_stray_control_bytes() {
        let mut app = App::new(vec![row(Mark::Changed), row(Mark::Verified)]);
        app.push_message(
            app.selected_id().unwrap(),
            "a\x1b[2J".into(),
            z("x\x07y\x1b]0;t\x07"),
        );
        let area = Rect::new(0, 0, 60, 12);
        let mut buf = Buffer::empty(area);
        draw(&app, area, &mut buf);
        let bytes = paint(&buf);
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0x1b {
                // Only "ESC [ <digits;> m|H" may appear.
                assert_eq!(bytes[i + 1], b'[');
                let end = bytes[i + 2..]
                    .iter()
                    .position(|b| b.is_ascii_alphabetic())
                    .unwrap();
                assert!(matches!(bytes[i + 2 + end], b'm' | b'H'));
                assert!(bytes[i + 2..i + 2 + end]
                    .iter()
                    .all(|b| b.is_ascii_digit() || *b == b';'));
                i += 3 + end;
            } else {
                assert!(bytes[i] >= 0x20, "raw control byte {:#x}", bytes[i]);
                i += 1;
            }
        }
        assert!(
            bytes.windows(3).any(|w| w == b"\x1b[7"),
            "reverse attribute used"
        );
    }

    #[test]
    fn wide_glyph_does_not_shift_the_line() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 4, 1));
        buf.set_string(0, 0, "한a", Style::new());
        let text = String::from_utf8(paint(&buf)).unwrap();
        assert!(text.contains("한a "), "{text:?}");
    }
}

mod terminal_more {
    use super::super::input::Decoder;
    use super::super::paint::paint;
    use super::*;

    fn keys(b: &[u8]) -> Vec<Key> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        d.feed(b, &mut out);
        out
    }

    #[test]
    fn string_sequences_and_broken_utf8_type_nothing_and_keep_next_key() {
        assert_eq!(keys(b"\x1b]11;rgb:0000/0000/0000\x07a"), [Key::Char('a')]);
        assert_eq!(keys(b"\x1bP1+r544e\x1b\\b"), [Key::Char('b')]);
        assert_eq!(keys(b"\xe3\x1b[A"), [Key::Up]);
        assert_eq!(keys(b"\xe3\r"), [Key::Enter]);
        assert_eq!(keys(b"\x1b[3\x1b[A"), [Key::Up]);
        assert_eq!(keys(b"\x1b[1;5Ac"), [Key::Char('c')]);
    }

    #[test]
    fn hangul_with_0x9b_byte_paints_without_panic() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 6, 1));
        buf.set_string(0, 0, "회원Û", Style::new());
        assert!(String::from_utf8(paint(&buf)).unwrap().contains("회원Û"));
    }
}
