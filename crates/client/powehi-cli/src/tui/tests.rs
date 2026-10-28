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
