use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::{channel, Sender};

use super::*;
use crate::testsrv::{serve, session, Backend};
use crate::{inbox, invite};

fn client() -> Client {
    crate::status::http_client().unwrap()
}

const FAST: Options = Options {
    safety_net: Duration::from_secs(30),
    fallback: Duration::from_millis(20),
    allow_changed: false,
};

struct Pair {
    _tmp: tempfile::TempDir,
    alice: Session,
    bob: Session,
    url: Url,
    gid: Uuid,
}

async fn pair() -> Pair {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let url = serve(Arc::new(Mutex::new(Backend::default()))).await;
    let (link, _) = invite::create(&client(), &url, &alice).await.unwrap();
    let link = invite::parse_link(&link).unwrap();
    let (gid, _) = invite::redeem(&client(), &url, &bob, &link).await.unwrap();
    inbox::receive(&client(), &url, &alice).await.unwrap();
    Pair {
        _tmp: tmp,
        alice,
        bob,
        url,
        gid,
    }
}

fn line(s: &str) -> Event {
    Event::Line(Zeroizing::new(format!("{s}\n")))
}

/// Runs Alice's REPL over `events` (then end of input) and returns what it printed.
async fn chat_as_alice(p: &Pair, events: Vec<Event>) -> String {
    let (tx, mut rx) = channel(64);
    for e in events {
        tx.send(e).await.unwrap();
    }
    tx.send(Event::Eof).await.unwrap();
    let mut out = Vec::new();
    run(&client(), &p.url, &p.alice, p.gid, &mut rx, &mut out, FAST)
        .await
        .unwrap();
    String::from_utf8(out).unwrap()
}

#[tokio::test]
async fn wake_fetches_shows_and_removes_peer_messages() {
    let p = pair().await;
    message::send(&client(), &p.url, &p.bob, p.gid, b"hello alice")
        .await
        .unwrap();
    let out = chat_as_alice(&p, vec![Event::Wake]).await;
    let want = format!("[{}] hello alice\n", message::short_id(&p.bob.device_id));
    assert_eq!(out.matches(&want).count(), 1, "shown exactly once: {out:?}");
    assert!(message::pending(&p.alice.store, p.gid).unwrap().is_empty());
}

#[tokio::test]
async fn the_first_sync_shows_messages_waiting_at_start() {
    let p = pair().await;
    message::send(&client(), &p.url, &p.bob, p.gid, b"early")
        .await
        .unwrap();
    let out = chat_as_alice(&p, vec![]).await;
    assert!(out.contains("] early\n"), "{out:?}");
}

#[tokio::test]
async fn typed_lines_are_sent_and_the_peer_receives_them() {
    let p = pair().await;
    chat_as_alice(&p, vec![line("hi bob"), line("   "), line("")]).await;
    let r = inbox::receive(&client(), &p.url, &p.bob).await.unwrap();
    assert_eq!(r.stored, 1, "blank lines are not sent");
    assert_eq!(
        message::pending(&p.bob.store, p.gid).unwrap()[0]
            .text
            .as_str(),
        "hi bob"
    );
}

#[tokio::test]
async fn quit_ends_the_session_before_later_lines() {
    let p = pair().await;
    chat_as_alice(&p, vec![line("one"), line(QUIT), line("never sent")]).await;
    let r = inbox::receive(&client(), &p.url, &p.bob).await.unwrap();
    assert_eq!(r.stored, 1);
}

#[tokio::test]
async fn an_unsendable_line_is_reported_without_echoing_it() {
    let p = pair().await;
    let long = "x".repeat(message::MAX_BODY_LEN + 1);
    let out = chat_as_alice(&p, vec![line(&long)]).await;
    assert!(out.contains("! not sent:"), "{out:?}");
    assert!(
        !out.contains("xxxx"),
        "the rejected text must not be echoed"
    );
    let r = inbox::receive(&client(), &p.url, &p.bob).await.unwrap();
    assert_eq!(r.stored, 0);
}

#[tokio::test]
async fn a_failed_send_does_not_end_the_session() {
    let p = pair().await;
    let (tx, mut rx) = channel(8);
    let state = Arc::new(Mutex::new(Backend::default()));
    state.lock().unwrap().fail_messages = true;
    let down = serve(state).await;
    tx.send(line("lost")).await.unwrap();
    tx.send(Event::Eof).await.unwrap();
    let mut out = Vec::new();
    run(&client(), &down, &p.alice, p.gid, &mut rx, &mut out, FAST)
        .await
        .unwrap();
    assert!(String::from_utf8(out).unwrap().contains("! not sent:"));
}

#[tokio::test]
async fn realtime_loss_is_announced_and_polling_still_delivers() {
    let p = pair().await;
    let (tx, mut rx) = channel(8);
    tx.send(Event::RealtimeLost).await.unwrap();
    let mut out = Vec::new();
    let (url, alice, gid) = (p.url.clone(), &p.alice, p.gid);
    let bob_sends = async {
        tokio::time::sleep(Duration::from_millis(60)).await;
        message::send(&client(), &p.url, &p.bob, gid, b"polled")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        tx.send(Event::Eof).await.unwrap();
    };
    let http = client();
    let chat = run(&http, &url, alice, gid, &mut rx, &mut out, FAST);
    let (res, ()) = tokio::join!(chat, bob_sends);
    res.unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("! realtime connection lost"), "{out:?}");
    assert!(out.contains("] polled\n"), "{out:?}");
}

#[tokio::test]
async fn a_closed_output_keeps_unshown_messages_in_the_store() {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let p = pair().await;
    message::send(&client(), &p.url, &p.bob, p.gid, b"keep me")
        .await
        .unwrap();
    let (_tx, mut rx) = channel(1);
    run(
        &client(),
        &p.url,
        &p.alice,
        p.gid,
        &mut rx,
        &mut Closed,
        FAST,
    )
    .await
    .unwrap();
    assert_eq!(message::pending(&p.alice.store, p.gid).unwrap().len(), 1);
}

async fn collect_lines(input: &[u8]) -> Vec<String> {
    let (tx, mut rx): (Sender<Event>, _) = channel(64);
    let input = input.to_vec();
    tokio::task::spawn_blocking(move || read_lines(std::io::Cursor::new(input), &tx))
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(e) = rx.recv().await {
        match e {
            Event::Line(l) => got.push(l.to_string()),
            Event::Eof => got.push("<eof>".into()),
            other => panic!("unexpected {other:?}"),
        }
    }
    got
}

#[tokio::test]
async fn read_lines_forwards_lines_then_eof() {
    assert_eq!(
        collect_lines(b"a\nb\r\nlast").await,
        ["a\n", "b\r\n", "last", "<eof>"]
    );
}

#[tokio::test]
async fn read_lines_flags_an_oversize_line_and_keeps_going() {
    let mut input = vec![b'y'; message::MAX_BODY_LEN * 3];
    input.extend_from_slice(b"\nafter\n");
    let got = collect_lines(&input).await;
    assert_eq!(got.len(), 3, "{}", got.len());
    assert!(got[0].len() > message::MAX_BODY_LEN);
    assert_eq!((got[1].as_str(), got[2].as_str()), ("after\n", "<eof>"));
}

#[tokio::test]
async fn read_lines_cap_boundaries() {
    let cap = message::MAX_BODY_LEN;
    // A body of exactly the cap plus its newline is forwarded verbatim.
    let mut exact = vec![b'e'; cap];
    exact.push(b'\n');
    let got = collect_lines(&exact).await;
    assert_eq!((got[0].len(), got[1].as_str()), (cap + 1, "<eof>"));
    assert_eq!(got.len(), 2);

    // One byte over the cap is flagged as too long, and the next line still arrives.
    for over in [cap + 1, cap + 2, cap + 3, cap + 4] {
        let mut input = vec![b'o'; over];
        input.extend_from_slice(b"\nnext\n");
        let got = collect_lines(&input).await;
        assert!(got[0].len() > cap, "over={over}");
        assert_eq!(&got[1..], ["next\n", "<eof>"], "over={over}");
    }
}

#[tokio::test]
async fn read_lines_oversize_without_newline_ends_cleanly() {
    let input = vec![b'u'; message::MAX_BODY_LEN * 2];
    let got = collect_lines(&input).await;
    assert_eq!(got.len(), 2);
    assert!(got[0].len() > message::MAX_BODY_LEN);
    assert_eq!(got[1], "<eof>");
}

#[tokio::test]
async fn changed_alert_is_printed_once_and_rearmed_after_it_clears() {
    let p = pair().await;
    let mut out = Vec::new();
    let mut alerted = false;
    alert_if_changed(&p.alice, p.gid, &mut alerted, &mut out).unwrap();
    assert!(out.is_empty(), "no confirmation record: silent");
    let n = verify::number(&p.alice.store, p.gid).unwrap();
    verify::confirm(&p.alice.store, p.gid, &n, &n).unwrap();
    alert_if_changed(&p.alice, p.gid, &mut alerted, &mut out).unwrap();
    assert!(out.is_empty(), "matching record: silent");
    p.alice
        .store
        .put(&format!("verified-{}", p.gid.hyphenated()), b"x")
        .unwrap();
    alert_if_changed(&p.alice, p.gid, &mut alerted, &mut out).unwrap();
    alert_if_changed(&p.alice, p.gid, &mut alerted, &mut out).unwrap();
    let text = String::from_utf8(out.clone()).unwrap();
    assert_eq!(text.matches("CHANGED").count(), 1, "{text:?}");
    verify::confirm(&p.alice.store, p.gid, &n, &n).unwrap();
    alert_if_changed(&p.alice, p.gid, &mut alerted, &mut out).unwrap();
    assert!(!alerted);
}

#[tokio::test]
async fn unverified_notice_is_printed_until_the_number_is_confirmed() {
    let p = pair().await;
    let text = chat_as_alice(&p, vec![]).await;
    assert!(text.contains(verify::UNVERIFIED_WARNING), "{text:?}");
    let n = verify::number(&p.alice.store, p.gid).unwrap();
    verify::confirm(&p.alice.store, p.gid, &n, &n).unwrap();
    let text = chat_as_alice(&p, vec![]).await;
    assert!(!text.contains("unverified"), "{text:?}");
}

#[tokio::test]
async fn changed_conversation_line_is_not_sent_without_allow_changed() {
    let p = pair().await;
    p.alice
        .store
        .put(&format!("verified-{}", p.gid.hyphenated()), b"x")
        .unwrap();
    let mut blocked = Vec::new();
    send_line(
        &client(),
        &p.url,
        &p.alice,
        p.gid,
        "hi",
        false,
        &mut blocked,
    )
    .await
    .unwrap();
    let text = String::from_utf8(blocked).unwrap();
    assert!(
        text.contains("! not sent:") && text.contains("--allow-changed"),
        "{text:?}"
    );
    let mut allowed = Vec::new();
    send_line(&client(), &p.url, &p.alice, p.gid, "hi", true, &mut allowed)
        .await
        .unwrap();
    assert!(allowed.is_empty(), "{allowed:?}");
}
