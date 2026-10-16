use std::sync::{Arc, Mutex};

use super::*;
use crate::inbox;
use crate::invite;
use crate::testsrv::{serve, session, Backend};

fn client() -> Client {
    crate::status::http_client().unwrap()
}

/// Alice invites, Bob redeems, Alice receives the Welcome and pq_init.
async fn pair() -> (tempfile::TempDir, Session, Session, Url, Uuid) {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state).await;
    let (link, _) = invite::create(&client(), &url, &alice).await.unwrap();
    let link = invite::parse_link(&link).unwrap();
    let (gid, _) = invite::redeem(&client(), &url, &bob, &link).await.unwrap();
    inbox::receive(&client(), &url, &alice).await.unwrap();
    (tmp, alice, bob, url, gid)
}

#[tokio::test]
async fn send_then_inbox_then_read_round_trips_both_ways() {
    let (_tmp, alice, bob, url, gid) = pair().await;
    send(&client(), &url, &bob, gid, b"hi alice").await.unwrap();
    let r = inbox::receive(&client(), &url, &alice).await.unwrap();
    assert_eq!(r.stored, 1);
    let got = pending(&alice.store, gid).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].text.as_str(), got[0].sender),
        ("hi alice", bob.device_id)
    );
    send(&client(), &url, &alice, gid, b"hi bob").await.unwrap();
    inbox::receive(&client(), &url, &bob).await.unwrap();
    assert_eq!(pending(&bob.store, gid).unwrap()[0].text.as_str(), "hi bob");
    discard(&alice.store, &got[0]).unwrap();
    assert!(pending(&alice.store, gid).unwrap().is_empty());
}

#[tokio::test]
async fn unread_counts_track_stored_messages_per_conversation() {
    let (_tmp, alice, bob, url, gid) = pair().await;
    assert!(unread_counts(&alice.store).unwrap().is_empty());
    for t in ["a", "b"] {
        send(&client(), &url, &bob, gid, t.as_bytes())
            .await
            .unwrap();
    }
    inbox::receive(&client(), &url, &alice).await.unwrap();
    assert_eq!(unread_counts(&alice.store).unwrap().get(&gid), Some(&2));
    for m in pending(&alice.store, gid).unwrap() {
        discard(&alice.store, &m).unwrap();
    }
    assert!(unread_counts(&alice.store).unwrap().is_empty());
}

#[tokio::test]
async fn messages_come_back_in_receive_order() {
    let (_tmp, alice, bob, url, gid) = pair().await;
    for t in ["one", "two", "three"] {
        send(&client(), &url, &bob, gid, t.as_bytes())
            .await
            .unwrap();
    }
    inbox::receive(&client(), &url, &alice).await.unwrap();
    let texts: Vec<String> = pending(&alice.store, gid)
        .unwrap()
        .into_iter()
        .map(|m| m.text.as_str().to_owned())
        .collect();
    assert_eq!(texts, ["one", "two", "three"]);
}

#[tokio::test]
async fn send_to_unknown_conversation_fails_without_calls() {
    let (_tmp, _alice, bob, url, _gid) = pair().await;
    let r = send(&client(), &url, &bob, Uuid::new_v4(), b"x").await;
    assert!(matches!(r, Err(MessageError::NoSuchConversation)));
}

#[tokio::test]
async fn resolve_accepts_full_id_and_unique_prefix_only() {
    let (_tmp, alice, _bob, _url, gid) = pair().await;
    let full = gid.hyphenated().to_string();
    assert_eq!(resolve(&alice.store, &full).unwrap(), gid);
    assert_eq!(
        resolve(&alice.store, &full[..8].to_uppercase()).unwrap(),
        gid
    );
    assert!(matches!(
        resolve(&alice.store, "zzzz"),
        Err(MessageError::NoSuchConversation)
    ));
    assert!(matches!(
        resolve(&alice.store, &full[..3]),
        Err(MessageError::NoSuchConversation)
    ));
}

#[test]
fn body_checks() {
    assert_eq!(check_body(b"hello\n").unwrap(), b"hello");
    assert_eq!(check_body(b"a\nb\r\n").unwrap(), b"a\nb");
    assert_eq!(check_body(b"hi\n\n").unwrap(), b"hi\n");
    assert!(matches!(check_body(b""), Err(MessageError::EmptyBody)));
    assert!(matches!(check_body(b" \n\n"), Err(MessageError::EmptyBody)));
    assert!(matches!(
        check_body(&[0xff, 0xfe]),
        Err(MessageError::NotText)
    ));
    let big = vec![b'a'; MAX_BODY_LEN + 1];
    assert!(matches!(check_body(&big), Err(MessageError::TooLong)));
    assert!(check_body(&big[..MAX_BODY_LEN]).is_ok());
}

#[test]
fn render_neutralises_terminal_escapes_and_hides_structured_payloads() {
    assert_eq!(
        render(b"\x1b[2Jhi\x07\nok\t!").as_str(),
        "\u{fffd}[2Jhi\u{fffd}\nok\t!"
    );
    assert_eq!(
        render("\u{9b}31m".as_bytes()).as_str(),
        "\u{fffd}31m",
        "C1 CSI"
    );
    assert_eq!(
        render(br#"{"type":"image","blobId":"x"}"#).as_str(),
        "[image]"
    );
    assert_eq!(
        render(br#"{"type":"reaction"}"#).as_str(),
        "[unsupported message]"
    );
    assert_eq!(render(br#"{"not":"typed"}"#).as_str(), r#"{"not":"typed"}"#);
    assert_eq!(
        render("a\u{202e}b\u{200b}c\u{2066}".as_bytes()).as_str(),
        "a\u{fffd}b\u{fffd}c\u{fffd}"
    );
    assert_eq!(
        render("a\u{e0041}b\u{2028}c\u{fe0f}".as_bytes()).as_str(),
        "a\u{fffd}b\u{fffd}c\u{fffd}"
    );
    assert_eq!(
        render(br#"{"type":"text","text":"hey\u001b[0m","ttl":5}"#).as_str(),
        "hey\u{fffd}[0m"
    );
    assert_eq!(
        render(br#"{"type":"text","text":3}"#).as_str(),
        "[unsupported message]"
    );
    assert_eq!(render(&[0xff]).as_str(), "\u{fffd}");
    // Arrays are not structured payloads (web client shows them raw).
    for raw in [r#"["text","hello"]"#, r#"["image"]"#] {
        assert_eq!(render(raw.as_bytes()).as_str(), raw);
    }
    // Duplicate keys: last wins, as in JSON.parse.
    assert_eq!(
        render(br#"{"type":"text","text":"a","text":"b"}"#).as_str(),
        "b"
    );
    assert_eq!(
        render(br#"{"type":"text","type":"image"}"#).as_str(),
        "[image]"
    );
    // Escaped multi-line text and CRLF / invalid UTF-8 mixes.
    assert_eq!(
        render(br#"{"type":"text","text":"a\nb \"q\" \\"}"#).as_str(),
        "a\nb \"q\" \\"
    );
    assert_eq!(
        render(b"x\r\n\xff\x1b").as_str(),
        "x\u{fffd}\n\u{fffd}\u{fffd}"
    );
    assert_eq!(
        render(br#"{"type":"image","x":[1,{"a":null}],"n":1.5}"#).as_str(),
        "[image]"
    );
}
