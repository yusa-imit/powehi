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
async fn changed_conversation_refuses_send_unless_allowed() {
    let (_tmp, alice, bob, url, gid) = pair().await;
    // A record that does not match the recomputed number is the CHANGED state (§5.6).
    bob.store
        .put(&format!("verified-{}", gid.hyphenated()), b"x")
        .unwrap();
    let r = send(&client(), &url, &bob, gid, b"blocked").await;
    assert!(matches!(r, Err(MessageError::Changed)), "{r:?}");
    let got = inbox::receive(&client(), &url, &alice).await.unwrap();
    assert_eq!(got.stored, 0, "nothing reached the server");
    let sent = conversation::load(&bob.store, &gid)
        .unwrap()
        .unwrap()
        .sent_since_update();
    assert_eq!(sent, 0, "no key was spent");
    send_with(&client(), &url, &bob, gid, b"override", true)
        .await
        .unwrap();
    assert_eq!(
        inbox::receive(&client(), &url, &alice)
            .await
            .unwrap()
            .stored,
        1
    );
}

#[tokio::test]
async fn verified_pair_that_grew_is_changed_and_refuses_send() {
    let (_tmp, _alice, bob, url, gid) = pair().await;
    let n = crate::verify::number(&bob.store, gid).unwrap();
    crate::verify::confirm(&bob.store, gid, &n, &n).unwrap();
    assert!(!crate::verify::changed_since_verified(&bob.store, gid));
    // A third member joins the MLS group behind the pair record's back (8.17 fail-closed).
    let mut local = LocalIdentity::load(&bob.store).unwrap();
    let mut group = mls_group::load_group(gid.as_bytes(), &local.provider)
        .unwrap()
        .unwrap();
    let carol = mls_group::generate_identity(b"carol", &local.provider).unwrap();
    let kp = mls_group::generate_key_package(&carol, &local.provider).unwrap();
    mls_group::add_member(
        &mut group,
        &local.identity.signer,
        kp.key_package().clone(),
        &local.provider,
    )
    .unwrap();
    local.save(&bob.store).unwrap();
    assert!(crate::verify::changed_since_verified(&bob.store, gid));
    let r = send(&client(), &url, &bob, gid, b"blocked").await;
    assert!(matches!(r, Err(MessageError::Changed)), "{r:?}");
    let sent = conversation::load(&bob.store, &gid)
        .unwrap()
        .unwrap()
        .sent_since_update();
    assert_eq!(sent, 0, "no key was spent");
}

#[tokio::test]
async fn well_formed_record_with_another_number_refuses_send() {
    let (_tmp, alice, bob, url, gid) = pair().await;
    let other = powehi_crypto_core::safety::pairwise(&[1u8; 32], &[2u8; 32]).unwrap();
    let rec = serde_json::json!({"version": 1, "number": other});
    bob.store
        .put(
            &format!("verified-{}", gid.hyphenated()),
            rec.to_string().as_bytes(),
        )
        .unwrap();
    let r = send(&client(), &url, &bob, gid, b"blocked").await;
    assert!(matches!(r, Err(MessageError::Changed)), "{r:?}");
    assert_eq!(
        inbox::receive(&client(), &url, &alice)
            .await
            .unwrap()
            .stored,
        0
    );
}

#[tokio::test]
async fn verified_or_unverified_conversation_still_sends() {
    let (_tmp, _alice, bob, url, gid) = pair().await;
    send(&client(), &url, &bob, gid, b"unverified is only a warning")
        .await
        .unwrap();
    let n = crate::verify::number(&bob.store, gid).unwrap();
    crate::verify::confirm(&bob.store, gid, &n, &n).unwrap();
    send(&client(), &url, &bob, gid, b"verified").await.unwrap();
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

#[tokio::test]
async fn show_removes_shown_messages_unless_keep() {
    let (_tmp, alice, bob, url, gid) = pair().await;
    for t in ["one", "two"] {
        send(&client(), &url, &bob, gid, t.as_bytes())
            .await
            .unwrap();
    }
    inbox::receive(&client(), &url, &alice).await.unwrap();
    let msgs = pending(&alice.store, gid).unwrap();
    let mut out = Vec::new();
    show(&alice.store, &msgs, true, false, &mut out).unwrap();
    assert_eq!(pending(&alice.store, gid).unwrap().len(), 2);
    assert!(String::from_utf8(out).unwrap().contains("one"));
    show(&alice.store, &msgs, false, false, &mut Vec::new()).unwrap();
    assert!(pending(&alice.store, gid).unwrap().is_empty());
}

#[tokio::test]
async fn show_to_closed_output_keeps_unseen_messages() {
    struct Closed;
    impl std::io::Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_tmp, alice, bob, url, gid) = pair().await;
    send(&client(), &url, &bob, gid, b"x").await.unwrap();
    inbox::receive(&client(), &url, &alice).await.unwrap();
    let msgs = pending(&alice.store, gid).unwrap();
    assert!(matches!(
        show(&alice.store, &msgs, false, false, &mut Closed),
        Err(ShowError::Output)
    ));
    assert_eq!(pending(&alice.store, gid).unwrap().len(), 1);
}

#[tokio::test]
async fn newest_limits_to_last_messages_and_leaves_older_stored() {
    let (_tmp, alice, bob, url, gid) = pair().await;
    for t in ["one", "two", "three"] {
        send(&client(), &url, &bob, gid, t.as_bytes())
            .await
            .unwrap();
    }
    inbox::receive(&client(), &url, &alice).await.unwrap();
    let msgs = pending(&alice.store, gid).unwrap();
    assert_eq!(newest(&msgs, None).len(), 3);
    assert_eq!(newest(&msgs, Some(10)).len(), 3);
    let tail = newest(&msgs, Some(2));
    assert_eq!(tail.len(), 2);
    let mut out = Vec::new();
    show(&alice.store, tail, false, false, &mut out).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(!out.contains("one") && out.contains("two") && out.contains("three"));
    let left = pending(&alice.store, gid).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].text.as_str(), "one");
}

#[tokio::test]
async fn show_json_emits_parseable_lines_and_discards_unless_kept() {
    let (_tmp, alice, bob, url, gid) = pair().await;
    let body = "q\"uote \\ back\nline\ttab é";
    send(&client(), &url, &bob, gid, body.as_bytes())
        .await
        .unwrap();
    inbox::receive(&client(), &url, &alice).await.unwrap();
    let msgs = pending(&alice.store, gid).unwrap();
    let mut out = Vec::new();
    show(&alice.store, &msgs, true, true, &mut out).unwrap();
    assert_eq!(pending(&alice.store, gid).unwrap().len(), 1);
    let out = String::from_utf8(out).unwrap();
    assert_eq!(out.lines().count(), 1);
    let v: serde_json::Value = serde_json::from_str(out.trim_end()).unwrap();
    assert_eq!(v["text"], body);
    assert_eq!(v["sender"], bob.device_id.to_string());
    assert!(v["received_at"].is_u64());
    show(&alice.store, &msgs, false, true, &mut Vec::new()).unwrap();
    assert!(pending(&alice.store, gid).unwrap().is_empty());
}

#[test]
fn write_sent_text_and_json() {
    let id = Uuid::from_u128(7);
    let mut t = Vec::new();
    write_sent(id, false, &mut t).unwrap();
    assert_eq!(
        String::from_utf8(t).unwrap(),
        format!("sent to conversation {id}\n")
    );
    let mut j = Vec::new();
    write_sent(id, true, &mut j).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&j).unwrap();
    assert_eq!(v, serde_json::json!({ "conversation": id.to_string() }));
    assert_eq!(j.iter().filter(|&&b| b == b'\n').count(), 1);
}

fn pending_at(received_at: u64) -> Pending {
    Pending {
        name: format!("rx-{received_at}"),
        sender: Uuid::from_u128(1),
        text: Zeroizing::new(String::new()),
        received_at,
    }
}

#[test]
fn since_keeps_messages_received_at_or_after_the_cutoff() {
    let msgs: Vec<Pending> = [10, 20, 20, 30].into_iter().map(pending_at).collect();
    assert_eq!(since(&msgs, None).len(), 4);
    assert_eq!(since(&msgs, Some(0)).len(), 4);
    assert_eq!(since(&msgs, Some(20)).len(), 3);
    assert_eq!(since(&msgs, Some(21)).len(), 1);
    assert!(since(&msgs, Some(31)).is_empty());
    assert!(since(&[], Some(5)).is_empty());
    // Composes with `newest`: the cutoff first, then the tail of what is left.
    assert_eq!(newest(since(&msgs, Some(20)), Some(2))[0].received_at, 20);
    assert_eq!(newest(since(&msgs, Some(21)), Some(2)).len(), 1);
}

#[test]
fn until_keeps_messages_received_before_the_cutoff() {
    let msgs: Vec<Pending> = [10, 20, 20, 30].into_iter().map(pending_at).collect();
    assert_eq!(until(&msgs, None).len(), 4);
    assert!(until(&msgs, Some(10)).is_empty());
    assert_eq!(until(&msgs, Some(11)).len(), 1);
    assert_eq!(until(&msgs, Some(21)).len(), 3);
    assert_eq!(until(&msgs, Some(31)).len(), 4);
    assert!(until(&[], Some(5)).is_empty());
    // Composes with `since`: a half-open window [20, 30).
    assert_eq!(since(until(&msgs, Some(30)), Some(20)).len(), 2);
}
