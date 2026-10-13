use std::sync::{Arc, Mutex};

use futures_util::SinkExt as _;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{channel, Receiver};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

use super::*;

const TICK: Duration = Duration::from_millis(1);

fn bearer() -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new("Bearer tok".into())
}

/// Accepts connections forever; each sends `frames` and then, if `close`, drops. The
/// `Authorization` header of every upgrade is recorded.
async fn server(frames: Vec<String>, close: bool) -> (Url, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let (frames, seen) = (frames.clone(), seen2.clone());
            tokio::spawn(async move {
                #[allow(clippy::result_large_err)] // callback signature fixed by tungstenite
                let cb = |req: &Request, resp: Response| {
                    let h = req.headers().get("authorization");
                    seen.lock()
                        .unwrap()
                        .push(h.and_then(|v| v.to_str().ok()).unwrap_or("").to_owned());
                    Ok(resp)
                };
                let mut ws = tokio_tungstenite::accept_hdr_async(sock, cb).await.unwrap();
                for f in frames {
                    ws.send(Message::Text(f)).await.unwrap();
                }
                if close {
                    drop(ws);
                } else {
                    std::future::pending::<()>().await;
                }
            });
        }
    });
    (url, seen)
}

async fn next(rx: &mut Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[test]
fn ws_url_maps_schemes_and_rejects_others() {
    let u = |s: &str| ws_url(&Url::parse(s).unwrap()).map(String::from);
    assert_eq!(
        u("https://h.example:8443/x").as_deref(),
        Some("wss://h.example:8443/v1/ws")
    );
    assert_eq!(
        u("http://127.0.0.1:1").as_deref(),
        Some("ws://127.0.0.1:1/v1/ws")
    );
    assert_eq!(u("ftp://h.example"), None);
}

#[test]
fn only_notifications_for_our_group_wake() {
    let g = Uuid::new_v4();
    let note = |gid: &str| format!(r#"{{"type":"envelope_received","group_id":"{gid}"}}"#);
    assert!(is_wake_for(&note(&g.to_string()), g));
    assert!(!is_wake_for(&note(&Uuid::new_v4().to_string()), g));
    assert!(!is_wake_for("not json", g));
    assert!(!is_wake_for(r#"{"type":"x"}"#, g));
    assert!(!is_wake_for(r#"{"group_id":7}"#, g));
}

#[tokio::test]
async fn connect_sends_bearer_wakes_for_our_group_and_ignores_others() {
    let g = Uuid::new_v4();
    let frames = vec![
        format!(
            r#"{{"type":"epoch_advanced","group_id":"{}","new_epoch":2}}"#,
            Uuid::new_v4()
        ),
        format!(r#"{{"type":"envelope_received","group_id":"{g}","envelope_id":"{g}"}}"#),
    ];
    let (url, seen) = server(frames, false).await;
    let (tx, mut rx) = channel(16);
    let task = tokio::spawn(wake_loop(url, bearer(), g, tx, TICK));
    // Wake 1: connect catch-up; wake 2: the matching frame; the other group's frame is dropped.
    assert!(matches!(next(&mut rx).await, Event::Wake));
    assert!(matches!(next(&mut rx).await, Event::Wake));
    assert!(tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());
    assert_eq!(seen.lock().unwrap().as_slice(), ["Bearer tok"]);
    task.abort();
}

#[tokio::test]
async fn a_dropped_connection_reconnects_and_catches_up() {
    let g = Uuid::new_v4();
    let (url, seen) = server(vec![], true).await;
    let (tx, mut rx) = channel(16);
    let task = tokio::spawn(wake_loop(url, bearer(), g, tx, TICK));
    assert!(matches!(next(&mut rx).await, Event::Wake));
    assert!(
        matches!(next(&mut rx).await, Event::Wake),
        "catch-up after reconnect"
    );
    assert!(seen.lock().unwrap().len() >= 2);
    task.abort();
}

#[tokio::test]
async fn gives_up_after_three_retries_and_says_so() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    drop(listener);
    let (tx, mut rx) = channel(16);
    wake_loop(url, bearer(), Uuid::new_v4(), tx, TICK).await;
    assert!(matches!(rx.recv().await, Some(Event::RealtimeLost)));
    assert!(rx.recv().await.is_none(), "no wakes without a connection");
}

#[tokio::test]
async fn a_server_that_accepts_and_drops_at_once_exhausts_the_budget() {
    let (url, seen) = server(vec![], true).await;
    let (tx, mut rx) = channel(64);
    tokio::time::timeout(
        Duration::from_secs(10),
        wake_loop(url, bearer(), Uuid::new_v4(), tx, TICK),
    )
    .await
    .unwrap();
    let mut last = None;
    while let Some(e) = rx.recv().await {
        last = Some(e);
    }
    assert!(matches!(last, Some(Event::RealtimeLost)));
    assert_eq!(seen.lock().unwrap().len(), 4, "1 try + 3 retries");
}

#[tokio::test]
async fn an_oversized_frame_ends_the_connection_without_waking() {
    let g = Uuid::new_v4();
    let big = format!(
        r#"{{"group_id":"{g}","pad":"{}"}}"#,
        "x".repeat(MAX_FRAME_BYTES + 1)
    );
    let (url, _seen) = server(vec![big], true).await;
    let (tx, mut rx) = channel(64);
    tokio::time::timeout(
        Duration::from_secs(10),
        wake_loop(url, bearer(), g, tx, TICK),
    )
    .await
    .unwrap();
    let mut wakes = 0;
    let mut last = None;
    while let Some(e) = rx.recv().await {
        if matches!(e, Event::Wake) {
            wakes += 1;
        }
        last = Some(e);
    }
    // Only the connect-time catch-up wakes fire; the matching-but-oversized frame never does.
    assert!(wakes <= 4, "got {wakes} wakes");
    assert!(matches!(last, Some(Event::RealtimeLost)));
}

#[test]
fn tls_connector_builds_with_an_explicit_provider() {
    assert!(tls_connector().is_some());
}
