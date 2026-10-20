//! Live-backend E2E gate (Phase 7.10): two CLI profiles register against a real
//! `powehi-server` (register ends with a real OPAQUE login; an extra explicit login would trip the
//! per-handle limiter, burst 5), start a conversation and exchange messages both ways.
//!
//! `#[ignore]`d: it needs the docker-compose stack and a running server, so it only runs in
//! the `CI — Live-backend E2E` workflow (or locally with `POWEHI_E2E_SERVER` set):
//! `POWEHI_E2E_SERVER=http://127.0.0.1:8080 cargo test -p powehi-cli live_e2e -- --ignored`.
//! Handles and passwords are random per run; nothing is logged.

use reqwest::Client;
use url::Url;
use uuid::Uuid;

use crate::auth::{self, Session};
use crate::profile::ProfilePaths;
use crate::prompt::ScriptedPrompter;
use crate::{inbox, invite, message, verify};

fn server() -> Url {
    let raw = std::env::var("POWEHI_E2E_SERVER").expect("POWEHI_E2E_SERVER must be set");
    Url::parse(&raw).expect("POWEHI_E2E_SERVER must be a URL")
}

fn prompter(handle: &str, password: &str) -> ScriptedPrompter {
    ScriptedPrompter {
        handle: handle.to_owned(),
        passwords: vec![password.to_owned(); 2],
        shown: Vec::new(),
    }
}

async fn register(
    client: &Client,
    url: &Url,
    tmp: &tempfile::TempDir,
    name: &str,
) -> (Session, String, String) {
    let handle = format!("e2e-cli-{}", Uuid::new_v4());
    let password = format!("pw-{}", Uuid::new_v4());
    let paths = ProfilePaths::resolve(tmp.path(), name).unwrap();
    let mut p = prompter(&handle, &password);
    let session = auth::register(client, url, &paths, &mut p).await.unwrap();
    assert_eq!(p.shown.len(), 1, "recovery phrase is shown exactly once");
    crate::identity::ensure_key_packages(client, url, &session)
        .await
        .unwrap();
    (session, handle, password)
}

#[tokio::test]
#[ignore = "needs a live powehi-server (CI — Live-backend E2E)"]
async fn two_profiles_register_converse_and_verify() {
    let url = server();
    let client = crate::status::http_client().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let (alice, _, _) = register(&client, &url, &tmp, "alice").await;
    let (bob, _, _) = register(&client, &url, &tmp, "bob").await;

    // Alice invites, Bob redeems, Alice joins from the Welcome.
    let (link, _) = invite::create(&client, &url, &alice).await.unwrap();
    let link = invite::parse_link(&link).unwrap();
    let (gid, _) = invite::redeem(&client, &url, &bob, &link).await.unwrap();
    let joined = inbox::receive(&client, &url, &alice).await.unwrap();
    assert_eq!(joined.joined, vec![gid]);

    // Both directions, through the real Delivery Service.
    message::send(&client, &url, &bob, gid, b"hello alice")
        .await
        .unwrap();
    assert_eq!(
        inbox::receive(&client, &url, &alice).await.unwrap().stored,
        1
    );
    let got = message::pending(&alice.store, gid).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].text.as_str(), got[0].sender),
        ("hello alice", bob.device_id)
    );

    message::send(&client, &url, &alice, gid, b"hello bob")
        .await
        .unwrap();
    inbox::receive(&client, &url, &bob).await.unwrap();
    let got = message::pending(&bob.store, gid).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].text.as_str(), got[0].sender),
        ("hello bob", alice.device_id)
    );

    // Both sides derive the same Safety Number from the group state alone.
    let a_num = verify::number(&alice.store, gid).unwrap();
    assert_eq!(a_num, verify::number(&bob.store, gid).unwrap());

    // 8.4: revoking ends the session. The token is dead on REST, and a second revoke is a no-op.
    auth::revoke_session(&client, &url, &alice).await.unwrap();
    assert!(inbox::receive(&client, &url, &alice).await.is_err());
    auth::revoke_session(&client, &url, &alice).await.unwrap();
}
