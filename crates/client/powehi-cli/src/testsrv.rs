//! In-test mini Delivery Service for the invite/welcome flows: just enough of `/v1/invites`,
//! `/v1/groups`, `/v1/messages` to run two profiles against each other over real HTTP.
//! The caller is identified by its bearer token, which tests set to the device UUID.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

#[derive(Default)]
pub struct Backend {
    /// code -> (inviter device, pinned key package)
    pub invites: HashMap<String, (Uuid, Vec<u8>)>,
    pub groups: Vec<Uuid>,
    pub members: Vec<(Uuid, Uuid, u64)>,
    /// Stored envelopes as the server returns them (`recipient` is a UUID string).
    pub inbox: Vec<Value>,
    /// `"METHOD /path"` of every request, in order.
    pub calls: Vec<String>,
    /// Corrupt the key package on redeem (what a malicious server would try).
    pub tamper_redeem: bool,
}

fn respond(status: u16, body: Option<Value>) -> String {
    let body = body.map(|v| v.to_string()).unwrap_or_default();
    let reason = if status < 300 { "OK" } else { "Err" };
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn handle(st: &mut Backend, method: &str, path: &str, caller: Uuid, body: &Value) -> String {
    st.calls.push(format!("{method} {path}"));
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method, segs.as_slice()) {
        ("POST", ["v1", "invites"]) => {
            let kp: Vec<u8> = serde_json::from_value(body["key_package"].clone()).unwrap();
            let code = Uuid::new_v4().simple().to_string();
            st.invites.insert(code.clone(), (caller, kp));
            respond(201, Some(json!({ "code": code })))
        }
        ("POST", ["v1", "invites", "redeem"]) => {
            let code = body["code"].as_str().unwrap_or_default();
            match st.invites.remove(code) {
                None => respond(404, Some(json!({ "code": "not_found" }))),
                Some((dev, mut kp)) => {
                    if st.tamper_redeem {
                        let last = kp.len() - 1;
                        kp[last] ^= 1;
                    }
                    respond(200, Some(json!({ "device_id": dev, "key_package": kp })))
                }
            }
        }
        ("POST", ["v1", "groups"]) => {
            st.groups
                .push(body["group_id"].as_str().unwrap().parse().unwrap());
            respond(204, None)
        }
        ("POST", ["v1", "groups", g, "members", d]) => {
            st.members.push((
                g.parse().unwrap(),
                d.parse().unwrap(),
                body["epoch"].as_u64().unwrap(),
            ));
            respond(204, None)
        }
        ("POST", ["v1", "messages", "welcome"]) => {
            st.inbox.push(json!({
                "id": Uuid::new_v4(),
                "group_id": body["group_id"],
                "sender": caller,
                "recipient": body["target_device_id"],
                "message_type": "Welcome",
                "ciphertext": body["welcome"],
                "epoch": null,
                "created_at": "2026-10-09T00:00:00Z",
                "expires_at": null,
            }));
            respond(204, None)
        }
        ("GET", ["v1", "messages"]) => {
            let mine: Vec<&Value> = st
                .inbox
                .iter()
                .filter(|e| e["recipient"].as_str() == Some(&caller.to_string()))
                .collect();
            respond(200, Some(json!(mine)))
        }
        ("DELETE", ["v1", "messages", id]) => {
            st.inbox.retain(|e| e["id"].as_str() != Some(id));
            respond(204, None)
        }
        _ => respond(404, None),
    }
}

async fn read_request(sock: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut data = Vec::new();
    let mut buf = [0u8; 16384];
    let (head_end, len) = loop {
        let n = sock.read(&mut buf).await.unwrap();
        data.extend_from_slice(&buf[..n]);
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..i]).to_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (i + 4, len);
        }
    };
    while data.len() < head_end + len {
        let n = sock.read(&mut buf).await.unwrap();
        data.extend_from_slice(&buf[..n]);
    }
    (
        String::from_utf8_lossy(&data[..head_end]).to_string(),
        data[head_end..head_end + len].to_vec(),
    )
}

/// Starts the server on a loopback port and returns its base URL.
pub async fn serve(state: Arc<Mutex<Backend>>) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let state = state.clone();
            tokio::spawn(async move {
                let (head, body) = read_request(&mut sock).await;
                let first = head.lines().next().unwrap_or_default().to_owned();
                let mut parts = first.split(' ');
                let (method, path) = (parts.next().unwrap(), parts.next().unwrap());
                let caller = head
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("authorization:"))
                    .and_then(|l| l.rsplit(' ').next())
                    .and_then(|t| t.trim().parse::<Uuid>().ok())
                    .unwrap_or_default();
                let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let resp = handle(&mut state.lock().unwrap(), method, path, caller, &body);
                sock.write_all(resp.as_bytes()).await.unwrap();
            });
        }
    });
    url
}

/// A seeded profile (account + signing seed) wrapped in a [`crate::auth::Session`] whose token
/// is its device id.
pub fn session(tmp: &tempfile::TempDir, name: &str, seed: u8) -> crate::auth::Session {
    use crate::auth::{ACCOUNT_RECORD, MLS_SIGNING_RECORD};
    use crate::profile::ProfilePaths;
    use crate::store::ProfileStore;
    let paths = ProfilePaths::resolve(tmp.path(), name).unwrap();
    let store = ProfileStore::open(&paths, &[seed; 32]).unwrap();
    let device = Uuid::new_v4();
    let account = json!({
        "version": 1, "user_id": Uuid::new_v4(), "device_id": device, "mls_label": vec![seed; 16],
    });
    store
        .put(ACCOUNT_RECORD, account.to_string().as_bytes())
        .unwrap();
    store.put(MLS_SIGNING_RECORD, &[seed; 32]).unwrap();
    crate::auth::Session::for_test(store, device, &device.to_string())
}
