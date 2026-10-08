//! `powehi register` / `powehi login` (prd.md §5.5, §7A.2, §8.5): OPAQUE through the crypto core.
//!
//! The server only ever sees OPAQUE messages and `SHA-256(handle)`. The OPAQUE `export_key`
//! (first 32 bytes) opens the encrypted profile store; the session token is held in memory in
//! [`Session`] and is never written to disk. The recovery phrase is generated here, shown once
//! through the [`Prompter`], and only its derived keys are persisted (encrypted).

use std::fmt::Write as _;
use std::fs;

use powehi_crypto_core::opaque::{self, EXPORT_KEY_LEN};
use powehi_crypto_core::recovery::{self, RecoveryError};
use rand::rngs::OsRng;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::profile::ProfilePaths;
use crate::prompt::{PromptError, Prompter};
use crate::store::{ProfileStore, StoreError};

/// Responses from the auth endpoints are small OPAQUE blobs; anything larger is rejected.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Store record holding the non-secret account ids.
pub const ACCOUNT_RECORD: &str = "account";
/// Store record holding the phrase-derived MLS signing key seed (consumed by Phase 7.5).
pub const MLS_SIGNING_RECORD: &str = "mls-signing-key";
const ACCOUNT_VERSION: u8 = 1;
const HANDLE_HASH_LEN: usize = 32;
const MLS_LABEL_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error(transparent)]
    Prompt(#[from] PromptError),
    #[error("the account was created but the recovery phrase could not be displayed; it cannot be recovered")]
    PhraseNotShown,
    #[error("could not reach the server")]
    Unreachable,
    #[error("server returned HTTP {0}")]
    HttpStatus(u16),
    #[error("unexpected response from the server")]
    BadResponse,
    #[error("incorrect handle or password")]
    InvalidCredentials,
    #[error("this profile already holds an account; pick another --profile")]
    ProfileInUse,
    #[error("this profile has no account; run `powehi register` first")]
    NotRegistered,
    #[error("profile data does not match the server account")]
    AccountMismatch,
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("cryptographic operation failed")]
    Crypto,
}

impl From<RecoveryError> for AuthError {
    fn from(_: RecoveryError) -> Self {
        AuthError::Crypto
    }
}

/// An authenticated session. The bearer token lives only here, in memory.
pub struct Session {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub store: ProfileStore,
    token: Zeroizing<String>,
}

impl Session {
    /// The `Authorization: Bearer` value for server calls.
    pub fn bearer(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", self.token.as_str()))
    }
}

#[cfg(test)]
impl Session {
    pub(crate) fn for_test(store: ProfileStore, device_id: Uuid, token: &str) -> Self {
        Session {
            user_id: Uuid::new_v4(),
            device_id,
            store,
            token: Zeroizing::new(token.to_owned()),
        }
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Account {
    version: u8,
    pub(crate) user_id: Uuid,
    pub(crate) device_id: Uuid,
    /// Non-secret 16-byte MLS credential label (`SHA-256(phrase)[..16]`, same as the web client).
    pub(crate) mls_label: Vec<u8>,
}

/// Reads and validates the `account` record of an open store.
pub(crate) fn load_account(store: &ProfileStore) -> Result<Account, AuthError> {
    let raw = store.get(ACCOUNT_RECORD)?.ok_or(AuthError::NotRegistered)?;
    let account: Account = serde_json::from_slice(&raw).map_err(|_| AuthError::NotRegistered)?;
    if account.version != ACCOUNT_VERSION {
        return Err(AuthError::NotRegistered);
    }
    Ok(account)
}

// ---- wire types (serde encodes `Vec<u8>` as a JSON integer array, matching the server) ----

#[derive(Serialize)]
struct RegInitReq<'a> {
    handle_hash: &'a [u8],
    opaque_request: &'a [u8],
}
#[derive(Deserialize)]
struct RegInitResp {
    user_id: Uuid,
    opaque_response: Vec<u8>,
}
#[derive(Serialize)]
struct RegFinishReq<'a> {
    user_id: Uuid,
    opaque_record: &'a [u8],
    mls_credential: &'a [u8],
    recovery_pubkey: &'a [u8],
}
#[derive(Deserialize)]
struct RegFinishResp {
    user_id: Uuid,
    device_id: Uuid,
}
#[derive(Serialize)]
struct LoginInitReq<'a> {
    handle_hash: &'a [u8],
    opaque_ke1: &'a [u8],
}
#[derive(Deserialize)]
struct LoginInitResp {
    user_id: Uuid,
    opaque_ke2: Vec<u8>,
    login_nonce: String,
}
#[derive(Serialize)]
struct LoginFinishReq<'a> {
    opaque_ke3: &'a [u8],
    login_nonce: &'a str,
    device_id: Uuid,
}

async fn post_json<B: Serialize, R: DeserializeOwned>(
    client: &Client,
    server: &Url,
    path: &str,
    body: &B,
) -> Result<R, AuthError> {
    let url = server.join(path).map_err(|_| AuthError::BadResponse)?;
    let mut resp = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(body).map_err(|_| AuthError::BadResponse)?)
        .send()
        .await
        .map_err(|_| AuthError::Unreachable)?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(AuthError::InvalidCredentials);
    }
    if !status.is_success() {
        return Err(AuthError::HttpStatus(status.as_u16()));
    }
    let mut buf = Zeroizing::new(Vec::new());
    while let Some(chunk) = resp.chunk().await.map_err(|_| AuthError::Unreachable)? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(AuthError::BadResponse);
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|_| AuthError::BadResponse)
}

fn handle_hash(handle: &str) -> [u8; HANDLE_HASH_LEN] {
    Sha256::digest(handle.as_bytes()).into()
}

/// True when the profile directory holds anything besides the lock file, or cannot be read.
/// Cheap pre-check so a doomed `register` fails before any server request; the authoritative
/// check runs again under the profile lock.
fn profile_has_data(paths: &ProfilePaths) -> bool {
    match fs::read_dir(&paths.dir) {
        Ok(mut it) => it.any(|e| e.map(|e| e.file_name() != ".lock").unwrap_or(true)),
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Constant-time equality for secret byte strings.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `SHA-256(phrase)[..16]`: the public MLS credential label, identical to the web client.
fn mls_label(phrase: &str) -> Vec<u8> {
    Sha256::digest(phrase.as_bytes())[..MLS_LABEL_LEN].to_vec()
}

/// Keys derived from a fresh recovery phrase. The phrase itself is returned only so it can be
/// shown once; the mnemonic and seed are dropped here.
struct RecoveryMaterial {
    phrase: Zeroizing<String>,
    recovery_pub: [u8; 32],
    signing_priv: Zeroizing<[u8; 32]>,
    label: Vec<u8>,
}

fn new_recovery_material() -> Result<RecoveryMaterial, AuthError> {
    let mnemonic = recovery::generate_mnemonic()?;
    // Pre-sized so the phrase is never copied by a reallocation (24 words, <= 8 bytes each).
    let mut phrase = Zeroizing::new(String::with_capacity(256));
    write!(phrase, "{mnemonic}").map_err(|_| AuthError::Crypto)?;
    let seed = recovery::mnemonic_to_seed(&mnemonic);
    drop(mnemonic);
    let (_auth_priv, recovery_pub) = recovery::derive_recovery_auth_keypair(&seed[..])?;
    let (signing_priv, _signing_pub) = recovery::derive_signing_keypair(&seed[..])?;
    let label = mls_label(&phrase);
    Ok(RecoveryMaterial {
        phrase,
        recovery_pub,
        signing_priv,
        label,
    })
}

fn persist_account(
    store: &ProfileStore,
    account: &Account,
    material: &RecoveryMaterial,
) -> Result<(), AuthError> {
    let json = serde_json::to_vec(account).map_err(|_| AuthError::Crypto)?;
    store.put(ACCOUNT_RECORD, &json)?;
    store.put(MLS_SIGNING_RECORD, &material.signing_priv[..])?;
    Ok(())
}

/// Registers a new account, then logs in on the freshly created device. Returns the session.
///
/// Order matters. The registration `export_key` equals the login one (RFC 9807 §4.1), so the
/// profile store is opened with it right away: as soon as the server accepts the account, the
/// account record and signing key are saved locally, and only then is the phrase shown. Any
/// later failure (network, rate limit) leaves a profile that `powehi login` can still open.
///
/// Known gap: if the `register/finish` response is lost after the server committed, the account
/// exists without a local record or a shown phrase; closing it needs an idempotent
/// `register/finish` on the server (same gap as the web client).
pub async fn register(
    client: &Client,
    server: &Url,
    paths: &ProfilePaths,
    prompter: &mut dyn Prompter,
) -> Result<Session, AuthError> {
    if profile_has_data(paths) {
        return Err(AuthError::ProfileInUse);
    }
    let handle = prompter.handle()?;
    let password = prompter.password(true)?;
    let hash = handle_hash(&handle);
    let mut rng = OsRng;

    let (state, request) =
        opaque::registration_start(password.as_bytes(), &mut rng).map_err(|_| AuthError::Crypto)?;
    let init: RegInitResp = post_json(
        client,
        server,
        "/v1/auth/register/init",
        &RegInitReq {
            handle_hash: &hash,
            opaque_request: &request,
        },
    )
    .await?;
    let (mut finished, upload) =
        opaque::registration_finish(state, password.as_bytes(), &init.opaque_response, &mut rng)
            .map_err(|_| AuthError::Crypto)?;
    let reg_export_key = Zeroizing::new(finished.export_key[..EXPORT_KEY_LEN].to_vec());
    opaque::scrub_registration_finish_result(&mut finished);
    drop(finished);

    // Takes the profile lock; re-check emptiness while holding it.
    let store = ProfileStore::open(paths, &reg_export_key)?;
    if !store.names()?.is_empty() {
        return Err(AuthError::ProfileInUse);
    }
    let material = new_recovery_material()?;
    let fin: RegFinishResp = post_json(
        client,
        server,
        "/v1/auth/register/finish",
        &RegFinishReq {
            user_id: init.user_id,
            opaque_record: &upload,
            mls_credential: &material.label,
            recovery_pubkey: &material.recovery_pub,
        },
    )
    .await?;
    // The server has committed the account and its registration session is single-use, so from
    // here on the phrase MUST be shown whatever else fails; persistence errors come after it.
    let account = Account {
        version: ACCOUNT_VERSION,
        user_id: fin.user_id,
        device_id: fin.device_id,
        mls_label: material.label.clone(),
    };
    let persisted = if fin.user_id != init.user_id {
        Err(AuthError::BadResponse)
    } else {
        persist_account(&store, &account, &material)
    };
    let shown = prompter.show_recovery_phrase(&material.phrase);
    persisted?;
    shown.map_err(|_| AuthError::PhraseNotShown)?;
    drop(material);

    let hs = login_handshake(client, server, &hash, &password).await?;
    if !ct_eq(&hs.export_key, &reg_export_key) {
        return Err(AuthError::Crypto);
    }
    drop(reg_export_key);
    finish_login(
        client,
        server,
        store,
        (account.user_id, account.device_id),
        hs,
    )
    .await
}

/// Logs in with the handle and password, returning a session.
pub async fn login(
    client: &Client,
    server: &Url,
    paths: &ProfilePaths,
    prompter: &mut dyn Prompter,
) -> Result<Session, AuthError> {
    let handle = prompter.handle()?;
    let password = prompter.password(false)?;
    let hs = login_handshake(client, server, &handle_hash(&handle), &password).await?;
    let store = ProfileStore::open(paths, &hs.export_key)?;
    let account = load_account(&store)?;
    finish_login(
        client,
        server,
        store,
        (account.user_id, account.device_id),
        hs,
    )
    .await
}

/// Result of the client side of OPAQUE login, before `login/finish` is sent.
struct Handshake {
    export_key: Zeroizing<Vec<u8>>,
    ke3: Vec<u8>,
    init: LoginInitResp,
}

async fn login_handshake(
    client: &Client,
    server: &Url,
    hash: &[u8; HANDLE_HASH_LEN],
    password: &str,
) -> Result<Handshake, AuthError> {
    let mut rng = OsRng;
    let (state, ke1) =
        opaque::login_start(password.as_bytes(), &mut rng).map_err(|_| AuthError::Crypto)?;
    let init: LoginInitResp = post_json(
        client,
        server,
        "/v1/auth/login/init",
        &LoginInitReq {
            handle_hash: hash,
            opaque_ke1: &ke1,
        },
    )
    .await?;
    // A wrong password (or an unknown handle, which the server answers with a dummy record)
    // fails here, client-side, before anything is sent that proves possession.
    let mut result =
        opaque::login_finish_full(state, password.as_bytes(), &init.opaque_ke2, &mut rng)
            .map_err(|_| AuthError::InvalidCredentials)?;
    let export_key = Zeroizing::new(result.export_key[..EXPORT_KEY_LEN].to_vec());
    let ke3 = result.message.serialize().to_vec();
    opaque::scrub_login_finish_result(&mut result);
    drop(result);
    Ok(Handshake {
        export_key,
        ke3,
        init,
    })
}

async fn finish_login(
    client: &Client,
    server: &Url,
    store: ProfileStore,
    (user_id, device_id): (Uuid, Uuid),
    hs: Handshake,
) -> Result<Session, AuthError> {
    if user_id != hs.init.user_id {
        return Err(AuthError::AccountMismatch);
    }
    let visible = |s: &str| s.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if hs.init.login_nonce.is_empty()
        || hs.init.login_nonce.len() > 128
        || !visible(&hs.init.login_nonce)
    {
        return Err(AuthError::BadResponse);
    }
    let token: String = post_json(
        client,
        server,
        "/v1/auth/login/finish",
        &LoginFinishReq {
            opaque_ke3: &hs.ke3,
            login_nonce: &hs.init.login_nonce,
            device_id,
        },
    )
    .await?;
    if token.is_empty() || token.len() > 4096 || !visible(&token) {
        return Err(AuthError::BadResponse);
    }
    Ok(Session {
        user_id,
        device_id,
        store,
        token: Zeroizing::new(token),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use opaque_ke::rand::rngs::OsRng as ServerRng;
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };
    use powehi_crypto_core::opaque::DefaultCipherSuite as Cs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::prompt::ScriptedPrompter;

    const TOKEN: &str = "session-token-0123456789";

    #[derive(Default)]
    struct Users {
        /// handle_hash -> (user_id, serialized password file)
        by_hash: HashMap<Vec<u8>, (Uuid, Vec<u8>)>,
        pending_reg: HashMap<Uuid, Vec<u8>>,
        pending_login: HashMap<String, ServerLogin<Cs>>,
        recovery_pubkeys: Vec<Vec<u8>>,
        credentials: Vec<Vec<u8>>,
        bodies: Vec<String>,
        finish_status: u16,
        /// Number of upcoming `login/init` calls to fail with HTTP 429.
        init_failures: u32,
        /// Make this directory read-only when `register/finish` is handled.
        lock_dir_on_finish: Option<std::path::PathBuf>,
    }

    struct Mock {
        users: Arc<Mutex<Users>>,
        url: Url,
    }

    async fn read_request(sock: &mut tokio::net::TcpStream) -> (String, serde_json::Value) {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
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
        let path = String::from_utf8_lossy(&data)
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        let body = serde_json::from_slice(&data[head_end..head_end + len]).unwrap();
        (path, body)
    }

    fn bytes(v: &serde_json::Value, k: &str) -> Vec<u8> {
        serde_json::from_value(v[k].clone()).unwrap()
    }

    fn handle(
        setup: &ServerSetup<Cs>,
        users: &mut Users,
        path: &str,
        body: &serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let mut rng = ServerRng;
        users.bodies.push(body.to_string());
        match path {
            "/v1/auth/register/init" => {
                let hash = bytes(body, "handle_hash");
                let req =
                    RegistrationRequest::<Cs>::deserialize(&bytes(body, "opaque_request")).unwrap();
                let resp = ServerRegistration::<Cs>::start(setup, req, &hash).unwrap();
                let uid = Uuid::new_v4();
                users.pending_reg.insert(uid, hash);
                let r = resp.message.serialize().to_vec();
                (
                    200,
                    serde_json::json!({"user_id": uid, "opaque_response": r}),
                )
            }
            "/v1/auth/register/finish" => {
                let uid: Uuid = serde_json::from_value(body["user_id"].clone()).unwrap();
                let hash = users.pending_reg.remove(&uid).unwrap();
                let up =
                    RegistrationUpload::<Cs>::deserialize(&bytes(body, "opaque_record")).unwrap();
                let file = ServerRegistration::<Cs>::finish(up).serialize().to_vec();
                users.recovery_pubkeys.push(bytes(body, "recovery_pubkey"));
                users.credentials.push(bytes(body, "mls_credential"));
                users.by_hash.insert(hash, (uid, file));
                if let Some(d) = &users.lock_dir_on_finish {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(d, fs::Permissions::from_mode(0o500)).unwrap();
                }
                (
                    200,
                    serde_json::json!({"user_id": uid, "device_id": Uuid::new_v4()}),
                )
            }
            "/v1/auth/login/init" if users.init_failures > 0 => {
                users.init_failures -= 1;
                (429, serde_json::Value::Null)
            }
            "/v1/auth/login/init" => {
                let hash = bytes(body, "handle_hash");
                let entry = users.by_hash.get(&hash).cloned();
                let req = CredentialRequest::<Cs>::deserialize(&bytes(body, "opaque_ke1")).unwrap();
                let file = entry
                    .as_ref()
                    .map(|e| ServerRegistration::<Cs>::deserialize(&e.1).unwrap());
                let start = ServerLogin::start(
                    &mut rng,
                    setup,
                    file,
                    req,
                    &hash,
                    ServerLoginParameters::default(),
                )
                .unwrap();
                let uid = entry.map(|e| e.0).unwrap_or_else(Uuid::new_v4);
                let nonce = Uuid::new_v4().to_string();
                users.pending_login.insert(nonce.clone(), start.state);
                let r = start.message.serialize().to_vec();
                (
                    200,
                    serde_json::json!({"user_id": uid, "opaque_ke2": r, "login_nonce": nonce}),
                )
            }
            "/v1/auth/login/finish" => {
                if users.finish_status != 0 {
                    return (users.finish_status, serde_json::Value::Null);
                }
                let nonce = body["login_nonce"].as_str().unwrap();
                let state = users.pending_login.remove(nonce).unwrap();
                let fin =
                    CredentialFinalization::<Cs>::deserialize(&bytes(body, "opaque_ke3")).unwrap();
                match state.finish(fin, ServerLoginParameters::default()) {
                    Ok(_) => (200, serde_json::json!(TOKEN)),
                    Err(_) => (401, serde_json::Value::Null),
                }
            }
            _ => (404, serde_json::Value::Null),
        }
    }

    async fn mock() -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let users = Arc::new(Mutex::new(Users::default()));
        let setup = Arc::new(ServerSetup::<Cs>::new(&mut ServerRng));
        let shared = users.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (path, body) = read_request(&mut sock).await;
                let (status, json) = handle(&setup, &mut shared.lock().unwrap(), &path, &body);
                let out = json.to_string();
                let resp = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                    out.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        Mock { users, url }
    }

    fn prompter(pw: &str) -> ScriptedPrompter {
        ScriptedPrompter {
            handle: "aurora-fox-2843".into(),
            passwords: vec![pw.to_owned()],
            shown: vec![],
        }
    }

    fn paths(dir: &tempfile::TempDir, name: &str) -> ProfilePaths {
        ProfilePaths::resolve(dir.path(), name).unwrap()
    }

    fn all_file_bytes(dir: &std::path::Path) -> Vec<u8> {
        let mut out = Vec::new();
        for e in fs::read_dir(dir).unwrap() {
            out.extend(fs::read(e.unwrap().path()).unwrap_or_default());
        }
        out
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn register_then_login_round_trip() {
        let m = mock().await;
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "a");
        let client = crate::status::http_client().unwrap();

        let mut pr = prompter("correct horse battery");
        let s = register(&client, &m.url, &p, &mut pr).await.unwrap();
        assert_eq!(pr.shown.len(), 1, "phrase shown exactly once");
        assert_eq!(pr.shown[0].split(' ').count(), 24);
        assert_eq!(*s.bearer(), format!("Bearer {TOKEN}"));
        // Invariants: what the server learns is derived from the phrase under the right domains.
        let phrase = pr.shown[0].clone();
        let seed = recovery::mnemonic_to_seed(&recovery::parse_phrase(&phrase).unwrap());
        let (_, auth_pub) = recovery::derive_recovery_auth_keypair(&seed[..]).unwrap();
        let (sign_priv, sign_pub) = recovery::derive_signing_keypair(&seed[..]).unwrap();
        assert_ne!(auth_pub, sign_pub);
        {
            let u = m.users.lock().unwrap();
            assert_eq!(u.recovery_pubkeys, vec![auth_pub.to_vec()]);
            assert_eq!(u.credentials, vec![mls_label(&phrase)]);
            // Neither the password, the phrase nor the signing key ever reach the server.
            let pw_bytes = format!("{:?}", "correct horse battery".as_bytes());
            let sign_bytes = format!("{:?}", &sign_priv[..]).replace(", ", ",");
            for b in &u.bodies {
                let compact = b.replace(", ", ",");
                assert!(!b.contains("correct horse battery"));
                assert!(!b.contains(&phrase));
                assert!(!compact.contains(&pw_bytes.replace(", ", ",").replace(['[', ']'], "")));
                assert!(!compact.contains(sign_bytes.trim_matches(['[', ']'])));
            }
        }
        assert_eq!(
            &**s.store.get(MLS_SIGNING_RECORD).unwrap().unwrap(),
            &sign_priv[..]
        );
        let (user, device) = (s.user_id, s.device_id);
        drop(s);

        let mut pr = prompter("correct horse battery");
        let s = login(&client, &m.url, &p, &mut pr).await.unwrap();
        assert_eq!((s.user_id, s.device_id), (user, device));
        assert!(s.store.get(MLS_SIGNING_RECORD).unwrap().is_some());
        assert!(pr.shown.is_empty());
        drop(s);

        let disk = all_file_bytes(&p.dir);
        let contains = |needle: &[u8]| disk.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(TOKEN.as_bytes()), "token must never touch disk");
        assert!(
            !contains(user.to_string().as_bytes()),
            "ids are encrypted too"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_password_is_invalid_credentials() {
        let m = mock().await;
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "a");
        let client = crate::status::http_client().unwrap();
        drop(
            register(&client, &m.url, &p, &mut prompter("right-password"))
                .await
                .unwrap(),
        );
        let e = login(&client, &m.url, &p, &mut prompter("wrong-password"))
            .await
            .unwrap_err();
        assert!(matches!(e, AuthError::InvalidCredentials), "{e:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_handle_is_indistinguishable_from_wrong_password() {
        let m = mock().await;
        let tmp = tempfile::tempdir().unwrap();
        let client = crate::status::http_client().unwrap();
        let e = login(
            &client,
            &m.url,
            &paths(&tmp, "x"),
            &mut prompter("pw-123456"),
        )
        .await
        .unwrap_err();
        assert!(matches!(e, AuthError::InvalidCredentials), "{e:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn login_on_a_profile_without_an_account_is_not_registered() {
        let m = mock().await;
        let tmp = tempfile::tempdir().unwrap();
        let client = crate::status::http_client().unwrap();
        let first = register(
            &client,
            &m.url,
            &paths(&tmp, "a"),
            &mut prompter("pw-123456"),
        )
        .await
        .unwrap();
        drop(first);
        let e = login(
            &client,
            &m.url,
            &paths(&tmp, "b"),
            &mut prompter("pw-123456"),
        )
        .await
        .unwrap_err();
        assert!(matches!(e, AuthError::NotRegistered), "{e:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn second_register_in_same_profile_is_refused_before_any_request() {
        let m = mock().await;
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "a");
        let client = crate::status::http_client().unwrap();
        drop(
            register(&client, &m.url, &p, &mut prompter("pw-123456"))
                .await
                .unwrap(),
        );
        let before = m.users.lock().unwrap().by_hash.len();
        let e = register(&client, &m.url, &p, &mut prompter("pw-123456"))
            .await
            .unwrap_err();
        assert!(matches!(e, AuthError::ProfileInUse), "{e:?}");
        assert_eq!(m.users.lock().unwrap().by_hash.len(), before);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_error_on_login_finish_is_typed() {
        let m = mock().await;
        let tmp = tempfile::tempdir().unwrap();
        let client = crate::status::http_client().unwrap();
        m.users.lock().unwrap().finish_status = 503;
        let e = register(
            &client,
            &m.url,
            &paths(&tmp, "a"),
            &mut prompter("pw-123456"),
        )
        .await
        .unwrap_err();
        assert!(matches!(e, AuthError::HttpStatus(503)), "{e:?}");
    }

    #[tokio::test]
    async fn unreachable_server_is_typed() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", l.local_addr().unwrap())).unwrap();
        drop(l);
        let tmp = tempfile::tempdir().unwrap();
        let client = crate::status::http_client().unwrap();
        let e = login(&client, &url, &paths(&tmp, "a"), &mut prompter("pw-123456"))
            .await
            .unwrap_err();
        assert!(matches!(e, AuthError::Unreachable), "{e:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failure_after_register_finish_leaves_a_loginable_profile() {
        let m = mock().await;
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "a");
        let client = crate::status::http_client().unwrap();
        m.users.lock().unwrap().init_failures = 1;
        let mut pr = prompter("pw-123456");
        let e = register(&client, &m.url, &p, &mut pr).await.unwrap_err();
        assert!(matches!(e, AuthError::HttpStatus(429)), "{e:?}");
        assert_eq!(pr.shown.len(), 1, "phrase was shown before the failure");
        let s = login(&client, &m.url, &p, &mut prompter("pw-123456"))
            .await
            .unwrap();
        assert_eq!(*s.bearer(), format!("Bearer {TOKEN}"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn phrase_is_shown_even_if_local_persistence_fails() {
        use std::os::unix::fs::PermissionsExt;
        let m = mock().await;
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp, "a");
        let client = crate::status::http_client().unwrap();
        m.users.lock().unwrap().lock_dir_on_finish = Some(p.dir.clone());
        let mut pr = prompter("pw-123456");
        let e = register(&client, &m.url, &p, &mut pr).await.unwrap_err();
        assert!(matches!(e, AuthError::Store(_)), "{e:?}");
        assert_eq!(pr.shown.len(), 1, "phrase must be shown before the error");
        fs::set_permissions(&p.dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn mls_label_known_answer_matches_web_formula() {
        // SHA-256("abandon"*23 + " art")[..16], as computed by the web client.
        let phrase = format!("{} art", ["abandon"; 23].join(" "));
        assert_eq!(
            mls_label(&phrase),
            hex16("69be79ef3c28f55d7cb84db2dd3c18df")
        );
    }

    fn hex16(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn handle_hash_is_sha256_of_the_handle() {
        assert_ne!(handle_hash("a"), handle_hash("b"));
        assert_eq!(handle_hash("a"), Sha256::digest(b"a").as_slice());
    }
}
