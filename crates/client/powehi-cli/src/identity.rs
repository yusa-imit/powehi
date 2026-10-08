//! MLS identity and KeyPackage top-up (prd.md §4.2, §5.3, §7A.2).
//!
//! The identity is the phrase-derived Ed25519 signing seed stored at register time
//! ([`MLS_SIGNING_RECORD`]) plus the public credential label from the `account` record, so it is
//! reproducible from the recovery phrase alone. Two more store records hold the live state:
//! `mls-provider` (the openmls key store: signer plus every KeyPackage private bundle) and
//! `pq-keys` (the ML-KEM-768 decapsulation key per KeyPackage). Both are written BEFORE a
//! KeyPackage is uploaded, so the server never hands out a package whose private half is lost.
//! KeyPackage bytes and keys are never logged or printed.

use powehi_crypto_core::kem;
use powehi_crypto_core::mls_group::{self, MlsError, PqKeyPackage, Provider, PQ_EXT_ENCAP_KEY_LEN};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::auth::{self, AuthError, Session, MAX_RESPONSE_BYTES, MLS_SIGNING_RECORD};
use crate::store::{ProfileStore, StoreError};

/// Store record holding the exported openmls key store.
pub const PROVIDER_RECORD: &str = "mls-provider";
/// Store record holding the ML-KEM decapsulation keys, one per outstanding KeyPackage.
pub const PQ_KEYS_RECORD: &str = "pq-keys";
/// Top up when the server holds fewer than this many KeyPackages for the device.
pub const LOW_WATERMARK: u64 = 10;
/// Top up to this many (server cap is 200 per device, 50 per call).
pub const TARGET_COUNT: u64 = 50;
/// KeyPackages per upload request (JSON-encoded they are ~8 KB each; server body cap 512 KB).
pub const UPLOAD_BATCH: usize = 10;
/// Upper bound on locally held decapsulation keys. The `mls-provider` record grows ~19.5 KB per
/// outstanding KeyPackage (measured; openmls values are JSON number arrays), so this keeps it
/// near 8 MB, half of `MAX_RECORD_LEN`, leaving room for group state (7.6+).
pub const MAX_PQ_KEYS: usize = 400;
/// Measured provider-record growth per KeyPackage, rounded up.
const PROVIDER_BYTES_PER_KP: usize = 20_000;
const _: () = assert!(MAX_PQ_KEYS * PROVIDER_BYTES_PER_KP <= crate::store::MAX_RECORD_LEN / 2);
const _: () = assert!(MAX_PQ_KEYS <= u16::MAX as usize);
const PQ_KEYS_VERSION: u8 = 1;
/// Length of a KeyPackageRef (SHA-256 ciphersuite).
const REF_LEN: usize = 32;
const ENTRY_LEN: usize = REF_LEN + kem::DK_SIZE;
const SEED_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("could not reach the server")]
    Unreachable,
    #[error("server returned HTTP {0}")]
    HttpStatus(u16),
    #[error("unexpected response from the server")]
    BadResponse,
    #[error("stored MLS identity is missing or malformed")]
    BadIdentity,
    #[error("stored key material is malformed")]
    BadKeyRecord,
    #[error("too many unused local KeyPackage keys (orphans from failed uploads)")]
    TooManyLocalKeys,
    #[error("MLS operation failed")]
    Mls,
}

impl From<MlsError> for IdentityError {
    fn from(_: MlsError) -> Self {
        IdentityError::Mls
    }
}

/// Decapsulation keys keyed by KeyPackageRef (RFC 9420 §5.2, what a Welcome names).
struct PqKeys {
    entries: Vec<([u8; REF_LEN], Zeroizing<Vec<u8>>)>,
}

impl PqKeys {
    /// Wire format: `version(1) || count(u16 BE) || (key_package_ref(32) || dk(2400))*`.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(3 + self.entries.len() * ENTRY_LEN));
        out.push(PQ_KEYS_VERSION);
        let n = u16::try_from(self.entries.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&n.to_be_bytes());
        for (hash, dk) in &self.entries {
            out.extend_from_slice(hash);
            out.extend_from_slice(dk);
        }
        out
    }

    fn decode(raw: &[u8]) -> Result<Self, IdentityError> {
        if raw.len() < 3 || raw[0] != PQ_KEYS_VERSION {
            return Err(IdentityError::BadKeyRecord);
        }
        let n = u16::from_be_bytes([raw[1], raw[2]]) as usize;
        let body = &raw[3..];
        if n > MAX_PQ_KEYS || body.len() != n * ENTRY_LEN {
            return Err(IdentityError::BadKeyRecord);
        }
        let (chunks, _) = body.as_chunks::<ENTRY_LEN>();
        let entries = chunks
            .iter()
            .map(|c| {
                let mut hash = [0u8; REF_LEN];
                hash.copy_from_slice(&c[..REF_LEN]);
                (hash, Zeroizing::new(c[REF_LEN..].to_vec()))
            })
            .collect();
        Ok(Self { entries })
    }

    fn load(store: &ProfileStore) -> Result<Self, IdentityError> {
        match store.get(PQ_KEYS_RECORD)? {
            Some(raw) => Self::decode(&raw),
            None => Ok(Self {
                entries: Vec::new(),
            }),
        }
    }

    fn save(&self, store: &ProfileStore) -> Result<(), IdentityError> {
        if self.entries.len() > MAX_PQ_KEYS {
            return Err(IdentityError::TooManyLocalKeys);
        }
        store.put(PQ_KEYS_RECORD, &self.encode())?;
        Ok(())
    }
}

/// The MLS provider and identity restored from the profile store.
pub struct LocalIdentity {
    pub provider: Provider,
    pub identity: mls_group::Identity,
    generation: u64,
}

impl LocalIdentity {
    /// Restores the provider (or starts an empty one) and re-creates the phrase-derived
    /// identity in it. Idempotent: repeated calls yield the same signing public key.
    pub fn load(store: &ProfileStore) -> Result<Self, IdentityError> {
        let account = auth::load_account(store)?;
        let seed = store
            .get(MLS_SIGNING_RECORD)?
            .ok_or(IdentityError::BadIdentity)?;
        let seed: Zeroizing<[u8; SEED_LEN]> = Zeroizing::new(
            <[u8; SEED_LEN]>::try_from(&seed[..]).map_err(|_| IdentityError::BadIdentity)?,
        );
        let (provider, generation) = match store.get(PROVIDER_RECORD)? {
            Some(raw) => mls_group::import_provider_state(&raw, 0)?,
            None => (Provider::default(), 0),
        };
        let identity =
            mls_group::generate_identity_from_seed(&account.mls_label, &seed, &provider)?;
        Ok(Self {
            provider,
            identity,
            generation,
        })
    }

    /// Persists the provider state with a bumped generation.
    pub fn save(&mut self, store: &ProfileStore) -> Result<(), IdentityError> {
        let next = self.generation.checked_add(1).ok_or(IdentityError::Mls)?;
        let blob = Zeroizing::new(mls_group::export_provider_state(&self.provider, next)?);
        store.put(PROVIDER_RECORD, &blob)?;
        self.generation = next;
        Ok(())
    }
}

#[derive(Deserialize)]
struct CountResp {
    count: u64,
}
#[derive(Serialize)]
struct UploadReq<'a> {
    packages: &'a [Vec<u8>],
}
#[derive(Deserialize)]
struct UploadResp {
    ids: Vec<serde::de::IgnoredAny>,
}

async fn send_bounded<R: DeserializeOwned>(
    req: reqwest::RequestBuilder,
    session: &Session,
) -> Result<R, IdentityError> {
    let bearer = session.bearer();
    let mut value = reqwest::header::HeaderValue::from_str(bearer.as_str())
        .map_err(|_| IdentityError::BadResponse)?;
    value.set_sensitive(true);
    let mut resp = req
        .header(reqwest::header::AUTHORIZATION, value)
        .send()
        .await
        .map_err(|_| IdentityError::Unreachable)?;
    if !resp.status().is_success() {
        return Err(IdentityError::HttpStatus(resp.status().as_u16()));
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| IdentityError::Unreachable)? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(IdentityError::BadResponse);
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|_| IdentityError::BadResponse)
}

fn kp_url(server: &Url, session: &Session, suffix: &str) -> Result<Url, IdentityError> {
    server
        .join(&format!("/v1/key-packages/{}{suffix}", session.device_id))
        .map_err(|_| IdentityError::BadResponse)
}

/// Asks the server how many KeyPackages it still holds for this device.
pub async fn server_count(
    client: &Client,
    server: &Url,
    session: &Session,
) -> Result<u64, IdentityError> {
    let url = kp_url(server, session, "/count")?;
    let r: CountResp = send_bounded(client.get(url), session).await?;
    Ok(r.count)
}

/// Generates `n` PQ KeyPackages, persists their private halves, and returns the public bytes.
/// Nothing is uploaded here; callers upload only after this returns.
fn generate_and_persist(
    store: &ProfileStore,
    local: &mut LocalIdentity,
    n: usize,
) -> Result<Vec<Vec<u8>>, IdentityError> {
    let mut keys = PqKeys::load(store)?;
    if keys.entries.len() + n > MAX_PQ_KEYS {
        return Err(IdentityError::TooManyLocalKeys);
    }
    let mut packages = Vec::with_capacity(n);
    for _ in 0..n {
        let PqKeyPackage {
            key_package,
            encap_key,
            key_package_ref,
            decap_key,
        } = mls_group::generate_pq_key_package(&local.identity, &local.provider)?;
        debug_assert_eq!(encap_key.len(), PQ_EXT_ENCAP_KEY_LEN);
        let key_ref =
            <[u8; REF_LEN]>::try_from(&key_package_ref[..]).map_err(|_| IdentityError::Mls)?;
        keys.entries.push((key_ref, decap_key));
        packages.push(key_package);
    }
    local.save(store)?;
    keys.save(store)?;
    Ok(packages)
}

/// Tops the server's KeyPackage pool up to [`TARGET_COUNT`] when it has fallen below
/// [`LOW_WATERMARK`]. Returns how many were uploaded.
pub async fn ensure_key_packages(
    client: &Client,
    server: &Url,
    session: &Session,
) -> Result<u64, IdentityError> {
    let have = server_count(client, server, session).await?;
    if have >= LOW_WATERMARK {
        return Ok(0);
    }
    let need = (TARGET_COUNT - have) as usize;
    let mut local = LocalIdentity::load(&session.store)?;
    let packages = generate_and_persist(&session.store, &mut local, need)?;
    drop(local);
    let mut uploaded = 0u64;
    for batch in packages.chunks(UPLOAD_BATCH) {
        let url = kp_url(server, session, "")?;
        let body = serde_json::to_vec(&UploadReq { packages: batch })
            .map_err(|_| IdentityError::BadResponse)?;
        let req = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        let r: UploadResp = send_bounded(req, session).await?;
        if r.ids.len() != batch.len() {
            return Err(IdentityError::BadResponse);
        }
        uploaded += batch.len() as u64;
    }
    debug_assert_eq!(uploaded as usize, need);
    Ok(uploaded)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use openmls::prelude::{tls_codec::Deserialize as _, *};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    use super::*;
    use crate::auth::ACCOUNT_RECORD;
    use crate::profile::ProfilePaths;

    const EXPORT_KEY: [u8; 32] = [3u8; 32];
    const SEED: [u8; 32] = [5u8; 32];
    const TOKEN: &str = "tok-0123456789";

    fn open(tmp: &tempfile::TempDir) -> ProfileStore {
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        ProfileStore::open(&paths, &EXPORT_KEY).unwrap()
    }

    fn seeded(tmp: &tempfile::TempDir) -> ProfileStore {
        let store = open(tmp);
        let account = serde_json::json!({
            "version": 1,
            "user_id": Uuid::new_v4(),
            "device_id": Uuid::new_v4(),
            "mls_label": vec![9u8; 16],
        });
        store
            .put(ACCOUNT_RECORD, account.to_string().as_bytes())
            .unwrap();
        store.put(MLS_SIGNING_RECORD, &SEED).unwrap();
        store
    }

    #[test]
    fn pq_keys_round_trip_and_reject_malformed() {
        let keys = PqKeys {
            entries: vec![
                ([1u8; 32], Zeroizing::new(vec![2u8; kem::DK_SIZE])),
                ([3u8; 32], Zeroizing::new(vec![4u8; kem::DK_SIZE])),
            ],
        };
        let enc = keys.encode();
        let dec = PqKeys::decode(&enc).unwrap();
        assert_eq!(dec.entries.len(), 2);
        assert_eq!(dec.entries[1].0, [3u8; 32]);
        assert_eq!(&dec.entries[1].1[..], &vec![4u8; kem::DK_SIZE][..]);
        assert!(PqKeys::decode(&[]).is_err());
        assert!(PqKeys::decode(&enc[..enc.len() - 1]).is_err());
        let mut bad_version = enc.to_vec();
        bad_version[0] = 9;
        assert!(PqKeys::decode(&bad_version).is_err());
        let mut bad_count = enc.to_vec();
        bad_count[1] = 0xff;
        bad_count[2] = 0xff;
        assert!(PqKeys::decode(&bad_count).is_err());
    }

    proptest::proptest! {
        #[test]
        fn pq_keys_encode_decode_round_trip(
            refs in proptest::collection::vec(proptest::array::uniform32(0u8..), 0..4),
            fill in 0u8..,
        ) {
            let keys = PqKeys {
                entries: refs.iter().map(|r| (*r, Zeroizing::new(vec![fill; kem::DK_SIZE]))).collect(),
            };
            let dec = PqKeys::decode(&keys.encode()).unwrap();
            proptest::prop_assert_eq!(dec.entries.len(), keys.entries.len());
            for (a, b) in dec.entries.iter().zip(&keys.entries) {
                proptest::prop_assert_eq!(a.0, b.0);
                proptest::prop_assert_eq!(&a.1[..], &b.1[..]);
            }
        }
    }

    #[test]
    fn load_without_signing_key_is_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        assert!(matches!(
            LocalIdentity::load(&store),
            Err(IdentityError::Auth(AuthError::NotRegistered))
        ));
        store
            .put(
                ACCOUNT_RECORD,
                serde_json::json!({"version":1,"user_id":Uuid::nil(),"device_id":Uuid::nil(),
                    "mls_label":vec![0u8;16]})
                .to_string()
                .as_bytes(),
            )
            .unwrap();
        assert!(matches!(
            LocalIdentity::load(&store),
            Err(IdentityError::BadIdentity)
        ));
        store.put(MLS_SIGNING_RECORD, &[1u8; 31]).unwrap();
        assert!(matches!(
            LocalIdentity::load(&store),
            Err(IdentityError::BadIdentity)
        ));
    }

    /// A KeyPackage persisted before a restart still joins a Welcome after reloading.
    #[test]
    fn persisted_key_package_survives_restart_and_joins_group() {
        let tmp = tempfile::tempdir().unwrap();
        let store = seeded(&tmp);
        let mut local = LocalIdentity::load(&store).unwrap();
        let first_pub = local.identity.credential_with_key.signature_key.clone();
        let kps = generate_and_persist(&store, &mut local, 2).unwrap();
        assert_eq!(kps.len(), 2);
        drop(local);
        drop(store);

        let store = open(&tmp);
        let stored = PqKeys::load(&store).unwrap();
        assert_eq!(stored.entries.len(), 2);
        let reloaded = LocalIdentity::load(&store).unwrap();
        assert_eq!(
            reloaded.identity.credential_with_key.signature_key,
            first_pub
        );

        let alice_provider = Provider::default();
        let alice = mls_group::generate_identity(b"alice", &alice_provider).unwrap();
        let msg = MlsMessageIn::tls_deserialize_exact(&kps[0]).unwrap();
        let MlsMessageBodyIn::KeyPackage(kp) = msg.extract() else {
            panic!("not a key package");
        };
        let kp = kp
            .validate(alice_provider.crypto(), ProtocolVersion::Mls10)
            .unwrap();
        let mut group = mls_group::create_group(&alice, &alice_provider).unwrap();
        let welcome =
            mls_group::add_member(&mut group, &alice.signer, kp, &alice_provider).unwrap();
        let joined = mls_group::join_group(&welcome, &reloaded.provider);
        assert!(
            joined.is_ok(),
            "reloaded provider must hold the KeyPackage private bundle"
        );
    }

    #[test]
    fn local_key_cap_is_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let store = seeded(&tmp);
        let mut local = LocalIdentity::load(&store).unwrap();
        let err = generate_and_persist(&store, &mut local, MAX_PQ_KEYS + 1).unwrap_err();
        assert!(matches!(err, IdentityError::TooManyLocalKeys));
        assert!(store.get(PQ_KEYS_RECORD).unwrap().is_none());
    }

    #[derive(Default)]
    struct Seen {
        count_value: u64,
        uploads: Vec<usize>,
        auth_headers: Vec<String>,
        upload_status: u16,
    }

    async fn serve(state: Arc<Mutex<Seen>>) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let state = state.clone();
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let mut buf = [0u8; 8192];
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
                    let head = String::from_utf8_lossy(&data[..head_end]).to_string();
                    let (status, body) = {
                        let mut st = state.lock().unwrap();
                        if let Some(h) = head
                            .lines()
                            .find(|l| l.to_lowercase().starts_with("authorization:"))
                        {
                            st.auth_headers
                                .push(h.split_once(':').unwrap().1.trim().to_owned());
                        }
                        if head.contains("/count") {
                            (200, serde_json::json!({"count": st.count_value}))
                        } else {
                            let v: serde_json::Value =
                                serde_json::from_slice(&data[head_end..head_end + len]).unwrap();
                            let n = v["packages"].as_array().unwrap().len();
                            st.uploads.push(n);
                            let ids: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
                            (st.upload_status, serde_json::json!({ "ids": ids }))
                        }
                    };
                    let body = body.to_string();
                    let reason = if status == 200 { "OK" } else { "Err" };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    sock.write_all(resp.as_bytes()).await.unwrap();
                });
            }
        });
        url
    }

    fn client() -> Client {
        crate::status::http_client().unwrap()
    }

    #[tokio::test]
    async fn tops_up_when_low_in_batches_with_bearer() {
        let tmp = tempfile::tempdir().unwrap();
        let session = Session::for_test(seeded(&tmp), Uuid::new_v4(), TOKEN);
        let state = Arc::new(Mutex::new(Seen {
            count_value: 3,
            upload_status: 200,
            ..Seen::default()
        }));
        let url = serve(state.clone()).await;
        let n = ensure_key_packages(&client(), &url, &session)
            .await
            .unwrap();
        assert_eq!(n, TARGET_COUNT - 3);
        let st = state.lock().unwrap();
        assert_eq!(st.uploads.iter().sum::<usize>() as u64, n);
        assert!(st.uploads.iter().all(|&b| b <= UPLOAD_BATCH));
        assert!(st
            .auth_headers
            .iter()
            .all(|h| h == &format!("Bearer {TOKEN}")));
        assert!(st.auth_headers.len() >= 2);
        drop(st);
        assert_eq!(
            PqKeys::load(&session.store).unwrap().entries.len() as u64,
            n
        );
        assert!(session.store.get(PROVIDER_RECORD).unwrap().is_some());
    }

    #[tokio::test]
    async fn no_upload_when_pool_is_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        let session = Session::for_test(seeded(&tmp), Uuid::new_v4(), TOKEN);
        let state = Arc::new(Mutex::new(Seen {
            count_value: LOW_WATERMARK,
            upload_status: 200,
            ..Seen::default()
        }));
        let url = serve(state.clone()).await;
        assert_eq!(
            ensure_key_packages(&client(), &url, &session)
                .await
                .unwrap(),
            0
        );
        assert!(state.lock().unwrap().uploads.is_empty());
        assert!(session.store.get(PQ_KEYS_RECORD).unwrap().is_none());
    }

    #[tokio::test]
    async fn upload_failure_is_typed_and_keys_stay_persisted() {
        let tmp = tempfile::tempdir().unwrap();
        let session = Session::for_test(seeded(&tmp), Uuid::new_v4(), TOKEN);
        let state = Arc::new(Mutex::new(Seen {
            upload_status: 500,
            ..Seen::default()
        }));
        let url = serve(state).await;
        let err = ensure_key_packages(&client(), &url, &session)
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::HttpStatus(500)));
        // Private halves were saved before the upload attempt.
        assert_eq!(
            PqKeys::load(&session.store).unwrap().entries.len() as u64,
            TARGET_COUNT
        );
    }
}
