//! Receiving an attachment, the receiver half of prd.md §9.2 (8.21 slice 3): fetch the
//! ciphertext from the pre-signed GET URL, check its hash, decrypt it.
//!
//! The body-size cap is derived from the validated descriptor and applied while reading, so a
//! hostile or swapped blob can never make this buffer more than the descriptor allows
//! (non-chunked: plaintext cap + 16-byte tag; chunked: `ceil(total / 16 MiB)` full chunks).
//! The blob hash is checked before any decryption (crypto-core R-2). The plaintext comes back in
//! a `Zeroizing` buffer; writing it to disk is a separate, explicit step ([`crate::media::save`]).
//! The download client never carries the bearer token. Nothing here logs a URL, key or name.

use powehi_crypto_core::media as core_media;
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::auth::Session;
use crate::identity::{self, IdentityError};
use crate::invite::{api, InviteError, SMALL_BODY};
use crate::media::{Payload, MAX_MEDIA_BYTES};

const GCM_TAG: u64 = 16;
const CHUNK_CT: u64 = core_media::MEDIA_CHUNK_SIZE as u64 + GCM_TAG;

#[derive(Debug, Error)]
pub enum RecvFileError {
    #[error("{0}")]
    Server(#[from] IdentityError),
    #[error("{0}")]
    Invite(#[from] InviteError),
    #[error("the server returned an unusable download address")]
    BadDownloadUrl,
    #[error("the download from object storage failed")]
    DownloadFailed,
    #[error("the attachment is larger than its message says")]
    TooLarge,
    #[error("the attachment failed its integrity check or could not be decrypted")]
    Corrupt,
}

/// Largest ciphertext the descriptor `p` can legitimately describe.
pub fn max_ciphertext_len(p: &Payload) -> u64 {
    assert!(!p.chunked || p.total_size.is_some_and(|n| n <= MAX_MEDIA_BYTES));
    match (p.chunked, p.total_size) {
        (true, Some(total)) => {
            total.div_ceil(core_media::MEDIA_CHUNK_SIZE as u64).max(1) * CHUNK_CT
        }
        _ => MAX_MEDIA_BYTES + GCM_TAG,
    }
}

/// Verifies the blob hash, then decrypts `ciphertext` as described by `p`.
pub fn open(p: &Payload, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, RecvFileError> {
    assert!(!p.chunked || p.total_size.is_some_and(|n| n <= MAX_MEDIA_BYTES));
    let plain = match (p.chunked, p.total_size) {
        (true, Some(total)) => {
            core_media::decrypt_chunked(&p.key, &p.iv, ciphertext, total, &p.blob_hash)
        }
        _ => core_media::decrypt_with_raw_key(p.key.as_slice(), &p.iv, ciphertext, &p.blob_hash),
    }
    .map_err(|_| RecvFileError::Corrupt)?;
    let plain = Zeroizing::new(plain);
    if plain.len() as u64 > MAX_MEDIA_BYTES {
        return Err(RecvFileError::TooLarge);
    }
    Ok(plain)
}

/// Reads the response body into memory, failing as soon as it passes `cap` bytes (the
/// `Content-Length` header is only a fast path; it is not trusted).
async fn read_bounded(mut resp: reqwest::Response, cap: u64) -> Result<Vec<u8>, RecvFileError> {
    if !resp.status().is_success() {
        return Err(RecvFileError::DownloadFailed);
    }
    if resp.content_length().is_some_and(|n| n > cap) {
        return Err(RecvFileError::TooLarge);
    }
    // Size the buffer once from the (already cap-checked) header so growth never doubles it.
    let mut buf = Vec::with_capacity(resp.content_length().map_or(0, |n| n as usize));
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| RecvFileError::DownloadFailed)?
    {
        if buf.len() as u64 + chunk.len() as u64 > cap {
            return Err(RecvFileError::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// The download address must be HTTPS, or on the API's own origin (a local test server).
fn check_url(url: &Url, server: &Url) -> Result<(), RecvFileError> {
    if url.scheme() != "https" && url.origin() != server.origin() {
        return Err(RecvFileError::BadDownloadUrl);
    }
    Ok(())
}

#[derive(Deserialize)]
struct DownloadGrant {
    download_url: String,
}

/// Fetches and decrypts the attachment `p`. `get` is the unauthenticated object-storage client.
/// The download address must be HTTPS (or on the API's own origin, i.e. a local test server).
pub async fn download(
    client: &Client,
    get: &Client,
    server: &Url,
    session: &Session,
    p: &Payload,
) -> Result<Zeroizing<Vec<u8>>, RecvFileError> {
    let req = client.get(api(
        server,
        &format!("/v1/media/{}/download-url", p.blob_id),
    )?);
    let raw = identity::send_raw(req, session, SMALL_BODY).await?;
    let grant: DownloadGrant =
        serde_json::from_slice(&raw).map_err(|_| RecvFileError::BadDownloadUrl)?;
    let url = Url::parse(&grant.download_url).map_err(|_| RecvFileError::BadDownloadUrl)?;
    check_url(&url, server)?;
    let resp = get
        .get(url)
        .send()
        .await
        .map_err(|_| RecvFileError::DownloadFailed)?;
    let ciphertext = read_bounded(resp, max_ciphertext_len(p)).await?;
    open(p, &ciphertext)
}

/// Tells the server the attachment was downloaded (it counts toward blob cleanup).
pub async fn confirm(
    client: &Client,
    server: &Url,
    session: &Session,
    blob_id: &uuid::Uuid,
) -> Result<(), RecvFileError> {
    let req = client.post(api(
        server,
        &format!("/v1/media/{blob_id}/confirm-download"),
    )?);
    identity::send_raw(req, session, SMALL_BODY).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::parse;
    use crate::media_send::{descriptor, seal};
    use tokio::io::AsyncWriteExt;
    use uuid::Uuid;

    fn payload_for(plain: &[u8]) -> (Payload, Vec<u8>) {
        let s = seal(plain).unwrap();
        let p = parse(&descriptor(&s, Uuid::from_u128(1)).unwrap()).unwrap();
        (p, s.ciphertext.clone())
    }

    #[test]
    fn open_round_trips_single_blob() {
        let (p, ct) = payload_for(b"hello attachment");
        assert_eq!(open(&p, &ct).unwrap().as_slice(), b"hello attachment");
        assert_eq!(max_ciphertext_len(&p), MAX_MEDIA_BYTES + 16);
    }

    #[test]
    fn open_round_trips_chunked_and_caps_at_chunk_count() {
        let plain = vec![9u8; core_media::MEDIA_CHUNK_SIZE + 1];
        let (p, ct) = payload_for(&plain);
        assert_eq!(max_ciphertext_len(&p), 2 * CHUNK_CT);
        assert_eq!(ct.len() as u64, max_ciphertext_len(&p));
        assert!(*open(&p, &ct).unwrap() == plain);
    }

    #[test]
    fn open_rejects_tampering_and_swaps() {
        let (p, mut ct) = payload_for(b"hello attachment");
        ct[0] ^= 1;
        assert!(matches!(open(&p, &ct), Err(RecvFileError::Corrupt)));
        let (_, other) = payload_for(b"another attachment");
        assert!(matches!(open(&p, &other), Err(RecvFileError::Corrupt)));
        assert!(matches!(open(&p, &[]), Err(RecvFileError::Corrupt)));
    }

    #[test]
    fn download_url_rule() {
        let server = Url::parse("http://127.0.0.1:8080/").unwrap();
        let ok = |u: &str| check_url(&Url::parse(u).unwrap(), &server).is_ok();
        assert!(ok("https://blobs.example.com/x?sig=1"));
        assert!(ok("http://127.0.0.1:8080/blob"));
        assert!(!ok("http://blobs.example.com/x"));
        assert!(!ok("http://127.0.0.1:9999/x"));
        assert!(!ok("ftp://127.0.0.1:8080/x"));
        assert!(!ok("file:///etc/passwd"));
    }

    async fn serve_once(response: Vec<u8>) -> Url {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", l.local_addr().unwrap())).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut s, &mut scratch).await;
            let _ = s.write_all(&response).await;
        });
        url
    }

    fn http(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
        let mut r = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{extra}\r\n").into_bytes();
        r.extend_from_slice(body);
        r
    }

    async fn read(response: Vec<u8>, cap: u64) -> Result<Vec<u8>, RecvFileError> {
        let url = serve_once(response).await;
        read_bounded(reqwest::get(url).await.unwrap(), cap).await
    }

    #[tokio::test]
    async fn read_bounded_enforces_cap_with_and_without_content_length() {
        let body = [5u8; 64];
        let ok = http("200 OK", "Content-Length: 64\r\n", &body);
        assert_eq!(read(ok, 64).await.unwrap(), body);
        let lying_header = http("200 OK", "Content-Length: 64\r\n", &body);
        assert!(matches!(
            read(lying_header, 63).await,
            Err(RecvFileError::TooLarge)
        ));
        let no_length = http("200 OK", "", &body);
        assert!(matches!(
            read(no_length, 63).await,
            Err(RecvFileError::TooLarge)
        ));
        let denied = http("403 Forbidden", "Content-Length: 0\r\n", &[]);
        assert!(matches!(
            read(denied, 64).await,
            Err(RecvFileError::DownloadFailed)
        ));
    }
}
