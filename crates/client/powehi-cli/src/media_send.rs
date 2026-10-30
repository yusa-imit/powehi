//! `send --file`, the sender half of prd.md §9.2 (8.21 slice 2): read a file, encrypt it, upload
//! the ciphertext to the pre-signed URL and build the media descriptor the peer parses with
//! [`crate::media::parse`].
//!
//! The server only ever sees the ciphertext size and hash (it hands out the URL; the PUT goes to
//! object storage). The file bytes and the media key live in `Zeroizing` buffers here; known
//! residual: openmls copies the descriptor (key included) into unwiped internal buffers when it
//! encrypts it, as on the receive side (`mls_group.rs`). The upload
//! client is separate from the pinned API client and the bearer token is never sent to it.
//! Nothing here logs a path, a name, a key or a URL.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use powehi_crypto_core::media as core_media;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::Session;
use crate::identity::{self, IdentityError};
use crate::invite::{api, json_post, InviteError, SMALL_BODY};
use crate::media::MAX_MEDIA_BYTES;

/// Content type signed into the pre-signed URL; the PUT must repeat it exactly.
const CONTENT_TYPE: &str = "application/octet-stream";
/// Plaintext above this goes the §9.4.2 chunked way (same threshold as the web client).
pub const CHUNK_THRESHOLD: u64 = core_media::MEDIA_CHUNK_SIZE as u64;
/// Room for the descriptor JSON so serialising never reallocates (a realloc leaves a copy).
const PAYLOAD_CAPACITY: usize = 1024;

#[derive(Debug, Error)]
pub enum SendFileError {
    #[error("could not read the file (it must be a regular, non-empty file)")]
    Unreadable,
    #[error("the file is larger than {MAX_MEDIA_BYTES} bytes")]
    TooLarge,
    #[error("encryption failed")]
    Encrypt,
    #[error("{0}")]
    Server(#[from] IdentityError),
    #[error("{0}")]
    Invite(#[from] InviteError),
    #[error("the server returned an unusable upload address")]
    BadUploadUrl,
    #[error("the upload to object storage failed")]
    UploadFailed,
}

/// An encrypted attachment ready to upload.
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    key: Zeroizing<[u8; core_media::MEDIA_KEY_BYTES]>,
    iv: [u8; core_media::MEDIA_IV_BYTES],
    hash: [u8; core_media::BLOB_HASH_BYTES],
    /// Plaintext length when chunked, else `None`.
    total: Option<u64>,
}

/// Reads a regular, non-empty file of at most `cap` bytes into a wiping buffer. The size is
/// checked on the open handle and the read is bounded, so a file that grows or a FIFO cannot
/// make this allocate more than `cap + 1`.
pub fn read_file(path: &Path, cap: u64) -> Result<Zeroizing<Vec<u8>>, SendFileError> {
    assert!(cap <= MAX_MEDIA_BYTES);
    // O_NONBLOCK so opening a FIFO with no writer returns at once; the `is_file` check below
    // then rejects it. It has no effect on reads from a regular file.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| SendFileError::Unreadable)?;
    let meta = f.metadata().map_err(|_| SendFileError::Unreadable)?;
    if !meta.is_file() || meta.len() == 0 {
        return Err(SendFileError::Unreadable);
    }
    if meta.len() > cap {
        return Err(SendFileError::TooLarge);
    }
    // Capacity is cap + 1, never the file's claimed size growing past it: `read_to_end` on a
    // full Vec would reallocate and leave an unwiped copy.
    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize + 1));
    f.take(meta.len() + 1)
        .read_to_end(&mut buf)
        .map_err(|_| SendFileError::Unreadable)?;
    if buf.len() as u64 > cap || buf.len() as u64 != meta.len() {
        return Err(SendFileError::Unreadable);
    }
    Ok(buf)
}

/// Encrypts `plain` (non-empty, within the cap): one AES-GCM blob up to [`CHUNK_THRESHOLD`],
/// fixed-size chunks above it.
pub fn seal(plain: &[u8]) -> Result<Sealed, SendFileError> {
    assert!(!plain.is_empty() && plain.len() as u64 <= MAX_MEDIA_BYTES);
    if plain.len() as u64 > CHUNK_THRESHOLD {
        let r = core_media::encrypt_chunked(plain).map_err(|_| SendFileError::Encrypt)?;
        return Ok(Sealed {
            ciphertext: r.ciphertext,
            key: r.key,
            iv: r.base_iv,
            hash: r.blob_hash,
            total: Some(r.total_plaintext_len),
        });
    }
    let (ciphertext, key, iv, hash) =
        core_media::encrypt(plain).map_err(|_| SendFileError::Encrypt)?;
    Ok(Sealed {
        ciphertext,
        key,
        iv,
        hash,
        total: None,
    })
}

#[derive(Serialize)]
struct Descriptor<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "blobId")]
    blob_id: Uuid,
    #[serde(rename = "blobHash")]
    blob_hash: &'a [u8],
    #[serde(rename = "mediaKey")]
    media_key: &'a [u8],
    iv: &'a [u8],
    #[serde(rename = "mimeType")]
    mime_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunked: Option<bool>,
    #[serde(rename = "totalSize", skip_serializing_if = "Option::is_none")]
    total_size: Option<u64>,
    #[serde(rename = "chunkSize", skip_serializing_if = "Option::is_none")]
    chunk_size: Option<u64>,
}

/// The media message body (the JSON the web client sends) for an uploaded blob.
pub fn descriptor(s: &Sealed, blob_id: Uuid) -> Result<Zeroizing<Vec<u8>>, SendFileError> {
    let chunked = s.total.is_some();
    let d = Descriptor {
        // The web client's discriminators (prd §9.2/§9.4.2): "image", and "video" when chunked.
        // Anything else would make a web peer print this JSON, key included, as chat text.
        kind: if chunked { "video" } else { "image" },
        blob_id,
        blob_hash: &s.hash,
        media_key: s.key.as_slice(),
        iv: &s.iv,
        mime_type: CONTENT_TYPE,
        chunked: chunked.then_some(true),
        total_size: s.total,
        chunk_size: chunked.then_some(core_media::MEDIA_CHUNK_SIZE as u64),
    };
    let mut out = Zeroizing::new(Vec::with_capacity(PAYLOAD_CAPACITY));
    serde_json::to_writer(&mut *out, &d).map_err(|_| SendFileError::Encrypt)?;
    assert!(out.len() <= PAYLOAD_CAPACITY && out.len() <= crate::message::MAX_BODY_LEN);
    Ok(out)
}

#[derive(Deserialize)]
struct UploadGrant {
    media_id: Uuid,
    upload_url: String,
}

/// Asks the server for an upload slot and PUTs the ciphertext there, then confirms it.
/// `put` is the unauthenticated object-storage client. The upload address must be HTTPS (or on
/// the API's own origin, which only a local test server is).
pub async fn upload(
    client: &Client,
    put: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    sealed: &Sealed,
) -> Result<Uuid, SendFileError> {
    #[derive(Serialize)]
    struct Req {
        content_type: &'static str,
        size_bytes: u64,
        group_id: Uuid,
    }
    let req = json_post(
        client,
        api(server, "/v1/media/upload-url")?,
        &Req {
            content_type: CONTENT_TYPE,
            size_bytes: sealed.ciphertext.len() as u64,
            group_id,
        },
    )?;
    let raw = identity::send_raw(req, session, SMALL_BODY).await?;
    let grant: UploadGrant =
        serde_json::from_slice(&raw).map_err(|_| SendFileError::BadUploadUrl)?;
    let url = Url::parse(&grant.upload_url).map_err(|_| SendFileError::BadUploadUrl)?;
    let same_origin = url.origin() == server.origin();
    if url.scheme() != "https" && !same_origin {
        return Err(SendFileError::BadUploadUrl);
    }
    let resp = put
        .put(url)
        .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
        .body(sealed.ciphertext.clone())
        .send()
        .await
        .map_err(|_| SendFileError::UploadFailed)?;
    if !resp.status().is_success() {
        return Err(SendFileError::UploadFailed);
    }
    let confirm = client.post(api(
        server,
        &format!("/v1/media/{}/confirm", grant.media_id),
    )?);
    identity::send_raw(confirm, session, SMALL_BODY).await?;
    Ok(grant.media_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::parse;

    #[test]
    fn descriptor_round_trips_through_parse_small() {
        let s = seal(b"hello attachment").unwrap();
        let id = Uuid::from_u128(5);
        let p = parse(&descriptor(&s, id).unwrap()).expect("peer accepts our descriptor");
        assert_eq!(p.blob_id, id);
        assert_eq!(p.key.as_slice(), s.key.as_slice());
        assert_eq!((p.blob_hash, p.iv), (s.hash, s.iv));
        assert!(!p.chunked && p.total_size.is_none());
        let plain =
            core_media::decrypt_with_raw_key(p.key.as_slice(), &p.iv, &s.ciphertext, &p.blob_hash)
                .unwrap();
        assert_eq!(plain, b"hello attachment");
    }

    #[test]
    fn large_file_is_chunked_and_descriptor_says_so() {
        let plain = vec![7u8; CHUNK_THRESHOLD as usize + 1];
        let s = seal(&plain).unwrap();
        assert_eq!(s.ciphertext.len(), 2 * (core_media::MEDIA_CHUNK_SIZE + 16));
        let p = parse(&descriptor(&s, Uuid::from_u128(6)).unwrap()).unwrap();
        assert!(p.chunked);
        assert_eq!(p.total_size, Some(plain.len() as u64));
        let back = core_media::decrypt_chunked(
            &p.key,
            &p.iv,
            &s.ciphertext,
            p.total_size.unwrap(),
            &p.blob_hash,
        )
        .unwrap();
        assert!(back == plain);
    }

    #[test]
    fn exact_threshold_stays_single_blob() {
        let s = seal(&vec![1u8; CHUNK_THRESHOLD as usize]).unwrap();
        assert!(s.total.is_none());
    }

    #[test]
    fn read_file_enforces_regular_nonempty_and_cap() {
        let dir = std::env::temp_dir().join(format!("powehi-ms-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let f = dir.join("a");
        std::fs::write(&f, b"12345").unwrap();
        assert_eq!(read_file(&f, 5).unwrap().as_slice(), b"12345");
        assert!(matches!(read_file(&f, 4), Err(SendFileError::TooLarge)));
        std::fs::write(&f, b"").unwrap();
        assert!(matches!(read_file(&f, 5), Err(SendFileError::Unreadable)));
        assert!(matches!(read_file(&dir, 5), Err(SendFileError::Unreadable)));
        assert!(matches!(
            read_file(&dir.join("missing"), 5),
            Err(SendFileError::Unreadable)
        ));
        let fifo = dir.join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            read_file(&fifo, 5),
            Err(SendFileError::Unreadable)
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
