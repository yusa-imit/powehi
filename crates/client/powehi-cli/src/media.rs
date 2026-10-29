//! Media attachments, the CLI side of prd.md §9.2 (slice 1: wire payload and file saving).
//!
//! A media message is an MLS application message whose plaintext is the JSON the web client
//! sends: `{"type":"image","blobId","blobHash":[32],"mediaKey":[32],"iv":[12],...}` (ADR-0004).
//! [`parse`] validates that JSON from an untrusted peer and keeps the key in `Zeroizing`.
//! [`save`] writes received bytes to a new `0600` file and never overwrites; the peer-chosen
//! file name is never used, so a hostile payload cannot pick a path. Nothing here logs.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use powehi_crypto_core::media::{BLOB_HASH_BYTES, MEDIA_IV_BYTES, MEDIA_KEY_BYTES};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Largest attachment `send --file` accepts and `save` writes (bytes of plaintext).
pub const MAX_MEDIA_BYTES: u64 = 64 * 1024 * 1024;
/// Largest media-message JSON `parse` looks at; a real payload is well under 1 KiB plus a
/// thumbnail of at most 16 KiB encoded as a number array.
const MAX_PAYLOAD_LEN: usize = 256 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MediaError {
    #[error("the attachment is larger than {MAX_MEDIA_BYTES} bytes")]
    TooLarge,
    #[error("the destination already exists; nothing was overwritten")]
    Exists,
    #[error("could not write the attachment")]
    Io,
}

/// A validated media attachment descriptor from a peer.
pub struct Payload {
    pub blob_id: Uuid,
    pub blob_hash: [u8; BLOB_HASH_BYTES],
    pub key: Zeroizing<[u8; MEDIA_KEY_BYTES]>,
    pub iv: [u8; MEDIA_IV_BYTES],
    /// True for the §9.4.2 chunked form; then `total_size` is the plaintext length.
    pub chunked: bool,
    pub total_size: Option<u64>,
}

/// Parse a decrypted message body as a media descriptor; `None` when it is anything else
/// (plain text, another structured type, malformed or out-of-bounds fields). The body is
/// peer plaintext, so nothing is copied into growable buffers or error strings: see
/// [`wire`] and `tests/media_residue.rs`.
pub fn parse(body: &[u8]) -> Option<Payload> {
    if body.len() > MAX_PAYLOAD_LEN || body.first() != Some(&b'{') {
        return None;
    }
    let p: Payload = serde_json::from_slice(body).ok()?;
    match (p.chunked, p.total_size) {
        (true, Some(n)) if n <= MAX_MEDIA_BYTES => Some(p),
        (true, _) => None,
        (false, _) => Some(Payload {
            total_size: None,
            ..p
        }),
    }
}

/// Allocation-free, value-free deserialisation of [`Payload`] (same approach as
/// `message::Structured`): the key is read element by element into a fixed `Zeroizing`
/// array, every rejection uses a fixed error text, and no `String` or `Vec` is built.
/// Known residual, as in `message::Structured`: serde_json's escape scratch buffer is freed
/// unwiped when a deserialised string (key, `type`, `blobId`) contains an escape; an honest
/// sender never produces one there.
mod wire {
    use serde::de::{self, Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

    use super::*;

    fn bad<E: de::Error>() -> E {
        E::custom("invalid media payload")
    }

    /// Overrides the listed `visit_*` methods to reject with the fixed error, so a peer value
    /// of an unexpected type is never copied into an error string.
    macro_rules! reject {
        ($($k:ident)*) => { $( reject!(@ $k); )* };
        (@ bool) => { fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> { Err(bad()) } };
        (@ i64) => { fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> { Err(bad()) } };
        (@ u64) => { fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> { Err(bad()) } };
        (@ f64) => { fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> { Err(bad()) } };
        (@ str) => { fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> { Err(bad()) } };
        (@ bytes) => { fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<Self::Value, E> { Err(bad()) } };
        (@ unit) => { fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> { Err(bad()) } };
        (@ seq) => { fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> { Err(bad()) } };
        (@ map) => { fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> { Err(bad()) } };
    }

    /// One array element, range-checked without echoing the value.
    struct Byte(u8);

    impl<'de> Deserialize<'de> for Byte {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Byte;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a byte")
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> Result<Byte, E> {
                    u8::try_from(v).map(Byte).map_err(|_| bad())
                }
                reject!(bool i64 f64 str bytes unit seq map);
            }
            d.deserialize_any(V)
        }
    }

    /// Exactly `N` bytes, in a `Zeroizing` array that is wiped on every error path.
    struct Fixed<const N: usize>(Zeroizing<[u8; N]>);

    impl<'de, const N: usize> Deserialize<'de> for Fixed<N> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V<const N: usize>;
            impl<'de, const N: usize> Visitor<'de> for V<N> {
                type Value = Fixed<N>;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a byte array")
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Fixed<N>, A::Error> {
                    let mut out = Zeroizing::new([0u8; N]);
                    for slot in out.iter_mut() {
                        *slot = s.next_element::<Byte>()?.ok_or_else(bad)?.0;
                    }
                    if s.next_element::<IgnoredAny>()?.is_some() {
                        return Err(bad());
                    }
                    Ok(Fixed(out))
                }
                reject!(bool i64 u64 f64 str bytes unit map);
            }
            d.deserialize_any(V::<N>)
        }
    }

    struct Kind;

    impl<'de> Deserialize<'de> for Kind {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Kind;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a media type")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Kind, E> {
                    if matches!(v, "image" | "video" | "file") {
                        Ok(Kind)
                    } else {
                        Err(bad())
                    }
                }
                reject!(bool i64 u64 f64 bytes unit seq map);
            }
            d.deserialize_any(V)
        }
    }

    struct Id(Uuid);

    impl<'de> Deserialize<'de> for Id {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Id;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a UUID")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Id, E> {
                    Uuid::parse_str(v).map(Id).map_err(|_| bad())
                }
                reject!(bool i64 u64 f64 bytes unit seq map);
            }
            d.deserialize_any(V)
        }
    }

    struct Flag(bool);

    impl<'de> Deserialize<'de> for Flag {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Flag;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a boolean")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> Result<Flag, E> {
                    Ok(Flag(v))
                }
                reject!(i64 u64 f64 str bytes unit seq map);
            }
            d.deserialize_any(V)
        }
    }

    struct Size(u64);

    impl<'de> Deserialize<'de> for Size {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Size;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a size")
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> Result<Size, E> {
                    Ok(Size(v))
                }
                reject!(bool i64 f64 str bytes unit seq map);
            }
            d.deserialize_any(V)
        }
    }

    #[derive(Clone, Copy)]
    enum Field {
        Type,
        BlobId,
        BlobHash,
        MediaKey,
        Iv,
        Chunked,
        TotalSize,
        Other,
    }

    impl<'de> Deserialize<'de> for Field {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl Visitor<'_> for V {
                type Value = Field;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("an object key")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Field, E> {
                    Ok(match v {
                        "type" => Field::Type,
                        "blobId" => Field::BlobId,
                        "blobHash" => Field::BlobHash,
                        "mediaKey" => Field::MediaKey,
                        "iv" => Field::Iv,
                        "chunked" => Field::Chunked,
                        "totalSize" => Field::TotalSize,
                        _ => Field::Other,
                    })
                }
            }
            d.deserialize_identifier(V)
        }
    }

    fn once<T, E: de::Error>(slot: &mut Option<T>, v: T) -> Result<(), E> {
        if slot.replace(v).is_some() {
            Err(bad())
        } else {
            Ok(())
        }
    }

    impl<'de> Deserialize<'de> for Payload {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Payload;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a media payload")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Payload, A::Error> {
                    let (mut kind, mut id, mut hash) = (None, None, None);
                    let (mut key, mut iv) = (None, None);
                    let (mut chunked, mut total) = (None, None);
                    while let Some(f) = m.next_key::<Field>()? {
                        match f {
                            Field::Type => {
                                m.next_value::<Kind>()?;
                                once(&mut kind, ())?;
                            }
                            Field::BlobId => once(&mut id, m.next_value::<Id>()?.0)?,
                            Field::BlobHash => once(&mut hash, m.next_value::<Fixed<32>>()?.0)?,
                            Field::MediaKey => once(&mut key, m.next_value::<Fixed<32>>()?.0)?,
                            Field::Iv => once(&mut iv, m.next_value::<Fixed<12>>()?.0)?,
                            Field::Chunked => once(&mut chunked, m.next_value::<Flag>()?.0)?,
                            Field::TotalSize => once(&mut total, m.next_value::<Size>()?.0)?,
                            Field::Other => {
                                m.next_value::<IgnoredAny>()?;
                            }
                        }
                    }
                    let (Some(()), Some(blob_id), Some(hash), Some(key), Some(iv)) =
                        (kind, id, hash, key, iv)
                    else {
                        return Err(bad());
                    };
                    Ok(Payload {
                        blob_id,
                        blob_hash: *hash,
                        key,
                        iv: *iv,
                        chunked: chunked.unwrap_or(false),
                        total_size: total,
                    })
                }
            }
            d.deserialize_map(V)
        }
    }
}

/// Write `bytes` to `dir/powehi-<blob_id>` as a new `0600` file and return its path.
/// The bytes go to a temporary name first and are linked into place only when complete, so
/// the final name is never a partial file; an existing path (file or symlink) is never
/// followed or replaced ([`MediaError::Exists`] means "something is already there", not
/// "your attachment is saved"). `dir` must be private: not group/other writable.
pub fn save(dir: &Path, blob_id: &Uuid, bytes: &[u8]) -> Result<PathBuf, MediaError> {
    assert!(!dir.as_os_str().is_empty(), "dir must be set");
    if bytes.len() as u64 > MAX_MEDIA_BYTES {
        return Err(MediaError::TooLarge);
    }
    let meta = std::fs::metadata(dir).map_err(|_| MediaError::Io)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o022 != 0 {
        return Err(MediaError::Io);
    }
    let path = dir.join(format!("powehi-{}", blob_id.simple()));
    let tmp = dir.join(format!(".powehi-tmp-{}", Uuid::new_v4().simple()));
    let written = write_new(&tmp, bytes).and_then(|()| std::fs::hard_link(&tmp, &path));
    let _ = std::fs::remove_file(&tmp);
    match written {
        Ok(()) => Ok(path),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(MediaError::Exists),
        Err(_) => Err(MediaError::Io),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(extra: &str, key_len: usize) -> Vec<u8> {
        let arr = |b: u8, n: usize| format!("{:?}", vec![b; n]);
        format!(
            r#"{{"type":"image","blobId":"{}","blobHash":{},"mediaKey":{},"iv":{}{extra}}}"#,
            Uuid::from_u128(9),
            arr(1, 32),
            arr(7, key_len),
            arr(2, 12)
        )
        .into_bytes()
    }

    #[test]
    fn parses_web_payload() {
        let p = parse(&json(r#","mimeType":"image/png""#, 32)).unwrap();
        assert_eq!(p.key.as_slice(), &[7u8; 32]);
        assert_eq!(p.blob_hash, [1u8; 32]);
        assert_eq!(p.iv, [2u8; 12]);
        assert_eq!(p.blob_id, Uuid::from_u128(9));
        assert!(!p.chunked);
    }

    #[test]
    fn rejects_text_and_bad_shapes() {
        assert!(parse(b"hello").is_none());
        assert!(parse(&json("", 31)).is_none());
        assert!(parse(&json("", 33)).is_none());
        assert!(parse(br#"{"type":"text","text":"x"}"#).is_none());
        let huge = vec![b'{'; MAX_PAYLOAD_LEN + 1];
        assert!(parse(&huge).is_none());
    }

    #[test]
    fn rejects_wrong_lengths_dups_and_kinds() {
        let ok = String::from_utf8(json("", 32)).unwrap();
        let hash7 = format!("{:?}", vec![1u8; 32]);
        let iv7 = format!("{:?}", vec![2u8; 12]);
        let key7 = format!("{:?}", vec![7u8; 32]);
        for bad in [
            ok.replace(&hash7, &format!("{:?}", vec![7u8; 31])),
            ok.replace(&hash7, &format!("{:?}", vec![7u8; 33])),
            ok.replace(&iv7, &format!("{:?}", vec![7u8; 11])),
            ok.replace(&iv7, &format!("{:?}", vec![7u8; 13])),
            ok.replace(r#""type":"image""#, r#""type":"text""#),
            ok.replace(r#""type":"image","#, r#""type":"image","type":"image","#),
            ok.replace(&iv7, "[300,1,1,1,1,1,1,1,1,1,1,1]"),
            ok.replace(r#""iv":"#, &format!(r#""iv":{iv7},"iv":"#)),
            ok.replace(
                r#""blobHash":"#,
                &format!(r#""blobHash":{hash7},"blobHash":"#),
            ),
            ok.replace(
                r#""mediaKey":"#,
                &format!(r#""mediaKey":{key7},"mediaKey":"#),
            ),
            ok.replace(r#""type":"image""#, r#""type":"image","chunked":"yes""#),
            ok.replace(r#""type":"image""#, r#""type":"image","totalSize":-1"#),
        ] {
            assert!(parse(bad.as_bytes()).is_none(), "{bad}");
        }
        for kind in ["video", "file"] {
            let k = ok.replace("image", kind);
            assert!(parse(k.as_bytes()).is_some());
        }
    }

    #[test]
    fn chunked_needs_bounded_size() {
        assert!(parse(&json(r#","chunked":true"#, 32)).is_none());
        let over = format!(r#","chunked":true,"totalSize":{}"#, MAX_MEDIA_BYTES + 1);
        assert!(parse(&json(&over, 32)).is_none());
        let ok = parse(&json(r#","chunked":true,"totalSize":10"#, 32)).unwrap();
        assert_eq!(ok.total_size, Some(10));
    }

    #[test]
    fn save_is_0600_and_never_overwrites() {
        let d = tempfile::tempdir().unwrap();
        let id = Uuid::from_u128(1);
        let p = save(d.path(), &id, b"abc").unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&p).unwrap(), b"abc");
        assert_eq!(save(d.path(), &id, b"zzz"), Err(MediaError::Exists));
        assert_eq!(std::fs::read(&p).unwrap(), b"abc");
    }

    #[test]
    fn nonchunked_total_size_is_dropped() {
        let p = parse(&json(r#","totalSize":18446744073709551615"#, 32)).unwrap();
        assert_eq!(p.total_size, None);
    }

    #[test]
    fn save_rejects_shared_dir_and_leaves_no_temp() {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            save(d.path(), &Uuid::from_u128(3), b"x"),
            Err(MediaError::Io)
        );
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        save(d.path(), &Uuid::from_u128(3), b"x").unwrap();
        save(d.path(), &Uuid::from_u128(3), b"y").unwrap_err();
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn save_does_not_follow_symlink() {
        let d = tempfile::tempdir().unwrap();
        let id = Uuid::from_u128(2);
        let target = d.path().join("victim");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, d.path().join(format!("powehi-{}", id.simple())))
            .unwrap();
        assert!(save(d.path(), &id, b"x").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }
}
