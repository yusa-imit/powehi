//! `media_recv::open` must leave no unwiped heap copy of the decrypted attachment or of the
//! media key (8.21 slice 5, 8.23 carry). Same scanning allocator as `media_residue.rs`.
//! Only the window around `open` is measured; the test's own encrypt step is outside it.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use powehi_cli::media::Payload;
use powehi_cli::media_recv::open;
use powehi_crypto_core::media as core_media;
use uuid::Uuid;
use zeroize::Zeroizing;

const TEXT_MARK: &[u8] = b"ZQXSECRET-ATTACHMENT";
/// First 8 bytes of the media key under test (0 = scanning off for the key).
static KEY_PREFIX: AtomicU64 = AtomicU64::new(0);
static LEAKED: AtomicUsize = AtomicUsize::new(0);

struct Scan;

fn scan(ptr: *mut u8, len: usize) {
    // SAFETY: called with a live block of `len` bytes, right before it is freed/moved.
    let block = unsafe { std::slice::from_raw_parts(ptr, len) };
    let key = KEY_PREFIX.load(Ordering::SeqCst).to_le_bytes();
    let hit = block.windows(TEXT_MARK.len()).any(|w| w == TEXT_MARK)
        || (key != [0; 8] && block.windows(key.len()).any(|w| w == key));
    if hit {
        LEAKED.fetch_add(1, Ordering::SeqCst);
    }
}

// SAFETY: delegates every operation to `System`; `scan` only reads the block.
unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        scan(p, l.size());
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        scan(p, l.size());
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Scan = Scan;

fn measure(p: &Payload, ciphertext: &[u8], expect_ok: bool, name: &str) {
    drop(open(p, ciphertext)); // warm up lazy statics
    LEAKED.store(0, Ordering::SeqCst);
    let out = open(p, ciphertext);
    assert_eq!(out.is_ok(), expect_ok, "open result: {name}");
    drop(out);
    assert_eq!(LEAKED.load(Ordering::SeqCst), 0, "unwiped copy: {name}");
}

// One test only: the counters are process-global.
#[test]
fn open_leaves_no_unwiped_copy() {
    let mut plain = TEXT_MARK.to_vec();
    plain.extend_from_slice(&[7; 64]);

    let (ct, key, iv, hash) = core_media::encrypt(&plain).unwrap();
    let single = Payload {
        blob_id: Uuid::nil(),
        blob_hash: hash,
        key: Zeroizing::new(*key),
        iv,
        chunked: false,
        total_size: None,
    };
    let mut bad = ct.clone();
    bad[0] ^= 1;
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&key[..8]);
    KEY_PREFIX.store(u64::from_le_bytes(prefix), Ordering::SeqCst);
    measure(&single, &ct, true, "single");
    measure(&single, &bad, false, "single, tampered");

    let r = core_media::encrypt_chunked(&plain).unwrap();
    prefix.copy_from_slice(&r.key[..8]);
    KEY_PREFIX.store(u64::from_le_bytes(prefix), Ordering::SeqCst);
    let chunked = Payload {
        blob_id: Uuid::nil(),
        blob_hash: r.blob_hash,
        key: Zeroizing::new(*r.key),
        iv: r.base_iv,
        chunked: true,
        total_size: Some(r.total_plaintext_len),
    };
    let mut bad = r.ciphertext.clone();
    bad[0] ^= 1;
    measure(&chunked, &r.ciphertext, true, "chunked");
    measure(&chunked, &bad, false, "chunked, tampered");
}
