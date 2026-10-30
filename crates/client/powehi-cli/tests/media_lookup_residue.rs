//! `message::find_attachment` / `load_candidate` must leave no unwiped heap copy of the media
//! key (8.21 slice 6, 8.23 carry). Same scanning allocator as `media_open_residue.rs`. Only
//! the window around the two calls is measured; storing the record is outside it.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use powehi_cli::media_send::{descriptor, seal};
use powehi_cli::message::{find_attachment, load_candidate};
use powehi_cli::profile::ProfilePaths;
use powehi_cli::store::ProfileStore;
use uuid::Uuid;

/// First 8 bytes of the media key under test (0 = scanning off).
static KEY_PREFIX: AtomicU64 = AtomicU64::new(0);
static LEAKED: AtomicUsize = AtomicUsize::new(0);

struct Scan;

fn scan(ptr: *mut u8, len: usize) {
    let key = KEY_PREFIX.load(Ordering::SeqCst).to_le_bytes();
    if key == [0; 8] {
        return;
    }
    // SAFETY: called with a live block of `len` bytes, right before it is freed/moved.
    let block = unsafe { std::slice::from_raw_parts(ptr, len) };
    if block.windows(key.len()).any(|w| w == key) {
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn lookup(store: &ProfileStore, gid: Uuid) -> bool {
    let cands = find_attachment(store, gid, "abcdef").unwrap();
    let p = load_candidate(store, &cands[0]).unwrap();
    p.is_some()
}

// One test only: the counters are process-global.
#[test]
fn attachment_lookup_leaves_no_unwiped_key() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = ProfilePaths::resolve(tmp.path(), "residue").unwrap();
    let store = ProfileStore::open(&paths, &[9u8; 32]).unwrap();
    let gid = Uuid::from_u128(1);
    let blob = Uuid::from_u128(0xabcdef12_3456_7890_abcd_ef1234567890);
    let sealed = seal(&[7u8; 64]).unwrap();
    let body = descriptor(&sealed, blob).unwrap();
    let rec = format!(
        r#"{{"group_id":"{gid}","sender":"{}","body":"{}","received_at":1}}"#,
        Uuid::from_u128(2),
        hex(&body)
    );
    store.put("rx-0000", rec.as_bytes()).unwrap();
    // The key bytes: recover them from the parsed payload (the test's own copy, Zeroizing).
    let cands = find_attachment(&store, gid, "abcdef").unwrap();
    let payload = load_candidate(&store, &cands[0]).unwrap().unwrap();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&payload.key[..8]);
    drop(payload);
    drop(cands);

    assert!(lookup(&store, gid)); // warm up lazy statics
    KEY_PREFIX.store(u64::from_le_bytes(prefix), Ordering::SeqCst);
    LEAKED.store(0, Ordering::SeqCst);
    assert!(lookup(&store, gid));
    KEY_PREFIX.store(0, Ordering::SeqCst);
    assert_eq!(LEAKED.load(Ordering::SeqCst), 0, "unwiped key copy");
}
