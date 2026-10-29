//! `media::parse` must leave no unwiped copy of the media key or of peer text on the heap
//! (crypto-reviewer, cycle 691). Same scanning allocator as `render_residue.rs`. Known
//! residual, not tested: serde_json's escape scratch buffer for escaped strings.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use powehi_cli::media::parse;

/// Key bytes are all 0x5A, so any freed block holding 8 of them is a leaked key fragment.
const KEY_MARK: [u8; 8] = [0x5A; 8];
const TEXT_MARK: &[u8] = b"ZQXSECRET";
static LEAKED: AtomicUsize = AtomicUsize::new(0);

struct Scan;

fn scan(ptr: *mut u8, len: usize) {
    // SAFETY: called with a live block of `len` bytes, right before it is freed/moved.
    let block = unsafe { std::slice::from_raw_parts(ptr, len) };
    let hit = block.windows(KEY_MARK.len()).any(|w| w == KEY_MARK)
        || block.windows(TEXT_MARK.len()).any(|w| w == TEXT_MARK);
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

fn arr(byte: u8, n: usize) -> String {
    let items = vec![byte.to_string(); n];
    format!("[{}]", items.join(","))
}

fn residue(body: &[u8]) -> (usize, bool) {
    LEAKED.store(0, Ordering::SeqCst);
    let out = parse(body);
    let parsed = out.is_some();
    drop(out);
    (LEAKED.load(Ordering::SeqCst), parsed)
}

// One test only: the counter is process-global.
#[test]
fn parse_leaves_no_unwiped_copy() {
    let id = "00000000-0000-0000-0000-000000000000";
    let (hash, key, iv) = (arr(1, 32), arr(0x5A, 32), arr(2, 12));
    let ok = format!(
        r#"{{"type":"image","blobId":"{id}","blobHash":{hash},"mediaKey":{key},"iv":{iv}}}"#
    );
    let chunked = format!(
        r#"{{"type":"video","blobId":"{id}","blobHash":{hash},"mediaKey":{key},"iv":{iv},"chunked":true,"totalSize":5}}"#
    );
    let no_iv = format!(r#"{{"mediaKey":{key},"type":"image"}}"#);
    let null_chunked = format!(
        r#"{{"type":"image","blobId":"{id}","blobHash":{hash},"mediaKey":{key},"iv":{iv},"chunked":null}}"#
    );
    let dup_key = format!(r#"{{"mediaKey":{key},"mediaKey":{key}}}"#);
    let long_key = format!(r#"{{"mediaKey":{}}}"#, arr(0x5A, 33));
    let str_key = r#"{"mediaKey":"ZQXSECRET"}"#.to_string();
    let type_text = r#"{"type":"ZQXSECRET"}"#.to_string();
    let str_chunked = format!(
        r#"{{"type":"image","blobId":"{id}","blobHash":{hash},"mediaKey":{key},"iv":{iv},"chunked":"ZQXSECRET"}}"#
    );
    let str_total = format!(
        r#"{{"type":"image","blobId":"{id}","blobHash":{hash},"mediaKey":{key},"iv":{iv},"chunked":true,"totalSize":"ZQXSECRET"}}"#
    );
    let thumb = format!(
        r#"{{"type":"image","blobId":"{id}","blobHash":{hash},"mediaKey":{key},"iv":{iv},"thumbnail":{{"ct":[1],"key":{key},"iv":{iv}}}}}"#
    );
    let dup_full = format!(
        r#"{{"type":"image","blobId":"{id}","blobHash":{hash},"mediaKey":{key},"mediaKey":{key},"iv":{iv}}}"#
    );
    let cases: [(&str, String, bool); 12] = [
        ("string chunked", str_chunked, false),
        ("string totalSize", str_total, false),
        ("thumbnail key", thumb, true),
        ("duplicate key in full payload", dup_full, false),
        ("single", ok, true),
        ("chunked", chunked, true),
        ("missing iv", no_iv, false),
        ("null chunked", null_chunked, false),
        ("duplicate key", dup_key, false),
        ("33-byte key", long_key, false),
        ("string key", str_key, false),
        ("type text", type_text, false),
    ];
    for (name, body, expect) in cases {
        let _ = parse(body.as_bytes()); // warm up lazy statics
        let (leaked, parsed) = residue(body.as_bytes());
        assert_eq!(parsed, expect, "parse result: {name}");
        assert_eq!(leaked, 0, "unwiped copy: {name}");
    }
}
