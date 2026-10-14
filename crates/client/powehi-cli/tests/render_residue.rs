//! `render` must leave no unwiped copy of the message body on the heap (7.11 F8). A scanning
//! allocator counts freed/reallocated blocks that still contain a marker; the only allowed
//! exception is serde_json's escape scratch buffer.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use powehi_cli::message::render;

const MARKS: [&[u8]; 2] = [b"ZQXSECRET", b"4111111111111111"];
static LEAKED: AtomicUsize = AtomicUsize::new(0);

struct Scan;

fn scan(ptr: *mut u8, len: usize) {
    // SAFETY: called with a live block of `len` bytes, right before it is freed/moved.
    let block = unsafe { std::slice::from_raw_parts(ptr, len) };
    if MARKS
        .iter()
        .any(|m| block.windows(m.len()).any(|w| w == *m))
    {
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

fn residue(body: &[u8]) -> usize {
    LEAKED.store(0, Ordering::SeqCst);
    let out = render(body);
    assert!(!out.is_empty());
    drop(out);
    LEAKED.load(Ordering::SeqCst)
}

// One test only: the counter is process-global.
#[test]
fn render_leaves_no_unwiped_copy() {
    let big = [b"ZQXSECRET".as_slice(), &[0xff, 0x1b, b'\r'].repeat(5000)].concat();
    let cases: [(&str, Vec<u8>); 9] = [
        ("plain", b"hi ZQXSECRET there".to_vec()),
        ("crlf", b"ZQXSECRET\r\n\x1b".to_vec()),
        ("invalid utf8", b"ZQXSECRET\xff".to_vec()),
        (
            "structured",
            br#"{"type":"text","text":"ZQXSECRET"}"#.to_vec(),
        ),
        ("key", br#"{"ZQXSECRET":1}"#.to_vec()),
        ("type value", br#"{"type":"ZQXSECRET"}"#.to_vec()),
        ("top-level string", br#""ZQXSECRET""#.to_vec()),
        ("top-level number", b"4111111111111111".to_vec()),
        ("worst case", big),
    ];
    for (name, body) in cases {
        // Warm up lazy statics so their one-off allocations are not counted.
        let _ = render(&body);
        assert_eq!(residue(&body), 0, "unwiped copy: {name}");
    }
}
