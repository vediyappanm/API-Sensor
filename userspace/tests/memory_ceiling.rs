//! The memory ceiling must hold against REAL heap usage, not just the sensor's own counter.
//!
//! This file is its own test process, so the global byte counter and the counting allocator
//! below see only this test. Before the fix, queued requests (headers plus a full captured
//! body each) lived outside the ceiling: a flood of large pipelined requests across many
//! connections grew the real heap to hundreds of MiB while the counter said 0.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use api_sec_sensor::container::ContainerResolver;
use api_sec_sensor::dns::DnsResolver;
use api_sec_sensor::stream::ShardedStreamState;
use api_sec_sensor::types::{ConnKey, TlsEventHeader, TrafficRole, TOTAL_BUFFER_BYTES};

struct CountingAlloc;
static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let np = System.realloc(p, l, new_size);
        if !np.is_null() {
            LIVE.fetch_add(new_size, Ordering::Relaxed);
            LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        }
        np
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn event(pid: u32, ssl_ptr: u64) -> TlsEventHeader {
    TlsEventHeader {
        ts_ns: 1,
        pid,
        tid: pid,
        ssl_ptr,
        data_len: 0,
        direction: 0, // request direction for a server-role sensor
        ip_family: 4,
        _pad16: 0,
        comm: *b"srv\0\0\0\0\0\0\0\0\0\0\0\0\0",
        cgroup_id: 0,
        netns_ino: 1,
        src_port: 40000,
        dst_port: 443,
        src_ip4: u32::from_be_bytes([10, 0, 0, 2]),
        dst_ip4: u32::from_be_bytes([10, 0, 0, 1]),
        src_ip6: [0; 16],
        dst_ip6: [0; 16],
    }
}

fn request(body_len: usize) -> Vec<u8> {
    let mut r = format!(
        "POST /upload HTTP/1.1\r\nHost: files.example.com\r\nContent-Type: application/octet-stream\r\n\
         User-Agent: load-gen/1.0\r\nX-Request-Id: 0123456789abcdef\r\nContent-Length: {body_len}\r\n\r\n"
    )
    .into_bytes();
    r.extend(std::iter::repeat(b'x').take(body_len));
    r
}

#[test]
fn queued_requests_stay_inside_the_ceiling_and_are_all_released() {
    std::env::set_var("PII_HASH_KEY", "42".repeat(32));
    api_sec_sensor::redaction::init_pii_hash_key().unwrap();

    const CEILING: usize = 4 * 1024 * 1024;
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let (dtx, _drx) = tokio::sync::mpsc::channel(8);
    let state = ShardedStreamState::new(
        1,
        TrafficRole::Server,
        65_536,
        Arc::new(ContainerResolver::new(tx, "node".into())),
        CEILING,
        Arc::new(DnsResolver::new(dtx)),
    );

    let heap_before = live();
    let req = request(20_000); // 20 KB body, far above the 8 KiB that is ever shipped

    // 200 connections x 120 pipelined requests that never get a response:
    // before the fix ~ 200 x 100 queued x ~20 KB = ~400 MB of untracked heap.
    for conn in 0..200u64 {
        let ev = event(1000 + (conn % 50) as u32, 0x10_000 + conn);
        for _ in 0..120 {
            state.handle_event(&ev, &req);
        }
    }

    let accounted = TOTAL_BUFFER_BYTES.load(Ordering::Relaxed);
    let grown = live().saturating_sub(heap_before);
    eprintln!("accounted={accounted} real_heap_growth={grown} ceiling={CEILING}");

    assert!(accounted <= CEILING, "counter {accounted} exceeded the ceiling {CEILING}");
    // The counter is only meaningful if it tracks reality: measured real growth must stay within
    // 25% of the ceiling (allocator/hash-map slack). Before the body allocation was shrunk after
    // truncation this was 2.2x the ceiling.
    assert!(
        grown <= CEILING + CEILING / 4,
        "real heap grew {grown} bytes against a {CEILING}-byte ceiling (counter said {accounted})"
    );
    assert!(
        api_sec_sensor::metrics::EVENTS_DROPPED.load(Ordering::Relaxed) > 0,
        "requests beyond the ceiling must be counted as drops"
    );

    // Closing the connections must give every byte back, whatever path removed the queues.
    for conn in 0..200u64 {
        state.evict_connection(&ConnKey { pid: 1000 + (conn % 50) as u32, ssl_ptr: 0x10_000 + conn, born_ms: 0 });
    }
    let after = TOTAL_BUFFER_BYTES.load(Ordering::Relaxed);
    assert_eq!(after, 0, "{after} bytes still accounted after every connection was evicted");
    let leaked = live().saturating_sub(heap_before);
    assert!(leaked < 2 * 1024 * 1024, "{leaked} heap bytes still held after eviction");
}
