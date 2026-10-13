//! Export queue and batch, bounded by bytes as well as by count.
//!
//! An item limit alone does not bound memory: 10,000 queued events with full body previews and
//! large header sets can hold hundreds of MiB. Producers reserve an event's size before it is
//! queued and the reservation is released when the batch task takes it. A batch never holds more
//! than its event count or byte limit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::metrics::{EVENTS_DROPPED, EXPORT_OVERSIZED_DROPS, EXPORT_QUEUE_BYTES, EXPORT_QUEUE_BYTE_DROPS};
use crate::types::ApiTrafficEvent;

struct Budget {
    used: AtomicUsize,
    limit: usize,
}

impl Budget {
    fn reserve(&self, n: usize) -> bool {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(n).filter(|&v| v <= self.limit) else { return false };
            match self.used.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    EXPORT_QUEUE_BYTES.store(next as u64, Ordering::Relaxed);
                    return true;
                }
                Err(actual) => cur = actual,
            }
        }
    }

    fn release(&self, n: usize) {
        let prev = self.used.fetch_sub(n, Ordering::AcqRel);
        EXPORT_QUEUE_BYTES.store(prev.saturating_sub(n) as u64, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct ExportSender {
    tx: mpsc::Sender<(ApiTrafficEvent, usize)>,
    budget: Arc<Budget>,
}

pub struct ExportReceiver {
    rx: mpsc::Receiver<(ApiTrafficEvent, usize)>,
    budget: Arc<Budget>,
}

/// A queue holding at most `max_events` events and `max_bytes` bytes of events.
pub fn export_channel(max_events: usize, max_bytes: usize) -> (ExportSender, ExportReceiver) {
    let (tx, rx) = mpsc::channel(max_events.max(1));
    let budget = Arc::new(Budget { used: AtomicUsize::new(0), limit: max_bytes });
    (ExportSender { tx, budget: budget.clone() }, ExportReceiver { rx, budget })
}

impl ExportSender {
    /// Queue without waiting. A full queue (by count or by bytes) drops the event and counts it.
    pub fn try_send(&self, ev: ApiTrafficEvent) -> bool {
        let size = ev.approx_bytes();
        if !self.budget.reserve(size) {
            EXPORT_QUEUE_BYTE_DROPS.fetch_add(1, Ordering::Relaxed);
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if self.tx.try_send((ev, size)).is_err() {
            self.budget.release(size);
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub fn queued_events(&self) -> usize {
        self.tx.max_capacity() - self.tx.capacity()
    }

    pub fn queued_bytes(&self) -> usize {
        self.budget.used.load(Ordering::Relaxed)
    }

    pub fn max_events(&self) -> usize {
        self.tx.max_capacity()
    }
}

impl ExportReceiver {
    /// Next event and its charged size; the queue's reservation is released here.
    pub async fn recv(&mut self) -> Option<(ApiTrafficEvent, usize)> {
        let item = self.rx.recv().await;
        if let Some((_, size)) = &item {
            self.budget.release(*size);
        }
        item
    }
}

/// Events awaiting one ingest request.
pub struct Batch {
    events: Vec<ApiTrafficEvent>,
    bytes: usize,
    max_events: usize,
    max_bytes: usize,
}

impl Batch {
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self { events: Vec::new(), bytes: 0, max_events: max_events.max(1), max_bytes }
    }

    /// Add an event and return the batches that are ready to send, oldest first. `max_bytes` is a
    /// hard ceiling: an event that would overflow the current batch flushes it first, and an event
    /// larger than `max_bytes` on its own can never be sent within budget, so it is dropped and
    /// counted.
    pub fn push(&mut self, ev: ApiTrafficEvent, size: usize) -> Vec<Vec<ApiTrafficEvent>> {
        let mut ready = Vec::new();
        if size > self.max_bytes {
            EXPORT_OVERSIZED_DROPS.fetch_add(1, Ordering::Relaxed);
            EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return ready;
        }
        if !self.events.is_empty() && self.bytes + size > self.max_bytes {
            ready.push(self.take());
        }
        self.events.push(ev);
        self.bytes += size;
        if self.events.len() >= self.max_events || self.bytes >= self.max_bytes {
            ready.push(self.take());
        }
        ready
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn take(&mut self) -> Vec<ApiTrafficEvent> {
        self.bytes = 0;
        std::mem::take(&mut self.events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApiRequest, ApiResponse};

    fn event(body_len: usize) -> ApiTrafficEvent {
        ApiTrafficEvent {
            protocol: "HTTP/1.1".into(),
            request: ApiRequest { method: "POST".into(), path: "/x".into(), body: Some("b".repeat(body_len)), ..Default::default() },
            response: ApiResponse { status_code: 200, ..Default::default() },
            ..Default::default()
        }
    }

    #[test]
    fn the_size_estimate_grows_with_the_payload() {
        let small = event(10).approx_bytes();
        let big = event(8_000).approx_bytes();
        assert!(big >= small + 7_990, "small={small} big={big}");
    }

    #[tokio::test]
    async fn the_queue_refuses_events_past_its_byte_budget_even_with_item_slots_free() {
        let one = event(8_000).approx_bytes();
        let (tx, mut rx) = export_channel(10_000, one * 3);
        let dropped_before = EXPORT_QUEUE_BYTE_DROPS.load(Ordering::Relaxed);
        let accepted = (0..10).filter(|_| tx.try_send(event(8_000))).count();
        assert_eq!(accepted, 3, "only three events fit the byte budget");
        assert!(tx.queued_bytes() <= one * 3);
        assert!(EXPORT_QUEUE_BYTE_DROPS.load(Ordering::Relaxed) >= dropped_before + 7);

        // Draining releases the bytes, so the queue accepts again.
        let (_, size) = rx.recv().await.unwrap();
        assert_eq!(size, one);
        assert!(tx.try_send(event(8_000)), "space freed by the consumer must be reusable");
        while tx.queued_events() > 0 {
            rx.recv().await.unwrap();
        }
        assert_eq!(tx.queued_bytes(), 0, "every reservation is released");
    }

    #[test]
    fn a_full_item_queue_releases_the_byte_reservation() {
        let (tx, _rx) = export_channel(1, usize::MAX / 2);
        assert!(tx.try_send(event(10)));
        let held = tx.queued_bytes();
        assert!(!tx.try_send(event(10)));
        assert_eq!(tx.queued_bytes(), held, "a refused event must not leak its reservation");
    }

    fn sizes(ready: &[Vec<ApiTrafficEvent>]) -> Vec<usize> {
        ready.iter().map(Vec::len).collect()
    }

    #[test]
    fn a_batch_flushes_on_bytes_before_reaching_its_event_count() {
        let mut batch = Batch::new(200, 200);
        assert!(batch.push(event(1), 100).is_empty());
        assert_eq!(sizes(&batch.push(event(1), 100)), [2], "byte limit reached exactly at 2 of 200 events");
        assert!(batch.is_empty());
        assert!(batch.push(event(1), 100).is_empty(), "sending the batch resets its byte count");
    }

    #[test]
    fn an_event_that_would_overflow_the_batch_flushes_it_first() {
        let mut batch = Batch::new(200, 250);
        assert!(batch.push(event(1), 100).is_empty());
        assert!(batch.push(event(1), 100).is_empty());
        // 200 + 100 > 250: the two queued events leave without the third.
        let ready = batch.push(event(1), 100);
        assert_eq!(sizes(&ready), [2]);
        assert!(!batch.is_empty(), "the third event starts the next batch");
        assert_eq!(sizes(&batch.push(event(1), 100)), Vec::<usize>::new(), "next batch holds 200 of 250");
        assert_eq!(sizes(&[batch.take()]), [2]);
    }

    #[test]
    fn an_event_that_exactly_fills_the_budget_after_a_flush_is_sent_on_its_own() {
        let mut batch = Batch::new(200, 250);
        assert!(batch.push(event(1), 100).is_empty());
        assert_eq!(sizes(&batch.push(event(1), 250)), [1, 1], "previous batch, then the full-budget event");
        assert!(batch.is_empty());
    }

    #[test]
    fn an_event_larger_than_the_whole_budget_is_dropped_and_counted() {
        let mut batch = Batch::new(200, 250);
        assert!(batch.push(event(1), 100).is_empty());
        let oversized_before = EXPORT_OVERSIZED_DROPS.load(Ordering::Relaxed);
        let dropped_before = EVENTS_DROPPED.load(Ordering::Relaxed);
        assert!(batch.push(event(1), 251).is_empty(), "nothing is sent for an event that cannot fit");
        assert!(EXPORT_OVERSIZED_DROPS.load(Ordering::Relaxed) > oversized_before);
        assert!(EVENTS_DROPPED.load(Ordering::Relaxed) > dropped_before);
        assert_eq!(batch.take().len(), 1, "the queued event is untouched");
    }

    #[test]
    fn no_sent_batch_ever_exceeds_its_byte_budget() {
        let mut batch = Batch::new(1_000, 1_000);
        let mut held: std::collections::VecDeque<usize> = Default::default();
        let mut sent = 0;
        for size in (0..500).map(|i| 1 + (i * 37) % 400) {
            held.push_back(size);
            for b in batch.push(event(1), size) {
                let bytes: usize = held.drain(..b.len()).sum();
                assert!(bytes <= 1_000, "sent batch of {bytes} bytes exceeds 1000");
                sent += 1;
            }
        }
        assert!(sent > 50, "the budget forced many flushes, got {sent}");
    }

    #[test]
    fn a_batch_still_flushes_on_event_count() {
        let mut batch = Batch::new(3, usize::MAX);
        assert!(batch.push(event(1), 100).is_empty());
        assert!(batch.push(event(1), 100).is_empty());
        assert_eq!(sizes(&batch.push(event(1), 100)), [3]);
    }
}
