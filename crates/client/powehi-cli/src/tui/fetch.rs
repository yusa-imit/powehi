//! Background inbox fetch for `powehi tui` (8.20 carry). The network fetch runs on a worker
//! thread so the event loop keeps reading keys (Ctrl-C, Esc) while the server is slow. The
//! worker holds `gate` for the whole fetch; every other writer of the profile store (send,
//! verify, drain) takes the same gate, so two MLS state updates never interleave.

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::sync::{Mutex, MutexGuard, TryLockError};

/// Takes the gate, waiting for a running fetch. A poisoned gate is still a valid gate: it
/// guards no data of its own.
pub fn lock(gate: &Mutex<()>) -> MutexGuard<'_, ()> {
    gate.lock().unwrap_or_else(|e| e.into_inner())
}

/// Takes the gate only if no fetch is running.
pub fn try_lock(gate: &Mutex<()>) -> Option<MutexGuard<'_, ()>> {
    match gate.try_lock() {
        Ok(g) => Some(g),
        Err(TryLockError::Poisoned(e)) => Some(e.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

/// The worker body: one `fetch` per request, under the gate, until the requester is dropped.
/// `fetch` answers whether it succeeded.
pub fn worker<F: FnMut() -> bool>(
    requests: Receiver<()>,
    done: SyncSender<bool>,
    gate: &Mutex<()>,
    mut fetch: F,
) {
    while requests.recv().is_ok() {
        let ok = {
            let _g = lock(gate);
            fetch()
        };
        if done.send(ok).is_err() {
            return;
        }
    }
}

/// The event-loop side: at most one fetch in flight, never blocks.
pub struct Poller {
    requests: SyncSender<()>,
    done: Receiver<bool>,
    in_flight: bool,
}

impl Poller {
    pub fn new(requests: SyncSender<()>, done: Receiver<bool>) -> Self {
        Self {
            requests,
            done,
            in_flight: false,
        }
    }

    /// Reports a fetch that finished since the last call (`Some(success)`), then, if `start`
    /// and nothing is running, asks for a new one.
    pub fn poll(&mut self, start: bool) -> Option<bool> {
        let mut finished = None;
        if self.in_flight {
            match self.done.try_recv() {
                Ok(ok) => {
                    self.in_flight = false;
                    finished = Some(ok);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.in_flight = false;
                    finished = Some(false);
                }
            }
        }
        if start && !self.in_flight && self.requests.try_send(()).is_ok() {
            self.in_flight = true;
        }
        finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;
    use std::time::Duration;

    #[test]
    fn one_fetch_in_flight_and_result_reported_once() {
        let (req_tx, req_rx) = sync_channel(1);
        let (done_tx, done_rx) = sync_channel(1);
        let gate = Mutex::new(());
        let mut poller = Poller::new(req_tx, done_rx);
        let (go_tx, go_rx) = sync_channel::<()>(0);
        let mut runs = 0u32;
        std::thread::scope(|s| {
            let worker_gate = &gate;
            let runs = &mut runs;
            s.spawn(move || {
                worker(req_rx, done_tx, worker_gate, || {
                    go_rx.recv().unwrap();
                    *runs += 1;
                    true
                });
            });
            assert_eq!(poller.poll(true), None);
            // Still running: a second request is not queued and the gate is held.
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(poller.poll(true), None);
            assert!(try_lock(&gate).is_none());
            go_tx.send(()).unwrap();
            let mut got = None;
            for _ in 0..200 {
                got = poller.poll(false);
                if got.is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(got, Some(true));
            assert_eq!(poller.poll(false), None);
            drop(poller);
        });
        assert_eq!(runs, 1);
        assert!(try_lock(&gate).is_some());
    }

    #[test]
    fn dropping_the_closure_that_owns_the_poller_ends_the_worker() {
        let (req_tx, req_rx) = sync_channel(1);
        let (done_tx, done_rx) = sync_channel(1);
        let gate = Mutex::new(());
        let mut poller = Poller::new(req_tx, done_rx);
        // Mirrors `run_tui`: the poller lives in a `move` closure that `run` consumes.
        let sync = move || poller.poll(false);
        std::thread::scope(|s| {
            let worker_gate = &gate;
            s.spawn(move || worker(req_rx, done_tx, worker_gate, || true));
            drop(sync);
        });
    }

    #[test]
    fn a_dead_worker_reads_as_failure() {
        let (req_tx, req_rx) = sync_channel(1);
        let (done_tx, done_rx) = sync_channel(1);
        let mut poller = Poller::new(req_tx, done_rx);
        assert_eq!(poller.poll(true), None);
        drop((req_rx, done_tx));
        assert_eq!(poller.poll(false), Some(false));
    }
}
