use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Simple circuit breaker: closed → open (after threshold failures) → closed (after open_duration).
///
/// Thread-safe via atomics + a single Mutex only for the Instant stamp.
/// The Mutex is panic-safe: if a thread panics while holding the lock the
/// PoisonError is recovered via `into_inner` so the circuit never hard-panics.
pub struct CircuitBreaker {
    failures: AtomicU32,
    threshold: u32,
    open_until: Mutex<Option<Instant>>,
    open_duration: Duration,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, open_duration: Duration) -> Self {
        Self {
            failures: AtomicU32::new(0),
            threshold,
            open_until: Mutex::new(None),
            open_duration,
        }
    }

    /// Returns `true` when the circuit is open (requests should be fast-rejected).
    pub fn is_open(&self) -> bool {
        let guard = self.open_until.lock().unwrap_or_else(|e| e.into_inner());
        match *guard {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        let mut guard = self.open_until.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }

    pub fn record_failure(&self) {
        let count = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.threshold {
            let mut guard = self.open_until.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                *guard = Some(Instant::now() + self.open_duration);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_starts_closed() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));
        assert!(!cb.is_open());
    }

    #[test]
    fn circuit_opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_open(), "should still be closed before threshold");
        cb.record_failure();
        assert!(cb.is_open(), "should be open at threshold");
    }

    #[test]
    fn success_resets_circuit_to_closed() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open());
        cb.record_success();
        assert!(!cb.is_open());
    }

    #[test]
    fn additional_failures_while_open_do_not_extend_deadline() {
        let cb = CircuitBreaker::new(1, Duration::from_secs(30));
        cb.record_failure(); // opens circuit, sets open_until = now + 30s
        let first_deadline = *cb.open_until.lock().unwrap();
        cb.record_failure(); // should NOT change open_until again
        let second_deadline = *cb.open_until.lock().unwrap();
        assert_eq!(
            first_deadline, second_deadline,
            "deadline must not be extended"
        );
    }

    #[test]
    fn circuit_closes_after_duration_expires() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(1));
        cb.record_failure();
        assert!(cb.is_open());
        std::thread::sleep(Duration::from_millis(5));
        assert!(!cb.is_open(), "circuit should auto-close after duration");
    }
}
