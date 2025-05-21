#[cfg(test)]
use crate::Clock;
#[cfg(test)]
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(test)]
#[derive(Clone)]
/// A test clock you can manually advance.
pub struct MockClock {
    inner: Arc<Mutex<Instant>>,
}

#[cfg(test)]
impl MockClock {
    /// Start the mock at the given instant.
    pub fn new(start: Instant) -> Self {
        MockClock {
            inner: Arc::new(Mutex::new(start)),
        }
    }

    /// Advance the clock by `d`.
    pub fn advance(&self, d: Duration) {
        let mut t = self.inner.lock().unwrap();
        *t += d;
    }
}

#[cfg(test)]
impl Clock for MockClock {
    fn now(&self) -> Instant {
        *self.inner.lock().unwrap()
    }
}
