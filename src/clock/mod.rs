pub mod mock;
mod system;

#[cfg(test)]
pub use self::mock::MockClock;

pub use self::system::SystemClock;

/// A trait for getting the current time
pub trait Clock: Send + Sync {
    /// Returns the current instant
    fn now(&self) -> std::time::Instant;
}
