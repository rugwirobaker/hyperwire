mod tun;

// Import and re-export
pub use self::tun::Tun;

// Mock device for testing
#[cfg(test)]
pub mod mock;
#[cfg(test)]
pub use self::mock::MockDevice;

/// A trait for network device I/O
pub trait Device: Send {
    /// Receive a packet from the device
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Send a packet to the device
    fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
}
