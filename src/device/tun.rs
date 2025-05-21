use crate::Device;
use std::io;

// Tun wraps a real tun device
pub struct Tun {
    device: tun_tap::Iface,
}

impl Tun {
    pub fn new(name: &str) -> io::Result<Self> {
        let device = tun_tap::Iface::without_packet_info(name, tun_tap::Mode::Tun)?;
        Ok(Self { device })
    }
}

impl Device for Tun {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.device.recv(buf)
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.device.send(buf) // Direct passthrough
    }
}
