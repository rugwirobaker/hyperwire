use crate::Device;
#[cfg(test)]
use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

#[cfg(test)]
#[derive(Clone)]
pub struct MockDevice {
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx_log: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    // mock_time: Arc<Mutex<Option<Instant>>>,
    drop_probability: Arc<Mutex<f32>>,
}

#[cfg(test)]
impl MockDevice {
    pub fn new() -> Self {
        Self {
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            tx_log: Arc::new(Mutex::new(Vec::new())),
            // mock_time: Arc::new(Mutex::new(None)), // No time control by default
            drop_probability: Arc::new(Mutex::new(0.0)), // No packet loss by default
        }
    }

    pub fn inject_packet(&self, desc: &str, packet: Vec<u8>) {
        println!("🧪 INJECT: {} ({} bytes)", desc, packet.len());
        self.rx_queue.lock().unwrap().push_back(packet);
    }

    pub fn get_sent_packets(&self) -> Vec<(String, Vec<u8>)> {
        self.tx_log.lock().unwrap().clone()
    }

    pub fn clear_sent(&self) {
        self.tx_log.lock().unwrap().clear();
    }

    pub fn last_sent_packet(&self) -> Option<Vec<u8>> {
        self.tx_log.lock().unwrap().last().map(|(_, p)| p.clone())
    }

    /// Set packet loss probability (0.0 = no loss, 1.0 = drop all)
    pub fn set_drop_probability(&self, probability: f32) {
        let prob = probability.max(0.0).min(1.0);
        *self.drop_probability.lock().unwrap() = prob;
        println!("📉 Packet loss probability set to {:.1}%", prob * 100.0);
    }
}

impl Device for MockDevice {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut queue = self.rx_queue.lock().unwrap();
        match queue.pop_front() {
            Some(packet) => {
                let len = packet.len().min(buf.len());
                buf[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            }
            None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        // Check if we should drop this packet
        let drop_probability = *self.drop_probability.lock().unwrap();
        if drop_probability > 0.0 && rand::random::<f32>() < drop_probability {
            println!("🔥 DROPPING outgoing packet (simulation)");
            // Return success but don't log - simulates packet loss
            return Ok(buf.len());
        }

        let packet = buf.to_vec();
        let len = packet.len(); // Save length before move

        if let Ok(ip) = Ipv4HeaderSlice::from_slice(buf) {
            if ip.protocol() == IpNumber::TCP {
                if let Ok(tcp) = TcpHeaderSlice::from_slice(&buf[ip.slice().len()..]) {
                    let flags_str = format!(
                        "{}{}{}{}{}",
                        if tcp.syn() { "S" } else { "-" },
                        if tcp.ack() { "A" } else { "-" },
                        if tcp.fin() { "F" } else { "-" },
                        if tcp.rst() { "R" } else { "-" },
                        if tcp.psh() { "P" } else { "-" },
                    );
                    let desc = format!(
                        "{}:{} → {}:{} [{}] seq={} ack={}",
                        ip.source_addr(),
                        tcp.source_port(),
                        ip.destination_addr(),
                        tcp.destination_port(),
                        flags_str,
                        tcp.sequence_number(),
                        tcp.acknowledgment_number()
                    );
                    println!("📤 SEND: {} ({} bytes)", desc, len);
                    self.tx_log.lock().unwrap().push((desc, packet));
                    return Ok(len);
                }
            }
        }
        self.tx_log
            .lock()
            .unwrap()
            .push(("Unknown".to_string(), packet));
        Ok(len)
    }
}
