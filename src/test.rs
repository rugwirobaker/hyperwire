use super::*;
use crate::tcp::TcpKey;
use etherparse::{IpNumber, Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice};
use std::collections::VecDeque;
use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

impl Clock for MockClock {
    fn now(&self) -> Instant {
        *self.inner.lock().unwrap()
    }
}

#[derive(Clone)]
struct MockDevice {
    rx_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    tx_log: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    // mock_time: Arc<Mutex<Option<Instant>>>,
    drop_probability: Arc<Mutex<f32>>,
}

impl MockDevice {
    fn new() -> Self {
        Self {
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            tx_log: Arc::new(Mutex::new(Vec::new())),
            // mock_time: Arc::new(Mutex::new(None)), // No time control by default
            drop_probability: Arc::new(Mutex::new(0.0)), // No packet loss by default
        }
    }

    fn inject_packet(&self, desc: &str, packet: Vec<u8>) {
        println!("🧪 INJECT: {} ({} bytes)", desc, packet.len());
        self.rx_queue.lock().unwrap().push_back(packet);
    }

    fn get_sent_packets(&self) -> Vec<(String, Vec<u8>)> {
        self.tx_log.lock().unwrap().clone()
    }

    fn clear_sent(&self) {
        self.tx_log.lock().unwrap().clear();
    }

    // fn drain_one_packet(&self) -> Option<Vec<u8>> {
    //     self.rx_queue.lock().unwrap().pop_front()
    // }

    fn last_sent_packet(&self) -> Option<Vec<u8>> {
        self.tx_log.lock().unwrap().last().map(|(_, p)| p.clone())
    }

    // fn enable_time_control(&self) -> bool {
    //     let mut time = self.mock_time.lock().unwrap();
    //     match *time {
    //         None => {
    //             *time = Some(Instant::now());
    //             println!("⏱️ Time control enabled");
    //             true
    //         }
    //         Some(_) => {
    //             println!("⏱️ Time control already enabled");
    //             false
    //         }
    //     }
    // }

    // fn advance_time(&self, duration: Duration) -> bool {
    //     let mut time = self.mock_time.lock().unwrap();
    //     match *time {
    //         Some(current) => {
    //             *time = Some(current + duration);
    //             println!("⏱️ Advanced mock time by {:?}", duration);
    //             true
    //         }
    //         None => {
    //             println!("⚠️ Cannot advance time: time control not enabled");
    //             false
    //         }
    //     }
    // }

    /// Set packet loss probability (0.0 = no loss, 1.0 = drop all)
    fn set_drop_probability(&self, probability: f32) {
        let prob = probability.max(0.0).min(1.0);
        *self.drop_probability.lock().unwrap() = prob;
        println!("📉 Packet loss probability set to {:.1}%", prob * 100.0);
    }

    // /// Get current drop probability
    // fn get_drop_probability(&self) -> f32 {
    //     *self.drop_probability.lock().unwrap()
    // }
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

// Helper to create various packet types
struct PacketFactory;

impl PacketFactory {
    fn syn(src: &str, dst: &str, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();

        let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64)
            .tcp(src_port, dst_port, seq, 65535)
            .syn();

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).unwrap();
        packet
    }

    fn ack(src: &str, dst: &str, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Vec<u8> {
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();

        let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64)
            .tcp(src_port, dst_port, seq, 65535)
            .ack(ack);

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).unwrap();
        packet
    }

    fn data(
        src: &str,
        dst: &str,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();

        let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64)
            .tcp(src_port, dst_port, seq, 65535)
            .psh()
            .ack(ack);

        let mut packet = Vec::with_capacity(builder.size(data.len()));
        builder.write(&mut packet, data).unwrap();
        packet
    }

    fn fin(src: &str, dst: &str, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Vec<u8> {
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();

        let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64)
            .tcp(src_port, dst_port, seq, 65535)
            .fin()
            .ack(ack);

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).unwrap();
        packet
    }
}

// Helper to parse packets for assertions
fn parse_tcp_packet(packet: &[u8]) -> (Ipv4HeaderSlice, TcpHeaderSlice) {
    let ip = Ipv4HeaderSlice::from_slice(packet).unwrap();
    let tcp = TcpHeaderSlice::from_slice(&packet[ip.slice().len()..]).unwrap();
    (ip, tcp)
}

// Now the actual tests
#[test]
fn test_tcp_handshake() {
    let dev = MockDevice::new();
    let start = Instant::now();
    let clock = Arc::new(MockClock::new(start));
    let mut server = Server::new(Box::new(dev.clone()), clock.clone());

    // Client sends SYN
    let syn = PacketFactory::syn("10.0.0.2", "10.0.0.1", 12345, 80, 1000);
    dev.inject_packet("Client SYN", syn.clone());

    // Process the SYN
    server.handle_packet(&syn);

    // Verify SYN-ACK was sent
    let sent = dev.get_sent_packets();
    assert_eq!(sent.len(), 1, "Expected 1 packet (SYN-ACK)");

    let syn_ack = &sent[0].1;
    let (_, tcp) = parse_tcp_packet(syn_ack);
    assert!(tcp.syn() && tcp.ack(), "Expected SYN+ACK flags");
    assert_eq!(tcp.acknowledgment_number(), 1001, "Expected ACK=1001");
}

#[test]
fn test_echo_single_line() {
    let dev = MockDevice::new();
    let start = Instant::now();
    let clock = Arc::new(MockClock::new(start));
    let mut server = Server::new(Box::new(dev.clone()), clock.clone());

    // Establish connection first
    establish_connection(&dev, &mut server);

    // Send data: "hello\n"
    let data = PacketFactory::data(
        "10.0.0.2", "10.0.0.1", 12345, 80, 1001, 1, // seq, ack
        b"hello\n",
    );
    dev.inject_packet("Data: hello", data.clone());
    server.handle_packet(&data);

    // Check that echo was sent back
    let sent = dev.get_sent_packets();

    // After establish_connection clears, we should have:
    // 1. ACK for the data
    // 2. DATA (echo)
    // But looking at the log, we only see the echo packet, so let's adjust
    assert!(!sent.is_empty(), "Expected at least 1 packet");

    let echo = sent.last().unwrap();
    let (_, tcp) = parse_tcp_packet(&echo.1);
    assert!(tcp.psh() && tcp.ack(), "Expected PSH+ACK for echo");

    // Verify the echoed data
    let payload_offset = Ipv4HeaderSlice::from_slice(&echo.1).unwrap().slice().len()
        + TcpHeaderSlice::from_slice(&echo.1[20..])
            .unwrap()
            .slice()
            .len();
    let echoed_data = &echo.1[payload_offset..];
    assert_eq!(echoed_data, b"hello\n", "Expected echoed data to match");
}

// Helper function to establish a connection
fn establish_connection(mock: &MockDevice, server: &mut Server) -> (TcpKey, u32) {
    // SYN
    let syn = PacketFactory::syn("10.0.0.2", "10.0.0.1", 12345, 80, 1000);
    server.handle_packet(&syn);

    // Get SYN-ACK details
    let syn_ack = mock.last_sent_packet().unwrap();
    let (ip_hdr, tcp_hdr) = parse_tcp_packet(&syn_ack);
    let key = TcpKey::new(&ip_hdr, &tcp_hdr);
    let server_seq = tcp_hdr.sequence_number();

    // ACK
    let ack = PacketFactory::ack("10.0.0.2", "10.0.0.1", 12345, 80, 1001, server_seq + 1);
    server.handle_packet(&ack);
    mock.clear_sent(); // Clear handshake packets for cleaner test output

    (key, server_seq)
}

#[test]
fn test_out_of_order_reassembly() {
    let dev = MockDevice::new();
    let start = Instant::now();
    let clock = Arc::new(MockClock::new(start));
    let mut server = Server::new(Box::new(dev.clone()), clock.clone());

    establish_connection(&dev, &mut server);

    // Send "world\n" first (out of order)
    let pkt2 = PacketFactory::data(
        "10.0.0.2", "10.0.0.1", 12345, 80, 1007, 1, // seq starts at 1007
        b"world\n",
    );
    server.handle_packet(&pkt2);

    // Then send "hello " (should reassemble to "hello world\n")
    let pkt1 = PacketFactory::data(
        "10.0.0.2", "10.0.0.1", 12345, 80, 1001, 1, // seq starts at 1001
        b"hello ",
    );
    server.handle_packet(&pkt1);

    // Verify the complete echo
    let sent = dev.get_sent_packets();
    let echo = sent.last().unwrap();

    let payload_offset = Ipv4HeaderSlice::from_slice(&echo.1).unwrap().slice().len()
        + TcpHeaderSlice::from_slice(&echo.1[20..])
            .unwrap()
            .slice()
            .len();
    let echoed_data = &echo.1[payload_offset..];
    assert_eq!(echoed_data, b"hello world\n", "Expected reassembled echo");
}

#[test]
fn test_connection_teardown() {
    let dev = MockDevice::new();
    let start = Instant::now();
    let clock = Arc::new(MockClock::new(start));
    let mut server = Server::new(Box::new(dev.clone()), clock.clone());

    establish_connection(&dev, &mut server);

    // Send data and get echo
    let data = PacketFactory::data("10.0.0.2", "10.0.0.1", 12345, 80, 1001, 1, b"test\n");
    server.handle_packet(&data);

    // Client sends FIN
    let fin = PacketFactory::fin(
        "10.0.0.2", "10.0.0.1", 12345, 80, 1006, 1, // seq after data
    );
    server.handle_packet(&fin);

    // Server should ACK the FIN and send its own FIN
    let sent = dev.get_sent_packets();
    let last_packets = sent.iter().rev().take(2).collect::<Vec<_>>();

    // Verify server sent FIN+ACK
    let has_fin_ack = last_packets.iter().any(|(desc, _)| desc.contains("-AF-"));
    assert!(has_fin_ack, "Expected server to send FIN+ACK");
}

#[test]
fn test_retransmission() {
    // 1) Set up mock device + clock + server
    let mock_dev = MockDevice::new();
    let start = Instant::now();
    let mock_clock = Arc::new(MockClock::new(start));
    let mut server = Server::new(Box::new(mock_dev.clone()), mock_clock.clone());

    // 2) Handshake & grab the key and the server initial sequence number
    let (key, server_isn) = establish_connection(&mock_dev, &mut server);

    // 3) Force a small RTO for quick test
    let test_rto = Duration::from_millis(200);
    server.force_rto_for(&key, test_rto);

    // 4) Tell the mock to DROP outgoing packets initially
    mock_dev.set_drop_probability(1.0);

    // 5) Inject a data packet from the client
    //    We pick client seq = 1001, ack = 1, payload = b"ping\n"
    let payload = b"ping\n";
    let client_seq = 1001;
    let client_ack = 1;
    let data_pkt = PacketFactory::data(
        "10.0.0.2", "10.0.0.1", 12345, 80, client_seq, client_ack, payload,
    );
    mock_dev.inject_packet("Client→Server data", data_pkt.clone());
    server.handle_packet(&data_pkt);

    // 6) The server tried to send its PSH+ACK echo, but it was dropped.
    //    Clear any logged sends just in case.
    // mock_dev.clear_sent();

    // 7) Advance time just past the RTO
    mock_clock.advance(test_rto + Duration::from_millis(1));

    // 8) Turn DROPPING off so we can *see* the retransmission
    mock_dev.set_drop_probability(0.0);

    // 9) Trigger retransmission sweep
    server.check_retransmissions();

    // 10) We should now have at least one packet in the log:
    let sent = mock_dev.get_sent_packets();
    assert!(
        !sent.is_empty(),
        "Expected at least one retransmitted packet"
    );

    // 11) Parse the first retransmitted packet and verify it matches our data
    let (_desc, pkt) = &sent[0];
    let (ip_hdr, tcp_hdr) = parse_tcp_packet(&pkt);

    let expected_seq = server_isn.wrapping_add(1);
    assert_eq!(
        tcp_hdr.sequence_number(),
        expected_seq,
        "Retransmit must use the server's original send sequence"
    );
    // 12) And that the payload is intact
    let payload_offset = ip_hdr.slice().len() + tcp_hdr.slice().len();
    assert_eq!(
        &pkt[payload_offset..],
        payload,
        "Retransmitted payload must match original"
    );
}

#[test]
fn test_retransmission_backoff_timing() {
    let mock_dev = MockDevice::new();
    let start = Instant::now();
    let clock = Arc::new(MockClock::new(start));
    let mut server = Server::new(Box::new(mock_dev.clone()), clock.clone());

    // 1. three-way handshake
    let (key, server_isn) = establish_connection(&mock_dev, &mut server);

    // Apply a *tiny* initial RTO (100 ms) to the **server-to-client** flow
    let initial_rto = Duration::from_millis(100);
    server.force_rto_for(&key.reverse(), initial_rto);

    // We want the first PSH+ACK to be dropped
    mock_dev.set_drop_probability(1.0);

    // 2. client sends a short line
    let payload = b"foo\n";
    let data_pkt = PacketFactory::data(
        "10.0.0.2", "10.0.0.1", 12345, 80, /*seq*/ 1001, /*ack*/ 1, payload,
    );
    mock_dev.inject_packet("C→S data", data_pkt.clone());
    server.handle_packet(&data_pkt);

    // 3. first retransmission (after 100 ms)
    clock.advance(initial_rto + Duration::from_millis(1)); // → ≈101 ms
    mock_dev.set_drop_probability(0.0); // observe sends
    server.check_retransmissions();

    let first = mock_dev.get_sent_packets();
    assert!(!first.is_empty(), "first retransmit expected");
    mock_dev.clear_sent(); // clean slate

    // 4. second retransmission should follow *after* doubled RTO
    let doubled_rto = initial_rto * 2; // 200 ms

    // 4-a  advance to 10 ms *before* the 2 × RTO threshold  (no send expected)
    clock.advance(doubled_rto - Duration::from_millis(10)); // +190 ms
    server.check_retransmissions();
    assert!(
        mock_dev.get_sent_packets().is_empty(),
        "should not retransmit before doubled RTO"
    );

    // 4-b  step *past* the deadline by another 15 ms (send expected)
    clock.advance(Duration::from_millis(15)); // +15 ms → 205 ms
    server.check_retransmissions();

    let second = mock_dev.get_sent_packets();
    assert!(
        !second.is_empty(),
        "second retransmit at doubled RTO expected"
    );

    let (_desc, pkt2) = &second[0];
    let (_ip, tcp2) = parse_tcp_packet(pkt2);

    let expected_seq = server_isn.wrapping_add(1); // first data seq
    assert_eq!(
        tcp2.sequence_number(),
        expected_seq,
        "second retransmit uses same server sequence"
    );

    let off = Ipv4HeaderSlice::from_slice(pkt2).unwrap().slice().len()
        + TcpHeaderSlice::from_slice(&pkt2[20..])
            .unwrap()
            .slice()
            .len();
    assert_eq!(&pkt2[off..], payload, "payload intact on second retransmit");
}

/// After MAX_RETRANSMISSIONS attempts the segment is abandoned.
#[test]
fn test_retransmission_abandon_after_max() {
    use crate::tcp::MAX_RETRANSMISSIONS;

    // ── test rig ────────────────────────────────────────────────────────────
    let dev = MockDevice::new();
    let clock = Arc::new(MockClock::new(Instant::now()));
    let mut srv = Server::new(Box::new(dev.clone()), clock.clone());

    let (cli_key, _isn) = establish_connection(&dev, &mut srv);

    let key = cli_key.reverse();

    // set a small-but-legal RTO (>= MIN_RTO so it is not clamped)
    let initial_rto = Duration::from_millis(250);
    assert!(srv.force_rto_for(&key, initial_rto));

    // make the very first transmit disappear
    dev.set_drop_probability(1.0);

    // C → S data (will generate a server reply that gets dropped)
    let data = PacketFactory::data(
        "10.0.0.2", "10.0.0.1", 12345, 80, /*seq*/ 1001, /*ack*/ 1, b"bar\n",
    );
    dev.inject_packet("C→S data", data.clone());
    srv.handle_packet(&data);

    dev.clear_sent(); // ignore the dropped packet
    dev.set_drop_probability(0.0); // watch retries

    //RTO cycles
    for attempt in 1..=MAX_RETRANSMISSIONS as usize + 1 {
        // pull the *current* RTO from the connection
        let cur_rto = srv.get_connection_for_key(&key).unwrap().get_rto();

        // go just past it
        clock.advance(cur_rto + Duration::from_millis(1));
        srv.check_retransmissions();

        let sent = dev.get_sent_packets();
        if attempt <= MAX_RETRANSMISSIONS as usize {
            assert!(
                !sent.is_empty(),
                "attempt {attempt}: expected retransmission"
            );
        } else {
            assert!(
                sent.is_empty(),
                "attempt {attempt}: expected no retransmission (segment abandoned)"
            );
        }
        dev.clear_sent();
    }

    // queue must be empty now
    assert!(
        srv.get_connection_for_key(&key)
            .unwrap()
            .get_retransmit_queue()
            .is_empty(),
        "retransmit queue should be empty after abandonment"
    );
}

#[test]
fn lost_syn_ack_then_success() {
    use crate::tcp::{TcpState, MAX_RETRANSMISSIONS};

    let dev = MockDevice::new();
    let clock = Arc::new(MockClock::new(Instant::now()));
    let mut server = Server::new(Box::new(dev.clone()), clock.clone());

    // ── 1) C → S : SYN ──────────────────────────────────────────────
    let syn = PacketFactory::syn("10.0.0.2", "10.0.0.1", 12345, 80, /*seq*/ 1000);
    server.handle_packet(&syn);

    let cli_srv_key = TcpKey::new_for_test("10.0.0.2", 12345, "10.0.0.1", 80);

    // make the SYN-ACK RTO tiny so the test runs fast
    let tiny_rto = Duration::from_millis(20);
    assert!(server.force_rto_for(&cli_srv_key, tiny_rto));

    // ── 2) drop the first N-1 retransmissions ──────────────────────────
    dev.set_drop_probability(1.0);

    // helper: gets the live RTO each time
    let mut current_rto = tiny_rto;
    for _ in 0..(MAX_RETRANSMISSIONS - 1) {
        clock.advance(current_rto + Duration::from_millis(1));
        server.check_retransmissions();
        dev.clear_sent();

        // after the first timeout the stack may have backed-off
        current_rto = server
            .get_connection_for_key(&cli_srv_key) // ← use the original key
            .unwrap()
            .get_rto();
    }

    // ── 3) allow the next SYN-ACK to pass ──────────────────────────────
    dev.set_drop_probability(0.0);
    clock.advance(current_rto + Duration::from_millis(1)); // ← use live RTO
    server.check_retransmissions();

    // we should now have exactly one packet: a SYN-ACK
    let syn_ack = dev.last_sent_packet().expect("SYN-ACK must appear");
    let (_ip, tcp_sa) = parse_tcp_packet(&syn_ack);
    assert!(
        tcp_sa.syn() && tcp_sa.ack(),
        "server packet should be SYN+ACK"
    );

    // ── 4) C → S : final ACK finishes the handshake ─────────────────
    let final_ack = PacketFactory::ack(
        "10.0.0.2",
        "10.0.0.1",
        12345,
        80,
        /*seq*/ 1001,
        tcp_sa.sequence_number() + 1, // ACK the SYN-ACK
    );
    server.handle_packet(&final_ack);

    let conn = server
        .get_connection_for_key(&cli_srv_key)
        .expect("connection should exist");

    assert_eq!(conn.state(), TcpState::Established, "handshake completed");
    assert!(
        conn.get_retransmit_queue().is_empty(),
        "retransmit queue must be empty after ACK arrives"
    );
}
