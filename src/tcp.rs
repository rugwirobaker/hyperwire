use etherparse::{IpNumber, Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::clock::Clock;
use crate::Device;

const INITIAL_RTO: Duration = Duration::from_millis(1000); // 1 second initial RTO
const MIN_RTO: Duration = Duration::from_millis(200); // 200ms minimum RTO
const MAX_RTO: Duration = Duration::from_secs(60); // 60 seconds maximum RTO
const ALPHA: f64 = 0.125; // Smoothing factor for SRTT (RFC 6298 recommends 1/8)
const BETA: f64 = 0.25; // Smoothing factor for RTTVAR (RFC 6298 recommends 1/4)

pub const MAX_RETRANSMISSIONS: u8 = 5; // Maximum retransmission attempts

///! TCP protocol flags as defined in RFC 793.
///
/// SYN flag - synchronize sequence numbers
pub const SYN: u8 = 1 << 1;
/// ACK flag - acknowledgment field is significant
pub const ACK: u8 = 1 << 4;
/// FIN flag - no more data from sender
pub const FIN: u8 = 1 << 0;
/// RST flag - reset the connection
pub const RST: u8 = 1 << 2;
/// PSH flag - push function
pub const PSH: u8 = 1 << 3;
/// URG flag - urgent pointer field is significant
pub const URG: u8 = 1 << 5;

/// Combines TCP flags for human-readable display
pub fn flags_to_string(flags: u8) -> String {
    format!(
        "{}{}{}{}{}",
        if flags & SYN != 0 { "S" } else { "-" },
        if flags & ACK != 0 { "A" } else { "-" },
        if flags & FIN != 0 { "F" } else { "-" },
        if flags & RST != 0 { "R" } else { "-" },
        if flags & PSH != 0 { "P" } else { "-" },
    )
}

/// Combine flags from a TCP header into a flags byte
pub fn tcp_header_to_flags(tcp_hdr: &TcpHeaderSlice) -> u8 {
    (tcp_hdr.fin() as u8) << 0
        | (tcp_hdr.syn() as u8) << 1
        | (tcp_hdr.rst() as u8) << 2
        | (tcp_hdr.psh() as u8) << 3
        | (tcp_hdr.ack() as u8) << 4
        | (tcp_hdr.urg() as u8) << 5
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

impl std::fmt::Display for TcpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} → {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

impl TcpKey {
    pub fn new(ip: &Ipv4HeaderSlice, tcp: &TcpHeaderSlice) -> Self {
        TcpKey {
            src_ip: ip.source_addr(),
            src_port: tcp.source_port(),
            dst_ip: ip.destination_addr(),
            dst_port: tcp.destination_port(),
        }
    }

    pub fn reverse(&self) -> Self {
        TcpKey {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    // Closed,
    Listen,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::SynReceived => write!(f, "SYN-RECEIVED"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::CloseWait => write!(f, "CLOSE-WAIT"),
            TcpState::LastAck => write!(f, "LAST-ACK"),
        }
    }
}

impl TcpState {
    pub fn on_event(self, ev: TcpEvent) -> Option<TcpState> {
        use TcpEvent::*;
        use TcpState::*;
        match (self, ev) {
            (Listen, RecvSyn) => Some(SynReceived),
            (SynReceived, RecvAck) => Some(Established),
            (Established, RecvFin) => Some(CloseWait),
            (CloseWait, RecvAck) => Some(LastAck),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpEvent {
    RecvSyn, // incoming SYN without ACK
    RecvAck, // pure ACK
    RecvFin, // incoming FIN
}

impl std::fmt::Display for TcpEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpEvent::RecvSyn => write!(f, "RCV_SYN"),
            TcpEvent::RecvAck => write!(f, "RCV_ACK"),
            TcpEvent::RecvFin => write!(f, "RCV_FIN"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RetransmitSegment {
    pub data: Vec<u8>,        // Payload data
    pub seq: u32,             // Starting sequence number
    pub sent_at: Instant,     // When this segment was last sent
    pub retransmit_count: u8, // Number of times this segment has been retransmitted
    pub flags: u8,            // TCP flags (SYN, ACK, FIN, etc.)
    pub ack: u32,             // ACK number (if ACK flag is set)
}

impl RetransmitSegment {
    pub fn new(
        seq: u32,
        retransmit_count: u8,
        sent_at: Instant,
        flags: u8,
        data: Vec<u8>,
        ack: u32,
    ) -> Self {
        RetransmitSegment {
            data,
            seq,
            sent_at,
            retransmit_count,
            flags,
            ack,
        }
    }
}

pub struct TcpConnection {
    id: u64,
    state: TcpState,
    server_isn: u32,
    recv_next: u32,
    send_next: u32,
    recv_buffer: Vec<u8>, // data we’ve received
    send_buffer: Vec<u8>, // data waiting to be sent
    reasm_buf: BTreeMap<u32, Vec<u8>>,
    // debugging
    created_at: Instant,
    established_at: Option<Instant>,
    bytes_received: usize,
    bytes_sent: usize,
    // retransmission
    rto: Duration,          // Current RTO value
    srtt: Option<Duration>, // Smoothed RTT
    rttvar: Duration,       // RTT variance
    // New retransmission queue - key is starting sequence number
    retransmit_queue: BTreeMap<u32, RetransmitSegment>,
    // a clock we control
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConnection")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("server_isn", &self.server_isn)
            .field("recv_next", &self.recv_next)
            .field("send_next", &self.send_next)
            .field("recv_buffer.len()", &self.recv_buffer.len())
            .field("send_buffer.len()", &self.send_buffer.len())
            .field("reasm_buf.len()", &self.reasm_buf.len())
            .field("rto", &self.rto)
            .field("srtt", &self.srtt)
            .field("rttvar", &self.rttvar)
            .field("retransmit_queue.len()", &self.retransmit_queue.len())
            .finish()
    }
}

impl TcpConnection {
    /// Create an initial listener-state connection
    pub fn new_listen(id: u64, clock: Arc<dyn Clock>) -> Self {
        TcpConnection {
            id,
            state: TcpState::Listen,
            server_isn: 0,
            recv_next: 0,
            send_next: 0,
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
            reasm_buf: BTreeMap::new(),
            created_at: clock.now(),
            established_at: None,
            bytes_received: 0,
            bytes_sent: 0,
            // Retransmission fields
            rto: INITIAL_RTO,
            srtt: None,
            rttvar: Duration::from_millis(500), // Initial variance
            retransmit_queue: BTreeMap::new(),
            clock,
        }
    }

    // on_segment is called whenever we receive a new segment
    pub fn on_segment(&mut self, key: &TcpKey, flags: u8, seq: u32, ack: u32, payload: &[u8]) {
        println!(
            "[#{}] {} RX: flags={} seq={} ack={} len={}",
            self.id,
            key,
            flags_to_string(flags),
            seq,
            ack,
            payload.len()
        );

        let event = if flags & SYN != 0 && flags & ACK == 0 {
            println!(
                "[#{}] {} ▶ New SYN received, initiating handshake",
                self.id, key
            );
            Some(TcpEvent::RecvSyn)
        } else if flags & FIN != 0 {
            println!(
                "[#{}] {} ▶ FIN received, peer initiating close",
                self.id, key
            );
            Some(TcpEvent::RecvFin)
        } else if flags & ACK != 0 {
            match self.state {
                TcpState::SynReceived if ack == self.send_next => {
                    println!(
                        "[#{}] {} ▶ Handshake ACK received, connection established!",
                        self.id, key
                    );
                    Some(TcpEvent::RecvAck)
                }
                TcpState::Established => {
                    if !payload.is_empty() {
                        println!("[#{}] {} ▶ Data ACK received", self.id, key);
                    }
                    Some(TcpEvent::RecvAck)
                }
                TcpState::CloseWait if ack == self.send_next => {
                    println!(
                        "[#{}] {} ▶ Final ACK received, closing connection",
                        self.id, key
                    );
                    Some(TcpEvent::RecvAck) // final ACK of our FIN
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some(ev) = event {
            if let Some(next) = self.state.on_event(ev) {
                println!(
                    "[#{}] {} STATE: {} --[{}]--> {}",
                    self.id, key, self.state, ev, next
                );
                self.state = next;

                // Mark when connection becomes established
                if next == TcpState::Established {
                    self.established_at = Some(self.clock.now());
                }
            }
        }

        // 2) Data reassembly only in Established
        if self.state == TcpState::Established && !payload.is_empty() {
            match seq.cmp(&self.recv_next) {
                Ordering::Equal => {
                    println!(
                        "📥 Accepting in-order segment seq={}, len={}",
                        seq,
                        payload.len()
                    );
                    self.accept_payload(payload);
                    while let Some((&nseq, _)) = self.reasm_buf.iter().next() {
                        if nseq != self.recv_next {
                            break;
                        }
                        let buf = self.reasm_buf.remove(&nseq).unwrap();
                        println!(
                            "🧩 Draining buffered segment seq={}, len={}",
                            nseq,
                            buf.len()
                        );
                        self.accept_payload(&buf);
                    }
                }
                Ordering::Greater => {
                    println!(
                        "📦 Buffering out-of-order segment seq={}, len={}",
                        seq,
                        payload.len()
                    );
                    self.reasm_buf.insert(seq, payload.to_vec());
                }
                Ordering::Less => {
                    let overlap = (self.recv_next - seq) as usize;
                    println!(
                        "🔄 Processing overlapping segment seq={}, len={}, overlap={}",
                        seq,
                        payload.len(),
                        overlap
                    );
                    if overlap < payload.len() {
                        self.accept_payload(&payload[overlap..]);
                    }
                }
            }
        }
    }

    /// advertising a constant window for now.
    pub fn advertised_window(&self) -> u16 {
        65_535 // max unscaled window
    }

    /// accept_payload into the recv_buffer
    pub fn accept_payload(&mut self, data: &[u8]) {
        self.recv_buffer.extend_from_slice(data);
        self.recv_next = self.recv_next.wrapping_add(data.len() as u32);
        self.bytes_received += data.len();

        if let Ok(text) = std::str::from_utf8(data) {
            if !text.chars().all(char::is_whitespace) {
                println!("[#{}] ◀ RCV: \"{}\"", self.id, text.trim_end());
            }
        }
    }
}

impl TcpConnection {
    /// Calculates new RTO when an RTT measurement is made
    pub fn update_rto(&mut self, measured_rtt: Duration) {
        println!(
            "[#{}] 📊 RTT measurement: {:?}, current RTO: {:?}",
            self.id, measured_rtt, self.rto
        );
        match self.srtt {
            // First RTT measurement - initialize SRTT and RTTVAR (RFC 6298)
            None => {
                self.srtt = Some(measured_rtt);
                self.rttvar = Duration::from_micros((measured_rtt.as_micros() / 2) as u64);
                let new_rto = Duration::from_micros(
                    (self.srtt.unwrap().as_micros() + 4 * self.rttvar.as_micros()) as u64,
                );
                self.rto = new_rto.clamp(MIN_RTO, MAX_RTO);
            }
            // Update RTTVAR and SRTT (RFC 6298)
            Some(srtt) => {
                // Convert to signed integers for calculations to avoid underflow
                let measured_micros = measured_rtt.as_micros() as i128;
                let srtt_micros = srtt.as_micros() as i128;
                let rttvar_micros = self.rttvar.as_micros() as i128;

                // Calculate absolute difference |SRTT - measured_RTT|
                let abs_diff = if srtt_micros > measured_micros {
                    srtt_micros - measured_micros
                } else {
                    measured_micros - srtt_micros
                };
                // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - measured_RTT|
                let new_rttvar_micros =
                    ((1.0 - BETA) * rttvar_micros as f64 + BETA * abs_diff as f64) as i128;
                // SRTT = (1 - alpha) * SRTT + alpha * measured_RTT
                let new_srtt_micros =
                    ((1.0 - ALPHA) * srtt_micros as f64 + ALPHA * measured_micros as f64) as i128;
                // Update the values
                self.rttvar = Duration::from_micros(new_rttvar_micros as u64);
                self.srtt = Some(Duration::from_micros(new_srtt_micros as u64));
                // RTO = SRTT + 4 * RTTVAR
                let new_rto =
                    Duration::from_micros((new_srtt_micros + 4 * new_rttvar_micros) as u64);
                // Enforce RTO bounds
                self.rto = new_rto.clamp(MIN_RTO, MAX_RTO);
            }
        }
        println!(
            "[#{}] 📊 Updated → SRTT: {:?}, RTTVAR: {:?}, new RTO: {:?}",
            self.id,
            self.srtt.unwrap(),
            self.rttvar,
            self.rto
        );
    }

    // Qeues packets to the retransmission queue
    pub fn queue_for_retransmit(&mut self, seq: u32, flags: u8, ack: u32, data: Vec<u8>) {
        let sent_at = self.clock.now();
        let segment = RetransmitSegment::new(seq, 0, sent_at, flags, data, ack);

        println!(
            "[#{}] 📦 Queueing for potential retransmit: seq={}, len={}, flags={:02b}",
            self.id,
            seq,
            segment.data.len(),
            flags
        );
        self.retransmit_queue.insert(seq, segment);
    }

    // Check for segments that need retransmission
    pub fn check_retransmit_queue(&mut self) -> Vec<RetransmitSegment> {
        let now = self.clock.now();
        let mut to_retransmit = Vec::new();

        // Collect segments that have timed out
        for (&seq, segment) in self.retransmit_queue.iter_mut() {
            if now.duration_since(segment.sent_at) >= self.rto {
                if segment.retransmit_count < MAX_RETRANSMISSIONS {
                    println!(
                        "[#{}] ⏱️ RTO expired for segment: seq={}, len={}, attempt={}",
                        self.id,
                        seq,
                        segment.data.len(),
                        segment.retransmit_count + 1
                    );

                    // Clone segment for retransmission
                    let mut retransmit = segment.clone();
                    retransmit.retransmit_count += 1;
                    to_retransmit.push(retransmit);

                    // Back off RTO using exponential backoff
                    if segment.retransmit_count == 0 {
                        // Only double RTO on first retransmission (RFC 6298)
                        self.rto = (self.rto * 2).clamp(MIN_RTO, MAX_RTO);
                        println!("[#{}] ⏱️ Backing off RTO to {:?}", self.id, self.rto);
                    }
                } else {
                    // Too many retransmissions, will remove from queue
                    println!(
                        "[#{}] ❌ Abandoned retransmission after {} attempts: seq={}",
                        self.id, MAX_RETRANSMISSIONS, seq
                    );
                }
            }
        }

        // Update segments with new retransmit info
        for segment in &to_retransmit {
            if let Some(entry) = self.retransmit_queue.get_mut(&segment.seq) {
                entry.sent_at = self.clock.now();
                entry.retransmit_count = segment.retransmit_count;
            }
        }

        // Remove segments that exceeded max retransmissions
        self.retransmit_queue
            .retain(|_, segment| segment.retransmit_count < MAX_RETRANSMISSIONS);
        to_retransmit
    }

    /// Remove acknowledged segments from retransmit queue
    pub fn process_ack(&mut self, ack_num: u32) {
        let mut segments_to_remove = Vec::new();
        let mut rtt_measurements = Vec::new();

        // Find all segments that are fully acknowledged
        for (&seq, segment) in &self.retransmit_queue {
            let end_seq = seq.wrapping_add(segment.data.len() as u32);

            // Check if this segment is fully acknowledged
            if is_seq_lte(seq, ack_num) && is_seq_lt(end_seq, ack_num) {
                segments_to_remove.push(seq);

                // If this isn't a retransmission, record RTT measurement
                if segment.retransmit_count == 0 {
                    let rtt = segment.sent_at.elapsed();
                    rtt_measurements.push(rtt);
                }
            }
        }

        // Process RTT measurements (if any)
        for rtt in rtt_measurements {
            self.update_rto(rtt);
        }

        // Remove acknowledged segments
        for seq in segments_to_remove {
            let removed = self.retransmit_queue.remove(&seq);
            if let Some(segment) = removed {
                println!(
                    "[#{}] ✅ Removed acknowledged segment from retransmit queue: seq={}, len={}",
                    self.id,
                    seq,
                    segment.data.len()
                );
            }
        }
    }
}

/// Determines if sequence number `a` is strictly less than sequence number `b`,
/// accounting for TCP sequence number wrapping.
///
/// TCP sequence numbers are 32-bit unsigned integers that wrap around to 0
/// after reaching 2^32 - 1. This makes traditional comparison operators
/// inadequate for determining the relative ordering of sequence numbers
/// near the wraparound point.
///
/// This implementation follows RFC 1323's recommendation for sequence number
/// comparison: `a < b` if `b - a` is positive when evaluated in 32-bit signed
/// integer arithmetic.
///
/// # Examples
///
/// ```text
/// // Normal case: 100 < 200
/// assert!(is_seq_lt(100, 200));
///
/// // Wraparound case: 4_294_967_290 < 10
/// // This means sequence number 10 comes after 4_294_967_290 in TCP sequence space
/// assert!(is_seq_lt(4_294_967_290, 10));
///
/// // Not less than: 200 !< 100
/// assert!(!is_seq_lt(200, 100));
/// ```
///
/// # References
///
/// - RFC 1323: TCP Extensions for High Performance
/// - RFC 793: Transmission Control Protocol
fn is_seq_lt(a: u32, b: u32) -> bool {
    // RFC 1323: a < b if b - a > 0, evaluated in 32-bit signed arithmetic
    ((b as i32) - (a as i32)) > 0
}
/// Determines if sequence number `a` is less than or equal to sequence number `b`,
/// accounting for TCP sequence number wrapping.
///
/// This function combines an equality check with the `is_seq_lt` function to
/// create a less-than-or-equal comparison that properly handles TCP sequence
/// number wrapping.
///
/// # Examples
///
/// ```text
/// // Equal case
/// assert!(is_seq_lte(100, 100));
///
/// // Less than case
/// assert!(is_seq_lte(100, 200));
///
/// // Wraparound case
/// assert!(is_seq_lte(4_294_967_290, 10));
///
/// // Not less than or equal
/// assert!(!is_seq_lte(200, 100));
/// ```
///
/// # References
///
/// - RFC 1323: TCP Extensions for High Performance
/// - RFC 793: Transmission Control Protocol
fn is_seq_lte(a: u32, b: u32) -> bool {
    a == b || is_seq_lt(a, b)
}

pub struct Server {
    device: Box<dyn Device>,
    clock: Arc<dyn Clock>,
    connections: HashMap<TcpKey, TcpConnection>,
    conn_counter: u64,
}

impl Server {
    pub fn new(device: Box<dyn Device>, clock: Arc<dyn Clock>) -> Self {
        Self {
            device,
            clock,
            connections: HashMap::new(),
            conn_counter: 0,
        }
    }

    pub fn run(&mut self) {
        let mut buf = [0u8; 1504];
        let mut last_retransmit_check = self.clock.now();
        loop {
            if last_retransmit_check.elapsed() > Duration::from_millis(100) {
                self.check_retransmissions();
                last_retransmit_check = self.clock.now();
            }
            let n = match self.device.recv(&mut buf) {
                Ok(n) => n,
                Err(_) => continue,
            };
            self.handle_packet(&buf[..n]);
        }
    }

    pub fn handle_packet(&mut self, packet: &[u8]) {
        let ip_hdr = match Ipv4HeaderSlice::from_slice(&packet) {
            Ok(h) if h.protocol() == IpNumber::from(6) => h,
            _ => return,
        };
        let tcp_hdr = match TcpHeaderSlice::from_slice(&packet[ip_hdr.slice().len()..]) {
            Ok(h) => h,
            _ => return,
        };

        let key = TcpKey::new(&ip_hdr, &tcp_hdr);
        let rkey = key.reverse();

        let flags = tcp_header_to_flags(&tcp_hdr);

        // Debug: Show which client/connection we're dealing with
        println!("📡 Packet from {}:{} -> {}:{}, flags=0x{:02x} (SYN={}, ACK={}, FIN={}, RST={}, PSH={})",
                       key.src_ip, key.src_port, key.dst_ip, key.dst_port, flags,
                       tcp_hdr.syn(), tcp_hdr.ack(), tcp_hdr.fin(), tcp_hdr.rst(), tcp_hdr.psh());

        // 1) New connection SYN
        if !self.connections.contains_key(&key) && flags == SYN {
            self.conn_counter += 1;
            let client_isn = tcp_hdr.sequence_number();
            let server_isn = rand::random();

            println!("\n🎯 New connection #{} from {}", self.conn_counter, key);
            println!("   Client ISN: {}, Server ISN: {}", client_isn, server_isn);

            let mut conn = TcpConnection::new_listen(self.conn_counter, self.clock.clone());
            // trigger Listen->SynReceived
            if let Some(ns) = conn.state.on_event(TcpEvent::RecvSyn) {
                conn.state = ns;
                conn.server_isn = server_isn;
                conn.send_next = server_isn.wrapping_add(1);
                conn.recv_next = client_isn.wrapping_add(1);
            }

            // send SYN-ACK
            let win = conn.advertised_window();
            let ackn = client_isn.wrapping_add(1);
            println!(
                "[#{}] {} TX: flags=SA- seq={} ack={} win={}",
                self.conn_counter, rkey, server_isn, ackn, win
            );
            let builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                .tcp(
                    rkey.src_port,
                    rkey.dst_port,
                    conn.server_isn,
                    conn.advertised_window(),
                )
                .syn()
                .ack(ackn);
            let mut pkt = Vec::with_capacity(builder.size(0));
            builder.write(&mut pkt, &[]).unwrap();
            self.device.send(&pkt).unwrap();

            // add to rentrasmition queue until we receive final ACK(handshake complete)
            conn.queue_for_retransmit(
                conn.server_isn,
                SYN | ACK,  // SYN-ACK flags
                ackn,       // acknowledgment number
                Vec::new(), // empty data for SYN
            );
            self.connections.insert(key, conn);
            return;
        }

        // 2) Existing connection
        if let Some(conn) = self.connections.get_mut(&key) {
            let off = ip_hdr.slice().len() + tcp_hdr.slice().len();
            let payload = &packet[off..];

            conn.on_segment(
                &key,
                flags,
                tcp_hdr.sequence_number(),
                tcp_hdr.acknowledgment_number(),
                payload,
            );

            if (flags & ACK) != 0 {
                conn.process_ack(tcp_hdr.acknowledgment_number());
            }

            // pure ACK for new data
            if conn.state == TcpState::Established
                && conn.recv_next != tcp_hdr.sequence_number().wrapping_add(payload.len() as u32)
            {
                println!(
                    "[#{}] {} TX: flags=-A-- seq={} ack={}",
                    conn.id, rkey, conn.send_next, conn.recv_next
                );

                let builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .ack(conn.recv_next);
                let mut pkt = Vec::with_capacity(builder.size(0));
                builder.write(&mut pkt, &[]).unwrap();
                self.device.send(&pkt).unwrap();
                // it's not necessary to retransmit pure acks
            }

            // Prepare echo data on newline
            if conn.state == TcpState::Established && conn.send_buffer.is_empty() {
                if let Some(pos) = conn.recv_buffer.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = conn.recv_buffer.drain(..=pos).collect();
                    if let Ok(text) = std::str::from_utf8(&line) {
                        if !text.chars().all(char::is_whitespace) {
                            println!("[#{}] 🔄 Echo queued: \"{}\"", conn.id, text.trim());
                        }
                    }
                    conn.send_buffer.extend_from_slice(&line);
                }
            }

            // build and send data packet
            if conn.state == TcpState::Established && !conn.send_buffer.is_empty() {
                let chunk = conn.send_buffer.drain(..).collect::<Vec<_>>();
                println!(
                    "[#{}] {} TX: flags=-AP- seq={} ack={} len={}",
                    conn.id,
                    rkey,
                    conn.send_next,
                    conn.recv_next,
                    chunk.len()
                );

                let builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .psh()
                    .ack(conn.recv_next);
                let mut pkt = Vec::with_capacity(builder.size(chunk.len()));
                builder.write(&mut pkt, &chunk).unwrap();
                self.device.send(&pkt).unwrap();

                conn.queue_for_retransmit(
                    conn.send_next,
                    PSH | ACK,      // PSH-ACK flags
                    conn.recv_next, // acknowledgment number
                    chunk.clone(),  // clone the data for potential retransmission
                );

                // conn.send_next = conn.send_next.wrapping_add(chunk.len() as u32);
                if let Ok(text) = std::str::from_utf8(&chunk) {
                    if !text.chars().all(char::is_whitespace) {
                        println!("[#{}] ▶ SND: \"{}\"", conn.id, text.trim());
                    }
                }

                conn.send_next = conn.send_next.wrapping_add(chunk.len() as u32);
                conn.bytes_sent += chunk.len();
            }

            // 5) ACK the peer's FIN so it stops retransmitting
            if conn.state == TcpState::CloseWait && (flags & FIN) != 0 {
                conn.recv_next = conn.recv_next.wrapping_add(1);
                println!(
                    "[#{}] {} TX: flags=-A-- seq={} ack={} (ACK for FIN)",
                    conn.id, rkey, conn.send_next, conn.recv_next
                );

                let builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .ack(conn.recv_next);
                let mut ack = Vec::with_capacity(builder.size(0));
                builder.write(&mut ack, &[]).unwrap();
                self.device.send(&ack).unwrap();
                // we need to make sure the client receives our ACK for their FIN
                conn.queue_for_retransmit(
                    conn.send_next,
                    ACK,            // ACK flag
                    conn.recv_next, // acknowledgment number
                    Vec::new(),     // empty data
                );
                println!("  ← Sent ACK for FIN (recv_next={})", conn.recv_next);
            }

            // 6) Send our FIN+ACK once echo is done
            if conn.state == TcpState::CloseWait && conn.send_buffer.is_empty() {
                println!(
                    "[#{}] {} TX: flags=-AF- seq={} ack={} (FIN+ACK)",
                    conn.id, rkey, conn.send_next, conn.recv_next
                );

                let builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .fin()
                    .ack(conn.recv_next);
                let mut fin_pkt = Vec::with_capacity(builder.size(0));
                builder.write(&mut fin_pkt, &[]).unwrap();
                self.device.send(&fin_pkt).unwrap();
                conn.queue_for_retransmit(
                    conn.send_next,
                    FIN | ACK,      // FIN-ACK flags
                    conn.recv_next, // acknowledgment number
                    Vec::new(),     // empty data for FIN
                );
                conn.send_next = conn.send_next.wrapping_add(1);
                conn.state = TcpState::LastAck;
            }

            // Close connection
            if conn.state == TcpState::LastAck
                && (flags & ACK) != 0
                && tcp_hdr.acknowledgment_number() == conn.send_next
            {
                let total_duration = conn.created_at.elapsed();
                let established_duration = conn
                    .established_at
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::from_secs(0));

                println!("\n📊 Connection #{} statistics:", conn.id);
                println!("   Total duration: {:.2}s", total_duration.as_secs_f64());
                println!(
                    "   Established duration: {:.2}s",
                    established_duration.as_secs_f64()
                );
                println!("   Bytes received: {}", conn.bytes_received);
                println!("   Bytes sent: {}", conn.bytes_sent);
                println!("   State: {} → CLOSED", conn.state);
                println!("🔚 Connection #{} closed\n", conn.id);

                self.connections.remove(&key);
            }
        }
        // 7) Handle RST flag: they said to shove it wherever
        if flags & RST != 0 {
            if let Some(conn) = self.connections.get(&key) {
                println!("\n⚠️  RST received for connection #{}", conn.id);
            }
            self.connections.remove(&key);
        }
    }

    pub fn check_retransmissions(&mut self) {
        let mut retransmissions = Vec::new();

        // Collect all retransmissions needed across connections
        for (key, conn) in &mut self.connections {
            let segments = conn.check_retransmit_queue();
            for segment in segments {
                retransmissions.push((key.clone(), conn.id, segment));
            }
        }

        // Process retransmissions
        for (key, conn_id, segment) in retransmissions {
            let rkey = key.reverse();

            println!(
                "[#{}] 🔄 Retransmitting: {} flags={:02b} seq={} ack={} len={}",
                conn_id,
                rkey,
                segment.flags,
                segment.seq,
                segment.ack,
                segment.data.len()
            );

            // Build packet with appropriate flags using match expressions
            let mut builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                .tcp(rkey.src_port, rkey.dst_port, segment.seq, 65535);

            // Apply TCP flags - using match for better readability
            builder = match segment.flags & SYN != 0 {
                true => builder.syn(),
                false => builder,
            };

            builder = match segment.flags & ACK != 0 {
                true => builder.ack(segment.ack),
                false => builder,
            };

            builder = match segment.flags & FIN != 0 {
                true => builder.fin(),
                false => builder,
            };

            builder = match segment.flags & PSH != 0 {
                true => builder.psh(),
                false => builder,
            };

            // Write packet and send
            let mut pkt = Vec::with_capacity(builder.size(segment.data.len()));
            builder.write(&mut pkt, &segment.data).unwrap();
            self.device.send(&pkt).unwrap();
        }
    }
}

#[cfg(test)]
impl TcpConnection {
    pub fn set_rto(&mut self, rto: Duration) {
        self.rto = rto;
    }
}

#[cfg(test)]
impl Server {
    pub fn get_connections(&self) -> &HashMap<TcpKey, TcpConnection> {
        &self.connections
    }

    pub fn get_connections_mut(&mut self) -> &mut HashMap<TcpKey, TcpConnection> {
        &mut self.connections
    }
}

#[cfg(test)]
impl Server {
    pub fn force_rto_for(&mut self, key: &TcpKey, rto: Duration) -> bool {
        match self.connections.get_mut(key) {
            Some(conn) => {
                conn.rto = rto;
                println!("✅ Forced RTO to {:?} for connection #{}", rto, conn.id);
                true
            }
            None => {
                println!("❌ No connection found for key: {}", key);
                false
            }
        }
    }
}

#[cfg(test)]
impl TcpKey {
    // Test-specific constructor that doesn't require header slices
    pub fn new_for_test(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> Self {
        TcpKey {
            src_ip: src_ip.parse().unwrap(),
            src_port,
            dst_ip: dst_ip.parse().unwrap(),
            dst_port,
        }
    }
}

impl TcpConnection {
    /// Test-only immutable snapshot of the connection’s state.
    #[cfg(test)]
    pub fn peek(&self) -> ConnSnapshot {
        ConnSnapshot {
            id: self.id,
            state: self.state,
            send_next: self.send_next,
            recv_next: self.recv_next,
            rto: self.rto,
            retransmits: self.retransmit_queue.len(),
            queued_bytes: self.send_buffer.len(),
            bytes_received: self.bytes_received,
            bytes_sent: self.bytes_sent,
        }
    }
}

/// Immutable view – every field is **Copy** so tests can pattern-match easily.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnSnapshot {
    pub id: u64,
    pub state: TcpState,
    pub send_next: u32,
    pub recv_next: u32,
    pub rto: Duration,
    pub retransmits: usize,
    pub queued_bytes: usize,
    pub bytes_received: usize,
    pub bytes_sent: usize,
}

#[cfg(test)]
impl Server {
    pub fn peek_conn(&self, key: &TcpKey) -> Option<ConnSnapshot> {
        self.connections.get(key).map(|c| c.peek())
    }
}
