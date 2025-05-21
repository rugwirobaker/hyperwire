use crate::tcp::{self, flags, segment};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{self};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::clock::Clock;

const INITIAL_RTO: Duration = Duration::from_millis(1000); // 1 second initial RTO
const MIN_RTO: Duration = Duration::from_millis(200); // 200ms minimum RTO
const MAX_RTO: Duration = Duration::from_secs(60); // 60 seconds maximum RTO
const ALPHA: f64 = 0.125; // Smoothing factor for SRTT (RFC 6298 recommends 1/8)
const BETA: f64 = 0.25; // Smoothing factor for RTTVAR (RFC 6298 recommends 1/4)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub(crate) src_ip: Ipv4Addr,
    pub(crate) src_port: u16,
    pub(crate) dst_ip: Ipv4Addr,
    pub(crate) dst_port: u16,
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} → {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

impl Key {
    pub fn new(ip: &Ipv4HeaderSlice, tcp: &TcpHeaderSlice) -> Self {
        Key {
            src_ip: ip.source_addr(),
            src_port: tcp.source_port(),
            dst_ip: ip.destination_addr(),
            dst_port: tcp.destination_port(),
        }
    }

    pub fn reverse(&self) -> Self {
        Key {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Listen,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
    // Client-side states
    SynSent,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    // special
    Closed,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Listen => write!(f, "LISTEN"),
            State::SynReceived => write!(f, "SYN-RECEIVED"),
            State::Established => write!(f, "ESTABLISHED"),
            State::CloseWait => write!(f, "CLOSE-WAIT"),
            State::LastAck => write!(f, "LAST-ACK"),
            State::SynSent => write!(f, "SYN-SENT"),
            State::FinWait1 => write!(f, "FIN-WAIT-1"),
            State::FinWait2 => write!(f, "FIN-WAIT-2"),
            State::Closing => write!(f, "CLOSING"),
            State::TimeWait => write!(f, "TIME-WAIT"),
            State::Closed => write!(f, "CLOSED"),
        }
    }
}

impl State {
    pub fn on_event(self, ev: Event) -> Option<State> {
        use Event::*;
        use State::*;
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
pub enum Event {
    // Closed,     // initial state: a special case
    RecvSyn,    // incoming SYN without ACK
    RecvAck,    // pure ACK
    RecvFin,    // incoming FIN
    SendSyn,    // outgoing SYN
    RecvSynAck, // incoming SYN+ACK
    SendFin,    // outgoing FIN
    Timeout,    // TIME_WAIT timeout expired
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // TcpEvent::Closed => write!(f, "CLOSED"),
            Event::RecvSyn => write!(f, "RCV_SYN"),
            Event::RecvAck => write!(f, "RCV_ACK"),
            Event::RecvFin => write!(f, "RCV_FIN"),
            Event::SendSyn => write!(f, "SND_SYN"),
            Event::RecvSynAck => write!(f, "RCV_SYN_ACK"),
            Event::SendFin => write!(f, "SND_FIN"),
            Event::Timeout => write!(f, "TIMEOUT"),
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

pub struct Connection {
    pub(crate) id: u64,
    pub(crate) state: State,
    pub(crate) server_isn: u32,
    pub(crate) recv_next: u32,
    pub(crate) send_next: u32,
    pub(crate) recv_buffer: Vec<u8>, // data we’ve received
    pub(crate) send_buffer: Vec<u8>, // data waiting to be sent
    reasm_buf: BTreeMap<u32, Vec<u8>>,
    // debugging
    pub(crate) created_at: Instant,
    pub(crate) established_at: Option<Instant>,
    pub(crate) bytes_received: usize,
    pub(crate) bytes_sent: usize,
    // retransmission
    pub(crate) rto: Duration, // Current RTO value
    srtt: Option<Duration>,   // Smoothed RTT
    rttvar: Duration,         // RTT variance
    // New retransmission queue - key is starting sequence number
    retransmit_queue: BTreeMap<u32, RetransmitSegment>,
    // a clock we control
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for Connection {
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

impl Connection {
    /// Create an initial listener-state connection
    pub fn listen(id: u64, clock: Arc<dyn Clock>) -> Self {
        Connection {
            id,
            state: State::Listen,
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

    /// Create an active, connecting connection (client-side)
    pub fn connect(id: u64, clock: Arc<dyn Clock>, isn: u32) -> Self {
        let mut conn = Connection {
            id,
            state: State::Closed,
            server_isn: 0,
            recv_next: 0,
            send_next: isn.wrapping_add(1), // Next byte after SYN
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
            reasm_buf: BTreeMap::new(),
            created_at: clock.now(),
            established_at: None,
            bytes_received: 0,
            bytes_sent: 0,
            rto: INITIAL_RTO,
            srtt: None,
            rttvar: Duration::from_millis(500),
            retransmit_queue: BTreeMap::new(),
            clock,
        };

        // Transition from Closed to SynSent
        if let Some(next_state) = conn.state.on_event(Event::SendSyn) {
            conn.state = next_state;
        }

        conn
    }

    // on_segment is called whenever we receive a new segment
    pub fn on_segment(&mut self, key: &Key, fgs: u8, seq: u32, ack: u32, payload: &[u8]) {
        println!(
            "[#{}] {} RX: flags={} seq={} ack={} len={}",
            self.id,
            key,
            flags::flags_to_string(fgs),
            seq,
            ack,
            payload.len()
        );

        let event = match self.state {
            // Server-side state handling
            State::Listen => {
                if fgs & flags::SYN != 0 && fgs & flags::ACK == 0 {
                    println!(
                        "[#{}] {} ▶ New SYN received, initiating handshake",
                        self.id, key
                    );
                    Some(Event::RecvSyn)
                } else {
                    None
                }
            }
            State::SynReceived => {
                if fgs & flags::ACK != 0 && ack == self.send_next {
                    println!(
                        "[#{}] {} ▶ Handshake ACK received, connection established!",
                        self.id, key
                    );
                    Some(Event::RecvAck)
                } else {
                    None
                }
            }
            State::Established => {
                if fgs & flags::FIN != 0 {
                    println!(
                        "[#{}] {} ▶ FIN received, peer initiating close",
                        self.id, key
                    );
                    Some(Event::RecvFin)
                } else {
                    // Just a data or ACK packet in established state
                    if !payload.is_empty() {
                        println!("[#{}] {} ▶ Data received", self.id, key);
                    }
                    Some(Event::RecvAck)
                }
            }
            State::CloseWait => {
                if fgs & flags::ACK != 0 && ack == self.send_next {
                    println!(
                        "[#{}] {} ▶ Final ACK received, connection closing",
                        self.id, key
                    );
                    Some(Event::RecvAck)
                } else {
                    None
                }
            }

            // Client-side state handling
            State::SynSent => {
                if fgs & flags::SYN != 0 && fgs & flags::ACK != 0 {
                    println!(
                        "[#{}] {} ▶ SYN-ACK received, handshake progressing",
                        self.id, key
                    );
                    // Store the server's ISN for acknowledging
                    self.server_isn = seq;
                    self.recv_next = seq.wrapping_add(1); // ACK the SYN
                    Some(Event::RecvSynAck)
                } else {
                    None
                }
            }
            State::FinWait1 => {
                if fgs & flags::ACK != 0 && ack == self.send_next {
                    if fgs & flags::FIN != 0 {
                        // Simultaneous close - FIN+ACK
                        println!("[#{}] {} ▶ FIN+ACK received in FIN_WAIT_1", self.id, key);
                        self.recv_next = seq.wrapping_add(1); // ACK the FIN
                        Some(Event::RecvFin)
                    } else {
                        // Just an ACK of our FIN
                        println!("[#{}] {} ▶ ACK of FIN received in FIN_WAIT_1", self.id, key);
                        Some(Event::RecvAck)
                    }
                } else if fgs & flags::FIN != 0 {
                    // Just a FIN (no ACK of our FIN)
                    println!("[#{}] {} ▶ FIN received in FIN_WAIT_1", self.id, key);
                    self.recv_next = seq.wrapping_add(1); // ACK the FIN
                    Some(Event::RecvFin)
                } else {
                    None
                }
            }
            State::FinWait2 => {
                if fgs & flags::FIN != 0 {
                    println!("[#{}] {} ▶ FIN received in FIN_WAIT_2", self.id, key);
                    self.recv_next = seq.wrapping_add(1); // ACK the FIN
                    Some(Event::RecvFin)
                } else {
                    None
                }
            }
            State::Closing => {
                if fgs & flags::ACK != 0 && ack == self.send_next {
                    println!("[#{}] {} ▶ ACK received in CLOSING state", self.id, key);
                    Some(Event::RecvAck)
                } else {
                    None
                }
            }
            State::TimeWait => {
                // In TIME_WAIT, we just wait for the 2MSL timeout
                // But we might get retransmitted FINs which we should ACK
                if fgs & flags::FIN != 0 {
                    println!("[#{}] {} ▶ Retransmitted FIN in TIME_WAIT", self.id, key);
                    // Don't change state, just acknowledge
                    None
                } else {
                    None
                }
            }
            State::LastAck => {
                if fgs & flags::ACK != 0 && ack == self.send_next {
                    println!("[#{}] {} ▶ Final ACK received in LAST_ACK", self.id, key);
                    Some(Event::RecvAck)
                } else {
                    None
                }
            }
            State::Closed => None,
        };

        if let Some(ev) = event {
            if let Some(next) = self.state.on_event(ev) {
                println!(
                    "[#{}] {} STATE: {} --[{}]--> {}",
                    self.id, key, self.state, ev, next
                );
                self.state = next;

                // Mark when connection becomes established
                if next == State::Established {
                    self.established_at = Some(self.clock.now());
                }
            }
        }

        // 2) Data reassembly only in Established
        if self.state == State::Established && !payload.is_empty() {
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

impl Connection {
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
                if segment.retransmit_count < tcp::MAX_RETRANSMISSIONS {
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
                        self.id,
                        tcp::MAX_RETRANSMISSIONS,
                        seq
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
            .retain(|_, segment| segment.retransmit_count < tcp::MAX_RETRANSMISSIONS);
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
            if segment::is_seq_lte(seq, ack_num) && segment::is_seq_lt(end_seq, ack_num) {
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

#[cfg(test)]
impl Connection {
    pub fn set_rto(&mut self, rto: Duration) {
        self.rto = rto;
    }
}

#[cfg(test)]
impl Key {
    // Test-specific constructor that doesn't require header slices
    pub fn new_for_test(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> Self {
        Key {
            src_ip: src_ip.parse().unwrap(),
            src_port,
            dst_ip: dst_ip.parse().unwrap(),
            dst_port,
        }
    }
}

/// Connection snapshot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub id: u64,
    pub state: State,
    pub send_next: u32,
    pub recv_next: u32,
    pub rto: Duration,
    pub retransmits: usize,
    pub queued_bytes: usize,
    pub bytes_received: usize,
    pub bytes_sent: usize,
}

impl Connection {
    pub fn peek(&self) -> Snapshot {
        Snapshot {
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
