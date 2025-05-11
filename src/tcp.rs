use etherparse::{IpNumber, Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::Device;

const SYN: u8 = 1 << 1;
const ACK: u8 = 1 << 4;
const FIN: u8 = 1 << 0;
const RST: u8 = 1 << 2;
const PSH: u8 = 1 << 3;

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
    // FinWait1,
    // FinWait2,
    CloseWait,
    LastAck,
    // TimeWait,
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

#[derive(Debug)]
pub struct TcpConnection {
    id: u64,
    state: TcpState,
    pub server_isn: u32,
    recv_next: u32,
    send_next: u32,
    recv_buffer: Vec<u8>,     // data we’ve received
    pub send_buffer: Vec<u8>, // data waiting to be sent
    reasm_buf: BTreeMap<u32, Vec<u8>>,
    // debugging
    pub created_at: Instant,
    established_at: Option<Instant>,
    bytes_received: usize,
    pub bytes_sent: usize,
}

impl TcpConnection {
    /// Create an initial listener-state connection
    pub fn new_listen(id: u64) -> Self {
        TcpConnection {
            id,
            state: TcpState::Listen,
            server_isn: 0,
            recv_next: 0,
            send_next: 0,
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
            reasm_buf: BTreeMap::new(),
            created_at: Instant::now(),
            established_at: None,
            bytes_received: 0,
            bytes_sent: 0,
        }
    }

    // on_segment is called whenever we receive a new segment
    pub fn on_segment(&mut self, key: &TcpKey, flags: u8, seq: u32, ack: u32, payload: &[u8]) {
        // Log incoming packet details
        let flags_str = format!(
            "{}{}{}{}{}",
            if flags & SYN != 0 { "S" } else { "-" },
            if flags & ACK != 0 { "A" } else { "-" },
            if flags & FIN != 0 { "F" } else { "-" },
            if flags & RST != 0 { "R" } else { "-" },
            if flags & PSH != 0 { "P" } else { "-" },
        );

        println!(
            "[#{}] {} RX: flags={} seq={} ack={} len={}",
            self.id,
            key,
            flags_str,
            seq,
            ack,
            payload.len()
        );
        // 1) FSM-driven state transition
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
                    self.established_at = Some(Instant::now());
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

    /// For our SYN-ACK, we’ll just advertise a constant window for now.
    pub fn advertised_window(&self) -> u16 {
        65_535 // max unscaled window
    }

    /// Only moves payload into recv_buffer & updates recv_next.
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

pub struct Server {
    device: Box<dyn Device>,
    connections: HashMap<TcpKey, TcpConnection>,
    conn_counter: u64,
}

impl Server {
    pub fn new(device: Box<dyn Device>) -> Self {
        Self {
            device,
            connections: HashMap::new(),
            conn_counter: 0,
        }
    }

    pub fn run(&mut self) {
        let mut buf = [0u8; 1504];
        loop {
            let n = match self.device.recv(&mut buf) {
                Ok(n) => n,
                Err(_) => continue,
            };
            self.handle_packet(&buf[..n]);
        }
    }

    pub fn handle_packet(&mut self, packet: &[u8]) {
        let ip = match Ipv4HeaderSlice::from_slice(&packet) {
            Ok(h) if h.protocol() == IpNumber::from(6) => h,
            _ => return,
        };
        let tcp = match TcpHeaderSlice::from_slice(&packet[ip.slice().len()..]) {
            Ok(h) => h,
            _ => return,
        };

        let key = TcpKey::new(&ip, &tcp);
        let rkey = key.reverse();

        let flags: u8 = (tcp.fin() as u8) << 0
            | (tcp.syn() as u8) << 1
            | (tcp.rst() as u8) << 2
            | (tcp.psh() as u8) << 3
            | (tcp.ack() as u8) << 4
            | (tcp.urg() as u8) << 5;

        // Debug: Show which client/connection we're dealing with
        println!("📡 Packet from {}:{} -> {}:{}, flags=0x{:02x} (SYN={}, ACK={}, FIN={}, RST={}, PSH={})",
                       key.src_ip, key.src_port, key.dst_ip, key.dst_port, flags,
                       tcp.syn(), tcp.ack(), tcp.fin(), tcp.rst(), tcp.psh());

        // 1) New connection SYN (FSM-driven)
        if !self.connections.contains_key(&key) && flags == SYN {
            self.conn_counter += 1;
            let client_isn = tcp.sequence_number();
            let server_isn = rand::random();

            println!("\n🎯 New connection #{} from {}", self.conn_counter, key);
            println!("   Client ISN: {}, Server ISN: {}", client_isn, server_isn);

            let mut conn = TcpConnection::new_listen(self.conn_counter);
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
            self.connections.insert(key, conn);
            return;
        }

        // 2) Existing connection
        if let Some(conn) = self.connections.get_mut(&key) {
            let off = ip.slice().len() + tcp.slice().len();
            let payload = &packet[off..];

            conn.on_segment(
                &key,
                flags,
                tcp.sequence_number(),
                tcp.acknowledgment_number(),
                payload,
            );

            // pure ACK for new data
            if conn.state == TcpState::Established
                && conn.recv_next != tcp.sequence_number().wrapping_add(payload.len() as u32)
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

            // echo data
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
                    .ack(conn.send_next);
                let mut pkt = Vec::with_capacity(builder.size(chunk.len()));
                builder.write(&mut pkt, &chunk).unwrap();
                self.device.send(&pkt).unwrap();

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
                conn.send_next = conn.send_next.wrapping_add(1);
                conn.state = TcpState::LastAck;
            }

            // Close connection
            if conn.state == TcpState::LastAck
                && (flags & ACK) != 0
                && tcp.acknowledgment_number() == conn.send_next
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
        // Handle RST flag
        if flags & RST != 0 {
            if let Some(conn) = self.connections.get(&key) {
                println!("\n⚠️  RST received for connection #{}", conn.id);
            }
            self.connections.remove(&key);
        }
    }
}
