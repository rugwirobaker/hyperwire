use etherparse::{IpNumber, Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use tun_tap::{self, Iface, Mode};

const SYN: u8 = 1 << 1;
const ACK: u8 = 1 << 4;
const FIN: u8 = 1 << 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

impl TcpKey {
    fn new(ip: &Ipv4HeaderSlice, tcp: &TcpHeaderSlice) -> Self {
        TcpKey {
            src_ip: ip.source_addr(),
            src_port: tcp.source_port(),
            dst_ip: ip.destination_addr(),
            dst_port: tcp.destination_port(),
        }
    }

    fn reverse(&self) -> Self {
        TcpKey {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
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

impl TcpState {
    fn on_event(self, ev: TcpEvent) -> Option<TcpState> {
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
enum TcpEvent {
    RecvSyn, // incoming SYN without ACK
    RecvAck, // pure ACK
    RecvFin, // incoming FIN
}

#[derive(Debug)]
struct TcpConnection {
    state: TcpState,
    server_isn: u32,
    recv_next: u32,
    send_next: u32,
    recv_buffer: Vec<u8>, // data we’ve received
    send_buffer: Vec<u8>, // data waiting to be sent
    reasm_buf: BTreeMap<u32, Vec<u8>>,
}

impl TcpConnection {
    /// Create an initial listener-state connection
    fn new_listen() -> Self {
        TcpConnection {
            state: TcpState::Listen,
            server_isn: 0,
            recv_next: 0,
            send_next: 0,
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
            reasm_buf: BTreeMap::new(),
        }
    }
    // fn new_syn_received(server_isn: u32, client_isn: u32) -> Self {
    //     TcpConnection {
    //         state: TcpState::SynReceived;,
    //         server_isn,
    //         send_next: server_isn.wrapping_add(1);, // we consumed one for SYN
    //         recv_next: client_isn.wrapping_add(1);,
    //         recv_buffer: Vec::new();,
    //         send_buffer: Vec::new();,
    //         reasm_buf: BTreeMap::new();,
    //     }
    // }
    // Transition helper stub:
    fn on_segment(&mut self, flags: u8, seq: u32, ack: u32, payload: &[u8]) {
        // 1) FSM-driven state transition
        let event = if flags & SYN != 0 && flags & ACK == 0 {
            println!("🔄 received new SYN");
            Some(TcpEvent::RecvSyn)
        } else if flags & FIN != 0 {
            println!("⚓ recieved FIN");
            Some(TcpEvent::RecvFin)
        } else if flags & ACK != 0 {
            match self.state {
                TcpState::SynReceived if ack == self.send_next => {
                    println!("✅ handshake-complete");
                    Some(TcpEvent::RecvAck)
                }
                TcpState::Established => {
                    println!("🔁 data-ACK");
                    Some(TcpEvent::RecvAck)
                }
                TcpState::CloseWait if ack == self.send_next => {
                    println!("🗑️ connection closed");
                    Some(TcpEvent::RecvAck) // final ACK of our FIN
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some(ev) = event {
            if let Some(next) = self.state.on_event(ev) {
                println!("State {:?} --{:?}--> {:?}", self.state, ev, next);
                self.state = next;
            }
        }

        // 2) Data reassembly only in Established
        if self.state == TcpState::Established && !payload.is_empty() {
            match seq.cmp(&self.recv_next) {
                Ordering::Equal => {
                    self.accept_payload(payload);
                    while let Some((&nseq, _)) = self.reasm_buf.iter().next() {
                        if nseq != self.recv_next {
                            break;
                        }
                        let buf = self.reasm_buf.remove(&nseq).unwrap();
                        self.accept_payload(&buf);
                    }
                }
                Ordering::Greater => {
                    self.reasm_buf.insert(seq, payload.to_vec());
                }
                Ordering::Less => {
                    let overlap = (self.recv_next - seq) as usize;
                    if overlap < payload.len() {
                        self.accept_payload(&payload[overlap..]);
                    }
                }
            }
        }
    }

    /// For our SYN-ACK, we’ll just advertise a constant window for now.
    fn advertised_window(&self) -> u16 {
        65_535 // max unscaled window
    }

    /// Only moves payload into recv_buffer & updates recv_next.
    fn accept_payload(&mut self, data: &[u8]) {
        self.recv_buffer.extend_from_slice(data);
        self.recv_next = self.recv_next.wrapping_add(data.len() as u32);
    }
}

fn main() {
    // Open the existing tun0 we created by hand
    let dev = Iface::without_packet_info("tun0", Mode::Tun).expect("failed to open tun0");
    // creates /dev/net/tun, name "tun0" :contentReference[oaicite:0]{index=0}

    println!("Listening on tun0 …");

    let mut table: HashMap<TcpKey, TcpConnection> = HashMap::new();

    let mut buf = [0u8; 1504]; // MTU + 4 bytes for headroom

    loop {
        let n = dev.recv(&mut buf).unwrap();
        let ip = match Ipv4HeaderSlice::from_slice(&buf[..n]) {
            Ok(h) if h.protocol() == IpNumber::from(6) => h,
            _ => continue,
        };
        let tcp = match TcpHeaderSlice::from_slice(&buf[ip.slice().len()..n]) {
            Ok(h) => h,
            _ => continue,
        };

        let key = TcpKey::new(&ip, &tcp);
        let rkey = key.reverse();

        let flags: u8 = (tcp.fin() as u8) << 0
            | (tcp.syn() as u8) << 1
            | (tcp.rst() as u8) << 2
            | (tcp.psh() as u8) << 3
            | (tcp.ack() as u8) << 4
            | (tcp.urg() as u8) << 5;

        // 1) New connection SYN (FSM-driven)
        if !table.contains_key(&key) && flags == SYN {
            let client_isn = tcp.sequence_number();
            let server_isn = rand::random();
            let mut conn = TcpConnection::new_listen();
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
            let mut pkt = Vec::with_capacity(
                PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(rkey.src_port, rkey.dst_port, server_isn, win)
                    .syn()
                    .ack(ackn)
                    .size(0),
            );
            PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                .tcp(rkey.src_port, rkey.dst_port, server_isn, win)
                .syn()
                .ack(ackn)
                .write(&mut pkt, &[])
                .unwrap();
            dev.send(&pkt).unwrap();
            table.insert(key, conn);
            continue;
        }

        // 2) Existing connection
        if let Some(conn) = table.get_mut(&key) {
            let off = ip.slice().len() + tcp.slice().len();
            let payload = &buf[off..n];

            conn.on_segment(
                flags,
                tcp.sequence_number(),
                tcp.acknowledgment_number(),
                payload,
            );

            // pure ACK for new data
            if conn.state == TcpState::Established
                && conn.recv_next != tcp.sequence_number().wrapping_add(payload.len() as u32)
            {
                let mut pkt = Vec::with_capacity(
                    PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                        .tcp(
                            rkey.src_port,
                            rkey.dst_port,
                            conn.send_next,
                            conn.advertised_window(),
                        )
                        .ack(conn.recv_next)
                        .size(0),
                );
                PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .ack(conn.recv_next)
                    .write(&mut pkt, &[])
                    .unwrap();
                dev.send(&pkt).unwrap();
            }

            // start echo on newline
            if conn.state == TcpState::Established && conn.send_buffer.is_empty() {
                if let Some(pos) = conn.recv_buffer.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = conn.recv_buffer.drain(..=pos).collect();
                    conn.send_buffer.extend_from_slice(&line);
                }
            }

            // echo data
            if conn.state == TcpState::Established && !conn.send_buffer.is_empty() {
                let chunk = conn.send_buffer.drain(..).collect::<Vec<_>>();
                let mut pkt = Vec::with_capacity(
                    PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                        .tcp(
                            rkey.src_port,
                            rkey.dst_port,
                            conn.send_next,
                            conn.advertised_window(),
                        )
                        .psh()
                        .ack(conn.recv_next)
                        .size(chunk.len()),
                );
                PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .psh()
                    .ack(conn.recv_next)
                    .write(&mut pkt, &chunk)
                    .unwrap();
                dev.send(&pkt).unwrap();
                conn.send_next = conn.send_next.wrapping_add(chunk.len() as u32);
            }

            // 5) ACK the peer's FIN so it stops retransmitting
            if conn.state == TcpState::CloseWait && (flags & FIN) != 0 {
                conn.recv_next = conn.recv_next.wrapping_add(1);
                let mut fin_ack = Vec::with_capacity(
                    PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                        .tcp(
                            rkey.src_port,
                            rkey.dst_port,
                            conn.send_next,
                            conn.advertised_window(),
                        )
                        .ack(conn.recv_next)
                        .size(0),
                );
                PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .ack(conn.recv_next)
                    .write(&mut fin_ack, &[])
                    .unwrap();
                dev.send(&fin_ack).unwrap();
                println!("  ← Sent ACK for FIN (recv_next={})", conn.recv_next);
            }

            // 6) Send our FIN+ACK once echo is done
            if conn.state == TcpState::CloseWait && conn.send_buffer.is_empty() {
                let mut fin_pkt = Vec::with_capacity(
                    PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                        .tcp(
                            rkey.src_port,
                            rkey.dst_port,
                            conn.send_next,
                            conn.advertised_window(),
                        )
                        .fin()
                        .ack(conn.recv_next)
                        .size(0),
                );
                PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .fin()
                    .ack(conn.recv_next)
                    .write(&mut fin_pkt, &[])
                    .unwrap();
                dev.send(&fin_pkt).unwrap();
                conn.send_next = conn.send_next.wrapping_add(1);
                conn.state = TcpState::LastAck;
                println!("⚓ Sent FIN+ACK, entering LastAck");
            }

            // 7) Teardown on final ACK
            if conn.state == TcpState::LastAck
                && (flags & ACK) != 0
                && tcp.acknowledgment_number() == conn.send_next
            {
                table.remove(&key);
                println!("🗑️ Connection torn down");
            }
        }
    }
}
