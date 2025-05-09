use etherparse::{IpNumber, Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice};
use std::collections::HashMap;
use tun_tap::{self, Iface, Mode};

use std::net::Ipv4Addr;

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
    // Listen,
    SynReceived,
    Established,
    // FinWait1,
    // FinWait2,
    // CloseWait,
    // LastAck,
    // TimeWait,
}

#[derive(Debug)]
struct TcpConnection {
    state: TcpState,
    send_isn: u32,
    recv_next: u32,
    send_next: u32,
    recv_buffer: Vec<u8>, // data we’ve received
    send_buffer: Vec<u8>, // data waiting to be sent
}

impl TcpConnection {
    fn new_syn_received(isn: u32, client_isn: u32) -> Self {
        TcpConnection {
            state: TcpState::SynReceived,
            send_isn: isn,
            send_next: isn.wrapping_add(1), // we consumed one for SYN
            recv_next: client_isn.wrapping_add(1),
            recv_buffer: Vec::new(),
            send_buffer: Vec::new(),
        }
    }
    // Transition helper stub:
    fn on_segment(&mut self, flags: u8, seq: u32, ack: u32, payload: &[u8]) {
        match self.state {
            TcpState::SynReceived => {
                if flags & 0x10 != 0 && ack == self.send_next {
                    // got final ACK
                    self.state = TcpState::Established;
                    println!("✅Connection established!");
                }
            }
            TcpState::Established => {
                if payload.len() > 0 && seq == self.recv_next {
                    // in-order data
                    self.recv_buffer.extend_from_slice(payload);
                    self.recv_next = seq.wrapping_add(payload.len() as u32);
                }
                // handle FIN, RST, etc.
            }
            _ => { /* handle other states later */ }
        }
    }

    /// For our SYN-ACK, we’ll just advertise a constant window for now.
    fn advertised_window(&self) -> u16 {
        65_535 // max unscaled window
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
        let n = dev.recv(&mut buf).expect("failed to read packet");

        let ip = match Ipv4HeaderSlice::from_slice(&buf[..n]) {
            Ok(h) => h,
            Err(_) => continue,
        };

        if ip.protocol() != IpNumber::from(6) {
            continue;
        }

        // Parse TCP header
        let tcp = match TcpHeaderSlice::from_slice(&buf[ip.slice().len()..n]) {
            Ok(h) => h,
            Err(_) => continue,
        };

        let key = TcpKey::new(&ip, &tcp);
        let rkey = key.reverse();

        let flags: u8 = (tcp.fin() as u8) << 0
            | (tcp.syn() as u8) << 1
            | (tcp.rst() as u8) << 2
            | (tcp.psh() as u8) << 3
            | (tcp.ack() as u8) << 4
            | (tcp.urg() as u8) << 5;

        if (flags & SYN) != 0 && (flags & ACK) == 0 {
            // SYN without ACK → new connection request
            println!("found a new connection");
            let server_isn: u32 = rand::random();
            // Build our new connection under the *forward* key, so lookups hit it later:
            let conn = TcpConnection::new_syn_received(server_isn, tcp.sequence_number());
            let win = conn.advertised_window();
            table.insert(key, conn);

            // Send our SYN-ACK
            println!("sending a SYN-ACK");
            let client_seq = tcp.sequence_number();
            let ack_num = client_seq.wrapping_add(1);
            let builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                .tcp(rkey.src_port, rkey.dst_port, server_isn, win)
                .syn()
                .ack(ack_num);
            let mut syn_ack_pkt = Vec::with_capacity(builder.size(0));
            builder.write(&mut syn_ack_pkt, &[]).unwrap();
            dev.send(&syn_ack_pkt).unwrap();
            continue;
        }
        // ——— Existing connection → advance its state —————————
        if let Some(conn) = table.get_mut(&key) {
            let payload_offset = ip.slice().len() + tcp.slice().len();
            let payload = &buf[payload_offset..n];
            let prev_recv = conn.recv_next;
            conn.on_segment(
                flags,
                tcp.sequence_number(),
                tcp.acknowledgment_number(),
                payload,
            );

            // If we've moved recv_next, send an ACK
            if conn.state == TcpState::Established && conn.recv_next != prev_recv {
                let ack_num = conn.recv_next;
                let win = conn.advertised_window();
                let builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next, // our next seq (still ISN+1 if no data yet)
                        win,
                    )
                    .ack(ack_num);

                let mut ack_pkt = Vec::with_capacity(builder.size(0));
                builder.write(&mut ack_pkt, &[]).unwrap();
                dev.send(&ack_pkt).unwrap();
                println!("  ← Sent ACK for recv_next={}", ack_num);
            }

            if conn.state == TcpState::Established && !conn.send_buffer.is_empty() {
                // send up to MSS worth of data
                let mss = 1460;
                let to_send = conn
                    .send_buffer
                    .drain(..mss.min(conn.send_buffer.len()))
                    .collect::<Vec<_>>();
                let builder = PacketBuilder::ipv4(rkey.src_ip.octets(), rkey.dst_ip.octets(), 64)
                    .tcp(
                        rkey.src_port,
                        rkey.dst_port,
                        conn.send_next,
                        conn.advertised_window(),
                    )
                    .psh()
                    .ack(conn.recv_next);

                let mut data_pkt = Vec::with_capacity(builder.size(to_send.len()));
                builder.write(&mut data_pkt, &to_send).unwrap();
                dev.send(&data_pkt).unwrap();
                conn.send_next = conn.send_next.wrapping_add(to_send.len() as u32);
                println!("  → Sent {} bytes of response", to_send.len());
            }
        }
    }
}
