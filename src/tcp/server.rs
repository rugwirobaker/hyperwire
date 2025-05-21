use crate::tcp::flags;
use crate::Clock;
use crate::{
    tcp::{Snapshot, Connection, Event, Key, State},
    Device,
};
use etherparse::{IpNumber, Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice};
use std::collections::HashMap;
use std::{sync::Arc, time::Duration};

pub struct Server {
    device: Box<dyn Device>,
    clock: Arc<dyn Clock>,
    connections: HashMap<Key, Connection>,
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

        let key = Key::new(&ip_hdr, &tcp_hdr);
        let rkey = key.reverse();

        let fgs = flags::tcp_header_to_flags(&tcp_hdr);

        // Debug: Show which client/connection we're dealing with
        println!("📡 Packet from {}:{} -> {}:{}, flags=0x{:02x} (SYN={}, ACK={}, FIN={}, RST={}, PSH={})",
                       key.src_ip, key.src_port, key.dst_ip, key.dst_port, fgs,
                       tcp_hdr.syn(), tcp_hdr.ack(), tcp_hdr.fin(), tcp_hdr.rst(), tcp_hdr.psh());

        // 1) New connection SYN
        if !self.connections.contains_key(&key) && fgs == flags::SYN {
            self.conn_counter += 1;
            let client_isn = tcp_hdr.sequence_number();
            let server_isn = rand::random();

            println!("\n🎯 New connection #{} from {}", self.conn_counter, key);
            println!("   Client ISN: {}, Server ISN: {}", client_isn, server_isn);

            let mut conn = Connection::listen(self.conn_counter, self.clock.clone());
            // trigger Listen->SynReceived
            if let Some(ns) = conn.state.on_event(Event::RecvSyn) {
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
                flags::SYN | flags::ACK, // SYN-ACK flags
                ackn,                    // acknowledgment number
                Vec::new(),              // empty data for SYN
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
                fgs,
                tcp_hdr.sequence_number(),
                tcp_hdr.acknowledgment_number(),
                payload,
            );

            if (fgs & flags::ACK) != 0 {
                conn.process_ack(tcp_hdr.acknowledgment_number());
            }

            // pure ACK for new data
            if conn.state == State::Established
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
            if conn.state == State::Established && conn.send_buffer.is_empty() {
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
            if conn.state == State::Established && !conn.send_buffer.is_empty() {
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
                    flags::PSH | flags::ACK, // PSH-ACK flags
                    conn.recv_next,          // acknowledgment number
                    chunk.clone(),           // clone the data for potential retransmission
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
            if conn.state == State::CloseWait && (fgs & flags::FIN) != 0 {
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
                    flags::ACK,     // ACK flag
                    conn.recv_next, // acknowledgment number
                    Vec::new(),     // empty data
                );
                println!("  ← Sent ACK for FIN (recv_next={})", conn.recv_next);
            }

            // 6) Send our FIN+ACK once echo is done
            if conn.state == State::CloseWait && conn.send_buffer.is_empty() {
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
                    flags::FIN | flags::ACK, // FIN-ACK flags
                    conn.recv_next,          // acknowledgment number
                    Vec::new(),              // empty data for FIN
                );
                conn.send_next = conn.send_next.wrapping_add(1);
                conn.state = State::LastAck;
            }

            // Close connection
            if conn.state == State::LastAck
                && (fgs & flags::ACK) != 0
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
        if fgs & flags::RST != 0 {
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
            builder = match segment.flags & flags::SYN != 0 {
                true => builder.syn(),
                false => builder,
            };

            builder = match segment.flags & flags::ACK != 0 {
                true => builder.ack(segment.ack),
                false => builder,
            };

            builder = match segment.flags & flags::FIN != 0 {
                true => builder.fin(),
                false => builder,
            };

            builder = match segment.flags & flags::PSH != 0 {
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

// #[cfg(test)]
impl Server {
    pub fn get_connections(&self) -> &HashMap<Key, Connection> {
        &self.connections
    }

    pub fn get_connections_mut(&mut self) -> &mut HashMap<Key, Connection> {
        &mut self.connections
    }

    pub fn force_rto_for(&mut self, key: &Key, rto: Duration) -> bool {
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
    pub fn peek_conn(&self, key: &Key) -> Option<Snapshot> {
        self.connections.get(key).map(|c| c.peek())
    }
}
