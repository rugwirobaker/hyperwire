use etherparse::{Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice};
use std::net::Ipv4Addr;

pub struct PacketFactory;

impl PacketFactory {
    pub fn syn(src: &str, dst: &str, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();

        let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64)
            .tcp(src_port, dst_port, seq, 65535)
            .syn();

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).unwrap();
        packet
    }

    pub fn ack(src: &str, dst: &str, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Vec<u8> {
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();

        let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64)
            .tcp(src_port, dst_port, seq, 65535)
            .ack(ack);

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).unwrap();
        packet
    }

    pub fn data(
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

    pub fn fin(src: &str, dst: &str, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Vec<u8> {
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
pub fn parse_tcp_packet(packet: &[u8]) -> (Ipv4HeaderSlice, TcpHeaderSlice) {
    let ip = Ipv4HeaderSlice::from_slice(packet).unwrap();
    let tcp = TcpHeaderSlice::from_slice(&packet[ip.slice().len()..]).unwrap();
    (ip, tcp)
}
