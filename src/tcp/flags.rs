use etherparse::TcpHeaderSlice;

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
