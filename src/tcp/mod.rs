mod connection;
mod flags;
mod segment;
mod server;

pub use self::connection::{Connection, Event, Key, Snapshot, State};
pub use self::segment::{is_seq_lt, is_seq_lte, RetransmitSegment};
pub use self::server::Server;

pub use self::flags::{flags_to_string, tcp_header_to_flags};
pub use self::flags::{ACK, FIN, PSH, RST, SYN, URG};

// Maximum retransmission attempts
pub const MAX_RETRANSMISSIONS: u8 = 5;
