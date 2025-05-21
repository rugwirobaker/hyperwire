//! TCP sequence number handling and segment definitions
use std::time::Instant;

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
/// ```
/// use hyperwire::tcp::is_seq_lt;
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
pub fn is_seq_lt(a: u32, b: u32) -> bool {
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
/// ```
/// use hyperwire::tcp::is_seq_lte;
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
pub fn is_seq_lte(a: u32, b: u32) -> bool {
    a == b || is_seq_lt(a, b)
}

/// A segment in the retransmission queue
#[derive(Debug, Clone)]
pub struct RetransmitSegment {
    /// Payload data
    pub data: Vec<u8>,
    /// Starting sequence number
    pub seq: u32,
    /// When this segment was last sent
    pub sent_at: Instant,
    /// Number of times this segment has been retransmitted
    pub retransmit_count: u8,
    /// TCP flags (SYN, ACK, FIN, etc.)
    pub flags: u8,
    /// ACK number (if ACK flag is set)
    pub ack: u32,
}

impl RetransmitSegment {
    /// Create a new segment for the retransmission queue
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
