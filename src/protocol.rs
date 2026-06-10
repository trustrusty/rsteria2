//! Hysteria2 wire protocol: QUIC varints, TCP request/response framing, padding.
//! Mirrors the official Go implementation (core/internal/protocol).

use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;

/// TCPRequest frame type id.
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

// DoS guards, same limits as the Go reference.
pub const MAX_MESSAGE_LENGTH: u64 = 2048;
pub const MAX_PADDING_LENGTH: u64 = 4096;

/// Largest QUIC datagram frame Hysteria2 advertises (Go `MaxDatagramFrameSize`).
pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 1200;
/// Largest reassembled UDP payload buffer (Go `MaxUDPSize`).
pub const MAX_UDP_SIZE: usize = 4096;

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Random alphanumeric padding of length in `[min, max)` (matches Go `padding.String`).
fn random_padding(min: usize, max: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let n = min + rng.random_range(0..(max - min));
    (0..n)
        .map(|_| PADDING_CHARS[rng.random_range(0..PADDING_CHARS.len())])
        .collect()
}

/// Auth request padding, Go `authRequestPadding = {256, 2048}`.
pub fn auth_request_padding() -> String {
    String::from_utf8(random_padding(256, 2048)).expect("alphanumeric is valid utf8")
}

/// TCP request padding, Go `tcpRequestPadding = {64, 512}`.
fn tcp_request_padding() -> Vec<u8> {
    random_padding(64, 512)
}

/// Append a QUIC varint (RFC 9000 §16) to `buf`.
fn put_varint(buf: &mut BytesMut, v: u64) {
    if v <= 63 {
        buf.put_u8(v as u8);
    } else if v <= 16383 {
        buf.put_u8((v >> 8) as u8 | 0x40);
        buf.put_u8(v as u8);
    } else if v <= 1_073_741_823 {
        buf.put_u8((v >> 24) as u8 | 0x80);
        buf.put_u8((v >> 16) as u8);
        buf.put_u8((v >> 8) as u8);
        buf.put_u8(v as u8);
    } else {
        buf.put_u8((v >> 56) as u8 | 0xc0);
        buf.put_u8((v >> 48) as u8);
        buf.put_u8((v >> 40) as u8);
        buf.put_u8((v >> 32) as u8);
        buf.put_u8((v >> 24) as u8);
        buf.put_u8((v >> 16) as u8);
        buf.put_u8((v >> 8) as u8);
        buf.put_u8(v as u8);
    }
}

/// Decode a QUIC varint from the front of `buf`.
/// Returns `(value, bytes_consumed)`, or `None` if `buf` is too short.
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | b as u64;
    }
    Some((val, len))
}

/// Serialize a TCPRequest frame:
/// `varint(0x401) | varint(addr_len) | addr | varint(pad_len) | pad`.
/// Padding is generated internally (matches Go `WriteTCPRequest`).
pub fn encode_tcp_request(address: &str) -> Bytes {
    let pad = tcp_request_padding();
    let mut buf = BytesMut::with_capacity(16 + address.len() + pad.len());
    put_varint(&mut buf, FRAME_TYPE_TCP_REQUEST);
    put_varint(&mut buf, address.len() as u64);
    buf.put_slice(address.as_bytes());
    put_varint(&mut buf, pad.len() as u64);
    buf.put_slice(&pad);
    buf.freeze()
}

/// Result of parsing a TCPResponse header from a byte buffer.
pub enum TcpResponseParse {
    /// Need more bytes before the full response header is available.
    NeedMore,
    /// Fully parsed: `ok` = status byte == 0; `consumed` bytes belong to the header.
    Done { ok: bool, consumed: usize },
    /// A length field exceeded its DoS guard — the server is misbehaving.
    Invalid,
}

/// Try to parse a TCPResponse header from `buf`:
/// `status(1) | varint(msg_len) | msg | varint(pad_len) | pad`.
pub fn parse_tcp_response(buf: &[u8]) -> TcpResponseParse {
    let mut pos = 0usize;
    let status = match buf.get(pos) {
        Some(&b) => b,
        None => return TcpResponseParse::NeedMore,
    };
    pos += 1;

    let (msg_len, n) = match buf.get(pos..).and_then(get_varint) {
        Some(v) => v,
        None => return TcpResponseParse::NeedMore,
    };
    if msg_len > MAX_MESSAGE_LENGTH {
        return TcpResponseParse::Invalid;
    }
    pos += n + msg_len as usize;
    if buf.len() < pos {
        return TcpResponseParse::NeedMore;
    }

    let (pad_len, n) = match buf.get(pos..).and_then(get_varint) {
        Some(v) => v,
        None => return TcpResponseParse::NeedMore,
    };
    if pad_len > MAX_PADDING_LENGTH {
        return TcpResponseParse::Invalid;
    }
    pos += n + pad_len as usize;
    if buf.len() < pos {
        return TcpResponseParse::NeedMore;
    }

    TcpResponseParse::Done {
        ok: status == 0x00,
        consumed: pos,
    }
}

// ---------------------------------------------------------------------------
// UDP relay (Go: UDPMessage in proxy.go, frag.go)
// ---------------------------------------------------------------------------

/// A UDP datagram encapsulated for relay over QUIC's unreliable datagram channel.
///
/// Wire format (big-endian, Go `UDPMessage`):
/// `SessionID(u32) | PacketID(u16) | FragID(u8) | FragCount(u8) |
///  varint(addr_len) | addr | data`
#[derive(Clone, Debug)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    /// Size of everything before the payload.
    pub fn header_size(&self) -> usize {
        4 + 2 + 1 + 1 + varint_len(self.addr.len() as u64) + self.addr.len()
    }

    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    /// Serialize into `buf`, returning the number of bytes written, or `None`
    /// if `buf` is too small (Go returns -1).
    pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let total = self.size();
        if buf.len() < total {
            return None;
        }
        buf[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.packet_id.to_be_bytes());
        buf[6] = self.frag_id;
        buf[7] = self.frag_count;
        let mut i = 8;
        i += put_varint_slice(&mut buf[i..], self.addr.len() as u64);
        buf[i..i + self.addr.len()].copy_from_slice(self.addr.as_bytes());
        i += self.addr.len();
        buf[i..i + self.data.len()].copy_from_slice(&self.data);
        i += self.data.len();
        Some(i)
    }

    /// Parse a UDPMessage from a complete datagram (Go `ParseUDPMessage`).
    pub fn parse(msg: &[u8]) -> Option<UdpMessage> {
        if msg.len() < 8 {
            return None;
        }
        let session_id = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
        let packet_id = u16::from_be_bytes([msg[4], msg[5]]);
        let frag_id = msg[6];
        let frag_count = msg[7];
        let (addr_len, n) = get_varint(&msg[8..])?;
        // Go: `lAddr == 0 || lAddr > MaxMessageLength` is invalid.
        if addr_len == 0 || addr_len > MAX_MESSAGE_LENGTH {
            return None;
        }
        let addr_start = 8 + n;
        let addr_end = addr_start + addr_len as usize;
        // Go expects at least one byte of data after the address (uses `<=`).
        if msg.len() <= addr_end {
            return None;
        }
        let addr = String::from_utf8(msg[addr_start..addr_end].to_vec()).ok()?;
        let data = msg[addr_end..].to_vec();
        Some(UdpMessage {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            addr,
            data,
        })
    }
}

/// Byte length of a QUIC varint encoding `v`.
fn varint_len(v: u64) -> usize {
    if v <= 63 {
        1
    } else if v <= 16383 {
        2
    } else if v <= 1_073_741_823 {
        4
    } else {
        8
    }
}

/// Write a varint into the front of `buf`; returns bytes written.
fn put_varint_slice(buf: &mut [u8], v: u64) -> usize {
    if v <= 63 {
        buf[0] = v as u8;
        1
    } else if v <= 16383 {
        buf[0] = (v >> 8) as u8 | 0x40;
        buf[1] = v as u8;
        2
    } else if v <= 1_073_741_823 {
        buf[0] = (v >> 24) as u8 | 0x80;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = v as u8;
        4
    } else {
        buf[0] = (v >> 56) as u8 | 0xc0;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = v as u8;
        8
    }
}

/// Split a UDP message into fragments no larger than `max_size` bytes on the
/// wire (Go `FragUDPMessage`). Returns the fragments in order, or an empty
/// vec if even a single header doesn't fit.
pub fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> {
    if m.size() <= max_size {
        return vec![m.clone()];
    }
    let max_payload = max_size.saturating_sub(m.header_size());
    if max_payload == 0 {
        return Vec::new();
    }
    let frag_count = m.data.len().div_ceil(max_payload);
    let mut frags = Vec::with_capacity(frag_count);
    let mut off = 0;
    let mut frag_id = 0u8;
    while off < m.data.len() {
        let end = (off + max_payload).min(m.data.len());
        frags.push(UdpMessage {
            session_id: m.session_id,
            packet_id: m.packet_id,
            frag_id,
            frag_count: frag_count as u8,
            addr: m.addr.clone(),
            data: m.data[off..end].to_vec(),
        });
        off = end;
        frag_id += 1;
    }
    frags
}

/// Reassembles fragmented UDP messages. Like the Go `Defragger`, it only
/// tracks one packet ID at a time; a new packet ID discards prior state.
#[derive(Default)]
pub struct Defragger {
    pkt_id: u16,
    frags: Vec<Option<UdpMessage>>,
    count: u8,
    size: usize,
}

impl Defragger {
    /// Feed a (possibly fragmented) message. Returns the fully reassembled
    /// message once all fragments have arrived, otherwise `None`.
    pub fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        if m.frag_count <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_count {
            return None;
        }
        if m.packet_id != self.pkt_id || m.frag_count as usize != self.frags.len() {
            // New message — reset state.
            self.pkt_id = m.packet_id;
            self.frags = vec![None; m.frag_count as usize];
            self.size = m.data.len();
            self.count = 1;
            let frag_id = m.frag_id as usize;
            self.frags[frag_id] = Some(m);
            None
        } else if self.frags[m.frag_id as usize].is_none() {
            self.size += m.data.len();
            self.count += 1;
            let frag_id = m.frag_id as usize;
            self.frags[frag_id] = Some(m);
            if self.count as usize == self.frags.len() {
                // All fragments present — assemble in order.
                let mut data = Vec::with_capacity(self.size);
                let mut first: Option<UdpMessage> = None;
                for slot in self.frags.iter_mut() {
                    if let Some(frag) = slot.take() {
                        data.extend_from_slice(&frag.data);
                        if first.is_none() {
                            first = Some(frag);
                        }
                    }
                }
                let mut out = first?;
                out.data = data;
                out.frag_id = 0;
                out.frag_count = 1;
                Some(out)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(data: &[u8], frag_id: u8, frag_count: u8, packet_id: u16) -> UdpMessage {
        UdpMessage {
            session_id: 0xDEADBEEF,
            packet_id,
            frag_id,
            frag_count,
            addr: "example.com:53".into(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn udp_message_roundtrip() {
        let m = msg(b"hello world", 0, 1, 0);
        let mut buf = vec![0u8; m.size()];
        let n = m.serialize(&mut buf).unwrap();
        assert_eq!(n, m.size());
        let parsed = UdpMessage::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.session_id, m.session_id);
        assert_eq!(parsed.addr, m.addr);
        assert_eq!(parsed.data, m.data);
    }

    #[test]
    fn udp_message_rejects_truncated_and_empty_data() {
        // No payload after the address is invalid (Go uses `<=`).
        let m = msg(b"", 0, 1, 0);
        let mut buf = vec![0u8; m.size() + 1];
        let n = m.serialize(&mut buf).unwrap();
        assert!(UdpMessage::parse(&buf[..n]).is_none());
        // Truncated header.
        assert!(UdpMessage::parse(&[0u8; 4]).is_none());
    }

    #[test]
    fn frag_then_defrag_reassembles() {
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let m = msg(&payload, 0, 1, 7);
        // Force fragmentation with a small max size.
        let frags = frag_udp_message(&m, m.header_size() + 100);
        assert!(frags.len() > 1);
        assert!(frags.iter().all(|f| f.frag_count as usize == frags.len()));

        let mut d = Defragger::default();
        let mut out = None;
        for f in frags {
            if let Some(full) = d.feed(f) {
                out = Some(full);
            }
        }
        let full = out.expect("reassembled");
        assert_eq!(full.data, payload);
        assert_eq!(full.frag_count, 1);
    }

    #[test]
    fn defrag_passes_through_unfragmented() {
        let m = msg(b"single", 0, 1, 0);
        let mut d = Defragger::default();
        let out = d.feed(m).unwrap();
        assert_eq!(out.data, b"single");
    }

    #[test]
    fn defrag_new_packet_id_resets_state() {
        let p1: Vec<u8> = vec![1; 300];
        let m1 = msg(&p1, 0, 2, 1); // only first frag of packet 1
        let p2: Vec<u8> = vec![2; 200];
        let f2 = frag_udp_message(&msg(&p2, 0, 1, 2), msg(&p2, 0, 1, 2).header_size() + 50);

        let mut d = Defragger::default();
        assert!(d.feed(m1).is_none());
        // A different packet arrives; previous partial state is dropped.
        let mut out = None;
        for f in f2 {
            if let Some(full) = d.feed(f) {
                out = Some(full);
            }
        }
        assert_eq!(out.unwrap().data, p2);
    }
}
