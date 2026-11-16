// Legacy adapters: converters at the edge, never on the hub. Cleartext
// legacy bytes exist only in the local app-to-adapter handoff.

use crate::datagrams;
use crate::node::{ConnectError, Node};

#[derive(Debug, PartialEq, Eq)]
pub enum FallbackError {
    RefusedNoIdentity,
}

// A connect that might fall back to a cleartext old protocol returns an
// error and sends nothing. No second stack, no downgrade path.
pub fn guarded_connect(node: &mut Node, name: &str) -> Result<(u64, Vec<u8>), FallbackError> {
    match node.connect(name, None) {
        Ok(v) => Ok(v),
        Err(ConnectError::NoRecord) => Err(FallbackError::RefusedNoIdentity),
        Err(_) => Err(FallbackError::RefusedNoIdentity),
    }
}

// TCP-shaped byte stream through one reliable stream. Payload is opaque.
pub struct ByteAdapter {
    pub conn: u64,
    pub stream: u32,
}

impl ByteAdapter {
    pub fn new(conn: u64, stream: u32) -> ByteAdapter {
        ByteAdapter { conn, stream }
    }
    pub fn write(&mut self, node: &mut Node, bytes: &[u8], tick: u64) -> Vec<Vec<u8>> {
        node.send_bytes(self.conn, self.stream, bytes, tick)
    }
    pub fn read(&mut self, node: &mut Node) -> Vec<u8> {
        node.take_stream_bytes(self.conn, self.stream)
    }
}

// UDP-shaped datagram: one frame per message, same crypto, no retransmit.
pub struct DatagramAdapter {
    pub conn: u64,
}

impl DatagramAdapter {
    pub fn new(conn: u64) -> DatagramAdapter {
        DatagramAdapter { conn }
    }
    pub fn send(&mut self, node: &mut Node, msg: &[u8]) -> Option<Vec<u8>> {
        node
            .sessions
            .get_mut(&self.conn)
            .and_then(|s| datagrams::send_datagram(s, msg))
    }
    pub fn recv(&mut self, node: &mut Node) -> Vec<Vec<u8>> {
        match node.sessions.get_mut(&self.conn) {
            Some(s) => datagrams::take_datagrams(s),
            None => vec![],
        }
    }
}

// Heuristic: would a legacy parser be tempted by these bytes?
pub fn looks_legacy(b: &[u8]) -> bool {
    if b.len() >= 4 && &b[..4] == b"NEW1" {
        return false;
    }
    const HTTP: [&[u8]; 6] = [b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI"];
    if b.len() >= 4 && HTTP.iter().any(|m| b.starts_with(m)) {
        return true;
    }
    // DNS-ish: 16-bit id, flags 0x0100 (query), qdcount 1.
    b.len() >= 6 && b[2] == 0x01 && b[3] == 0x00 && b[4] == 0x00 && b[5] == 0x01
}
