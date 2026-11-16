// Attack generators: spoof, replay, tamper, flood, legacy-on-hub.

use crate::crypto;
use crate::wire;

pub struct Rng {
    pub state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng { state: if seed == 0 { 0x2545F4914F6CDD1D } else { seed } }
    }
    pub fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let w = self.next().to_le_bytes();
            v.extend_from_slice(&w);
        }
        v.truncate(n);
        v
    }
}

// Data packet on someone else's conn_id, sealed under the wrong key.
pub fn spoof_data(conn: u64, seq: u64, wrong_key: &[u8; 32], frame: &[u8]) -> Vec<u8> {
    let hdr = wire::Header {
        version: wire::VERSION,
        ptype: wire::TYPE_DATA,
        conn_id: conn,
        seq,
        len: (frame.len() + crypto::TAG_LEN) as u16,
    };
    let hbytes = wire::encode(&hdr, &[]);
    let ct = crypto::seal(wrong_key, seq, &hbytes, frame).unwrap();
    wire::encode(&hdr, &ct)
}

pub fn flip_bit(bytes: &mut [u8], byte_idx: usize, bit: u8) {
    bytes[byte_idx] ^= 1 << (bit % 8);
}

pub fn random_packet(rng: &mut Rng, max_len: usize) -> Vec<u8> {
    let n = (rng.next() % max_len as u64) as usize;
    rng.bytes(n)
}

// Well-formed NEW1 handshake1-shaped packet with random body: full header
// parse, garbage payload.
pub fn garbage_handshake(rng: &mut Rng, conn: u64) -> Vec<u8> {
    let n = 64 + (rng.next() % 200) as usize;
    let body = rng.bytes(n);
    wire::encode(
        &wire::Header {
            version: wire::VERSION,
            ptype: wire::TYPE_HANDSHAKE1,
            conn_id: conn,
            seq: 0,
            len: body.len() as u16,
        },
        &body,
    )
}

// DNS query-shaped blob and an HTTP request-shaped blob.
pub fn dns_blob() -> Vec<u8> {
    let mut b = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    b.extend_from_slice(b"\x03com\x00\x00\x01\x00\x01");
    b.extend_from_slice(&[0u8; 8]); // pad past the fixed NEW1 header size
    b
}

pub fn http_blob() -> Vec<u8> {
    b"GET /index.html HTTP/1.1\r\nHost: tv.local\r\n\r\n".to_vec()
}
