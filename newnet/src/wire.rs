// Fixed-shape packet header, hand-encoded. Header is cleartext and is
// covered as AEAD associated data. Decode is total: no panics, Ok or Err.

pub const MAGIC: [u8; 4] = *b"NEW1";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 24;
pub const MAX_DATAGRAM: usize = 1200;

pub const TYPE_HANDSHAKE1: u8 = 0;
pub const TYPE_HANDSHAKE2: u8 = 1;
pub const TYPE_DATA: u8 = 2;
pub const TYPE_CLOSE: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub ptype: u8,
    pub conn_id: u64,
    pub seq: u64,
    pub len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub body: Vec<u8>, // ciphertext + 16-byte tag
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    TooShort,
    BadMagic,
    BadVersion,
    BadType,
    LenMismatch,
    BodyEmpty,
}

pub fn encode(header: &Header, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(header.version);
    out.push(header.ptype);
    out.extend_from_slice(&header.conn_id.to_le_bytes());
    out.extend_from_slice(&header.seq.to_le_bytes());
    out.extend_from_slice(&header.len.to_le_bytes());
    out.extend_from_slice(body);
    out
}

// Returns Ok(header, body) or Err. Never panics on any input.
pub fn decode(buf: &[u8]) -> Result<Packet, WireError> {
    if buf.len() < HEADER_LEN {
        return Err(WireError::TooShort);
    }
    if buf[0..4] != MAGIC {
        return Err(WireError::BadMagic);
    }
    if buf[4] != VERSION {
        return Err(WireError::BadVersion);
    }
    if !matches!(buf[5], TYPE_HANDSHAKE1 | TYPE_HANDSHAKE2 | TYPE_DATA | TYPE_CLOSE) {
        return Err(WireError::BadType);
    }
    let conn_id = u64::from_le_bytes(buf[6..14].try_into().unwrap());
    let seq = u64::from_le_bytes(buf[14..22].try_into().unwrap());
    let len = u16::from_le_bytes(buf[22..24].try_into().unwrap());
    let body = &buf[HEADER_LEN..];
    if body.is_empty() {
        return Err(WireError::BodyEmpty);
    }
    if len as usize != body.len() {
        return Err(WireError::LenMismatch);
    }
    Ok(Packet {
        header: Header { version: VERSION, ptype: buf[5], conn_id, seq, len },
        body: body.to_vec(),
    })
}

impl Packet {
    pub fn header_bytes(&self) -> Vec<u8> {
        encode(&self.header, &[])[..HEADER_LEN].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(ptype: u8, conn: u64, seq: u64, body_len: usize) -> Header {
        Header { version: VERSION, ptype, conn_id: conn, seq, len: body_len as u16 }
    }

    #[test]
    fn round_trip() {
        let body = vec![9u8; 40];
        let p = encode(&hdr(TYPE_DATA, 7, 3, body.len()), &body);
        let d = decode(&p).unwrap();
        assert_eq!(d.header.conn_id, 7);
        assert_eq!(d.body, body);
    }

    #[test]
    fn header_bit_flip_changes_decode() {
        let body = vec![9u8; 40];
        let mut p = encode(&hdr(TYPE_DATA, 7, 3, body.len()), &body);
        p[13] ^= 1; // conn_id bit
        let d = decode(&p).unwrap();
        assert_ne!(d.header.conn_id, 7);
    }

    #[test]
    fn rejects_bad_magic_version_type_len_short() {
        let body = vec![9u8; 40];
        let mut p = encode(&hdr(TYPE_DATA, 1, 1, body.len()), &body);
        p[0] = b'X';
        assert_eq!(decode(&p), Err(WireError::BadMagic));
        p = encode(&hdr(TYPE_DATA, 1, 1, body.len()), &body);
        p[4] = 2;
        assert_eq!(decode(&p), Err(WireError::BadVersion));
        p = encode(&hdr(TYPE_DATA, 1, 1, body.len()), &body);
        p[5] = 9;
        assert_eq!(decode(&p), Err(WireError::BadType));
        p = encode(&hdr(TYPE_DATA, 1, 1, body.len()), &body);
        p.truncate(p.len() - 1); // header len no longer equals body
        assert_eq!(decode(&p), Err(WireError::LenMismatch));
        assert_eq!(decode(&[1, 2, 3]), Err(WireError::TooShort));
    }

    #[test]
    fn fuzz_decode_never_panics() {
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut ok = 0usize;
        let mut err = 0usize;
        for _ in 0..10_000 {
            let n = (next() % 1300) as usize;
            let mut buf = vec![0u8; n];
            for b in buf.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            if n > 4 {
                buf[0..4].copy_from_slice(&MAGIC);
            }
            match decode(&buf) {
                Ok(_) => ok += 1,
                Err(_) => err += 1,
            }
        }
        assert_eq!(ok + err, 10_000);
    }
}
