// Typed messages inside streams. postcard here only, never on the header.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_MSG: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Msg {
    Text(String),
    Video { keyframe: bool, pts: u64, sha256: [u8; 32], bytes: Vec<u8> },
    FileMeta { sha256: [u8; 32], total: u64 },
    FileChunk { off: u64, bytes: Vec<u8> },
    FileEnd,
    ResolveReq { name: String },
    ResolveResp(Option<Vec<u8>>), // signed record bytes, naming.rs format
}

pub fn put(msg: &Msg) -> Vec<u8> {
    let body = postcard::to_allocvec(msg).expect("ser msg");
    assert!(body.len() <= MAX_MSG);
    let mut v = (body.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(&body);
    v
}

// Total, resync-on-error framing over stream bytes.
pub struct Reader {
    buf: Vec<u8>,
    pub bad: u64,
    pub broken: bool,
}

impl Default for Reader {
    fn default() -> Self {
        Reader { buf: Vec::new(), bad: 0, broken: false }
    }
}

impl Reader {
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Msg> {
        if self.broken {
            return vec![];
        }
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let n = u32::from_le_bytes(self.buf[..4].try_into().unwrap()) as usize;
            if n > MAX_MSG {
                self.broken = true;
                self.bad += 1;
                self.buf.clear();
                break;
            }
            if self.buf.len() < 4 + n {
                break;
            }
            let body = self.buf[4..4 + n].to_vec();
            self.buf.drain(..4 + n);
            match postcard::from_bytes(&body) {
                Ok(m) => out.push(m),
                Err(_) => {
                    self.bad += 1;
                    self.broken = true;
                    self.buf.clear();
                    break;
                }
            }
        }
        out
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// File helpers: chunk a blob for FileMeta/FileChunk/FileEnd.
pub fn file_chunks(blob: &[u8], chunk: usize) -> Vec<Msg> {
    let hash = sha256(blob);
    let mut out = vec![Msg::FileMeta { sha256: hash, total: blob.len() as u64 }];
    for (i, c) in blob.chunks(chunk).enumerate() {
        out.push(Msg::FileChunk { off: (i * chunk) as u64, bytes: c.to_vec() });
    }
    out.push(Msg::FileEnd);
    out
}

#[derive(Default)]
pub struct FileRx {
    pub sha256: [u8; 32],
    pub total: u64,
    pub got: Vec<u8>,
    pub done: Option<bool>,
}

impl FileRx {
    pub fn on(&mut self, m: &Msg) {
        match m {
            Msg::FileMeta { sha256, total } => {
                self.sha256 = *sha256;
                self.total = *total;
            }
            Msg::FileChunk { off, bytes } => {
                // Stream order is guaranteed; chunks arrive in sequence.
                let _ = off;
                self.got.extend_from_slice(bytes);
            }
            Msg::FileEnd => {
                self.got.truncate(self.total as usize);
                self.done = Some(self.got.len() == self.total as usize && sha256(&self.got) == self.sha256);
            }
            _ => {}
        }
    }
}
