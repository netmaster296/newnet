// One encrypted session: replay window, key generations, state machine.
// Handshake state accepts no application frames.

use crate::crypto::{self, KeyChain};
use crate::streams::{self, Frame, StreamRx, StreamTx};
use crate::wire;

pub const REPLAY_WINDOW: usize = 2048;

#[derive(Debug, PartialEq, Eq)]
pub enum WindowOutcome {
    Fresh,
    Seen,
    TooOld,
    TooFar,
}

#[derive(Clone)]
pub struct ReplayWindow {
    started: bool,
    highest: u64,
    bits: [u64; REPLAY_WINDOW / 64],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow { started: false, highest: 0, bits: [0; REPLAY_WINDOW / 64] }
    }
}

impl ReplayWindow {
    pub fn check(&mut self, seq: u64) -> WindowOutcome {
        if !self.started {
            self.started = true;
            self.highest = seq;
            self.set_bit(0);
            return WindowOutcome::Fresh;
        }
        if seq > self.highest {
            let d = seq - self.highest;
            if d >= REPLAY_WINDOW as u64 {
                return WindowOutcome::TooFar;
            }
            self.shift(d as usize);
            self.highest = seq;
            self.set_bit(0);
            return WindowOutcome::Fresh;
        }
        let d = (self.highest - seq) as usize;
        if d >= REPLAY_WINDOW {
            return WindowOutcome::TooOld;
        }
        if self.get_bit(d) {
            return WindowOutcome::Seen;
        }
        self.set_bit(d);
        WindowOutcome::Fresh
    }

    fn get_bit(&self, i: usize) -> bool {
        (self.bits[i / 64] >> (i % 64)) & 1 == 1
    }
    fn set_bit(&mut self, i: usize) {
        self.bits[i / 64] |= 1u64 << (i % 64);
    }
    fn shift(&mut self, n: usize) {
        let words = n / 64;
        let rem = n % 64;
        let mut out = [0u64; REPLAY_WINDOW / 64];
        for i in 0..out.len() {
            if i >= words {
                let mut v = self.bits[i - words] << rem;
                if rem > 0 && i >= words + 1 {
                    v |= self.bits[i - words - 1] >> (64 - rem);
                }
                out[i] = v;
            }
        }
        self.bits = out;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Handshake,
    Open,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    BadTag,
    Replay(WindowOutcome),
    BadFrame,
    NotOpen,
}

pub struct Session {
    pub conn_id: u64,
    pub state: State,
    pub is_initiator: bool,
    tx: KeyChain,
    tx_seq: u64,
    rx: KeyChain,
    window: ReplayWindow,
    pub tx_streams: std::collections::HashMap<u32, StreamTx>,
    pub rx_streams: std::collections::HashMap<u32, StreamRx>,
    pub dgram_in: Vec<Vec<u8>>,
    pub delivered: std::collections::HashMap<u32, Vec<u8>>,
    pub transcript: [u8; 32],
    pub stat_badtag: u64,
    pub stat_replay: u64,
}

impl Session {
    pub fn from_split(conn_id: u64, keys: &crypto::SplitKeys, is_initiator: bool) -> Session {
        let (txk, rxk) = if is_initiator {
            (keys.a_to_b_gen0, keys.b_to_a_gen0)
        } else {
            (keys.b_to_a_gen0, keys.a_to_b_gen0)
        };
        Session {
            conn_id,
            state: State::Open,
            is_initiator,
            tx: KeyChain::new(txk),
            tx_seq: 0,
            rx: KeyChain::new(rxk),
            window: ReplayWindow::default(),
            tx_streams: Default::default(),
            rx_streams: Default::default(),
            dgram_in: Vec::new(),
            delivered: Default::default(),
            transcript: keys.transcript_hash,
            stat_badtag: 0,
            stat_replay: 0,
        }
    }

    // Seal one inner frame into a full datagram. Header is AAD.
    pub fn seal_frame(&mut self, frame: &Frame) -> Vec<u8> {
        let pt = streams::encode_frame(frame);
        let seq = self.tx_seq;
        self.tx_seq += 1;
        let gen = seq / crypto::KEY_ROTATION_INTERVAL;
        let key = self.tx.key_for(gen);
        let hdr = wire::Header {
            version: wire::VERSION,
            ptype: wire::TYPE_DATA,
            conn_id: self.conn_id,
            seq,
            len: (pt.len() + crypto::TAG_LEN) as u16,
        };
        let hbytes = wire::encode(&hdr, &[]);
        let ct = crypto::seal(&key, seq, &hbytes, &pt).expect("seal space");
        wire::encode(&hdr, &ct)
    }

    // Open a DATA packet: AEAD first, then replay window. Returns plaintext.
    pub fn open_data(&mut self, pkt: &wire::Packet) -> Result<Vec<u8>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::NotOpen);
        }
        let seq = pkt.header.seq;
        let gen = seq / crypto::KEY_ROTATION_INTERVAL;
        let key = self.rx.key_for(gen);
        let hbytes = pkt.header_bytes();
        let pt = crypto::open(&key, seq, &hbytes, &pkt.body)
            .map_err(|_| {
                self.stat_badtag += 1;
                SessionError::BadTag
            })?;
        match self.window.check(seq) {
            WindowOutcome::Fresh => Ok(pt),
            other => {
                self.stat_replay += 1;
                Err(SessionError::Replay(other))
            }
        }
    }

    // Process an opened frame payload. Returns inner frames to send back.
    pub fn on_frame(&mut self, pt: &[u8], now: u64) -> Result<Vec<Frame>, SessionError> {
        let f = streams::decode_frame(pt).map_err(|_| SessionError::BadFrame)?;
        match f.ftype {
            streams::FRAME_STREAM => {
                let rx = self.rx_streams.entry(f.id).or_default();
                let out = rx.put(f.off, &f.data);
                if !out.is_empty() {
                    self.delivered.entry(f.id).or_default().extend_from_slice(&out);
                }
                Ok(vec![Frame {
                    ftype: streams::FRAME_ACK,
                    id: f.id,
                    off: 0,
                    cum: rx.expected,
                    sacks: rx.sacks(),
                    data: vec![],
                }])
            }
            streams::FRAME_ACK => {
                let tx = self.tx_streams.entry(f.id).or_default();
                tx.on_ack(f.cum, &f.sacks);
                Ok(tx.gap_retransmit(f.id, now))
            }
            streams::FRAME_DGRAM => {
                if self.dgram_in.len() < 10_000 {
                    self.dgram_in.push(f.data);
                }
                Ok(vec![])
            }
            streams::FRAME_CLOSE => {
                self.state = State::Closed;
                Ok(vec![])
            }
            _ => Err(SessionError::BadFrame),
        }
    }

    pub fn tick_timeouts(&mut self, now: u64, timeout: u64) -> Vec<Frame> {
        let ids: Vec<u32> = self.tx_streams.keys().copied().collect();
        let mut out = Vec::new();
        for id in ids {
            out.extend(self.tx_streams.get_mut(&id).unwrap().timeout(id, now, timeout));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_boundaries() {
        let mut w = ReplayWindow::default();
        assert_eq!(w.check(5000), WindowOutcome::Fresh); assert_eq!(w.check(5000), WindowOutcome::Seen);
        assert_eq!(w.check(5001), WindowOutcome::Fresh);
        assert_eq!(w.check(4999), WindowOutcome::Fresh);
        assert_eq!(w.check(4999), WindowOutcome::Seen);
        // behind the window
        assert_eq!(w.check(5001 - REPLAY_WINDOW as u64), WindowOutcome::TooOld);
        // too far ahead: rejected, window not advanced
        assert_eq!(w.check(5001 + REPLAY_WINDOW as u64 + 10), WindowOutcome::TooFar);
        assert_eq!(w.check(5001), WindowOutcome::Seen);
        // inside and new
        assert_eq!(w.check(5002), WindowOutcome::Fresh);
        // jump inside window advances it
        assert_eq!(w.check(5001 + 1500), WindowOutcome::Fresh);
        assert_eq!(w.check(5002), WindowOutcome::Seen); assert_eq!(w.check(5000), WindowOutcome::Seen); // both still inside the advanced window
    }
}
