// One encrypted session: replay window, key generations, state machine.
// Handshake state accepts no application frames.

use crate::crypto::{self, KeyChain};
use crate::streams::{self, Frame, StreamRx, StreamTx};
use crate::wire;

pub const REPLAY_WINDOW: usize = 2048;

// How far ahead of the highest authenticated sequence number a header may
// claim to be before it is refused without deriving a key. It bounds what a
// forged header can cost (about a thousand key generations, once) and how
// long an outage the session survives.
pub const MAX_LOOKAHEAD: u64 = 1 << 20;

// Pings a new initiator sends before the peer confirms, after which the
// session is dropped as dead.
pub const PING_RESENDS: u32 = 5;

// Ticks without an authenticated packet from the peer before the session
// is dropped. One tick is 1 ms, so this is 12 s.
pub const IDLE_TTL: u64 = 12_000;

// Ticks of silence before this side asks the peer to speak.
pub const KEEPALIVE_AFTER: u64 = IDLE_TTL / 3;

// A quarter of REPLAY_WINDOW, so that new chunks, gap retransmits and timer
// retransmits sealed in one pump round (at most 3 x 512) stay inside the window.
pub const MAX_IN_FLIGHT: usize = 512;

// Out-of-order chunks one session will hold across all its streams. An
// honest sender has at most MAX_IN_FLIGHT chunks in flight.
pub const MAX_RX_BUFFERED: usize = 4 * MAX_IN_FLIGHT;

// Receive streams per session.
pub const MAX_STREAMS: usize = 16_384;

// How far ahead of a stream's `expected` offset a peer may put a chunk.
// A peer choosing offsets near u64::MAX cannot make this side hold ranges
// that no honest sender would ever reach.
pub const MAX_OFFSET_AHEAD: u64 = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum WindowOutcome {
    Fresh,
    Seen,
    TooOld,
    TooFar,
}

#[derive(Clone)]
pub struct ReplayWindow {
    highest: u64,
    bits: [u64; REPLAY_WINDOW / 64],
}

// The window starts at sequence 0, where every sender starts. It does not
// anchor on whichever packet happens to arrive first: a reordered packet
// from far ahead used to become the anchor, and everything sent before it
// was then rejected as too old.
impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow { highest: 0, bits: [0; REPLAY_WINDOW / 64] }
    }
}

impl ReplayWindow {
    // Highest authenticated sequence number seen.
    pub fn highest(&self) -> u64 {
        self.highest
    }

    // True when the seq is beyond MAX_LOOKAHEAD of the highest authenticated
    // seq. Needs no key, so it can run before a packet is authenticated.
    pub fn too_far(&self, seq: u64) -> bool {
        seq > self.highest && seq - self.highest >= MAX_LOOKAHEAD
    }

    // An authenticated seq above `highest` always moves the window: the
    // sender gets a new key every 1000 seqs, so refusing an honest jump is
    // how an outage stalls a session for good.
    pub fn check(&mut self, seq: u64) -> WindowOutcome {
        if seq > self.highest {
            let d = seq - self.highest;
            if d >= REPLAY_WINDOW as u64 {
                self.bits = [0; REPLAY_WINDOW / 64];
            } else {
                self.shift(d as usize);
            }
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
    // Where the peer is now: learned from authenticated packets, then
    // followed when the peer roams.
    pub peer_addr: crate::link::Addr,
    // The name the peer claimed in its Hello, recorded at the handshake.
    pub peer_name: String,
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
    pub stat_overlimit: u64,
    // True once any fresh packet from the peer has been opened: the peer
    // proved it holds the split keys.
    pub confirmed: bool,
    ping_sent: u64,
    pings: u32,
    // Tick the last authenticated packet from the peer was accepted.
    last_heard: u64,
    // Tick the last idle keepalive PING went out.
    last_keepalive: u64,
    // Chunks waiting for their first transmission, in the order the
    // application submitted them: (stream id, offset, chunk bytes).
    send_queue: std::collections::VecDeque<(u32, u64, Vec<u8>)>,
    // Always equals the sum of pending() over all tx_streams.
    in_flight_total: usize,
    // Always equals the sum of buffered() over all rx_streams.
    rx_buffered: usize,
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
            peer_addr: crate::link::ADDR_ANY,
            peer_name: String::new(),
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
            stat_overlimit: 0,
            confirmed: false,
            ping_sent: 0,
            pings: 0,
            last_heard: 0,
            last_keepalive: 0,
            send_queue: std::collections::VecDeque::new(),
            in_flight_total: 0,
            rx_buffered: 0,
        }
    }

    pub fn in_flight_total(&self) -> usize {
        self.in_flight_total
    }

    pub fn rx_buffered(&self) -> usize {
        self.rx_buffered
    }

    pub fn queued_chunks(&self) -> usize {
        self.send_queue.len()
    }

    // Release queued chunks up to the in-flight cap, arming each as it goes.
    pub fn flush(&mut self, now: u64) -> Vec<Frame> {
        let mut out = Vec::new();
        while self.in_flight_total < MAX_IN_FLIGHT {
            let Some((stream, off, chunk)) = self.send_queue.pop_front() else { break };
            let f = self.tx_streams.entry(stream).or_default().start(stream, off, chunk, now);
            self.in_flight_total += 1;
            out.push(f);
        }
        out
    }

    // Split bytes into chunks, assign offsets now, queue for first
    // transmission, and release whatever the cap still allows.
    pub fn queue_stream_bytes(&mut self, stream: u32, bytes: &[u8], now: u64) -> Vec<Frame> {
        for chunk in bytes.chunks(streams::CHUNK) {
            let tx = self.tx_streams.entry(stream).or_default();
            let off = tx.next_off;
            tx.next_off += chunk.len() as u64;
            self.send_queue.push_back((stream, off, chunk.to_vec()));
        }
        self.flush(now)
    }

    // Seal one inner frame into a full datagram. Header is AAD.
    pub fn seal_frame(&mut self, frame: &Frame) -> Vec<u8> {
        let pt = streams::encode_frame(frame);
        let seq = self.tx_seq;
        self.tx_seq += 1;
        let gen = seq / crypto::KEY_ROTATION_INTERVAL;
        let key = self.tx.key_for(gen).expect("the current send generation is always held");
        self.tx.forget_before(gen);
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

    // Receive-side keys held now (older generations are erased).
    pub fn rx_generations(&self) -> usize {
        self.rx.generations()
    }

    // Highest authenticated sequence number this side has opened.
    pub fn rx_highest(&self) -> u64 {
        self.window.highest()
    }

    // Send-side keys held now: only the current generation.
    pub fn tx_generations(&self) -> usize {
        self.tx.generations()
    }

    // Open a DATA packet: AEAD first, then replay window. Returns plaintext.
    pub fn open_data(&mut self, pkt: &wire::Packet) -> Result<Vec<u8>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::NotOpen);
        }
        let seq = pkt.header.seq;
        // The traffic key is derived from the sequence number, and the header
        // is not authenticated yet. A sequence number the window would refuse
        // anyway is refused here, before any key is derived. Without this,
        // one forged header with a huge seq made the receiver derive key
        // generations until it ran out of memory.
        if self.window.too_far(seq) {
            self.stat_replay += 1;
            return Err(SessionError::Replay(WindowOutcome::TooFar));
        }
        let gen = seq / crypto::KEY_ROTATION_INTERVAL;
        // A packet whose key was erased is older than the window: its key is
        // gone, so it cannot be authenticated and is refused as too old.
        let key = match self.rx.key_for(gen) {
            Some(k) => k,
            None => {
                self.stat_replay += 1;
                return Err(SessionError::Replay(WindowOutcome::TooOld));
            }
        };
        let hbytes = pkt.header_bytes();
        let pt = crypto::open(&key, seq, &hbytes, &pkt.body)
            .map_err(|_| {
                self.stat_badtag += 1;
                SessionError::BadTag
            })?;
        match self.window.check(seq) {
            WindowOutcome::Fresh => {
                self.confirmed = true;
                // Only an authenticated packet erases keys. Erase everything
                // below the window: a later packet inside the window still
                // finds its key, one below it is TooOld either way.
                let low = self.window.highest().saturating_sub(REPLAY_WINDOW as u64 - 1);
                self.rx.forget_before(low / crypto::KEY_ROTATION_INTERVAL);
                Ok(pt)
            }
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
                // A peer that finished the handshake is trusted to be who it
                // says, not to be well behaved: cap what it can make this
                // side hold. Refused frames create no state and get no ACK.
                let expected = self.rx_streams.get(&f.id).map(|r| r.expected).unwrap_or(0);
                if f.off > expected.saturating_add(MAX_OFFSET_AHEAD) {
                    self.stat_overlimit += 1;
                    return Ok(vec![]);
                }
                if !self.rx_streams.contains_key(&f.id) && self.rx_streams.len() >= MAX_STREAMS {
                    self.stat_overlimit += 1;
                    return Ok(vec![]);
                }
                if f.off > expected && self.rx_buffered >= MAX_RX_BUFFERED {
                    self.stat_overlimit += 1;
                    return Ok(vec![]);
                }
                let rx = self.rx_streams.entry(f.id).or_default();
                let before = rx.buffered();
                let out = rx.put(f.off, &f.data);
                let after = rx.buffered();
                if after >= before {
                    self.rx_buffered += after - before;
                } else {
                    self.rx_buffered -= before - after;
                }
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
                // An ACK names a stream this side sent on. A peer inventing
                // ids must not create sender state for them.
                let tx = match self.tx_streams.get_mut(&f.id) {
                    Some(t) => t,
                    None => return Ok(vec![]),
                };
                let before = tx.pending();
                tx.on_ack(f.cum, &f.sacks);
                let released = before - tx.pending();
                let mut reply = tx.gap_retransmit(f.id, now);
                self.in_flight_total -= released;
                reply.extend(self.flush(now));
                Ok(reply)
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
            // PING id 0 is a request, answered once with id 1; a reply is
            // never answered.
            streams::FRAME_PING => {
                if f.id == 0 {
                    Ok(vec![Frame {
                        ftype: streams::FRAME_PING,
                        id: 1,
                        off: 0,
                        cum: 0,
                        sacks: vec![],
                        data: vec![],
                    }])
                } else {
                    Ok(vec![])
                }
            }
            _ => Err(SessionError::BadFrame),
        }
    }

    // Record when the liveness PING went out, so the timer starts there.
    pub fn note_ping_sent(&mut self, now: u64) {
        self.ping_sent = now;
    }

    // Record that an authenticated packet from the peer was accepted now.
    pub fn note_heard(&mut self, now: u64) {
        self.last_heard = now;
    }

    pub fn last_heard(&self) -> u64 {
        self.last_heard
    }

    pub fn idle_expired(&self, now: u64) -> bool {
        now >= self.last_heard + IDLE_TTL
    }

    pub fn tick_timeouts(&mut self, now: u64, timeout: u64) -> Vec<Frame> {
        // Initiator liveness: keep proving the peer got the handshake until
        // it answers something. After PING_RESENDS silent probes the session
        // is dead.
        let mut out = Vec::new();
        if self.is_initiator && !self.confirmed && now >= self.ping_sent + timeout {
            if self.pings < PING_RESENDS {
                self.pings += 1;
                self.ping_sent = now;
                out.push(Frame {
                    ftype: streams::FRAME_PING,
                    id: 0,
                    off: 0,
                    cum: 0,
                    sacks: vec![],
                    data: vec![],
                });
            } else {
                self.state = State::Closed;
                return vec![];
            }
        }
        // Idle keepalive: a confirmed session that has heard nothing for
        // KEEPALIVE_AFTER ticks asks the peer to speak. The peer answers a
        // PING id 0 with id 1; hearing that answer refreshes last_heard.
        if self.confirmed
            && now >= self.last_heard + KEEPALIVE_AFTER
            && now >= self.last_keepalive + KEEPALIVE_AFTER
        {
            self.last_keepalive = now;
            out.push(Frame {
                ftype: streams::FRAME_PING,
                id: 0,
                off: 0,
                cum: 0,
                sacks: vec![],
                data: vec![],
            });
        }
        let ids: Vec<u32> = self.tx_streams.keys().copied().collect();
        for id in ids {
            out.extend(self.tx_streams.get_mut(&id).unwrap().timeout(id, now, timeout));
        }
        out.extend(self.flush(now));
        debug_assert_eq!(self.in_flight_total, self.tx_streams.values().map(|t| t.pending()).sum::<usize>());
        debug_assert_eq!(self.rx_buffered, self.rx_streams.values().map(|r| r.buffered()).sum::<usize>());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_boundaries() {
        let mut w = ReplayWindow::default();
        assert_eq!(w.check(0), WindowOutcome::Fresh);
        assert_eq!(w.check(0), WindowOutcome::Seen);
        for s in [1500u64, 3000, 4500, 5000] {
            assert_eq!(w.check(s), WindowOutcome::Fresh);
        }
        assert_eq!(w.check(5000), WindowOutcome::Seen);
        assert_eq!(w.check(5001), WindowOutcome::Fresh);
        assert_eq!(w.check(4999), WindowOutcome::Fresh);
        assert_eq!(w.check(4999), WindowOutcome::Seen);
        // behind the window
        assert_eq!(w.check(5001 - REPLAY_WINDOW as u64), WindowOutcome::TooOld);
        // a jump past the window is accepted and moves it; nothing older survives
        let far = 5001 + REPLAY_WINDOW as u64 + 10;
        assert_eq!(w.check(far), WindowOutcome::Fresh);
        assert_eq!(w.check(far), WindowOutcome::Seen);
        assert_eq!(w.check(5001), WindowOutcome::TooOld);
        assert_eq!(w.check(far - 1), WindowOutcome::Fresh);
        // the guard that runs before authentication
        assert!(!w.too_far(far + MAX_LOOKAHEAD - 1));
        assert!(w.too_far(far + MAX_LOOKAHEAD));
        assert!(!w.too_far(0));
    }
}
