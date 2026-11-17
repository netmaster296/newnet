// Ordered reliable streams inside a session. Frames ride data packets.
// No head-of-line blocking across streams: each stream reassembles alone.

use std::collections::BTreeMap;

pub const FRAME_STREAM: u8 = 0;
pub const FRAME_ACK: u8 = 1;
pub const FRAME_DGRAM: u8 = 2;
pub const FRAME_CLOSE: u8 = 3;
pub const FRAME_PING: u8 = 4;

pub const MAX_SACKS: usize = 8;
pub const CHUNK: usize = 1100;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    Short,
    BadType,
}

pub struct Frame {
    pub ftype: u8,
    pub id: u32,
    pub off: u64,
    pub cum: u64,
    pub sacks: Vec<(u64, u64)>, // inclusive ranges
    pub data: Vec<u8>,
}

pub fn encode_frame(f: &Frame) -> Vec<u8> {
    let mut v = vec![f.ftype];
    v.extend_from_slice(&f.id.to_le_bytes());
    match f.ftype {
        FRAME_STREAM => {
            v.extend_from_slice(&f.off.to_le_bytes());
            v.extend_from_slice(&f.data);
        }
        FRAME_ACK => {
            v.extend_from_slice(&f.cum.to_le_bytes());
            v.push(f.sacks.len() as u8);
            for (a, b) in &f.sacks {
                v.extend_from_slice(&a.to_le_bytes());
                v.extend_from_slice(&b.to_le_bytes());
            }
        }
        FRAME_DGRAM => v.extend_from_slice(&f.data),
        _ => {}
    }
    v
}

// Total decode. No panics on adversarial bytes.
pub fn decode_frame(b: &[u8]) -> Result<Frame, FrameError> {
    if b.len() < 5 {
        return Err(FrameError::Short);
    }
    let ftype = b[0];
    let id = u32::from_le_bytes(b[1..5].try_into().unwrap());
    match ftype {
        FRAME_STREAM => {
            if b.len() < 13 {
                return Err(FrameError::Short);
            }
            let off = u64::from_le_bytes(b[5..13].try_into().unwrap());
            Ok(Frame { ftype, id, off, cum: 0, sacks: vec![], data: b[13..].to_vec() })
        }
        FRAME_ACK => {
            if b.len() < 14 {
                return Err(FrameError::Short);
            }
            let cum = u64::from_le_bytes(b[5..13].try_into().unwrap());
            let n = b[13] as usize;
            if n > MAX_SACKS || b.len() != 14 + n * 16 {
                return Err(FrameError::Short);
            }
            let mut sacks = Vec::new();
            for i in 0..n {
                let o = 14 + i * 16;
                let a = u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
                let e = u64::from_le_bytes(b[o + 8..o + 16].try_into().unwrap());
                if a <= e {
                    sacks.push((a, e));
                }
            }
            Ok(Frame { ftype, id, off: 0, cum, sacks, data: vec![] })
        }
        FRAME_DGRAM => {
            Ok(Frame { ftype, id, off: 0, cum: 0, sacks: vec![], data: b[5..].to_vec() })
        }
        FRAME_CLOSE => Ok(Frame { ftype, id, off: 0, cum: 0, sacks: vec![], data: vec![] }),
        FRAME_PING => Ok(Frame { ftype, id, off: 0, cum: 0, sacks: vec![], data: vec![] }),
        _ => Err(FrameError::BadType),
    }
}

// Receiver side of one stream.
#[derive(Default)]
pub struct StreamRx {
    pub expected: u64,
    buf: BTreeMap<u64, Vec<u8>>,
    pub closed: bool,
}

impl StreamRx {
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    pub fn put(&mut self, off: u64, mut data: &[u8]) -> Vec<u8> {
        // The offset comes from the peer: an end at or past u64::MAX cannot
        // be represented, so refuse the chunk and store nothing.
        let Some(end) = off.checked_add(data.len() as u64) else {
            return vec![];
        };
        if data.is_empty() || end <= self.expected {
            return vec![];
        }
        // A chunk starting below `expected` but ending above it would be
        // stored under an offset the release loop can never reach, so it
        // would sit in the buffer for ever. Trim the already-delivered
        // prefix and treat the rest as starting at `expected`.
        let off = if off < self.expected {
            data = &data[(self.expected - off) as usize..];
            self.expected
        } else {
            off
        };
        self.buf.entry(off).or_insert_with(|| data.to_vec());
        let mut out = Vec::new();
        while let Some(bytes) = self.buf.remove(&self.expected) {
            self.expected += bytes.len() as u64;
            out.extend_from_slice(&bytes);
        }
        out
    }

    pub fn sacks(&self) -> Vec<(u64, u64)> {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for (off, bytes) in &self.buf {
            let start = *off;
            let end = off.saturating_add(bytes.len() as u64).saturating_sub(1);
            if let Some(last) = ranges.last_mut() {
                if start <= last.1.saturating_add(1) {
                    if end > last.1 {
                        last.1 = end;
                    }
                    continue;
                }
            }
            ranges.push((start, end));
        }
        ranges.truncate(MAX_SACKS);
        ranges
    }
}

// Sender side of one stream.
#[derive(Default)]
pub struct StreamTx {
    pub next_off: u64,
    in_flight: BTreeMap<u64, (Vec<u8>, u64)>, // off -> (bytes, sent_tick)
    acked: u64,
    sacks: Vec<(u64, u64)>,
}

impl StreamTx {
    pub fn new() -> Self {
        StreamTx { next_off: 0, in_flight: BTreeMap::new(), acked: 0, sacks: vec![] }
    }

    pub fn send(&mut self, id: u32, bytes: &[u8], tick: u64) -> Vec<Frame> {
        let mut frames = Vec::new();
        for chunk in bytes.chunks(CHUNK) {
            let off = self.next_off;
            self.next_off += chunk.len() as u64;
            self.in_flight.insert(off, (chunk.to_vec(), tick));
            frames.push(mk_stream(id, off, chunk));
        }
        frames
    }

    // Arm one queued chunk at its already-assigned offset and return the
    // frame for its first transmission.
    pub fn start(&mut self, id: u32, off: u64, chunk: Vec<u8>, now: u64) -> Frame {
        let f = mk_stream(id, off, &chunk);
        self.in_flight.insert(off, (chunk, now));
        f
    }

    fn covered(&self, off: u64, end: u64) -> bool {
        if end < self.acked {
            return true;
        }
        self.sacks.iter().any(|(a, b)| *a <= off && end <= *b)
    }

    pub fn on_ack(&mut self, cum: u64, sacks: &[(u64, u64)]) {
        self.acked = self.acked.max(cum);
        self.sacks = sacks.to_vec();
        let drop: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(off, (bytes, _))| self.covered(**off, **off + bytes.len() as u64 - 1))
            .map(|(off, _)| *off)
            .collect();
        for off in drop {
            self.in_flight.remove(&off);
        }
    }

    pub fn pending(&self) -> usize {
        self.in_flight.len()
    }

    pub fn oldest_sent(&self) -> Option<u64> {
        self.in_flight.values().map(|(_, t)| *t).min()
    }

    // Retransmit on timer: in-flight chunks older than timeout.
    pub fn timeout(&mut self, id: u32, now: u64, timeout: u64) -> Vec<Frame> {
        let mut frames = Vec::new();
        for (off, (bytes, sent)) in self.in_flight.iter_mut() {
            if *sent + timeout < now {
                *sent = now;
                frames.push(mk_stream(id, *off, bytes));
            }
        }
        frames
    }

    // Retransmit on gap: peer reported bytes past a hole we still hold.
    // A chunk is re-sent at most once per tick; otherwise ACKs of our own
    // retransmits re-fire the same hole and the traffic explodes.
    pub fn gap_retransmit(&mut self, id: u32, now: u64) -> Vec<Frame> {
        let holes: Vec<(u64, Vec<u8>)> = self
            .in_flight
            .iter()
            .filter(|(off, (bytes, sent))| {
                let end = **off + bytes.len() as u64 - 1;
                *sent != now
                    && !self.covered(**off, end)
                    && (self.sacks.iter().any(|(a, _)| *a > end) || self.acked > end + 1)
            })
            .map(|(off, (bytes, _))| (*off, bytes.clone()))
            .collect();
        let mut frames = Vec::new();
        for (off, bytes) in holes {
            if let Some((_, sent)) = self.in_flight.get_mut(&off) {
                *sent = now; // restart the timer for this chunk, never disable it
            }
            frames.push(mk_stream(id, off, &bytes));
        }
        frames
    }
}

fn mk_stream(id: u32, off: u64, bytes: &[u8]) -> Frame {
    Frame { ftype: FRAME_STREAM, id, off, cum: 0, sacks: vec![], data: bytes.to_vec() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembly_under_loss_reorder_and_sack() {
        let mut rx = StreamRx::default();
        // chunks 0..5, delivered: 0,2,3,1,5,4 (loss then reorder)
        let chunks: Vec<Vec<u8>> = (0..6).map(|i| vec![i as u8; 10]).collect();
        rx.put(0, &chunks[0]);
        rx.put(20, &chunks[2]);
        rx.put(30, &chunks[3]);
        let out = rx.put(10, &chunks[1]);
        // filling the hole releases 1, 2 and 3 contiguously
        assert_eq!(out, [&chunks[1][..], &chunks[2][..], &chunks[3][..]].concat());
        assert_eq!(rx.expected, 40);
        let sacks = rx.sacks();
        assert_eq!(sacks, vec![]); // buffer drained: cum carries the truth now
        rx.put(40, &chunks[4]);
        let out = rx.put(50, &chunks[5]);
        assert_eq!(rx.expected, 60);
        let mut all = vec![];
        all.extend(rx.put(0, &chunks[0])); // fully duplicate: nothing
        assert!(all.is_empty());
        let _ = out;
    }

    #[test]
    fn a_chunk_overlapping_delivered_bytes_is_trimmed() {
        let mut rx = StreamRx::default();
        rx.put(0, &[1, 2, 3, 4]);
        assert_eq!(rx.put(2, &[3, 4, 5, 6]), vec![5, 6]);
        assert_eq!(rx.expected, 6);
        assert_eq!(rx.buffered(), 0);
    }

    #[test]
    fn tx_ack_and_gap_retransmit() {
        let mut tx = StreamTx::new();
        let frames = tx.send(1, &[7u8; 3300], 0); // 3 chunks
        assert_eq!(frames.len(), 3);
        // receiver got 0 and 2, gap at 1: cum=1100, sack (2200,3299)
        tx.on_ack(1100, &[(2200, 3299)]);
        let holes = tx.gap_retransmit(1, 5);
        assert_eq!(holes.len(), 1);
        assert_eq!(holes[0].off, 1100);
        // same tick: an ACK of our own retransmit must not re-fire the hole
        assert!(tx.gap_retransmit(1, 5).is_empty());
        // ack covers everything
        tx.on_ack(3300, &[]);
        assert_eq!(tx.pending(), 0);
    }

    #[test]
    fn timeout_retransmits_stale() {
        let mut tx = StreamTx::new();
        tx.send(1, &[9u8; 1100], 0);
        tx.on_ack(0, &[]); // nothing acked
        let f = tx.timeout(1, 10, 3);
        assert_eq!(f.len(), 1);
        let again = tx.timeout(1, 11, 3); // just refreshed
        assert!(again.is_empty());
    }

    #[test]
    fn decode_frame_total_over_random() {
        let mut st = 0x0BADC0DEu64;
        for _ in 0..10_000 {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            let n = (st % 64) as usize;
            let mut b = vec![0u8; n];
            for x in b.iter_mut() {
                *x = (st >> 24) as u8;
                st ^= st << 3;
            }
            let _ = decode_frame(&b); // never panics
        }
    }
}

#[cfg(test)]
mod tail_tests {
    use super::*;

    #[test]
    fn gap_retransmit_does_not_disable_the_timer() {
        let mut tx = StreamTx::new();
        tx.send(1, &[5u8; 100], 0);
        tx.send(1, &[6u8; 60], 0);
        // peer got everything except the tail: sack beyond? tail is last: only timer sees it.
        let t1 = tx.timeout(1, 10, 3);
        assert_eq!(t1.len(), 2);
        // now a gap case: sack beyond chunk 0
        tx.on_ack(0, &[(100, 159)]);
        let g = tx.gap_retransmit(1, 11);
        assert_eq!(g.len(), 1); // chunk 0 retransmitted (sack starts past its end)
        // timer must still be able to fire for everything unacked
        let t2 = tx.timeout(1, 30, 3);
        assert_eq!(t2.len(), 1); // chunk 1 was sack-covered and dropped; chunk 0 keeps retrying
    }

    #[test]
    fn gap_retransmit_fires_at_most_once_per_tick() {
        let mut tx = StreamTx::new();
        tx.send(1, &[5u8; 100], 0);
        tx.send(1, &[6u8; 60], 0);
        tx.on_ack(0, &[(100, 159)]);
        // ACK storm: every ACK of the retransmit lands in the same tick
        let g1 = tx.gap_retransmit(1, 11);
        assert_eq!(g1.len(), 1);
        for _ in 0..100 {
            assert!(tx.gap_retransmit(1, 11).is_empty());
        }
        // next tick may retry once
        let g2 = tx.gap_retransmit(1, 12);
        assert_eq!(g2.len(), 1);
        assert!(tx.gap_retransmit(1, 12).is_empty());
    }
}

#[cfg(test)]
mod offset_tests {
    use super::*;

    #[test]
    fn a_chunk_ending_past_u64_max_is_refused() {
        let mut rx = StreamRx::default();
        assert_eq!(rx.put(u64::MAX, &[1]), Vec::<u8>::new());
        assert_eq!(rx.buffered(), 0);
        assert_eq!(rx.put(u64::MAX - 1, &[1, 2, 3]), Vec::<u8>::new());
        assert_eq!(rx.buffered(), 0);
    }

    #[test]
    fn sacks_of_a_chunk_at_the_top_of_the_range_do_not_panic() {
        let mut rx = StreamRx::default();
        rx.put(u64::MAX - 10, &[1u8; 5]);
        let _ = rx.sacks();
    }
}
