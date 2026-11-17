// In-memory hub: broadcast medium with scripted loss, reorder, jitter.
// Deterministic: seeded xorshift. The hub only forwards datagrams; it
// allocates nothing and reads nothing.

use std::collections::VecDeque;

// Source address as the hub sees it: the sender's node index.
pub type Addr = u32;
// "Source unknown": used by the old entry points.
pub const ADDR_ANY: Addr = u32::MAX;

pub struct Hub {
    queues: Vec<VecDeque<(usize, Vec<u8>)>>,
    pub tick: u64,
    loss_pct: u32,
    reorder_pct: u32,
    state: u64,
    pub wire_records: Vec<Vec<u8>>, // Eve's tap: every datagram on the wire
    pub delivered: u64,
    pub dropped_loss: u64,
    pub forwarded: u64,
}

impl Hub {
    pub fn new(nodes: usize, loss_pct: u32, reorder_pct: u32, seed: u64) -> Hub {
        Hub {
            queues: (0..nodes).map(|_| VecDeque::new()).collect(),
            tick: 0,
            loss_pct,
            reorder_pct,
            state: if seed == 0 { 0x853C_49E6_748F_EA9B } else { seed },
            wire_records: Vec::new(),
            delivered: 0,
            dropped_loss: 0,
            forwarded: 0,
        }
    }

    fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    pub fn send(&mut self, from: usize, bytes: &[u8]) {
        if self.wire_records.len() < 300_000 {
            self.wire_records.push(bytes.to_vec());
        }
        for to in 0..self.queues.len() {
            if to == from {
                continue;
            }
            if (self.next() % 100) < self.loss_pct as u64 {
                self.dropped_loss += 1;
                continue;
            }
            self.forwarded += 1;
            if (self.next() % 100) < self.reorder_pct as u64 {
                self.queues[to].push_front((from, bytes.to_vec()));
            } else {
                self.queues[to].push_back((from, bytes.to_vec()));
            }
        }
    }

    // Unicast: same wire record, same loss and reorder draws, one recipient.
    pub fn send_to(&mut self, from: usize, to: usize, bytes: &[u8]) {
        if self.wire_records.len() < 300_000 {
            self.wire_records.push(bytes.to_vec());
        }
        if to == from {
            return;
        }
        if (self.next() % 100) < self.loss_pct as u64 {
            self.dropped_loss += 1;
            return;
        }
        self.forwarded += 1;
        if (self.next() % 100) < self.reorder_pct as u64 {
            self.queues[to].push_front((from, bytes.to_vec()));
        } else {
            self.queues[to].push_back((from, bytes.to_vec()));
        }
    }

    pub fn step(&mut self) {
        self.tick += 1;
    }

    pub fn drain(&mut self, to: usize) -> Vec<Vec<u8>> {
        let v: Vec<Vec<u8>> = self.queues[to].drain(..).map(|(_, b)| b).collect();
        self.delivered += v.len() as u64;
        v
    }

    // Drain naming the sender of each datagram.
    pub fn drain_from(&mut self, to: usize) -> Vec<(Addr, Vec<u8>)> {
        let v: Vec<(Addr, Vec<u8>)> = self.queues[to].drain(..).map(|(f, b)| (f as Addr, b)).collect();
        self.delivered += v.len() as u64;
        v
    }
}
