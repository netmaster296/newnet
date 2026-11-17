// Real UDP endpoint: owns a Node and a nonblocking UdpSocket. No threads:
// the application drives everything through poll(). Datagrams that cannot
// go out yet wait in `out`; each poll sends at most BURST of them, crude
// pacing until there is congestion control.

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::link::{Addr, ADDR_ANY};
use crate::node::{ConnectError, Node};

pub const TICK_MS: u64 = 20;
pub const TIMEOUT_TICKS: u64 = 25;
// Datagrams one poll may send per tick.
pub const BURST: usize = 32;
pub const MAX_PEERS: usize = 4096;
// A flood must not starve the timers or the send step: one poll drains at
// most this many datagrams and the rest wait for the next poll.
pub const MAX_RECV_PER_POLL: usize = 256;
// Ceiling on queued outgoing datagrams. A dropped ACK goes out again when
// the data is retransmitted; dropped data is retransmitted by the stream
// timers, so a full queue slows a transfer but cannot break it.
pub const MAX_OUT: usize = 8192;

pub struct UdpEndpoint {
    pub node: Node,
    socket: UdpSocket,
    start: Instant,
    peers: Vec<SocketAddr>,
    index: HashMap<SocketAddr, Addr>,
    max_peers: usize,
    evict_next: usize,
    out: VecDeque<(SocketAddr, Vec<u8>)>,
    send_tick: u64,
    sent_this_tick: usize,
    max_out: usize,
    // Datagrams the OS refused at send time (dropped, poll goes on).
    pub send_errors: u64,
    // Datagrams dropped because the outgoing queue was full.
    pub dropped_out: u64,
}

impl UdpEndpoint {
    pub fn bind(node: Node, local: &str) -> std::io::Result<UdpEndpoint> {
        Self::bind_with_capacity(node, local, MAX_PEERS)
    }

    pub fn bind_with_capacity(mut node: Node, local: &str, max_peers: usize) -> std::io::Result<UdpEndpoint> {
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        let epoch_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        node.set_stamp_base(epoch_ms);
        Ok(UdpEndpoint {
            node,
            socket,
            start: Instant::now(),
            peers: Vec::new(),
            index: HashMap::new(),
            max_peers,
            evict_next: 0,
            out: VecDeque::new(),
            send_tick: 0,
            sent_this_tick: 0,
            max_out: MAX_OUT,
            send_errors: 0,
            dropped_out: 0,
        })
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    pub fn now(&self) -> u64 {
        1 + self.start.elapsed().as_millis() as u64 / TICK_MS
    }

    // The index of sa in peers, adding it if new. At capacity, evict the
    // first slot (round-robin from `evict_next`) that no live handshake or
    // session depends on; only if every slot is in use does a new source get
    // ADDR_ANY, where no reply can be addressed to it.
    fn addr_id(&mut self, sa: SocketAddr) -> Addr {
        if let Some(&i) = self.index.get(&sa) {
            return i;
        }
        if self.peers.len() >= self.max_peers {
            let n = self.peers.len();
            if n > 0 {
                let start = self.evict_next % n;
                for k in 0..n {
                    let i = (start + k) % n;
                    if !self.node.addr_in_use(i as Addr) {
                        self.index.remove(&self.peers[i]);
                        self.peers[i] = sa;
                        self.index.insert(sa, i as Addr);
                        self.evict_next = i + 1;
                        return i as Addr;
                    }
                }
            }
            return ADDR_ANY;
        }
        self.peers.push(sa);
        let i = (self.peers.len() - 1) as Addr;
        self.index.insert(sa, i);
        i
    }

    pub fn set_max_out(&mut self, n: usize) {
        self.max_out = n;
    }

    fn queue_to(&mut self, addr: Addr, dgram: Vec<u8>) {
        if addr == ADDR_ANY || addr as usize >= self.peers.len() {
            return;
        }
        if self.out.len() >= self.max_out {
            self.dropped_out += 1;
            return;
        }
        let sa = self.peers[addr as usize];
        self.out.push_back((sa, dgram));
    }

    pub fn connect(&mut self, name: &str, to: SocketAddr) -> Result<u64, ConnectError> {
        let id = self.addr_id(to);
        let (conn, dgram) = self.node.connect_to(name, id, None, self.now())?;
        self.queue_to(id, dgram);
        Ok(conn)
    }

    pub fn send_bytes(&mut self, conn: u64, stream: u32, bytes: &[u8]) {
        let now = self.now();
        let datagrams = self.node.send_bytes(conn, stream, bytes, now);
        let to = self.node.addr_of(conn);
        for dgram in datagrams {
            self.queue_to(to, dgram);
        }
    }

    // One round: receive up to MAX_RECV_PER_POLL datagrams, run the timers,
    // then send up to BURST queued datagrams. Whatever is still in the socket
    // is read by the next poll, so a flood cannot starve the other steps.
    // Returns how many datagrams were received.
    pub fn poll(&mut self) -> std::io::Result<usize> {
        let mut received = 0usize;
        let mut buf = [0u8; 2048];
        while received < MAX_RECV_PER_POLL {
            match self.socket.recv_from(&mut buf) {
                Ok((n, src)) => {
                    received += 1;
                    let now = self.now();
                    let id = self.addr_id(src);
                    let outs = self.node.on_datagram_from(id, &buf[..n], now);
                    for dgram in outs {
                        self.queue_to(id, dgram);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                // On Windows an earlier datagram refused by the other side
                // (port closed since) surfaces here as a reset. No datagram
                // is lost: drop it and keep draining.
                Err(e) if e.kind() == ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            }
        }

        let now = self.now();
        let timers = self.node.tick_sessions(now, TIMEOUT_TICKS);
        for (conn, dgram) in timers {
            let to = self.node.addr_of(conn);
            self.queue_to(to, dgram);
        }

        // Sends are paced by time, not by how often poll is called: at most
        // BURST datagrams go out per tick, however many polls fall inside it.
        let now = self.now();
        if now != self.send_tick {
            self.send_tick = now;
            self.sent_this_tick = 0;
        }
        while self.sent_this_tick < BURST {
            let Some((sa, dgram)) = self.out.pop_front() else { break };
            match self.socket.send_to(&dgram, sa) {
                Ok(_) => self.sent_this_tick += 1,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    self.out.push_front((sa, dgram));
                    break;
                }
                // A destination the OS refuses (broadcast, unspecified) must
                // not stop the endpoint: drop this datagram and go on. Dropped
                // ACKs and data come back through the timers.
                Err(_) => {
                    self.send_errors += 1;
                    continue;
                }
            }
        }
        Ok(received)
    }

    pub fn queued(&self) -> usize {
        self.out.len()
    }

    // The socket address stored in this peer slot; None for ADDR_ANY or an
    // out-of-range slot.
    pub fn peer_socket(&self, addr: Addr) -> Option<SocketAddr> {
        if addr == ADDR_ANY {
            return None;
        }
        self.peers.get(addr as usize).copied()
    }

    // Send CLOSE to wherever this conn is addressed and free local state.
    pub fn close(&mut self, conn: u64) {
        let to = self.node.addr_of(conn);
        if let Some(dgram) = self.node.close(conn) {
            self.queue_to(to, dgram);
        }
    }
}
