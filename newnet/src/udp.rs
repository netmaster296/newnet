// Real UDP endpoint: owns a Node and a nonblocking UdpSocket. No threads:
// the application drives everything through poll(). Datagrams that cannot
// go out yet wait in `out`; each poll sends at most BURST of them, crude
// pacing until there is congestion control.

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::link::{Addr, ADDR_ANY};
use crate::node::{ConnectError, Node};

pub const TICK_MS: u64 = 20;
pub const TIMEOUT_TICKS: u64 = 25;
pub const BURST: usize = 32;
pub const MAX_PEERS: usize = 4096;

pub struct UdpEndpoint {
    pub node: Node,
    socket: UdpSocket,
    start: Instant,
    peers: Vec<SocketAddr>,
    out: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl UdpEndpoint {
    pub fn bind(mut node: Node, local: &str) -> std::io::Result<UdpEndpoint> {
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        let epoch_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        node.set_stamp_base(epoch_ms);
        Ok(UdpEndpoint { node, socket, start: Instant::now(), peers: Vec::new(), out: VecDeque::new() })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    pub fn now(&self) -> u64 {
        1 + self.start.elapsed().as_millis() as u64 / TICK_MS
    }

    // The index of sa in peers, adding it if new. At capacity a new source
    // gets ADDR_ANY: no reply can be addressed to it.
    fn addr_id(&mut self, sa: SocketAddr) -> Addr {
        if let Some(i) = self.peers.iter().position(|p| *p == sa) {
            return i as Addr;
        }
        if self.peers.len() >= MAX_PEERS {
            return ADDR_ANY;
        }
        self.peers.push(sa);
        (self.peers.len() - 1) as Addr
    }

    fn queue_to(&mut self, addr: Addr, dgram: Vec<u8>) {
        if addr == ADDR_ANY || addr as usize >= self.peers.len() {
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

    // One round: receive everything pending, run the timers, then send up
    // to BURST queued datagrams. Returns how many datagrams were received.
    pub fn poll(&mut self) -> std::io::Result<usize> {
        let mut received = 0usize;
        let mut buf = [0u8; 2048];
        loop {
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

        for _ in 0..BURST {
            let Some((sa, dgram)) = self.out.pop_front() else { break };
            match self.socket.send_to(&dgram, sa) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    self.out.push_front((sa, dgram));
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(received)
    }

    pub fn queued(&self) -> usize {
        self.out.len()
    }
}
