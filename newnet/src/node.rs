// Node: holds identity, pins, sessions. Allocates session state only after
// a verified handshake. Handshake DH work is budgeted per hub tick.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;

use crate::content::{self, Msg, Reader};
use crate::crypto::{self, PeerRecord};
use crate::identity::{Identity, PinStore};
use crate::naming::{NameRecord, Registry};
use crate::noise_ik::{self, Hello, InitiatorHandshake, ResponderHandshake};
use crate::session::{Session, SessionError};
use crate::streams::Frame;
use crate::wire;

// Initiator retry policy: each attempt resends its byte-identical HS1
// HS_RESENDS times, then escalates to a fresh attempt (new ephemeral, new
// conn id, new stamp), up to HS_ATTEMPTS attempts in total.
pub const HALF_OPEN_TTL: u64 = 20;
pub const MAX_HALF_OPEN: usize = 64;
pub const HS_RESENDS: u32 = 3;
pub const HS_ATTEMPTS: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectError {
    NoRecord,
    Pin(crate::identity::IdentityError),
}

#[derive(Debug, Default)]
pub struct NodeStats {
    pub bad_header_dropped: u64,
    pub legacy_dropped: u64,
    pub no_session_dropped: u64,
    pub handshake_dropped_budget: u64,
    pub auth_fails: u64,
    pub dh_count: u64,
    pub sessions_allocated: u64,
    pub data_ok: u64,
    pub data_badtag: u64,
    pub data_replay: u64,
    pub hs_retransmits: u64,
    pub hs2_resent: u64,
    pub hs_replay_dropped: u64,
    pub half_open_dropped_full: u64,
    pub sessions_dead: u64,
}

struct PendingInit {
    hs: InitiatorHandshake,
    datagram: Vec<u8>,
    peer: String,
    sent: u64,
    resends: u32,
    attempt: u32,
}

struct HalfOpen {
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    keys: crypto::SplitKeys,
    created: u64,
}

pub struct Node {
    pub name: String,
    pub ident: Identity,
    pub pins: PinStore,
    pub records: HashMap<String, PeerRecord>,
    pub sessions: HashMap<u64, Session>, // confirmed sessions only
    pending_init: HashMap<u64, PendingInit>,
    half_open: HashMap<u64, HalfOpen>,
    last_stamp: HashMap<String, u64>, // greatest Hello.stamp accepted per peer name
    next_stamp: u64,
    pub readers: HashMap<(u64, u32), Reader>,
    pub stats: NodeStats,
    pub logs: Vec<String>,
    pub registry: Option<Registry>,
    next_conn: u64,
    budget_tick: u64,
    budget_used: u32,
}

impl Node {
    pub fn new(name: &str, seed: u64) -> Node {
        Node {
            name: name.to_string(),
            ident: Identity::from_seed(seed),
            pins: PinStore::default(),
            records: HashMap::new(),
            sessions: HashMap::new(),
            pending_init: HashMap::new(),
            half_open: HashMap::new(),
            last_stamp: HashMap::new(),
            next_stamp: 0,
            readers: HashMap::new(),
            stats: NodeStats::default(),
            logs: Vec::new(),
            registry: None,
            next_conn: seed ^ 0xC0FFEE,
            budget_tick: u64::MAX,
            budget_used: 0,
        }
    }

    pub fn lookup_name(&self, name: &str) -> Option<PeerRecord> {
        if let Some(r) = self.records.get(name) {
            return Some(PeerRecord { name: r.name.clone(), ed: r.ed, x: r.x, expiry: r.expiry });
        }
        let reg = self.registry.as_ref()?;
        let rec = reg.get(name)?;
        Some(PeerRecord { name: rec.name.clone(), ed: VerifyingKey::from_bytes(&rec.ed).ok()?, x: rec.x_pub(), expiry: rec.expiry })
    }

    // TOFU pin store feeds the record cache. Pin mismatch fails closed.
    pub fn pin_record(&mut self, rec: &NameRecord, now: u64) -> Result<(), ConnectError> {
        self.pins
            .check_or_pin(&rec.name, rec.ed, rec.x25519, rec.expiry, now)
            .map_err(ConnectError::Pin)?;
        self.records.insert(
            rec.name.clone(),
            PeerRecord { name: rec.name.clone(), ed: VerifyingKey::from_bytes(&rec.ed).map_err(|_| ConnectError::NoRecord)?, x: rec.x_pub(), expiry: rec.expiry },
        );
        Ok(())
    }

    fn resolve(&mut self, name: &str, now: u64) -> Result<PeerRecord, ConnectError> {
        let rec = self.lookup_name(name).ok_or(ConnectError::NoRecord)?;
        if rec.expiry < now {
            return Err(ConnectError::Pin(crate::identity::IdentityError::CertExpired));
        }
        self.pins
            .check_or_pin(&rec.name, rec.ed.to_bytes(), rec.x.to_bytes(), rec.expiry, now)
            .map_err(ConnectError::Pin)?;
        Ok(rec)
    }

    pub fn connect(&mut self, name: &str, eph: Option<[u8; 32]>) -> Result<(u64, Vec<u8>), ConnectError> {
        let t = if self.budget_tick == u64::MAX { 0 } else { self.budget_tick };
        self.connect_at(name, eph, t)
    }

    pub fn connect_at(&mut self, name: &str, eph: Option<[u8; 32]>, tick: u64) -> Result<(u64, Vec<u8>), ConnectError> {
        self.start_attempt(name, eph, tick, 1)
    }

    // One handshake attempt: fresh IK machine bound to conn via prologue,
    // Hello(stamp, name) as the msg1 payload, stored for identical resends.
    fn start_attempt(&mut self, name: &str, eph: Option<[u8; 32]>, tick: u64, attempt: u32) -> Result<(u64, Vec<u8>), ConnectError> {
        let rec = self.resolve(name, tick)?;
        let conn = self.next_conn;
        self.next_conn = self.next_conn.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.next_stamp += 1;
        let stamp = self.next_stamp;
        let mut hs = InitiatorHandshake::new(&self.ident.x_static.to_bytes(), rec.x.as_bytes(), &noise_ik::prologue(conn), eph)
            .map_err(|_| ConnectError::NoRecord)?;
        let body = hs.write_msg1(&noise_ik::encode_hello(&Hello { stamp, name: self.name.clone() }))
            .map_err(|_| ConnectError::NoRecord)?;
        let datagram = wire::encode(
            &wire::Header { version: wire::VERSION, ptype: wire::TYPE_HANDSHAKE1, conn_id: conn, seq: 0, len: body.len() as u16 },
            &body,
        );
        self.pending_init.insert(conn, PendingInit { hs, datagram: datagram.clone(), peer: name.to_string(), sent: tick, resends: 0, attempt });
        Ok((conn, datagram))
    }

    pub fn half_open_count(&self) -> usize {
        self.half_open.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending_init.len()
    }

    // One hub datagram in, datagrams to send back out. Never panics.
    pub fn on_datagram(&mut self, bytes: &[u8], tick: u64) -> Vec<Vec<u8>> {
        let pkt = match wire::decode(bytes) {
            Ok(p) => p,
            Err(wire::WireError::BadMagic) => {
                self.stats.legacy_dropped += 1;
                return vec![];
            }
            Err(_) => {
                self.stats.bad_header_dropped += 1;
                return vec![];
            }
        };
        match pkt.header.ptype {
            wire::TYPE_HANDSHAKE1 => self.on_hs1(pkt, bytes, tick),
            wire::TYPE_HANDSHAKE2 => self.on_hs2(pkt, tick),
            wire::TYPE_DATA => self.on_data(pkt, tick),
            _ => vec![],
        }
    }

    fn on_hs1(&mut self, pkt: wire::Packet, bytes: &[u8], tick: u64) -> Vec<Vec<u8>> {
        let conn = pkt.header.conn_id;
        // A live conn is never reset by a replayed HS1.
        if self.sessions.contains_key(&conn) {
            self.stats.auth_fails += 1;
            return vec![];
        }
        // Half-open: the identical HS1 gets the stored HS2 back, free of
        // charge. Anything else on this conn is refused.
        if let Some(half) = self.half_open.get(&conn) {
            if half.msg1 == bytes {
                self.stats.hs2_resent += 1;
                return vec![half.msg2.clone()];
            }
            self.stats.auth_fails += 1;
            return vec![];
        }
        if self.budget_tick != tick {
            self.budget_tick = tick;
            self.budget_used = 0;
        }
        if self.budget_used >= crypto::HANDSHAKE_DH_BUDGET_PER_TICK as u32 {
            self.stats.handshake_dropped_budget += 1;
            return vec![];
        }
        self.budget_used += 1;
        self.stats.dh_count += 2; // es and ss happen inside msg1, before any payload check
        let mut hs = match ResponderHandshake::new(&self.ident.x_static.to_bytes(), &noise_ik::prologue(conn), None) {
            Ok(h) => h,
            Err(_) => {
                self.stats.auth_fails += 1;
                return vec![];
            }
        };
        let (payload, remote_static) = match hs.read_msg1(&pkt.body) {
            Ok(v) => v,
            Err(_) => {
                self.stats.auth_fails += 1;
                return vec![];
            }
        };
        let hello = match noise_ik::decode_hello(&payload) {
            Some(h) => h,
            None => {
                self.stats.bad_header_dropped += 1;
                return vec![];
            }
        };
        let rec = match self.resolve(&hello.name, tick) {
            Ok(r) => r,
            Err(_) => {
                self.stats.auth_fails += 1;
                return vec![];
            }
        };
        if rec.x.as_bytes() != &remote_static {
            self.stats.auth_fails += 1;
            return vec![];
        }
        // Stamps are per name and strictly increasing: a recorded HS1 can
        // never re-open state, even under a fresh conn id.
        if hello.stamp <= self.last_stamp.get(&hello.name).copied().unwrap_or(0) {
            self.stats.hs_replay_dropped += 1;
            self.stats.auth_fails += 1;
            return vec![];
        }
        if self.half_open.len() >= MAX_HALF_OPEN {
            self.stats.half_open_dropped_full += 1;
            return vec![];
        }
        self.last_stamp.insert(hello.name.clone(), hello.stamp);
        self.stats.dh_count += 2; // ee + se for msg2
        let (msg2, keys) = match hs.write_msg2(&[]) {
            Ok(v) => v,
            Err(_) => {
                self.stats.auth_fails += 1;
                return vec![];
            }
        };
        let datagram2 = wire::encode(
            &wire::Header { version: wire::VERSION, ptype: wire::TYPE_HANDSHAKE2, conn_id: conn, seq: 0, len: msg2.len() as u16 },
            &msg2,
        );
        self.half_open.insert(conn, HalfOpen { msg1: bytes.to_vec(), msg2: datagram2.clone(), keys, created: tick });
        vec![datagram2]
    }

    fn on_hs2(&mut self, pkt: wire::Packet, tick: u64) -> Vec<Vec<u8>> {
        let conn = pkt.header.conn_id;
        if !self.pending_init.contains_key(&conn) {
            self.stats.no_session_dropped += 1;
            return vec![];
        }
        // Read in place: a forged msg2 must not kill the attempt (snow
        // restores its state on error).
        let keys = match self.pending_init.get_mut(&conn).unwrap().hs.read_msg2(&pkt.body) {
            Ok((_, keys)) => keys,
            Err(e) => {
                self.stats.auth_fails += 1;
                self.logs.push(format!("handshake fail conn={conn}: {e:?}"));
                return vec![];
            }
        };
        self.pending_init.remove(&conn);
        let mut s = Session::from_split(conn, &keys, true);
        let ping = s.seal_frame(&Frame { ftype: crate::streams::FRAME_PING, id: 0, off: 0, cum: 0, sacks: vec![], data: vec![] });
        s.note_ping_sent(tick);
        self.logs.push(format!("handshake open conn={conn} transcript={}", hex::encode(s.transcript)));
        self.sessions.insert(conn, s);
        self.stats.sessions_allocated += 1;
        vec![ping]
    }

    fn on_data(&mut self, pkt: wire::Packet, tick: u64) -> Vec<Vec<u8>> {
        let conn = pkt.header.conn_id;
        if self.sessions.contains_key(&conn) {
            let s = self.sessions.get_mut(&conn).unwrap();
            let pt = match s.open_data(&pkt) {
                Ok(p) => p,
                Err(SessionError::BadTag) => {
                    self.stats.data_badtag += 1;
                    return vec![];
                }
                Err(SessionError::Replay(_)) => {
                    self.stats.data_replay += 1;
                    return vec![];
                }
                Err(_) => {
                    self.stats.bad_header_dropped += 1;
                    return vec![];
                }
            };
            self.handle_opened(conn, pt, tick)
        } else if let Some(half) = self.half_open.get(&conn) {
            // First DATA under a conn id proves the initiator holds the split
            // keys: that is the confirmation. The half-open entry stays only
            // while the proof fails.
            let mut s = Session::from_split(conn, &half.keys, false);
            let pt = match s.open_data(&pkt) {
                Ok(p) => p,
                Err(_) => {
                    self.stats.data_badtag += 1;
                    return vec![];
                }
            };
            self.half_open.remove(&conn);
            self.sessions.insert(conn, s);
            self.stats.sessions_allocated += 1;
            // The replay window already recorded this packet: handle the
            // plaintext without opening it a second time.
            self.handle_opened(conn, pt, tick)
        } else {
            self.stats.no_session_dropped += 1;
            vec![]
        }
    }

    // Process an already-opened frame payload on a confirmed session.
    fn handle_opened(&mut self, conn: u64, pt: Vec<u8>, tick: u64) -> Vec<Vec<u8>> {
        self.stats.data_ok += 1;
        let s = self.sessions.get_mut(&conn).unwrap();
        let replies = match s.on_frame(&pt, tick) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let out: Vec<Vec<u8>> = replies.iter().map(|f| s.seal_frame(f)).collect();
        if s.state == crate::session::State::Closed {
            self.sessions.remove(&conn);
            self.logs.push(format!("session closed conn={conn} (CLOSE frame)"));
        }
        out
    }

    pub fn is_open(&self, conn: u64) -> bool {
        matches!(self.sessions.get(&conn), Some(s) if s.state == crate::session::State::Open)
    }

    // Drop an unfinished initiator attempt (app-side retry).
    pub fn connect_cleanup(&mut self, conn: u64) {
        self.pending_init.remove(&conn);
    }

    pub fn send_frame(&mut self, conn: u64, f: &Frame) -> Option<Vec<u8>> {
        self.sessions.get_mut(&conn).map(|s| s.seal_frame(f))
    }

    // Send one typed message over a reliable stream inside the session.
    pub fn send_msg(&mut self, conn: u64, stream: u32, m: &Msg) -> Vec<Vec<u8>> {
        let s = match self.sessions.get_mut(&conn) {
            Some(s) => s,
            None => return vec![],
        };
        let frames = s.queue_stream_bytes(stream, &content::put(m), 0);
        frames.iter().map(|f| s.seal_frame(f)).collect()
    }

    // Raw bytes onto a reliable stream (legacy adapter path, no framing).
    pub fn send_bytes(&mut self, conn: u64, stream: u32, bytes: &[u8], tick: u64) -> Vec<Vec<u8>> {
        let s = match self.sessions.get_mut(&conn) {
            Some(s) => s,
            None => return vec![],
        };
        let frames = s.queue_stream_bytes(stream, bytes, tick);
        frames.iter().map(|f| s.seal_frame(f)).collect()
    }

    pub fn take_stream_bytes(&mut self, conn: u64, stream: u32) -> Vec<u8> {
        match self.sessions.get_mut(&conn) {
            Some(s) => s.delivered.remove(&stream).unwrap_or_default(),
            None => vec![],
        }
    }

    // Drain delivered stream bytes for a (conn, stream), framed as messages.
    pub fn recv_msgs(&mut self, conn: u64, stream: u32) -> Vec<Msg> {
        let bytes = match self.sessions.get_mut(&conn) {
            Some(s) => s.delivered.remove(&stream),
            None => None,
        };
        match bytes {
            Some(b) => self.readers.entry((conn, stream)).or_default().feed(&b),
            None => vec![],
        }
    }

    pub fn tick_sessions(&mut self, now: u64, timeout: u64) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        // Initiator: resend the byte-identical HS1 on the same conn up to
        // HS_RESENDS times, then escalate to a fresh handshake: new
        // ephemeral, new conn id, new stamp.
        let expired: Vec<u64> = self
            .pending_init
            .iter()
            .filter(|(_, p)| now >= p.sent + timeout)
            .map(|(c, _)| *c)
            .collect();
        for conn in expired {
            let resend = {
                let p = self.pending_init.get_mut(&conn).unwrap();
                if p.resends < HS_RESENDS {
                    p.resends += 1;
                    p.sent = now;
                    self.stats.hs_retransmits += 1;
                    Some(p.datagram.clone())
                } else {
                    None
                }
            };
            if let Some(dgram) = resend {
                out.push((conn, dgram));
                continue;
            }
            let removed = self.pending_init.remove(&conn).unwrap();
            if removed.attempt < HS_ATTEMPTS {
                if let Ok((new_conn, dgram)) = self.start_attempt(&removed.peer, None, now, removed.attempt + 1) {
                    self.logs.push(format!("hs attempt {} conn={new_conn} to {}", removed.attempt + 1, removed.peer));
                    out.push((new_conn, dgram));
                }
            } else {
                self.logs.push(format!("connect to {} failed: no answer", removed.peer));
            }
        }
        // Responder: reap half-open handshakes the initiator never confirmed.
        let reap: Vec<u64> = self
            .half_open
            .iter()
            .filter(|(_, h)| now >= h.created + HALF_OPEN_TTL)
            .map(|(c, _)| *c)
            .collect();
        for conn in reap {
            self.half_open.remove(&conn);
        }
        for (conn, s) in self.sessions.iter_mut() {
            let frames = s.tick_timeouts(now, timeout);
            for f in &frames {
                out.push((*conn, s.seal_frame(f)));
            }
        }
        // Sessions whose peer never answered the liveness PING are dead.
        let dead: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.state == crate::session::State::Closed)
            .map(|(c, _)| *c)
            .collect();
        for conn in dead {
            self.sessions.remove(&conn);
            self.stats.sessions_dead += 1;
            self.logs.push(format!("session dead conn={conn}: peer never confirmed"));
        }
        out
    }

    // Send CLOSE and free local state.
    pub fn close(&mut self, conn: u64) -> Option<Vec<u8>> {
        let f = Frame { ftype: crate::streams::FRAME_CLOSE, id: 0, off: 0, cum: 0, sacks: vec![], data: vec![] };
        let bytes = self.sessions.get_mut(&conn).map(|s| s.seal_frame(&f));
        self.sessions.remove(&conn);
        self.pending_init.remove(&conn);
        self.half_open.remove(&conn);
        bytes
    }
}

// Registry service: answer ResolveReq frames inside Open sessions only.
pub fn pump_registry(node: &mut Node, now: u64) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    let reqs: Vec<(u64, u32, String)> = {
        let reg = match node.registry.as_ref() {
            Some(r) => r,
            None => return out,
        };
        let _ = reg;
        let mut v = Vec::new();
        let conns: Vec<u64> = node.sessions.keys().copied().collect();
        for conn in conns {
            for m in node.recv_msgs(conn, 0) {
                if let Msg::ResolveReq { name } = m {
                    v.push((conn, 0, name));
                }
            }
        }
        v
    };
    for (conn, stream, name) in reqs {
        let resp = Msg::ResolveResp(node.registry.as_ref().unwrap().signed_bytes(&name));
        out.extend(node.send_msg(conn, stream, &resp).into_iter().map(|b| (conn, b)));
    }
    let _ = now;
    out
}


