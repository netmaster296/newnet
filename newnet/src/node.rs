// Node: holds identity, pins, sessions. Allocates session state only after
// a verified handshake. Handshake DH work is budgeted per hub tick.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;

use crate::content::{self, Msg, Reader};
use crate::crypto::{self, PeerRecord};
use crate::identity::{Identity, PinStore};
use crate::naming::{NameRecord, Registry};
use crate::noise::{InitiatorHandshake, ResponderHandshake};
use crate::session::{Session, SessionError};
use crate::streams::Frame;
use crate::wire;

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
}

pub struct Node {
    pub name: String,
    pub ident: Identity,
    pub pins: PinStore,
    pub records: HashMap<String, PeerRecord>,
    pub sessions: HashMap<u64, Session>,
    pending_init: HashMap<u64, (InitiatorHandshake, Vec<u8>, u64, u32)>, // hs, msg1 bytes, sent tick, attempts
    pending_resp: HashMap<u64, (ResponderHandshake, u64)>, // machine, created tick
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
            pending_resp: HashMap::new(),
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
            return Some(PeerRecord { name: r.name.clone(), ed: r.ed, x: r.x, cert: r.cert.clone() });
        }
        let reg = self.registry.as_ref()?;
        let rec = reg.get(name)?;
        Some(PeerRecord { name: rec.name.clone(), ed: VerifyingKey::from_bytes(&rec.ed).ok()?, x: rec.x_pub(), cert: vec![] })
    }

    // TOFU pin store feeds the record cache. Pin mismatch fails closed.
    pub fn pin_record(&mut self, rec: &NameRecord, now: u64) -> Result<(), ConnectError> {
        self.pins
            .check_or_pin(&rec.name, rec.ed, rec.x25519, rec.expiry, now)
            .map_err(ConnectError::Pin)?;
        self.records.insert(
            rec.name.clone(),
            PeerRecord { name: rec.name.clone(), ed: VerifyingKey::from_bytes(&rec.ed).map_err(|_| ConnectError::NoRecord)?, x: rec.x_pub(), cert: vec![] },
        );
        Ok(())
    }

    pub fn connect(&mut self, name: &str, eph: Option<[u8; 32]>) -> Result<(u64, Vec<u8>), ConnectError> {
        let t = if self.budget_tick == u64::MAX { 0 } else { self.budget_tick };
        self.connect_at(name, eph, t)
    }

    pub fn connect_at(&mut self, name: &str, eph: Option<[u8; 32]>, tick: u64) -> Result<(u64, Vec<u8>), ConnectError> {
        let rec = self.lookup_name(name).ok_or(ConnectError::NoRecord)?;
        let mut hs = InitiatorHandshake::new(&self.ident, &rec, eph)
            .map_err(|_| ConnectError::NoRecord)?;
        let conn = self.next_conn;
        self.next_conn = self.next_conn.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let body = hs.msg1_body(&self.ident, &self.name);
        let pkt = wire::encode(
            &wire::Header { version: wire::VERSION, ptype: wire::TYPE_HANDSHAKE1, conn_id: conn, seq: 0, len: body.len() as u16 },
            &body,
        );
        self.pending_init.insert(conn, (hs, pkt.clone(), tick, 0));
        Ok((conn, pkt))
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
            wire::TYPE_HANDSHAKE1 => self.on_hs1(pkt, tick),
            wire::TYPE_HANDSHAKE2 => self.on_hs2(pkt),
            wire::TYPE_DATA => self.on_data(pkt, tick),
            _ => vec![],
        }
    }

    fn on_hs1(&mut self, pkt: wire::Packet, tick: u64) -> Vec<Vec<u8>> {
        // An existing conn (half-open or live) is never reset by a replayed HS1.
        // Initiator retransmits escalate to a fresh conn id instead.
        if self.sessions.contains_key(&pkt.header.conn_id) || self.pending_resp.contains_key(&pkt.header.conn_id) {
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
        self.stats.dh_count += 1; // es happens in start before any payload check
        let reg_lookup = |n: &str| self.lookup_name(n);
        match ResponderHandshake::start(&self.ident, &pkt.body, &reg_lookup, None) {
            Ok(mut resp) => {
                self.stats.dh_count += 2; // ss in start, plus ee + se for msg2
                let body2 = resp.msg2_body(&self.name);
                let conn = pkt.header.conn_id;
                let keys = resp.split();
                let mut s = Session::from_split(conn, &keys, false);
                s.transcript = keys.transcript_hash;
                self.sessions.insert(conn, s);
                self.pending_resp.insert(conn, (resp, tick));
                self.stats.sessions_allocated += 1;
                vec![wire::encode(
                    &wire::Header { version: wire::VERSION, ptype: wire::TYPE_HANDSHAKE2, conn_id: conn, seq: 0, len: body2.len() as u16 },
                    &body2,
                )]
            }
            Err(crate::crypto::NoiseError::BadPayload) => {
                self.stats.bad_header_dropped += 1;
                vec![]
            }
            Err(_) => {
                self.stats.auth_fails += 1;
                vec![]
            }
        }
    }

    fn on_hs2(&mut self, pkt: wire::Packet) -> Vec<Vec<u8>> {
        let conn = pkt.header.conn_id;
        let (mut hs, _msg1, _sent, _att) = match self.pending_init.remove(&conn) {
            Some(h) => h,
            None => {
                self.stats.no_session_dropped += 1;
                return vec![];
            }
        };
        match hs.msg2_accept(&pkt.body) {
            Ok(keys) => {
                let s = Session::from_split(conn, &keys, true);
                self.logs.push(format!("handshake open conn={conn} transcript={}", hex::encode(s.transcript)));
                self.sessions.insert(conn, s);
                self.stats.sessions_allocated += 1;
                vec![]
            }
            Err(e) => {
                self.stats.auth_fails += 1;
                self.logs.push(format!("handshake fail conn={conn}: {e:?}"));
                vec![]
            }
        }
    }

    fn on_data(&mut self, pkt: wire::Packet, tick: u64) -> Vec<Vec<u8>> {
        let conn = pkt.header.conn_id;
        let s = match self.sessions.get_mut(&conn) {
            Some(s) => s,
            None => {
                self.stats.no_session_dropped += 1;
                return vec![];
            }
        };
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
        self.stats.data_ok += 1;
        let replies = match s.on_frame(&pt, tick) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        self.pending_resp.remove(&conn);
        let s = self.sessions.get_mut(&conn).unwrap();
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
        let frames = s.tx_streams.entry(stream).or_default().send(stream, &content::put(m), 0);
        frames.iter().map(|f| s.seal_frame(f)).collect()
    }

    // Raw bytes onto a reliable stream (legacy adapter path, no framing).
    pub fn send_bytes(&mut self, conn: u64, stream: u32, bytes: &[u8], tick: u64) -> Vec<Vec<u8>> {
        let s = match self.sessions.get_mut(&conn) {
            Some(s) => s,
            None => return vec![],
        };
        let frames = s.tx_streams.entry(stream).or_default().send(stream, bytes, tick);
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
        // Initiator: resend HS1 on the same conn up to 3 times, then escalate
        // to a fresh conn id (the peer never resets a conn it already knows).
        let mut escalated: Vec<u64> = Vec::new();
        let mut resends: Vec<(u64, Vec<u8>)> = Vec::new();
        for (conn, (hs, pkt, sent, att)) in self.pending_init.iter_mut() {
            let _ = hs;
            if now >= *sent + timeout {
                *att += 1;
                *sent = now;
                if *att <= 3 {
                    self.stats.hs_retransmits += 1;
                    resends.push((*conn, pkt.clone()));
                } else {
                    escalated.push(*conn);
                }
            }
        }
        out.extend(resends);
        for old in escalated {
            let (hs, pkt, _, _) = self.pending_init.remove(&old).unwrap();
            self.logs.push(format!("hs escalate conn={old} -> new conn"));
            let conn = self.next_conn;
            self.next_conn = self.next_conn.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            // Same handshake body (same ephemeral), fresh conn id. The body
            // bytes are reused verbatim; a cloned machine would re-encrypt
            // with advanced nonces and fail the responder's fixed nonce.
            let mut p = wire::decode(&pkt).expect("stored hs1 packet decodes");
            p.header.conn_id = conn;
            let pkt = wire::encode(&p.header, &p.body);
            self.pending_init.insert(conn, (hs, pkt.clone(), now, 0));
            out.push((conn, pkt));
        }
        // Responder: reap handshakes the initiator never confirmed with data.
        let mut reap: Vec<u64> = Vec::new();
        for (conn, (_r, created)) in self.pending_resp.iter() {
            if now >= created + 20 {
                reap.push(*conn);
            }
        }
        for conn in reap {
            self.pending_resp.remove(&conn);
            if let Some(s) = self.sessions.get(&conn) {
                if s.tx_streams.is_empty() && s.stat_badtag == 0 && s.stat_replay == 0 {
                    self.sessions.remove(&conn);
                }
            }
        }
        for (conn, s) in self.sessions.iter_mut() {
            let frames = s.tick_timeouts(now, timeout);
            for f in &frames {
                out.push((*conn, s.seal_frame(f)));
            }
        }
        out
    }

    // Send CLOSE and free local state.
    pub fn close(&mut self, conn: u64) -> Option<Vec<u8>> {
        let f = Frame { ftype: crate::streams::FRAME_CLOSE, id: 0, off: 0, cum: 0, sacks: vec![], data: vec![] };
        let bytes = self.sessions.get_mut(&conn).map(|s| s.seal_frame(&f));
        self.sessions.remove(&conn);
        self.pending_init.remove(&conn);
        self.pending_resp.remove(&conn);
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


