// Node: holds identity, pins, sessions. Allocates session state only after
// a verified handshake. Handshake DH work is budgeted per budget epoch
// (BUDGET_EPOCH_TICKS ticks).

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use x25519_dalek::PublicKey as XPublic;

use crate::content::{self, Msg, Reader};
use crate::cookie::{self, CookieKeys, SrcKey};
use crate::crypto::{self, PeerRecord};
use crate::identity::{Identity, PinStore};
use crate::link::{Addr, ADDR_ANY};
use crate::naming::{NameRecord, Registry};
use crate::noise_ik::{self, Hello, InitiatorHandshake, ResponderHandshake};
use crate::peerbook::PeerLine;
use crate::session::{Session, SessionError, IDLE_TTL};
use crate::streams::Frame;
use crate::wire;

// Initiator retry policy: each attempt resends its byte-identical HS1
// HS_RESENDS times, then escalates to a fresh attempt (new ephemeral, new
// conn id, new stamp), up to HS_ATTEMPTS attempts in total.
// One tick is 1 ms, so this TTL is 400 ms.
pub const HALF_OPEN_TTL: u64 = 400;
pub const MAX_HALF_OPEN: usize = 64;
// One enrolled peer name never holds more than this many half-open entries:
// the oldest of them is evicted to admit a newer (spec step 5).
pub const MAX_HALF_OPEN_PER_PEER: usize = 2;
// Session caps (spec step 5): a node holds at most this many sessions; one
// peer name at most this many, its least recently heard closing first.
pub const MAX_SESSIONS: usize = 64;
pub const MAX_SESSIONS_PER_PEER: usize = 4;
pub const HS_RESENDS: u32 = 3;
pub const HS_ATTEMPTS: u32 = 3;

// One attempt accepts at most this many COOKIE datagrams (spec 4.5): enough
// for the round and one lost-and-reforged retry, not enough for a flood to
// pin the attempt to a fresh cookie forever.
pub const COOKIE_ACCEPT_MAX: u8 = 2;

// Ceiling on all handshake DH work in one budget epoch, whatever the
// source split.
pub const HANDSHAKE_GLOBAL_BUDGET_PER_TICK: u32 = 64;

// Length of the handshake budget epoch in ticks: budgets keep their v1
// per-20 ms rate. The budget resets when tick / BUDGET_EPOCH_TICKS changes.
pub const BUDGET_EPOCH_TICKS: u64 = 20;

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
    pub sessions_idle_dropped: u64,
    pub cookies_sent: u64,
    pub cookies_received: u64,
    pub hs1_bad_size: u64,
    pub hs_stamp_floor_dropped: u64,
    pub half_open_evicted: u64,
    pub sessions_refused_full: u64,
    pub sessions_evicted_peer: u64,
}

struct PendingInit {
    hs: InitiatorHandshake,
    datagram: Vec<u8>,
    // Noise message 1 without the cookie prefix: what a COOKIE reply rebuilds
    // the HANDSHAKE1 around, and what the half-open entry later compares.
    noise: Vec<u8>,
    cookies_accepted: u8,
    peer: String,
    sent: u64,
    resends: u32,
    attempt: u32,
    to: Addr,
}

struct HalfOpen {
    // Noise bytes of the accepted message 1 only (not the cookie): a replay
    // of the same Noise under the same conn gets the stored HS2 back.
    noise: Vec<u8>,
    msg2: Vec<u8>,
    keys: crypto::SplitKeys,
    created: u64,
    from: Addr,
    peer: String,
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
    // Accepted Hello stamps must exceed this (step 5): a real endpoint sets
    // it to process-start wall clock minus 300 s, so a recording older than
    // five minutes cannot re-open state after a restart.
    stamp_floor: u64,
    pub readers: HashMap<(u64, u32), Reader>,
    pub stats: NodeStats,
    pub logs: Vec<String>,
    pub registry: Option<Registry>,
    budget_epoch: u64,
    budget_by_source: HashMap<Addr, u32>,
    budget_total: u32,
    // Greatest tick this node has acted at (datagram in or tick_sessions).
    // connect() starts an attempt here, not at the budget-window start.
    last_tick: u64,
    // Responder cookie secrets (rotation at the top of every HANDSHAKE1).
    cookies: CookieKeys,
    // Minimum ticks between gap retransmits of one chunk on this node's
    // sessions (amendment A6a). 1 in the in-memory lab; the UDP endpoint
    // sets 20, which is 20 ms.
    gap_interval: u64,
}

impl Node {
    pub fn new(name: &str, seed: u64) -> Node {
        Node::from_identity(name, Identity::from_seed(seed))
    }

    // A node whose identity comes from a key file rather than a demo seed
    // (spec 3.5). Everything else starts empty: the peers are added by
    // add_peer from the peers file.
    pub fn from_identity(name: &str, ident: Identity) -> Node {
        Node {
            name: name.to_string(),
            ident,
            pins: PinStore::default(),
            records: HashMap::new(),
            sessions: HashMap::new(),
            pending_init: HashMap::new(),
            half_open: HashMap::new(),
            last_stamp: HashMap::new(),
            next_stamp: 0,
            stamp_floor: 0,
            readers: HashMap::new(),
            stats: NodeStats::default(),
            logs: Vec::new(),
            registry: None,
            budget_epoch: u64::MAX,
            budget_by_source: HashMap::new(),
            budget_total: 0,
            last_tick: 0,
            cookies: CookieKeys::new(0),
            gap_interval: 1,
        }
    }

    // Gap retransmit spacing for every session on this node (amendment
    // A6a): stored here and pushed down to sessions, so a session opened
    // later inherits the node's value.
    pub fn set_gap_interval(&mut self, ticks: u64) {
        self.gap_interval = ticks;
        for s in self.sessions.values_mut() {
            s.set_gap_interval(ticks);
        }
    }

    pub fn gap_interval(&self) -> u64 {
        self.gap_interval
    }

    // One line of the peers file becomes one record. The Ed25519 half is
    // absent: a name imported from the file is trusted for its X25519 key,
    // and expiry is checked at load, not here (spec 3.5).
    pub fn add_peer(&mut self, l: &PeerLine) {
        self.records.insert(
            l.name.clone(),
            PeerRecord {
                name: l.name.clone(),
                ed: None,
                x: XPublic::from(l.key),
                expiry: l.expires.unwrap_or(u64::MAX),
            },
        );
    }

    // Fixed cookie secret for tests; also the published-vector hook.
    pub fn set_cookie_secret_for_test(&mut self, secret: [u8; 32], now: u64) {
        self.cookies = CookieKeys::from_secret_for_test(secret, now);
    }

    pub fn lookup_name(&self, name: &str) -> Option<PeerRecord> {
        if let Some(r) = self.records.get(name) {
            return Some(PeerRecord { name: r.name.clone(), ed: r.ed, x: r.x, expiry: r.expiry });
        }
        let reg = self.registry.as_ref()?;
        let rec = reg.get(name)?;
        Some(PeerRecord { name: rec.name.clone(), ed: Some(VerifyingKey::from_bytes(&rec.ed).ok()?), x: rec.x_pub(), expiry: rec.expiry })
    }

    // TOFU pin store feeds the record cache. Pin mismatch fails closed.
    pub fn pin_record(&mut self, rec: &NameRecord, now: u64) -> Result<(), ConnectError> {
        self.pins
            .check_or_pin(&rec.name, rec.ed, rec.x25519, rec.expiry, now)
            .map_err(ConnectError::Pin)?;
        self.records.insert(
            rec.name.clone(),
            PeerRecord { name: rec.name.clone(), ed: Some(VerifyingKey::from_bytes(&rec.ed).map_err(|_| ConnectError::NoRecord)?), x: rec.x_pub(), expiry: rec.expiry },
        );
        Ok(())
    }

    fn resolve(&mut self, name: &str, now: u64) -> Result<PeerRecord, ConnectError> {
        let rec = self.lookup_name(name).ok_or(ConnectError::NoRecord)?;
        if rec.expiry < now {
            return Err(ConnectError::Pin(crate::identity::IdentityError::CertExpired));
        }
        // A peers-file record carries no Ed25519 key: it pins on zeros, so
        // the pin is the name plus the X25519 key and a key swap under a
        // running node still fails closed (spec 3.5).
        let ed_pin = rec.ed.map(|k| k.to_bytes()).unwrap_or([0u8; 32]);
        self.pins
            .check_or_pin(&rec.name, ed_pin, rec.x.to_bytes(), rec.expiry, now)
            .map_err(ConnectError::Pin)?;
        Ok(rec)
    }

    pub fn connect(&mut self, name: &str, eph: Option<[u8; 32]>) -> Result<(u64, Vec<u8>), ConnectError> {
        self.connect_at(name, eph, self.last_tick)
    }

    pub fn connect_at(&mut self, name: &str, eph: Option<[u8; 32]>, tick: u64) -> Result<(u64, Vec<u8>), ConnectError> {
        self.start_attempt(name, eph, tick, 1, ADDR_ANY)
    }

    // connect with the destination address recorded: what `tick_sessions`
    // retransmits are addressed to, and what the session falls back to when
    // a reply arrives with an unknown source.
    pub fn connect_to(&mut self, name: &str, to: Addr, eph: Option<[u8; 32]>, tick: u64) -> Result<(u64, Vec<u8>), ConnectError> {
        self.start_attempt(name, eph, tick, 1, to)
    }

    // A real endpoint calls this once at start with wall-clock milliseconds,
    // so stamps keep increasing across restarts. The in-memory lab does not
    // need it. The stamp never moves backwards.
    pub fn set_stamp_base(&mut self, base: u64) {
        if base > self.next_stamp {
            self.next_stamp = base;
        }
    }

    pub fn next_stamp(&self) -> u64 {
        self.next_stamp
    }

    // Responder floor (step 5): an accepted stamp must exceed this as well
    // as the per-name table. UdpEndpoint::bind sets it at start.
    pub fn set_stamp_floor(&mut self, floor: u64) {
        self.stamp_floor = floor;
    }

    // One handshake attempt: fresh IK machine bound to conn via prologue,
    // Hello(stamp, name) as the msg1 payload, stored for identical resends.
    fn start_attempt(&mut self, name: &str, eph: Option<[u8; 32]>, tick: u64, attempt: u32, to: Addr) -> Result<(u64, Vec<u8>), ConnectError> {
        let rec = self.resolve(name, tick)?;
        let mut rng = rand::rngs::OsRng;
        let conn = loop {
            let c = rng.next_u64();
            if !self.sessions.contains_key(&c) && !self.pending_init.contains_key(&c) && !self.half_open.contains_key(&c) {
                break c;
            }
        };
        self.next_stamp += 1;
        let stamp = self.next_stamp;
        let mut hs = InitiatorHandshake::new(&self.ident.x_static.to_bytes(), rec.x.as_bytes(), &noise_ik::prologue(conn), eph)
            .map_err(|_| ConnectError::NoRecord)?;
        let noise = hs.write_msg1(&noise_ik::encode_hello(&Hello { stamp, name: self.name.clone() }))
            .map_err(|_| ConnectError::NoRecord)?;
        // v2 body layout: 16 zero cookie bytes, then the Noise message.
        let mut body = Vec::with_capacity(wire::COOKIE_LEN + noise.len());
        body.extend_from_slice(&[0u8; wire::COOKIE_LEN]);
        body.extend_from_slice(&noise);
        let datagram = wire::encode(
            &wire::Header { version: wire::VERSION, ptype: wire::TYPE_HANDSHAKE1, conn_id: conn, seq: 0, len: body.len() as u16 },
            &body,
        );
        self.pending_init.insert(conn, PendingInit { hs, datagram: datagram.clone(), noise, cookies_accepted: 0, peer: name.to_string(), sent: tick, resends: 0, attempt, to });
        Ok((conn, datagram))
    }

    pub fn half_open_count(&self) -> usize {
        self.half_open.len()
    }

    // Room for one new session for `peer` (step 5): a fifth session for one
    // name closes that name's least recently heard session; a 65th session
    // on the node is refused outright. False means drop the creating packet.
    fn make_session_room(&mut self, peer: &str) -> bool {
        let mut same_name: Vec<(u64, u64)> = self.sessions.iter().filter(|(_, s)| s.peer_name == peer).map(|(c, s)| (*c, s.last_heard())).collect();
        if same_name.len() >= MAX_SESSIONS_PER_PEER {
            same_name.sort_by_key(|(_, heard)| *heard);
            let (oldest, _) = same_name[0];
            self.sessions.remove(&oldest);
            self.stats.sessions_evicted_peer += 1;
            self.logs.push(format!("session evicted conn={oldest}: peer {peer} over per-peer cap"));
        }
        if self.sessions.len() >= MAX_SESSIONS {
            self.stats.sessions_refused_full += 1;
            return false;
        }
        true
    }

    pub fn pending_count(&self) -> usize {
        self.pending_init.len()
    }

    // Old entry point: source unknown. All such datagrams share one
    // budget bucket, so the per-node behaviour is unchanged.
    pub fn on_datagram(&mut self, bytes: &[u8], tick: u64) -> Vec<Vec<u8>> {
        self.on_datagram_from(ADDR_ANY, bytes, tick)
    }

    // One hub datagram in, datagrams to send back out. Every datagram
    // returned is a reply to `from`. Never panics. The hub's source id
    // becomes the lab source key, so the in-memory lab does the cookie
    // round too.
    pub fn on_datagram_from(&mut self, from: Addr, bytes: &[u8], tick: u64) -> Vec<Vec<u8>> {
        self.on_datagram_src(from, &cookie::src_key_lab(from), bytes, tick)
    }

    // Same, with the real claimed source of the datagram: what a UDP
    // endpoint passes (src_key_from_socket), the hub what it can derive.
    pub fn on_datagram_src(&mut self, from: Addr, src: &SrcKey, bytes: &[u8], tick: u64) -> Vec<Vec<u8>> {
        self.last_tick = tick;
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
            wire::TYPE_HANDSHAKE1 => self.on_hs1(pkt, bytes, src, tick, from),
            wire::TYPE_HANDSHAKE2 => self.on_hs2(pkt, tick, from),
            wire::TYPE_DATA => self.on_data(pkt, tick, from),
            wire::TYPE_COOKIE => self.on_cookie(pkt, tick, from),
            _ => vec![],
        }
    }

    fn on_hs1(&mut self, pkt: wire::Packet, bytes: &[u8], src: &SrcKey, tick: u64, from: Addr) -> Vec<Vec<u8>> {
        let conn = pkt.header.conn_id;
        // 2. Size before anything else: a HANDSHAKE1 is 147..=210 bytes on
        // the wire (spec 2.2); junk outside the range costs no cookie work.
        if bytes.len() < wire::HS1_MIN_DATAGRAM || bytes.len() > wire::HS1_MAX_DATAGRAM {
            self.stats.hs1_bad_size += 1;
            return vec![];
        }
        // 3. Cookie (spec 4.4): one HMAC, no table, no DH. A bad or absent
        // cookie is answered with a 40-byte COOKIE, nothing else.
        self.cookies.rotate_if_due(tick);
        let mut want = [0u8; cookie::COOKIE_LEN];
        want.copy_from_slice(&pkt.body[..cookie::COOKIE_LEN]);
        if !self.cookies.check(src, conn, &want) {
            let made = self.cookies.make(src, conn);
            self.stats.cookies_sent += 1;
            return vec![wire::encode(
                &wire::Header { version: wire::VERSION, ptype: wire::TYPE_COOKIE, conn_id: conn, seq: 0, len: cookie::COOKIE_LEN as u16 },
                &made,
            )];
        }
        // A live conn is never reset by a replayed HS1.
        if self.sessions.contains_key(&conn) {
            self.stats.auth_fails += 1;
            return vec![];
        }
        // 5. Half-open: the same Noise bytes under this conn get the stored
        // HS2 back, free of charge. Anything else on this conn is refused.
        if let Some(half) = self.half_open.get(&conn) {
            if half.noise == pkt.body[cookie::COOKIE_LEN..] {
                self.stats.hs2_resent += 1;
                return vec![half.msg2.clone()];
            }
            self.stats.auth_fails += 1;
            return vec![];
        }
        // 6. Budget, charged only now (after the cookie): what makes the
        // per-source budget meaningful on UDP (spec 4.7). Budgets run in
        // epochs of BUDGET_EPOCH_TICKS ticks, so 1 ms ticks keep the v1
        // per-20 ms rate.
        let epoch = tick / BUDGET_EPOCH_TICKS;
        if self.budget_epoch != epoch {
            self.budget_epoch = epoch;
            self.budget_by_source.clear();
            self.budget_total = 0;
        }
        // Per-source budget, then a global ceiling on the epoch's work:
        // junk from one source cannot starve the others.
        let used = self.budget_by_source.get(&from).copied().unwrap_or(0);
        if used >= crypto::HANDSHAKE_DH_BUDGET_PER_TICK as u32 || self.budget_total >= HANDSHAKE_GLOBAL_BUDGET_PER_TICK {
            self.stats.handshake_dropped_budget += 1;
            return vec![];
        }
        *self.budget_by_source.entry(from).or_insert(0) += 1;
        self.budget_total += 1;
        self.stats.dh_count += 2; // es and ss happen inside msg1, before any payload check
        let mut hs = match ResponderHandshake::new(&self.ident.x_static.to_bytes(), &noise_ik::prologue(conn), None) {
            Ok(h) => h,
            Err(_) => {
                self.stats.auth_fails += 1;
                return vec![];
            }
        };
        let (payload, remote_static) = match hs.read_msg1(&pkt.body[cookie::COOKIE_LEN..]) {
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
        // Stamps are per name and strictly increasing, and must clear the
        // floor (step 5): a recorded HS1 can never re-open state, even
        // under a fresh conn id and an empty stamp table.
        if hello.stamp <= self.stamp_floor {
            self.stats.hs_stamp_floor_dropped += 1;
            self.stats.auth_fails += 1;
            self.logs.push(format!("stamp below floor conn={conn} stamp={} floor={}", hello.stamp, self.stamp_floor));
            return vec![];
        }
        if hello.stamp <= self.last_stamp.get(&hello.name).copied().unwrap_or(0) {
            self.stats.hs_replay_dropped += 1;
            self.stats.auth_fails += 1;
            return vec![];
        }
        // Per-peer half-open cap (step 5): an enrolled name holds at most
        // MAX_HALF_OPEN_PER_PEER entries; the oldest of them makes room.
        let mut same_name: Vec<(u64, u64)> = self.half_open.iter().filter(|(_, h)| h.peer == hello.name).map(|(c, h)| (*c, h.created)).collect();
        if same_name.len() >= MAX_HALF_OPEN_PER_PEER {
            same_name.sort_by_key(|(_, created)| *created);
            let (oldest, _) = same_name[0];
            self.half_open.remove(&oldest);
            self.stats.half_open_evicted += 1;
            self.logs.push(format!("half-open evicted conn={oldest}: peer {} over per-peer cap", hello.name));
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
        self.half_open.insert(conn, HalfOpen { noise: pkt.body[cookie::COOKIE_LEN..].to_vec(), msg2: datagram2.clone(), keys, created: tick, from, peer: hello.name.clone() });
        vec![datagram2]
    }

    // Initiator side of the cookie round (spec 4.5): a COOKIE rebuilds the
    // attempt's datagram around the fresh cookie. Accepted only for a live
    // pending attempt, with a 16-byte body, from the address the attempt
    // was sent to (when known), and at most COOKIE_ACCEPT_MAX times per
    // attempt.
    fn on_cookie(&mut self, pkt: wire::Packet, tick: u64, from: Addr) -> Vec<Vec<u8>> {
        self.stats.cookies_received += 1;
        let conn = pkt.header.conn_id;
        let p = match self.pending_init.get_mut(&conn) {
            Some(p) => p,
            None => return vec![],
        };
        if pkt.body.len() != cookie::COOKIE_LEN {
            return vec![];
        }
        if p.to != ADDR_ANY && from != p.to {
            return vec![];
        }
        if p.cookies_accepted >= COOKIE_ACCEPT_MAX {
            return vec![];
        }
        p.cookies_accepted += 1;
        let mut body = Vec::with_capacity(cookie::COOKIE_LEN + p.noise.len());
        body.extend_from_slice(&pkt.body);
        body.extend_from_slice(&p.noise);
        let dgram = wire::encode(
            &wire::Header { version: wire::VERSION, ptype: wire::TYPE_HANDSHAKE1, conn_id: conn, seq: 0, len: body.len() as u16 },
            &body,
        );
        p.datagram = dgram.clone();
        p.sent = tick; // the resend timer now guards the cookie-bearing copy
        vec![dgram]
    }

    fn on_hs2(&mut self, pkt: wire::Packet, tick: u64, from: Addr) -> Vec<Vec<u8>> {
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
        // Session room is checked BEFORE the attempt is consumed (amendment
        // A6b): a full node drops the packet and leaves the pending attempt
        // in place, so the handshake can still complete later instead of
        // silently losing the attempt.
        let peer = self.pending_init.get(&conn).unwrap().peer.clone();
        if !self.make_session_room(&peer) {
            self.logs.push(format!("session refused conn={conn}: node at {MAX_SESSIONS} sessions"));
            return vec![];
        }
        let removed = self.pending_init.remove(&conn).unwrap();
        let mut s = Session::from_split(conn, &keys, true);
        s.set_gap_interval(self.gap_interval);
        // Follow the packet; fall back to the recorded destination when the
        // reply arrived with an unknown source.
        s.peer_addr = if from == ADDR_ANY { removed.to } else { from };
        s.peer_name = removed.peer.clone();
        s.note_heard(tick);
        let ping = s.seal_frame(&Frame { ftype: crate::streams::FRAME_PING, id: 0, off: 0, cum: 0, sacks: vec![], data: vec![] });
        s.note_ping_sent(tick);
        self.logs.push(format!("handshake open conn={conn} transcript={}", hex::encode(s.transcript)));
        self.sessions.insert(conn, s);
        self.stats.sessions_allocated += 1;
        vec![ping]
    }

    fn on_data(&mut self, pkt: wire::Packet, tick: u64, from: Addr) -> Vec<Vec<u8>> {
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
            // Roaming: only an authenticated packet moves the peer address.
            if from != ADDR_ANY {
                s.peer_addr = from;
            }
            self.handle_opened(conn, pt, tick)
        } else if let Some(half) = self.half_open.get(&conn) {
            // First DATA under a conn id proves the initiator holds the split
            // keys: that is the confirmation. The half-open entry stays only
            // while the proof fails.
            let mut s = Session::from_split(conn, &half.keys, false);
            s.set_gap_interval(self.gap_interval);
            let pt = match s.open_data(&pkt) {
                Ok(p) => p,
                Err(_) => {
                    self.stats.data_badtag += 1;
                    return vec![];
                }
            };
            let peer = half.peer.clone();
            if !self.make_session_room(&peer) {
                self.logs.push(format!("session refused conn={conn}: node at {MAX_SESSIONS} sessions"));
                // The half-open entry stays: the confirming packet is dropped.
                return vec![];
            }
            self.half_open.remove(&conn);
            // The confirming packet names the peer.
            s.peer_addr = from;
            s.peer_name = peer;
            s.note_heard(tick);
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
        s.note_heard(tick);
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

    // Where datagrams for this conn should go: the learned peer address, or
    // the recorded destination of an unfinished attempt.
    pub fn addr_of(&self, conn: u64) -> Addr {
        if let Some(s) = self.sessions.get(&conn) {
            return s.peer_addr;
        }
        if let Some(p) = self.pending_init.get(&conn) {
            return p.to;
        }
        if let Some(h) = self.half_open.get(&conn) {
            return h.from;
        }
        ADDR_ANY
    }

    // The name recorded at the handshake for a confirmed session; None for
    // an unknown conn, a pending attempt, or a half-open entry.
    pub fn peer_of(&self, conn: u64) -> Option<&str> {
        self.sessions.get(&conn).map(|s| s.peer_name.as_str())
    }

    // The conn id of a confirmed session in state Open whose recorded peer
    // name equals `peer`. If several match, the one with the greatest
    // last_heard(). Survives a retry: the new attempt's conn id replaces the
    // one `connect` returned.
    pub fn session_with(&self, peer: &str) -> Option<u64> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.state == crate::session::State::Open && s.peer_name == peer)
            .max_by_key(|(_, s)| s.last_heard())
            .map(|(c, _)| *c)
    }

    // True while any pending handshake attempt is addressed to this peer
    // name: the node has not given up yet.
    pub fn is_connecting_to(&self, peer: &str) -> bool {
        self.pending_init.values().any(|p| p.peer == peer)
    }

    // True if any live handshake or session is addressed to this source id:
    // replies for it would be lost if the endpoint forgot the address.
    pub fn addr_in_use(&self, addr: Addr) -> bool {
        self.sessions.values().any(|s| s.peer_addr == addr)
            || self.pending_init.values().any(|p| p.to == addr)
            || self.half_open.values().any(|h| h.from == addr)
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
        self.last_tick = now;
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
                if let Ok((new_conn, dgram)) = self.start_attempt(&removed.peer, None, now, removed.attempt + 1, removed.to) {
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
        // Sessions whose peer has fallen silent past the idle TTL are gone.
        // Nothing is sent to the silent peer.
        let idle: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.idle_expired(now))
            .map(|(c, _)| *c)
            .collect();
        for conn in idle {
            self.sessions.remove(&conn);
            self.stats.sessions_idle_dropped += 1;
            self.logs.push(format!("session idle conn={conn}: nothing heard for {IDLE_TTL} ticks"));
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



#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyfile;
    use crate::peerbook::{self, PeerLine};

    // The line a person carries: format on one machine, parse on the other.
    fn line_for(name: &str, secret: [u8; 32]) -> PeerLine {
        let l = PeerLine { name: name.to_string(), key: keyfile::public_of(&secret), expires: None };
        peerbook::parse_pub_line(&peerbook::format_pub_line(&l)).expect("the line round-trips")
    }

    // Two nodes built from fresh key files, peers imported from the files,
    // handshake through the lab hub. A third node whose line was never
    // imported costs one auth_fails and no state (spec 3.5).
    #[test]
    fn node_from_identity_handshakes_with_imported_peer() {
        let ka = keyfile::generate("alice").unwrap();
        let kb = keyfile::generate("bob").unwrap();
        let mut a = Node::from_identity(&ka.name, Identity::from_secret(ka.secret));
        let mut b = Node::from_identity(&kb.name, Identity::from_secret(kb.secret));
        a.add_peer(&line_for(&kb.name, kb.secret));
        b.add_peer(&line_for(&ka.name, ka.secret));

        let (conn, hs1) = a.connect_at("bob", None, 1).unwrap();
        let cookie = b.on_datagram_from(ADDR_ANY, &hs1, 1);
        assert_eq!(cookie.len(), 1, "a zero-cookie HANDSHAKE1 is answered with a COOKIE");
        let rebuilt = a.on_datagram(&cookie[0], 1);
        assert_eq!(rebuilt.len(), 1, "the initiator answers the COOKIE with one datagram");
        let hs2 = b.on_datagram_from(ADDR_ANY, &rebuilt[0], 1);
        assert_eq!(hs2.len(), 1, "the cookie-bearing HANDSHAKE1 gets a HANDSHAKE2: {:?}", b.stats);
        let confirm = a.on_datagram(&hs2[0], 1);
        assert_eq!(confirm.len(), 1);
        let reply = b.on_datagram_from(ADDR_ANY, &confirm[0], 1);
        assert_eq!(reply.len(), 1);
        assert!(a.on_datagram(&reply[0], 1).is_empty());
        assert!(a.is_open(conn) && b.is_open(conn), "a node from key files completes the handshake: {:?} {:?}", a.stats, b.stats);
        assert_eq!(a.stats.auth_fails, 0, "nothing failed on the way: {:?}", a.logs);
        assert_eq!(b.stats.auth_fails, 0, "nothing failed on the way: {:?}", b.logs);

        let kc = keyfile::generate("carol").unwrap();
        let mut c = Node::from_identity(&kc.name, Identity::from_secret(kc.secret));
        c.add_peer(&line_for("bob", kb.secret));
        let (cconn, chs1) = c.connect_at("bob", None, 2).unwrap();
        let ck = b.on_datagram_from(ADDR_ANY, &chs1, 2);
        assert_eq!(ck.len(), 1, "carol is answered with a COOKIE like anyone else");
        assert_eq!(wire::decode(&ck[0]).unwrap().header.ptype, wire::TYPE_COOKIE);
        let again = c.on_datagram(&ck[0], 2);
        assert_eq!(again.len(), 1);
        let out = b.on_datagram_from(ADDR_ANY, &again[0], 2);
        assert!(out.is_empty(), "a key that was never imported is refused without a reply: {:?}", b.stats);
        assert_eq!(b.stats.auth_fails, 1, "the refusal is counted exactly once");
        assert_eq!(b.half_open_count(), 0, "it leaves no half-open state");
        assert_eq!(b.sessions.len(), 1, "it leaves no session either: only alice is open");
        assert!(!c.is_open(cconn), "carol has no session");
    }
}
