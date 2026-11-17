// The cases the demo script does not send: a cleartext close, recorded
// handshakes, unconfirmed sessions, a leaked responder key, and both
// long-term keys against a recorded session.
//
// The attacker side uses `mini`, a second Noise IK initiator written from the
// specification with the four Diffie-Hellman results passed in by the test.
// That lets a test say exactly which secrets the attacker holds, and its
// control test shows the crate interoperates with an implementation that is
// not its own.

use newnet::crypto::{PeerRecord, SplitKeys};
use newnet::link::ADDR_ANY;
use newnet::node::{Node, BUDGET_EPOCH_TICKS, HALF_OPEN_TTL, MAX_HALF_OPEN};
use newnet::noise_ik::{self, Hello};
use newnet::session::Session;
use newnet::streams::{self, Frame};
use newnet::wire;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

mod mini {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};

    #[derive(Clone)]
    pub struct St {
        h: [u8; 32],
        ck: [u8; 32],
        k: [u8; 32],
        n: u64,
    }

    fn nonce(n: u64) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[4..].copy_from_slice(&n.to_le_bytes());
        b
    }

    impl St {
        // IK pre-message: the responder's static key is known to both sides.
        pub fn new(prologue: &[u8], rs_pub: &[u8; 32]) -> St {
            let name = b"Noise_IK_25519_ChaChaPoly_SHA256"; // 32 bytes, so h = name
            let mut s = St { h: *name, ck: *name, k: [0; 32], n: 0 };
            s.mix_hash(prologue);
            s.mix_hash(rs_pub);
            s
        }
        pub fn mix_hash(&mut self, d: &[u8]) {
            let mut x = Sha256::new();
            x.update(self.h);
            x.update(d);
            self.h = x.finalize().into();
        }
        pub fn mix_key(&mut self, ikm: &[u8; 32]) {
            let mut okm = [0u8; 64];
            Hkdf::<Sha256>::new(Some(&self.ck), ikm).expand(&[], &mut okm).unwrap();
            self.ck.copy_from_slice(&okm[..32]);
            self.k.copy_from_slice(&okm[32..]);
            self.n = 0;
        }
        pub fn enc(&mut self, pt: &[u8]) -> Vec<u8> {
            let c = ChaCha20Poly1305::new((&self.k).into())
                .encrypt(Nonce::from_slice(&nonce(self.n)), Payload { msg: pt, aad: &self.h })
                .unwrap();
            self.n += 1;
            self.mix_hash(&c);
            c
        }
        pub fn dec(&mut self, ct: &[u8]) -> Option<Vec<u8>> {
            let p = ChaCha20Poly1305::new((&self.k).into())
                .decrypt(Nonce::from_slice(&nonce(self.n)), Payload { msg: ct, aad: &self.h })
                .ok();
            self.n += 1;
            self.mix_hash(ct);
            p
        }
        pub fn split(&self) -> ([u8; 32], [u8; 32]) {
            let mut okm = [0u8; 64];
            Hkdf::<Sha256>::new(Some(&self.ck), &[]).expand(&[], &mut okm).unwrap();
            (okm[..32].try_into().unwrap(), okm[32..].try_into().unwrap())
        }
    }

    // -> e, es, s, ss
    pub fn msg1(prologue: &[u8], rs_pub: &[u8; 32], e_pub: &[u8; 32], s_pub: &[u8; 32], es: &[u8; 32], ss: &[u8; 32], payload: &[u8]) -> (Vec<u8>, St) {
        let mut st = St::new(prologue, rs_pub);
        st.mix_hash(e_pub);
        st.mix_key(es);
        let cs = st.enc(s_pub);
        st.mix_key(ss);
        let cp = st.enc(payload);
        let mut m = e_pub.to_vec();
        m.extend_from_slice(&cs);
        m.extend_from_slice(&cp);
        (m, st)
    }

    // <- e, ee, se. Returns (message 2 authenticated, i->r key, r->i key).
    pub fn finish(mut st: St, msg2: &[u8], ee: &[u8; 32], se: &[u8; 32]) -> (bool, [u8; 32], [u8; 32]) {
        st.mix_hash(&msg2[..32]);
        st.mix_key(ee);
        st.mix_key(se);
        let ok = st.dec(&msg2[32..]).is_some();
        let (k1, k2) = st.split();
        (ok, k1, k2)
    }
}

fn pair() -> (Node, Node) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: Some(b.ident.ed_pub()), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    (a, b)
}

mod common;
use common::{complete_cookie_round, cookie_for_handbuilt, fill_cookie};

// Full open through the nodes, cookie round included. Returns the conn id
// and the handshake datagram as an eavesdropper would have recorded it:
// the copy that carries the cookie.
fn open(a: &mut Node, b: &mut Node, eph: u8) -> (u64, Vec<u8>) {
    let (conn, hs1) = a.connect("bob", Some([eph; 32])).unwrap();
    let hs1 = complete_cookie_round(a, b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 1);
    assert_eq!(hs2.len(), 1, "responder answers: {:?}", b.stats);
    let confirm = a.on_datagram(&hs2[0], 1);
    assert_eq!(confirm.len(), 1, "initiator proves its keys with one packet");
    let reply = b.on_datagram(&confirm[0], 1);
    assert_eq!(reply.len(), 1, "responder answers the confirming PING");
    assert!(a.on_datagram(&reply[0], 1).is_empty());
    assert!(a.is_open(conn) && b.is_open(conn));
    (conn, hs1)
}

fn dh(sk: &StaticSecret, pk: &[u8; 32]) -> [u8; 32] {
    sk.diffie_hellman(&XPublic::from(*pk)).to_bytes()
}

fn public(sk: &StaticSecret) -> [u8; 32] {
    XPublic::from(sk).to_bytes()
}

fn hello(stamp: u64) -> Vec<u8> {
    noise_ik::encode_hello(&Hello { stamp, name: "alice".into() })
}

fn hs_packet(ptype: u8, conn: u64, body: &[u8]) -> Vec<u8> {
    wire::encode(&wire::Header { version: wire::VERSION, ptype, conn_id: conn, seq: 0, len: body.len() as u16 }, body)
}

// v2 HANDSHAKE1: 16 zero cookie bytes in front of the Noise message.
fn hs1_zero_cookie(conn: u64, noise: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; wire::COOKIE_LEN];
    body.extend_from_slice(noise);
    hs_packet(wire::TYPE_HANDSHAKE1, conn, &body)
}

fn initiator_session(conn: u64, k1: [u8; 32], k2: [u8; 32]) -> Session {
    Session::from_split(conn, &SplitKeys { a_to_b_gen0: k1, b_to_a_gen0: k2, transcript_hash: [0u8; 32] }, true)
}

fn stream_frame(data: &[u8]) -> Frame {
    Frame { ftype: streams::FRAME_STREAM, id: 1, off: 0, cum: 0, sacks: vec![], data: data.to_vec() }
}

// ---- header and lifecycle ----

#[test]
fn cleartext_close_must_not_kill_a_live_session() {
    let (mut a, mut b) = pair();
    let (conn, _) = open(&mut a, &mut b, 1);
    // Type 3 was the unauthenticated close.
    b.on_datagram(&hs_packet(3, conn, &[0u8]), 2);
    assert!(b.is_open(conn), "an unauthenticated header removed Bob's live session");
    let c = a.close(conn).expect("authenticated close");
    b.on_datagram(&c, 2);
    assert!(!b.is_open(conn), "the authenticated CLOSE frame still works");
}

#[test]
fn responder_is_not_open_until_the_initiator_proves_its_keys() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([2u8; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 1);
    assert_eq!(hs2.len(), 1);
    assert!(!b.is_open(conn), "message 1 alone is replayable; it must not open a session");
    assert_eq!(b.half_open_count(), 1);
    assert_eq!(b.stats.sessions_allocated, 0);
    let confirm = a.on_datagram(&hs2[0], 1);
    assert_eq!(confirm.len(), 1);
    b.on_datagram(&confirm[0], 1);
    assert!(b.is_open(conn));
    assert_eq!(b.half_open_count(), 0);
    assert_eq!(b.stats.sessions_allocated, 1);
}

#[test]
fn recorded_hs1_under_fresh_conn_id_must_not_allocate() {
    let (mut a, mut b) = pair();
    let (_conn, hs1) = open(&mut a, &mut b, 3);
    let mut p = wire::decode(&hs1).unwrap();
    p.header.conn_id ^= 0xDEAD_BEEF;
    let tampered = wire::encode(&p.header, &p.body);
    // The recorded cookie belongs to the old conn: a fresh conn gets a fresh
    // cookie challenge, and the same recorded Noise still must not allocate.
    let ck = b.on_datagram(&tampered, 2);
    assert_eq!(ck.len(), 1, "the fresh conn is answered with one COOKIE");
    assert_eq!(wire::decode(&ck[0]).unwrap().header.ptype, wire::TYPE_COOKIE, "the challenge is a COOKIE");
    let filled = fill_cookie(&tampered, &wire::decode(&ck[0]).unwrap().body);
    let out = b.on_datagram(&filled, 2);
    assert!(out.is_empty(), "Bob answered a recorded HS1 under a new conn id");
    assert_eq!(b.half_open_count(), 0);
    assert_eq!(b.stats.sessions_allocated, 1);
}

#[test]
fn recorded_hs1_replayed_after_the_session_is_gone_must_not_allocate() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = open(&mut a, &mut b, 4);
    let c = a.close(conn).unwrap();
    b.on_datagram(&c, 2);
    assert!(b.sessions.is_empty());
    let out = b.on_datagram(&hs1, 3); // same bytes, same conn id, later: cookie still fresh
    assert!(out.is_empty(), "Bob answered a stale HS1");
    assert_eq!(b.half_open_count(), 0);
    assert_eq!(b.stats.hs_replay_dropped, 1);
    // A fresh handshake from the real Alice still works afterwards.
    open(&mut a, &mut b, 5);
}

#[test]
fn half_open_is_reaped_even_after_junk_data() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([6u8; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    assert_eq!(b.on_datagram(&hs1, 1).len(), 1); // reply never reaches Alice
    b.on_datagram(&newnet::attacks::spoof_data(conn, 0, &[1u8; 32], b"junk"), 1);
    assert_eq!(b.half_open_count(), 1, "junk data neither opens nor removes it");
    for t in 2..=(HALF_OPEN_TTL + 60) {
        b.tick_sessions(t, 3);
    }
    assert_eq!(b.half_open_count(), 0, "unconfirmed handshake still held 59 ticks later");
    assert!(b.sessions.is_empty());
}

#[test]
fn half_open_table_is_bounded() {
    let (mut a, mut b) = pair();
    for i in 0..(MAX_HALF_OPEN as u64 + 6) {
        // One name holds at most MAX_HALF_OPEN_PER_PEER half-open entries
        // (step 5), so filling the global table takes one name per conn.
        let name = format!("peer{i}");
        a.name = name.clone();
        b.records.insert(name.clone(), PeerRecord { name: name.clone(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX });
        let (_c, hs1) = a.connect("bob", None).unwrap();
        let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
        b.on_datagram(&hs1, 100 + i * BUDGET_EPOCH_TICKS); // a new budget epoch each time, so the DH budget is not the limit
    }
    assert_eq!(b.half_open_count(), MAX_HALF_OPEN);
    assert_eq!(b.stats.half_open_dropped_full, 6);
    assert_eq!(b.stats.sessions_allocated, 0);
}

#[test]
fn lost_hs2_is_healed_by_resending_the_same_datagram() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect_at("bob", Some([7u8; 32]), 0).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    assert_eq!(b.on_datagram(&hs1, 0).len(), 1); // Bob's reply is lost
    let dh_before = b.stats.dh_count;
    for t in 1..=10 {
        for (_, p) in a.tick_sessions(t, 2) {
            assert_eq!(p, hs1, "a resend is the identical datagram");
            for reply in b.on_datagram(&p, t) {
                for confirm in a.on_datagram(&reply, t) {
                    b.on_datagram(&confirm, t);
                }
            }
        }
        if a.is_open(conn) {
            break;
        }
    }
    assert!(a.is_open(conn) && b.is_open(conn), "same conn id opens on both sides");
    assert_eq!(b.stats.hs2_resent, 1);
    assert_eq!(b.stats.dh_count, dh_before, "answering a duplicate costs no key exchange");
    assert_eq!(b.sessions.len(), 1);
}

// The traffic key for a packet is derived from its sequence number, which
// sits in the cleartext header. One forged header must not make the receiver
// derive keys: with seq = u64::MAX the old code derived generations until
// the process ran out of memory.
#[test]
fn a_forged_far_future_sequence_number_derives_no_keys() {
    let (mut a, mut b) = pair();
    let (conn, _) = open(&mut a, &mut b, 10);
    let before = b.sessions[&conn].rx_generations();
    // Three billion first: three million generations if the guard is missing,
    // which shows the fault without exhausting memory. Only then the real one.
    b.on_datagram(&newnet::attacks::spoof_data(conn, 3_000_000_000, &[1u8; 32], b"x"), 2);
    assert_eq!(b.sessions[&conn].rx_generations(), before, "a forged header drove key derivation");
    b.on_datagram(&newnet::attacks::spoof_data(conn, u64::MAX, &[1u8; 32], b"x"), 2);
    assert_eq!(b.sessions[&conn].rx_generations(), before);
    // The session is unharmed.
    for p in a.send_bytes(conn, 1, b"still here", 2) {
        b.on_datagram(&p, 2);
    }
    assert_eq!(b.take_stream_bytes(conn, 1), b"still here".to_vec());

    // Same forged packet against a handshake that is only half open.
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([11u8; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 1);
    b.on_datagram(&newnet::attacks::spoof_data(conn, 3_000_000_000, &[1u8; 32], b"x"), 1);
    b.on_datagram(&newnet::attacks::spoof_data(conn, u64::MAX, &[1u8; 32], b"x"), 1);
    assert_eq!(b.half_open_count(), 1);
    for confirm in a.on_datagram(&hs2[0], 1) {
        b.on_datagram(&confirm, 1);
    }
    assert!(b.is_open(conn));
}

#[test]
fn a_forged_hs2_does_not_kill_a_pending_handshake() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([8u8; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 1);
    assert!(a.on_datagram(&hs_packet(wire::TYPE_HANDSHAKE2, conn, &[0x55u8; 48]), 1).is_empty());
    assert_eq!(a.stats.auth_fails, 1);
    assert_eq!(a.pending_count(), 1, "the attempt survives a forged reply");
    assert_eq!(a.on_datagram(&hs2[0], 1).len(), 1);
    assert!(a.is_open(conn));
}

#[test]
fn initiator_gives_up_after_bounded_attempts_with_fresh_ephemerals() {
    let (mut a, _b) = pair();
    let (_conn, first) = a.connect_at("bob", Some([9u8; 32]), 0).unwrap();
    let mut sent = vec![first];
    for t in 1..=200 {
        for (_, p) in a.tick_sessions(t, 2) {
            sent.push(p);
        }
    }
    assert_eq!(a.pending_count(), 0, "the initiator stops trying");
    let mut conns: Vec<u64> = sent.iter().map(|p| wire::decode(p).unwrap().header.conn_id).collect();
    conns.dedup();
    let mut ephs: Vec<Vec<u8>> = sent.iter().map(|p| wire::decode(p).unwrap().body[..32].to_vec()).collect();
    ephs.dedup();
    assert_eq!(conns.len(), 3, "three attempts, each under its own conn id");
    assert_eq!(ephs.len(), 3, "each attempt has its own ephemeral key");
    assert_eq!(sent.len(), 12, "each attempt is sent once and resent three times");
}

// ---- key schedule, against an independent implementation ----

#[test]
fn an_independent_noise_ik_initiator_interoperates() {
    let (a, mut b) = pair();
    let (sa, sa_pub, sb_pub) = (a.ident.x_static.clone(), a.ident.x_pub.to_bytes(), b.ident.x_pub.to_bytes());
    let e = StaticSecret::from([0x21u8; 32]);
    let conn = 0x1111u64;
    let (m1, st) = mini::msg1(&noise_ik::prologue(conn), &sb_pub, &public(&e), &sa_pub, &dh(&e, &sb_pub), &dh(&sa, &sb_pub), &hello(1));
    let filled = cookie_for_handbuilt(&mut b, &hs1_zero_cookie(conn, &m1), ADDR_ANY, 1);
    let out = b.on_datagram(&filled, 1);
    assert_eq!(out.len(), 1, "Bob answers a spec-built message 1: {:?}", b.stats);
    let m2 = wire::decode(&out[0]).unwrap().body;
    let re: [u8; 32] = m2[..32].try_into().unwrap();
    let (ok, k1, k2) = mini::finish(st, &m2, &dh(&e, &re), &dh(&sa, &re));
    assert!(ok, "message 2 authenticates under independently derived keys");
    b.on_datagram(&initiator_session(conn, k1, k2).seal_frame(&stream_frame(b"hello bob")), 1);
    assert!(b.is_open(conn));
    assert_eq!(b.take_stream_bytes(conn, 1), b"hello bob".to_vec());
}

// Key-compromise impersonation. Noise IK lets the holder of Bob's key forge
// message 1 in Alice's name; that is a documented property and the reason Bob
// holds it half-open. What must never work is finishing: `se` needs Alice's
// static private key or Bob's fresh ephemeral.
#[test]
fn bobs_static_key_alone_must_not_let_anyone_be_alice() {
    let (a, mut b) = pair();
    let sb = b.ident.x_static.clone(); // the leaked key
    let (sa_pub, sb_pub) = (a.ident.x_pub.to_bytes(), b.ident.x_pub.to_bytes());
    let e = StaticSecret::from([0x66u8; 32]);
    let conn = 0x4D41u64;
    let (m1, st) = mini::msg1(&noise_ik::prologue(conn), &sb_pub, &public(&e), &sa_pub, &dh(&e, &sb_pub), &dh(&sb, &sa_pub), &hello(1));
    let filled = cookie_for_handbuilt(&mut b, &hs1_zero_cookie(conn, &m1), ADDR_ANY, 1);
    let out = b.on_datagram(&filled, 1);
    assert_eq!(out.len(), 1, "forged message 1 is expected to be answered: {:?}", b.stats);
    let m2 = wire::decode(&out[0]).unwrap().body;
    let re: [u8; 32] = m2[..32].try_into().unwrap();
    let ee = dh(&e, &re);
    // Everything Mallory can compute in place of se = DH(s_alice, e_bob).
    let guesses = [dh(&sb, &re), dh(&e, &sb_pub), ee, dh(&sb, &sa_pub), [0u8; 32]];
    for (i, se) in guesses.iter().enumerate() {
        let (ok, k1, k2) = mini::finish(st.clone(), &m2, &ee, se);
        assert!(!ok, "guess {i} authenticated message 2");
        b.on_datagram(&initiator_session(conn, k1, k2).seal_frame(&stream_frame(b"i am alice")), 1);
        assert!(!b.is_open(conn), "guess {i} opened a session in Alice's name");
        assert!(b.take_stream_bytes(conn, 1).is_empty());
    }
    assert_eq!(b.stats.sessions_allocated, 0);
}

// Forward secrecy guard: both long-term private keys and the full wire
// record do not yield the transport keys, because ee needs an ephemeral.
#[test]
fn both_static_keys_do_not_open_a_recorded_session() {
    let (a, mut b) = pair();
    let (sa, sb) = (a.ident.x_static.clone(), b.ident.x_static.clone());
    let (sa_pub, sb_pub) = (a.ident.x_pub.to_bytes(), b.ident.x_pub.to_bytes());
    let e = StaticSecret::from([0x31u8; 32]);
    let (e_pub, conn) = (public(&e), 0x2222u64);
    let prologue = noise_ik::prologue(conn);

    // The honest session, recorded.
    let (m1, st) = mini::msg1(&prologue, &sb_pub, &e_pub, &sa_pub, &dh(&e, &sb_pub), &dh(&sa, &sb_pub), &hello(1));
    let filled = cookie_for_handbuilt(&mut b, &hs1_zero_cookie(conn, &m1), ADDR_ANY, 1);
    let out = b.on_datagram(&filled, 1);
    let m2 = wire::decode(&out[0]).unwrap().body;
    let re: [u8; 32] = m2[..32].try_into().unwrap();
    let (ok, k1, k2) = mini::finish(st, &m2, &dh(&e, &re), &dh(&sa, &re));
    assert!(ok);
    b.on_datagram(&initiator_session(conn, k1, k2).seal_frame(&stream_frame(b"real")), 1);
    assert_eq!(b.take_stream_bytes(conn, 1), b"real".to_vec());

    // Eve: both static private keys, no ephemeral. She can rebuild message 1
    // (the initiator's identity is not forward secret in IK) and compute se.
    let (es, ss, se) = (dh(&sb, &e_pub), dh(&sa, &sb_pub), dh(&sa, &re));
    let (m1_again, st) = mini::msg1(&prologue, &sb_pub, &e_pub, &sa_pub, &es, &ss, &hello(1));
    assert_eq!(m1_again, m1);
    let before = b.stats.data_badtag;
    let guesses = [es, ss, se, dh(&sb, &re), [0u8; 32]];
    for (i, ee) in guesses.iter().enumerate() {
        let (ok, k1, k2) = mini::finish(st.clone(), &m2, ee, &se);
        assert!(!ok, "guess {i} authenticated message 2 without an ephemeral");
        let mut eve = initiator_session(conn, k1, k2);
        eve.seal_frame(&stream_frame(b"skip seq 0"));
        b.on_datagram(&eve.seal_frame(&stream_frame(b"eve")), 2);
        assert!(b.take_stream_bytes(conn, 1).is_empty(), "guess {i} was accepted");
    }
    assert_eq!(b.stats.data_badtag - before, guesses.len() as u64);
}
