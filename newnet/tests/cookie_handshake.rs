// Step 4 (A3 4c): the return-routability cookie on both sides. The cookie
// is always required, so every test here does the cookie round, as every
// other test in the crate does. Order rules tested are spec 4.4
// (responder) and 4.5 (initiator).

use newnet::crypto::PeerRecord;
use newnet::link::Hub;
use newnet::node::{COOKIE_ACCEPT_MAX, Node};
use newnet::wire;

mod common;
use common::complete_cookie_round;

fn pair_names(a_name: &str) -> (Node, Node) {
    let mut a = Node::new(a_name, 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: a_name.into(), ed: a.ident.ed_pub(), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert(a_name.into(), rec_a);
    b.set_cookie_secret_for_test([0x5C; 32], 0);
    (a, b)
}

fn pair() -> (Node, Node) {
    pair_names("alice")
}

fn hs1_of(a: &mut Node, eph: u8, tick: u64) -> (u64, Vec<u8>) {
    a.connect_at("bob", Some([eph; 32]), tick).unwrap()
}

// b must answer this HS1 with exactly one 40-byte COOKIE, and nothing else.
fn cookie_reply(b: &mut Node, from: u32, dgram: &[u8], tick: u64) -> Vec<u8> {
    let r = b.on_datagram_from(from, dgram, tick);
    assert_eq!(r.len(), 1, "a cookie-less HS1 is answered with exactly one datagram: {:?}", b.stats);
    let p = wire::decode(&r[0]).expect("the reply decodes");
    assert_eq!(p.header.ptype, wire::TYPE_COOKIE, "the reply must be a COOKIE");
    assert_eq!(p.body.len(), wire::COOKIE_LEN, "a COOKIE body is 16 bytes");
    assert_eq!(r[0].len(), 40, "a COOKIE datagram is 40 bytes");
    r[0].clone()
}

fn fill_cookie(hs1: &[u8], cookie: &[u8]) -> Vec<u8> {
    let mut p = wire::decode(hs1).unwrap();
    p.body[..wire::COOKIE_LEN].copy_from_slice(cookie);
    wire::encode(&p.header, &p.body)
}

// 1. The zero-cookie HS1 costs one HMAC and one 40-byte answer: no DH, no
// half-open entry, no budget charge.
#[test]
fn hs1_without_cookie_gets_cookie_and_no_work() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = hs1_of(&mut a, 1, 0);
    let reply = cookie_reply(&mut b, 5, &hs1, 1);
    let p = wire::decode(&reply).unwrap();
    assert_eq!(p.header.conn_id, conn, "the conn id is echoed");
    assert_eq!(p.header.seq, 0, "a COOKIE carries seq 0");
    assert_eq!(b.stats.dh_count, 0, "the cookie answer does no key exchange");
    assert_eq!(b.half_open_count(), 0, "the cookie answer allocates no half-open entry");
    assert_eq!(b.stats.handshake_dropped_budget, 0, "the cookie answer charges no budget");
    assert_eq!(b.stats.cookies_sent, 1);
}

// 2. Amplification (spec 4.6): the 40-byte answer is smaller than the
// smallest and the largest legal HANDSHAKE1.
#[test]
fn cookie_reply_is_smaller_than_request() {
    let long_name = "a".repeat(64);
    for name in ["q", long_name.as_str()] {
        let (mut a, mut b) = pair_names(name);
        let (_conn, hs1) = hs1_of(&mut a, 2, 0);
        let want = if name.len() == 1 { wire::HS1_MIN_DATAGRAM } else { wire::HS1_MAX_DATAGRAM };
        assert_eq!(hs1.len(), want, "a {}-char name puts the HS1 at {} bytes", name.len(), want);
        let reply = cookie_reply(&mut b, 5, &hs1, 1);
        assert!(reply.len() < hs1.len(), "a {}-byte answer is not smaller than a {}-byte request", reply.len(), hs1.len());
    }
}

// 3. The cookie is an HMAC over the source: the same filled HS1 from a
// different address gets a fresh COOKIE, and only the source that asked
// gets the HS2.
#[test]
fn cookie_is_bound_to_source() {
    let (mut a, mut b) = pair();
    let (_conn, hs1) = hs1_of(&mut a, 3, 0);
    let got = cookie_reply(&mut b, 5, &hs1, 1);
    let cookie = wire::decode(&got).unwrap().body;
    let filled = fill_cookie(&hs1, &cookie);
    let reply2 = cookie_reply(&mut b, 6, &filled, 1);
    let c2 = wire::decode(&reply2).unwrap().body;
    assert_ne!(cookie, c2, "the cookie made for source 6 differs: the source is in the MAC");
    assert_eq!(b.stats.dh_count, 0, "a cookie from the wrong source does no key exchange");
    assert_eq!(b.half_open_count(), 0);
    assert_eq!(b.stats.cookies_sent, 2);
    // The right source with the right cookie is taken.
    let r3 = b.on_datagram_from(5, &filled, 1);
    assert_eq!(r3.len(), 1);
    let p3 = wire::decode(&r3[0]).unwrap();
    assert_eq!(p3.header.ptype, wire::TYPE_HANDSHAKE2, "the source that asked gets the HS2");
    assert_eq!(b.half_open_count(), 1);
    assert_eq!(b.stats.dh_count, 4, "one accepted message 1 and its message 2: four DH ops");
}

// 4. The conn id is in the MAC: a cookie for one conn does not open
// another, and its Noise would fail the prologue binding anyway.
#[test]
fn cookie_is_bound_to_conn_id() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = hs1_of(&mut a, 4, 0);
    let got = cookie_reply(&mut b, 5, &hs1, 1);
    let cookie = wire::decode(&got).unwrap().body;
    let mut p = wire::decode(&hs1).unwrap();
    p.header.conn_id = conn ^ 0x0100;
    let mut body = p.body.clone();
    body[..wire::COOKIE_LEN].copy_from_slice(&cookie);
    let foreign = wire::encode(&p.header, &body);
    let reply = cookie_reply(&mut b, 5, &foreign, 1);
    let c2 = wire::decode(&reply).unwrap().body;
    assert_ne!(cookie, c2, "the cookie made for the new conn differs: the conn id is in the MAC");
    assert_eq!(b.stats.dh_count, 0, "a cookie for another conn does no key exchange");
    assert_eq!(b.half_open_count(), 0);
}

// 5. Through the hub, the exchange is exactly six
// datagrams: HS1, COOKIE, HS1, HS2, DATA(PING), DATA(ack) (spec 2.7), and
// both sides end Open.
#[test]
fn handshake_with_cookie_round_completes() {
    let (a, b) = pair();
    let mut nodes = vec![a, b];
    let mut hub = Hub::new(2, 0, 0, 0xC0FF_EE11);
    let (conn, hs1) = nodes[0].connect_at("bob", None, 0).unwrap();
    hub.send(0, &hs1);
    for _ in 0..10 {
        hub.step();
        let mut any = false;
        for i in 0..2 {
            for (from, p) in hub.drain_from(i) {
                any = true;
                let outs = nodes[i].on_datagram_from(from, &p, hub.tick);
                for o in outs {
                    hub.send(i, &o);
                }
            }
        }
        if !any {
            break;
        }
    }
    assert!(nodes[0].is_open(conn) && nodes[1].is_open(conn), "the cookie round completes: {:?}", nodes[1].stats);
    let types: Vec<u8> = hub.wire_records.iter().map(|r| wire::decode(r).unwrap().header.ptype).collect();
    assert_eq!(
        types,
        vec![wire::TYPE_HANDSHAKE1, wire::TYPE_COOKIE, wire::TYPE_HANDSHAKE1, wire::TYPE_HANDSHAKE2, wire::TYPE_DATA, wire::TYPE_DATA],
        "the cookie round is HS1, COOKIE, HS1, HS2, DATA(PING), DATA(ack)"
    );
    assert_eq!(hub.wire_records.len(), 6, "the lab handshake costs exactly two more datagrams than the v1 four");
    assert_eq!(nodes[1].stats.cookies_sent, 1);
    assert_eq!(nodes[0].stats.cookies_received, 1);
}

// 6. A flood of zero-cookie HS1s from many sources costs one HMAC each and
// no budget: the real handshake after it gets through the same tick.
#[test]
fn forged_flood_does_not_consume_budget() {
    let (mut a, mut b) = pair();
    b.set_cookie_secret_for_test([9u8; 32], 0);
    let mut rng = newnet::attacks::Rng::new(0xF10D);
    for i in 0..10_000u64 {
        let p = newnet::attacks::garbage_handshake(&mut rng, 0xF100_0000 | i);
        b.on_datagram_from(i as u32, &p, 5);
    }
    assert_eq!(b.stats.cookies_sent, 10_000, "every zero-cookie HS1 gets its cookie");
    assert_eq!(b.stats.dh_count, 0, "the flood does no key exchange");
    assert_eq!(b.stats.handshake_dropped_budget, 0, "the flood charges no budget");
    let (conn, hs1) = a.connect_at("bob", Some([6u8; 32]), 0).unwrap();
    let filled = complete_cookie_round(&mut a, &mut b, hs1, 20_000);
    let reply = b.on_datagram_from(20_000, &filled, 5);
    assert_eq!(reply.len(), 1, "the real handshake is answered in the same tick");
    let p = wire::decode(&reply[0]).unwrap();
    assert_eq!(p.header.conn_id, conn);
    assert_eq!(p.header.ptype, wire::TYPE_HANDSHAKE2);
    assert_eq!(b.stats.handshake_dropped_budget, 0, "the flood charged no budget");
    assert_eq!(b.stats.dh_count, 4, "only the real handshake did DH work: four ops");
}

// 7. A cookie lives 60 to 120 s: one rotation still accepts it, two
// rotations do not (spec 4.3).
#[test]
fn cookie_expires_after_two_rotations() {
    let (mut a, mut b) = pair();
    let (_conn, hs1) = hs1_of(&mut a, 7, 0);
    let reply = cookie_reply(&mut b, 5, &hs1, 1);
    let cookie = wire::decode(&reply).unwrap().body;
    let filled = fill_cookie(&hs1, &cookie);
    let r = b.on_datagram_from(5, &filled, 1);
    assert_eq!(wire::decode(&r[0]).unwrap().header.ptype, wire::TYPE_HANDSHAKE2, "the cookie works before any rotation");
    assert_eq!(b.stats.dh_count, 4);
    // The same conn and source replayed at the first rotation tick: the
    // cookie still verifies, now through the previous secret.
    let rb = b.on_datagram_from(5, &filled, 60_000);
    assert_eq!(rb.len(), 1);
    assert_eq!(wire::decode(&rb[0]).unwrap().header.ptype, wire::TYPE_HANDSHAKE2, "one rotation keeps the old cookie valid");
    assert_eq!(b.stats.hs2_resent, 1, "the half-open entry answers the replay");
    assert_eq!(b.stats.dh_count, 4, "the replay across the rotation costs no key exchange");
    // And past the second rotation the same cookie is refused.
    let rc = b.on_datagram_from(5, &filled, 120_000);
    assert_eq!(rc.len(), 1);
    assert_eq!(wire::decode(&rc[0]).unwrap().header.ptype, wire::TYPE_COOKIE, "two rotations kill the old cookie");
    assert_eq!(b.stats.dh_count, 4, "the refused cookie costs no key exchange");
    assert_eq!(b.stats.cookies_sent, 2, "the killed cookie gets a fresh cookie for the same conn and source");
}

// 8. The initiator keeps its attempt through junk COOKIEs: wrong conn,
// wrong address, short body are all ignored, and only COOKIE_ACCEPT_MAX
// accepted cookies per attempt rebuild the datagram; a real cookie among
// them still works.
#[test]
fn initiator_ignores_bad_cookies() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect_to("bob", 1, Some([8u8; 32]), 0).unwrap();
    let ck = |c: u64, body: &[u8]| {
        wire::encode(&wire::Header { version: wire::VERSION, ptype: wire::TYPE_COOKIE, conn_id: c, seq: 0, len: body.len() as u16 }, body)
    };
    let junk = ck(0xDEAD_BEEF, &[0x11u8; 16]); // conn id of no attempt
    let short = ck(conn, &[0x22u8; 15]); // body is not 16 bytes
    let wrong = ck(conn, &[0x33u8; 16]); // right conn, wrong address
    let o1 = a.on_datagram_from(9, &junk, 1);
    assert!(o1.is_empty(), "a COOKIE for an unknown conn is ignored");
    let o2 = a.on_datagram_from(1, &short, 1);
    assert!(o2.is_empty(), "a COOKIE with a 15-byte body is ignored");
    let o3 = a.on_datagram_from(9, &wrong, 1);
    assert!(o3.is_empty(), "a COOKIE from a wrong address is ignored");
    assert_eq!(a.stats.cookies_received, 3, "every COOKIE datagram is counted as received");
    assert_eq!(a.pending_count(), 1, "the attempt survives junk cookies");
    for t in 2..=499 {
        assert!(a.tick_sessions(t, 500).is_empty(), "no retransmit at tick {t}: the COOKIE at tick 1 reset the timer");
    }
    let real = cookie_reply(&mut b, 1, &hs1, 1);
    let real_cookie = wire::decode(&real).unwrap().body;
    let o4 = a.on_datagram_from(1, &real, 501);
    assert_eq!(o4.len(), 1, "the real COOKIE after the junk is accepted");
    let rebuilt = wire::decode(&o4[0]).unwrap();
    assert_eq!(rebuilt.header.ptype, wire::TYPE_HANDSHAKE1);
    assert_eq!(o4[0], fill_cookie(&hs1, &real_cookie), "the attempt's datagram is rebuilt with the cookie");
    // COOKIE_ACCEPT_MAX accepted cookies, no more: the next is ignored and
    // the stored datagram stays what it was.
    for i in 2..=COOKIE_ACCEPT_MAX {
        let ok = a.on_datagram_from(1, &real, 501 + i as u64);
        assert_eq!(ok.len(), 1, "accepted cookie {i} of {}", COOKIE_ACCEPT_MAX);
        assert_eq!(ok[0], fill_cookie(&hs1, &real_cookie), "the rebuild is the same datagram");
    }
    let over = a.on_datagram_from(1, &real, 510);
    assert!(over.is_empty(), "the {}-th accepted COOKIE for one attempt is ignored", COOKIE_ACCEPT_MAX + 1);
    assert_eq!(a.pending_count(), 1);
    // The rebuilt datagram, delivered, completes the handshake.
    let r = b.on_datagram_from(1, &o4[0], 511);
    assert_eq!(r.len(), 1, "the cookie-bearing HS1 is answered with the HS2");
    assert_eq!(wire::decode(&r[0]).unwrap().header.ptype, wire::TYPE_HANDSHAKE2);
}

// 9. A replayed HS1 that carries a valid cookie and the same Noise under
// the same conn gets the stored HS2 back for free (spec 4.4, step 5).
#[test]
fn replayed_hs1_with_valid_cookie_from_same_source_resends_hs2_for_free() {
    let (mut a, mut b) = pair();
    let (_conn, hs0) = hs1_of(&mut a, 9, 0);
    let hs1 = complete_cookie_round(&mut a, &mut b, hs0, 5);
    let reply = b.on_datagram_from(5, &hs1, 1);
    assert_eq!(reply.len(), 1, "the filled HS1 gets the HS2: {:?}", b.stats);
    let p = wire::decode(&reply[0]).unwrap();
    assert_eq!(p.header.ptype, wire::TYPE_HANDSHAKE2);
    assert_eq!(wire::HEADER_LEN + p.body.len(), wire::HS2_DATAGRAM, "the HS2 datagram is 72 bytes");
    let dh0 = b.stats.dh_count;
    let resent0 = b.stats.hs2_resent;
    // Same bytes, same source: the cached HS2 comes back with no key
    // exchange, no new state, no budget charge, no new COOKIE.
    let again = b.on_datagram_from(5, &hs1, 2);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0], reply[0], "the replay gets the identical HS2");
    assert_eq!(b.stats.dh_count, dh0, "the replay costs no key exchange");
    assert_eq!(b.stats.hs2_resent, resent0 + 1);
    assert_eq!(b.half_open_count(), 1, "the replay does not add state");
    assert_eq!(b.stats.handshake_dropped_budget, 0, "the replay charges no budget");
    assert_eq!(b.stats.cookies_sent, 1, "the replay carried a valid cookie: no second COOKIE");
    // Same conn and cookie but different Noise bytes: refused, no work.
    let p2 = wire::decode(&hs1).unwrap();
    let mut body = p2.body.clone();
    let n = body.len() - 1;
    body[n] ^= 0x40;
    let r3 = b.on_datagram_from(5, &wire::encode(&p2.header, &body), 3);
    assert!(r3.is_empty(), "different Noise bytes on a half-open conn are refused");
    assert_eq!(b.stats.dh_count, dh0, "the refusal did no key exchange");
}
