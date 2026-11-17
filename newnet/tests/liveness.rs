// Initiator liveness: the PING that follows the handshake is a request with
// a reply, it is resent a bounded number of times, and a session whose peer
// never confirms is dropped instead of kept alive by a dead initiator.

use newnet::crypto::PeerRecord;
use newnet::link::ADDR_ANY;
use newnet::node::Node;

mod common;
use common::complete_cookie_round;
use newnet::session::PING_RESENDS;
use newnet::streams::Frame;

fn pair() -> (Node, Node) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: Some(b.ident.ed_pub()), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    (a, b)
}

#[test]
fn the_responder_answers_the_ping_and_the_initiator_is_confirmed() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect_at("bob", None, 0).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 0);
    assert_eq!(hs2.len(), 1);
    let ping = a.on_datagram(&hs2[0], 0);
    assert_eq!(ping.len(), 1, "initiator sends the PING");
    assert!(!a.sessions[&conn].confirmed);
    let reply = b.on_datagram(&ping[0], 0);
    assert_eq!(reply.len(), 1, "responder answers the PING");
    assert!(a.on_datagram(&reply[0], 0).is_empty());
    assert!(a.sessions[&conn].confirmed);
}

#[test]
fn a_reply_is_never_answered() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect_at("bob", None, 0).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 0);
    assert_eq!(hs2.len(), 1);
    let ping = a.on_datagram(&hs2[0], 0);
    assert_eq!(ping.len(), 1);
    let reply = b.on_datagram(&ping[0], 0);
    assert_eq!(reply.len(), 1);
    assert!(a.on_datagram(&reply[0], 0).is_empty());
    let pong = b
        .send_frame(conn, &Frame { ftype: newnet::streams::FRAME_PING, id: 1, off: 0, cum: 0, sacks: vec![], data: vec![] })
        .unwrap();
    assert!(a.on_datagram(&pong, 0).is_empty(), "a PING reply is never answered");
}

#[test]
fn a_lost_ping_is_resent_until_the_responder_confirms() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect_at("bob", None, 0).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 0);
    assert_eq!(hs2.len(), 1);
    a.on_datagram(&hs2[0], 0); // a's first PING is lost
    let mut resent: Option<Vec<u8>> = None;
    for t in 1..=3 {
        for (_, p) in a.tick_sessions(t, 2) {
            assert!(resent.is_none(), "exactly one datagram may come out");
            resent = Some(p);
        }
    }
    let ping = resent.expect("the lost PING is resent once");
    let reply = b.on_datagram(&ping, 2);
    assert_eq!(reply.len(), 1, "responder opens and answers the PING");
    assert!(b.is_open(conn));
    assert!(a.on_datagram(&reply[0], 2).is_empty());
    for t in 4..=40 {
        assert!(a.tick_sessions(t, 2).is_empty(), "confirmed: no more PINGs");
    }
    assert!(a.is_open(conn));
}

#[test]
fn a_session_whose_peer_never_confirms_is_dropped() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect_at("bob", None, 0).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 0);
    assert_eq!(hs2.len(), 1);
    a.on_datagram(&hs2[0], 0); // everything from here on is lost
    let mut pings = 0usize;
    for t in 1..=60 {
        pings += a.tick_sessions(t, 2).len();
    }
    assert_eq!(pings, PING_RESENDS as usize, "the PING goes out PING_RESENDS times");
    assert!(!a.is_open(conn));
    assert!(a.sessions.is_empty());
    assert_eq!(a.stats.sessions_dead, 1);
}

#[test]
fn data_from_the_peer_confirms_without_a_reply() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect_at("bob", None, 0).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 0);
    assert_eq!(hs2.len(), 1);
    let ping = a.on_datagram(&hs2[0], 0);
    assert_eq!(ping.len(), 1);
    let reply = b.on_datagram(&ping[0], 0);
    assert_eq!(reply.len(), 1);
    assert!(!a.sessions[&conn].confirmed, "b's reply is lost");
    for p in b.send_bytes(conn, 1, b"hi", 1) {
        a.on_datagram(&p, 1);
    }
    assert!(a.sessions[&conn].confirmed, "fresh data from the peer confirms");
    for t in 2..=40 {
        a.tick_sessions(t, 2);
    }
    assert_eq!(a.stats.sessions_dead, 0);
    assert!(a.is_open(conn));
}
