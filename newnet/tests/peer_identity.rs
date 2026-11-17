// A confirmed session remembers which name its peer claimed: the
// application can ask who is on the other end of a conn.

use newnet::crypto::PeerRecord;
use newnet::link::ADDR_ANY;
use newnet::node::Node;

mod common;
use common::complete_cookie_round;

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
fn both_sides_know_the_peer_name() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([1; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 1);
    assert_eq!(hs2.len(), 1, "responder answers: {:?}", b.stats);
    let confirm = a.on_datagram(&hs2[0], 1);
    assert_eq!(confirm.len(), 1, "initiator proves its keys with one packet");
    let reply = b.on_datagram(&confirm[0], 1);
    assert_eq!(reply.len(), 1, "responder answers the confirming PING");
    assert!(a.on_datagram(&reply[0], 1).is_empty());
    assert!(a.is_open(conn) && b.is_open(conn));
    assert_eq!(a.peer_of(conn), Some("bob"));
    assert_eq!(b.peer_of(conn), Some("alice"));
}

// A retry moves the session under a new conn id: the id connect returned is
// dead, and the caller must be able to ask the node for the live one.
#[test]
fn session_with_finds_the_session_after_a_retry() {
    let (mut a, mut b) = pair();
    let (conn0, _hs1) = a.connect_at("bob", None, 0).unwrap();
    // Never deliver that attempt's datagrams: drive a's timers and keep the
    // last datagram of the round.
    let mut last: Option<(u64, Vec<u8>)> = None;
    for t in 1..=9u64 {
        for entry in a.tick_sessions(t, 2) {
            last = Some(entry);
        }
    }
    let (retry_conn, hs1) = last.expect("the retry datagram was seen");
    assert_ne!(retry_conn, conn0, "the second attempt uses a new conn id");

    // The retry still has a zero cookie: answer it, rebuild, deliver the
    // cookie-bearing copy.
    let ck = b.on_datagram(&hs1, 9);
    assert_eq!(ck.len(), 1, "the retry is answered with one COOKIE: {:?}", b.stats);
    let hs1 = a.on_datagram(&ck[0], 9);
    assert_eq!(hs1.len(), 1, "the retry rebuilds with the cookie");
    let hs2 = b.on_datagram(&hs1[0], 9);
    assert_eq!(hs2.len(), 1, "responder answers the retry: {:?}", b.stats);
    let confirm = a.on_datagram(&hs2[0], 9);
    assert_eq!(confirm.len(), 1, "initiator proves its keys with one packet");
    let reply = b.on_datagram(&confirm[0], 9);
    assert_eq!(reply.len(), 1, "responder answers the confirming PING");
    assert!(a.on_datagram(&reply[0], 9).is_empty());

    let c = a.session_with("bob").expect("the live session is findable by name");
    assert_ne!(c, conn0, "the dead conn id connect returned is not the session");
    assert_eq!(c, retry_conn);
    assert!(a.is_open(c));
    assert_eq!(a.session_with("carol"), None);
    assert!(!a.is_connecting_to("bob"));
}

#[test]
fn a_half_open_or_unknown_conn_has_no_peer() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([2; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 1);
    assert_eq!(hs2.len(), 1, "responder answers: {:?}", b.stats);
    // HS1 has reached b and nothing else: b holds only a half-open entry.
    assert_eq!(b.peer_of(conn), None);
    assert_eq!(b.peer_of(12345), None);
}
