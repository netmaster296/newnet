// A confirmed session remembers which name its peer claimed: the
// application can ask who is on the other end of a conn.

use newnet::crypto::PeerRecord;
use newnet::node::Node;

fn pair() -> (Node, Node) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: a.ident.ed_pub(), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    (a, b)
}

#[test]
fn both_sides_know_the_peer_name() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([1; 32])).unwrap();
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

#[test]
fn a_half_open_or_unknown_conn_has_no_peer() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([2; 32])).unwrap();
    let hs2 = b.on_datagram(&hs1, 1);
    assert_eq!(hs2.len(), 1, "responder answers: {:?}", b.stats);
    // HS1 has reached b and nothing else: b holds only a half-open entry.
    assert_eq!(b.peer_of(conn), None);
    assert_eq!(b.peer_of(12345), None);
}
