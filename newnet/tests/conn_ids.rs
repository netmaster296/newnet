// Conn ids come from the operating system's random source, so two nodes
// built from the same identity seed never pick the same id, and stamps can
// be seeded from wall-clock time so a restarted endpoint is not refused as
// a replay.

use std::collections::HashSet;

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

// Full three-datagram open through the nodes: HS1, HS2, PING, reply.
fn open(a: &mut Node, b: &mut Node, eph: u8) -> u64 {
    let (conn, hs1) = a.connect("bob", Some([eph; 32])).unwrap();
    let hs2 = b.on_datagram(&hs1, 1);
    assert_eq!(hs2.len(), 1, "responder answers: {:?}", b.stats);
    let confirm = a.on_datagram(&hs2[0], 1);
    assert_eq!(confirm.len(), 1, "initiator proves its keys with one packet");
    let reply = b.on_datagram(&confirm[0], 1);
    assert_eq!(reply.len(), 1, "responder answers the confirming PING");
    assert!(a.on_datagram(&reply[0], 1).is_empty());
    assert!(a.is_open(conn) && b.is_open(conn));
    conn
}

#[test]
fn two_nodes_with_the_same_seed_pick_different_conn_ids() {
    let (mut a1, _b1) = pair();
    let (mut a2, _b2) = pair();
    let (c1, _) = a1.connect("bob", None).unwrap();
    let (c2, _) = a2.connect("bob", None).unwrap();
    assert_ne!(c1, c2, "same seed must not produce the same conn id");
}

#[test]
fn conn_ids_on_one_node_are_distinct() {
    let (mut a, _b) = pair();
    let mut ids = HashSet::new();
    for _ in 0..200 {
        let (c, _) = a.connect("bob", None).unwrap();
        assert!(ids.insert(c), "conn id {c} repeated");
    }
    assert_eq!(ids.len(), 200);
    assert_eq!(a.pending_count(), 200);
}

#[test]
fn set_stamp_base_never_goes_backwards() {
    let (mut a, _b) = pair();
    a.set_stamp_base(500);
    a.set_stamp_base(100);
    assert_eq!(a.next_stamp(), 500);
    a.connect("bob", None).unwrap();
    assert_eq!(a.next_stamp(), 501);
}

#[test]
fn a_restarted_initiator_needs_a_clock_based_stamp() {
    let (mut a1, mut b) = pair();
    a1.set_stamp_base(1_000);
    let conn = open(&mut a1, &mut b, 1);
    assert!(a1.is_open(conn) && b.is_open(conn));

    let rec_b = PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, expiry: u64::MAX };

    // A "restarted" alice: same identity, fresh process, no clock.
    let mut a2 = Node::new("alice", 0xA11CE);
    a2.records.insert("bob".into(), PeerRecord { name: rec_b.name.clone(), ed: rec_b.ed, x: rec_b.x, expiry: rec_b.expiry });
    let (_c2, hs1) = a2.connect("bob", None).unwrap();
    let before = b.stats.hs_replay_dropped;
    let out = b.on_datagram(&hs1, 2);
    assert!(out.is_empty(), "Bob answered the restarted alice's low-stamp HS1");
    assert_eq!(b.stats.hs_replay_dropped, before + 1);

    // With a clock-based stamp the same fresh alice is accepted.
    let mut a3 = Node::new("alice", 0xA11CE);
    a3.records.insert("bob".into(), PeerRecord { name: rec_b.name, ed: rec_b.ed, x: rec_b.x, expiry: rec_b.expiry });
    a3.set_stamp_base(2_000);
    let (_c3, hs1) = a3.connect("bob", None).unwrap();
    let out = b.on_datagram(&hs1, 3);
    assert_eq!(out.len(), 1, "Bob must answer the restarted alice once her stamp is ahead: {:?}", b.stats);
}
