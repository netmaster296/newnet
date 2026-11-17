// Source addresses: the handshake budget is per source, sessions learn
// and follow the peer address, and the hub can name the sender.

use newnet::crypto::PeerRecord;
use newnet::link::{Hub, ADDR_ANY};
use newnet::node::Node;
use newnet::streams::Frame;
use newnet::wire;

mod common;
use common::{complete_cookie_round, cookie_for_handbuilt};

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
fn junk_from_one_source_does_not_starve_another() {
    let (mut a, mut b) = pair();
    let mut rng = newnet::attacks::Rng::new(7);
    for i in 0..10u64 {
        let p = newnet::attacks::garbage_handshake(&mut rng, 9000 + i);
        let p = cookie_for_handbuilt(&mut b, &p, 7, 5);
        b.on_datagram_from(7, &p, 5);
    }
    let (_conn, hs1) = a.connect("bob", Some([1u8; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, 3);
    let hs2 = b.on_datagram_from(3, &hs1, 5);
    assert_eq!(hs2.len(), 1, "a fresh source gets its handshake through");
    assert_eq!(b.stats.handshake_dropped_budget, 6);
}

#[test]
fn the_old_entry_point_still_has_one_shared_budget() {
    let (mut a, mut b) = pair();
    let mut rng = newnet::attacks::Rng::new(7);
    for i in 0..10u64 {
        let p = newnet::attacks::garbage_handshake(&mut rng, 9000 + i);
        let p = cookie_for_handbuilt(&mut b, &p, ADDR_ANY, 5);
        b.on_datagram(&p, 5);
    }
    let (_conn, hs1) = a.connect("bob", Some([2u8; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    assert!(b.on_datagram(&hs1, 5).is_empty(), "unknown sources share one bucket");
}

#[test]
fn a_global_cap_bounds_the_work_per_tick() {
    let (_a, mut b) = pair();
    let mut rng = newnet::attacks::Rng::new(11);
    for i in 0..100u64 {
        let p = newnet::attacks::garbage_handshake(&mut rng, 20000 + i);
        let p = cookie_for_handbuilt(&mut b, &p, 1000 + i as u32, 9);
        b.on_datagram_from(1000 + i as u32, &p, 9);
    }
    assert!(b.stats.dh_count <= 2 * 64, "the tick is capped globally: {} DH", b.stats.dh_count);
    assert_eq!(b.stats.handshake_dropped_budget, 36);
}

#[test]
fn sessions_learn_and_follow_the_peer_address() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect_to("bob", 2, Some([3u8; 32]), 1).unwrap();
    // The attempt is addressed to 2, so its COOKIE must come from 2 (spec 4.5):
    // the shared helper's unknown-source delivery would be ignored.
    let ck = b.on_datagram_from(1, &hs1, 1);
    assert_eq!(ck.len(), 1, "the zero-cookie HS1 is answered with one COOKIE");
    assert_eq!(wire::decode(&ck[0]).unwrap().header.ptype, wire::TYPE_COOKIE, "the first reply is the COOKIE");
    let hs1 = a.on_datagram_from(2, &ck[0], 1);
    assert_eq!(hs1.len(), 1, "the attempt rebuilds into a cookie-bearing HS1");
    let hs2 = b.on_datagram_from(1, &hs1[0], 1);
    assert_eq!(hs2.len(), 1);
    let confirm = a.on_datagram_from(2, &hs2[0], 1);
    assert_eq!(confirm.len(), 1);
    let reply = b.on_datagram_from(1, &confirm[0], 1);
    assert_eq!(reply.len(), 1);
    assert!(a.on_datagram_from(2, &reply[0], 1).is_empty());
    assert!(a.is_open(conn) && b.is_open(conn));
    assert_eq!(a.addr_of(conn), 2);
    assert_eq!(b.addr_of(conn), 1);

    // The peer roams: an authenticated packet from a new address moves it.
    let d = a.send_frame(conn, &Frame { ftype: newnet::streams::FRAME_DGRAM, id: 0, off: 0, cum: 0, sacks: vec![], data: vec![7] }).unwrap();
    b.on_datagram_from(9, &d, 2);
    assert_eq!(b.addr_of(conn), 9);

    // A packet that fails authentication never moves it.
    b.on_datagram_from(66, &newnet::attacks::spoof_data(conn, 5, &[1u8; 32], b"nope"), 2);
    assert_eq!(b.addr_of(conn), 9);
}

#[test]
fn hub_send_to_reaches_one_node_and_names_the_sender() {
    let mut hub = Hub::new(3, 0, 0, 1);
    hub.send_to(0, 2, b"x");
    assert_eq!(hub.drain_from(2), vec![(0, b"x".to_vec())]);
    assert!(hub.drain(1).is_empty());
}
