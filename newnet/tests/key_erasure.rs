// Key erasure: old traffic keys are zeroed and dropped as the replay window
// moves, so reading process memory later does not hand over generation 0.
// A packet whose key is already erased is refused as too old, before AEAD.

use newnet::crypto::PeerRecord;
use newnet::link::ADDR_ANY;
use newnet::node::Node;

mod common;
use common::complete_cookie_round;
use newnet::streams::Frame;

fn pair() -> (Node, Node) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: a.ident.ed_pub(), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    (a, b)
}

// Full open through the nodes, cookie round included: HS1, COOKIE, HS1, HS2, PING, reply.
fn open(a: &mut Node, b: &mut Node, eph: u8) -> u64 {
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
    conn
}

fn dgram(a: &mut Node, conn: u64, n: u8) -> Vec<u8> {
    a.send_frame(conn, &Frame { ftype: newnet::streams::FRAME_DGRAM, id: 0, off: 0, cum: 0, sacks: vec![], data: vec![n] }).unwrap()
}

#[test]
fn old_receive_keys_are_erased_as_the_window_moves() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 1);
    for n in 0..5000u32 {
        let p = dgram(&mut a, conn, (n % 251) as u8 + 1);
        b.on_datagram(&p, 2);
    }
    assert!(b.sessions[&conn].rx_generations() <= 4, "the receiver still holds keys older than its window");
    assert_eq!(a.sessions[&conn].tx_generations(), 1, "the sender must hold only the current generation");
}

#[test]
fn a_packet_whose_key_was_erased_is_refused() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 2);
    let pkts: Vec<Vec<u8>> = (0..5000u32).map(|n| dgram(&mut a, conn, (n % 251) as u8 + 1)).collect();
    for p in &pkts[1..] {
        b.on_datagram(p, 2);
    }
    let replay_before = b.stats.data_replay;
    let dgrams_before = b.sessions[&conn].dgram_in.len();
    b.on_datagram(&pkts[0], 2);
    assert_eq!(b.stats.data_replay, replay_before + 1);
    assert_eq!(b.sessions[&conn].dgram_in.len(), dgrams_before, "a refused packet must not be delivered");
}

#[test]
fn a_forged_old_sequence_number_reaches_no_key() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 3);
    for n in 0..5000u32 {
        let p = dgram(&mut a, conn, (n % 251) as u8 + 1);
        b.on_datagram(&p, 2);
    }
    let badtag_before = b.stats.data_badtag;
    let replay_before = b.stats.data_replay;
    let gens_before = b.sessions[&conn].rx_generations();
    b.on_datagram(&newnet::attacks::spoof_data(conn, 5, &[1u8; 32], b"x"), 2);
    assert_eq!(b.stats.data_badtag, badtag_before, "an erased key must not be touched by AEAD");
    assert_eq!(b.stats.data_replay, replay_before + 1);
    assert_eq!(b.sessions[&conn].rx_generations(), gens_before, "a forged old seq must derive no key");
}

#[test]
fn recent_packets_still_open_after_erasure() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 4);
    for n in 0..5000u32 {
        let p = dgram(&mut a, conn, (n % 251) as u8 + 1);
        b.on_datagram(&p, 2);
    }
    let ok_before = b.stats.data_ok;
    let next = dgram(&mut a, conn, 200);
    b.on_datagram(&next, 2);
    assert_eq!(b.stats.data_ok, ok_before + 1, "a current packet must still open after erasure");
}
