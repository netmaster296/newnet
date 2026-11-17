// Peer limits: a peer that completed the handshake is trusted to be who it
// says, not to be well behaved. It may not make the node buffer unbounded
// out-of-order chunks, open unbounded streams, or create sender state for
// streams the node never sent on.

use newnet::crypto::PeerRecord;
use newnet::link::ADDR_ANY;
use newnet::node::Node;
use newnet::session::{MAX_RX_BUFFERED, MAX_STREAMS};

mod common;
use common::complete_cookie_round;
use newnet::streams::{Frame, FRAME_ACK, FRAME_STREAM};

fn pair() -> (Node, Node) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: Some(b.ident.ed_pub()), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX };
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

#[test]
fn an_ack_for_a_stream_never_sent_creates_no_state() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 1);
    for id in 1000u32..1200 {
        let dgram = a.send_frame(conn, &Frame { ftype: FRAME_ACK, id, off: 0, cum: 0, sacks: vec![], data: vec![] }).unwrap();
        b.on_datagram(&dgram, 2);
    }
    assert_eq!(b.sessions[&conn].tx_streams.len(), 0);
}

#[test]
fn out_of_order_buffering_is_capped() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 2);
    let mut acks = 0usize;
    for i in 0..3000u64 {
        let dgram = a.send_frame(conn, &Frame { ftype: FRAME_STREAM, id: 1, off: 2 * (i + 1), cum: 0, sacks: vec![], data: vec![i as u8] }).unwrap();
        acks += b.on_datagram(&dgram, 2).len();
    }
    assert_eq!(b.sessions[&conn].rx_buffered(), MAX_RX_BUFFERED);
    assert_eq!(b.sessions[&conn].stat_overlimit, 3000 - MAX_RX_BUFFERED as u64);
    assert_eq!(acks, MAX_RX_BUFFERED, "an ACK only for the frames kept");
}

#[test]
fn filling_a_hole_frees_room() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 3);
    for i in 0..3000u64 {
        let dgram = a.send_frame(conn, &Frame { ftype: FRAME_STREAM, id: 1, off: 2 * (i + 1), cum: 0, sacks: vec![], data: vec![i as u8] }).unwrap();
        b.on_datagram(&dgram, 2);
    }
    assert_eq!(b.sessions[&conn].rx_buffered(), MAX_RX_BUFFERED);
    // The hole at 0..2 joins up with the chunk at offset 2 and drains.
    let dgram = a.send_frame(conn, &Frame { ftype: FRAME_STREAM, id: 1, off: 0, cum: 0, sacks: vec![], data: vec![200, 201] }).unwrap();
    b.on_datagram(&dgram, 3);
    assert!(b.sessions[&conn].rx_buffered() < MAX_RX_BUFFERED);
    assert_eq!(b.sessions[&conn].delivered[&1], vec![200, 201, 0]);
    // Room freed: a fresh high offset is accepted, no new refusal.
    let over_before = b.sessions[&conn].stat_overlimit;
    let dgram = a.send_frame(conn, &Frame { ftype: FRAME_STREAM, id: 1, off: 100_000, cum: 0, sacks: vec![], data: vec![7] }).unwrap();
    assert_eq!(b.on_datagram(&dgram, 3).len(), 1, "the freed slot must answer with an ACK");
    assert_eq!(b.sessions[&conn].stat_overlimit, over_before);
}

#[test]
fn stream_count_is_capped() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 4);
    for id in 0..(MAX_STREAMS as u32 + 10) {
        let dgram = a.send_frame(conn, &Frame { ftype: FRAME_STREAM, id, off: 0, cum: 0, sacks: vec![], data: vec![1] }).unwrap();
        b.on_datagram(&dgram, 2);
    }
    assert_eq!(b.sessions[&conn].rx_streams.len(), MAX_STREAMS);
    assert_eq!(b.sessions[&conn].stat_overlimit, 10);
    // An existing stream id keeps working.
    let dgram = a.send_frame(conn, &Frame { ftype: FRAME_STREAM, id: 0, off: 1, cum: 0, sacks: vec![], data: vec![2] }).unwrap();
    assert_eq!(b.on_datagram(&dgram, 2).len(), 1);
    assert_eq!(b.sessions[&conn].delivered[&0], vec![1, 2]);
    assert_eq!(b.sessions[&conn].stat_overlimit, 10);
}
