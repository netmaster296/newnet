// The in-flight cap: a large send releases only MAX_IN_FLIGHT chunks, ACKs
// release the rest, and reordering inside the cap never trips the replay window.

use newnet::crypto::PeerRecord;
use newnet::link::{Hub, ADDR_ANY};
use newnet::node::Node;
use newnet::session::MAX_IN_FLIGHT;

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

fn chunk_pattern(n: usize) -> Vec<u8> {
    (0..n * newnet::streams::CHUNK).map(|i| (i % 251) as u8).collect()
}

#[test]
fn a_large_send_releases_only_the_cap() {
    let (mut a, mut b) = pair();
    let (conn, _) = open(&mut a, &mut b, 1);
    let out = a.send_bytes(conn, 1, &chunk_pattern(3000), 0);
    assert_eq!(out.len(), MAX_IN_FLIGHT);
    assert_eq!(a.sessions[&conn].in_flight_total(), MAX_IN_FLIGHT);
    assert_eq!(a.sessions[&conn].queued_chunks(), 3000 - MAX_IN_FLIGHT);
}

#[test]
fn acks_release_the_rest_and_every_byte_arrives() {
    let (mut a, mut b) = pair();
    let (conn, _) = open(&mut a, &mut b, 2);
    let want = chunk_pattern(3000);
    let mut batch = a.send_bytes(conn, 1, &want, 0);
    let mut t = 1u64;
    while !batch.is_empty() {
        let mut from_b = Vec::new();
        for p in &batch {
            from_b.extend(b.on_datagram(p, t));
        }
        let mut next = Vec::new();
        for r in &from_b {
            next.extend(a.on_datagram(r, t));
        }
        assert!(a.sessions[&conn].in_flight_total() <= MAX_IN_FLIGHT);
        batch = next;
        t += 1;
    }
    assert_eq!(a.sessions[&conn].queued_chunks(), 0);
    assert_eq!(b.take_stream_bytes(conn, 1), want);
}

#[test]
fn a_small_send_is_unchanged() {
    let (mut a, mut b) = pair();
    let (conn, _) = open(&mut a, &mut b, 3);
    let out = a.send_bytes(conn, 1, &chunk_pattern(5), 0);
    assert_eq!(out.len(), 5);
}

#[test]
fn reordering_inside_the_cap_never_trips_the_replay_window() {
    let (mut a, mut b) = pair();
    let mut hub = Hub::new(2, 0, 5, 7);
    let (conn, hs1) = a.connect_at("bob", Some([4u8; 32]), 0).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    for o in b.on_datagram(&hs1, 0) {
        for c in a.on_datagram(&o, 0) {
            b.on_datagram(&c, 0);
        }
    }
    assert!(a.is_open(conn) && b.is_open(conn));

    let want = chunk_pattern(3000);
    let first = a.send_bytes(conn, 1, &want, 0);
    assert_eq!(first.len(), MAX_IN_FLIGHT);
    for p in &first {
        hub.send(0, p);
    }

    let mut rounds = 0usize;
    loop {
        hub.step();
        for i in 0..2 {
            let pkts = hub.drain(i);
            for p in &pkts {
                let outs = if i == 0 { a.on_datagram(p, hub.tick) } else { b.on_datagram(p, hub.tick) };
                for o in outs {
                    hub.send(i, &o);
                }
            }
        }
        for (_, o) in a.tick_sessions(hub.tick, 3) {
            hub.send(0, &o);
        }
        rounds += 1;
        if b.sessions[&conn].delivered.get(&1).map(|v| v.len()).unwrap_or(0) >= want.len() {
            break;
        }
        assert!(rounds < 5_000, "5,000 rounds reached: delivered={} alice in_flight={} queued={}",
            b.sessions[&conn].delivered.get(&1).map(|v| v.len()).unwrap_or(0),
            a.sessions[&conn].in_flight_total(),
            a.sessions[&conn].queued_chunks());
    }
    assert_eq!(b.take_stream_bytes(conn, 1), want);
    assert_eq!(a.stats.data_replay, 0);
    assert_eq!(b.stats.data_replay, 0);
}
