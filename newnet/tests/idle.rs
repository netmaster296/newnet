// Idle timeout: a session whose peer fell silent is dropped after IDLE_TTL
// ticks of hearing nothing, a side asks the peer to speak after
// KEEPALIVE_AFTER silent ticks, and any authenticated traffic from the peer
// resets the idle clock.

use newnet::crypto::PeerRecord;
use newnet::node::Node;
use newnet::session::{IDLE_TTL, KEEPALIVE_AFTER};
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
fn a_session_with_a_silent_peer_is_dropped() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 1);
    let mut sent = 0usize;
    for t in 2..=(IDLE_TTL + 5) {
        sent += b.tick_sessions(t, 3).len();
    }
    assert!(!b.is_open(conn), "the silent peer's session must not be kept for ever");
    assert_eq!(b.stats.sessions_idle_dropped, 1);
    assert!(sent >= 1 && sent <= (IDLE_TTL / KEEPALIVE_AFTER) as usize, "b sent {sent} keepalive datagrams");
}

#[test]
fn keepalives_hold_an_idle_session_open() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 2);
    for t in 2..=(3 * IDLE_TTL) {
        for (_, d) in a.tick_sessions(t, 3) {
            for r in b.on_datagram(&d, t) {
                a.on_datagram(&r, t);
            }
        }
        for (_, d) in b.tick_sessions(t, 3) {
            for r in a.on_datagram(&d, t) {
                b.on_datagram(&r, t);
            }
        }
    }
    assert!(a.is_open(conn) && b.is_open(conn), "keepalive answers hold the session open");
    assert_eq!(a.stats.sessions_idle_dropped, 0);
    assert_eq!(b.stats.sessions_idle_dropped, 0);
}

#[test]
fn traffic_resets_the_idle_clock() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 3);
    let t = IDLE_TTL - 10;
    let d = a
        .send_frame(conn, &Frame { ftype: newnet::streams::FRAME_DGRAM, id: 0, off: 0, cum: 0, sacks: vec![], data: vec![7] })
        .unwrap();
    b.on_datagram(&d, t);
    b.tick_sessions(IDLE_TTL + 5, 3);
    assert!(b.is_open(conn), "recent traffic must postpone the idle drop");
    b.tick_sessions(2 * IDLE_TTL, 3);
    assert!(!b.is_open(conn));
    assert_eq!(b.stats.sessions_idle_dropped, 1);
}
