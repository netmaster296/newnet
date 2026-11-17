// Outage tolerance: retransmissions burn sequence numbers, so a few silent
// ticks leave the sender more than REPLAY_WINDOW ahead. An authenticated
// packet above the window now always moves it, so the session keeps working
// after the blackout. The pre-authentication guard (MAX_LOOKAHEAD) still
// caps what a forged header can cost.

use newnet::crypto::PeerRecord;
use newnet::node::Node;
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

fn dgram(a: &mut Node, conn: u64, n: u8) -> Vec<u8> {
    a.send_frame(conn, &Frame { ftype: newnet::streams::FRAME_DGRAM, id: 0, off: 0, cum: 0, sacks: vec![], data: vec![n] }).unwrap()
}

#[test]
fn a_long_outage_does_not_stall_the_session() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 1);
    // Six thousand datagrams sealed during the blackout, none delivered:
    // the sender is far past the replay window.
    for n in 0..6000u32 {
        let _p = dgram(&mut a, conn, (n % 251) as u8 + 1);
    }
    let last = dgram(&mut a, conn, 200);
    let before = b.stats.data_ok;
    b.on_datagram(&last, 2);
    assert_eq!(b.stats.data_ok, before + 1, "the first packet after the outage must be accepted");
    assert_eq!(b.sessions[&conn].dgram_in.last().unwrap(), &vec![200u8]);
}

#[test]
fn packets_from_before_a_jump_are_refused() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 2);
    let first = dgram(&mut a, conn, 1);
    for n in 1..6000u32 {
        let _p = dgram(&mut a, conn, (n % 251) as u8 + 1);
    }
    let last = dgram(&mut a, conn, 200);
    b.on_datagram(&last, 2);
    assert_eq!(b.sessions[&conn].dgram_in.last().unwrap(), &vec![200u8]);
    // The datagram sealed before the jump lands far behind the moved window.
    let replay_before = b.stats.data_replay;
    let dgrams_before = b.sessions[&conn].dgram_in.len();
    b.on_datagram(&first, 2);
    assert_eq!(b.stats.data_replay, replay_before + 1);
    assert_eq!(b.sessions[&conn].dgram_in.len(), dgrams_before, "a refused packet must not be delivered");
}

#[test]
fn a_forged_header_inside_the_lookahead_costs_a_bounded_number_of_keys() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 3);
    let before = b.sessions[&conn].rx_generations();
    b.on_datagram(&newnet::attacks::spoof_data(conn, 1_000_000, &[1u8; 32], b"x"), 2);
    assert_eq!(b.stats.data_badtag, 1, "the wrong key fails the tag");
    assert!(
        b.sessions[&conn].rx_generations() <= before + 1_001,
        "one forged header cost more than its share of key generations"
    );
    // The forged packet never reached the window: the session still works.
    let next = dgram(&mut a, conn, 7);
    let ok_before = b.stats.data_ok;
    b.on_datagram(&next, 2);
    assert_eq!(b.stats.data_ok, ok_before + 1, "the forged packet must not move the window");
    assert_eq!(b.sessions[&conn].dgram_in.last().unwrap(), &vec![7u8]);
}

#[test]
fn a_forged_header_past_the_lookahead_costs_nothing() {
    let (mut a, mut b) = pair();
    let conn = open(&mut a, &mut b, 4);
    let before = b.sessions[&conn].rx_generations();
    b.on_datagram(&newnet::attacks::spoof_data(conn, (1 << 20) + 50, &[1u8; 32], b"x"), 2);
    assert_eq!(b.sessions[&conn].rx_generations(), before, "a past-the-guard header must derive no key");
}
