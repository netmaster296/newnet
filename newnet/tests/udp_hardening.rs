// Hostile-sender hardening: one poll drains at most MAX_RECV_PER_POLL
// datagrams, and a full peer table evicts an address no live handshake or
// session depends on, never one it does.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use newnet::crypto::PeerRecord;
use newnet::node::Node;
use newnet::session::MAX_IN_FLIGHT;
use newnet::streams::{Frame, FRAME_STREAM};
use newnet::udp::{UdpEndpoint, BURST, MAX_RECV_PER_POLL};

mod common;
use common::complete_cookie_round;

fn pair_with_b_capacity(max_peers: usize) -> (UdpEndpoint, UdpEndpoint) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: Some(b.ident.ed_pub()), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    let ea = UdpEndpoint::bind(a, "127.0.0.1:0").unwrap();
    let eb = UdpEndpoint::bind_with_capacity(b, "127.0.0.1:0", max_peers).unwrap();
    (ea, eb)
}

// Drive both endpoints until the condition holds. Sleep 1 ms only when a
// round moved nothing at all: a Windows sleep can last 15 ms, and sleeping
// every round would let the retransmit timer outrun the data.
fn pump(a: &mut UdpEndpoint, b: &mut UdpEndpoint, until: impl Fn(&UdpEndpoint, &UdpEndpoint) -> bool, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let ra = a.poll().unwrap();
        let rb = b.poll().unwrap();
        if until(a, b) {
            return;
        }
        assert!(Instant::now() < deadline, "pump: condition not met within {secs} s");
        if ra == 0 && rb == 0 && a.queued() == 0 && b.queued() == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn one_poll_receives_a_bounded_number_of_datagrams() {
    let (mut _a, mut b) = pair_with_b_capacity(4096);
    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..400u32 {
        let dgram = [b'f', (i % 251) as u8, (i / 251) as u8, (i % 97) as u8, 0x21];
        raw.send_to(&dgram, b.local_addr()).unwrap();
    }
    std::thread::sleep(Duration::from_millis(20));

    let first = b.poll().unwrap();
    assert_eq!(first, MAX_RECV_PER_POLL, "first poll did not stop at the cap");

    let mut total = first;
    for _ in 0..10 {
        let r = b.poll().unwrap();
        total += r;
        if r == 0 {
            break;
        }
    }
    assert!(total > MAX_RECV_PER_POLL, "only {total} datagrams arrived in total");
    assert!(total <= 400, "received {total}, more than the 400 sent");
}

#[test]
fn a_full_peer_table_still_admits_a_real_peer() {
    let (mut ea, mut eb) = pair_with_b_capacity(4);

    let mut junk = Vec::new();
    for i in 0..4u8 {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(&[b'x', i, i ^ 0x5A, 0x07, i], eb.local_addr()).unwrap();
        junk.push(s);
    }
    let start = Instant::now();
    while eb.peer_count() < 4 {
        let r = eb.poll().unwrap();
        assert!(start.elapsed() < Duration::from_secs(10), "peer table only reached {} entries", eb.peer_count());
        if r == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(eb.peer_count(), 4);

    let conn = ea.connect("bob", eb.local_addr()).unwrap();
    pump(&mut ea, &mut eb, |a, b| a.node.is_open(conn) && b.node.is_open(conn), 10);
    assert_eq!(eb.peer_count(), 4);
}

#[test]
fn addresses_in_use_are_never_evicted() {
    let (mut ea, mut eb) = pair_with_b_capacity(1);
    let conn = ea.connect("bob", eb.local_addr()).unwrap();
    pump(&mut ea, &mut eb, |a, b| a.node.is_open(conn) && b.node.is_open(conn), 10);

    let alice_addr = ea.local_addr();
    let slot = eb.node.addr_of(conn);
    assert_eq!(eb.peer_socket(slot), Some(alice_addr));

    // Three other sources send junk while alice stays silent. Alice is NOT polled here.
    let junk: Vec<UdpSocket> = (0..3)
        .map(|_| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.set_nonblocking(true).unwrap();
            s
        })
        .collect();
    for s in &junk {
        s.send_to(b"junk junk junk", eb.local_addr()).unwrap();
    }
    for _ in 0..50 {
        eb.poll().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }

    // One slot, and it belongs to a live session: it must not have moved.
    assert_eq!(eb.peer_count(), 1);
    assert_eq!(eb.peer_socket(slot), Some(alice_addr), "the session's address was given away");
    assert_eq!(eb.node.addr_of(conn), slot);
    let mut scratch = [0u8; 64];
    for s in &junk {
        assert!(s.recv_from(&mut scratch).is_err(), "b answered a junk source");
    }

    // And the session still carries data: alice sends 100,000 bytes on
    // stream 1, b receives them byte-exact within 20 s.
    let data: Vec<u8> = (0..100_000u64).map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8).collect();
    ea.send_bytes(conn, 1, &data);

    let start = Instant::now();
    let mut got: Vec<u8> = Vec::new();
    while got.len() < data.len() {
        let ra = ea.poll().unwrap();
        let rb = eb.poll().unwrap();
        got.extend(eb.node.take_stream_bytes(conn, 1));
        assert!(start.elapsed() < Duration::from_secs(20), "only {} of 100000 bytes crossed in 20 s", got.len());
        if ra == 0 && rb == 0 && ea.queued() == 0 && eb.queued() == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(got, data);
}

// One poll: receive at most the cap, run the timers, then send. A junk flood
// at the cap must not starve the send step: the queued file datagrams still
// move in the same poll.
#[test]
fn a_flood_does_not_stop_the_send_step() {
    let (mut a, mut b) = pair_with_b_capacity(4096);
    let conn = a.connect("bob", b.local_addr()).unwrap();
    pump(&mut a, &mut b, |a, b| a.node.is_open(conn) && b.node.is_open(conn), 10);

    let conn_b = b.node.session_with("alice").expect("b holds a session with alice");

    let data: Vec<u8> = (0..200_000u64).map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8).collect();
    b.send_bytes(conn_b, 1, &data);
    let q0 = b.queued();
    assert!(q0 > 0, "sending 200000 bytes must leave datagrams queued");

    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..400u32 {
        let dgram = [b'f', (i % 251) as u8, (i / 251) as u8, (i % 97) as u8, 0x21];
        raw.send_to(&dgram, b.local_addr()).unwrap();
    }
    std::thread::sleep(Duration::from_millis(20));

    let got = b.poll().unwrap();
    assert_eq!(got, MAX_RECV_PER_POLL, "one poll did not stop at the cap");
    assert!(
        b.queued() < q0,
        "the send step did not run while the flood still waited: queued {} was not under q0 {}",
        b.queued(),
        q0
    );
}

#[test]
fn sends_are_paced_by_time_not_by_poll_calls() {
    let (mut a, mut b) = pair_with_b_capacity(4096);
    let conn = a.connect("bob", b.local_addr()).unwrap();
    pump(&mut a, &mut b, |a, b| a.node.is_open(conn) && b.node.is_open(conn), 10);

    let data: Vec<u8> = (0..5_000_000u64).map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8).collect();
    a.send_bytes(conn, 1, &data);

    // A fixed 200 ms window of tight poll rounds on a only. b is left
    // unpolled: no ACKs come back, nothing is retransmitted (the
    // retransmit timeout is 500 ticks), and the outgoing queue is pure
    // supply. send_bytes has just released MAX_IN_FLIGHT datagrams into
    // that queue, so every datagram that leaves a shows up as a queue
    // drop. Epoch pacing releases at most BURST per 20-tick epoch, so at
    // most (window/20 + 2) bursts can leave in the window; a per-tick cap
    // dumps the whole MAX_IN_FLIGHT supply in the first rounds, far above
    // the bound's two-epoch slop.
    let supply = a.queued();
    assert_eq!(supply, MAX_IN_FLIGHT, "send_bytes must release exactly MAX_IN_FLIGHT datagrams into the outgoing queue");
    let t0 = a.now();
    while a.now() < t0 + 200 {
        a.poll().unwrap();
    }
    let window = a.now() - t0;
    let sent = supply - a.queued();
    assert!(
        sent > 2 * BURST,
        "only {sent} datagrams left a in {window} ms: the check has no signal"
    );
    assert!(
        sent <= ((window / 20) as usize + 2) * BURST,
        "a sent {sent} datagrams over {window} ticks: more than BURST per 20-tick pacing epoch",
    );
}

// Two in-memory nodes, opened the way the outage tests do, for checks that
// need no sockets at all.
fn mem_pair() -> (Node, Node) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: Some(b.ident.ed_pub()), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    (a, b)
}

fn open_mem(a: &mut Node, b: &mut Node, eph: u8) -> u64 {
    let (conn, hs1) = a.connect("bob", Some([eph; 32])).unwrap();
    let hs1 = complete_cookie_round(a, b, hs1, newnet::link::ADDR_ANY);
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
fn a_far_ahead_stream_offset_is_refused() {
    let (mut a, mut b) = mem_pair();
    let conn = open_mem(&mut a, &mut b, 7);
    let frame = Frame { ftype: FRAME_STREAM, id: 1, off: 1 << 40, cum: 0, sacks: vec![], data: vec![9] };
    let dgram = a.send_frame(conn, &frame).expect("an open session seals the frame");
    let replies = b.on_datagram(&dgram, 2);
    assert!(replies.is_empty(), "a refused frame must come back with no datagram");
    let s = &b.sessions[&conn];
    assert_eq!(s.stat_overlimit, 1, "the refusal must be counted");
    assert_eq!(s.rx_buffered(), 0, "a refused frame must buffer nothing");
    assert!(!s.rx_streams.contains_key(&1), "a refused frame must create no state");
}

// One datagram the OS refuses to send must cost one send_errors and nothing
// else: poll still returns Ok and the endpoint goes on.
#[test]
fn an_unsendable_destination_does_not_break_poll() {
    let (mut a, _b) = pair_with_b_capacity(4096);
    a.connect("bob", "255.255.255.255:9".parse().unwrap()).unwrap();
    for _ in 0..10 {
        assert!(a.poll().is_ok(), "poll must survive an unsendable destination");
        std::thread::sleep(Duration::from_millis(10));
    }
    if a.send_errors == 0 {
        eprintln!("this platform allowed the send to 255.255.255.255:9, so nothing to count");
    } else {
        assert!(a.send_errors >= 1, "a refused send must be counted");
        assert_eq!(a.queued(), 0, "the refused datagram must be dropped, not kept");
    }
}

// A full outgoing queue drops datagrams and counts them; the stream timers
// retransmit, so the whole transfer still crosses.
#[test]
fn a_full_outgoing_queue_drops_and_the_transfer_still_completes() {
    let (mut a, mut b) = pair_with_b_capacity(4096);
    let conn = a.connect("bob", b.local_addr()).unwrap();
    pump(&mut a, &mut b, |a, b| a.node.is_open(conn) && b.node.is_open(conn), 10);

    a.set_max_out(10);
    let data: Vec<u8> = (0..300_000u64).map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8).collect();
    a.send_bytes(conn, 1, &data);
    assert_eq!(a.queued(), 10, "the outgoing queue must stop at max_out");
    assert!(a.dropped_out > 0, "a full queue must count its drops");

    let start = Instant::now();
    let mut got: Vec<u8> = Vec::new();
    while got.len() < data.len() {
        let ra = a.poll().unwrap();
        let rb = b.poll().unwrap();
        got.extend(b.node.take_stream_bytes(conn, 1));
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "only {} of 300000 bytes crossed in 60 s",
            got.len()
        );
        if ra == 0 && rb == 0 && a.queued() == 0 && b.queued() == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(got, data, "every byte must cross byte-exact");
}
