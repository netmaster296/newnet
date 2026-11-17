// Hostile-sender hardening: one poll drains at most MAX_RECV_PER_POLL
// datagrams, and a full peer table evicts an address no live handshake or
// session depends on, never one it does.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use newnet::crypto::PeerRecord;
use newnet::node::Node;
use newnet::udp::{UdpEndpoint, MAX_RECV_PER_POLL};

fn pair_with_b_capacity(max_peers: usize) -> (UdpEndpoint, UdpEndpoint) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: a.ident.ed_pub(), x: a.ident.x_pub, expiry: u64::MAX };
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

    for i in 0..3u8 {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(&[b'y', i, 0x33, i << 2, 9], eb.local_addr()).unwrap();
    }
    for _ in 0..5 {
        ea.poll().unwrap();
        eb.poll().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }

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
