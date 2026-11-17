// Two UdpEndpoints on this machine, 127.0.0.1 only, no threads: a real
// socket carries the handshake and 2 MB of stream bytes across loopback.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use newnet::crypto::PeerRecord;
use newnet::node::Node;
use newnet::udp::UdpEndpoint;

fn pair() -> (UdpEndpoint, UdpEndpoint) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: a.ident.ed_pub(), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    let ea = UdpEndpoint::bind(a, "127.0.0.1:0").unwrap();
    let eb = UdpEndpoint::bind(b, "127.0.0.1:0").unwrap();
    (ea, eb)
}

// Drive both endpoints until the condition holds. Sleep 1 ms only when a
// round moved nothing at all: a Windows sleep can last 15 ms, and sleeping
// every round would let the 500 ms retransmit timer outrun the data.
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
fn two_endpoints_open_a_session_over_udp() {
    let (mut a, mut b) = pair();
    let conn = a.connect("bob", b.local_addr()).unwrap();
    pump(&mut a, &mut b, |a, b| a.node.is_open(conn) && b.node.is_open(conn), 10);
}

#[test]
fn two_megabytes_cross_the_loopback_byte_exact() {
    let (mut a, mut b) = pair();
    let conn = a.connect("bob", b.local_addr()).unwrap();
    pump(&mut a, &mut b, |a, b| a.node.is_open(conn) && b.node.is_open(conn), 10);

    let data: Vec<u8> = (0..2_000_000u64).map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8).collect();
    a.send_bytes(conn, 1, &data);

    let start = Instant::now();
    let mut got: Vec<u8> = Vec::new();
    while got.len() < data.len() {
        let ra = a.poll().unwrap();
        let rb = b.poll().unwrap();
        got.extend(b.node.take_stream_bytes(conn, 1));
        assert!(start.elapsed() < Duration::from_secs(60), "only {} of {} bytes crossed in 60 s", got.len(), data.len());
        if ra == 0 && rb == 0 && a.queued() == 0 && b.queued() == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(got, data);
    assert_eq!(b.node.stats.data_badtag, 0);
}

#[test]
fn a_restarted_initiator_reconnects() {
    let (mut a, mut b) = pair();
    let conn = a.connect("bob", b.local_addr()).unwrap();
    pump(&mut a, &mut b, |a, b| a.node.is_open(conn) && b.node.is_open(conn), 10);
    drop(a);
    std::thread::sleep(Duration::from_millis(5));

    let mut a2 = Node::new("alice", 0xA11CE);
    a2.records.insert(
        "bob".into(),
        PeerRecord { name: "bob".into(), ed: b.node.ident.ed_pub(), x: b.node.ident.x_pub, expiry: u64::MAX },
    );
    let mut a = UdpEndpoint::bind(a2, "127.0.0.1:0").unwrap();
    let conn2 = a.connect("bob", b.local_addr()).unwrap();
    pump(&mut a, &mut b, |a, b| a.node.is_open(conn2) && b.node.is_open(conn2), 10);
}

#[test]
fn garbage_from_the_network_is_ignored() {
    let (_a, mut b) = pair();
    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    raw.send_to(b"hello", b.local_addr()).unwrap();
    raw.send_to(&[0xFFu8; 40], b.local_addr()).unwrap();
    let mut look = newnet::wire::encode(
        &newnet::wire::Header { version: newnet::wire::VERSION, ptype: newnet::wire::TYPE_HANDSHAKE1, conn_id: 0xDEAD_BEEF, seq: 0, len: 76 },
        &(0..76u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect::<Vec<u8>>(),
    );
    assert!(look.starts_with(b"NEW1"));
    assert_eq!(look.len(), 100);
    raw.send_to(&look, b.local_addr()).unwrap();

    for _ in 0..5 {
        b.poll().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(b.node.sessions.is_empty());
    assert_eq!(b.node.half_open_count(), 0);
    raw.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let mut reply = [0u8; 2048];
    let err = raw.recv(&mut reply).unwrap_err();
    assert!(
        matches!(err.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock),
        "the plain socket got a reply: {err:?}"
    );
}
