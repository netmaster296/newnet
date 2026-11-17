// Identity path: both sides of the handshake check record expiry and the
// pin store. Expired records are refused before any state is allocated;
// first contact pins, a later different key fails closed.

use newnet::crypto::PeerRecord;
use newnet::identity::IdentityError;
use newnet::node::{ConnectError, Node};

fn pair() -> (Node, Node) {
    let mut a = Node::new("alice", 0xA11CE);
    let mut b = Node::new("bob", 0xB0B);
    let rec_b = PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, expiry: u64::MAX };
    let rec_a = PeerRecord { name: "alice".into(), ed: a.ident.ed_pub(), x: a.ident.x_pub, expiry: u64::MAX };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    (a, b)
}

#[test]
fn expired_record_is_refused_by_the_initiator() {
    let (mut a, _b) = pair();
    a.records.get_mut("bob").unwrap().expiry = 5;
    assert!(a.connect_at("bob", None, 5).is_ok());
    let (mut a, _b) = pair();
    a.records.get_mut("bob").unwrap().expiry = 5;
    assert_eq!(a.connect_at("bob", None, 10), Err(ConnectError::Pin(IdentityError::CertExpired)));
    assert_eq!(a.pending_count(), 0);
}

#[test]
fn expired_record_is_refused_by_the_responder() {
    let (mut a, mut b) = pair();
    b.records.get_mut("alice").unwrap().expiry = 5;
    let (_, hs1) = a.connect_at("bob", None, 0).unwrap();
    let out = b.on_datagram(&hs1, 10);
    assert!(out.is_empty());
    assert_eq!(b.half_open_count(), 0);
    assert_eq!(b.stats.auth_fails, 1);
}

#[test]
fn responder_pins_on_first_handshake_and_refuses_a_changed_key() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([1u8; 32])).unwrap();
    let hs2 = b.on_datagram(&hs1, 1);
    assert_eq!(hs2.len(), 1);
    let confirm = a.on_datagram(&hs2[0], 1);
    assert_eq!(confirm.len(), 1);
    assert!(b.on_datagram(&confirm[0], 1).is_empty());
    assert!(a.is_open(conn) && b.is_open(conn));
    assert_eq!(b.pins.get("alice").unwrap().x25519, a.ident.x_pub.to_bytes());

    let mut a2 = Node::new("alice", 0xBAD);
    a2.records.insert(
        "bob".into(),
        PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, expiry: u64::MAX },
    );
    b.records.insert(
        "alice".into(),
        PeerRecord { name: "alice".into(), ed: a2.ident.ed_pub(), x: a2.ident.x_pub, expiry: u64::MAX },
    );
    let (_, hs1_2) = a2.connect("bob", None).unwrap();
    let before = b.stats.auth_fails;
    let out = b.on_datagram(&hs1_2, 2);
    assert!(out.is_empty());
    assert_eq!(b.half_open_count(), 0);
    assert_eq!(b.stats.auth_fails, before + 1);
    assert_eq!(b.pins.get("alice").unwrap().x25519, a.ident.x_pub.to_bytes());
}

#[test]
fn initiator_pins_the_responder_on_first_connect() {
    let (mut a, _b) = pair();
    assert!(a.connect("bob", None).is_ok());
    assert!(a.pins.get("bob").is_some());
    let bad = Node::new("bob", 0xBAD);
    a.records.insert(
        "bob".into(),
        PeerRecord { name: "bob".into(), ed: bad.ident.ed_pub(), x: bad.ident.x_pub, expiry: u64::MAX },
    );
    assert_eq!(a.connect("bob", None), Err(ConnectError::Pin(IdentityError::PinMismatch)));
}
