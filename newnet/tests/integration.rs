// Integration: handshake opens, pins enforce, attacks stay cheap.

use newnet::crypto::PeerRecord;
use newnet::naming::{self, NameRecord};
use newnet::node::Node;

fn pair() -> (Node, Node) {
    let a = Node::new("alice", 0xA11CE);
    let b = Node::new("bob", 0xB0B);
    let (mut a, mut b) = (a, b);
    let rec_b = PeerRecord { name: "bob".into(), ed: b.ident.ed_pub(), x: b.ident.x_pub, cert: vec![] };
    let rec_a = PeerRecord { name: "alice".into(), ed: a.ident.ed_pub(), x: a.ident.x_pub, cert: vec![] };
    a.records.insert("bob".into(), rec_b);
    b.records.insert("alice".into(), rec_a);
    (a, b)
}

#[test]
fn handshake_roundtrip_opens_both_sides() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([1u8; 32])).unwrap();
    let hs2s = b.on_datagram(&hs1, 1);
    assert_eq!(hs2s.len(), 1, "responder replies with msg2");
    let outs = a.on_datagram(&hs2s[0], 1);
    assert!(outs.is_empty());
    assert!(a.is_open(conn), "initiator open: {:?}", a.logs);
    assert!(b.is_open(conn), "responder open");
    assert_eq!(a.sessions[&conn].transcript, b.sessions[&conn].transcript);

    // Data flows both directions.
    let dp = a.send_msg(conn, 0, &newnet::content::Msg::Text("hi".into()));
    let back = b.on_datagram(&dp[0], 1);
    println!("dp len {} back len {} bobstats {:?}", dp.len(), back.len(), b.stats);
    assert!(!back.is_empty(), "ack back");
    a.on_datagram(&back[0], 1);
    let got: Vec<_> = b.recv_msgs(conn, 0);
    assert_eq!(got.len(), 1);
}

#[test]
fn wrong_pinned_key_fails_handshake() {
    let (mut a, mut b) = pair();
    // Bob pinned the wrong key for alice: lookup gives a bad cert binding.
    let wrong = Node::new("ghost", 0x6057);
    b.records.insert(
        "alice".into(),
        PeerRecord { name: "alice".into(), ed: wrong.ident.ed_pub(), x: wrong.ident.x_pub, cert: vec![] },
    );
    let (_conn, hs1) = a.connect("bob", Some([2u8; 32])).unwrap();
    let hs2s = b.on_datagram(&hs1, 1);
    assert!(hs2s.is_empty(), "no session for a claim whose record does not match");
    assert_eq!(b.stats.auth_fails, 1);
    assert_eq!(b.stats.sessions_allocated, 0);
}

#[test]
fn registry_bad_signature_fails_closed() {
    let reg = naming::Registry::new();
    let anchor = naming::anchor_identity();
    let rec = NameRecord { name: "x".into(), ed: [9u8; 32], x25519: [8u8; 32], expiry: u64::MAX };
    let mut s = naming::sign_record(&anchor, &rec);
    s.bytes[5] ^= 1;
    assert_eq!(naming::verify_signed(&s, &anchor.ed_pub(), 1), Err(naming::NamingError::BadSig));
    let good = naming::sign_record(&reg.ident, &rec);
    assert!(naming::verify_signed(&good, &reg.ident.ed_pub(), 1).is_ok());
    // wrong anchor
    assert_eq!(
        naming::verify_signed(&good, &Node::new("z", 1).ident.ed_pub(), 1),
        Err(naming::NamingError::BadSig)
    );
}

#[test]
fn handshake_budget_caps_dh_per_tick() {
    let (_a, mut b) = pair();
    let mut rng = newnet::attacks::Rng::new(7);
    let d0 = b.stats.dh_count;
    for i in 0..10u64 {
        let p = newnet::attacks::garbage_handshake(&mut rng, 9000 + i);
        b.on_datagram(&p, 5);
    }
    assert!(b.stats.dh_count - d0 <= 4 * 2, "at most 4 attempts per tick (2 DH each before payload check fails)");
    assert_eq!(b.stats.sessions_allocated, 0);
}

#[test]
fn legacy_on_hub_allocates_nothing() {
    let (_a, mut b) = pair();
    b.on_datagram(&newnet::attacks::dns_blob(), 1);
    b.on_datagram(&newnet::attacks::http_blob(), 1);
    assert_eq!(b.stats.legacy_dropped, 2);
    assert_eq!(b.stats.sessions_allocated, 0);
    assert_eq!(b.stats.dh_count, 0);
}

#[test]
fn streams_are_independent_no_head_of_line_blocking() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([5u8; 32])).unwrap();
    let hs2 = b.on_datagram(&hs1, 1);
    a.on_datagram(&hs2[0], 1);
    assert!(a.is_open(conn));

    // Big blob on stream 2 with one chunk held back; text on stream 1 flows.
    let blob = vec![42u8; 5000]; // 5 chunks
    let blob_pkts = a.send_bytes(conn, 2, &blob, 0);
    for (i, p) in blob_pkts.iter().enumerate() {
        if i != 2 {
            b.on_datagram(p, 1); // chunk 2 "lost"
        }
    }
    let text_pkts = a.send_msg(conn, 1, &newnet::content::Msg::Text("still flowing".into()));
    for p in &text_pkts {
        b.on_datagram(p, 1);
    }
    let got: Vec<_> = b.recv_msgs(conn, 1);
    assert_eq!(got.len(), 1, "text stream delivered despite stream-2 hole");

    // Fill the stream-2 hole; blob reassembles independently.
    b.on_datagram(&blob_pkts[2], 1);
    let bytes = b.take_stream_bytes(conn, 2);
    assert_eq!(bytes.len(), 5000);
}

#[test]
fn no_application_frames_before_open() {
    let (mut a, mut b) = pair();
    let (conn, _hs1) = a.connect("bob", Some([6u8; 32])).unwrap();
    // Alice's session is still Handshaking: send_msg allocates nothing to send.
    let dp = a.send_msg(conn, 0, &newnet::content::Msg::Text("too early".into()));
    assert!(dp.is_empty(), "no frames out of a non-Open session");
    // A DATA packet aimed at that half-open conn: Bob has no session for it.
    let early = newnet::attacks::spoof_data(conn, 0, &[1u8; 32], b"too early");
    let outs = b.on_datagram(&early, 1);
    assert!(outs.is_empty());
    assert_eq!(b.stats.no_session_dropped, 1);
    assert_eq!(b.stats.sessions_allocated, 0);
}

#[test]
fn handshake_retransmits_in_protocol_no_app_retry() {
    let (mut a, mut b) = pair();
    let (conn, _hs1) = a.connect_at("bob", Some([7u8; 32]), 0).unwrap(); // first copy "lost"
    let mut opened = false;
    for t in 1..=10 {
        for (_, p) in a.tick_sessions(t, 2) {
            let out = b.on_datagram(&p, t);
            for o in out {
                a.on_datagram(&o, t);
            }
        }
        if a.is_open(conn) {
            opened = true;
            break;
        }
    }
    assert!(opened, "in-protocol HS1 retransmit must open the session");
    assert_eq!(b.stats.hs_retransmits, 0); // the retransmit is the first copy b ever saw
}

#[test]
fn replayed_hs1_cannot_disturb_a_live_session() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([8u8; 32])).unwrap();
    let hs2 = b.on_datagram(&hs1, 1);
    a.on_datagram(&hs2[0], 1);
    assert!(a.is_open(conn) && b.is_open(conn));
    let outs = b.on_datagram(&hs1, 2); // attacker replays the captured HS1
    assert!(outs.is_empty(), "conn already known: HS1 rejected, no reset");
    assert_eq!(b.stats.auth_fails, 1);
    assert_eq!(b.stats.sessions_allocated, 1);
    let dp = a.send_msg(conn, 1, &newnet::content::Msg::Text("still alive".into()));
    for p in &dp {
        b.on_datagram(p, 2);
    }
    assert_eq!(b.stats.data_badtag, 0);
    assert_eq!(b.recv_msgs(conn, 1).len(), 1, "original session unharmed");
}

#[test]
fn lost_hs2_escalates_to_a_new_conn_and_reaps_the_old_one() {
    let (mut a, mut b) = pair();
    let (c0, hs1) = a.connect_at("bob", Some([11u8; 32]), 0).unwrap();
    b.on_datagram(&hs1, 1); // responder's msg2 "lost": never delivered to a
    let mut opened_conn = None;
    for t in 1..=30 {
        for (_c, p) in a.tick_sessions(t, 2) {
            let out = b.on_datagram(&p, t);
            for o in out {
                a.on_datagram(&o, t);
            }
        }
        if let Some(c) = a.sessions.keys().copied().find(|c| a.is_open(*c) && *c != c0) {
            opened_conn = Some(c);
            break;
        }
    }
    assert!(opened_conn.is_some(), "escalation must open a fresh conn");
    for t in 21..=25 {
        a.tick_sessions(t, 2);
        b.tick_sessions(t, 2);
    }
    assert_eq!(b.sessions.len(), 1, "half-open responder session reaped, live one stays");
}#[test]
fn close_frees_state_on_both_sides() {
    let (mut a, mut b) = pair();
    let (conn, hs1) = a.connect("bob", Some([9u8; 32])).unwrap();
    let hs2 = b.on_datagram(&hs1, 1);
    a.on_datagram(&hs2[0], 1);
    assert!(a.is_open(conn) && b.is_open(conn));
    let c = a.close(conn).expect("close frame");
    b.on_datagram(&c, 1);
    assert!(!a.is_open(conn) && !b.is_open(conn));
    assert!(a.sessions.is_empty() && b.sessions.is_empty());
}
