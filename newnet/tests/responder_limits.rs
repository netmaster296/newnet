// Step 5 responder limits: a stamp floor five minutes before process start,
// a per-name half-open cap, and per-name / per-node session caps.

use newnet::crypto::PeerRecord;
use newnet::link::{Addr, ADDR_ANY};
use newnet::node::{Node, BUDGET_EPOCH_TICKS, MAX_HALF_OPEN_PER_PEER, MAX_SESSIONS, MAX_SESSIONS_PER_PEER};
use newnet::wire;

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

// Full open through the nodes at `tick`, cookie round included:
// HS1, COOKIE, HS1, HS2, PING, reply.
fn open_at(a: &mut Node, b: &mut Node, eph: u8, tick: u64) -> u64 {
    let (conn, hs1) = a.connect_at("bob", Some([eph; 32]), tick).unwrap();
    let hs1 = complete_cookie_round(a, b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, tick);
    assert_eq!(hs2.len(), 1, "responder answers: {:?}", b.stats);
    let confirm = a.on_datagram(&hs2[0], tick);
    assert_eq!(confirm.len(), 1, "initiator proves its keys with one packet");
    let reply = b.on_datagram(&confirm[0], tick);
    assert_eq!(reply.len(), 1, "responder answers the confirming PING");
    assert!(a.on_datagram(&reply[0], tick).is_empty());
    assert!(a.is_open(conn) && b.is_open(conn));
    conn
}

#[test]
fn stamp_below_floor_is_refused() {
    let (mut a, mut b) = pair();
    b.set_stamp_floor(1000);

    a.set_stamp_base(998); // stamp 999: below the floor
    let (_c1, hs1) = a.connect("bob", Some([1u8; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let out = b.on_datagram(&hs1, 1);
    assert!(out.is_empty(), "a stamp at or below the floor is refused: {:?}", b.stats);
    assert_eq!(b.stats.hs_stamp_floor_dropped, 1);
    assert_eq!(b.half_open_count(), 0, "a floor refusal allocates nothing");

    a.set_stamp_base(1000); // stamp 1001: clears the floor
    let (_c2, hs1) = a.connect("bob", Some([2u8; 32])).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let out = b.on_datagram(&hs1, 2);
    assert_eq!(out.len(), 1, "a stamp above the floor is accepted: {:?}", b.stats);
    assert_eq!(wire::decode(&out[0]).unwrap().header.ptype, wire::TYPE_HANDSHAKE2);
    assert_eq!(b.stats.hs_stamp_floor_dropped, 1, "the accepted stamp is not a floor drop");
    assert_eq!(b.stats.hs_replay_dropped, 0);
}

#[test]
fn third_half_open_from_one_peer_evicts_the_oldest() {
    let (mut a, mut b) = pair();
    let froms: [Addr; 3] = [1, 2, 3];
    let mut conns = [0u64; 3];
    for i in 0..3 {
        let (c, hs1) = a.connect("bob", None).unwrap();
        let hs1 = complete_cookie_round(&mut a, &mut b, hs1, froms[i]);
        let out = b.on_datagram_from(froms[i], &hs1, (i + 1) as u64);
        assert_eq!(out.len(), 1, "the accepted HS1 answers with HANDSHAKE2: {:?}", b.stats);
        conns[i] = c;
    }
    assert_eq!(b.half_open_count(), MAX_HALF_OPEN_PER_PEER, "one name holds at most two half-open entries");
    assert_eq!(b.stats.half_open_evicted, 1);
    assert_eq!(b.addr_of(conns[0]), ADDR_ANY, "the oldest of the two was evicted");
    assert_eq!(b.addr_of(conns[1]), froms[1], "the newest two are present");
    assert_eq!(b.addr_of(conns[2]), froms[2], "the newest two are present");
    assert_eq!(b.stats.half_open_dropped_full, 0);
}

#[test]
fn fifth_session_from_one_peer_closes_its_oldest() {
    let (mut a, mut b) = pair();
    let mut cs = [0u64; 5];
    for i in 0..5u64 {
        cs[i as usize] = open_at(&mut a, &mut b, (i + 1) as u8, i * BUDGET_EPOCH_TICKS);
    }
    assert_eq!(b.sessions.len(), MAX_SESSIONS_PER_PEER, "a name never keeps more than four sessions");
    assert_eq!(b.stats.sessions_evicted_peer, 1);
    assert_eq!(b.stats.sessions_refused_full, 0);
    assert!(!b.is_open(cs[0]), "the peer's least recently heard session closed");
    for c in &cs[1..] {
        assert!(b.is_open(*c), "the newest four stay open");
    }
    assert_eq!(a.sessions.len(), MAX_SESSIONS_PER_PEER, "the same cap applies where the initiator opens");
    assert!(!a.is_open(cs[0]));
}

#[test]
fn sixty_fifth_session_is_refused() {
    // 16 peer names by 4 sessions each = 64; the 65th is refused outright.
    let (_a0, mut b) = pair();
    let mut a = Node::new("peer0", 0xA11CE);
    a.records.insert("bob".into(), PeerRecord { name: "bob".into(), ed: Some(b.ident.ed_pub()), x: b.ident.x_pub, expiry: u64::MAX });
    let mut n = 0u64;
    for i in 0..16u64 {
        let name = format!("peer{i}");
        a.name = name.clone();
        b.records.insert(name.clone(), PeerRecord { name: name.clone(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX });
        for j in 0..4u64 {
            // four opens per 20-tick budget epoch: the per-source handshake
            // budget is not the limit here.
            open_at(&mut a, &mut b, n as u8, i * BUDGET_EPOCH_TICKS + j);
            n += 1;
        }
    }
    assert_eq!(n, MAX_SESSIONS as u64);
    assert_eq!(b.sessions.len(), MAX_SESSIONS);
    assert_eq!(b.stats.sessions_refused_full, 0, "filling the table evicts nothing: no name is over four");
    assert_eq!(b.stats.sessions_evicted_peer, 0);

    a.name = "peer16".into();
    b.records.insert("peer16".into(), PeerRecord { name: "peer16".into(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX });
    let (c65, hs1) = a.connect_at("bob", None, 16 * BUDGET_EPOCH_TICKS).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY);
    let hs2 = b.on_datagram(&hs1, 16 * BUDGET_EPOCH_TICKS);
    assert_eq!(hs2.len(), 1, "the cap bites at the confirming DATA, not at message 2: {:?}", b.stats);
    let confirm = a.on_datagram(&hs2[0], 16 * BUDGET_EPOCH_TICKS);
    assert_eq!(confirm.len(), 1, "the initiator side opens its session: {:?}", a.stats);
    let reply = b.on_datagram(&confirm[0], 16 * BUDGET_EPOCH_TICKS);
    assert!(reply.is_empty(), "the 65th session is refused");
    assert_eq!(b.stats.sessions_refused_full, 1);
    assert_eq!(b.sessions.len(), MAX_SESSIONS, "a refusal changes nothing");
    assert!(!b.is_open(c65));
}

#[test]
fn restart_with_clock_stamp_passes_and_old_recording_fails() {
    let (mut a, mut b) = pair();
    // Wall clock "now" in the same units a real endpoint uses.
    let now = 1_700_000_000_000u64;
    a.set_stamp_base(now - 600_000); // alice's clock ran 10 minutes slow
    let (conn, hs1) = a.connect_at("bob", Some([1u8; 32]), 1).unwrap();
    let hs1_rec = complete_cookie_round(&mut a, &mut b, hs1, ADDR_ANY); // the recording: stamp now-600_000
    let hs2 = b.on_datagram(&hs1_rec, 1);
    assert_eq!(hs2.len(), 1);
    let confirm = a.on_datagram(&hs2[0], 1);
    assert_eq!(b.on_datagram(&confirm[0], 1).len(), 1);
    assert!(b.is_open(conn));

    // Bob restarts: new process, stamp floor five minutes before start.
    let mut b2 = Node::new("bob", 0xB0B);
    b2.records.insert("alice".into(), PeerRecord { name: "alice".into(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX });
    b2.set_stamp_base(now);
    b2.set_stamp_floor(now - 300_000);

    // A fresh alice at the clock stamp passes.
    let mut a2 = Node::new("alice", 0xA11CE);
    a2.records.insert("bob".into(), PeerRecord { name: "bob".into(), ed: Some(b2.ident.ed_pub()), x: b2.ident.x_pub, expiry: u64::MAX });
    a2.set_stamp_base(now);
    let (_cfresh, hs1) = a2.connect("bob", None).unwrap();
    let hs1 = complete_cookie_round(&mut a2, &mut b2, hs1, ADDR_ANY);
    let out = b2.on_datagram(&hs1, 2);
    assert_eq!(out.len(), 1, "the clock-based stamp clears the floor: {:?}", b2.stats);
    assert_eq!(b2.half_open_count(), 1);

    // The recording from ten minutes earlier fails against the fresh node:
    // empty stamp table, so only the floor stands between it and state.
    // Its old cookie is stale; fetch a fresh one for the same conn first.
    let ck = b2.on_datagram(&hs1_rec, 3);
    assert_eq!(ck.len(), 1, "the recorded conn is answered with one COOKIE");
    assert_eq!(wire::decode(&ck[0]).unwrap().header.ptype, wire::TYPE_COOKIE);
    let filled = common::fill_cookie(&hs1_rec, &wire::decode(&ck[0]).unwrap().body);
    let out = b2.on_datagram(&filled, 4);
    assert!(out.is_empty(), "a stamp from before the floor is refused after a restart: {:?}", b2.stats);
    assert_eq!(b2.stats.hs_stamp_floor_dropped, 1);
    assert_eq!(b2.half_open_count(), 1, "the refusal allocates nothing");
    assert!(b2.sessions.is_empty());
}

// Amendment A6(b): a node at MAX_SESSIONS that receives a valid
// HANDSHAKE2 for a pending attempt drops the packet and KEEPS the
// attempt: room is checked before the attempt is consumed.
#[test]
fn a_full_initiator_keeps_its_pending_attempt() {
    let mut a = Node::new("alice", 0xA11CE);
    let mut rs: Vec<Node> = (0..17).map(|i| Node::new(&format!("r{i}"), 0xB0B + i as u64)).collect();
    for r in rs.iter_mut() {
        r.records.insert(
            "alice".into(),
            PeerRecord { name: "alice".into(), ed: Some(a.ident.ed_pub()), x: a.ident.x_pub, expiry: u64::MAX },
        );
        a.records.insert(
            r.name.clone(),
            PeerRecord { name: r.name.clone(), ed: Some(r.ident.ed_pub()), x: r.ident.x_pub, expiry: u64::MAX },
        );
    }
    // Fill `a` with MAX_SESSIONS sessions: four each with r1..r16. r0
    // holds none, so its attempt meets the node-wide cap, not the per-peer one.
    let mut n = 0u64;
    for i in 1..=16usize {
        for j in 0..4u64 {
            let tick = i as u64 * BUDGET_EPOCH_TICKS + j;
            let (conn, hs1) = a.connect_at(&rs[i].name, None, tick).unwrap();
            let hs1 = complete_cookie_round(&mut a, &mut rs[i], hs1, ADDR_ANY);
            let hs2 = rs[i].on_datagram(&hs1, tick);
            assert_eq!(hs2.len(), 1, "the responder answers: {:?}", rs[i].stats);
            let confirm = a.on_datagram(&hs2[0], tick);
            assert_eq!(confirm.len(), 1, "the initiator proves its keys: {:?}", a.stats);
            let reply = rs[i].on_datagram(&confirm[0], tick);
            assert_eq!(reply.len(), 1, "the responder answers the confirming PING");
            assert!(a.on_datagram(&reply[0], tick).is_empty());
            assert!(a.is_open(conn), "session {n} is open on the initiator");
            n += 1;
        }
    }
    assert_eq!(n, MAX_SESSIONS as u64);
    assert_eq!(a.sessions.len(), MAX_SESSIONS, "the initiator itself is full");
    assert_eq!(a.stats.sessions_refused_full, 0, "filling to exactly the cap refuses nothing");

    // A fresh attempt to r0 completes its round and gets a valid
    // HANDSHAKE2, but there is no room on `a`.
    let tick = 17 * BUDGET_EPOCH_TICKS;
    let (c65, hs1) = a.connect_at("r0", None, tick).unwrap();
    let hs1 = complete_cookie_round(&mut a, &mut rs[0], hs1, ADDR_ANY);
    let hs2 = rs[0].on_datagram(&hs1, tick);
    assert_eq!(hs2.len(), 1, "the responder has room and answers: {:?}", rs[0].stats);
    let before = a.pending_count();
    let outs = a.on_datagram(&hs2[0], tick);
    assert!(outs.is_empty(), "the full initiator sends nothing back");
    assert_eq!(a.pending_count(), before, "the pending attempt is not consumed");
    assert_eq!(a.stats.sessions_refused_full, 1, "the refusal is counted once");
    assert_eq!(a.sessions.len(), MAX_SESSIONS, "the refusal changes no session state");
    assert!(!a.is_open(c65));
}
