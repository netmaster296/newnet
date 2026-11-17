// The traffic show: Alice, Bob, Registry on a hub. Eve taps. Mallory attacks.
// Deterministic: seeded hub, seeded ephemerals, single-threaded pump.

use newnet::attacks::{self, Rng};
use newnet::content::{self, Msg};
use newnet::crypto;
use newnet::legacy::{self, ByteAdapter, DatagramAdapter};
use newnet::link::Hub;
use newnet::naming::{self, Registry};
use newnet::node::{self, Node};

const NOW: u64 = 1;
const ALICE: usize = 0;
const BOB: usize = 1;
const REG: usize = 2;
const MALLORY: usize = 3;

fn seed32(tag: u8) -> [u8; 32] {
    let mut b = [tag; 32];
    for i in 0..32 {
        b[i] = b[i].wrapping_mul(31).wrapping_add(i as u8);
    }
    b
}

// Deliver everything queued until the network is quiet or rounds run out.
// Handshakes that lose their packet to simulated loss are retried app-side.
fn open_to(hub: &mut Hub, nodes: &mut [Node], i: usize, name: &str, tries: usize) -> u64 {
    for t in 0..tries {
        let (conn, pkt) = nodes[i].connect(name, Some(seed32(0x90 + i as u8 * 8 + t as u8))).unwrap();
        hub.send(i, &pkt);
        pump(hub, nodes, 10);
        if nodes[i].is_open(conn) {
            return conn;
        }
        // clean the pending attempt before retrying
        nodes[i].connect_cleanup(conn);
    }
    panic!("could not open session to {name}");
}

fn pump(hub: &mut Hub, nodes: &mut [Node], max_rounds: usize) -> usize {
    let mut rounds = 0;
    for _ in 0..max_rounds {
        hub.step();
        let mut any = false;
        for i in 0..nodes.len() {
            let pkts = hub.drain(i);
            if pkts.is_empty() {
                continue;
            }
            any = true;
            for p in &pkts {
                let outs = nodes[i].on_datagram(p, hub.tick);
                for o in outs {
                    hub.send(i, &o);
                }
            }
        }
        // retransmit timers
        for i in 0..nodes.len() {
            let outs = nodes[i].tick_sessions(hub.tick, 3);
            for (_, o) in outs {
                hub.send(i, &o);
                any = true;
            }
        }
        rounds += 1;
        if !any {
            break;
        }
    }
    rounds
}

fn main() {
    println!("newnet POC demo — one suite, one transport, key IS the address\n");

    let mut reg = Registry::new();
    let mut nodes = vec![
        Node::new("alice.example", 0xA11CE),
        Node::new("bob.example", 0xB0B),
        Node::new("registry.example", naming::REGISTRY_SEED),
        Node::new("mallory.example", 0xFA17),
    ];
    nodes[REG].registry = Some(Registry::new());
    // registry identity is the anchor: its node identity must match.
    let anchor = naming::anchor_identity();
    nodes[REG].ident = anchor.clone();

    // Populate the registry table.
    for (name, idx) in [("alice.example", ALICE), ("bob.example", BOB), ("mallory.example", MALLORY)] {
        reg.set_record(name, *nodes[idx].ident.ed_pub().as_bytes(), nodes[idx].ident.x_pub.as_bytes().to_owned(), u64::MAX);
    }
    reg.set_record("registry.example", *anchor.ed_pub().as_bytes(), anchor.x_pub.as_bytes().to_owned(), u64::MAX);
    nodes[REG].registry = Some(reg);

    // Everyone knows the anchor: pin the registry.
    for i in [ALICE, BOB, MALLORY] {
        nodes[i].pins.check_or_pin("registry.example", *anchor.ed_pub().as_bytes(), anchor.x_pub.as_bytes().to_owned(), u64::MAX, NOW).unwrap();
        nodes[i].records.insert(
            "registry.example".into(),
            newnet::crypto::PeerRecord { name: "registry.example".into(), ed: anchor.ed_pub(), x: anchor.x_pub, expiry: u64::MAX },
        );
    }

    let mut hub = Hub::new(4, 2, 3, 0xBADC0FFE);

    // Sessions to the registry (with retry through 2% loss).
    let mut reg_sessions = Vec::new(); // (node, conn)
    for i in [ALICE, BOB] {
        let conn = open_to(&mut hub, &mut nodes, i, "registry.example", 6);
        reg_sessions.push((i, conn));
    }
    for (i, conn) in &reg_sessions {
        assert!(nodes[*i].is_open(*conn), "registry session must open: {:?} {:?}", nodes[*i].logs, nodes[*i].stats);
    }
    println!("[1] registry sessions open (alice, bob) — handshake under loss with app-side retry");
    // Resolve + TOFU pin: alice resolves bob, bob resolves alice.
    let anchor_vk = anchor.ed_pub();
    for (i, name) in [(ALICE, "bob.example"), (BOB, "alice.example")] {
        let conn = reg_sessions.iter().find(|(n, _)| *n == i).unwrap().1;
        let out = nodes[i].send_msg(conn, 0, &Msg::ResolveReq { name: name.into() });
        for o in out {
            hub.send(i, &o);
        }
    }
    pump(&mut hub, &mut nodes, 20);
    let routs = node::pump_registry(&mut nodes[REG], NOW);
    for (_, o) in routs {
        hub.send(REG, &o);
    }
    pump(&mut hub, &mut nodes, 20);
    for (i, name) in [(ALICE, "bob.example"), (BOB, "alice.example")] {
        let conn = reg_sessions.iter().find(|(n, _)| *n == i).unwrap().1;
        let mut got = None;
        for m in nodes[i].recv_msgs(conn, 0) {
            if let Msg::ResolveResp(Some(blob)) = m {
                got = Some(naming::parse_signed_bytes(&blob, &anchor_vk, NOW).unwrap());
            }
        }
        let rec = got.expect("resolve response");
        assert_eq!(rec.name, name);
        nodes[i].pin_record(&rec, NOW).unwrap();
    }
    println!("[2] name->key records verified against the baked-in registry key; pinned TOFU");

    // Alice <-> Bob session.
    let ab_conn = open_to(&mut hub, &mut nodes, ALICE, "bob.example", 6);
    let bob_conn = ab_conn; // same conn id both sides
    let tr = nodes[ALICE].sessions.get(&ab_conn).unwrap().transcript;
    println!("[3] alice<->bob open, transcript {}", hex::encode(tr));

    // Text: ASCII, Unicode, emoji.
    let texts = ["hello", "π = 3.14159 ραθ", "🔒🌐✨"];
    for t in texts {
        let out = nodes[ALICE].send_msg(ab_conn, 1, &Msg::Text(t.into()));
        for o in out {
            hub.send(ALICE, &o);
        }
    }
    pump(&mut hub, &mut nodes, 40);
    let mut got_texts = Vec::new();
    for m in nodes[BOB].recv_msgs(bob_conn, 1) {
        if let Msg::Text(t) = m {
            got_texts.push(t);
        }
    }
    assert_eq!(got_texts, texts);
    println!("[4] text delivered byte-exact (ascii, unicode, emoji)");
    // Legacy byte pipe: 100 KB opaque through the adapter, byte-exact.
    let mut rng = Rng::new(0x5EED);
    let pipe: Vec<u8> = rng.bytes(100 * 1024);
    let mut a_pipe = ByteAdapter::new(ab_conn, 2);
    let mut b_pipe = ByteAdapter::new(bob_conn, 2);
    let out = a_pipe.write(&mut nodes[ALICE], &pipe, hub.tick);
    for o in out {
        hub.send(ALICE, &o);
    }
    pump(&mut hub, &mut nodes, 300);
    let mut rx_pipe = Vec::new();
    rx_pipe.extend(b_pipe.read(&mut nodes[BOB]));
    while rx_pipe.len() < pipe.len() {
        let r = pump(&mut hub, &mut nodes, 100);
        rx_pipe.extend(b_pipe.read(&mut nodes[BOB]));
        if r == 0 {
            break;
        }
    }
    assert_eq!(rx_pipe, pipe);
    println!("[5] legacy TCP-shaped byte pipe: {} bytes byte-exact, ciphertext on the hub", pipe.len());

    // Legacy datagrams: 20 opaque messages, no retransmit.
    let mut a_dg = DatagramAdapter::new(ab_conn);
    let mut dg_msgs = Vec::new();
    for i in 0..20u32 {
        let m = format!("dg-{i}-{}", hex::encode(rng.bytes(8))).into_bytes();
        dg_msgs.push(m.clone());
        if let Some(o) = a_dg.send(&mut nodes[ALICE], &m) {
            hub.send(ALICE, &o);
        }
    }
    pump(&mut hub, &mut nodes, 60);
    let got_dg = DatagramAdapter::new(bob_conn).recv(&mut nodes[BOB]);
    for g in &got_dg {
        assert!(dg_msgs.contains(g), "datagram content must be byte-exact");
    }
    println!("[6] legacy UDP-shaped datagrams: {}/20 survived 2% loss, no retransmit, byte-exact", got_dg.len());

    // File: 100 KB chunked, SHA-256 end to end.
    let blob = rng.bytes(100 * 1024);
    let msgs = content::file_chunks(&blob, 900);
    for m in &msgs {
        let out = nodes[ALICE].send_msg(ab_conn, 3, m);
        for o in out {
            hub.send(ALICE, &o);
        }
    }
    pump(&mut hub, &mut nodes, 400);
    let mut frx = content::FileRx::default();
    loop {
        let ms = nodes[BOB].recv_msgs(bob_conn, 3);
        if ms.is_empty() {
            break;
        }
        for m in ms {
            frx.on(&m);
        }
    }
    assert_eq!(frx.done, Some(true));
    println!("[7] file 100 KB chunked+reassembled, SHA-256 verified end to end");

    // Video: ~120 mock frames, I ~100 KB / P ~10 KB, PTS, 2% loss + reorder.
    let mut frames: Vec<Msg> = Vec::new();
    for i in 0..120u64 {
        let key = i % 30 == 0;
        let size = if key { 100 * 1024 } else { 10 * 1024 };
        let data = rng.bytes(size);
        let h = content::sha256(&data);
        frames.push(Msg::Video { keyframe: key, pts: i * 3003, sha256: h, bytes: data });
    }
    let sent_frames = frames.len();
    for f in &frames {
        let out = nodes[ALICE].send_msg(ab_conn, 4, f);
        for o in out {
            hub.send(ALICE, &o);
        }
    }
    let rounds = pump(&mut hub, &mut nodes, 2000);
    let alice_next = nodes[ALICE].sessions[&ab_conn].tx_streams.get(&4).map(|t| t.next_off).unwrap_or(0);
    let bob_exp = nodes[BOB].sessions[&bob_conn].rx_streams.get(&4).map(|r| r.expected).unwrap_or(0);
    println!("  video offsets: alice sent {alice_next}, bob delivered {bob_exp}");
    let mut ok_frames = 0usize;
    let mut bad_frames = 0usize;
    loop {
        let ms = nodes[BOB].recv_msgs(bob_conn, 4);
        if ms.is_empty() {
            break;
        }
        for m in ms {
            if let Msg::Video { sha256, bytes, .. } = m {
                if content::sha256(&bytes) == sha256 {
                    ok_frames += 1;
                } else {
                    bad_frames += 1;
                }
            }
        }
    }
    assert_eq!(bad_frames, 0);
    assert_eq!(ok_frames, sent_frames);
    println!("[8] video {sent_frames}/{sent_frames} frames delivered+hash-verified through 2% loss and reorder, {rounds} rounds drained (retransmits deduped by offsets; replays counted: {})", nodes[BOB].stats.data_replay);
    // ---- Attacks ----
    let before = nodes[BOB].stats.data_badtag;
    let spoof = attacks::spoof_data(bob_conn, 999_999, &seed32(0x77), b"i am alice");
    hub.send(MALLORY, &spoof);
    pump(&mut hub, &mut nodes, 5);
    assert_eq!(nodes[BOB].stats.data_badtag, before + 1);
    println!("[9] spoof: wrong-key packet on alice's conn_id -> AEAD reject, no session for mallory");

    // Replay: send a real data packet, then resend the recorded bytes late.
    let fresh = nodes[ALICE].send_msg(ab_conn, 5, &Msg::Text("replay me".into()));
    hub.send(ALICE, &fresh[0]);
    pump(&mut hub, &mut nodes, 5);
    let real = fresh[0].clone();
    let rb = nodes[BOB].stats.data_replay;
    hub.send(MALLORY, &real);
    pump(&mut hub, &mut nodes, 5);
    assert_eq!(nodes[BOB].stats.data_replay, rb + 1);
    println!("[10] replay: recorded packet resent late -> replay window reject");

    // Tamper: ciphertext bit and clear-header bit.
    let mut ct_bad = real.clone();
    let n = ct_bad.len();
    attacks::flip_bit(&mut ct_bad, n - 1, 3);
    let mut hdr_bad = real.clone();
    attacks::flip_bit(&mut hdr_bad, 15, 0); // seq field in the clear header
    let bb = nodes[BOB].stats.data_badtag;
    hub.send(MALLORY, &ct_bad);
    hub.send(MALLORY, &hdr_bad);
    pump(&mut hub, &mut nodes, 5);
    // Both flips fail the AEAD tag: ciphertext edit and clear-header (seq) edit.
    assert_eq!(nodes[BOB].stats.data_badtag, bb + 2);
    println!("[11] tamper: ciphertext bit and clear-header bit -> AEAD/tag failure");

    // Flood: 10k random + 1k well-formed garbage handshakes at Bob.
    let s0 = nodes[BOB].stats.sessions_allocated;
    let d0 = nodes[BOB].stats.dh_count;
    let mut frng = Rng::new(0xF10D);
    for _ in 0..10_000 {
        let p = attacks::random_packet(&mut frng, 1200);
        hub.send(MALLORY, &p);
    }
    for _ in 0..1_000 {
        let cid = 0xDEAD_0000 | (frng.next() & 0xFFFF);
        let p = attacks::garbage_handshake(&mut frng, cid);
        hub.send(MALLORY, &p);
    }
    let fr = pump(&mut hub, &mut nodes, 40);
    assert_eq!(nodes[BOB].stats.sessions_allocated, s0, "flood allocates no sessions");
    let dh_used = nodes[BOB].stats.dh_count - d0;
    assert!(dh_used <= 4 * (fr as u64) * crypto::HANDSHAKE_DH_BUDGET_PER_TICK as u64);
    println!("[12] flood: 10k random + 1k garbage handshakes -> 0 sessions, DH work capped by per-tick budget ({dh_used} DH in {fr} ticks)");

    // MITM part 1: a forged HS2 neither completes nor ends Alice's handshake.
    hub.step();
    let (conn, hs1) = nodes[ALICE].connect("bob.example", None).unwrap();
    let hs2 = nodes[BOB].on_datagram(&hs1, hub.tick);
    assert_eq!(hs2.len(), 1, "bob answers the untouched hs1 with exactly one hs2");
    let forged = newnet::wire::encode(
        &newnet::wire::Header { version: newnet::wire::VERSION, ptype: newnet::wire::TYPE_HANDSHAKE2, conn_id: conn, seq: 0, len: 48 },
        &[0x4Du8; 48],
    );
    let af0 = nodes[ALICE].stats.auth_fails;
    let fout = nodes[ALICE].on_datagram(&forged, hub.tick);
    assert!(fout.is_empty(), "forged hs2 gets no answer");
    assert_eq!(nodes[ALICE].stats.auth_fails, af0 + 1, "forged hs2 costs exactly one auth fail");
    assert!(!nodes[ALICE].is_open(conn), "forged hs2 does not open the session");
    let aout = nodes[ALICE].on_datagram(&hs2[0], hub.tick);
    assert_eq!(aout.len(), 1, "the real hs2 completes alice's handshake");
    assert!(nodes[ALICE].is_open(conn), "alice open after real hs2");
    let _bout = nodes[BOB].on_datagram(&aout[0], hub.tick);
    assert!(nodes[BOB].is_open(conn), "bob open once alice's first frame confirms him");
    let c = nodes[ALICE].close(conn).unwrap();
    nodes[BOB].on_datagram(&c, hub.tick);
    assert!(!nodes[BOB].is_open(conn), "close from alice ends bob's session");

    // MITM part 2: stranger claiming alice.example with his own key.
    let mut fake = newnet::node::Node::new("alice.example", 0x0BAD_5EED);
    fake.records.insert("bob.example".into(), nodes[ALICE].lookup_name("bob.example").unwrap());
    let (_, pkt) = fake.connect("bob.example", None).unwrap();
    hub.step();
    let bf = nodes[BOB].stats.auth_fails;
    let bh = nodes[BOB].half_open_count();
    let out = nodes[BOB].on_datagram(&pkt, hub.tick);
    assert!(out.is_empty(), "bob answers the stranger with nothing");
    assert_eq!(nodes[BOB].stats.auth_fails, bf + 1, "stranger costs exactly one auth fail");
    assert_eq!(nodes[BOB].half_open_count(), bh, "stranger allocates no half-open state");

    println!("[13] MITM: a forged reply neither completes nor ends Alice's handshake; a stranger claiming alice.example with his own key is refused by Bob");

    // Second contact: registry lies about bob.example with no handover.
    let m_ed = *nodes[MALLORY].ident.ed_pub().as_bytes();
    let m_x = nodes[MALLORY].ident.x_pub.as_bytes().to_owned();
    if let Some(r) = nodes[REG].registry.as_mut() {
        r.set_record("bob.example", m_ed, m_x, u64::MAX);
    }
    let conn = reg_sessions.iter().find(|(n, _)| *n == ALICE).unwrap().1;
    let out = nodes[ALICE].send_msg(conn, 0, &Msg::ResolveReq { name: "bob.example".into() });
    for o in out {
        hub.send(ALICE, &o);
    }
    pump(&mut hub, &mut nodes, 20);
    let routs = node::pump_registry(&mut nodes[REG], NOW);
    for (_, o) in routs {
        hub.send(REG, &o);
    }
    pump(&mut hub, &mut nodes, 20);
    let mut pinned_fail = false;
    for m in nodes[ALICE].recv_msgs(conn, 0) {
        if let Msg::ResolveResp(Some(blob)) = m {
            let rec2 = naming::parse_signed_bytes(&blob, &anchor_vk, NOW).unwrap();
            if nodes[ALICE].pin_record(&rec2, NOW).is_err() {
                pinned_fail = true;
            }
        }
    }
    assert!(pinned_fail);
    println!("[14] second contact: registry swap without signed handover -> pin rejects");

    // Legacy blobs on the hub: dropped, no state, no answer.
    let lg = nodes[BOB].stats.legacy_dropped;
    hub.send(MALLORY, &attacks::dns_blob());
    hub.send(MALLORY, &attacks::http_blob());
    pump(&mut hub, &mut nodes, 5);
    assert_eq!(nodes[BOB].stats.legacy_dropped, lg + 2);
    println!("[15] legacy DNS- and TCP/HTTP-shaped blobs on the hub -> dropped, nothing allocated");

    // Downgrade attempt: no record -> error, zero bytes on the wire.
    let mut carol = Node::new("carol.example", 0xCA401);
    let w0 = hub.wire_records.len();
    let r = legacy::guarded_connect(&mut carol, "dave.example");
    assert_eq!(r.unwrap_err(), legacy::FallbackError::RefusedNoIdentity);
    assert_eq!(hub.wire_records.len(), w0, "cleartext fallback sent nothing");
    println!("[16] downgrade: fallback path returns an error and sends nothing");

    // ---- Scoreboard ----
    let e = &hub.wire_records;
    let sample = e.iter().find(|r| newnet::wire::decode(r).map(|p| p.header.ptype == newnet::wire::TYPE_DATA).unwrap_or(false)).unwrap();
    let p = newnet::wire::decode(sample).unwrap();
    println!("\nSCOREBOARD");
    println!("  accepted: 3 texts, 100 KB byte pipe, 100 KB file (sha256 ok), {sent_frames}/{sent_frames} video frames, {}/20 datagrams", got_dg.len());
    println!("  bob stats: badtag={} replay={} auth_fails={} legacy={} bad_header={} budget_drop={} no_session={}",
        nodes[BOB].stats.data_badtag, nodes[BOB].stats.data_replay, nodes[BOB].stats.auth_fails,
        nodes[BOB].stats.legacy_dropped, nodes[BOB].stats.bad_header_dropped,
        nodes[BOB].stats.handshake_dropped_budget, nodes[BOB].stats.no_session_dropped);
    println!("  sessions allocated (bob): {} | DH ops (bob): {}", nodes[BOB].stats.sessions_allocated, nodes[BOB].stats.dh_count);
    println!("  hub: forwarded={} dropped_loss={} wire records (Eve)={}", hub.forwarded, hub.dropped_loss, e.len());
    println!("  clear prefix: {}", hex::encode(&sample[..newnet::wire::HEADER_LEN]));
    println!("  ciphertext sample: {}", hex::encode(&p.body[..32.min(p.body.len())]));
    println!("  transcript (alice-bob): {}", hex::encode(tr));
    println!("  padding/cover traffic: OFF (cost would be extra bytes on the hub)");
    println!("\ndone.");
}



