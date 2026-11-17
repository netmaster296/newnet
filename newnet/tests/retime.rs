// Step 1 retime: one tick is 1 ms and every wall-clock value is unchanged.
// The constants are in ticks, so each one multiplied by TICK_MS must still
// equal its v1 millisecond value.

use std::time::Duration;

use newnet::attacks;
use newnet::crypto::PeerRecord;
use newnet::node::{BUDGET_EPOCH_TICKS, HALF_OPEN_TTL, Node};
use newnet::session::IDLE_TTL;
use newnet::udp::{TICK_MS, TIMEOUT_TICKS, UdpEndpoint};

#[test]
fn idle_ttl_is_twelve_seconds() {
    assert_eq!(IDLE_TTL * TICK_MS, 12_000);
    assert_eq!(HALF_OPEN_TTL * TICK_MS, 400);
    assert_eq!(TIMEOUT_TICKS * TICK_MS, 500);
}

#[test]
fn endpoint_tick_is_one_millisecond() {
    let ep = UdpEndpoint::bind(Node::new("ticky", 1), "127.0.0.1:0").unwrap();
    let before = ep.now();
    std::thread::sleep(Duration::from_millis(60));
    let advanced = ep.now() - before;
    assert!(
        (55..=120).contains(&advanced),
        "now() advanced by {advanced} ticks over a 60 ms sleep: a tick is not 1 ms"
    );
}

#[test]
fn budget_epoch_is_twenty_ticks() {
    let mut b = Node::new("bob", 0xB0B);
    let mut rng = attacks::Rng::new(7);
    for i in 0..4u64 {
        let p = attacks::garbage_handshake(&mut rng, 4000 + i);
        b.on_datagram(&p, 0);
    }
    assert_eq!(b.stats.dh_count, 8, "the first four handshakes of an epoch do DH work");
    let fifth = attacks::garbage_handshake(&mut rng, 4004);
    b.on_datagram(&fifth, 19);
    assert_eq!(b.stats.handshake_dropped_budget, 1, "the 5th at tick 19 is still in epoch 0");
    assert_eq!(b.stats.dh_count, 8, "a budget-dropped handshake costs no key exchange");
    let sixth = attacks::garbage_handshake(&mut rng, 4005);
    b.on_datagram(&sixth, BUDGET_EPOCH_TICKS);
    assert_eq!(b.stats.handshake_dropped_budget, 1, "the handshake at tick 20 opens a new epoch");
    assert_eq!(b.stats.dh_count, 10, "the new epoch admits the next handshake");
}
