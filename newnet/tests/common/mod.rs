// Each test binary compiles this whole module but uses only some of it.
#![allow(dead_code)]

// Shared test helpers (step 4). The cookie round a client must complete
// before the responder does any Noise work: HS1 (zero cookie) -> COOKIE ->
// HS1 (cookie filled). `from` is the address the responder sees the HS1
// from; the COOKIE is delivered to `a` as if from an unknown source, so
// attempts made with connect()/connect_at() (destination ADDR_ANY) accept
// it. For connect_to() attempts, drive the COOKIE into `a` from the peer
// address instead.

use newnet::link::Addr;
use newnet::node::Node;
use newnet::wire;

pub fn complete_cookie_round(a: &mut Node, b: &mut Node, hs1: Vec<u8>, from: Addr) -> Vec<u8> {
    let reply = b.on_datagram_from(from, &hs1, 1);
    assert_eq!(reply.len(), 1, "a zero-cookie HS1 must be answered with exactly one COOKIE: {:?}", b.stats);
    let ck = wire::decode(&reply[0]).expect("the COOKIE reply decodes");
    assert_eq!(ck.header.ptype, wire::TYPE_COOKIE, "the first reply must be a COOKIE");
    assert_eq!(ck.body.len(), wire::COOKIE_LEN, "a COOKIE body is 16 bytes");
    let rebuilt = a.on_datagram(&reply[0], 1);
    assert_eq!(rebuilt.len(), 1, "the initiator answers a COOKIE with exactly one datagram");
    let hs1b = wire::decode(&rebuilt[0]).expect("the rebuilt HS1 decodes");
    assert_eq!(hs1b.header.ptype, wire::TYPE_HANDSHAKE1, "the answer must be a HANDSHAKE1");
    assert_eq!(hs1b.header.conn_id, ck.header.conn_id, "the rebuilt HS1 keeps the conn id");
    assert_ne!(&hs1b.body[..wire::COOKIE_LEN], &[0u8; wire::COOKIE_LEN], "the rebuilt HS1 carries the cookie");
    rebuilt[0].clone()
}

// Replace the 16 leading cookie bytes of an encoded HS1 with `cookie`.
pub fn fill_cookie(pkt: &[u8], cookie: &[u8]) -> Vec<u8> {
    let mut p = wire::decode(pkt).expect("the packet decodes");
    assert_eq!(p.header.ptype, wire::TYPE_HANDSHAKE1, "only a HANDSHAKE1 carries a cookie");
    p.body[..wire::COOKIE_LEN].copy_from_slice(cookie);
    wire::encode(&p.header, &p.body)
}

// The cookie round for a hand-built HS1 (garbage, mini-Noise) that no
// initiator node owns: drive the zero-cookie copy at `b` from `from`, take
// the cookie out of the COOKIE answer, and return the copy with that cookie
// in front of the Noise bytes. The result is not yet delivered.
pub fn cookie_for_handbuilt(b: &mut Node, pkt: &[u8], from: Addr, tick: u64) -> Vec<u8> {
    let reply = b.on_datagram_from(from, pkt, tick);
    assert_eq!(reply.len(), 1, "a zero-cookie HS1 must be answered with exactly one COOKIE: {:?}", b.stats);
    let ck = wire::decode(&reply[0]).expect("the COOKIE reply decodes");
    assert_eq!(ck.header.ptype, wire::TYPE_COOKIE, "the first reply must be a COOKIE");
    assert_eq!(ck.body.len(), wire::COOKIE_LEN, "a COOKIE body is 16 bytes");
    fill_cookie(pkt, &ck.body)
}
