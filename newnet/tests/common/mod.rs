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
