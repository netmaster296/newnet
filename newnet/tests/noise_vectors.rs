// Pins the handshake to the Noise specification instead of to itself.
//
// The vector is the Noise_IK_25519_ChaChaPoly_SHA256 entry of the cacophony
// test-vector set, as shipped with the snow crate 0.10.0
// (tests/vectors/cacophony.txt). Fixed static and ephemeral keys go in; the
// handshake bytes, the handshake hash and both transport keys must come out
// exactly as published.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use newnet::noise_ik::{self, Hello, InitiatorHandshake, ResponderHandshake};

const PROLOGUE: &str = "4a6f686e2047616c74";
const INIT_STATIC: &str = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
const INIT_EPH: &str = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
const RESP_STATIC_PUB: &str = "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62";
const RESP_STATIC: &str = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
const RESP_EPH: &str = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
const HANDSHAKE_HASH: &str = "0b0f68fb0c27e03ce9b97565995ed4838cc0581b762ef72b062f6a546419fad7";

const P1: &str = "4c756477696720766f6e204d69736573";
const C1: &str = "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f18146e8cd0873654207148333479d4d16c289f0294b29960a72f48e0b7bba2e89083169825e59642148d492020664ccf7";
const P2: &str = "4d757272617920526f746862617264";
const C2: &str = "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435361e70b2ed446e6c9ec387d1d6b3b840f194e373979d241b203c4acafccf5";
// First transport message in each direction, Noise nonce 0, empty AD.
const P3: &str = "462e20412e20486179656b";
const C3: &str = "050e9f3c8fac16b68dbce8f8c4bfbf6617c897f9ada4aa29aa19c8";
const P4: &str = "4361726c204d656e676572";
const C4: &str = "344233a6cabb7141d80f3da2fedc311d9646bbb0f505afe403a667";

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn k(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

fn vector_pair() -> (InitiatorHandshake, ResponderHandshake) {
    let i = InitiatorHandshake::new(&k(INIT_STATIC), &k(RESP_STATIC_PUB), &h(PROLOGUE), Some(k(INIT_EPH))).unwrap();
    let r = ResponderHandshake::new(&k(RESP_STATIC), &h(PROLOGUE), Some(k(RESP_EPH))).unwrap();
    (i, r)
}

fn noise_open(key: &[u8; 32], ct: &str) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: &h(ct), aad: &[] })
        .ok()
}

#[test]
fn ik_matches_the_published_noise_vector() {
    let (mut i, mut r) = vector_pair();

    let m1 = i.write_msg1(&h(P1)).unwrap();
    assert_eq!(hex::encode(&m1), C1, "message 1 bytes");
    let (p1, initiator_static) = r.read_msg1(&m1).unwrap();
    assert_eq!(p1, h(P1));
    let want = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(k(INIT_STATIC)));
    assert_eq!(&initiator_static, want.as_bytes(), "responder learns the initiator's static key");

    let (m2, rk) = r.write_msg2(&h(P2)).unwrap();
    assert_eq!(hex::encode(&m2), C2, "message 2 bytes");
    let (p2, ik) = i.read_msg2(&m2).unwrap();
    assert_eq!(p2, h(P2));

    assert_eq!(hex::encode(ik.transcript_hash), HANDSHAKE_HASH, "handshake hash");
    assert_eq!(ik.transcript_hash, rk.transcript_hash);
    assert_eq!(ik.a_to_b_gen0, rk.a_to_b_gen0);
    assert_eq!(ik.b_to_a_gen0, rk.b_to_a_gen0);

    // The split is the right way round and the keys are the published ones.
    assert_eq!(noise_open(&ik.a_to_b_gen0, C3), Some(h(P3)), "initiator-to-responder key");
    assert_eq!(noise_open(&ik.b_to_a_gen0, C4), Some(h(P4)), "responder-to-initiator key");
    assert_eq!(noise_open(&ik.b_to_a_gen0, C3), None, "keys are per direction");
}

#[test]
fn tampered_or_mismatched_handshake_fails() {
    // One flipped bit anywhere in message 1.
    for idx in [0usize, 40, 90, 100] {
        let (mut i, mut r) = vector_pair();
        let mut m1 = i.write_msg1(&h(P1)).unwrap();
        m1[idx] ^= 1;
        assert!(r.read_msg1(&m1).is_err(), "bit flip at byte {idx} accepted");
    }
    // Same message, different prologue on the responder.
    let (mut i, _) = vector_pair();
    let m1 = i.write_msg1(&h(P1)).unwrap();
    let mut r = ResponderHandshake::new(&k(RESP_STATIC), b"other prologue", Some(k(RESP_EPH))).unwrap();
    assert!(r.read_msg1(&m1).is_err(), "prologue is not bound");
    // Too short to hold the fixed part.
    let (_, mut r) = vector_pair();
    assert!(r.read_msg1(&m1[..50]).is_err());
}

#[test]
fn a_forged_msg2_does_not_poison_the_initiator() {
    let (mut i, mut r) = vector_pair();
    let m1 = i.write_msg1(&h(P1)).unwrap();
    r.read_msg1(&m1).unwrap();
    let (m2, _) = r.write_msg2(&h(P2)).unwrap();
    let mut forged = m2.clone();
    forged[40] ^= 1;
    assert!(i.read_msg2(&forged).is_err());
    assert!(i.read_msg2(&[0u8; 10]).is_err());
    let (p2, _) = i.read_msg2(&m2).expect("the real message 2 still completes the handshake");
    assert_eq!(p2, h(P2));
}

#[test]
fn prologue_binds_the_connection_id() {
    assert_ne!(noise_ik::prologue(1), noise_ik::prologue(2));
    assert!(noise_ik::prologue(7).starts_with(b"NEWNET2"));
    assert_eq!(noise_ik::prologue(7).len(), 7 + 8);
}

#[test]
fn hello_round_trip_and_strict_decode() {
    let hello = Hello { stamp: 0x0102_0304_0506_0708, name: "alice.example".into() };
    let bytes = noise_ik::encode_hello(&hello);
    assert_eq!(bytes.len(), 8 + 2 + 13);
    assert_eq!(&bytes[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(noise_ik::decode_hello(&bytes), Some(hello));
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(noise_ik::decode_hello(&long), None, "trailing bytes rejected");
    assert_eq!(noise_ik::decode_hello(&bytes[..bytes.len() - 1]), None, "truncated rejected");
    assert_eq!(noise_ik::decode_hello(&[]), None);
    let mut bad_utf8 = bytes.clone();
    bad_utf8[10] = 0xFF;
    assert_eq!(noise_ik::decode_hello(&bad_utf8), None, "name must be UTF-8");
}
