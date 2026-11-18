# Grok analysis — New Internet POC

Date: 2026-11-16. Read of `newnet/src` as it sits. `cargo check --offline` was run. The crate was not modified, and `cargo test` was not run, because the library does not typecheck.

## Status

An earlier pass said the proof of concept is green: 20 tests and a passing demo. That was true of an earlier tree. `newnet/target/debug/demo.exe` is still there from that build. The source no longer matches it.

`cargo check --offline` fails in `node.rs`:

- Line 43 types `pending_init` as `(InitiatorHandshake, Vec<u8>, u64)`.
- Line 102 inserts a bare `InitiatorHandshake`.
- Line 187 calls `msg2_accept` on that tuple.

Until those three lines agree, nothing in the implementation log can be re-run.

The module split is the one the plan asked for, plus `noise.rs` and `node.rs`. Wire decode, the data-packet AEAD, the replay window, stream independence, registry signatures, pin mismatch, and signed handover all have real tests. The demo script covers text, a 100 KB byte pipe, 20 datagrams, a 100 KB file, 120 video frames, and the attack scoreboard. That shape is right. The crypto and a few session rules underneath it are not what the plan says they are.

## Forward secrecy is not in the key schedule

`CipherState::mix_key` in `crypto.rs` replaces `k` with HKDF of the new Diffie-Hellman output alone. There is no chaining key. Each mix throws away the previous one.

`noise.rs` then does this for message 2, on both sides:

- mix `ee` (initiator ephemeral × responder ephemeral)
- mix what the comment calls `se`

The second call is `DH(initiator ephemeral, responder static)`. That is `es` again, the same secret that already encrypted message 1. It is not `DH(initiator static, responder ephemeral)`, which is what Noise_IK's `se` token is.

`split()` runs on whatever `k` is last. Transport keys are HKDF of `DH(initiator ephemeral, responder static)`.

The initiator ephemeral sits in the clear at the front of message 1. Anyone who later obtains the responder's X25519 static recomputes every past transport key and also opens the handshake payload, which is encrypted under that same `es`. The plan says application payloads sit under both ephemerals, and that a stolen identity key does not open old sessions. This code does not do that. `ee` and `ss` are computed and then overwritten, so they never reach the traffic keys.

## The handshake does not prove the X25519 static

Message 1's signature covers `h0 = SHA-256(protocol name || responder static)` only. It does not cover the ephemeral, the ciphertext, or `conn_id`.

The responder checks that signature against the registry Ed25519 key, inside the `es` ciphertext. The `ss` mix, which would prove the initiator holds the X25519 static, is discarded before any later decrypt. A holder of the Ed25519 identity key can build a fresh message 1 without the X25519 private key. The plan's rule is the other way around: allocate a session only after proof of the X25519 static.

## A recorded handshake allocates new sessions

`conn_id` is not an input to the handshake hash or the signature. Handshake sequence numbers are fixed at 0, and the data replay window does not cover handshake packets.

A captured HANDSHAKE1, resent with a new `conn_id`, still decrypts under the responder's static key. `on_hs1` then inserts a session. The peer does not need the initiator's secrets to force that allocation. The per-tick budget limits how fast this goes. It does not stop it. The plan treated session allocation as something only a party who can complete a real handshake can do.

## Close is unauthenticated

`Node::on_datagram` handles `TYPE_CLOSE` by deleting `sessions[conn_id]`. It does not check the AEAD tag. `conn_id` is in the clear header. Anyone who has seen a packet can end the session. The demo never sends this type, so the scoreboard does not show it. Data-packet tamper tests do not cover it.

## Smaller mismatches with the plan

- Handshake certs are checked with `verify_cert(..., now = 0)`. For a `u64`, `expiry < 0` is impossible, so a handshake cert never expires. Name-record expiry is checked, at resolve time, with a real `now`.
- `pin_record` and the registry lookup store `PeerRecord` with an empty `cert`. `InitiatorHandshake::new` skips cert verification when `cert` is empty. The binding is checked later, on message 2, against the key the record already carried.
- `StreamRx::put` only releases a chunk whose offset equals `expected`. A chunk that starts before `expected` and extends past it is stored and never consumed. The demo's chunks are aligned, so the video run does not hit this.
- `seal_frame` does not enforce the 1200-byte datagram maximum. Current chunks stay under it (1100 bytes of payload plus framing). A long handshake name is not rejected.
- There is no padding knob. Packets are variable length. That matches "padding off." It does not match the sentence that says datagram size is fixed at 1200.
- `State::Handshake` is never entered. `Session::from_split` starts at `Open`. Refusing application data before open is implemented by having no session yet. The integration test covers that. The state machine in the plan is not the one in the code.
- The hub applies loss and one-step reorder. The comment mentions jitter. There is no delayed queue.
- `content::put` uses `assert!` and `expect`. A too-large message panics. `wire::decode` and `streams::decode_frame` do not.
- `FileRx` ignores the chunk offset and appends. Safe only while the stream layer emits each byte once, which it does for aligned chunks.

## What the tests and the log overclaim

- `wrong_pinned_key_fails_handshake` replaces Bob's `PeerRecord` for Alice. It never calls `PinStore`.
- `handshake_budget_caps_dh_per_tick` allows `4 * 2` Diffie-Hellman operations. Garbage handshakes fail inside message 1, so the interesting cap is attempts, and the assertion is loose.
- The flood check in `demo.rs` allows `4 * ticks * 4` Diffie-Hellman operations. A budget bug that still stayed under that line would pass.
- The implementation log says every node that can authenticate the name in HANDSHAKE1 opens a parallel session. Message 1 is encrypted to the target's static key. Other nodes burn one budget slot, fail authentication, and do not allocate a session.
- `dh_count` on a successful handshake adds 3. The function performs four Diffie-Hellman operations (`es`, `ss`, `ee`, and the second `es`). The counter is not the number of scalar multiplications.

## What is solid

- Data packets put the 24-byte header, including `conn_id`, `seq`, and `len`, in the AEAD associated data. A flipped sequence bit fails open. The demo checks that.
- The replay window rejects seen, too-old, and too-far sequence numbers, and the too-far case does not advance the window. The unit test exercises the boundaries.
- Failed header parses and failed authentications do not insert a session. Legacy bytes that lack the `NEW1` magic take the no-Diffie-Hellman path.
- Registry records are postcard bytes signed by `anchor_identity()`, which is `Identity::from_seed` of a fixed constant. A bad signature fails closed. A second resolve that changes Bob's key fails the pin unless a handover signed by the pinned Ed25519 key is applied. Those unit tests are real.
- One stream's hole does not block another stream whose packets already arrived. The integration test holds one chunk of stream 2 and still delivers text on stream 1.
- `guarded_connect` returns `RefusedNoIdentity` and writes nothing. There is no cleartext socket behind it.
- Selective acknowledgements exist, with a cap of 8 ranges, and the sender also retransmits on a 3-tick timer in the demo's pump. The log's note that the timer does most of the work under this loss rate is consistent with the code.

## Bottom

The demo, when it last built, showed reliable delivery on one hub and rejection of the scripted attacks. It did not show forward secrecy, proof of the X25519 static, handshake replay resistance, or an authenticated close. Those four are properties the plan states and this source does not implement. Fix the `pending_init` type error first, or the rest cannot be re-checked.
