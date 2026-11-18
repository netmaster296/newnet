# newnet

An identity-first secure session layer, as a proof of concept in Rust.

Peers are known by their keys, not their addresses. Everything on the wire is encrypted and authenticated, and existing protocols ride inside unchanged, with no fallback to cleartext.

## Status

This is a research proof of concept. **It has not been audited. Do not rely on it to protect anything.**

It has been tested on one machine, over the loopback interface. Nothing has been run across a real network yet.

## What is here

- **Handshake.** `Noise_IK_25519_ChaChaPoly_SHA256` through the `snow` crate, checked against a published test vector. Every handshake includes a cookie round, so a node does no key-exchange work for a sender that cannot receive at its claimed address.
- **Sessions.** ChaCha20-Poly1305, a new key generation every 1,000 packets with old keys erased, a replay window, liveness and idle timeouts, and limits on what an authenticated peer can make a node hold.
- **Streams and datagrams.** Ordered reliable streams and unreliable datagrams inside a session.
- **Identities.** Key files exchanged by hand with `newnet-keys`, in the manner of SSH or WireGuard public keys. No registry is needed.
- **Real sockets.** A UDP endpoint, and `udpfile`, which sends one file between two processes and reports success only after the receiver confirms it is stored.
- **A lab.** An in-memory network with scripted loss and reordering, a demo with an attack scoreboard, and a harness that replays packet traces.

## Try it

```
cd newnet
cargo test
cargo run --release --bin demo
```

Send a file between two processes on one machine. Build first with `cargo build --release`; the binaries are in `target/release`.

```
newnet-keys gen --name host --file host.key
newnet-keys gen --name vm --file vm.key
newnet-keys show --file host.key
newnet-keys show --file vm.key
newnet-keys add-peer --peers host.peers --line "<the line that show printed for vm>"
newnet-keys add-peer --peers vm.peers --line "<the line that show printed for host>"
```

Then, in two terminals, receiver first:

```
udpfile recv --identity vm.key --peers vm.peers --listen 127.0.0.1:4002 --out received.bin
udpfile send --identity host.key --peers host.peers --peer vm --to 127.0.0.1:4002 --file <any file>
```

## Documents

- `SPEC-v2.md`: the specification for wire version 2.
- `grok-analysis.md`: an early outside review.

## How it was built

With heavy use of AI coding assistants, directed by the owner. There was an initial version, an outside review by Grok, and a hardening pass specified, measured and reviewed with Claude. Most later code was written by a local Qwen model from written specifications, one step at a time, with tests as the gate. The commit messages say which is which.

## Credits

- The Noise Protocol Framework, and the `snow` crate (github.com/mcginty/snow) that implements it.
- The RustCrypto crates (`chacha20poly1305`, `hkdf`, `hmac`, `sha2`) and the dalek crates (`x25519-dalek`, `ed25519-dalek`).
- The handshake test vector comes from the cacophony vector set as shipped with `snow`.
- The cookie and the planned loss detection follow ideas from WireGuard and QUIC.
- The packet captures used in testing (MAWI, NETRESEC) are third-party data and are not included in this repository.

## Licence

GPL-3.0-only. Copyright (C) 2026 netmaster296. See `LICENSE`.
