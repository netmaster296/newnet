# newnet wire version 2: specification

Status, 2026-11-16. This is the working specification for version 2. It is "design B" (smallest correct change) from a design round that was stopped early to save cost, so it was not compared against alternatives. Sections 1 to 4 and steps 1 to 7 (phase 1, ending at a file sent between two real machines) have been read and accepted. Sections 5 to 7 and steps 8 to 14 (phase 2, performance) have NOT been reviewed yet and must be before step 8 starts.

The open questions in section 12 are answered with their recommended answers until the owner says otherwise. The ones that matter for phase 1: a cookie on every handshake; a stamp floor five minutes before process start; one tick equals 1 ms; private keys protected by file permissions (mode 600 on Linux, an ACL set with icacls on Windows), with no passphrase.

## Amendments (these override the text below)

A1. Step 7, binary name. Cargo names a binary after its source file. The key tool's source is `src/bin/newnet-keys.rs`, so the binary is `newnet-keys` and tests use `env!("CARGO_BIN_EXE_newnet-keys")`.

A2. Section 3.4, Windows ACL. `std::process::Command` does not expand `%USERNAME%`. Read the environment variables `USERDOMAIN` and `USERNAME` and pass `<USERDOMAIN>\<USERNAME>:F` to icacls. If either variable is missing, delete the file and return `KeyError::Io`.

A3. Step 4 is done as three commits, to keep each one small:
  - 4a. Add everything step 4 lists (the cookie in the node on both sides, `on_datagram_src`, the endpoint passing the real source key, the new stats, `tests/common/mod.rs`, `tests/cookie_handshake.rs`), but behind a switch: `Node` gets a private `require_cookie: bool`, default `false`, and `pub fn set_require_cookie(&mut self, on: bool)`. When it is false the responder treats every HANDSHAKE1 as if its cookie were valid, and the body layout is ALREADY the version 2 layout (16 cookie bytes, zero, then the Noise message). The initiator always handles a COOKIE datagram. The new tests in `tests/cookie_handshake.rs` call `set_require_cookie(true)` on the responder. No existing test changes except those that hand-build a HANDSHAKE1 body, which gain the 16 zero bytes.
  - 4b. Make the default `true`. Every existing test and binary that drives a handshake by hand gains the cookie round through the helper in `tests/common/mod.rs` (for `src/bin/replay.rs`, written inline). No assertion is removed or weakened; tests that count the datagrams of a handshake gain two.
  - 4c. Remove `require_cookie` and `set_require_cookie` entirely. The cookie is always required. `grep -rn "require_cookie" src tests` prints nothing.

A4. Step 1. Only tick numbers change. Every assertion stays. A test loop that waits for a timeout uses the constant or scales its bound by 20. Tests that used a new tick to get a fresh handshake budget now move by `BUDGET_EPOCH_TICKS`.

A5. Every step. The implementer runs each mutation the step names, sees the named test fail, restores the code, and records the result in `qwen-run/v2/<step>.mutations.md`. A second, separate run then repeats the mutations as a check.

A6. Fixes found when the phase 1 chain was checked. Do both as one step, after step 7.
  (a) Gap retransmits are limited in ticks, and step 1 changed a tick from 20 ms to 1 ms without changing that limit. On a real endpoint a missing chunk is now re-sent up to once per millisecond instead of once per 20 ms, and with a slow receiver that floods the queue. Measured with debug binaries, 5 MB over loopback, three runs: 12.0 s, a timeout at 90 s, 3.3 s. With the limit at 20 ticks: 5.6 s, 4.1 s, 3.5 s.
      - `src/streams.rs`: add `pub fn gap_retransmit_spaced(&mut self, id: u32, now: u64, interval: u64) -> Vec<Frame>`: the body of today's `gap_retransmit`, except that a chunk is re-sent only when `now >= sent + interval`. `gap_retransmit(id, now)` stays, with its signature, and calls `gap_retransmit_spaced(id, now, 1)`.
      - `src/session.rs`: `Session` gets a private `gap_interval: u64`, 1 in `from_split`; `pub fn set_gap_interval(&mut self, ticks: u64)` and `pub fn gap_interval(&self) -> u64`. The ACK branch of `on_frame` calls `gap_retransmit_spaced(.., self.gap_interval)`.
      - `src/node.rs`: `Node` gets a private `gap_interval: u64`, 1 in every constructor; `pub fn set_gap_interval(&mut self, ticks: u64)` (stores it and applies it to every existing session) and `pub fn gap_interval(&self) -> u64`. Every place that creates a `Session` calls `set_gap_interval(self.gap_interval)` on it.
      - `src/udp.rs`: `pub const GAP_INTERVAL_TICKS: u64 = 20;` and `bind_with_capacity` calls `node.set_gap_interval(GAP_INTERVAL_TICKS)`. The in-memory lab keeps 1, because there a tick is one pump round.
      - Tests: in `src/streams.rs`, `gap_interval_spaces_retransmits`: with interval 20, a chunk gap-retransmitted at tick 100 is not re-sent by calls at ticks 101 to 119 and is re-sent at tick 120; with interval 1 a call at tick 101 re-sends it. In `tests/retime.rs`, `the_udp_endpoint_spaces_gap_retransmits_by_twenty_ms`: bind an endpoint on 127.0.0.1:0 and assert `ep.node.gap_interval() * TICK_MS == 20`; and `a_lab_node_keeps_the_one_tick_interval`: `Node::new("x", 1).gap_interval() == 1`.
      - Mutations: do not call `set_gap_interval` in `bind_with_capacity` (the endpoint test fails); compare with `now > sent` in `gap_retransmit_spaced` (the streams test fails).
      - Acceptance: `cargo test --test keys_cli` passes FIVE times in a row and each run takes under 90 seconds. Record the five times.
  (b) In `Node::on_hs2` the pending attempt is removed before the session-room check, so when the node already holds `MAX_SESSIONS` sessions the attempt is consumed instead of the packet being dropped. Check for room first. When there is none: count `sessions_refused_full`, leave the pending attempt in place, return nothing. Test in `tests/responder_limits.rs`, `a_full_initiator_keeps_its_pending_attempt`: a node holding `MAX_SESSIONS` sessions that receives a valid HANDSHAKE2 for a pending attempt still has `pending_count()` unchanged and `sessions_refused_full` one higher. Mutation: restore the old order; the test fails.

---


Stance: the smallest change from the current crate that is correct. Every mechanism below has one obvious implementation and at least one test that fails if it is written wrong. Where a bigger mechanism (several frame types, load-triggered cookies, per-stream credit, BBR-style pacing, DPAPI key storage) would be cleverer, this design takes the plain one and says what it costs.

What I read: `local notes` (last three sections), `wire.rs`, `noise_ik.rs`, `node.rs`, `session.rs`, `streams.rs`, `crypto.rs`, `identity.rs`, `udp.rs`, and the listings of the other files. I did NOT read the bodies of `newnet/tests/*.rs`, `naming.rs`, `link.rs`, `replay.rs`, `demo.rs`, `udpfile.rs`; where a step says "existing tests change", the list is by file name and by what must be true, and the implementer finds exact lines with the compiler. Three numbers are assumptions to be measured, not facts: the CPU cost of one handshake message 1 (assumed 150 microseconds for two X25519 operations), how far the lab hub moves a "reordered" packet, and the throughput of the two real machines. Each is flagged where used.

---

## 1. Scope and non-goals

In scope (wire version 2, one version bump):

1. Identity from real key files exchanged by hand; no registry needed.
2. A return-routability cookie on every handshake.
3. Connection-level flow control; sender backpressure; per-destination outgoing queues served in turn.
4. Loss detection by packet number, measured RTT, one congestion controller (NewReno in bytes), real pacing.
5. A re-timing of the logical clock from 20 ms to 1 ms per tick (needed for RTT on a LAN).

Non-goals (not done, not claimed):

- No negotiation of anything: one cipher suite, one version, no cleartext fallback. A version 1 datagram is dropped by the version check.
- No traffic-analysis resistance: conn id, packet number, sizes and timing are cleartext.
- No post-quantum protection, no revocation service, no key transparency, no multi-hop routing, no NAT traversal, no IPv6 testing (the source key supports it, nothing tests it).
- No passphrase on key files; no hardware key storage.
- No per-stream flow control (one slow-read stream stalls the connection credit; section 6).
- No ECN, no delay-based or BBR control, no path MTU discovery (datagrams stay at most 1200 bytes).
- No file resume after a session dies (udpfile restarts the transfer).
- The Ed25519 registry, `naming.rs`, handovers and the TOFU pin store stay in the crate for the lab. The real path does not use them (section 3).

---

## 2. Wire format v2

All integers are little-endian except where marked. "Tick" is the logical clock; in v2 one tick is 1 ms on a real endpoint (section 8, step 1). Maximum datagram 1200 bytes.

### 2.1 Datagram header (24 bytes, cleartext, unchanged layout)

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `4E 45 57 31` ("NEW1"; kept as the family tag) |
| 4 | 1 | version | **2** |
| 5 | 1 | type | 0 HANDSHAKE1, 1 HANDSHAKE2, 2 DATA, **3 COOKIE** |
| 6 | 8 | conn_id | random u64 chosen by the initiator (OS RNG) |
| 14 | 8 | seq | packet number; 0 on types 0, 1, 3; per-packet counter on DATA, never repeats |
| 22 | 2 | len | body length in bytes, must equal the bytes after the header |

`wire::decode` accepts versions equal to 2 only (`BadVersion` otherwise), types 0..=3 only (`BadType`), and a non-empty body. The header remains AEAD associated data on DATA. Type 3 was the removed unauthenticated close in v1; it is reused here, which is safe because the version byte changed.

### 2.2 HANDSHAKE1 (type 0), initiator to responder

Body = `cookie[16]` || `noise_msg1`.

| Body offset | Size | Field |
|---|---|---|
| 0 | 16 | cookie: 16 zero bytes on the first try, else the value from a COOKIE datagram |
| 16 | 32 | Noise IK message 1: ephemeral public key `e` |
| 48 | 48 | encrypted initiator static `s` (32 + 16 tag) |
| 96 | 26+N | encrypted payload `Hello` (plaintext 10+N bytes, plus 16 tag), N = name length |

`Hello` plaintext: `stamp u64` | `name_len u16` | `name` (1 to 64 bytes, characters `a-z 0-9 . _ -`; `decode_hello` returns None otherwise).

Sizes: noise_msg1 = 32 + 48 + (10 + N + 16) = 106 + N, so body = 122 + N, datagram = 146 + N. With N from 1 to 64 the HANDSHAKE1 datagram is **147 to 210 bytes**. The responder drops any HANDSHAKE1 datagram outside that range without a reply (`hs1_bad_size`). Prologue (Noise) = ASCII `NEWNET2` (7 bytes) || conn_id (8 bytes). The cookie is NOT in the prologue and not in the Noise message, so an identical Noise message 1 can be resent with a different cookie.

### 2.3 COOKIE (type 3), responder to initiator

Header: conn_id echoed from the HANDSHAKE1, seq 0, len 16. Body = `cookie[16]`. Datagram = **40 bytes**. It is unauthenticated (see section 9 for what that allows).

### 2.4 HANDSHAKE2 (type 1), responder to initiator

Header: conn_id echoed, seq 0. Body = Noise IK message 2: `e`[32] || encrypted empty payload [16] = 48 bytes. Datagram = **72 bytes**. Unchanged from v1 except the prologue.

### 2.5 DATA (type 2)

Header with seq = packet number. Body = `ChaCha20-Poly1305(key_gen(seq/1000), nonce = seq, aad = 24 header bytes, plaintext = exactly one frame)` = frame bytes + 16 tag. Key rotation, nonce, replay window 2048, 2^20 look-ahead refusal: all unchanged. Because every sealed packet takes the next seq (ACK-only packets and retransmissions included), **seq is the packet number** for loss detection.

### 2.6 Frames (plaintext inside DATA; one frame per datagram, unchanged)

Every frame starts with a one-byte type. There is no common "id" field any more.

**STREAM (0)** — ack-eliciting.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `00` |
| 1 | 4 | stream_id u32 |
| 5 | 8 | offset u64 (offset of the first data byte in the stream) |
| 13 | 1..=1100 | data |

Largest datagram: 24 + 13 + 1100 + 16 = 1153 bytes. Empty data is rejected.

**ACK (1)** — not ack-eliciting.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `01` |
| 1 | 8 | largest u64: highest packet number received |
| 9 | 2 | ack_delay u16: ticks between receiving `largest` and sending this ACK (saturating at 65535) |
| 11 | 8 | max_data u64: the receiver's absolute connection limit (section 6) |
| 19 | 1 | n u8: number of ranges, 1 to 16 |
| 20 | 16 n | n ranges, newest first: `start u64`, `end u64`, both inclusive |

Validity (decoder returns `FrameError::Malformed` otherwise): 1 <= n <= 16; length exactly 20 + 16 n; for each range start <= end; `ranges[0].end == largest`; for i > 0, `ranges[i].end + 1 < ranges[i-1].start` (strictly separated, so ranges never touch or overlap). Maximum size 276 bytes of plaintext.

**DGRAM (2)** — not ack-eliciting, not retransmitted, not congestion controlled. `02` || data (0 to 1150 bytes).

**CLOSE (3)** — not ack-eliciting. `03`. Receiver sets the session Closed.

**PING (4)** — ack-eliciting. `04`. The reply is an ACK (there is no id and no PING reply any more).

Unknown type or truncated frame: `FrameError`, the packet is dropped (already authenticated, so it counts as `bad_frame`), session stays.

### 2.7 Handshake exchange, in order

1. I -> R: HANDSHAKE1 (zero cookie, Noise msg1). R computes one HMAC and replies COOKIE. R does no DH, stores nothing.
2. R -> I: COOKIE.
3. I -> R: HANDSHAKE1 (same Noise bytes, same conn_id, cookie filled).
4. R -> I: HANDSHAKE2. R now holds a half-open entry.
5. I -> R: DATA seq 0 = PING (this is the confirmation; R creates the session on it).
6. R -> I: DATA seq 0 = ACK. I sets `confirmed` when it opens this.

---

## 3. Identity files and hand exchange

### 3.1 What an identity is

One X25519 secret (32 bytes) and a local name. The X25519 public key is the only handshake identity (as in v1, since Noise IK uses it). The Ed25519 half of `Identity` is derived from the same secret (`hkdf1(secret, "NEWNET2-ED25519")`) so the struct stays whole; the real path never uses it.

Name rule: 1 to 64 bytes of `a-z 0-9 . _ -`. A node's own name is what it puts in `Hello.name`. The name is a label for humans and for the stamp table; the key is the authority. A peer is accepted only if the Noise static key in message 1 equals the key the peers file holds under the name in `Hello` (this is the existing `resolve` plus `rec.x == remote_static` check).

### 3.2 Files

**Secret file** (`identity.key`), text, three lines, newline-terminated:

```
newnet-secret-v1
alice
0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
```

(line 3 is the secret in lowercase hex, 64 characters; the example is a test vector, never a real key).

**Public line** (what a person shows and sends), one line:

```
newnet1 <name> <key-hex-64> <check-hex-8> [expires=<unix-seconds>]
```

`check` = first 4 bytes of `SHA-256("NEWNET-PUB1" || name || 0x00 || key)` in hex. It catches typos and truncation, not attackers. Test vector: name `alice`, key = bytes 0x01..0x20 gives

```
newnet1 alice 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 26098c0f
```

**Fingerprint** (for comparing out of band by voice or screen): `SHA-256(key)` first 16 bytes, hex, in 8 groups of 4 separated by spaces. Same vector: `ae21 6c2e f524 7a37 82c1 35ef a279 a3e4`.

**Peers file** (`peers`): one public line per peer; blank lines and lines starting with `#` ignored. At most 1024 lines (bounds the table). Duplicate names or duplicate keys are a load error. A line whose `expires` is in the past at load time is skipped and reported on stderr.

### 3.3 Commands (new binary `newnet-keys`)

```
newnet-keys gen --name <name> [--file <path>]      create the secret file; refuse if it exists; print the public line and fingerprint
newnet-keys show [--file <path>]                   print the public line and fingerprint
newnet-keys add-peer --peers <path> --line "<public line>" [--replace]
newnet-keys list --peers <path>                    print name, fingerprint, expiry per peer
```

Workflow: on each machine `gen`; `show`; carry the line to the other machine (type it, `scp`, paste into chat; it is public); read the fingerprints aloud or compare on both screens; `add-peer`. Then `udpfile ... --identity <secret file> --peers <peers file>`. `add-peer` re-parses the line and refuses a bad checksum; a name already present with a different key is refused unless `--replace`.

### 3.4 Storage and permissions

Default secret path: Linux `$XDG_CONFIG_HOME/newnet/identity.key`, else `~/.config/newnet/identity.key`; Windows `%APPDATA%\newnet\identity.key`. Directory created if absent.

- **Linux**: `OpenOptions::new().write(true).create_new(true).mode(0o600)` (the mode is set at creation, so there is no window with wider permissions). On load, the file's mode `& 0o077 != 0` returns `KeyError::PermissionsTooOpen` and the node does not start (same rule as OpenSSH). The parent directory is created with mode 0700.
- **Windows**: `create_new(true)`, then run `icacls "<path>" /inheritance:r /grant:r "%USERNAME%:F"` via `std::process::Command` (no new crate). If icacls fails or exits non-zero, delete the file and return `KeyError::Io`. Load on Windows does not check the ACL (stated limit; the file lives in the user's profile).
- Both: never overwrite (`create_new` fails with `Exists`). The secret is never printed by `show`, never logged, and never put on a command line. The in-memory secret is not zeroized (limit).

### 3.5 Names, pinning, expiry, rotation

- Names map to keys only through the peers file. There is no lookup service in the real path. `Node::add_peer(&PeerLine)` inserts a `PeerRecord` into `records`.
- Pinning: the peers file IS the pin. The in-memory `PinStore` is pre-satisfied by the first `resolve`; a changed file takes effect only at the next process start (no live reload), so a key can never change under a running node.
- An unknown name, or a known name with a different key, is refused after the two DH operations of message 1 (the static key is only readable after the first DH). This is the allowlist: only people whose lines were imported can create half-open or session state (sections 4 and 9).
- Expiry: `expires=` is checked ONLY at file load, in unix seconds. A node that runs past a line's expiry keeps trusting it until restart (stated limit).
- Rotation: a flag day. The owner runs `gen` under the same name (after moving the old file aside), sends the new line to every peer; each peer runs `add-peer --replace` and restarts. There is no overlap period (open question 6). The old key stops working at the peer's restart.

---

## 4. Handshake cookie

### 4.1 When it is demanded

**Always**, for every HANDSHAKE1, including retransmissions. There is no load threshold and no load state. Cost: one extra round trip per connect, and two extra datagrams (a 40-byte COOKIE and a repeated HANDSHAKE1). Gain: there is nothing to tune and nothing to get subtly wrong. (Open question 1.)

### 4.2 Cookie MAC

```
cookie = HMAC-SHA256(secret32, "NEWNET2-COOKIE" || src_key[19] || conn_id u64 LE)[0..16]
```

`src_key` (19 bytes) is the claimed source address of the datagram: byte 0 = family (4 or 6), bytes 1..17 = the IP address (IPv4 as 4 bytes then 12 zero bytes), bytes 17..19 = port, big-endian. For the lab hub, `src_key_lab(addr: u32)` = byte 0 `0`, bytes 1..5 = addr big-endian, rest zero.

Vector: secret = 32 zero bytes, src_key = IPv4 10.0.0.1 port 4002 (`04 0A 00 00 01` then 12 zero bytes then `0F A2`), conn_id = `0x0102030405060708` (little-endian bytes `08 07 06 05 04 03 02 01`):

```
cookie = 4066a83b52d0598b20ebf777341ab3e7
```

Verification uses `Mac::verify_truncated_left` (constant time), never `==`.

### 4.3 Secrets and rotation

Two secrets: `cur` and `prev`. Both 32 bytes from `OsRng`. Rotation (`rotate_if_due(now)`): when `now >= born + 60_000` ticks (60 s), `prev = cur`, `cur = fresh random`, `born = now`. A cookie is accepted if it matches `cur` or `prev`; it therefore lives 60 to 120 seconds. New secrets are made at process start, so cookies never survive a restart. Rotation is checked at the top of every HANDSHAKE1 (no timer thread).

### 4.4 Responder behaviour (order matters; each line is cheaper than the next)

1. `wire::decode` OK, type 0.
2. Datagram length outside 147..=210: drop, count `hs1_bad_size`, no reply.
3. `rotate_if_due(tick)`; `check(src_key, conn_id, body[0..16])`. If it fails (including all-zero): reply COOKIE with `make(src_key, conn_id)`, count `cookies_sent`, return. **No budget is charged, no table is touched, no DH is done.**
4. conn_id already a live session: drop (as v1).
5. conn_id in half-open and `body[16..] == stored noise bytes`: resend stored HANDSHAKE2 (72 bytes), free. Different bytes: drop.
6. Budget (charged only now; section 8): per source 4 per 20-tick epoch, 64 per epoch in total.
7. Noise message 1, name lookup, key equality, stamp, per-peer caps, half-open insert (as v1 plus step 5 of the plan).

The half-open entry stores the Noise bytes only (not the cookie).

### 4.5 Initiator behaviour

`start_attempt` builds the Noise message 1 once and stores it (`noise: Vec<u8>`) and sends HANDSHAKE1 with a zero cookie. On a COOKIE datagram: accept only if the conn_id matches a pending attempt, body length is 16, the datagram came from the address the attempt was sent to (when known), and fewer than `COOKIE_ACCEPT_MAX = 2` cookies were accepted for this attempt. Then rebuild the datagram with the cookie, store it as the attempt's resend datagram, reset the resend timer, and return it. The existing resend policy (3 identical resends, then a new attempt with new ephemeral, conn_id and stamp, 3 attempts) applies to whatever the current datagram is. A new attempt starts again with a zero cookie.

### 4.6 Amplification bound

Smallest legal HANDSHAKE1 is 147 bytes; the reply to it is a 40-byte COOKIE: ratio **40/147 = 0.27**. The largest reply to any HANDSHAKE1 is the 72-byte HANDSHAKE2 (cached resend, needs a valid cookie) for a request of at least 147 bytes: ratio 0.49. Both are below 1, so the responder can never be used to send more bytes than the spoofer sent. Number of replies: at most one per received datagram.

### 4.7 Interaction with other tables and fields

- **Half-open table (64 entries, TTL 400 ticks)**: entered only after cookie + Noise + known key + stamp. A forged-source sender never reaches it. An enrolled peer is capped at 2 entries by name (section 8, step 5).
- **Stamp**: unchanged check (`stamp > last_stamp[name]`), plus a floor at process start (step 5). It runs after the cookie and after the two DH operations.
- **Prologue**: `NEWNET2 || conn_id`; the cookie is outside it.
- **Budgets**: charged after the cookie check. This is what makes the per-source budget meaningful on UDP: the source address in a charged message is one that could receive the COOKIE.
- **Lab/hub**: `on_datagram_from(from, bytes, tick)` stays and calls the new `on_datagram_src(from, &src_key_lab(from), bytes, tick)`, so the in-memory lab also does the cookie round.

---

## 5. Loss detection

Packet-number scheme in the style of RFC 9002, reduced. The crate's tick is the clock; the sender stamps each tracked packet with the tick at which it was sealed.

### 5.1 What is ack-eliciting

STREAM and PING. ACK, CLOSE and DGRAM are not. Only ack-eliciting packets are tracked by the sender.

### 5.2 Receiver: what to ACK and when

State per session: `unacked: u32` (ack-eliciting packets received since the last ACK sent), `ack_deadline: u64`, `last_ack_tick: Option<u64>`, `recv_largest_time: u64` (tick `largest` arrived).

- R1: a packet with no ack-eliciting frame never causes an ACK.
- R2: an ack-eliciting packet: `unacked += 1`; if `unacked == 1` set `ack_deadline = now + MAX_ACK_DELAY` (2 ticks).
- R3: send an ACK now if the frame is PING, or `seq != prev_highest + 1` (a gap, or a late packet filling one; the very first packet is never a gap), or `unacked >= ACK_EVERY` (4).
- R4: at every tick, if `unacked > 0` and `now >= ack_deadline`, send an ACK.
- R5: **at most one ACK per session per tick.** If R3 or R4 fires while `last_ack_tick == Some(now)`, the ACK waits for the next tick. This bounds ACK output to 1000 per second per session (at most 24 + 276 + 16 = 316 bytes each).
- Sending an ACK sets `unacked = 0`, `last_ack_tick = Some(now)`.

ACK contents: `largest` = `window.highest()`; `ack_delay = now - recv_largest_time`; `max_data` (section 6); ranges from `ReplayWindow::ranges(16, 256)`: scan the 256 newest packet numbers below and including `largest` in the replay-window bitmap, newest first, merge consecutive set bits into ranges, return at most 16. (Packets more than 256 behind are not re-reported; the sender will have judged them lost by then. Cost: at most 256 bit tests per ACK.) The bitmap holds every packet number, ACK-only packets included, so ranges can name packets the sender never tracked as ack-eliciting; 5.4 step 2 ignores numbers with no SentPacket.

### 5.3 Sender: state

```
struct SentPacket { seq: u64, sent: u64, bytes: u16, chunk: Option<(u32, u64)> }   // (stream, offset)
sent: BTreeMap<u64, SentPacket>     // ack-eliciting, unacked, not yet declared lost
largest_acked: Option<u64>
rtt: Rtt
pto_count: u32; pto_base: u64       // pto_base = tick of the latest ack-eliciting send or of the latest ACK progress
```

Chunk bytes stay in the stream's `unacked: BTreeMap<offset, Vec<u8>>` (replacing the v1 `in_flight` map that also carried a sent tick). A chunk is removed from there only when some packet carrying it is acknowledged.

### 5.4 On receiving an ACK frame

1. Sanity: if `largest >= tx_seq` (acknowledges a packet number never sent), drop the frame, count `bad_ack`. Same for any range with `end >= tx_seq`.
2. For every `SentPacket` whose seq lies in any range: remove it; if it has a chunk, remove that chunk from the stream's `unacked` (if still there); update congestion state (section 7) — for data packets only: a PING's bytes were never added to `bytes_in_flight`, so a PING entry takes no controller call. Collect `newly_acked`.
3. If `newly_acked` is non-empty: `pto_count = 0`, `pto_base = now`. If the packet `largest` is among `newly_acked`: take an RTT sample (5.5). `largest_acked = max(largest_acked, largest)`.
4. `send_limit = max(send_limit, frame.max_data)` (section 6). Mark the session `confirmed` (already done by `open_data`).
5. Run `detect_lost(now)` (5.6).

### 5.5 RTT (all in ticks, integer arithmetic)

```
sample = now - sent_tick(largest)
ack_delay = min(frame.ack_delay, 25)                       // clamp: a peer cannot claim a huge delay
adj = if sample >= min_rtt + ack_delay { sample - ack_delay } else { sample }
first sample:  srtt = sample; rttvar = sample / 2; min_rtt = sample
later:         min_rtt = min(min_rtt, sample)
               rttvar = (3 * rttvar + |srtt - adj|) / 4
               srtt   = (7 * srtt + adj) / 8
latest = sample
pto        = srtt + max(4 * rttvar, 2) + MAX_ACK_DELAY
loss_delay = max(9 * max(srtt, latest) / 8, 1)
before the first sample: srtt = INITIAL_RTT (100), rttvar = 50, latest = 100
```

Worked vector: first sample 100: srtt 100, rttvar 50. Second sample 200 with ack_delay 0: rttvar = (150 + 100)/4 = 62, srtt = (700 + 200)/8 = 112, pto = 112 + 248 + 2 = 362, loss_delay = 9 * 200 / 8 = 225. Resolution is 1 ms: on a LAN with RTT under 1 ms the estimate is 0 or 1 ticks; the floors above (2, 1) keep timers sane. This is a stated limit on LAN pacing accuracy.

### 5.6 `detect_lost(now)` — when is a packet lost

A tracked packet p is lost iff `largest_acked` exists, `p.seq < largest_acked`, and either `largest_acked - p.seq >= 3` (PACKET_THRESHOLD) or `now >= p.sent + loss_delay`. Iterate `sent` from the smallest seq upward and stop at the first packet that is not lost: both conditions are monotone in seq, so this is O(lost + 1) per call. A reordering of up to 2 packets therefore never causes a retransmission.

`mark_lost(seq)`: remove from `sent`; for a data packet, subtract its bytes from `bytes_in_flight` (section 7) and call the controller's `on_lost` (a PING takes neither); if it has a chunk and the stream still holds that offset in `unacked`, push `(stream, offset)` onto `retx_queue` (a VecDeque, served before new chunks). If the chunk is no longer in `unacked`, nothing is queued (a copy was already acknowledged).

`detect_lost` is called after every ACK and on every tick.

### 5.7 Timers

- **Loss time**: covered by calling `detect_lost(now)` each tick.
- **PTO** (tail loss, no ACK): if `sent` is non-empty, or the session is credit-blocked (`wants_credit`, section 6), and `now >= pto_base + (pto << min(pto_count, 6))` (the shift binds tighter than the add): send one PING (exempt from the congestion window and pacer), `pto_count += 1`, `pto_base = now`. The PING's ACK arrives later than the stuck packets, and 5.6 then declares them lost. (This costs one RTT more than a QUIC data probe and has one mechanism instead of two.)
- **Unconfirmed initiator**: if `!confirmed` and `pto_count >= PING_RESENDS (5)`: session state Closed (removed by the node). This replaces the v1 `ping_sent`/`pings` fields.
- **Persistent congestion**: `pto_count >= 3` makes the controller reset to `MIN_CWND` (section 7).
- Idle timeout (12 000 ticks) and keepalive (after 4 000 ticks, a PING) are unchanged in meaning; with the PING now answered by an ACK, `last_heard` still refreshes on any authenticated packet.

### 5.8 How stream data is retransmitted

By re-sending the same `(stream, offset, bytes)` in a new packet with a new seq (never the same seq). The receiver's `StreamRx` already de-duplicates by offset. The v1 mechanisms `StreamTx::timeout`, `StreamTx::gap_retransmit` and the per-stream `cum`/`sacks` ACK are deleted. Receiver-side reassembly (`StreamRx::put`) stays.

---

## 6. Flow control

One window for the whole connection. No per-stream window.

### 6.1 Definitions

- Both sides start with `INITIAL_MAX_DATA = CONN_WINDOW = 1 048 576` (1 MiB). No frame carries the initial value.
- Receiver keeps per stream `high` (largest `offset + len` of any accepted STREAM frame), `conn_high = sum of high`, and `consumed` = total bytes the application has taken out of the session (`take_delivered`, `recv_msgs`).
- Receiver limit: `recv_limit = consumed + CONN_WINDOW`. It never decreases.
- Every ACK carries `max_data = recv_limit`.
- Sender keeps `send_limit` (start 1 MiB), raised to the maximum seen in any ACK; and `sent_high = sum over tx streams of next_off` (offsets are assigned when bytes are accepted into the queue).

### 6.2 Sender API and backpressure

```rust
Session::queue_stream_bytes(&mut self, stream: u32, bytes: &[u8], now: u64) -> (usize, Vec<Frame>)
// accepted = min(bytes.len(), send_limit - sent_high (saturating), SEND_BUF_MAX - tx_buffered)
// Only the accepted prefix gets offsets and is queued. Returns the frames released now.
Node::send_bytes(conn, stream, bytes, tick) -> (usize, Vec<Vec<u8>>)
UdpEndpoint::send_bytes(conn, stream, bytes) -> usize          // accepted
```

The caller keeps the unaccepted tail and offers it again later. `tx_buffered` = bytes in `send_queue` + bytes in all streams' `unacked` (SEND_BUF_MAX = 4 MiB). If `accepted < bytes.len()` because of credit, set `wants_credit = true`; clear it when `send_limit` rises. The PTO machinery (5.7) then sends PINGs while blocked, so a lost window update is recovered by the next PING's ACK.

### 6.3 Receiver accounting and violations

On a STREAM frame, before touching any state: `new_high = max(stream.high, off + len)` (checked add); `delta = new_high - stream.high`; violation if `conn_high + delta > recv_limit`, or the stream is new and there are already `MAX_STREAMS (1024)` streams, or `off > expected + 16 MiB` (kept), or the out-of-order buffer already holds `MAX_RX_BUFFERED (2048)` chunks and this chunk is not in order.

**A violation closes the session** (state Closed, no CLOSE frame, count `flow_violations`). Reason: in the v1 scheme a refused STREAM frame simply got no ACK, so the sender retransmitted. With packet-number ACKs the packet carrying the frame would be acknowledged even though its data was refused, which would be silent data loss. A conforming sender cannot trigger any of these checks: its in-flight chunks are at most 1024 (so out-of-order at most 1024 < 2048), it respects `send_limit <= recv_limit`, and it uses few streams.

### 6.4 Window updates

Updates ride in ACKs (R3/R4 above). Additionally, in the per-tick timer: if `recv_limit - last_advertised >= CONN_WINDOW / 4` an ACK is sent even with `unacked == 0`. (It obeys R5.) `last_advertised` is the `max_data` of the last ACK sent.

### 6.5 Memory bound per session (receive side)

Unread delivered bytes plus out-of-order bytes are at most `recv_limit - consumed = 1 MiB`. Out-of-order chunk overhead: at most 2048 entries * about 100 bytes = 0.2 MiB. Streams: at most 1024 * about 150 bytes = 0.15 MiB. DGRAM queue: `DGRAM_IN_MAX = 256` entries (was 10 000) * at most 1150 bytes = 0.3 MiB. Total about 1.7 MiB per session. With `MAX_SESSIONS = 64` (step 5): about 110 MiB per node worst case.

### 6.6 Defaults

Window 1 MiB: larger than the bandwidth-delay product of a 1 Gbit/s link at 5 ms (about 600 KiB), so a LAN transfer is never credit-limited, and small enough to bound memory. `SEND_BUF_MAX` 4 MiB. Both are constants (no negotiation).

---

## 7. Congestion control, pacing, per-destination queues

### 7.1 Controller (`cc.rs`, NewReno in bytes, RFC 9002 section 7 shape)

State: `cwnd`, `ssthresh`, `bytes_in_flight`, `recovery_seq: Option<u64>`.

- Constants: MSS 1200, INITIAL_CWND 12 000 (10 packets), MIN_CWND 2 400, MAX_CWND 1 228 800 (1024 packets, half the replay window, so a packet in flight can never fall out of the peer's window by in-flight count alone).
- `can_send(bytes)`: `bytes_in_flight + bytes <= cwnd`.
- `on_sent(bytes)`: `bytes_in_flight += bytes` (STREAM packets only; PING probes are exempt).
- `on_acked(bytes, seq)`: `bytes_in_flight -= bytes`; if `recovery_seq` is Some(r) and `seq <= r`: stop (no growth during recovery). If `cwnd < ssthresh`: `cwnd += bytes`; else `cwnd += max(1, MSS * bytes / cwnd)`. Clamp to MAX_CWND.
- `on_lost(bytes, seq, next_seq)`: `bytes_in_flight -= bytes`; if `recovery_seq` is None or `seq > r`: `ssthresh = max(cwnd / 2, MIN_CWND)`, `cwnd = ssthresh`, `recovery_seq = Some(next_seq - 1)`. A loss of a packet sent before recovery began does not cut again. This uses packet numbers as the epoch, so no extra clock. `next_seq` = the smallest packet number greater than `seq` that has been sent or will be sent: the smallest tracked seq above `seq`, else `tx_seq` (tail loss: the epoch starts at the next packet, so `recovery_seq = tx_seq - 1` cuts nothing further until a later loss with `seq > recovery_seq`).
- `on_persistent()`: `cwnd = MIN_CWND`, `recovery_seq = None`.
- Slow start initial `ssthresh = u64::MAX`.

Known weaknesses (stated): cwnd grows while the application is the limit (no app-limited rule); DGRAM bypasses the controller; an optimistic-ACK receiver is limited only by MAX_CWND (section 9).

### 7.2 Pacer (`pacer.rs`, token bucket in bytes)

```
rate_per_tick = cwnd * 2 / max(srtt,1)      while cwnd < ssthresh
              = cwnd * 5 / (4 * max(srtt,1)) otherwise
tokens = min(PACER_BURST, tokens + rate_per_tick * (now - last))      // PACER_BURST = 12 000
send a packet of `bytes` only if tokens >= bytes; then tokens -= bytes
```

Before the first RTT sample `srtt = 100`, so the first window leaves as an initial burst (12 000 bytes) then at 240 bytes per tick until the first ACK. Pacing applies to STREAM packets (new and retransmitted). `Session::flush(now)` is the only place that releases STREAM frames, and it is called from the tick timer and after every ACK, so a blocked flush is retried within one tick. A lab/test switch `Session::set_pacing(false)` exists.

### 7.3 Flush order (one function, one place)

```
flush(now): loop {
   pick next = retx_queue.front() (skip entries no longer in unacked) else send_queue.front(); none -> break
   bytes = 24 + 13 + chunk.len() + 16
   if !cc.can_send(bytes) or !pacer.try_take(bytes): break
   pop; seal; record SentPacket; cc.on_sent(bytes)
}
```

### 7.4 Per-destination outgoing queues (`outq.rs`, used by `udp.rs`)

Replaces the single `VecDeque` capped at 8192.

- `queues: HashMap<Addr, VecDeque<(SocketAddr, Vec<u8>)>>` and `ring: VecDeque<Addr>` (destinations with a non-empty queue, in service order).
- `push(addr, has_session, sa, dgram) -> bool`: cap `MAX_OUT_PER_PEER = 256` datagrams if the destination has a session, else `MAX_OUT_UNKNOWN = 4` (COOKIE and HANDSHAKE2 replies to addresses that may be forged). Over cap: drop, count `dropped_out`. A destination entering with an empty queue is appended to `ring`.
- `pop_next()`: take the front destination from `ring`, pop one datagram from its queue, push the destination back to the ring end if its queue is still non-empty, else remove the (empty) queue entry.
- Egress ceiling `MAX_DGRAMS_PER_TICK = 64` per endpoint (about 77 MB/s at 1200 bytes; a safety ceiling for the OS, raise later). It replaces BURST 32 per 20 ms.
- Worst-case memory: 64 sessions * 256 * 1200 = 19.7 MB, plus 4096 unknown addresses * 4 * 72 bytes = 1.2 MB (replies to unknown addresses are at most 72 bytes).
- Fairness: with n non-empty destinations each is served once per n pops, so a flooding peer gets at most `1/n` of the egress and cannot occupy anyone else's queue.

---

## 8. Constants

Time constants are in ticks of 1 ms (after step 1). "Was" is the v1 value in 20 ms ticks.

| Constant | Value | Reason |
|---|---|---|
| VERSION | 2 | one bump for everything |
| TYPE_COOKIE | 3 | one new message type |
| COOKIE_LEN | 16 | 128-bit MAC tag; guess probability 2^-128 |
| SRC_KEY_LEN | 19 | family + 16 address + 2 port |
| COOKIE_ROTATE_TICKS | 60 000 | cookie lives 60 to 120 s; long enough for a slow retry, short enough to limit reuse |
| COOKIE_ACCEPT_MAX | 2 | initiator accepts at most 2 cookies per attempt; bounds a forged-cookie loop |
| HS1 min / max datagram | 147 / 210 | from the layout in 2.2; makes the 0.27 ratio checkable |
| NAME_MAX | 64 | bounds HS1 size |
| TICK_MS | 1 (was 20) | RTT on a LAN is under 20 ms |
| HS resend timeout (TIMEOUT_TICKS) | 500 (was 25) | same 500 ms |
| HS_RESENDS / HS_ATTEMPTS | 3 / 3 | unchanged |
| HALF_OPEN_TTL | 400 (was 20) | same 400 ms |
| MAX_HALF_OPEN | 64 | unchanged |
| MAX_HALF_OPEN_PER_PEER | 2 | an enrolled peer cannot fill the table; one retry plus one in flight |
| BUDGET_EPOCH_TICKS | 20 | budgets stay "per 20 ms" |
| Handshake budget per source / global per epoch | 4 / 64 | unchanged, now charged after the cookie |
| STAMP_FLOOR_SLACK_MS | 300 000 | replayed message 1 older than 5 minutes before a restart is refused; clock skew up to 5 minutes tolerated |
| MAX_SESSIONS / MAX_SESSIONS_PER_PEER | 64 / 4 | bounds memory (6.5); a restarting peer evicts its own oldest |
| IDLE_TTL | 12 000 (was 600) | same 12 s |
| KEEPALIVE_AFTER | 4 000 (was 200) | IDLE_TTL / 3 |
| REPLAY_WINDOW, MAX_LOOKAHEAD, KEY_ROTATION_INTERVAL | 2048, 2^20, 1000 | unchanged |
| CHUNK | 1100 | unchanged; 1153-byte datagram |
| PACKET_THRESHOLD | 3 | tolerates reordering of 2; RFC 9002 value |
| TIME_THRESHOLD | 9/8 * max(srtt, latest), floor 1 | RFC 9002 value |
| INITIAL_RTT | 100 | conservative before any sample |
| MAX_ACK_DELAY | 2 | small against LAN and WAN RTT |
| ACK_DELAY_CLAMP | 25 | a peer cannot inflate the delay adjustment |
| ACK_EVERY | 4 | ACK datagrams are 25% of data datagrams, not 50% |
| ACK_SCAN | 256 | bounds work per ACK |
| MAX_ACK_RANGES | 16 | 276-byte frame at most |
| PTO backoff cap | 2^6 | 64x |
| PING_RESENDS | 5 | unconfirmed initiator closes after 5 PTOs |
| MSS, INITIAL_CWND, MIN_CWND | 1200, 12 000, 2 400 | RFC 9002 shapes at our datagram size |
| MAX_CWND | 1 228 800 | 1024 packets; half the replay window |
| PACER_BURST | 12 000 | 10 packets |
| CONN_WINDOW | 1 048 576 | section 6.6 |
| SEND_BUF_MAX | 4 194 304 | bounds sender buffering |
| MAX_STREAMS | 1024 (was 16 384) | memory bound 6.5 |
| MAX_RX_BUFFERED | 2048 | unchanged |
| MAX_OFFSET_AHEAD | 16 MiB | unchanged (now redundant with the window, kept as a second check) |
| DGRAM_IN_MAX | 256 (was 10 000) | memory bound 6.5 |
| MAX_OUT_PER_PEER / MAX_OUT_UNKNOWN | 256 / 4 | section 7.4 |
| MAX_DGRAMS_PER_TICK | 64 | egress ceiling |
| MAX_RECV_PER_POLL | 256 | unchanged |
| MAX_PEERS (address slots) | 4096 | unchanged |
| Peers file lines | 1024 | bounds the record table |

Removed: `MAX_IN_FLIGHT` 512 chunks (replaced by the congestion window and MAX_CWND), `MAX_SACKS`, `BURST`, `MAX_OUT` 8192.

---

## 9. Security analysis

Notation: "per packet sent" means per datagram the adversary sends.

### 9.1 Off-path forger (can spoof any source address, cannot receive replies sent to it)

| Attack | What stops it | Bound |
|---|---|---|
| Flood of HANDSHAKE1 with forged sources | cookie check first (4.4 step 3) | Per packet: 1 HMAC-SHA256 over 41 bytes (under 1 microsecond) and at most one 40-byte reply. No DH, no table entry, no budget charge. DH work caused: 0. |
| Reflection onto a victim | reply smaller than request | 40/147 = 0.27 bytes out per byte in. Total COOKIE output of a node is capped by the egress ceiling: 64 datagrams per ms * 40 bytes = 2.56 MB/s, shared over all victims; unknown-destination queues hold 4 datagrams each. |
| Starving real peers' handshakes (v1: 3 200 forged messages per second) | budgets charged only after a valid cookie | Forged traffic charges 0 of the 64 per 20 ms. Real peers are unaffected by forgery. |
| Guess a cookie | 128-bit tag | 2^-128 per guess, per (address, conn_id). |
| Forge a COOKIE or HANDSHAKE2 to an initiator | needs the 64-bit random conn_id of a live attempt | 2^-64 per packet. Effect if guessed: at most 2 wrong cookies per attempt, then the resend/new-attempt logic runs. A forged HANDSHAKE2 fails Noise authentication and does not end the attempt (unchanged). |
| Forge DATA | AEAD under a per-direction key | unchanged; a conn_id lookup miss costs one hash lookup; `too_far` check runs before key derivation. |

### 9.2 On-path observer / active attacker (can read, drop, modify, and receive at its own addresses)

- **Reads**: sees the 24-byte header, sizes, timing, cookies (they are bound to the sender's address and lifetime 60 to 120 s). Payloads, stream ids, offsets, ACK contents and the initiator's name are encrypted (the name is inside the Noise payload; the initiator static key is encrypted to the responder's static key).
- **Drops / delays**: can stop any connection; nothing here prevents denial by an on-path attacker.
- **Modifies**: any change to a DATA packet or HANDSHAKE2 fails authentication. COOKIE is unauthenticated: an on-path attacker can substitute a bad cookie, which costs the initiator one resend; he could equally drop packets.
- **Own-address handshakes**: he gets a valid cookie for his own address and can then make the responder do 2 DH operations per message, up to 4 per 20 ms per source and 64 per 20 ms in total, which is at most 200 per second per address and 3 200 per second per node. At the assumed 150 microseconds per message this is at most about 0.5 of one core when 16 or more such addresses are used. **Open: an attacker controlling at least 16 reachable addresses can keep new handshakes from completing** (existing sessions are unaffected). An unknown static key is refused after the DH work and creates no state.
- **Downgrade**: none exists (one suite, one version).
- **Replayed handshake**: see 9.4.

### 9.3 Authenticated but misbehaving peer (holds an enrolled key)

| Resource | Bound |
|---|---|
| Sessions | 4 per peer name (a new one closes that peer's oldest), 64 per node. Half-open: 2 per peer name. |
| Receive memory per session | about 1.7 MiB (6.5), regardless of whether the application reads. |
| Send memory | at most 4 MiB of application bytes buffered per session, and only if the application queues them. |
| Streams | 1024 per session. A 1025th closes the session. |
| Credit overrun, offset overrun, buffer overrun | closes that session; counted in `flow_violations`. |
| Output we are made to produce | at most 1 ACK per tick per session (316 bytes) = 316 kB/s per session worst case; per-destination queue 256 datagrams. |
| Starving other peers on egress | no: round-robin over destinations (7.4). A peer that never reads or never ACKs only fills its own 256-datagram queue. |
| Lying about RTT | `ack_delay` clamped to 25 ticks. |
| ACK for packets never sent | frame dropped, `bad_ack` counted. |
| Optimistic ACKs (acking packets not received) | **Open.** Our sender then runs at up to MAX_CWND (1.2 MB in flight) and the egress ceiling; the only victim is the path to that peer. No packet-number skipping is implemented. |
| Receive CPU | **Open.** One peer sending at line rate uses CPU for decryption; only `MAX_RECV_PER_POLL` 256 per poll bounds the work between timer runs. No per-peer ingress rate limit. |
| Slow reader on one stream | **Open.** Connection-level credit means one unread stream can use all 1 MiB and stall every other stream of that peer on that session (not other peers). |
| Unreliable datagrams | not congestion-controlled; inbound queue at most 256 entries. |

### 9.4 Restarted or replaying peer

- **Replayed HANDSHAKE1 against a running responder**: the stamp must exceed the last accepted for that name; refused (unchanged, `hs_replay_dropped`).
- **Replayed HANDSHAKE1 after the responder restarts** (the stamp table is lost): the cookie secret is new, so a recorded cookie is useless; the replayer must fetch a cookie for his own address, and the Noise message must pass. Two defences: stamp floor `process_start_epoch_ms - 300 000` (any recording older than 5 minutes before the restart is refused), and, within that window, the replay yields only a half-open entry: no session can follow because the confirming DATA needs keys derived from the initiator's ephemeral secret, which the replayer lacks. Cost to the node: one half-open entry (at most 2 per peer name, 400 ms lifetime) and one 72-byte reply to the replayer's own address. **Open: clocks of the two machines must agree within about 5 minutes**; a peer whose clock is further behind the responder's start time is refused (the error log says "stamp below floor").
- **Replayed DATA**: replay window 2048 per session; new session, new keys.
- **Restarted initiator**: new ephemeral, conn_id and clock-based stamp; the old session ages out after 12 s; `session_with` picks the newest; per-peer cap evicts the oldest.
- **Key compromise**: if a peer's secret leaks, the holder can impersonate it until the peers files are edited and nodes restarted. There is no revocation channel. Forward secrecy: Noise IK ephemerals plus key generations erased as the window passes (unchanged).

### 9.5 What the design does not protect against (summary)

On-path denial of service; an attacker with 16 or more reachable addresses delaying new handshakes; optimistic-ACK senders; per-peer ingress CPU; head-of-line credit stalls between streams; traffic analysis; compromised endpoints or leaked key files; clock skew over 5 minutes (refuses, does not endanger); trust of the first key exchange (the human compare of fingerprints is the only authentication of the key import); keys held in memory unzeroized; Windows key file ACL not re-checked on load.

---

## 10. Implementation plan (14 steps)

Rules for every step: `cargo test` green before and after; one commit; the implementer must run the listed mutation by hand, see the named test fail, and revert. New files carry no new dependencies. Phase 1 (steps 1 to 7) ends at the two-machine milestone; phase 2 (8 to 14) is performance.

### Step 1. Retime: 1 ms ticks, wall-clock values unchanged

- Goal: all tick constants multiplied by 20 so wall-clock behaviour is identical; the endpoint's tick becomes 1 ms.
- Files: `udp.rs`, `node.rs`, `session.rs`, `crypto.rs` (budget epoch only if it lives there), tests that hard-code tick counts.
- API: `udp::TICK_MS = 1`, `udp::TIMEOUT_TICKS = 500`, `node::HALF_OPEN_TTL = 400`, `session::IDLE_TTL = 12_000`, `session::KEEPALIVE_AFTER = IDLE_TTL / 3`, `pub const BUDGET_EPOCH_TICKS: u64 = 20` in `node.rs`; the handshake budget resets when `tick / BUDGET_EPOCH_TICKS` changes; `udp.rs` pacing accounting uses `now / 20` as its epoch (BURST 32 per epoch, unchanged for now).
- Tests to add (`tests/retime.rs`): `idle_ttl_is_twelve_seconds` asserts `IDLE_TTL * TICK_MS == 12_000`, `HALF_OPEN_TTL * TICK_MS == 400`, `TIMEOUT_TICKS * TICK_MS == 500`. `endpoint_tick_is_one_millisecond` binds an endpoint, sleeps 60 ms, asserts `now()` advanced by 55..=120. `budget_epoch_is_twenty_ticks`: 4 handshakes from one source at tick 0 are accepted, a 5th at tick 19 is dropped (`handshake_dropped_budget`), one at tick 20 is accepted.
- Existing tests change: any test that loops a hard-coded number of ticks to wait for a timeout (idle, liveness, half-open reaping, outage) must use the constant or multiply by 20. Rule: mechanical, no logic change.
- Acceptance: `cargo test` green; `udpfile` 5 000 000 bytes over loopback in the same time as before within 20% (it was 2.9 s).
- Mutation: leave `IDLE_TTL` at 600: `idle_ttl_is_twelve_seconds` fails.

### Step 2. Wire v2 header, COOKIE type, prologue, Hello name rule

- Files: `wire.rs`, `noise_ik.rs`, `node.rs` (match arm only).
- API: `wire::VERSION = 2`, `wire::TYPE_COOKIE = 3`, `wire::COOKIE_LEN = 16`, `wire::HS1_MIN_DATAGRAM = 147`, `wire::HS1_MAX_DATAGRAM = 210`, `wire::HS2_DATAGRAM = 72`; `decode` accepts type 3; `noise_ik::PROLOGUE_TAG = b"NEWNET2"`; `decode_hello` returns None for a name of length 0, over 64, or with a character outside `a-z0-9._-`.
- Node: type 3 is ignored for now (`_ => vec![]`).
- Tests to add: `wire.rs`: `version_one_is_refused` (byte 4 = 1 gives BadVersion), `cookie_type_decodes`, `type_four_is_refused`. `noise_ik.rs`: `prologue_is_newnet2_then_conn_id` (exact 15 bytes), `hello_name_rules` (table: "" None, 64 chars Some, 65 None, "Alice" None, "a b" None, "a.b_c-1" Some).
- Existing tests change: `wire::rejects_bad_magic_version_type_len_short` (the bad version byte becomes 1, the bad type 9 stays); anything asserting `VERSION == 1` or the string `NEWNET1`. `noise_vectors.rs` passes its own prologue bytes and should not change; if it uses `PROLOGUE_TAG`, switch it to a literal copy of the vector's prologue.
- Acceptance: all tests green; the lab handshake still completes (type 3 is never sent yet).
- Mutation: leave `VERSION = 1`: `version_one_is_refused` fails.

### Step 3. Cookie module (pure)

- Files: new `cookie.rs`, `lib.rs` (one line).
- API:
```rust
pub const COOKIE_LEN: usize = 16;
pub const SRC_KEY_LEN: usize = 19;
pub const COOKIE_ROTATE_TICKS: u64 = 60_000;
pub type SrcKey = [u8; SRC_KEY_LEN];
pub fn src_key_from_socket(sa: &std::net::SocketAddr) -> SrcKey;
pub fn src_key_lab(addr: u32) -> SrcKey;
pub struct CookieKeys { /* cur, prev: Option<[u8;32]>, born: u64 */ }
impl CookieKeys {
    pub fn new(now: u64) -> CookieKeys;                       // OsRng
    pub fn from_secret_for_test(secret: [u8; 32], now: u64) -> CookieKeys;
    pub fn rotate_if_due(&mut self, now: u64);
    pub fn make(&self, src: &SrcKey, conn_id: u64) -> [u8; COOKIE_LEN];
    pub fn check(&self, src: &SrcKey, conn_id: u64, cookie: &[u8; COOKIE_LEN]) -> bool;
}
```
- Tests to add (in `cookie.rs`): `cookie_matches_published_vector` (the vector in 4.2: zero secret, 10.0.0.1:4002, conn 0x0102030405060708 gives `4066a83b52d0598b20ebf777341ab3e7`); `src_key_layout` (v4 10.0.0.1:4002 equals `04 0A 00 00 01`, 12 zeros, `0F A2`); `cookie_differs_by_source_conn_and_secret`; `every_byte_of_the_cookie_matters` (flip one bit in each of the 16 bytes, `check` false each time); `previous_secret_still_accepted_once` (rotate once: old cookie ok; rotate twice: rejected); `no_rotation_before_sixty_seconds` (rotate_if_due at born+59 999 changes nothing; at born+60 000 it does).
- Existing tests change: none.
- Acceptance: unit tests green; no other file changes behaviour.
- Mutations: compare only the first 8 bytes: `every_byte_of_the_cookie_matters` fails. Leave conn_id out of the MAC: `cookie_differs_by_source_conn_and_secret` fails. Never drop `prev`: `previous_secret_still_accepted_once` fails. Rotate at 59 999: `no_rotation_before_sixty_seconds` fails.

### Step 4. Cookie in the node (both sides) and in the endpoint

- Files: `node.rs`, `udp.rs`, `noise_ik.rs` (none), test helper `tests/common/mod.rs` (new).
- API:
```rust
Node::on_datagram_src(&mut self, from: Addr, src: &SrcKey, bytes: &[u8], tick: u64) -> Vec<Vec<u8>>
Node::on_datagram_from(&mut self, from: Addr, bytes: &[u8], tick: u64) -> Vec<Vec<u8>>   // = on_datagram_src(from, &src_key_lab(from), ..)
Node::set_cookie_secret_for_test(&mut self, secret: [u8; 32], now: u64)
pub struct NodeStats { + cookies_sent, + cookies_received, + hs1_bad_size }
```
  Node gets `cookies: CookieKeys`. Responder order exactly as 4.4. Initiator: `PendingInit` gains `noise: Vec<u8>`, `cookies_accepted: u8`; handling of type 3 as 4.5. `udp.rs` passes `src_key_from_socket(&src)`. `tests/common/mod.rs` provides `fn complete_cookie_round(a: &mut Node, b: &mut Node, hs1: Vec<u8>, from: Addr) -> Vec<u8>` returning the HANDSHAKE1 that carries a valid cookie.
- Tests to add (`tests/cookie_handshake.rs`):
  1. `hs1_without_cookie_gets_cookie_and_no_work`: reply count 1, type 3, length 40, `dh_count == 0`, `half_open_count() == 0`, `handshake_dropped_budget == 0`.
  2. `cookie_reply_is_smaller_than_request`: for a 147-byte and a 210-byte HANDSHAKE1, reply length < request length (40 < 147).
  3. `cookie_is_bound_to_source`: cookie obtained at address 5, used from address 6: another COOKIE, `dh_count == 0`.
  4. `cookie_is_bound_to_conn_id`: cookie reused on an HS1 with a different conn_id: COOKIE again.
  5. `handshake_with_cookie_round_completes`: via the lab hub, connect; the datagram sequence seen is HS1, COOKIE, HS1, HS2, DATA(PING), DATA(ack); session open on both sides.
  6. `forged_flood_does_not_consume_budget`: 10 000 zero-cookie HS1s from 10 000 different source keys in one tick, then one real handshake: succeeds, `handshake_dropped_budget == 0`, `dh_count == 4`(real only).
  7. `cookie_expires_after_two_rotations` (ticks 0, 60 000, 120 000).
  8. `initiator_ignores_bad_cookies`: COOKIE for an unknown conn_id, COOKIE from a wrong address, COOKIE with 15-byte body, and a third accepted COOKIE for one attempt: all ignored (resend datagram unchanged); a real COOKIE after those still works.
  9. `replayed_hs1_with_valid_cookie_from_same_source_resends_hs2_for_free` (cached HS2, `dh_count` unchanged).
- Existing tests change: tests that hand-build a HANDSHAKE1 with `wire::encode` (the garbage-handshake and budget tests in `udp_hardening.rs`, `scoreboard_gaps.rs`, `peer_identity.rs`, `peer_limits.rs`; the hub-based demo step "budget" in `demo.rs`) must prefix 16 cookie bytes, using the helper, or count `cookies_sent` instead of `auth_fails`. Tests that count datagrams of a handshake gain two.
- Acceptance: the whole suite green; loopback `udpfile` works; lab handshake costs exactly 2 more datagrams than before (assert in test 5).
- Mutations: do the Noise read before the cookie check: test 1 (`dh_count == 0`) fails. Charge the budget before the cookie check: test 6 fails. Leave the source out of the MAC: test 3 fails. Pad the COOKIE reply to 150 bytes: test 2 fails. Accept unlimited cookies: test 8 fails.

### Step 5. Responder limits: stamp floor, per-peer caps

- Files: `node.rs`, `udp.rs` (one call at bind).
- API: `Node::set_stamp_floor(&mut self, floor: u64)`; `UdpEndpoint::bind` calls `set_stamp_base(epoch_ms)` and `set_stamp_floor(epoch_ms.saturating_sub(300_000))`; constants `MAX_HALF_OPEN_PER_PEER = 2`, `MAX_SESSIONS = 64`, `MAX_SESSIONS_PER_PEER = 4`; new stats `hs_stamp_floor_dropped`, `half_open_evicted`, `sessions_refused_full`, `sessions_evicted_peer`.
  Rules: stamp must exceed `max(last_stamp[name], floor)`. After a successful message 1, if the name already has 2 half-open entries, remove the oldest of those two, then insert. When a new session would be created (first DATA on a half-open entry, or HANDSHAKE2 on an initiator): if that peer name already has 4 sessions, close the one with the smallest `last_heard` first; if the node has 64 sessions, drop the packet and count `sessions_refused_full`.
- Tests to add (`tests/responder_limits.rs`): `stamp_below_floor_is_refused` (floor 1000, stamp 999 refused, 1001 accepted); `third_half_open_from_one_peer_evicts_the_oldest` (count stays 2, first conn gone, newest two present); `fifth_session_from_one_peer_closes_its_oldest`; `sixty_fifth_session_is_refused` (63 peers... use 16 peers by 4 sessions each = 64, a 65th refused, `sessions_refused_full == 1`); `restart_with_clock_stamp_passes_and_old_recording_fails` (node restarts with floor = now - 300 s; a stamp from 10 minutes earlier refused).
- Existing tests change: tests that open many sessions to one peer (`peer_limits.rs`, `conn_ids.rs`) must stay within 4 per peer or expect the eviction.
- Acceptance: all green; on the lab, a peer opening 10 sessions in a row ends with 4 open and the newest 4 alive.
- Mutations: compare stamp with `<` instead of `<=` is not this step's; instead drop the floor (`max(.., 0)`): `stamp_below_floor_is_refused` fails. Evict the newest instead of the oldest: `third_half_open...` fails. Raise the per-peer limit to 5: `fifth_session...` fails.

### Step 6. Key files and the peers file (pure plus file IO)

- Files: new `keyfile.rs`, new `peerbook.rs`, `identity.rs` (`Identity::from_secret`), `crypto.rs` (`PeerRecord.ed` becomes `Option<VerifyingKey>`), `node.rs` and `naming.rs` call sites of `.ed` (find with the compiler), `lib.rs`.
- API:
```rust
// keyfile.rs
pub enum KeyError { BadName, BadFormat, BadChecksum, Io(String), PermissionsTooOpen, Exists, DuplicateName, DuplicateKey, TooManyPeers }
pub struct KeyFile { pub name: String, pub secret: [u8; 32] }
pub fn valid_name(s: &str) -> bool;
pub fn generate(name: &str) -> Result<KeyFile, KeyError>;
pub fn encode_secret_file(k: &KeyFile) -> String;
pub fn decode_secret_file(text: &str) -> Result<KeyFile, KeyError>;
pub fn save_new(path: &Path, k: &KeyFile) -> Result<(), KeyError>;
pub fn load(path: &Path) -> Result<KeyFile, KeyError>;
pub fn public_of(secret: &[u8; 32]) -> [u8; 32];
pub fn fingerprint(public: &[u8; 32]) -> String;
pub fn default_key_path() -> PathBuf;
// peerbook.rs
pub struct PeerLine { pub name: String, pub key: [u8; 32], pub expires: Option<u64> }
pub fn format_pub_line(l: &PeerLine) -> String;
pub fn parse_pub_line(s: &str) -> Result<PeerLine, KeyError>;
pub fn load_peers(path: &Path, unix_now: u64) -> Result<(Vec<PeerLine>, Vec<PeerLine>), KeyError>; // (active, expired)
pub fn add_peer(path: &Path, l: &PeerLine, replace: bool) -> Result<(), KeyError>;
// identity.rs
Identity::from_secret(secret: [u8; 32]) -> Identity
// node.rs
Node::from_identity(name: &str, ident: Identity) -> Node
Node::add_peer(&mut self, l: &PeerLine)
```
- Tests to add: `keyfile.rs`: `secret_file_round_trip_and_vector` (the 3-line example); `bad_names_refused` (table: "", 65 chars, "A", "a b", "a/b", "../x"); `public_line_matches_vector` (the alice line with `26098c0f`) and `fingerprint_matches_vector` (`ae21 6c2e f524 7a37 82c1 35ef a279 a3e4`); `any_changed_hex_digit_breaks_the_checksum` (loop over all 64 key positions and the 8 check positions, each flipped to another hex digit: `BadChecksum`); `save_new_never_overwrites` (second call returns `Exists`, file bytes unchanged); `#[cfg(unix)] save_new_creates_mode_0600` and `#[cfg(unix)] load_refuses_group_readable_file` (chmod 0640 gives `PermissionsTooOpen`); `#[cfg(windows)] save_new_restricts_acl` (runs `icacls`, output mentions the current user and no `Everyone`, `Users`, or `Authenticated Users`). `peerbook.rs`: `comments_and_blank_lines_ignored`; `duplicate_name_and_duplicate_key_refused`; `expired_line_is_returned_separately`; `add_peer_refuses_changed_key_without_replace` and `add_peer_replace_swaps_it`; `more_than_1024_lines_refused`. `identity.rs`: `from_secret_is_deterministic_and_public_matches` (public equals `x25519(secret, basepoint)` via `x25519_dalek`). `node.rs`: `node_from_identity_handshakes_with_imported_peer` (two nodes from fresh keys, lines exchanged through `format`/`parse`, handshake completes through the hub; a third node with an unimported key is refused, `auth_fails == 1`, no state).
- Existing tests change: those that construct `PeerRecord { ed: .. }` wrap `ed` in `Some`.
- Acceptance: all green; the secret file produced on Linux has mode 600 (checked in the test); a node built from files completes a lab handshake.
- Mutations: write the file with `create` instead of `create_new` and no mode: `save_new_never_overwrites` and `save_new_creates_mode_0600` fail. Drop the checksum comparison: `any_changed_hex_digit...` fails. Accept `& 0o007` instead of `& 0o077`: `load_refuses_group_readable_file` fails.

### Step 7. `newnet-keys` binary and real identities in `udpfile`; MILESTONE

- Files: new `src/bin/keys.rs`; `src/bin/udpfile.rs`; `Cargo.toml` only if the bin needs a `[[bin]]` entry (it does not under the default layout).
- API: command lines as in 3.3. `udpfile recv --identity <secret> --peers <peers> --listen <addr:port> --out <file>`; `udpfile send --identity <secret> --peers <peers> --peer <name> --to <addr:port> --file <file>`. Seed flags (`--seed`, `--peer-seed`) remain for tests and work **only if every address given is loopback**; otherwise exit code 2 with `lab identities may only be used on loopback`.
- Tests to add (`tests/keys_cli.rs`, using `env!("CARGO_BIN_EXE_newnet-keys")` and `env!("CARGO_BIN_EXE_udpfile")`): `gen_then_show_prints_a_line_add_peer_accepts`; `gen_twice_refuses_and_keeps_the_first_key`; `add_peer_rejects_bad_checksum`; `transfer_with_real_key_files_is_byte_exact` (5 MB, 127.0.0.1, SHA-256 equal); `wrong_peer_key_fails_and_writes_no_output` (sender exits non-zero before the timeout, no `<out>` or `<out>.part` is left); `unknown_sender_is_refused` (a third key not in the receiver's peers file never gets a session; receiver `auth_fails >= 1` logged); `seed_identity_refused_off_loopback` (`--listen 0.0.0.0:0` with `--seed` exits 2).
- Existing tests change: `udpfile_cli.rs` keeps working through the seed flags.
- Acceptance (milestone): the two-machine procedure in section 11.2 passes: 100 MB, SHA-256 equal in both directions, capture shows no plaintext.
- Mutations: skip the loopback check: `seed_identity_refused_off_loopback` fails. Let the receiver accept any key: `unknown_sender_is_refused` fails.

### Step 8. Frame codec v2 and packet-number ACKs (retransmit timer still fixed)

- Files: `streams.rs`, `session.rs`, `node.rs`, `crypto.rs` none, tests.
- API: as 2.6: `pub struct AckInfo { pub largest: u64, pub delay: u16, pub max_data: u64, pub ranges: Vec<(u64, u64)> }`; `pub struct Frame { pub ftype: u8, pub id: u32, pub off: u64, pub data: Vec<u8>, pub ack: Option<AckInfo> }`; `pub fn is_ack_eliciting(ftype: u8) -> bool`; `FrameError::Malformed`; `ReplayWindow::ranges(&self, max_ranges: usize, scan: usize) -> Vec<(u64, u64)>`; `Session::seal_frame(&mut self, frame: &Frame, now: u64) -> Vec<u8>` records a `SentPacket` for ack-eliciting frames; `Session::take_ack(&mut self, now: u64) -> Option<Frame>` implementing R1 to R5; `Session::on_ack(&mut self, a: &AckInfo, now: u64)`; `Session::mark_lost(&mut self, seq: u64)`. `max_data` is written as 1 MiB and ignored until step 10. `StreamTx` keeps `unacked: BTreeMap<u64, Vec<u8>>` plus `last_seq: BTreeMap<u64, u64>`; `StreamTx::timeout`, `gap_retransmit`, `on_ack(cum, sacks)`, `StreamRx::sacks` are removed. Transitional trigger: a tracked packet older than the `timeout` argument is passed to `mark_lost` by `tick_timeouts` (the same function step 9 will drive differently). Node calls `take_ack` after each opened packet and in `tick_sessions`.
- Tests to add: `streams.rs`: `ack_round_trip`; `ack_decode_rejects_each_malformed_case` (table: n = 0, n = 17, start > end, ranges ascending, ranges touching (gap 0), overlap, `ranges[0].end != largest`, trailing byte, truncated range); `stream_frame_layout_is_exact` (byte-for-byte against 2.6); `ping_close_dgram_layouts`. `session.rs`: `window_ranges_report_exact_holes` (seqs 0..=4, 7..=9, 11: ranges `[(11,11),(7,9),(0,4)]`; end inclusive); `ack_is_sent_on_every_fourth_eliciting_packet` (3 STREAM packets: none, 4th: one ACK); `ack_is_immediate_on_a_gap_and_on_a_ping`; `ack_only_packets_never_cause_an_ack`; `at_most_one_ack_per_tick_under_ping_flood` (100 PINGs in one tick: one ACK; next tick: the pending one); `ack_with_unsent_packet_number_is_ignored` (`bad_ack == 1`, nothing removed); `acked_packet_removes_its_chunk_and_it_is_not_retransmitted`; `lost_packet_requeues_chunk_once` (a chunk lost twice via two packets is queued once; a chunk already acknowledged via another copy is not queued).
- Existing tests change: tests that build `Frame { cum, sacks, .. }`; `liveness.rs` and `idle.rs` where they expect a PING reply with id 1 (now an ACK); the v1 locks named `gap_retransmit_does_not_disable_the_timer` and `gap_retransmit_fires_at_most_once_per_tick` are deleted and replaced by `lost_packet_requeues_chunk_once` and `retransmit_uses_a_new_sequence_number`; `in_flight_cap.rs` keeps the 512-chunk cap for now.
- Acceptance: whole suite and all four trace replays byte-exact; no performance claim.
- Mutations: treat range end as exclusive: `window_ranges_report_exact_holes` fails. ACK on every packet: `ack_is_sent_on_every_fourth...` fails. Skip the `tx_seq` check: `ack_with_unsent...` fails. Leave the chunk in `unacked` on ACK: `acked_packet_removes...` fails.

### Step 9. RTT, loss detection by packet number, PTO

- Files: new `loss.rs`; `session.rs`; remove the fixed timer path.
- API:
```rust
// loss.rs
pub const PACKET_THRESHOLD: u64 = 3;
pub const MAX_ACK_DELAY: u64 = 2;
pub const ACK_DELAY_CLAMP: u64 = 25;
pub const INITIAL_RTT: u64 = 100;
pub struct Rtt { pub srtt: u64, pub rttvar: u64, pub min_rtt: u64, pub latest: u64 /* + have_sample */ }
impl Rtt { pub fn new() -> Rtt; pub fn on_sample(&mut self, sample: u64, ack_delay: u64); pub fn pto(&self) -> u64; pub fn loss_delay(&self) -> u64; }
pub fn is_lost(seq: u64, sent: u64, largest_acked: u64, now: u64, loss_delay: u64) -> bool;
// session.rs
Session::detect_lost(&mut self, now: u64)         // 5.6
Session::tick_timeouts(&mut self, now: u64) -> Vec<Frame>   // loss time, PTO, unconfirmed close, flush
Session::rtt(&self) -> &Rtt
```
  `tick_sessions(now, timeout)` keeps its signature (the `timeout` is still used for handshake resends).
- Tests to add: `loss.rs`: `rtt_vector` (first 100; then 200: srtt 112, rttvar 62, pto 362, loss_delay 225); `ack_delay_adjustment_and_clamp` (delay 60 000 behaves as 25; adj never below min_rtt); `is_lost_table` (seq 5, largest 8: lost by threshold; seq 6, largest 8, now before sent+delay: not lost; same with now at sent+delay: lost; seq == largest: never; seq > largest: never). `session.rs` (two-session helper, no hub): `reorder_of_two_causes_no_retransmit`; `reorder_of_four_causes_one_retransmit`; `rtt_sample_only_from_the_largest_newly_acked`; `tail_loss_is_recovered_by_pto` (drop the last data packet and everything the receiver sends for one PTO; assert exactly one PING at `pto_base + pto`, then retransmission after its ACK, and completion); `pto_doubles_then_caps` (interval sequence t, 2t, 4t, ... 64t, 64t); `unconfirmed_initiator_closes_after_five_ptos`; `loss_scan_stops_at_first_unlost` (counter of examined packets in a 1000-packet flight with one loss is at most 3).
- Existing tests change: `outage.rs`, `liveness.rs`, `scoreboard_gaps.rs` where they relied on the fixed retransmit timeout; they now wait for PTO (about `INITIAL_RTT`-scale ticks) and need larger tick loops.
- Acceptance (measurable): trace replay `synth_40flows` at 1% loss and 2% reorder: STREAM frames accepted by the receiver divided by chunks sent <= **1.03** (v1: 16 465 / 14 499 = 1.136), 80/80 streams byte-exact. Reorder alone (0% loss): ratio <= 1.01. **Assumption to check first**: how far the lab hub displaces a reordered packet. Before coding the acceptance, print a histogram of displacement from the hub. If displacements above 2 packets are common, the threshold 3 will fire and the target must be set from that measurement (state the new target in the commit message).
- Mutations: threshold 1 instead of 3: `reorder_of_two_causes_no_retransmit` fails. Remove the `largest_acked` bound: `is_lost_table` fails. Take the RTT sample from any acked packet: `rtt_sample_only_from_...` fails. Never reset `pto_count` on progress: `pto_doubles_then_caps` or the replay ratio fails.

### Step 10. Flow control and backpressure

- Files: `session.rs`, `node.rs`, `udp.rs`, `bin/udpfile.rs`, `bin/replay.rs`, `bin/demo.rs`, tests.
- API: as 6.2 plus `Session::take_delivered(&mut self, stream: u32) -> Vec<u8>`, `Session::consumed(&self) -> u64`, `Session::recv_limit(&self) -> u64`, `Session::send_credit(&self) -> u64`, `Session::tx_buffered(&self) -> usize`, constants `CONN_WINDOW`, `SEND_BUF_MAX`, `MAX_STREAMS = 1024`, `DGRAM_IN_MAX = 256`; `NodeStats.flow_violations`, `bad_ack`. `Node::take_stream_bytes` and `recv_msgs` call `take_delivered`. The ACK carries `max_data = recv_limit()`. `udpfile` send loop: offer the remaining tail every poll until accepted.
- Tests to add (`tests/flow_control.rs`): `sender_stops_at_the_credit` (receiver never reads: total accepted over many ticks == 1 048 576 exactly; mutation: remove the credit term gives 4 MiB); `unread_bytes_never_exceed_the_window` (while the sender keeps offering, `delivered_unread + rx_buffered_bytes <= 1 MiB` at every tick); `reading_reopens_the_window` (after `take_delivered` of everything and 50 ticks, another 1 MiB is accepted); `window_update_sent_at_a_quarter` (read 256 KiB; within 2 ticks the sender's `send_limit` rises by 256 KiB without any data in flight); `lost_window_update_is_recovered_by_ping` (drop the ACK that carries the update; the PTO PING's ACK restores it); `stale_ack_cannot_lower_the_limit` (an ACK with smaller `max_data` after a larger one changes nothing); `credit_violation_closes_the_session` (a hand-sealed STREAM frame past the limit: session Closed, `flow_violations == 1`); `stream_1025_closes_the_session`; `ooo_buffer_overflow_closes_the_session`; `offsets_assigned_only_for_accepted_bytes` (queue 3 MiB: `next_off == accepted`).
- Existing tests change: every caller of `send_bytes` (compiler lists them: `udp_loopback.rs`, `udpfile_cli.rs`, `peer_limits.rs`, `in_flight_cap.rs`, `integration.rs`, `replay.rs`, `demo.rs`) uses the accepted count and re-offers the tail; tests that never read delivered bytes while sending more than 1 MiB now read.
- Acceptance: 100 MB file over loopback completes while the receiver reads slowly (sleep 1 ms per 64 KiB): receiver resident memory for session buffers never exceeds 3 MiB (assert through `rx_buffered_bytes + delivered_unread`); trace replays byte-exact.
- Mutations: as named above for the credit test; skip the `wants_credit` PING: `lost_window_update_is_recovered_by_ping` fails; apply `min` instead of `max` to `send_limit`: `stale_ack_cannot_lower_the_limit` fails.

### Step 11. Congestion controller (window only, no pacing yet) and a bottleneck link

- Files: new `cc.rs`; `session.rs` (flush gating, loss/ack hooks, remove `in_flight_total` chunk cap and `MAX_IN_FLIGHT`); `link.rs` (bottleneck).
- API: `NewReno` per 7.1 with `new()`, `can_send`, `on_sent`, `on_acked`, `on_lost`, `on_persistent`, `cwnd()`, `bytes_in_flight()`; `Session::cwnd(&self) -> u64`; `Hub::set_bottleneck(&mut self, pkts_per_round: u32, queue_pkts: usize, delay_rounds: u32)` (tail drop; counters `hub.dropped_by_queue`, `hub.max_queue`).
- Tests to add: `cc.rs`: `slow_start_adds_acked_bytes` (12 000 + 12 000 = 24 000); `loss_halves_once_per_recovery` (cwnd 48 000: loss gives 24 000; a second loss with `seq <= recovery_seq` leaves it; a loss with a larger seq halves again); `congestion_avoidance_adds_about_one_mss_per_window` (cwnd 24 000, ssthresh 24 000, ack 1200: +60); `never_below_min_or_above_max`; `persistent_congestion_resets` (3 PTOs). `tests/path_fill.rs`: with `set_bottleneck(10, 30, 5)`, transfer 4 MiB: byte-exact; rounds taken <= `chunks / (10 * 0.6)` (goodput at least 60% of the bottleneck); `hub.dropped_by_queue / packets_sent <= 0.05`; data packets sent / chunks <= 1.15; `session.cwnd()` never exceeds `MAX_CWND`.
- Existing tests change: `in_flight_cap.rs` now asserts `bytes_in_flight <= cwnd` and packets in flight <= 1024.
- Acceptance: the numbers in `path_fill` above; trace replays byte-exact with ratio <= 1.03 still.
- Mutations: never halve on loss: `path_fill` drop ratio fails and `loss_halves_once_per_recovery` fails. Halve on every loss in recovery: `loss_halves_once_per_recovery` fails. Never grow: the goodput assertion fails. Count PINGs as in flight: a stalled-window case in `flow_control` fails.

### Step 12. Pacer

- Files: new `pacer.rs`; `session.rs` (`flush`).
- API: `Pacer::new(now)`, `refill(now, rate_per_tick)`, `try_take(bytes) -> bool`, `tokens()`; `pub fn rate_per_tick(cwnd: u64, srtt: u64, slow_start: bool) -> u64`; `Session::set_pacing(&mut self, on: bool)`.
- Tests to add: `pacer.rs`: `rate_vectors` (cwnd 12 000, srtt 100, slow start: 240; same, congestion avoidance: 150; srtt 0 treated as 1); `tokens_never_exceed_the_burst` (idle 10 000 ticks then tokens == 12 000); `take_consumes_tokens`; `refill_saturates` (no overflow at huge cwnd and tick gap). `session.rs`: `no_more_than_ten_packets_in_one_tick` (1000 chunks queued, huge cwnd, srtt 100: first flush releases 10); `steady_rate_matches_formula` (after the burst, 1200-byte packets leave at one per 5 ticks, plus or minus one over 100 ticks); `blocked_flush_resumes_next_tick`; `retransmissions_are_paced_too`.
- Existing tests change: lab tests that expect a whole window within one tick call `set_pacing(false)`; the replay harness keeps pacing on and reports rounds.
- Acceptance: 100 MB loopback transfer: in no 1-ms interval does the endpoint emit more than `PACER_BURST / 1200 + 64` datagrams (assert from an endpoint counter `max_sent_in_tick`), and the transfer still completes.
- Mutations: no cap on tokens: `tokens_never_exceed_the_burst` and `no_more_than_ten...` fail. Do not subtract on take: `steady_rate_matches_formula` fails.

### Step 13. Per-destination queues in the UDP endpoint

- Files: new `outq.rs`; `udp.rs`; `node.rs` (add `addr_has_session(addr) -> bool`).
- API: `OutQueues::new()`, `push(&mut self, addr: Addr, has_session: bool, sa: SocketAddr, dgram: Vec<u8>) -> bool`, `pop_next(&mut self) -> Option<(SocketAddr, Vec<u8>)>`, `len()`, `destinations()`; `UdpEndpoint::dropped_out`, `queued()` keep their meanings; `set_max_out` removed.
- Tests to add: `outq.rs`: `serves_destinations_in_turn` (3 destinations with 10 each pop as a b c a b c ...); `a_flooder_cannot_starve_others` (A pushes 10 000: 256 stored, 9 744 `dropped`; B pushes 1, and is popped within 2 pops); `unknown_destination_cap_is_four`; `empty_destinations_leave_no_state` (after draining, `destinations() == 0` and the internal maps are empty). `tests/udp_fairness.rs`: two senders to one receiver over loopback, both transferring, bytes delivered by each within a ratio of 0.5 to 2.0 after 2 seconds; a third peer sends garbage HANDSHAKE1 at full speed and the two transfers lose at most 20% throughput.
- Existing tests change: `udp_hardening.rs` tests that set `set_max_out(n)` and expect a total cap now fill one destination up to 256.
- Acceptance: as above.
- Mutations: use one FIFO: `serves_destinations_in_turn` and `a_flooder_cannot_starve_others` fail. Leave empty queues in the map: `empty_destinations_leave_no_state` fails.

### Step 14. Clean-up, documentation, acceptance runs

- Files: remove dead code and constants named in section 8 "Removed"; `local notes` gets a "Wire version 2" section replacing the v1 statements it supersedes (list them as the Handshake rework section does); `demo.rs` runs to the end.
- Tests to add: `tests/wire_v2_golden.rs`: byte-exact hex of one HANDSHAKE1 header, one COOKIE (40 bytes), one STREAM frame, one ACK frame, so any future layout change is a deliberate edit; `v1_datagram_is_ignored_by_node` (a v1 datagram gets no reply and no state).
- Acceptance: `cargo test` green; the four trace replays byte-exact with replay counter 0 and ratio <= 1.03 at 1% loss and 2% reorder; two-machine transfer of 256 MiB recorded in MB/s in `local notes`; target >= 25 MB/s on gigabit Ethernet (an estimate, not a measurement; if lower, profile before changing the design); no `unsafe`.
- Mutation: change the version byte in the golden HANDSHAKE1: the golden test fails.

---

## 11. Test plan

### 11.1 Levels

1. Unit tests in each new module (`cookie`, `keyfile`, `peerbook`, `loss`, `cc`, `pacer`, `outq`), including the published vectors in this document (cookie MAC, public line checksum, fingerprint, RTT vector).
2. Lab tests on the in-memory hub with seeded loss and reorder: cookie round, responder limits, flow control, path fill (bottleneck).
3. Loopback tests with real sockets: `udp_loopback`, `udp_hardening`, `udpfile_cli`, `keys_cli`, `udp_fairness`.
4. Trace replays (`synth_40flows`, `synth_2000flows`, `hao123_http`, `id1cn_http`): byte-exact, replay counter 0, and from step 9 the ratio of accepted STREAM frames to chunks.
5. The two-machine run (11.2).

Every key test names the mutation it catches (section 10); the implementer applies each mutation once and confirms the failure before moving on.

### 11.2 Two-machine transfer (Windows host to Linux VM on one LAN), after step 7

1. Build both: `cargo build --release` on Windows; on the VM install the Rust toolchain or copy the source and build there. Same commit on both (compare `git rev-parse HEAD`).
2. Keys: on each machine `newnet-keys gen --name host` (Windows) and `newnet-keys gen --name vm` (Linux). Check the Linux file mode is 600 and the Windows icacls listing shows only the user, SYSTEM and Administrators.
3. Exchange: `newnet-keys show` on each; copy the public line to the other machine by any channel (it is public); on both screens compare the fingerprints aloud; then `newnet-keys add-peer --peers peers --line "..."` on each.
4. Network: pick UDP port 4002. Windows Defender Firewall inbound rule for that port if the Windows host will receive (run by the owner, elevated): `New-NetFirewallRule -DisplayName newnet -Direction Inbound -Protocol UDP -LocalPort 4002 -Action Allow`. On the VM, check `ufw`/`iptables`. With the VM bridged, use its LAN address (not NAT).
5. Receive on the VM: `udpfile recv --identity identity.key --peers peers --listen 0.0.0.0:4002 --out received.bin`. Send from Windows: `udpfile send --identity identity.key --peers peers --peer vm --to <vm-lan-ip>:4002 --file test.bin`.
6. Pass criteria: sender prints success only after the receiver's confirmation; SHA-256 of both files equal; run for 100 MB, then the same in the other direction, then a 1-byte file and an empty file.
7. Capture (Wireshark or `tcpdump -i <if> udp port 4002` on the VM): the test file is made of a repeated marker string; search the capture for the marker: zero hits. The first four datagrams must be 147 to 210 bytes (HS1), 40 bytes (COOKIE), HS1 again, 72 bytes (HS2).
8. Negative runs: (a) replace the peer line on one side with a key from a third `gen`: transfer fails with a clear error within the timeout and no output file or `.part` remains; (b) run the sender with only a seed identity against the VM address: refused with exit code 2; (c) pull the network cable or disable the adapter for 5 seconds mid-transfer: the transfer either completes after the link returns (PTO recovery) or fails cleanly at the idle timeout; it never writes a file that fails the hash; (d) start a second sender from a third key not in the peers file: the receiver logs `auth_fails` and the first transfer is unaffected.
9. Record: MB/s, round-trip time from the logs, any retransmit counts, in `local notes`.

### 11.3 Performance-phase acceptance (steps 9 to 14)

- Step 9: ratio <= 1.03 at 1% loss and 2% reorder (and <= 1.01 at reorder only), subject to the hub-displacement check.
- Step 11: bottleneck test numbers; step 12: burst bound; step 13: fairness ratio; step 14: two-machine MB/s recorded.

---

## 12. Open questions for the owner (each with a recommended answer)

1. Cookie on every handshake, or only when the node is busy? Recommend **always**: one extra round trip per connect (about 1 ms on a LAN), nothing to tune. Revisit only if connects become frequent.
2. Stamp floor of 5 minutes before process start (requires the two clocks to agree within 5 minutes)? Recommend **yes**; the alternative is writing the last stamp to disk, which adds a file that can be lost or corrupted. If the VM clock is unreliable, fix it with NTP before the milestone.
3. One logical tick equal to 1 ms? Recommend **yes**; the cost is multiplying constants once (step 1). RTT below 1 ms is rounded; fine for a first controller.
4. Windows private-key protection: ACL via `icacls` (this design) or DPAPI (needs a Windows-API crate or a PowerShell shell-out and ties the key to the Windows account)? Recommend **ACL now**, DPAPI only if the key will live on shared machines.
5. Passphrase-encrypted key files? Recommend **no for the milestone** (needs a password KDF crate and a prompt); add later behind a new file version.
6. Key rotation with an overlap period (two keys per name)? Recommend **no**: flag day plus restart; it keeps the allowlist a plain map. Add overlap if rotation ever has to be done without downtime.
7. Keep the registry, TOFU pins and Ed25519 handovers in the crate? Recommend **keep, mark lab-only** in comments and docs; they are not on the real path and removing them is a separate, riskier change.
8. Connection-level flow control only? Recommend **yes** now; add per-stream credit only when an application needs two streams with different readers.
9. Window 1 MiB and egress ceiling 64 datagrams per ms (about 77 MB/s)? Recommend **keep** for the first two-machine runs; raise the ceiling only after step 14 shows the cap is what limits throughput.
10. Optimistic-ACK defence (skip packet numbers on purpose and reject ACKs for the skipped ones)? Recommend **not now**; the exposure is limited to the sender's own path at 1.2 MB in flight, and each added mechanism is one more place for a weak implementer to err.
11. Should the first transfer use `udpfile`'s existing 1 GiB cap and `.part`/rename behaviour unchanged? Recommend **yes**. Separately, the `<out>.part` symlink overwrite noted in `local notes` is still open and unrelated to this design; fix it before using the tool on a shared machine.
