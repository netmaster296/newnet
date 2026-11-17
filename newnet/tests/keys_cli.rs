// The newnet-keys binary and udpfile driven with real key files, all over
// 127.0.0.1. Scratch lives under target/scratch so every artefact of a run
// sits inside this directory.

use std::io::Read;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use newnet::crypto::sha256;
use newnet::keyfile;
use newnet::peerbook::{self, PeerLine};

fn keys() -> Command {
    Command::new(env!("CARGO_BIN_EXE_newnet-keys"))
}

fn udpfile() -> Command {
    Command::new(env!("CARGO_BIN_EXE_udpfile"))
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

// Run newnet-keys to completion and hand back the whole result.
fn run_keys(args: &[&str]) -> Out {
    let out = keys().args(args).stdin(Stdio::null()).output().expect("newnet-keys runs");
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

// One directory per test under target/scratch, emptied when the test starts.
fn scratch(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("scratch")
        .join(format!("keys_cli_{tag}_{}_{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

// Owns the spawned children and scratch directories of one test: when the
// test ends, by return or by panic, any child still running is killed and
// every scratch directory is removed.
struct Guard {
    children: Vec<Child>,
    dirs: Vec<PathBuf>,
}

impl Guard {
    fn new() -> Guard {
        Guard { children: Vec::new(), dirs: Vec::new() }
    }

    fn dir(&mut self, p: &Path) {
        self.dirs.push(p.to_path_buf());
    }

    fn spawn_udpfile(&mut self, args: &[&str]) -> usize {
        let child = udpfile()
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        self.children.push(child);
        self.children.len() - 1
    }

    fn wait_exit(&mut self, idx: usize, secs: u64) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            match self.children[idx].try_wait().unwrap() {
                Some(status) => return status.code().unwrap_or(-1),
                None => {
                    if Instant::now() >= deadline {
                        let _ = self.children[idx].kill();
                        let _ = self.children[idx].wait();
                        panic!("child did not exit within {secs} s");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn stderr_of(&mut self, idx: usize) -> String {
        let mut s = String::new();
        if let Some(err) = self.children[idx].stderr.as_mut() {
            err.read_to_string(&mut s).unwrap();
        }
        s
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        for d in &self.dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

// One network test at a time inside this binary: three file transfers of
// busy-polling process pairs starve each other on the loopback under
// debug-build CPU pressure, and a starved receiver turns a 5 MB transfer
// into a retransmit stall.
fn net_lock() -> std::sync::MutexGuard<'static, ()> {
    static NET: std::sync::Mutex<()> = std::sync::Mutex::new(());
    NET.lock().unwrap_or_else(|e| e.into_inner())
}

fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    drop(s);
    port
}

fn part_of(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

// Run `newnet-keys gen` and return (secret file path, public line,
// fingerprint). The fingerprint must look like 8 groups of 4 hex digits.
fn gen_key(dir: &Path, name: &str) -> (PathBuf, String, String) {
    let kf = dir.join(format!("{name}.key"));
    let r = run_keys(&["gen", "--name", name, "--file", kf.to_str().unwrap()]);
    assert_eq!(r.code, 0, "gen {name} must succeed: {}", r.stderr);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "gen prints exactly the line and the fingerprint: {:?}", r.stdout);
    assert!(lines[0].starts_with(&format!("newnet1 {name} ")), "the public line names the peer: {:?}", lines[0]);
    let groups: Vec<&str> = lines[1].split(' ').collect();
    assert_eq!(groups.len(), 8, "the fingerprint is 8 groups: {:?}", lines[1]);
    for g in &groups {
        assert_eq!(g.len(), 4, "each fingerprint group is 4 hex: {:?}", lines[1]);
        assert!(g.chars().all(|c| c.is_ascii_hexdigit()), "fingerprint hex: {:?}", lines[1]);
    }
    (kf, lines[0].to_string(), lines[1].to_string())
}

// The public line of `name` carrying the key found in `who_keyfile`,
// formatted fresh so the checksum is correct for that pairing.
fn line_with_key(name: &str, who_keyfile: &Path) -> String {
    let kf = keyfile::load(who_keyfile).expect("the key file loads");
    let key = keyfile::public_of(&kf.secret);
    peerbook::format_pub_line(&PeerLine { name: name.to_string(), key, expires: None })
}

fn sample(n: u64) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8).collect()
}

// The number logged after `auth_fails=` on the receiver's stderr.
fn logged_auth_fails(s: &str) -> Option<u64> {
    let at = s.find("auth_fails=")?;
    let digits: String = s[at + "auth_fails=".len()..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

#[test]
fn gen_then_show_prints_a_line_add_peer_accepts() {
    let dir = scratch("gen_show_add");
    let (kf, line, fp) = gen_key(&dir, "alice");
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields.len(), 4, "no expiry on a fresh line: {line:?}");

    // The file on disk is the authority: what was printed is its public line
    // and fingerprint, recomputed here from the loaded secret.
    let loaded = keyfile::load(&kf).expect("the secret file loads");
    let pubk = keyfile::public_of(&loaded.secret);
    assert_eq!(line, peerbook::format_pub_line(&PeerLine { name: "alice".into(), key: pubk, expires: None }));
    assert_eq!(fp, keyfile::fingerprint(&pubk));

    // show prints the same two lines without touching the secret.
    let s = run_keys(&["show", "--file", kf.to_str().unwrap()]);
    assert_eq!(s.code, 0, "show must succeed: {}", s.stderr);
    assert_eq!(s.stdout, format!("{line}\n{fp}\n"), "show repeats gen's public output");

    // add-peer accepts the line; a second add of the same line is no error.
    let peers = dir.join("peers");
    let a = run_keys(&["add-peer", "--peers", peers.to_str().unwrap(), "--line", &line]);
    assert_eq!(a.code, 0, "add-peer accepts a good line: {}", a.stderr);
    assert!(peers.exists(), "the peers file was created");
    let a2 = run_keys(&["add-peer", "--peers", peers.to_str().unwrap(), "--line", &line]);
    assert_eq!(a2.code, 0, "the same line twice is not an error: {}", a2.stderr);
    let (active, expired) = peerbook::load_peers(&peers, 0).expect("the peers file loads");
    assert_eq!(expired.len(), 0);
    assert_eq!(active, vec![peerbook::parse_pub_line(&line).expect("the line parses")]);

    // list prints the name and the fingerprint of every peer.
    let l = run_keys(&["list", "--peers", peers.to_str().unwrap()]);
    assert_eq!(l.code, 0, "list must succeed: {}", l.stderr);
    assert!(l.stdout.contains("alice"), "list names the peer: {:?}", l.stdout);
    assert!(l.stdout.contains(&fp), "list shows the fingerprint: {:?}", l.stdout);
}

#[test]
fn gen_twice_refuses_and_keeps_the_first_key() {
    let dir = scratch("gen_twice");
    let (kf, line, _) = gen_key(&dir, "alice");
    let bytes = std::fs::read(&kf).expect("the first key file is on disk");
    let again = run_keys(&["gen", "--name", "alice", "--file", kf.to_str().unwrap()]);
    assert_eq!(again.code, 1, "a second gen must refuse, got {}: {}", again.code, again.stderr);
    assert!(!again.stderr.is_empty(), "the refusal says why");
    assert_eq!(std::fs::read(&kf).expect("the file is still there"), bytes, "the refusal changed nothing");
    let s = run_keys(&["show", "--file", kf.to_str().unwrap()]);
    assert_eq!(s.code, 0, "show still works: {}", s.stderr);
    assert!(s.stdout.starts_with(&line), "the first key is still the one on disk: {:?}", s.stdout);
}

#[test]
fn add_peer_rejects_bad_checksum() {
    let dir = scratch("bad_checksum");
    let (_kf, line, _) = gen_key(&dir, "alice");
    let peers = dir.join("peers");
    let fields: Vec<String> = line.split(' ').map(|s| s.to_string()).collect();
    let hexd: Vec<char> = "0123456789abcdef".chars().collect();
    for field in [2usize, 3usize] {
        let mut chars: Vec<char> = fields[field].chars().collect();
        let old = chars[0];
        chars[0] = *hexd.iter().find(|c| **c != old).unwrap();
        let mut bad = fields.clone();
        bad[field] = chars.into_iter().collect();
        let bad_line = bad.join(" ");
        assert_ne!(bad_line, line);
        let r = run_keys(&["add-peer", "--peers", peers.to_str().unwrap(), "--line", &bad_line]);
        assert_eq!(r.code, 1, "a flipped digit in field {field} must be refused, got {}: {bad_line}", r.code);
        assert!(!peers.exists(), "the refused add wrote no peers file");
    }
    let good = run_keys(&["add-peer", "--peers", peers.to_str().unwrap(), "--line", &line]);
    assert_eq!(good.code, 0, "the untampered line is accepted: {}", good.stderr);
    assert!(peers.exists(), "the accepted add wrote the peers file");
}

#[test]
fn transfer_with_real_key_files_is_byte_exact() {
    let _net = net_lock();
    let mut g = Guard::new();
    let dir = scratch("real_transfer");
    g.dir(&dir);
    let (alice_key, alice_line, _) = gen_key(&dir, "alice");
    let (bob_key, bob_line, _) = gen_key(&dir, "bob");
    let peers_a = dir.join("peers_a");
    let peers_b = dir.join("peers_b");
    assert_eq!(run_keys(&["add-peer", "--peers", peers_a.to_str().unwrap(), "--line", &bob_line]).code, 0);
    assert_eq!(run_keys(&["add-peer", "--peers", peers_b.to_str().unwrap(), "--line", &alice_line]).code, 0);

    let input = dir.join("in.bin");
    let output = dir.join("out.bin");
    let data = sample(5_000_000);
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let r = g.spawn_udpfile(&[
        "recv",
        "--identity", bob_key.to_str().unwrap(),
        "--peers", peers_b.to_str().unwrap(),
        "--listen", &format!("127.0.0.1:{port}"),
        "--out", output.to_str().unwrap(),
        "--timeout-secs", "180",
    ]);
    let s = g.spawn_udpfile(&[
        "send",
        "--identity", alice_key.to_str().unwrap(),
        "--peers", peers_a.to_str().unwrap(),
        "--peer", "bob",
        "--to", &format!("127.0.0.1:{port}"),
        "--file", input.to_str().unwrap(),
        "--timeout-secs", "180",
    ]);
    assert_eq!(g.wait_exit(s, 240), 0, "send must exit 0, stderr: {}", g.stderr_of(s));
    assert_eq!(g.wait_exit(r, 240), 0, "recv must exit 0, stderr: {}", g.stderr_of(r));
    let got = std::fs::read(&output).expect("the output file exists");
    assert_eq!(sha256(&[&data]), sha256(&[&got]), "SHA-256 of input and output must match");
    assert_eq!(got, data, "byte-exact: the output file equals the input file");
}

#[test]
fn wrong_peer_key_fails_and_writes_no_output() {
    let _net = net_lock();
    let mut g = Guard::new();
    let dir = scratch("wrong_peer_key");
    g.dir(&dir);
    let (alice_key, _, _) = gen_key(&dir, "alice");
    let (bob_key, bob_line, _) = gen_key(&dir, "bob");
    let (mallory_key, _, _) = gen_key(&dir, "mallory");
    // Bob's peers file holds alice's NAME under mallory's key: the key the
    // handshake presents (alice's own) is not the one on file.
    let bad_line = line_with_key("alice", &mallory_key);
    let peers_a = dir.join("peers_a");
    let peers_b = dir.join("peers_b");
    assert_eq!(run_keys(&["add-peer", "--peers", peers_a.to_str().unwrap(), "--line", &bob_line]).code, 0);
    assert_eq!(run_keys(&["add-peer", "--peers", peers_b.to_str().unwrap(), "--line", &bad_line]).code, 0);

    let input = dir.join("in.bin");
    let output = dir.join("out.bin");
    std::fs::write(&input, sample(200_000)).unwrap();
    let port = free_port();

    let r = g.spawn_udpfile(&[
        "recv",
        "--identity", bob_key.to_str().unwrap(),
        "--peers", peers_b.to_str().unwrap(),
        "--listen", &format!("127.0.0.1:{port}"),
        "--out", output.to_str().unwrap(),
        "--timeout-secs", "20",
    ]);
    let s = g.spawn_udpfile(&[
        "send",
        "--identity", alice_key.to_str().unwrap(),
        "--peers", peers_a.to_str().unwrap(),
        "--peer", "bob",
        "--to", &format!("127.0.0.1:{port}"),
        "--file", input.to_str().unwrap(),
        "--timeout-secs", "60",
    ]);
    // The sender gives up its handshake retries well before its 60 s
    // timeout: exiting inside 25 s proves the failure, not the clock, ended it.
    let rc_send = g.wait_exit(s, 25);
    let send_err = g.stderr_of(s);
    assert_eq!(rc_send, 1, "send with a wrong peer key must exit 1, got {rc_send}, stderr: {send_err}");
    assert!(send_err.contains("peer did not answer"), "send must report the failed handshake, got: {send_err}");
    assert!(!send_err.contains("timed out"), "send must fail before its --timeout-secs deadline, got: {send_err}");
    let rc_recv = g.wait_exit(r, 30);
    assert_eq!(rc_recv, 1, "recv with no accepted handshake must exit 1");
    assert!(!output.exists(), "no output file may exist after a failed run");
    assert!(!part_of(&output).exists(), "no .part file may be left after a failed run");
}

#[test]
fn unknown_sender_is_refused() {
    let _net = net_lock();
    let mut g = Guard::new();
    let dir = scratch("unknown_sender");
    g.dir(&dir);
    let (alice_key, alice_line, _) = gen_key(&dir, "alice");
    let (bob_key, _, _) = gen_key(&dir, "bob");
    let (carol_key, _, _) = gen_key(&dir, "carol");
    // Alice's peers file names carol but holds bob's key: carol's own key is
    // not in the file, so the key-equality refusal is what keeps her out.
    let peers_a = dir.join("peers_a");
    let peers_c = dir.join("peers_c");
    let carol_line = line_with_key("carol", &bob_key);
    assert_eq!(run_keys(&["add-peer", "--peers", peers_a.to_str().unwrap(), "--line", &carol_line]).code, 0);
    assert_eq!(run_keys(&["add-peer", "--peers", peers_c.to_str().unwrap(), "--line", &alice_line]).code, 0);

    let input = dir.join("in.bin");
    let output = dir.join("out.bin");
    std::fs::write(&input, sample(100_000)).unwrap();
    let port = free_port();

    let r = g.spawn_udpfile(&[
        "recv",
        "--identity", alice_key.to_str().unwrap(),
        "--peers", peers_a.to_str().unwrap(),
        "--listen", &format!("127.0.0.1:{port}"),
        "--out", output.to_str().unwrap(),
        "--timeout-secs", "8",
    ]);
    let s = g.spawn_udpfile(&[
        "send",
        "--identity", carol_key.to_str().unwrap(),
        "--peers", peers_c.to_str().unwrap(),
        "--peer", "alice",
        "--to", &format!("127.0.0.1:{port}"),
        "--file", input.to_str().unwrap(),
        "--timeout-secs", "60",
    ]);
    let rc_send = g.wait_exit(s, 25);
    let send_err = g.stderr_of(s);
    assert_eq!(rc_send, 1, "the unknown sender must exit 1, got {rc_send}, stderr: {send_err}");
    assert!(send_err.contains("peer did not answer"), "the unknown sender never gets a session, got: {send_err}");
    let rc_recv = g.wait_exit(r, 30);
    let recv_err = g.stderr_of(r);
    assert_eq!(rc_recv, 1, "recv must exit 1 with no accepted handshake, got {rc_recv}: {recv_err}");
    assert!(recv_err.contains("timed out"), "recv times out with no session: {recv_err}");
    let fails = logged_auth_fails(&recv_err).expect("the receiver logs auth_fails");
    assert!(fails >= 1, "the receiver must log at least one auth failure, got {fails}: {recv_err}");
    assert!(!output.exists(), "the unknown sender never got a file across");
    assert!(!part_of(&output).exists(), "no .part file may be left");
}

#[test]
fn seed_identity_refused_off_loopback() {
    let mut g = Guard::new();
    let dir = scratch("seed_off_loopback");
    g.dir(&dir);
    let out = dir.join("out.bin");
    let input = dir.join("in.bin");
    std::fs::write(&input, b"hello").unwrap();

    let r = g.spawn_udpfile(&[
        "recv",
        "--name", "a",
        "--seed", "1",
        "--peer", "b",
        "--peer-seed", "2",
        "--listen", "0.0.0.0:0",
        "--out", out.to_str().unwrap(),
        "--timeout-secs", "30",
    ]);
    let code = g.wait_exit(r, 10);
    let err = g.stderr_of(r);
    assert_eq!(code, 2, "recv --listen 0.0.0.0 with --seed must exit 2, got {code}: {err}");
    assert!(err.contains("lab identities may only be used on loopback"), "the refusal must say why, got: {err}");
    assert!(!out.exists(), "nothing binds and no probe runs before the check");
    assert!(!part_of(&out).exists(), "the probe .part must not be created before the check");

    let s = g.spawn_udpfile(&[
        "send",
        "--name", "a",
        "--seed", "1",
        "--peer", "b",
        "--peer-seed", "2",
        "--to", "93.184.216.34:4002",
        "--file", input.to_str().unwrap(),
        "--timeout-secs", "30",
    ]);
    let scode = g.wait_exit(s, 10);
    let serr = g.stderr_of(s);
    assert_eq!(scode, 2, "send --to off loopback with --seed must exit 2, got {scode}: {serr}");
    assert!(serr.contains("lab identities may only be used on loopback"), "got: {serr}");
}
