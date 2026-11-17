// udpfile: send one file from one process to another over a newnet session
// on UDP. Real identities come from key files made by newnet-keys (spec 3.3):
//   udpfile recv --identity <secret> --peers <peers> --listen <addr:port> --out <file> [--timeout-secs 30]
//   udpfile send --identity <secret> --peers <peers> --peer <name> --to <addr:port> --file <file>
// The lab seed flags remain for tests and work only if every address given
// is loopback:
//   udpfile recv --name bob --seed 2 --peer alice --peer-seed 1 --listen 127.0.0.1:4002 --out received.bin [--timeout-secs 30]
//   udpfile send --name alice --seed 1 --peer bob --peer-seed 2 --to 127.0.0.1:4002 --file input.bin [--listen 127.0.0.1:0] [--timeout-secs 30]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use newnet::crypto::PeerRecord;
use newnet::identity::Identity;
use newnet::keyfile;
use newnet::node::Node;
use newnet::peerbook;
use newnet::udp::UdpEndpoint;

const MAX_FILE_BYTES: u64 = 1 << 30;

fn usage() -> ! {
    eprintln!("usage: udpfile recv --identity <secret> --peers <peers> --listen <addr:port> --out <file> [--timeout-secs <n>]");
    eprintln!("   or: udpfile send --identity <secret> --peers <peers> --peer <name> --to <addr:port> --file <file> [--listen <addr:port>] [--timeout-secs <n>]");
    eprintln!("   or: udpfile recv --name <name> --seed <n> --peer <name> --peer-seed <n> --listen <addr:port> --out <file> [--timeout-secs <n>]");
    eprintln!("   or: udpfile send --name <name> --seed <n> --peer <name> --peer-seed <n> --to <addr:port> --file <file> [--listen <addr:port>] [--timeout-secs <n>]");
    exit(2);
}

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("{}", msg.as_ref());
    exit(1);
}

struct Opts {
    mode: String,
    name: String,
    seed: u64,
    peer: Option<String>,
    peer_seed: u64,
    identity: Option<PathBuf>,
    peers: Option<PathBuf>,
    listen: Option<String>,
    out: Option<PathBuf>,
    file: Option<PathBuf>,
    to: Option<SocketAddr>,
    timeout_secs: u64,
}

// Pure limit check: the sender refuses a file longer than the cap before
// it binds or reads the bytes.
fn too_big(len: u64) -> bool {
    len > MAX_FILE_BYTES
}

fn parse() -> Opts {
    // args_os: an argument that is not valid Unicode is a malformed
    // argument, not a panic.
    let args: Vec<String> = match std::env::args_os().skip(1).map(|a| a.into_string()).collect() {
        Ok(v) => v,
        Err(_) => usage(),
    };
    let mut o = Opts {
        mode: String::new(),
        name: String::new(),
        seed: 0,
        peer: None,
        peer_seed: 0,
        identity: None,
        peers: None,
        listen: None,
        out: None,
        file: None,
        to: None,
        timeout_secs: 30,
    };
    let mut it = args.into_iter();
    o.mode = match it.next() {
        Some(m) if m == "recv" || m == "send" => m,
        _ => usage(),
    };
    let mut have_seed = false;
    let mut have_peer_seed = false;
    while let Some(a) = it.next() {
        let mut val = || match it.next() {
            Some(v) => v,
            None => usage(),
        };
        match a.as_str() {
            "--name" => o.name = val(),
            "--seed" => {
                o.seed = val().parse().unwrap_or_else(|_| usage());
                have_seed = true;
            }
            "--peer" => o.peer = Some(val()),
            "--peer-seed" => {
                o.peer_seed = val().parse().unwrap_or_else(|_| usage());
                have_peer_seed = true;
            }
            "--identity" => o.identity = Some(PathBuf::from(val())),
            "--peers" => o.peers = Some(PathBuf::from(val())),
            "--listen" => o.listen = Some(val()),
            "--out" => o.out = Some(PathBuf::from(val())),
            "--file" => o.file = Some(PathBuf::from(val())),
            "--to" => o.to = Some(val().parse().unwrap_or_else(|_| usage())),
            "--timeout-secs" => o.timeout_secs = val().parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    // Two identity modes, never mixed: key files (spec 3.3) or lab seeds.
    let seed_mode = have_seed || have_peer_seed;
    let file_mode = o.identity.is_some() || o.peers.is_some();
    if (seed_mode && !have_seed) || (have_seed && !have_peer_seed) {
        usage();
    }
    if seed_mode && file_mode {
        usage();
    }
    if file_mode && (o.identity.is_none() || o.peers.is_none()) {
        usage();
    }
    if !file_mode && !seed_mode {
        usage();
    }
    if !file_mode && (o.name.is_empty() || o.peer.is_none()) {
        usage();
    }
    if o.mode == "send" && o.peer.is_none() {
        usage();
    }
    if o.mode == "recv" && (o.listen.is_none() || o.out.is_none()) {
        usage();
    }
    if o.mode == "send" && (o.to.is_none() || o.file.is_none()) {
        usage();
    }
    if o.mode == "send" && o.listen.is_none() {
        o.listen = Some("127.0.0.1:0".to_string());
    }
    o
}

// Seed identities are lab identities: they work only if every address given
// is loopback (spec step 7). Checked before anything is bound or read.
fn check_seed_loopback(o: &Opts) {
    if o.identity.is_some() {
        return;
    }
    eprintln!("LAB ONLY: identities are derived from numeric seeds");
    let off_loopback = match &o.listen {
        Some(s) => match s.parse::<SocketAddr>() {
            Ok(a) => !a.ip().is_loopback(),
            Err(_) => usage(),
        },
        None => false,
    } || match &o.to {
        Some(t) => !t.ip().is_loopback(),
        None => false,
    };
    if off_loopback {
        eprintln!("lab identities may only be used on loopback");
        exit(2);
    }
}

// The node's identity comes from the secret file (its name is the name in
// the file), and its peers from the peers file: the file is the pin
// (spec 3.3, 3.5). In seed mode the old numeric identities are used.
fn node_from_opts(o: &Opts) -> Result<Node, String> {
    if let Some(idpath) = &o.identity {
        let kf = keyfile::load(idpath).map_err(|e| format!("cannot read the identity file {}: {e:?}", idpath.display()))?;
        let mut node = Node::from_identity(&kf.name, Identity::from_secret(kf.secret));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let (active, _expired) = peerbook::load_peers(&o.peers.clone().unwrap(), now)
            .map_err(|e| format!("cannot read the peers file: {e:?}"))?;
        for l in &active {
            node.add_peer(l);
        }
        return Ok(node);
    }
    let mut node = Node::new(&o.name, o.seed);
    let id = Identity::from_seed(o.peer_seed);
    let peer = o.peer.clone().unwrap();
    node.records.insert(
        peer.clone(),
        PeerRecord { name: peer, ed: Some(id.ed_pub()), x: id.x_pub, expiry: u64::MAX },
    );
    Ok(node)
}

fn timed_out(start: Instant, secs: u64) -> bool {
    start.elapsed() >= Duration::from_secs(secs)
}

// The announced length in the first 8 bytes, or None while fewer than 8
// bytes have arrived. A length above `max` is an error, so no addition on
// untrusted values can overflow: callers compare buf.len() - 8 >= n after
// checking buf.len() >= 8.
fn frame_length(buf: &[u8], max: u64) -> Result<Option<usize>, String> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let b = [buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
    let n = u64::from_le_bytes(b);
    if n > max {
        return Err(format!("length prefix {n} exceeds the limit of {max} bytes"));
    }
    Ok(Some(n as usize))
}

// The path of the staging file for `out`.
fn part_of(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

// The receiver checks its output path at startup, before binding: one bad
// path must fail at once, not after a whole transfer has crossed.
fn probe_out(out: &Path) {
    if out.is_dir() {
        fail(format!("cannot write to {}: {} is an existing directory", out.display(), out.display()));
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            fail(format!("cannot write to {}: the directory {} does not exist", out.display(), parent.display()));
        }
    }
    let part = part_of(out);
    match std::fs::File::create(&part) {
        Ok(_) => {
            let _ = std::fs::remove_file(&part);
        }
        Err(e) => fail(format!("cannot write to {}: {e}", out.display())),
    }
}

fn main() {
    let o = parse();
    let listen: SocketAddr = match &o.listen {
        Some(s) => match s.parse() {
            Ok(a) => a,
            Err(_) => usage(),
        },
        None => usage(),
    };
    check_seed_loopback(&o);

    if o.mode == "send" {
        let file = match &o.file {
            Some(f) => f.clone(),
            None => usage(),
        };
        if let Ok(m) = std::fs::metadata(&file) {
            if too_big(m.len()) {
                fail(format!("file exceeds the limit of {MAX_FILE_BYTES} bytes"));
            }
        }
        // The reported size can be wrong (a device, a pipe, a file that is
        // still growing), so the read itself is bounded as well.
        let data = {
            use std::io::Read;
            let mut d = Vec::new();
            let read = std::fs::File::open(&file).and_then(|f| f.take(MAX_FILE_BYTES + 1).read_to_end(&mut d));
            if let Err(e) = read {
                fail(format!("cannot read the input file {}: {e}", file.display()));
            }
            if too_big(d.len() as u64) {
                fail(format!("file exceeds the limit of {MAX_FILE_BYTES} bytes"));
            }
            d
        };
        let node = match node_from_opts(&o) {
            Ok(n) => n,
            Err(msg) => fail(msg),
        };
        let mut ep = match UdpEndpoint::bind(node, &listen.to_string()) {
            Ok(e) => e,
            Err(e) => fail(format!("cannot bind {listen}: {e}")),
        };
        let to = match o.to {
            Some(t) => t,
            None => usage(),
        };
        let peer = match &o.peer {
            Some(p) => p.clone(),
            None => usage(),
        };
        // The conn id connect returned can die under a retry: the node starts
        // a fresh attempt under a new id. Follow the session by peer name
        // instead of holding the id.
        if let Err(e) = ep.connect(&peer, to) {
            fail(format!("cannot connect to {peer}: {e:?}"));
        }
        let start = Instant::now();
        let conn = loop {
            if timed_out(start, o.timeout_secs) {
                fail("timed out");
            }
            if let Some(c) = ep.node.session_with(&peer) {
                break c;
            }
            if !ep.node.is_connecting_to(&peer) {
                fail("peer did not answer");
            }
            match ep.poll() {
                Ok(r) => {
                    if r == 0 && ep.queued() == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(e) => fail(format!("poll failed: {e}")),
            }
        };
        ep.send_bytes(conn, 1, &(data.len() as u64).to_le_bytes());
        ep.send_bytes(conn, 1, &data);
        loop {
            if !ep.node.sessions.contains_key(&conn) {
                fail("session ended before the file was acknowledged");
            }

            let done = {
                let s = ep.node.sessions.get(&conn).unwrap();
                ep.queued() == 0 && s.in_flight_total() == 0 && s.queued_chunks() == 0
            };
            if done {
                break;
            }
            if timed_out(start, o.timeout_secs) {
                fail("timed out");
            }
            match ep.poll() {
                Ok(r) => {
                    if r == 0 && ep.queued() == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(e) => fail(format!("poll failed: {e}")),
            }
        }
        // Acknowledged stream 1 means the bytes arrived, not that the file
        // was stored. Wait for the receiver's one-byte verdict on stream 2;
        // the --timeout-secs deadline still applies.
        let mut confirm: Vec<u8> = Vec::new();
        while confirm.is_empty() {
            if timed_out(start, o.timeout_secs) {
                fail("timed out");
            }
            if ep.node.peer_of(conn).is_none() {
                fail("session ended before the receiver confirmed");
            }
            confirm.extend(ep.node.take_stream_bytes(conn, 2));
            match ep.poll() {
                Ok(r) => {
                    if r == 0 && ep.queued() == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(e) => fail(format!("poll failed: {e}")),
            }
        }
        // The tail is not subject to --timeout-secs: it has its own bound.
        // Close the session and let the CLOSE datagram leave.
        ep.close(conn);
        let tail = Instant::now();
        while ep.queued() > 0 && tail.elapsed() < Duration::from_secs(2) {
            if let Err(e) = ep.poll() {
                fail(format!("poll failed: {e}"));
            }
        }
        if confirm[0] != 0 {
            eprintln!("receiver could not store the file");
            exit(1);
        }
        println!("sent {} bytes", data.len());
        exit(0);
    }

    let out = match &o.out {
        Some(p) => p.clone(),
        None => usage(),
    };
    probe_out(&out);
    let node = match node_from_opts(&o) {
        Ok(n) => n,
        Err(msg) => fail(msg),
    };
    let mut ep = match UdpEndpoint::bind(node, &listen.to_string()) {
        Ok(e) => e,
        Err(e) => fail(format!("cannot bind {listen}: {e}")),
    };
    let start = Instant::now();
    let mut conn: Option<u64> = None;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if timed_out(start, o.timeout_secs) {
            // Log the handshake verdict: an unknown or mismatched key shows
            // here as auth_fails >= 1 while nothing else happened.
            eprintln!(
                "receiver stats: auth_fails={} sessions={}",
                ep.node.stats.auth_fails,
                ep.node.sessions.len()
            );
            fail("timed out");
        }
        match ep.poll() {
            Ok(r) => {
                if r == 0 && ep.queued() == 0 {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Err(e) => fail(format!("poll failed: {e}")),
        }
        if conn.is_none() {
            // With key files the peers file is the allowlist: any session
            // that opened is one the file authorized, so the receiver takes
            // the first one. Seed mode keeps matching by the given name.
            conn = ep
                .node
                .sessions
                .keys()
                .copied()
                .find(|c| match &o.peer {
                    Some(p) => ep.node.peer_of(*c) == Some(p.as_str()),
                    None => true,
                });
        }
        if let Some(c) = conn {
            if ep.node.peer_of(c).is_none() {
                fail("session ended before the file was complete");
            }
            buf.extend(ep.node.take_stream_bytes(c, 1));
            // The tool only reads stream 1: take and drop whatever the peer
            // delivered on every other stream so it cannot pile up.
            let others: Vec<u32> = ep
                .node
                .sessions
                .get(&c)
                .map(|s| s.delivered.keys().copied().filter(|id| *id != 1).collect())
                .unwrap_or_default();
            for id in others {
                ep.node.take_stream_bytes(c, id);
            }
            match frame_length(&buf, MAX_FILE_BYTES) {
                Ok(None) => {}
                Err(msg) => fail(msg),
                Ok(Some(n)) => {
                    if buf.len() >= 8 && buf.len() - 8 >= n {
                        // Write safely: fill <out>.part, then rename it into
                        // place. On any failure the .part file is removed, so
                        // a failed run leaves nothing at the output path.
                        let part = part_of(&out);
                        let mut stored = true;
                        if let Err(e) = std::fs::write(&part, &buf[8..8 + n]) {
                            let _ = std::fs::remove_file(&part);
                            eprintln!("cannot write the output file {}: {e}", out.display());
                            stored = false;
                        } else if let Err(e) = std::fs::rename(&part, &out) {
                            let _ = std::fs::remove_file(&part);
                            eprintln!("cannot move {} to {}: {e}", part.display(), out.display());
                            stored = false;
                        }
                        // Tell the sender on stream 2 whether the file was
                        // stored: 0 stored, 1 failure. This is the sender's
                        // cue to close, so the verdict must go out even when
                        // the write failed.
                        ep.send_bytes(c, 2, &[if stored { 0 } else { 1 }]);
                        if stored {
                            println!("received {n} bytes");
                        }
                        // The tail is not subject to --timeout-secs: it has
                        // its own bound. Keep polling so the verdict and the
                        // final ACKs leave and the sender's CLOSE arrives.
                        // The receiver never closes the session itself: it
                        // ends when the sender closes it, or after 10 seconds
                        // from the write. Poll errors are ignored: the file
                        // verdict is already decided.
                        let written = Instant::now();
                        while ep.node.peer_of(c).is_some() && written.elapsed() < Duration::from_secs(10) {
                            let got = ep.poll().unwrap_or(0);
                            if got == 0 && ep.queued() == 0 {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                        }
                        exit(if stored { 0 } else { 1 });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(n: u64) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    #[test]
    fn seven_bytes_are_not_a_length_yet() {
        let buf = vec![1u8; 7];
        assert_eq!(frame_length(&buf, MAX_FILE_BYTES), Ok(None));
    }

    #[test]
    fn a_small_prefix_is_returned_as_is() {
        let buf = prefix(5);
        assert_eq!(frame_length(&buf, MAX_FILE_BYTES), Ok(Some(5)));
    }

    #[test]
    fn max_u64_prefix_is_an_error() {
        let buf = prefix(u64::MAX);
        assert!(frame_length(&buf, MAX_FILE_BYTES).is_err());
    }

    #[test]
    fn near_max_u64_prefix_is_an_error() {
        let buf = prefix(u64::MAX - 3);
        assert!(frame_length(&buf, MAX_FILE_BYTES).is_err());
    }

    #[test]
    fn a_prefix_of_exactly_max_is_accepted() {
        let buf = prefix(MAX_FILE_BYTES);
        assert_eq!(frame_length(&buf, MAX_FILE_BYTES), Ok(Some(MAX_FILE_BYTES as usize)));
    }

    #[test]
    fn a_prefix_of_max_plus_one_is_an_error() {
        let buf = prefix(MAX_FILE_BYTES + 1);
        assert!(frame_length(&buf, MAX_FILE_BYTES).is_err());
    }

    #[test]
    fn the_size_limit_holds_at_exactly_the_cap() {
        assert!(!too_big(MAX_FILE_BYTES));
        assert!(too_big(MAX_FILE_BYTES + 1));
    }
}
