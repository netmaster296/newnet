// udpfile: send one file from one process to another over a newnet session
// on UDP. Usage:
//   udpfile recv --name bob --seed 2 --peer alice --peer-seed 1 --listen 127.0.0.1:4002 --out received.bin [--timeout-secs 30]
//   udpfile send --name alice --seed 1 --peer bob --peer-seed 2 --to 127.0.0.1:4002 --file input.bin [--listen 127.0.0.1:0] [--timeout-secs 30]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, Instant};

use newnet::crypto::PeerRecord;
use newnet::identity::Identity;
use newnet::node::Node;
use newnet::udp::UdpEndpoint;

const MAX_FILE_BYTES: u64 = 1 << 30;

fn usage() -> ! {
    eprintln!("usage: udpfile recv --name <name> --seed <n> --peer <name> --peer-seed <n> --listen <addr:port> --out <file> [--timeout-secs <n>]");
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
    peer: String,
    peer_seed: u64,
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
        peer: String::new(),
        peer_seed: 0,
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
            "--peer" => o.peer = val(),
            "--peer-seed" => {
                o.peer_seed = val().parse().unwrap_or_else(|_| usage());
                have_peer_seed = true;
            }
            "--listen" => o.listen = Some(val()),
            "--out" => o.out = Some(PathBuf::from(val())),
            "--file" => o.file = Some(PathBuf::from(val())),
            "--to" => o.to = Some(val().parse().unwrap_or_else(|_| usage())),
            "--timeout-secs" => o.timeout_secs = val().parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    if o.name.is_empty() || o.peer.is_empty() || !have_seed || !have_peer_seed {
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

fn warn_lab_only(listen: &SocketAddr) {
    eprintln!("LAB ONLY: identities are derived from numeric seeds");
    if !listen.ip().is_loopback() {
        eprintln!("WARNING: listening beyond loopback. This build has no handshake cookie; do not expose it to an untrusted network.");
    }
}

fn node_with_peer(o: &Opts) -> Node {
    let mut node = Node::new(&o.name, o.seed);
    let id = Identity::from_seed(o.peer_seed);
    node.records.insert(
        o.peer.clone(),
        PeerRecord { name: o.peer.clone(), ed: id.ed_pub(), x: id.x_pub, expiry: u64::MAX },
    );
    node
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
    warn_lab_only(&listen);

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
        let data = match std::fs::read(&file) {
            Ok(d) => d,
            Err(e) => fail(format!("cannot read the input file {}: {e}", file.display())),
        };
        let mut ep = match UdpEndpoint::bind(node_with_peer(&o), &listen.to_string()) {
            Ok(e) => e,
            Err(e) => fail(format!("cannot bind {listen}: {e}")),
        };
        let to = match o.to {
            Some(t) => t,
            None => usage(),
        };
        // The conn id connect returned can die under a retry: the node starts
        // a fresh attempt under a new id. Follow the session by peer name
        // instead of holding the id.
        if let Err(e) = ep.connect(&o.peer, to) {
            fail(format!("cannot connect to {}: {e:?}", o.peer));
        }
        let start = Instant::now();
        let conn = loop {
            if timed_out(start, o.timeout_secs) {
                fail("timed out");
            }
            if let Some(c) = ep.node.session_with(&o.peer) {
                break c;
            }
            if !ep.node.is_connecting_to(&o.peer) {
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
    let mut ep = match UdpEndpoint::bind(node_with_peer(&o), &listen.to_string()) {
        Ok(e) => e,
        Err(e) => fail(format!("cannot bind {listen}: {e}")),
    };
    let start = Instant::now();
    let mut conn: Option<u64> = None;
    let mut buf: Vec<u8> = Vec::new();
    loop {
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
        if conn.is_none() {
            conn = ep
                .node
                .sessions
                .keys()
                .copied()
                .find(|c| ep.node.peer_of(*c) == Some(o.peer.as_str()));
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
