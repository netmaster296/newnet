// udpfile: send one file from one process to another over a newnet session
// on UDP. Usage:
//   udpfile recv --name bob --seed 2 --peer alice --peer-seed 1 --listen 127.0.0.1:4002 --out received.bin [--timeout-secs 30]
//   udpfile send --name alice --seed 1 --peer bob --peer-seed 2 --to 127.0.0.1:4002 --file input.bin [--listen 127.0.0.1:0] [--timeout-secs 30]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::exit;
use std::time::{Duration, Instant};

use newnet::crypto::PeerRecord;
use newnet::identity::Identity;
use newnet::node::Node;
use newnet::udp::UdpEndpoint;

fn usage() -> ! {
    eprintln!("usage: udpfile recv --name <name> --seed <n> --peer <name> --peer-seed <n> --listen <addr:port> --out <file> [--timeout-secs <n>]");
    eprintln!("   or: udpfile send --name <name> --seed <n> --peer <name> --peer-seed <n> --to <addr:port> --file <file> [--listen <addr:port>] [--timeout-secs <n>]");
    exit(2);
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

fn parse() -> Opts {
    let args: Vec<String> = std::env::args().skip(1).collect();
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

// 16 chunks per slice: one poll's BURST is 32 datagrams, and bursts above
// the peer's kernel receive buffer (64 KB on Windows) get dropped and turn
// into a retransmit storm.
const BURST_SLICE: usize = 16 * newnet::streams::CHUNK;

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
        let data = match &o.file {
            Some(f) => match std::fs::read(f) {
                Ok(d) => d,
                Err(_) => usage(),
            },
            None => usage(),
        };
        let mut ep = match UdpEndpoint::bind(node_with_peer(&o), &listen.to_string()) {
            Ok(e) => e,
            Err(_) => usage(),
        };
        let to = o.to.unwrap();
        let conn = match ep.connect(&o.peer, to) {
            Ok(c) => c,
            Err(_) => usage(),
        };
        let start = Instant::now();
        while !ep.node.is_open(conn) {
            if timed_out(start, o.timeout_secs) {
                eprintln!("timed out");
                exit(1);
            }
            let r = ep.poll().unwrap();
            if r == 0 && ep.queued() == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        ep.send_bytes(conn, 1, &(data.len() as u64).to_le_bytes());
        // Feed the file a slice per poll round: queuing all 1.5 MB at once
        // lets the first BURST outrun the peer's small kernel receive buffer,
        // and the retransmit storm that follows eats the transfer.
        let mut pos = 0usize;
        loop {
            let s = ep.node.sessions.get(&conn);
            let done = pos >= data.len()
                && ep.queued() == 0
                && matches!(s, Some(s) if s.in_flight_total() == 0 && s.queued_chunks() == 0);
            if done {
                break;
            }
            if timed_out(start, o.timeout_secs) {
                eprintln!("timed out");
                exit(1);
            }
            if ep.queued() == 0 && pos < data.len() {
                let end = (pos + BURST_SLICE).min(data.len());
                ep.send_bytes(conn, 1, &data[pos..end]);
                pos = end;
            }
            let r = ep.poll().unwrap();
            if r == 0 && ep.queued() == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        ep.close(conn);
        for _ in 0..5 {
            ep.poll().unwrap();
            if ep.queued() == 0 {
                break;
            }
        }
        println!("sent {} bytes", data.len());
        exit(0);
    }

    let out = o.out.clone().unwrap();
    let mut ep = match UdpEndpoint::bind(node_with_peer(&o), &listen.to_string()) {
        Ok(e) => e,
        Err(_) => usage(),
    };
    let start = Instant::now();
    let mut conn: Option<u64> = None;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if timed_out(start, o.timeout_secs) {
            eprintln!("timed out");
            exit(1);
        }
        let r = ep.poll().unwrap();
        if conn.is_none() {
            conn = ep.node.sessions.keys().next().copied();
        }
        if let Some(c) = conn {
            buf.extend(ep.node.take_stream_bytes(c, 1));
            if buf.len() >= 8 {
                let n = u64::from_le_bytes(buf[..8].try_into().unwrap()) as usize;
                if buf.len() >= 8 + n {
                    match std::fs::write(&out, &buf[8..8 + n]) {
                        Ok(_) => {}
                        Err(_) => usage(),
                    }
                    // Let the final ACKs leave before exiting: the sender
                    // waits for them before it closes.
                    while ep.queued() > 0 {
                        ep.poll().unwrap();
                    }
                    println!("received {} bytes", n);
                    exit(0);
                }
            }
        }
        if r == 0 && ep.queued() == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
