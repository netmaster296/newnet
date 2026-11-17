// Trace-shape replay: MAWI/CAIDA/own captures drive newnet sessions with
// real packet-size distributions, flow mix, burstiness and concurrency.
// Usage: cargo run --release --bin replay -- <path.pcap|path.dump[.gz]> [opts]
//   --max-packets N   parse at most N trace records (default 500000)
//   --flows N         replay the N largest flows (default 200)
//   --loss P          hub loss percent (default 0)
//   --reorder P       hub reorder percent (default 0)
//   --adversarial     every trace packet (+1 bit flip) through on_datagram
//   --full            parse the entire file (overrides --max-packets)

use std::io::BufReader;
use std::time::Instant;

use flate2::read::GzDecoder;

use newnet::link::Hub;
use newnet::node::Node;
use newnet::pcap::{self, TraceReader};

struct Opts {
    path: String,
    max_packets: usize,
    flows: usize,
    loss: usize,
    reorder: usize,
    adversarial: bool,
    compat: bool,
}

fn pat(flow: usize, dir: usize, idx: usize) -> u8 {
    ((idx as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add((flow * 1000 + dir) as u64)
        >> 24) as u8
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut o = Opts {
        path: String::new(),
        max_packets: 500_000,
        flows: 200,
        loss: 0,
        reorder: 0,
        adversarial: false,
        compat: false,
    };
    let mut i = 1;
    let mut full = false;
    while i < argv.len() {
        match argv[i].as_str() {
            "--max-packets" => {
                o.max_packets = argv[i + 1].parse().unwrap();
                i += 2;
            }
            "--flows" => {
                o.flows = argv[i + 1].parse().unwrap();
                i += 2;
            }
            "--loss" => {
                o.loss = argv[i + 1].parse().unwrap();
                i += 2;
            }
            "--reorder" => {
                o.reorder = argv[i + 1].parse().unwrap();
                i += 2;
            }
            "--adversarial" => {
                o.adversarial = true;
                i += 1;
            }
            "--compat" => {
                o.compat = true;
                i += 1;
            }
            "--full" => {
                full = true;
                i += 1;
            }
            s => {
                o.path = s.to_string();
                i += 1;
            }
        }
    }
    if o.path.is_empty() {
        println!("usage: replay <trace.pcap|dump[.gz]> [--full] [--max-packets N] [--flows N] [--loss P] [--reorder P] [--adversarial]");
        return;
    }
    if full {
        o.max_packets = usize::MAX;
    }

    let file = match std::fs::File::open(&o.path) {
        Ok(f) => f,
        Err(e) => {
            println!("cannot open {}: {e}", o.path);
            return;
        }
    };
    let t_load = Instant::now();
    let mut pkts: Vec<pcap::TracePacket> = Vec::new();
    let linktype;
    let mut parse_errs = 0usize;
    let read = if o.path.ends_with(".gz") {
        Box::new(BufReader::new(GzDecoder::new(file))) as Box<dyn std::io::Read>
    } else {
        Box::new(BufReader::new(file)) as Box<dyn std::io::Read>
    };
    let mut tr = match TraceReader::new(read) {
        Ok(t) => t,
        Err(e) => {
            println!("cannot parse {}: {e:?}", o.path);
            return;
        }
    };
    linktype = tr.linktype;
    for p in tr.by_ref() {
        match p {
            Ok(p) => {
                pkts.push(p);
                if pkts.len() >= o.max_packets {
                    break;
                }
            }
            Err(_) => {
                parse_errs += 1;
                break;
            }
        }
    }
    println!(
        "trace: {} records parsed in {:.2}s (parse errors at stream end: {})",
        pkts.len(),
        t_load.elapsed().as_secs_f64(),
        parse_errs
    );
    // ---- trace character ----
    let t_stat = Instant::now();
    let mut proto_cnt = [0u64; 3]; // tcp, udp, icmp/other-ip
    let mut non_ip = 0u64;
    let mut ip_bytes = 0u64;
    let mut buckets = [0u64; 7]; // <=64 128 256 512 1024 1500 >1500
    let mut first_ts = u64::MAX;
    let mut last_ts = 0u64;
    for p in &pkts {
        match pcap::l3_link(&p.data, linktype) {
            Some((_, _, proto, _, _, payload)) => {
                ip_bytes += p.wirelen as u64;
                *match proto {
                    6 => &mut proto_cnt[0],
                    17 => &mut proto_cnt[1],
                    _ => &mut proto_cnt[2],
                } += 1;
                let s = payload.len();
                let b = if s <= 64 {
                    0
                } else if s <= 128 {
                    1
                } else if s <= 256 {
                    2
                } else if s <= 512 {
                    3
                } else if s <= 1024 {
                    4
                } else if s <= 1500 {
                    5
                } else {
                    6
                };
                buckets[b] += 1;
                first_ts = first_ts.min(p.ts_micros);
                last_ts = last_ts.max(p.ts_micros);
            }
            None => non_ip += 1,
        }
    }
    println!(
        "shape: tcp={} udp={} other-ip={} non-ip={} ip-bytes={} span={:.1}s",
        proto_cnt[0],
        proto_cnt[1],
        proto_cnt[2],
        non_ip,
        ip_bytes,
        (last_ts.saturating_sub(first_ts)) as f64 / 1e6
    );
    println!(
        "payload-size buckets <=64/128/256/512/1024/1500/>1500: {:?}",
        buckets
    );

    let fl = pcap::flows_link(&pkts, linktype);
    let total_flow_bytes: u64 = fl.iter().map(|f| f.bytes_ab + f.bytes_ba).sum();
    let mut fl = fl;
    fl.sort_by(|a, b| {
        (b.bytes_ab + b.bytes_ba).cmp(&(a.bytes_ab + a.bytes_ba))
    });
    let mut sel: Vec<&pcap::FlowShape> = fl
        .iter()
        .filter(|f| f.bytes_ab + f.bytes_ba > 0)
        .take(o.flows)
        .collect();
    if o.compat {
        // compat mode: flows that actually carry payload (full-payload captures)
        let mut with_payload: Vec<&pcap::FlowShape> = fl
            .iter()
            .filter(|f| {
                f.bytes_ab > 0
                    && f.sizes_ab.iter().any(|s| *s > 0)
                    && f.key.proto == 6
            })
            .collect();
        with_payload.sort_by(|a, b| {
            (b.bytes_ab + b.bytes_ba).cmp(&(a.bytes_ab + a.bytes_ba))
        });
        sel = with_payload.into_iter().take(o.flows).collect();
    }
    let sel_bytes: u64 = sel.iter().map(|f| f.bytes_ab + f.bytes_ba).sum();
    println!(
        "flows: total={} replaying top={} covering {} bytes of {} ({:.1}% of flow bytes)",
        fl.len(),
        sel.len(),
        sel_bytes,
        total_flow_bytes,
        100.0 * sel_bytes as f64 / (total_flow_bytes.max(1)) as f64
    );
    for f in sel.iter().take(5) {
        println!(
            "  proto={} a:{}:{} b:{}:{} pkts={}+{} bytes={}+{}",
            f.key.proto,
            hex::encode(f.key.a),
            f.key.pa,
            hex::encode(f.key.b),
            f.key.pb,
            f.pkts_ab,
            f.pkts_ba,
            f.bytes_ab,
            f.bytes_ba
        );
    }
    println!("stats took {:.2}s", t_stat.elapsed().as_secs_f64());

    // ---- topology: alice <-> bob, direct-pinned records ----
    let mut nodes = vec![Node::new("alice.example", 0xA11CE), Node::new("bob.example", 0xB0B)];
    for (me, other) in [(0usize, 1usize), (1, 0)] {
        let rec = newnet::crypto::PeerRecord {
            name: nodes[other].name.clone(),
            ed: nodes[other].ident.ed_pub().clone(),
            x: nodes[other].ident.x_pub,
            cert: vec![],
        };
        nodes[me].records.insert(rec.name.clone(), rec);
    }
    let mut hub = Hub::new(2, o.loss as u32, o.reorder as u32, 0xBADC0FFE);
    let (conn, hs1) = nodes[0].connect("bob.example", Some([7u8; 32])).unwrap();
    let hs2 = nodes[1].on_datagram(&hs1, 0);
    nodes[0].on_datagram(&hs2[0], 0);
    assert!(nodes[0].is_open(conn) && nodes[1].is_open(conn));

    // ---- replay: each flow direction is its own stream, chunked per trace packet ----
    let payloads = if o.compat { flow_payloads(&pkts, &sel, linktype) } else { Vec::new() };
    let t_rep = Instant::now();
    let mut sent_pkts = 0usize;
    let mut sent_bytes = 0u64;
    let mut expected: Vec<(u32, Vec<u8>)> = Vec::new(); // stream id, expected bytes
    for (k, f) in sel.iter().enumerate() {
        for (dir, sizes) in [(0usize, &f.sizes_ab), (1, &f.sizes_ba)] {
            if sizes.is_empty() {
                continue;
            }
            let stream = (k * 2 + dir) as u32;
            let mut buf: Vec<u8> = Vec::new();
            let chunks: Vec<Vec<u8>> = if o.compat {
                if dir == 0 {
                    payloads[k].0.clone()
                } else {
                    payloads[k].1.clone()
                }
            } else {
                let mut v: Vec<Vec<u8>> = Vec::new();
                let mut off = 0usize;
                for s in sizes {
                    let n = *s as usize;
                    if n == 0 {
                        continue;
                    }
                    v.push((0..n).map(|i| pat(k, dir, off + i)).collect());
                    off += n;
                }
                v
            };
            for chunk in &chunks {
                if chunk.is_empty() {
                    continue;
                }
                buf.extend_from_slice(chunk);
                let out = nodes[0].send_bytes(conn, stream, chunk, 0);
                sent_pkts += out.len();
                sent_bytes += chunk.len() as u64;
                for p in out {
                    hub.send(0, &p);
                }
            }
            expected.push((stream, buf));
        }
    }
    let rep_send = t_rep.elapsed().as_secs_f64();

    // drain with retransmit timers running
    let total_expected: u64 = expected.iter().map(|(_, b)| b.len() as u64).sum();
    let mut rounds = 0usize;
    for _ in 0..200_000 {
        hub.step();
        let mut any = false;
        for n in 0..2 {
            let pk = hub.drain(n);
            if pk.is_empty() {
                continue;
            }
            any = true;
            for p in &pk {
                let outs = nodes[n].on_datagram(p, hub.tick);
                for o2 in outs {
                    hub.send(n, &o2);
                }
            }
        }
        let outs = nodes[0].tick_sessions(hub.tick, 3);
        for (_, o2) in outs {
            hub.send(0, &o2);
            any = true;
        }
        rounds += 1;
        if rounds % 2000 == 0 { eprintln!("round={} any={} ok={} fwd={} pend={}", rounds, any, nodes[1].stats.data_ok, hub.forwarded, nodes[0].sessions.get(&conn).map(|s| s.tx_streams.values().map(|t| t.pending()).sum::<usize>()).unwrap_or(0)); }
        if !any {
            let deliv = nodes[1]
                .sessions
                .get(&conn)
                .map(|s| s.delivered.values().map(|v| v.len() as u64).sum())
                .unwrap_or(0);
            if deliv >= total_expected {
                break;
            }
        }
    }
    let rep_total = t_rep.elapsed().as_secs_f64();

    // ---- verification ----
    let mut streams_ok = 0usize;
    let mut mismatches = 0usize;
    let mut delivered_bytes = 0u64;
    for (stream, want) in &expected {
        let got = nodes[1].take_stream_bytes(conn, *stream);
        delivered_bytes += got.len() as u64;
        let ok = got.len() == want.len()
            && got.iter().enumerate().all(|(i, b)| *b == want[i]);
        if ok {
            streams_ok += 1;
        } else {
            mismatches += 1;
            println!("  mismatch stream={stream} want={} got={}", want.len(), got.len());
            let ax = nodes[0].sessions.get(&conn).and_then(|s| s.tx_streams.get(&stream)).map(|t| (t.next_off, t.pending())).unwrap_or((0,0));
            let br = nodes[1].sessions.get(&conn).and_then(|s| s.rx_streams.get(&stream)).map(|r| r.expected).unwrap_or(0);
            println!("    alice next_off={} pending={} oldest_sent={} hub_tick={} bob expected={}", ax.0, ax.1, nodes[0].sessions.get(&conn).and_then(|s| s.tx_streams.get(&stream)).and_then(|t| t.oldest_sent()).unwrap_or(u64::MAX), hub.tick, br);
        }
    }

    println!(
        "replay: sent {} stream-chunks / {} bytes over {} streams; hub rounds={}; delivered={} bytes",
        sent_pkts,
        sent_bytes,
        expected.len(),
        rounds,
        delivered_bytes
    );
    println!(
        "verify: {}/{} streams byte-exact; mismatches={}",
        streams_ok,
        expected.len(),
        mismatches
    );
    let st = &nodes[1].stats;
    println!(
        "counters: ok={} badtag={} replay={} nosess={} budget_drop={} legacy={} bad_header={}",
        st.data_ok, st.data_badtag, st.data_replay, st.no_session_dropped, st.handshake_dropped_budget, st.legacy_dropped, st.bad_header_dropped
    );
    println!(
        "speed: send {:.1} Mbps ({:.2}s), total {:.1} Mbps ({:.2}s)  [CPU: {} streams in one session]",
        8.0 * sent_bytes as f64 / rep_send / 1e6,
        rep_send,
        8.0 * sent_bytes as f64 / rep_total / 1e6,
        rep_total,
        expected.len()
    );

    // ---- adversarial pass: real packets through the receive path ----
    if o.adversarial {
        let t_adv = Instant::now();
        let (mut legacy, mut badhdr) = (0u64, 0u64);
        for p in &pkts {
            let b0 = nodes[1].stats.legacy_dropped;
            let b1 = nodes[1].stats.bad_header_dropped;
            let outs = nodes[1].on_datagram(&p.data, 1);
            for x in outs {
                hub.send(1, &x);
            }
            if nodes[1].stats.legacy_dropped > b0 {
                legacy += 1;
            } else if nodes[1].stats.bad_header_dropped > b1 {
                badhdr += 1;
            }
            // one bit flip at a position that varies per packet
            if !p.data.is_empty() {
                let mut q = p.data.clone();
                let pos = p.ts_micros as usize % q.len();
                q[pos] ^= 1 << (p.ts_micros % 8) as usize;
                nodes[1].on_datagram(&q, 1);
            }
        }
        println!(
            "adversarial: {} packets + {} bitflips -> legacy_magic={} bad_header={} no panics ({:.2}s)",
            pkts.len(),
            pkts.len(),
            legacy,
            badhdr,
            t_adv.elapsed().as_secs_f64()
        );
    }
    println!("done.");
}

// Collect per-flow payload vectors (trace packet order), for compat replay.
pub fn flow_payloads(
    pkts: &[pcap::TracePacket],
    sel: &[&pcap::FlowShape],
    linktype: u32,
) -> Vec<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    use std::collections::HashMap;
    let mut idx: HashMap<pcap::FlowKey, usize> = HashMap::new();
    for (k, f) in sel.iter().enumerate() {
        idx.insert(f.key, k);
    }
    let mut out: Vec<(Vec<Vec<u8>>, Vec<Vec<u8>>)> = sel.iter().map(|_| (Vec::new(), Vec::new())).collect();
    for p in pkts {
        let (s, d, proto, pa, pb, payload) = match pcap::l3_link(&p.data, linktype) {
            Some(x) => x,
            None => continue,
        };
        let (a, b, qa, qb, forward) = if (s, pa) <= (d, pb) {
            (s, d, pa, pb, true)
        } else {
            (d, s, pb, pa, false)
        };
        let k = match idx.get(&pcap::FlowKey { a, b, proto, pa: qa, pb: qb }) {
            Some(k) => *k,
            None => continue,
        };
        if forward {
            out[k].0.push(payload);
        } else {
            out[k].1.push(payload);
        }
    }
    out
}
