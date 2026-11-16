// Offline trace readers: classic pcap and snoop (MAWI's older .dump format).
// Pure parsing + flow-shape extraction. No replay timing lives here.

use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub enum PcapError {
    Truncated,
    Unsupported(String),
}

#[derive(Clone, Debug)]
pub struct TracePacket {
    pub ts_micros: u64,
    pub wirelen: u32,
    pub data: Vec<u8>,
}

// ---- streaming reader: pcap and snoop, record-at-a-time ----

use std::io::Read;

pub struct TraceReader<R: Read> {
    r: R,
    kind: u8, // 1 = pcap, 2 = snoop
    le: bool,
    init: bool,
    pub linktype: u32,
}

fn read_or_eof(r: &mut impl Read, buf: &mut [u8]) -> Result<bool, PcapError> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(PcapError::Truncated),
        }
    }
    if filled == 0 {
        return Ok(false); // clean EOF at a record boundary
    }
    if filled < buf.len() {
        return Err(PcapError::Truncated);
    }
    Ok(true)
}

impl<R: Read> TraceReader<R> {
    pub fn new(mut r: R) -> Result<TraceReader<R>, PcapError> {
        let mut m = [0u8; 4];
        if !read_or_eof(&mut r, &mut m)? {
            return Err(PcapError::Truncated);
        }
        let v = u32::from_be_bytes(m);
        let (kind, le) = match v {
            0xa1b2_c3d4 | 0xa1b2_3c4d => (1u8, false),
            0xd4c3_b2a1 | 0x4dc3_b2a1 => (1, true),
            0x0737_010d => (2, false),
            0x0a0d_0d0a => {
                return Err(PcapError::Unsupported("pcapng not supported".into()))
            }
            _ => return Err(PcapError::Unsupported(format!("unknown magic {v:08x}"))),
        };
        // Consume the rest of the fixed global header and capture the link type now.
        let rest = if kind == 1 { 20 } else { 16 };
        let mut tmp = [0u8; 20];
        if !read_or_eof(&mut r, &mut tmp[..rest])? {
            return Err(PcapError::Truncated);
        }
        let linktype = if kind == 1 {
            let a = [tmp[16], tmp[17], tmp[18], tmp[19]];
            if le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        } else {
            let a = [tmp[4], tmp[5], tmp[6], tmp[7]]; // snoop: linktype at file hdr offset 8
            u32::from_be_bytes(a)
        };
        Ok(TraceReader { r, kind, le, init: true, linktype })
    }
}

impl<R: Read> Iterator for TraceReader<R> {
    type Item = Result<TracePacket, PcapError>;
    fn next(&mut self) -> Option<Result<TracePacket, PcapError>> {
        if !self.init {
            let rest = if self.kind == 1 { 20 } else { 16 }; // skip fixed global header tail
            let mut tmp = [0u8; 20];
            if let Err(e) = read_or_eof(&mut self.r, &mut tmp[..rest]) {
                return Some(Err(e));
            }
            self.linktype = if self.kind == 1 {
                let a = [tmp[16], tmp[17], tmp[18], tmp[19]];
                if self.le {
                    u32::from_le_bytes(a)
                } else {
                    u32::from_be_bytes(a)
                }
            } else {
                let a = [tmp[4], tmp[5], tmp[6], tmp[7]]; // snoop: linktype at file hdr offset 8
                u32::from_be_bytes(a)
            };
            self.init = true;
        }
        let mut hdr = [0u8; 20];
        let hdrlen = if self.kind == 1 { 16usize } else { 20usize };
        match read_or_eof(&mut self.r, &mut hdr[..hdrlen]) {
            Ok(false) => return None,
            Ok(true) => {}
            Err(e) => return Some(Err(e)),
        }
        let g = |o: usize| -> u32 {
            let a = [hdr[o], hdr[o + 1], hdr[o + 2], hdr[o + 3]];
            if self.le {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            }
        };
        let (sec, usec, present, wirelen) = if self.kind == 1 {
            (g(0) as u64, g(4) as u64, g(8) as usize, g(12))
        } else {
            (g(12) as u64, g(16) as u64, g(4) as usize, g(0))
        };
        let _ = hdrlen;
        if present > 65536 {
            return Some(Err(PcapError::Truncated));
        }
        let mut data = vec![0u8; present];
        if let Err(e) = read_or_eof(&mut self.r, &mut data) {
            return Some(Err(e));
        }
        if self.kind == 2 {
            let pad = (4 - present % 4) % 4;
            if pad > 0 {
                let mut p = [0u8; 3];
                if let Err(e) = read_or_eof(&mut self.r, &mut p[..pad]) {
                    return Some(Err(e));
                }
            }
        }
        Some(Ok(TracePacket {
            ts_micros: sec * 1_000_000 + usec,
            wirelen,
            data,
        }))
    }
}

// Collect an entire in-memory file (tests, small captures).
pub fn open(bytes: &[u8]) -> Result<Vec<TracePacket>, PcapError> {
    let mut r = TraceReader::new(bytes)?;
    let mut out = Vec::new();
    for p in r.by_ref() {
        out.push(p?);
    }
    Ok(out)
}

// ---- L3/L4 view for flow shaping ----

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FlowKey {
    pub a: [u8; 16],
    pub b: [u8; 16],
    pub proto: u8,
    pub pa: u16,
    pub pb: u16,
}

#[derive(Clone, Debug)]
pub struct FlowShape {
    pub key: FlowKey,
    pub pkts_ab: u32,
    pub pkts_ba: u32,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub sizes_ab: Vec<u16>,
    pub sizes_ba: Vec<u16>,
}

const MAX_SIZES: usize = 4096;

// Parse IP -> TCP/UDP from the L3 start offset. Ethernet assumed; use l3_link for other link types.
pub fn l3(pkt: &[u8]) -> Option<([u8; 16], [u8; 16], u8, u16, u16, Vec<u8>)> {
    l3_link(pkt, 1)
}

// Link types: 1=Ethernet, 12/107/228=raw IP, 113=Linux SLL, 276=Linux SLL2.
pub fn l3_link(pkt: &[u8], linktype: u32) -> Option<([u8; 16], [u8; 16], u8, u16, u16, Vec<u8>)> {
    let mut off = match linktype {
        1 => 14usize,
        12 | 107 | 228 => 0usize, // raw IP: no L2
        113 => {
            if pkt.len() < 16 {
                return None;
            }
            16usize
        }
        276 => {
            if pkt.len() < 20 {
                return None;
            }
            20usize
        }
        _ => return None,
    };
    let mut et = match linktype {
        1 => {
            if pkt.len() < 14 {
                return None;
            }
            u16::from_be_bytes([pkt[12], pkt[13]])
        }
        113 => u16::from_be_bytes([pkt[14], pkt[15]]),
        276 => u16::from_be_bytes([pkt[0], pkt[1]]),
        _ => 0xffff,
    };
    if linktype == 1 {
        while et == 0x8100 || et == 0x88a8 {
            if off + 4 > pkt.len() {
                return None;
            }
            et = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
            off += 4;
        }
        if et != 0x0800 && et != 0x86dd {
            return None;
        }
    }
    let ip = &pkt[off.min(pkt.len())..];
    if ip.is_empty() {
        return None;
    }
    let v = ip[0] >> 4;
    let (src, dst, proto, l4off) = match v {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            if ihl < 20 || ip.len() < ihl {
                return None;
            }
            let mf = (ip[6] & 0x01) != 0;
            let frag_off = ((ip[6] as u16 & 0x3f) << 8 | ip[7] as u16) & 0x1fff;
            if mf && frag_off != 0 {
                return None; // non-first fragment: no reliable L4
            }
            if frag_off != 0 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s[..4].copy_from_slice(&ip[12..16]);
            d[..4].copy_from_slice(&ip[16..20]);
            (s, d, ip[9], ihl)
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&ip[8..24]);
            d.copy_from_slice(&ip[24..40]);
            let mut proto = ip[6];
            let mut l4 = 40usize;
            for _ in 0..4 {
                match proto {
                    0 | 43 | 60 => {
                        if l4 + 8 > ip.len() {
                            return None;
                        }
                        proto = ip[l4];
                        l4 += 8 + (ip[l4 + 1] as usize) * 8;
                    }
                    44 => {
                        if l4 + 14 > ip.len() {
                            return None;
                        }
                        proto = ip[l4];
                        l4 += 14;
                    }
                    _ => break,
                }
            }
            if l4 >= ip.len() {
                return None;
            }
            (s, d, proto, l4)
        }
        _ => return None,
    };
    let (pa, pb, po) = match proto {
        6 => {
            if l4off + 20 > ip.len() {
                return None;
            }
            let doff = ((ip[l4off + 12] >> 4) as usize) * 4;
            if doff < 20 || l4off + doff > ip.len() {
                return None;
            }
            (
                u16::from_be_bytes([ip[l4off], ip[l4off + 1]]),
                u16::from_be_bytes([ip[l4off + 2], ip[l4off + 3]]),
                l4off + doff,
            )
        }
        17 => {
            if l4off + 8 > ip.len() {
                return None;
            }
            (
                u16::from_be_bytes([ip[l4off], ip[l4off + 1]]),
                u16::from_be_bytes([ip[l4off + 2], ip[l4off + 3]]),
                l4off + 8,
            )
        }
        1 => (0, 0, l4off + 8), // ICMP: shape it as a flow, ports 0
        _ => return None,
    };
    Some((src, dst, proto, pa, pb, ip[po.min(ip.len())..].to_vec()))
}

// Group trace packets into directional flow shapes (normalized key order).
pub fn flows(pkts: &[TracePacket]) -> Vec<FlowShape> {
    flows_link(pkts, 1)
}

pub fn flows_link(pkts: &[TracePacket], linktype: u32) -> Vec<FlowShape> {
    let mut map: BTreeMap<FlowKey, FlowShape> = BTreeMap::new();
    for p in pkts {
        let (s, d, proto, pa, pb, payload) = match l3_link(&p.data, linktype) {
            Some(x) => x,
            None => continue,
        };
        let (a, b, qa, qb, forward) = if (s, pa) <= (d, pb) {
            (s, d, pa, pb, true)
        } else {
            (d, s, pb, pa, false)
        };
        let key = FlowKey { a, b, proto, pa: qa, pb: qb };
        let f = map.entry(key).or_insert_with(|| FlowShape {
            key,
            pkts_ab: 0,
            pkts_ba: 0,
            bytes_ab: 0,
            bytes_ba: 0,
            first_ts: p.ts_micros,
            last_ts: p.ts_micros,
            sizes_ab: Vec::new(),
            sizes_ba: Vec::new(),
        });
        f.first_ts = f.first_ts.min(p.ts_micros);
        f.last_ts = f.last_ts.max(p.ts_micros);
        let n = payload.len() as u64;
        if forward {
            f.pkts_ab += 1;
            f.bytes_ab += n;
            if f.sizes_ab.len() < MAX_SIZES {
                f.sizes_ab.push(payload.len() as u16);
            }
        } else {
            f.pkts_ba += 1;
            f.bytes_ba += n;
            if f.sizes_ba.len() < MAX_SIZES {
                f.sizes_ba.push(payload.len() as u16);
            }
        }
    }
    map.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_ipv4_tcp(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 14 + 20 + 20];
        p[12] = 0x08;
        p[13] = 0x00;
        p[14] = 0x45;
        let tl = 20 + 20 + payload.len();
        p[16] = (tl >> 8) as u8;
        p[17] = tl as u8;
        p[23] = 6;
        p[26] = 10; // src ip first byte
        p[30] = 20; // dst
        p[34] = 0x30;
        p[35] = 0x39; // sport 12345
        p[36] = 0x00;
        p[37] = 80; // dport
        p[46] = 0x50; // data offset 20
        p.extend_from_slice(payload);
        p
    }

    fn pcap_le(records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        f.extend_from_slice(&[2, 4, 0, 0]);
        f.extend_from_slice(&0i32.to_le_bytes());
        f.extend_from_slice(&0u32.to_le_bytes());
        f.extend_from_slice(&65535u32.to_le_bytes());
        f.extend_from_slice(&1u32.to_le_bytes());
        for (sec, usec, d) in records {
            f.extend_from_slice(&sec.to_le_bytes());
            f.extend_from_slice(&usec.to_le_bytes());
            f.extend_from_slice(&(d.len() as u32).to_le_bytes());
            f.extend_from_slice(&(d.len() as u32).to_le_bytes());
            f.extend_from_slice(d);
        }
        f
    }

    #[test]
    fn pcap_roundtrip_and_flows() {
        let a = eth_ipv4_tcp(b"abc");
        let b = eth_ipv4_tcp(b"defg");
        let file = pcap_le(&[(100, 0, &a), (101, 500, &b)]);
        let pk = open(&file).unwrap();
        assert_eq!(pk.len(), 2);
        assert_eq!(pk[0].ts_micros, 100_000_000);
        let fl = flows(&pk);
        assert_eq!(fl.len(), 1);
        let f = &fl[0];
        assert_eq!(f.key.proto, 6);
        assert_eq!(f.key.pa, 12345);
        assert_eq!(f.key.pb, 80);
        assert_eq!(f.pkts_ab, 2);
        assert_eq!(f.sizes_ab, vec![3, 4]);
    }

    #[test]
    fn snoop_roundtrip() {
        let a = eth_ipv4_tcp(b"hi");
        let mut f = Vec::new();
        f.extend_from_slice(&0x0737010du32.to_be_bytes());
        f.extend_from_slice(&2u32.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.extend_from_slice(&65535u32.to_be_bytes());
        f.extend_from_slice(&(a.len() as u32).to_be_bytes());
        f.extend_from_slice(&(a.len() as u32).to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.extend_from_slice(&55u32.to_be_bytes());
        f.extend_from_slice(&7u32.to_be_bytes());
        f.extend_from_slice(&a);
        let pad = (4 - a.len() % 4) % 4;
        f.extend_from_slice(&vec![0u8; pad]); // pad to 4
        let pk = open(&f).unwrap();
        assert_eq!(pk.len(), 1);
        assert_eq!(pk[0].ts_micros, 55_000_007);
        assert_eq!(flows(&pk).len(), 1);
    }

    #[test]
    fn malformed_never_panics() {
        for m in [&[0u8; 4][..], &[0xa1, 0xb2, 0xc3, 0xd4][..], &[0x07, 0x37, 0x01, 0x0d][..], b"junk"] {
            let _ = open(m);
        }
        let mut f = pcap_le(&[(1, 0, &[0u8; 4])]);
        f.truncate(f.len() - 3); // cut a record short
        assert!(open(&f).is_err());
        // garbage never panics through L3
        for i in 0..200u8 {
            let junk = vec![i; 60];
            let _ = l3(&junk);
        }
    }
}
