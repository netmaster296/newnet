// The peers file (spec 3.2, 3.5): the public lines a person carried over by
// hand, one per peer. Blank lines and `#` comments are ignored, at most 1024
// lines, a duplicate name or key is a load error, and a line whose expiry is
// already past is skipped and reported. This file is the pin: the node trusts
// exactly the keys it holds.

use std::path::Path;

use crate::keyfile::{check_of, decode_hex, valid_name, KeyError, PUB_CHECK_LEN, PUB_TAG};

pub const PEERS_MAX_LINES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerLine {
    pub name: String,
    pub key: [u8; 32],
    pub expires: Option<u64>,
}

pub fn format_pub_line(l: &PeerLine) -> String {
    let mut s = format!("{PUB_TAG} {} {} {}", l.name, hex::encode(l.key), hex::encode(check_of(&l.name, &l.key)));
    if let Some(e) = l.expires {
        s.push_str(&format!(" expires={e}"));
    }
    s
}

pub fn parse_pub_line(s: &str) -> Result<PeerLine, KeyError> {
    let mut it = s.split_whitespace();
    if it.next() != Some(PUB_TAG) {
        return Err(KeyError::BadFormat);
    }
    let name = it.next().ok_or(KeyError::BadFormat)?;
    if !valid_name(name) {
        return Err(KeyError::BadName);
    }
    let key = decode_hex::<32>(it.next().ok_or(KeyError::BadFormat)?).ok_or(KeyError::BadFormat)?;
    let check =
        decode_hex::<PUB_CHECK_LEN>(it.next().ok_or(KeyError::BadFormat)?).ok_or(KeyError::BadFormat)?;
    if check != check_of(name, &key) {
        return Err(KeyError::BadChecksum);
    }
    let mut expires = None;
    if let Some(rest) = it.next() {
        let digits = rest.strip_prefix("expires=").ok_or(KeyError::BadFormat)?;
        expires = Some(digits.parse::<u64>().map_err(|_| KeyError::BadFormat)?);
    }
    if it.next().is_some() {
        return Err(KeyError::BadFormat);
    }
    Ok(PeerLine { name: name.to_string(), key, expires })
}

fn is_skippable(raw: &str) -> bool {
    let t = raw.trim_start();
    t.is_empty() || t.starts_with('#')
}

// (active, expired). Expired lines are reported on stderr and kept out of the
// node; expiry is checked only here, at load (spec 3.5).
pub fn load_peers(path: &Path, unix_now: u64) -> Result<(Vec<PeerLine>, Vec<PeerLine>), KeyError> {
    let text = std::fs::read_to_string(path).map_err(|e| KeyError::Io(e.to_string()))?;
    let mut active: Vec<PeerLine> = Vec::new();
    let mut expired: Vec<PeerLine> = Vec::new();
    let mut lines = 0usize;
    for raw in text.lines() {
        if is_skippable(raw) {
            continue;
        }
        lines += 1;
        if lines > PEERS_MAX_LINES {
            return Err(KeyError::TooManyPeers);
        }
        let l = parse_pub_line(raw.trim())?;
        if active.iter().chain(expired.iter()).any(|p| p.name == l.name) {
            return Err(KeyError::DuplicateName);
        }
        if active.iter().chain(expired.iter()).any(|p| p.key == l.key) {
            return Err(KeyError::DuplicateKey);
        }
        match l.expires {
            Some(e) if e < unix_now => {
                eprintln!("peers: {} expired at {e} (now {unix_now}), skipped", l.name);
                expired.push(l);
            }
            _ => active.push(l),
        }
    }
    Ok((active, expired))
}

// Insert or replace one line, keeping comments and the order of the rest.
// A name already present with a different key is refused unless `replace`;
// the same key under another name is always a refusal (spec 3.3).
pub fn add_peer(path: &Path, l: &PeerLine, replace: bool) -> Result<(), KeyError> {
    if !valid_name(&l.name) {
        return Err(KeyError::BadName);
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(KeyError::Io(e.to_string())),
    };
    let mut out_lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let mut target: Option<usize> = None;
    let mut peers = 0usize;
    for (i, raw) in text.lines().enumerate() {
        if is_skippable(raw) {
            continue;
        }
        peers += 1;
        let existing = parse_pub_line(raw.trim())?;
        if existing.name == l.name {
            if existing.key != l.key && !replace {
                return Err(KeyError::DuplicateName);
            }
            target = Some(i);
        } else if existing.key == l.key {
            return Err(KeyError::DuplicateKey);
        }
    }
    match target {
        Some(i) => out_lines[i] = format_pub_line(l),
        None => {
            if peers >= PEERS_MAX_LINES {
                return Err(KeyError::TooManyPeers);
            }
            out_lines.push(format_pub_line(l));
        }
    }
    let mut body = out_lines.join("\n");
    body.push('\n');
    std::fs::write(path, body).map_err(|e| KeyError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn scratch(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("scratch")
            .join(format!("peerbook_{tag}_{n}"));
        // Scratch directories outlive a run and the counter restarts: start
        // empty so an add_peer into a missing file really sees no file.
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn key_num(i: usize) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = (i & 0xff) as u8;
        k[1] = ((i >> 8) & 0xff) as u8;
        k
    }

    fn line(name: &str, b: u8, expires: Option<u64>) -> PeerLine {
        PeerLine { name: name.to_string(), key: [b; 32], expires }
    }

    fn file_text(lines: &[&PeerLine]) -> String {
        let mut t = String::new();
        for l in lines {
            t.push_str(&format_pub_line(l));
            t.push('\n');
        }
        t
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let dir = scratch("comments");
        let p = dir.join("peers");
        let a = line("alice", 1, None);
        let b = line("bob.example-1", 2, Some(u64::MAX));
        std::fs::write(
            &p,
            format!("# newnet peers\n\n  \n{}\n\n\t\n{}\n# end of file\n", format_pub_line(&a), format_pub_line(&b)),
        )
        .unwrap();
        let (active, expired) = load_peers(&p, 1_000).unwrap();
        assert_eq!(active, vec![a.clone(), b.clone()], "the two peers are the only lines");
        assert!(expired.is_empty());
        std::fs::write(&p, "# nothing here\n\n   \n").unwrap();
        assert_eq!(load_peers(&p, 1_000).unwrap(), (vec![], vec![]), "comments alone load empty");
        std::fs::write(&p, format!("{}\nnewnet1 carol 00 00\n", format_pub_line(&a))).unwrap();
        assert_eq!(load_peers(&p, 1_000).unwrap_err(), KeyError::BadFormat, "a short key is refused");
        std::fs::write(&p, format!("{}\nnewnet2 alice {}\n", format_pub_line(&a), hex::encode(a.key))).unwrap();
        assert_eq!(load_peers(&p, 1_000).unwrap_err(), KeyError::BadFormat, "a wrong tag is refused");
    }

    #[test]
    fn duplicate_name_and_duplicate_key_refused() {
        let p = scratch("dup").join("peers");
        std::fs::write(&p, file_text(&[&line("alice", 1, None), &line("alice", 2, None)])).unwrap();
        assert_eq!(load_peers(&p, 0).unwrap_err(), KeyError::DuplicateName);
        std::fs::write(&p, file_text(&[&line("alice", 1, None), &line("bob", 1, None)])).unwrap();
        assert_eq!(load_peers(&p, 0).unwrap_err(), KeyError::DuplicateKey);
        // An already-expired pair is still a duplicate: one name, one key.
        std::fs::write(&p, file_text(&[&line("alice", 1, Some(5)), &line("alice", 1, Some(9))])).unwrap();
        assert_eq!(load_peers(&p, 100).unwrap_err(), KeyError::DuplicateName);
    }

    #[test]
    fn expired_line_is_returned_separately() {
        let p = scratch("expired").join("peers");
        let now = 1_000_000u64;
        let old = line("old", 3, Some(now - 1));
        let edge = line("edge", 4, Some(now));
        let fresh = line("fresh", 5, Some(now + 1));
        let plain = line("plain", 6, None);
        std::fs::write(&p, file_text(&[&old, &edge, &fresh, &plain])).unwrap();
        let (active, expired) = load_peers(&p, now).unwrap();
        assert_eq!(active, vec![edge, fresh, plain], "an expiry exactly at now is not past");
        assert_eq!(expired, vec![old], "the past line comes back separately");
    }

    #[test]
    fn add_peer_refuses_changed_key_without_replace() {
        let p = scratch("addrefuse").join("peers");
        assert_eq!(add_peer(&p, &line("alice", 1, None), false), Ok(()), "a missing file is created");
        assert_eq!(add_peer(&p, &line("alice", 1, None), false), Ok(()), "the same line twice is not an error");
        assert_eq!(load_peers(&p, 0).unwrap().0.len(), 1, "and it is not stored twice");
        assert_eq!(add_peer(&p, &line("alice", 2, None), false), Err(KeyError::DuplicateName));
        assert_eq!(load_peers(&p, 0).unwrap().0, vec![line("alice", 1, None)], "the refusal changed nothing");
        assert_eq!(add_peer(&p, &line("bob", 1, None), false), Err(KeyError::DuplicateKey), "one key, one name");
        assert_eq!(load_peers(&p, 0).unwrap().0.len(), 1);
    }

    #[test]
    fn add_peer_replace_swaps_it() {
        let dir = scratch("replace");
        let p = dir.join("peers");
        std::fs::write(&p, "# my peers\n").unwrap();
        add_peer(&p, &line("alice", 1, None), false).unwrap();
        add_peer(&p, &line("bob", 2, Some(500)), false).unwrap();
        add_peer(&p, &line("alice", 9, Some(700)), true).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("# my peers\n"), "comments survive an add");
        let (active, _) = load_peers(&p, 0).unwrap();
        assert_eq!(active, vec![line("alice", 9, Some(700)), line("bob", 2, Some(500))], "the replaced line keeps its place");
        assert_eq!(add_peer(&p, &line("alice", 9, Some(700)), false), Ok(()), "the same key needs no --replace");
        assert_eq!(add_peer(&p, &line("Alice", 9, None), false), Err(KeyError::BadName), "an uppercase name is refused");
    }

    #[test]
    fn more_than_1024_lines_refused() {
        let dir = scratch("cap");
        let p = dir.join("peers");
        let text: String = (0..PEERS_MAX_LINES)
            .map(|i| format!("{}\n", format_pub_line(&PeerLine { name: format!("peer{i}"), key: key_num(i), expires: None })))
            .collect();
        std::fs::write(&p, &text).unwrap();
        assert_eq!(load_peers(&p, 0).unwrap().0.len(), PEERS_MAX_LINES, "1024 lines load");
        std::fs::write(&p, format!("{text}{}\n", format_pub_line(&PeerLine { name: "one-too-many".into(), key: key_num(PEERS_MAX_LINES), expires: None }))).unwrap();
        assert_eq!(load_peers(&p, 0).unwrap_err(), KeyError::TooManyPeers, "1025 lines are refused");
        // Back to a full file: an add cannot push it over the bound either.
        std::fs::write(&p, &text).unwrap();
        assert_eq!(
            add_peer(&p, &PeerLine { name: "newcomer".into(), key: key_num(4096), expires: None }, false),
            Err(KeyError::TooManyPeers)
        );
        assert_eq!(load_peers(&p, 0).unwrap().0.len(), PEERS_MAX_LINES, "the refused add left the file loadable");
    }
}
