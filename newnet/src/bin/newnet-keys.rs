// newnet-keys: the key tool of spec 3.3. Gen creates a secret file and
// prints the public line and fingerprint a person carries to a peer by hand;
// show prints them again without touching the secret; add-peer inserts or
// replaces one public line in a peers file; list shows what a peers file
// holds. The secret is never printed, never logged, never put on a command
// line.

use std::path::PathBuf;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use newnet::keyfile::{self, KeyError};
use newnet::peerbook::{self, PeerLine};

fn usage() -> ! {
    eprintln!("usage: newnet-keys gen --name <name> [--file <path>]");
    eprintln!("   or: newnet-keys show [--file <path>]");
    eprintln!("   or: newnet-keys add-peer --peers <path> --line \"<public line>\" [--replace]");
    eprintln!("   or: newnet-keys list --peers <path>");
    exit(2);
}

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("{}", msg.as_ref());
    exit(1);
}

fn describe(e: &KeyError) -> String {
    match e {
        KeyError::BadName => "bad name: 1 to 64 characters of a-z 0-9 . _ -".to_string(),
        KeyError::BadFormat => "bad format: expected `newnet1 <name> <key-hex-64> <check-hex-8> [expires=<unix-seconds>]`".to_string(),
        KeyError::BadChecksum => "bad checksum: the public line's check digits do not match (typo or truncation)".to_string(),
        KeyError::Io(s) => format!("io error: {s}"),
        KeyError::PermissionsTooOpen => "refusing: the key file is readable by group or other".to_string(),
        KeyError::Exists => "refusing: the key file already exists (never overwrite)".to_string(),
        KeyError::DuplicateName => "refusing: that name is already in the peers file with a different key (use --replace)".to_string(),
        KeyError::DuplicateKey => "refusing: that key is already in the peers file under another name".to_string(),
        KeyError::TooManyPeers => "refusing: the peers file is at its limit of 1024 lines".to_string(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// The public line and fingerprint of a loaded secret file, as two stdout
// lines (spec 3.3).
fn print_public(kf: &keyfile::KeyFile) {
    let key = keyfile::public_of(&kf.secret);
    let l = PeerLine { name: kf.name.clone(), key, expires: None };
    println!("{}", peerbook::format_pub_line(&l));
    println!("{}", keyfile::fingerprint(&key));
}

fn main() {
    let args: Vec<String> = match std::env::args_os().skip(1).map(|a| a.into_string()).collect() {
        Ok(v) => v,
        Err(_) => usage(),
    };
    let mut it = args.into_iter();
    let cmd = match it.next() {
        Some(c) => c,
        None => usage(),
    };
    let mut name: Option<String> = None;
    let mut file: Option<PathBuf> = None;
    let mut peers: Option<PathBuf> = None;
    let mut line: Option<String> = None;
    let mut replace = false;
    while let Some(a) = it.next() {
        let mut val = || match it.next() {
            Some(v) => v,
            None => usage(),
        };
        match a.as_str() {
            "--name" => name = Some(val()),
            "--file" => file = Some(PathBuf::from(val())),
            "--peers" => peers = Some(PathBuf::from(val())),
            "--line" => line = Some(val()),
            "--replace" => replace = true,
            _ => usage(),
        }
    }
    match cmd.as_str() {
        "gen" => {
            if peers.is_some() || line.is_some() || replace || name.is_none() {
                usage();
            }
            let path = file.unwrap_or_else(keyfile::default_key_path);
            let n = name.unwrap();
            let kf = match keyfile::generate(&n) {
                Ok(k) => k,
                Err(e) => fail(describe(&e)),
            };
            if let Err(e) = keyfile::save_new(&path, &kf) {
                fail(format!("{}: {}", path.display(), describe(&e)));
            }
            print_public(&kf);
            exit(0);
        }
        "show" => {
            if name.is_some() || peers.is_some() || line.is_some() || replace {
                usage();
            }
            let path = file.unwrap_or_else(keyfile::default_key_path);
            let kf = match keyfile::load(&path) {
                Ok(k) => k,
                Err(e) => fail(format!("{}: {}", path.display(), describe(&e))),
            };
            print_public(&kf);
            exit(0);
        }
        "add-peer" => {
            if name.is_some() || file.is_some() || line.is_none() || peers.is_none() {
                usage();
            }
            let path = peers.unwrap();
            let l = match peerbook::parse_pub_line(&line.unwrap()) {
                Ok(l) => l,
                Err(e) => fail(describe(&e)),
            };
            if let Err(e) = peerbook::add_peer(&path, &l, replace) {
                fail(format!("{}: {}", path.display(), describe(&e)));
            }
            println!("added {} to {}", l.name, path.display());
            exit(0);
        }
        "list" => {
            if name.is_some() || file.is_some() || line.is_some() || replace || peers.is_none() {
                usage();
            }
            let path = peers.unwrap();
            let (active, expired) = match peerbook::load_peers(&path, unix_now()) {
                Ok(v) => v,
                Err(e) => fail(format!("{}: {}", path.display(), describe(&e))),
            };
            for l in active.iter().chain(expired.iter()) {
                let expiry = match l.expires {
                    Some(e) => format!("expires={e}"),
                    None => "expires=none".to_string(),
                };
                println!("{} {} {}", l.name, keyfile::fingerprint(&l.key), expiry);
            }
            exit(0);
        }
        _ => usage(),
    }
}
