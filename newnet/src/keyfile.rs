// Key files (spec 3.2, 3.4): the X25519 secret and its name on disk, held
// with private permissions, and the public line a person shows and sends.
// The secret file is three newline-terminated lines; the public line carries
// a short checksum so a typo is caught before a key is trusted.

use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngCore;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::crypto::sha256;

pub const SECRET_FILE_TAG: &str = "newnet-secret-v1";
pub const PUB_TAG: &str = "newnet1";
pub const PUB_CHECK_TAG: &[u8] = b"NEWNET-PUB1";
pub const PUB_CHECK_LEN: usize = 4;
pub const NAME_MAX: usize = 64;
pub const FP_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    BadName,
    BadFormat,
    BadChecksum,
    Io(String),
    PermissionsTooOpen,
    Exists,
    DuplicateName,
    DuplicateKey,
    TooManyPeers,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    pub name: String,
    pub secret: [u8; 32],
}

// A name is 1 to 64 bytes of `a-z 0-9 . _ -` (spec 3.1): the same rule the
// wire Hello enforces, so a name that reaches the wire is one the files hold.
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= NAME_MAX
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

pub fn generate(name: &str) -> Result<KeyFile, KeyError> {
    if !valid_name(name) {
        return Err(KeyError::BadName);
    }
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    Ok(KeyFile { name: name.to_string(), secret })
}

pub fn encode_secret_file(k: &KeyFile) -> String {
    let mut s = String::with_capacity(18 + k.name.len() + 65);
    s.push_str(SECRET_FILE_TAG);
    s.push('\n');
    s.push_str(&k.name);
    s.push('\n');
    s.push_str(&hex::encode(k.secret));
    s.push('\n');
    s
}

pub fn decode_secret_file(text: &str) -> Result<KeyFile, KeyError> {
    let mut lines = text.lines();
    if lines.next().unwrap_or("") != SECRET_FILE_TAG {
        return Err(KeyError::BadFormat);
    }
    let name = lines.next().ok_or(KeyError::BadFormat)?;
    if !valid_name(name) {
        return Err(KeyError::BadName);
    }
    let key_hex = lines.next().ok_or(KeyError::BadFormat)?;
    let secret = decode_hex::<32>(key_hex).ok_or(KeyError::BadFormat)?;
    if lines.next().is_some() {
        return Err(KeyError::BadFormat);
    }
    Ok(KeyFile { name: name.to_string(), secret })
}

// Lowercase hex only: what we write is lowercase, and letting two spellings
// of one key look like two keys would break the duplicate check.
pub fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    let raw = hex::decode(s).ok()?;
    Some(raw.as_slice().try_into().ok()?)
}

// The X25519 public key of a secret: the only handshake identity (spec 3.1).
pub fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    XPublic::from(&StaticSecret::from(*secret)).to_bytes()
}

// First four bytes of SHA-256(tag || name || 0x00 || key): catches typos and
// truncation, not an attacker who chooses both halves (spec 3.2).
pub fn check_of(name: &str, key: &[u8; 32]) -> [u8; PUB_CHECK_LEN] {
    let d = sha256(&[PUB_CHECK_TAG, name.as_bytes(), &[0u8], key]);
    d[..PUB_CHECK_LEN].try_into().unwrap()
}

// SHA-256(key), first 16 bytes, hex in 8 groups of 4: read aloud or compared
// on two screens (spec 3.2).
pub fn fingerprint(public: &[u8; 32]) -> String {
    let h = hex::encode(&sha256(&[public])[..FP_BYTES]);
    let mut out = String::with_capacity(FP_BYTES * 3 - 1);
    for i in 0..FP_BYTES / 2 {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&h[i * 4..i * 4 + 4]);
    }
    out
}

fn io_err(e: std::io::Error) -> KeyError {
    KeyError::Io(e.to_string())
}

// The directory holding a key file, created 0700 on unix so the key is not
// reachable by another user before its own mode is applied.
#[cfg(unix)]
fn create_dir_if_absent(dir: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true).mode(0o700);
    b.create(dir).map_err(io_err)
}

#[cfg(not(unix))]
fn create_dir_if_absent(dir: &Path) -> Result<(), KeyError> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).map_err(io_err)
}

// Never overwrite: create_new fails with Exists (spec 3.4). On unix the mode
// is set at creation, so there is no window with wider permissions; on
// Windows the ACL is narrowed immediately after the file appears.
pub fn save_new(path: &Path, k: &KeyFile) -> Result<(), KeyError> {
    create_dir_if_absent(path.parent().unwrap_or(Path::new(".")))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(KeyError::Exists),
        Err(e) => return Err(io_err(e)),
    };
    let written = f.write_all(encode_secret_file(k).as_bytes()).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = written {
        let _ = std::fs::remove_file(path);
        return Err(io_err(e));
    }
    #[cfg(windows)]
    restrict_acl(path)?;
    Ok(())
}

// A2: Command does not expand %USERNAME%, so read the variables here and pass
// "<USERDOMAIN>\<USERNAME>:F" to icacls. A missing variable means the file has
// no owner we can name, so it is deleted and the caller sees Io.
#[cfg(windows)]
fn restrict_acl(path: &Path) -> Result<(), KeyError> {
    let domain = std::env::var("USERDOMAIN");
    let user = std::env::var("USERNAME");
    let (Ok(d), Ok(u)) = (domain, user) else {
        let _ = std::fs::remove_file(path);
        return Err(KeyError::Io("USERDOMAIN or USERNAME is not set".to_string()));
    };
    let grant = format!("{d}\\{u}:F");
    let out = match std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(&grant)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_file(path);
            return Err(io_err(e));
        }
    };
    if !out.status.success() {
        let _ = std::fs::remove_file(path);
        let why = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(KeyError::Io(format!("icacls exit {:?}: {why}", out.status.code())));
    }
    Ok(())
}

// The OpenSSH rule as a mask: any group or other bit is a refusal. Split out
// from the unix-only load so the mask itself is testable on every OS.
#[cfg(any(unix, test))]
fn mode_too_open(mode: u32) -> bool {
    mode & 0o077 != 0
}

pub fn load(path: &Path) -> Result<KeyFile, KeyError> {
    // Windows does not re-check the ACL on load (stated limit: the file
    // lives in the profile).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path).map_err(io_err)?;
        if mode_too_open(md.permissions().mode()) {
            return Err(KeyError::PermissionsTooOpen);
        }
    }
    let text = std::fs::read_to_string(path).map_err(io_err)?;
    decode_secret_file(&text)
}

// Linux: $XDG_CONFIG_HOME/newnet/identity.key, else ~/.config/newnet/.
// Windows: %APPDATA%\newnet\identity.key.
pub fn default_key_path() -> PathBuf {
    #[cfg(windows)]
    let dir_var = "APPDATA";
    #[cfg(not(windows))]
    let dir_var = "XDG_CONFIG_HOME";
    if let Ok(v) = std::env::var(dir_var) {
        if !v.is_empty() {
            return Path::new(&v).join("newnet").join("identity.key");
        }
    }
    #[cfg(not(windows))]
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Path::new(&home).join(".config").join("newnet").join("identity.key");
        }
    }
    PathBuf::from("newnet-identity.key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peerbook::{format_pub_line, parse_pub_line, PeerLine};

    const VEC_NAME: &str = "alice";
    const VEC_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const VEC_CHECK: &str = "26098c0f";
    const VEC_FP: &str = "ae21 6c2e f524 7a37 82c1 35ef a279 a3e4";

    // The published vector bytes 0x01..0x20. The secret-file example and the
    // public-line example both use them; they are two vectors, not a pair.
    fn vector() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        s
    }

    fn vec_line() -> String {
        format!("{SECRET_FILE_TAG}\n{VEC_NAME}\n{VEC_HEX}\n")
    }

    // One directory per test under target/scratch, unique in this binary.
    fn scratch(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("scratch")
            .join(format!("keyfile_{tag}_{n}"));
        // The directory survives a run, and the counter restarts each run:
        // start empty so a fresh save_new really is new.
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn key_file(name: &str) -> KeyFile {
        KeyFile { name: name.to_string(), secret: vector() }
    }

    #[test]
    fn secret_file_round_trip_and_vector() {
        let k = decode_secret_file(&vec_line()).unwrap();
        assert_eq!(k.name, VEC_NAME);
        assert_eq!(k.secret, vector());
        assert_eq!(encode_secret_file(&k), vec_line());
        assert_eq!(decode_secret_file(&encode_secret_file(&k)).unwrap(), k);
        let upper = vec_line().replace(VEC_HEX, "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");
        let cases = [
            (format!("newnet-secret-v2\n{VEC_NAME}\n{VEC_HEX}\n"), KeyError::BadFormat),
            (format!("{SECRET_FILE_TAG}\n{VEC_NAME}\n0102\n"), KeyError::BadFormat),
            (format!("{SECRET_FILE_TAG}\n{VEC_NAME}\n{VEC_HEX}0\n"), KeyError::BadFormat),
            (format!("{SECRET_FILE_TAG}\n{VEC_NAME}\n{}\n", &VEC_HEX[..62]), KeyError::BadFormat),
            (format!("{SECRET_FILE_TAG}\n{VEC_NAME}\nzz030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"), KeyError::BadFormat),
            (upper, KeyError::BadFormat),
            (format!("{SECRET_FILE_TAG}\n{VEC_NAME}\n{VEC_HEX}\nextra\n"), KeyError::BadFormat),
            (format!("{SECRET_FILE_TAG}\n{VEC_NAME}\n"), KeyError::BadFormat),
            (format!("{SECRET_FILE_TAG}\n"), KeyError::BadFormat),
        ];
        for (text, want) in cases {
            assert_eq!(decode_secret_file(&text), Err(want), "refusing {text:?}");
        }
    }

    #[test]
    fn bad_names_refused() {
        for n in ["a", "abc", "a.b_c-1", "x9", &"z".repeat(64)] {
            assert!(valid_name(n), "{n} is a valid name");
        }
        for n in ["", &"z".repeat(65), "A", "a b", "a/b", "../x", "alic\u{e9}", "a\tb", "a\nb"] {
            assert!(!valid_name(n), "{n} is not a valid name");
            assert_eq!(generate(n), Err(KeyError::BadName), "generate {n:?}");
            let text = format!("{SECRET_FILE_TAG}\n{n}\n{VEC_HEX}\n");
            // A name with a newline cannot be put on one line at all: the
            // file no longer has three lines, which is a format fault first.
            let want = if n.contains('\n') { KeyError::BadFormat } else { KeyError::BadName };
            assert_eq!(decode_secret_file(&text), Err(want), "decode {n:?}");
        }
        assert_eq!(generate("alice").map(|k| k.name), Ok("alice".to_string()));
    }

    #[test]
    fn public_line_matches_vector() {
        let l = PeerLine { name: VEC_NAME.to_string(), key: vector(), expires: None };
        assert_eq!(
            format_pub_line(&l),
            format!("{PUB_TAG} {VEC_NAME} {VEC_HEX} {VEC_CHECK}"),
            "the published alice line"
        );
        assert_eq!(check_of(VEC_NAME, &vector()), [0x26, 0x09, 0x8c, 0x0f]);
        assert_eq!(parse_pub_line(&format_pub_line(&l)).unwrap(), l);
        let dated = PeerLine { name: VEC_NAME.to_string(), key: vector(), expires: Some(1_800_000_000) };
        assert_eq!(
            format_pub_line(&dated),
            format!("{PUB_TAG} {VEC_NAME} {VEC_HEX} {VEC_CHECK} expires=1800000000")
        );
        assert_eq!(parse_pub_line(&format_pub_line(&dated)).unwrap(), dated);
    }

    #[test]
    fn fingerprint_matches_vector() {
        assert_eq!(fingerprint(&vector()), VEC_FP);
        assert_eq!(fingerprint(&vector()).chars().count(), 8 * 4 + 7);
    }

    #[test]
    fn any_changed_hex_digit_breaks_the_checksum() {
        let line = format_pub_line(&PeerLine { name: VEC_NAME.to_string(), key: vector(), expires: None });
        let key_at = line.find(VEC_HEX).expect("the key hex is in the line");
        let check_at = line.find(VEC_CHECK).expect("the check hex is in the line");
        let base: Vec<char> = line.chars().collect();
        let hexd: Vec<char> = "0123456789abcdef".chars().collect();
        let flips: Vec<usize> = (0..64).map(|i| key_at + i).chain((0..8).map(|i| check_at + i)).collect();
        for at in flips {
            let old = base[at];
            let fresh = hexd.iter().copied().find(|c| *c != old).unwrap();
            let mut m = base.clone();
            m[at] = fresh;
            let mutated: String = m.into_iter().collect();
            assert_eq!(
                parse_pub_line(&mutated),
                Err(KeyError::BadChecksum),
                "digit {old} -> {fresh} at byte {} of the line: {mutated}",
                if at < check_at { 0 } else { 1 }
            );
        }
        assert!(parse_pub_line(&line).is_ok(), "the unmutated line parses");
    }

    #[test]
    fn save_new_never_overwrites() {
        let p = scratch("overwrite").join("identity.key");
        let k = key_file(VEC_NAME);
        save_new(&p, &k).expect("first save_new");
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(bytes, encode_secret_file(&k).as_bytes(), "the file is the encoded key");
        let other = KeyFile { name: "bob".to_string(), secret: [9u8; 32] };
        assert_eq!(save_new(&p, &other), Err(KeyError::Exists), "a second save refuses");
        assert_eq!(std::fs::read(&p).unwrap(), bytes, "the refused save left the bytes alone");
        assert_eq!(load(&p).unwrap(), k, "the first key is still the one on disk");
    }

    #[cfg(unix)]
    #[test]
    fn save_new_creates_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let p = scratch("mode").join("identity.key");
        let k = key_file(VEC_NAME);
        save_new(&p, &k).expect("save_new");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the secret file is created mode 600");
        assert_eq!(load(&p).unwrap(), k, "a mode 600 file loads");
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let p = scratch("group").join("identity.key");
        save_new(&p, &key_file(VEC_NAME)).expect("save_new");
        for mode in [0o640u32, 0o604, 0o601, 0o670, 0o664] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                load(&p),
                Err(KeyError::PermissionsTooOpen),
                "mode {mode:o} must be refused"
            );
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&p).is_ok(), "mode 600 is the one that loads");
    }

    // The same mask that load applies on unix, checked without a filesystem:
    // a Windows host cannot chmod, but it can still fail a widened mask.
    #[test]
    fn the_permission_mask_refuses_every_group_or_other_bit() {
        assert!(!mode_too_open(0o600), "600 is the mode save_new creates");
        assert!(!mode_too_open(0o400), "owner-only read is private too");
        for mode in [0o640u32, 0o604, 0o601, 0o670, 0o644, 0o666] {
            assert!(mode_too_open(mode), "mode {mode:o} must be refused");
        }
    }

    #[cfg(windows)]
    #[test]
    fn save_new_restricts_acl() {
        let p = scratch("acl").join("identity.key");
        let k = key_file(VEC_NAME);
        save_new(&p, &k).expect("save_new applies the ACL");
        assert_eq!(load(&p).unwrap(), k);
        let out = std::process::Command::new("icacls").arg(&p).output().expect("icacls runs");
        assert!(out.status.success(), "icacls could not read the ACL: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let path_s = p.to_string_lossy().to_string();
        // The path is echoed first and may itself contain "Users": judge only
        // what follows it, which is where the access-allowed entries are.
        let at = text.find(&path_s).expect("icacls names the file") + path_s.len();
        let aces = text[at..].to_ascii_lowercase();
        let user = format!(
            "{}\\{}",
            std::env::var("USERDOMAIN").expect("USERDOMAIN is set on Windows"),
            std::env::var("USERNAME").expect("USERNAME is set on Windows")
        );
        assert!(aces.contains(&user.to_ascii_lowercase()), "the current user must hold the file: {aces}");
        for banned in ["everyone", "users", "authenticated users"] {
            assert!(!aces.contains(banned), "{banned} still has a right on the key: {aces}");
        }
    }
}
