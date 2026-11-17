// Return-routability cookie (spec 4.2, 4.3): a stateless HMAC the responder
// demands on every HANDSHAKE1. Pure module: no I/O, no node state.
// Verification uses Mac::verify_truncated_left (constant time), never ==.

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

pub const COOKIE_LEN: usize = 16;
pub const SRC_KEY_LEN: usize = 19;
pub const COOKIE_ROTATE_TICKS: u64 = 60_000;

pub type SrcKey = [u8; SRC_KEY_LEN];

const COOKIE_MAC_LABEL: &[u8] = b"NEWNET2-COOKIE";

// Claimed source address of a datagram: byte 0 = family (4 or 6),
// bytes 1..17 = IP address (IPv4 as 4 bytes then 12 zero bytes),
// bytes 17..19 = port, big-endian.
pub fn src_key_from_socket(sa: &std::net::SocketAddr) -> SrcKey {
    let mut k = [0u8; SRC_KEY_LEN];
    match sa {
        std::net::SocketAddr::V4(v4) => {
            k[0] = 4;
            k[1..5].copy_from_slice(&v4.ip().octets());
        }
        std::net::SocketAddr::V6(v6) => {
            k[0] = 6;
            k[1..17].copy_from_slice(&v6.ip().octets());
        }
    }
    k[17..19].copy_from_slice(&sa.port().to_be_bytes());
    k
}

// Lab hub address: byte 0 = 0, bytes 1..5 = addr big-endian, rest zero.
pub fn src_key_lab(addr: u32) -> SrcKey {
    let mut k = [0u8; SRC_KEY_LEN];
    k[0] = 0;
    k[1..5].copy_from_slice(&addr.to_be_bytes());
    k
}

pub struct CookieKeys {
    cur: [u8; 32],
    prev: Option<[u8; 32]>,
    born: u64,
}

fn random_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

impl CookieKeys {
    pub fn new(now: u64) -> CookieKeys {
        CookieKeys { cur: random_secret(), prev: Some(random_secret()), born: now }
    }

    pub fn from_secret_for_test(secret: [u8; 32], now: u64) -> CookieKeys {
        CookieKeys { cur: secret, prev: None, born: now }
    }

    // Checked at the top of every HANDSHAKE1; no timer thread. On rotation
    // the old cur becomes prev and is dropped by the next rotation, so a
    // cookie lives 60 to 120 seconds.
    pub fn rotate_if_due(&mut self, now: u64) {
        if now >= self.born + COOKIE_ROTATE_TICKS {
            self.prev = Some(self.cur);
            self.cur = random_secret();
            self.born = now;
        }
    }

    fn mac(secret: &[u8; 32], src: &SrcKey, conn_id: u64) -> Hmac<Sha256> {
        let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
        m.update(COOKIE_MAC_LABEL);
        m.update(src);
        m.update(&conn_id.to_le_bytes());
        m
    }

    pub fn make(&self, src: &SrcKey, conn_id: u64) -> [u8; COOKIE_LEN] {
        let tag = Self::mac(&self.cur, src, conn_id).finalize().into_bytes();
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&tag[..COOKIE_LEN]);
        cookie
    }

    pub fn check(&self, src: &SrcKey, conn_id: u64, cookie: &[u8; COOKIE_LEN]) -> bool {
        let cur_ok = Self::mac(&self.cur, src, conn_id)
            .verify_truncated_left(cookie)
            .is_ok();
        if cur_ok {
            return true;
        }
        match self.prev {
            Some(prev) => Self::mac(&prev, src, conn_id)
                .verify_truncated_left(cookie)
                .is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(ip: [u8; 4], port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port)
    }

    #[test]
    fn cookie_matches_published_vector() {
        // Spec 4.2: secret 32 zero bytes, src 10.0.0.1:4002,
        // conn_id 0x0102030405060708 -> 4066a83b52d0598b20ebf777341ab3e7.
        let keys = CookieKeys::from_secret_for_test([0u8; 32], 0);
        let src = src_key_from_socket(&v4([10, 0, 0, 1], 4002));
        let cookie = keys.make(&src, 0x0102_0304_0506_0708);
        assert_eq!(hex::encode(cookie), "4066a83b52d0598b20ebf777341ab3e7");
        assert!(keys.check(&src, 0x0102_0304_0506_0708, &cookie));
    }

    #[test]
    fn src_key_layout() {
        let k = src_key_from_socket(&v4([10, 0, 0, 1], 4002));
        let mut want = [0u8; SRC_KEY_LEN];
        want[0] = 4;
        want[1..5].copy_from_slice(&[0x0A, 0x00, 0x00, 0x01]);
        want[17..19].copy_from_slice(&[0x0F, 0xA2]);
        assert_eq!(k, want);
        assert_eq!(k[0], 4);
        assert_eq!(&k[1..5], &[0x0A, 0x00, 0x00, 0x01]);
        assert_eq!(&k[5..17], &[0u8; 12]);
        assert_eq!(&k[17..19], &[0x0F, 0xA2]);

        let v6 = std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let k6 = src_key_from_socket(&v6);
        assert_eq!(k6[0], 6);
        assert_eq!(&k6[1..3], &[0x20, 0x01]);
        assert_eq!(&k6[15..17], &[0x00, 0x01]);
        assert_eq!(&k6[17..19], &[0x01, 0xBB]);

        let lab = src_key_lab(0x0A00_0001);
        assert_eq!(lab[0], 0);
        assert_eq!(&lab[1..5], &[0x0A, 0x00, 0x00, 0x01]);
        assert_eq!(&lab[5..], &[0u8; 14]);
    }

    #[test]
    fn cookie_differs_by_source_conn_and_secret() {
        let keys = CookieKeys::from_secret_for_test([0u8; 32], 0);
        let src1 = src_key_from_socket(&v4([10, 0, 0, 1], 4002));
        let src2 = src_key_from_socket(&v4([10, 0, 0, 2], 4002));
        let src2p = src_key_from_socket(&v4([10, 0, 0, 1], 4003));
        let conn = 0x0102_0304_0506_0708u64;
        let base = keys.make(&src1, conn);
        assert_ne!(base, keys.make(&src2, conn), "source changes the cookie");
        assert_ne!(base, keys.make(&src2p, conn), "port changes the cookie");
        assert_ne!(base, keys.make(&src1, conn + 1), "conn_id changes the cookie");
        let other = CookieKeys::from_secret_for_test([1u8; 32], 0);
        assert_ne!(base, other.make(&src1, conn), "secret changes the cookie");
        // The lab src_key space is distinct from the v4 space.
        assert_ne!(base, keys.make(&src_key_lab(0x0A00_0001), conn));
    }

    #[test]
    fn every_byte_of_the_cookie_matters() {
        let keys = CookieKeys::from_secret_for_test([7u8; 32], 0);
        let src = src_key_from_socket(&v4([192, 168, 1, 5], 1234));
        let cookie = keys.make(&src, 99);
        assert!(keys.check(&src, 99, &cookie));
        for i in 0..COOKIE_LEN {
            for bit in 0..8u32 {
                let mut bad = cookie;
                bad[i] ^= 1 << bit;
                assert!(!keys.check(&src, 99, &bad), "byte {i} bit {bit} must be checked");
            }
        }
        // All-zero cookie (the first-try placeholder) is not a valid cookie.
        assert!(!keys.check(&src, 99, &[0u8; COOKIE_LEN]));
    }

    #[test]
    fn previous_secret_still_accepted_once() {
        let mut keys = CookieKeys::from_secret_for_test([3u8; 32], 0);
        let src = src_key_from_socket(&v4([10, 0, 0, 1], 4002));
        let old = keys.make(&src, 5);
        assert!(keys.check(&src, 5, &old));
        keys.rotate_if_due(COOKIE_ROTATE_TICKS); // prev = old secret, cur = fresh
        assert!(keys.check(&src, 5, &old), "previous secret still accepted once");
        let fresh = keys.make(&src, 5);
        keys.rotate_if_due(2 * COOKIE_ROTATE_TICKS); // prev dropped, cur = fresh2
        assert!(!keys.check(&src, 5, &old), "two rotations: old cookie rejected");
        assert!(keys.check(&src, 5, &fresh), "a cookie made after rotation 1 is prev after rotation 2");
    }

    #[test]
    fn no_rotation_before_sixty_seconds() {
        let mut keys = CookieKeys::from_secret_for_test([4u8; 32], 0);
        let src = src_key_from_socket(&v4([10, 0, 0, 1], 4002));
        let before = keys.make(&src, 1);
        keys.rotate_if_due(COOKIE_ROTATE_TICKS - 1); // born + 59 999: no rotation
        assert_eq!(keys.make(&src, 1), before, "59 999 ticks must not rotate");
        keys.rotate_if_due(COOKIE_ROTATE_TICKS); // born + 60 000: rotates
        assert_ne!(keys.make(&src, 1), before, "60 000 ticks must rotate");
        assert!(keys.check(&src, 1, &before), "old cookie still valid after one rotation");
    }
}
