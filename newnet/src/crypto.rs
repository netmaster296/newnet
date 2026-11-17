// One suite: X25519 + Ed25519 + ChaCha20-Poly1305 + SHA-256/HKDF.
// Traffic keys rotate every 1000 packets; nonce = seq. The handshake
// machine lives in noise_ik.rs.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as XPublic;

pub const KEY_ROTATION_INTERVAL: u64 = 1000;
pub const TAG_LEN: usize = 16;
pub const HANDSHAKE_DH_BUDGET_PER_TICK: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseError {
    AuthFailed,
    BadPayload,
    UnknownName,
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn hkdf1(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).unwrap();
    okm
}

pub fn nonce96(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&seq.to_le_bytes());
    n
}

pub fn seal(key: &[u8; 32], seq: u64, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, ()> {
    let c = ChaCha20Poly1305::new(key.into());
    let nb = nonce96(seq);
    let n = Nonce::from_slice(&nb);
    c.encrypt(n, chacha20poly1305::aead::Payload { msg: pt, aad }).map_err(|_| ())
}

pub fn open(key: &[u8; 32], seq: u64, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, ()> {
    let c = ChaCha20Poly1305::new(key.into());
    let nb = nonce96(seq);
    let n = Nonce::from_slice(&nb);
    c.decrypt(n, chacha20poly1305::aead::Payload { msg: ct, aad }).map_err(|_| ())
}

pub struct SplitKeys {
    pub a_to_b_gen0: [u8; 32],
    pub b_to_a_gen0: [u8; 32],
    pub transcript_hash: [u8; 32],
}

// Traffic key chain, one direction. gen = seq / 1000. Old generations are
// erased: the chain holds only generations >= base, so reading process
// memory later does not hand over the generation-0 seed.
pub struct KeyChain {
    base: u64,
    gens: std::collections::VecDeque<[u8; 32]>,
}

impl KeyChain {
    pub fn new(gen0: [u8; 32]) -> Self {
        KeyChain { base: 0, gens: std::collections::VecDeque::from([gen0]) }
    }
    // Key for a generation, deriving forward as needed. None when the
    // generation has been erased (gen < base). The key for generation g
    // sits at index g - base.
    pub fn key_for(&mut self, gen: u64) -> Option<[u8; 32]> {
        if gen < self.base {
            return None;
        }
        while self.base + self.gens.len() as u64 <= gen {
            let prev = *self.gens.back().unwrap();
            self.gens.push_back(hkdf1(&prev, b"NEWNET-GEN"));
        }
        Some(self.gens[(gen - self.base) as usize])
    }
    // Erase every generation below `gen`, zeroing each key before dropping
    // it. The newest key is never removed.
    pub fn forget_before(&mut self, gen: u64) {
        while self.base < gen && self.gens.len() > 1 {
            if let Some(front) = self.gens.front_mut() {
                front.fill(0);
            }
            self.gens.pop_front();
            self.base += 1;
        }
    }
    // How many keys are held now.
    pub fn generations(&self) -> usize {
        self.gens.len()
    }
}

pub struct PeerRecord {
    pub name: String,
    // The Ed25519 half is present for registry/TOFU records and absent for a
    // peer imported from the peers file, where the X25519 key alone is the
    // authority (spec 3.5: the file is the pin).
    pub ed: Option<VerifyingKey>,
    pub x: XPublic,
    pub expiry: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_wrongkey_and_aad_flip() {
        let k = [3u8; 32];
        let k2 = [4u8; 32];
        let pt = b"hello newnet";
        let ct = seal(&k, 5, b"hdr", pt).unwrap();
        assert_eq!(open(&k, 5, b"hdr", &ct).unwrap(), pt);
        assert!(open(&k2, 5, b"hdr", &ct).is_err());
        assert!(open(&k, 6, b"hdr", &ct).is_err());
        assert!(open(&k, 5, b"hxdr", &ct).is_err()); // aad is covered
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&k, 5, b"hdr", &bad).is_err());
    }

    #[test]
    fn keychain_rotates_per_generation() {
        let mut kc = KeyChain::new([3u8; 32]);
        let g0 = kc.key_for(0).unwrap();
        let g1 = kc.key_for(1).unwrap();
        let g2 = kc.key_for(2).unwrap();
        assert_ne!(g0, g1);
        assert_ne!(g1, g2);
        assert_eq!(kc.key_for(0).unwrap(), g0); // chain is append-only
    }

    #[test]
    fn keychain_forgets_old_generations() {
        let mut kc = KeyChain::new([3u8; 32]);
        let g2 = kc.key_for(3).unwrap();
        let g2k = kc.key_for(2).unwrap();
        kc.forget_before(2);
        assert_eq!(kc.key_for(1), None);
        assert_eq!(kc.key_for(2).unwrap(), g2k);
        assert_eq!(kc.key_for(3).unwrap(), g2);
        let g5 = kc.key_for(5).unwrap();
        kc.forget_before(100);
        assert_eq!(kc.generations(), 1);
        assert_eq!(kc.key_for(5).unwrap(), g5);
    }
}
