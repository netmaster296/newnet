// Ed25519 identity + X25519 static, bound by a signed cert. Registry trust
// anchor is a constant. Pin store with signed handover for rotation.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

pub const CERT_TAG: &[u8] = b"NEWNET-CERT1";
pub const HANDOVER_TAG: &[u8] = b"NEWNET-HAND1";
pub const CERT_LEN: usize = CERT_TAG.len() + 32 + 8 + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    BadCertSignature,
    CertExpired,
    PinMismatch,
    HandoverBadSignature,
}

#[derive(Clone)]
pub struct Identity {
    pub ed_sign: SigningKey,
    pub x_static: StaticSecret,
    pub x_pub: XPublic,
}

impl Identity {
    // Deterministic from a seed so the demo and tests are reproducible.
    pub fn from_seed(seed: u64) -> Self {
        let mut s = [0u8; 32];
        for i in 0..4 {
            let w = seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add((i as u64).wrapping_mul(0x1000_0000_0000_0001));
            s[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
        }
        let ed_sign = SigningKey::from_bytes(&s);
        let mut x = [0u8; 32];
        x.copy_from_slice(&s);
        x[0] ^= 0x08;
        let x_static = StaticSecret::from(x);
        let x_pub = XPublic::from(&x_static);
        Identity { ed_sign, x_static, x_pub }
    }

    pub fn ed_pub(&self) -> VerifyingKey {
        self.ed_sign.verifying_key()
    }

    // Ed25519 key binds the X25519 static: tag || x25519 || expiry, signed.
    pub fn make_cert(&self, expiry: u64) -> Vec<u8> {
        let mut cert = CERT_TAG.to_vec();
        cert.extend_from_slice(self.x_pub.as_bytes());
        cert.extend_from_slice(&expiry.to_le_bytes());
        let sig = self.ed_sign.sign(&cert);
        cert.extend_from_slice(sig.to_bytes().as_slice());
        cert
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CertInfo {
    pub x25519: [u8; 32],
    pub expiry: u64,
}

// Verify a cert against a named Ed25519 key. Fails closed.
pub fn verify_cert(ed: &VerifyingKey, cert: &[u8], now: u64) -> Result<CertInfo, IdentityError> {
    if cert.len() != CERT_LEN || &cert[..CERT_TAG.len()] != CERT_TAG {
        return Err(IdentityError::BadCertSignature);
    }
    let body = &cert[..CERT_TAG.len() + 40];
    let sig = Signature::from_slice(&cert[CERT_TAG.len() + 40..])
        .map_err(|_| IdentityError::BadCertSignature)?;
    ed.verify_strict(body, &sig)
        .map_err(|_| IdentityError::BadCertSignature)?;
    let mut x = [0u8; 32];
    x.copy_from_slice(&cert[CERT_TAG.len()..CERT_TAG.len() + 32]);
    let expiry =
        u64::from_le_bytes(cert[CERT_TAG.len() + 32..CERT_TAG.len() + 40].try_into().unwrap());
    if expiry < now {
        return Err(IdentityError::CertExpired);
    }
    Ok(CertInfo { x25519: x, expiry })
}

// Rotation: old Ed25519 signs old_ed || new_ed || new_x25519 || expiry.
pub fn make_handover(old: &Identity, new: &Identity, expiry: u64) -> Vec<u8> {
    let mut h = HANDOVER_TAG.to_vec();
    h.extend_from_slice(old.ed_pub().as_bytes());
    h.extend_from_slice(new.ed_pub().as_bytes());
    h.extend_from_slice(new.x_pub.as_bytes());
    h.extend_from_slice(&expiry.to_le_bytes());
    let sig = old.ed_sign.sign(&h);
    h.extend_from_slice(sig.to_bytes().as_slice());
    h
}

#[derive(Debug, PartialEq, Eq)]
pub struct HandoverInfo {
    pub new_ed: [u8; 32],
    pub new_x25519: [u8; 32],
    pub expiry: u64,
}

// Verified against the pinned (old) Ed25519 key.
pub fn verify_handover(
    pinned_ed: &VerifyingKey,
    handover: &[u8],
    now: u64,
) -> Result<HandoverInfo, IdentityError> {
    let expect = HANDOVER_TAG.len() + 32 + 32 + 32 + 8;
    if handover.len() != expect + 64 || &handover[..HANDOVER_TAG.len()] != HANDOVER_TAG {
        return Err(IdentityError::HandoverBadSignature);
    }
    let sig = Signature::from_slice(&handover[expect..])
        .map_err(|_| IdentityError::HandoverBadSignature)?;
    pinned_ed
        .verify_strict(&handover[..expect], &sig)
        .map_err(|_| IdentityError::HandoverBadSignature)?;
    let mut info = HandoverInfo { new_ed: [0; 32], new_x25519: [0; 32], expiry: 0 };
    let t = HANDOVER_TAG.len();
    info.new_ed.copy_from_slice(&handover[t + 32..t + 64]);
    info.new_x25519.copy_from_slice(&handover[t + 64..t + 96]);
    info.expiry = u64::from_le_bytes(handover[t + 96..t + 104].try_into().unwrap());
    if info.expiry < now {
        return Err(IdentityError::CertExpired);
    }
    Ok(info)
}

#[derive(Debug, Clone)]
pub struct Pinned {
    pub ed: [u8; 32],
    pub x25519: [u8; 32],
    pub expiry: u64,
}

#[derive(Default)]
pub struct PinStore {
    pins: std::collections::HashMap<String, Pinned>,
}

impl PinStore {
    pub fn get(&self, name: &str) -> Option<&Pinned> {
        self.pins.get(name)
    }

    // TOFU: first contact pins, later mismatch fails.
    pub fn check_or_pin(
        &mut self,
        name: &str,
        ed: [u8; 32],
        x25519: [u8; 32],
        expiry: u64,
        now: u64,
    ) -> Result<(), IdentityError> {
        if expiry < now {
            return Err(IdentityError::CertExpired);
        }
        match self.pins.get(name) {
            None => {
                self.pins.insert(name.to_string(), Pinned { ed, x25519, expiry });
                Ok(())
            }
            Some(p) if p.ed == ed && p.x25519 == x25519 => Ok(()),
            Some(_) => Err(IdentityError::PinMismatch),
        }
    }

    // A verified handover moves the pin.
    pub fn apply_handover(&mut self, name: &str, h: &HandoverInfo) {
        if let Some(p) = self.pins.get_mut(name) {
            p.ed = h.new_ed;
            p.x25519 = h.new_x25519;
            p.expiry = h.expiry;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_round_trip_and_tamper() {
        let id = Identity::from_seed(1);
        let cert = id.make_cert(100);
        let info = verify_cert(&id.ed_pub(), &cert, 50).unwrap();
        assert_eq!(info.x25519, id.x_pub.as_bytes().to_owned());
        let mut bad = cert.clone();
        bad[CERT_TAG.len()] ^= 1;
        assert_eq!(verify_cert(&id.ed_pub(), &bad, 50), Err(IdentityError::BadCertSignature));
        assert_eq!(verify_cert(&id.ed_pub(), &cert, 101), Err(IdentityError::CertExpired));
        let other = Identity::from_seed(2);
        assert_eq!(verify_cert(&other.ed_pub(), &cert, 50), Err(IdentityError::BadCertSignature));
    }

    #[test]
    fn tofu_handover_and_mismatch() {
        let old = Identity::from_seed(3);
        let new = Identity::from_seed(4);
        let mut store = PinStore::default();
        store
            .check_or_pin("bob", *old.ed_pub().as_bytes(), old.x_pub.as_bytes().to_owned(), 100, 1)
            .unwrap();
        // Different identity, no handover: fail closed.
        assert_eq!(
            store.check_or_pin("bob", *new.ed_pub().as_bytes(), new.x_pub.as_bytes().to_owned(), 200, 1),
            Err(IdentityError::PinMismatch)
        );
        // Signed handover updates the pin.
        let ho = make_handover(&old, &new, 200);
        let hi = verify_handover(&old.ed_pub(), &ho, 1).unwrap();
        store.apply_handover("bob", &hi);
        store
            .check_or_pin("bob", *new.ed_pub().as_bytes(), new.x_pub.as_bytes().to_owned(), 200, 1)
            .unwrap();
        // Forged handover from a stranger fails.
        let stranger = Identity::from_seed(5);
        let ho2 = make_handover(&stranger, &new, 300);
        assert_eq!(verify_handover(&new.ed_pub(), &ho2, 1), Err(IdentityError::HandoverBadSignature));
    }
}
