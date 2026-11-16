// Naming: signed name -> key records. Registry speaks only inside an Open
// session. The registry Ed25519 key is baked into the binary (trust anchor).

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use x25519_dalek::PublicKey as XPublic;

use crate::identity::Identity;

pub const REGISTRY_SEED: u64 = 0x2E77_4E31_0000_0052; // "newnet anchor"

pub fn anchor_identity() -> Identity {
    Identity::from_seed(REGISTRY_SEED)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    pub name: String,
    pub ed: [u8; 32],
    pub x25519: [u8; 32],
    pub expiry: u64,
}

impl NameRecord {
    pub fn x_pub(&self) -> XPublic {
        XPublic::from(self.x25519)
    }
}

pub fn record_bytes(r: &NameRecord) -> Vec<u8> {
    postcard::to_allocvec(r).expect("ser record")
}

pub struct SignedRecord {
    pub bytes: Vec<u8>,
    pub sig: [u8; 64],
}

pub fn sign_record(reg: &Identity, r: &NameRecord) -> SignedRecord {
    let bytes = record_bytes(r);
    let sig = reg.ed_sign.sign(&bytes);
    SignedRecord { bytes, sig: sig.to_bytes().into() }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NamingError {
    BadSig,
    Expired,
    NameMismatch,
    Malformed,
}

// Verify against the baked-in anchor. Fails closed.
pub fn verify_signed(
    s: &SignedRecord,
    anchor: &VerifyingKey,
    now: u64,
) -> Result<NameRecord, NamingError> {
    let sig = Signature::from_slice(&s.sig).map_err(|_| NamingError::Malformed)?;
    anchor
        .verify_strict(&s.bytes, &sig)
        .map_err(|_| NamingError::BadSig)?;
    let r: NameRecord = postcard::from_bytes(&s.bytes).map_err(|_| NamingError::Malformed)?;
    if r.expiry < now {
        return Err(NamingError::Expired);
    }
    Ok(r)
}

pub struct Registry {
    pub ident: Identity,
    table: BTreeMap<String, NameRecord>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry { ident: anchor_identity(), table: BTreeMap::new() }
    }

    pub fn set_record(&mut self, name: &str, ed: [u8; 32], x25519: [u8; 32], expiry: u64) {
        self.table.insert(name.to_string(), NameRecord { name: name.to_string(), ed, x25519, expiry });
    }

    pub fn get(&self, name: &str) -> Option<&NameRecord> {
        self.table.get(name)
    }

    pub fn sign(&self, name: &str) -> Option<SignedRecord> {
        self.table.get(name).map(|r| sign_record(&self.ident, r))
    }

    pub fn signed_bytes(&self, name: &str) -> Option<Vec<u8>> {
        let s = self.sign(name)?;
        let mut v = (s.bytes.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(&s.bytes);
        v.extend_from_slice(&s.sig);
        Some(v)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Registry::new()
    }
}

// Client side: unpack a ResolveResp payload into a verified record.
pub fn parse_signed_bytes(blob: &[u8], anchor: &VerifyingKey, now: u64) -> Result<NameRecord, NamingError> {
    if blob.len() < 4 + 64 {
        return Err(NamingError::Malformed);
    }
    let n = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
    if 4 + n + 64 != blob.len() {
        return Err(NamingError::Malformed);
    }
    let s = SignedRecord {
        bytes: blob[4..4 + n].to_vec(),
        sig: blob[4 + n..].try_into().map_err(|_| NamingError::Malformed)?,
    };
    verify_signed(&s, anchor, now)
}
