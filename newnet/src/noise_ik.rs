// Handshake: Noise_IK_25519_ChaChaPoly_SHA256 via the snow crate
// (Apache-2.0 OR MIT). Transport keys are taken with snow's raw split
// because this crate has its own packet format.

use crate::crypto::{NoiseError, SplitKeys};

pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
pub const PROLOGUE_TAG: &[u8] = b"NEWNET1";

/// PROLOGUE_TAG followed by conn_id as 8 little-endian bytes.
pub fn prologue(conn_id: u64) -> Vec<u8> {
    let mut p = PROLOGUE_TAG.to_vec();
    p.extend_from_slice(&conn_id.to_le_bytes());
    p
}

/// Payload of handshake message 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub stamp: u64,
    pub name: String,
}

/// stamp as 8 little-endian bytes, then name length as u16 little-endian,
/// then the name's UTF-8 bytes.
pub fn encode_hello(h: &Hello) -> Vec<u8> {
    let mut b = Vec::with_capacity(10 + h.name.len());
    b.extend_from_slice(&h.stamp.to_le_bytes());
    b.extend_from_slice(&(h.name.len() as u16).to_le_bytes());
    b.extend_from_slice(h.name.as_bytes());
    b
}

/// Strict inverse. None if too short, if the length field does not match the
/// remaining bytes exactly, or if the name is not UTF-8.
pub fn decode_hello(b: &[u8]) -> Option<Hello> {
    if b.len() < 10 {
        return None;
    }
    let stamp = u64::from_le_bytes(b[..8].try_into().unwrap());
    let name_len = u16::from_le_bytes(b[8..10].try_into().unwrap()) as usize;
    let name_bytes = b.get(10..)?;
    if name_bytes.len() != name_len {
        return None;
    }
    let name = std::str::from_utf8(name_bytes).ok()?.to_string();
    Some(Hello { stamp, name })
}

fn split_keys(hs: &mut snow::HandshakeState) -> SplitKeys {
    let (a_to_b, b_to_a) = hs.dangerously_get_raw_split();
    let mut transcript_hash = [0u8; 32];
    transcript_hash.copy_from_slice(hs.get_handshake_hash());
    SplitKeys {
        a_to_b_gen0: a_to_b,
        b_to_a_gen0: b_to_a,
        transcript_hash,
    }
}

pub struct InitiatorHandshake {
    hs: snow::HandshakeState,
}

impl InitiatorHandshake {
    pub fn new(
        local_static: &[u8; 32],
        remote_static: &[u8; 32],
        prologue: &[u8],
        eph: Option<[u8; 32]>,
    ) -> Result<Self, NoiseError> {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        let mut builder = snow::Builder::new(params);
        builder = builder
            .local_private_key(local_static)
            .map_err(|_| NoiseError::AuthFailed)?
            .remote_public_key(remote_static)
            .map_err(|_| NoiseError::AuthFailed)?
            .prologue(prologue)
            .map_err(|_| NoiseError::AuthFailed)?;
        if let Some(e) = eph.as_ref() {
            builder = builder.fixed_ephemeral_key_for_testing_only(e);
        }
        let hs = builder.build_initiator().map_err(|_| NoiseError::AuthFailed)?;
        Ok(InitiatorHandshake { hs })
    }

    pub fn write_msg1(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut out = vec![0u8; payload.len() + 256];
        let n = self
            .hs
            .write_message(payload, &mut out)
            .map_err(|_| NoiseError::AuthFailed)?;
        out.truncate(n);
        Ok(out)
    }

    /// Returns (payload of message 2, session keys). snow restores its own
    /// state on error, so a forged message 2 cannot kill a pending handshake.
    pub fn read_msg2(&mut self, msg2: &[u8]) -> Result<(Vec<u8>, SplitKeys), NoiseError> {
        let mut out = vec![0u8; msg2.len()];
        let n = self
            .hs
            .read_message(msg2, &mut out)
            .map_err(|_| NoiseError::AuthFailed)?;
        out.truncate(n);
        Ok((out, split_keys(&mut self.hs)))
    }
}

pub struct ResponderHandshake {
    hs: snow::HandshakeState,
}

impl ResponderHandshake {
    pub fn new(
        local_static: &[u8; 32],
        prologue: &[u8],
        eph: Option<[u8; 32]>,
    ) -> Result<Self, NoiseError> {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        let mut builder = snow::Builder::new(params);
        builder = builder
            .local_private_key(local_static)
            .map_err(|_| NoiseError::AuthFailed)?
            .prologue(prologue)
            .map_err(|_| NoiseError::AuthFailed)?;
        if let Some(e) = eph.as_ref() {
            builder = builder.fixed_ephemeral_key_for_testing_only(e);
        }
        let hs = builder.build_responder().map_err(|_| NoiseError::AuthFailed)?;
        Ok(ResponderHandshake { hs })
    }

    /// Returns (payload of message 1, the initiator's static public key).
    pub fn read_msg1(&mut self, msg1: &[u8]) -> Result<(Vec<u8>, [u8; 32]), NoiseError> {
        let mut out = vec![0u8; msg1.len()];
        let n = self
            .hs
            .read_message(msg1, &mut out)
            .map_err(|_| NoiseError::AuthFailed)?;
        out.truncate(n);
        let rs = self.hs.get_remote_static().ok_or(NoiseError::AuthFailed)?;
        if rs.len() != 32 {
            return Err(NoiseError::AuthFailed);
        }
        let mut static_key = [0u8; 32];
        static_key.copy_from_slice(rs);
        Ok((out, static_key))
    }

    /// Returns (message 2 bytes, session keys).
    pub fn write_msg2(&mut self, payload: &[u8]) -> Result<(Vec<u8>, SplitKeys), NoiseError> {
        let mut out = vec![0u8; payload.len() + 256];
        let n = self
            .hs
            .write_message(payload, &mut out)
            .map_err(|_| NoiseError::AuthFailed)?;
        out.truncate(n);
        Ok((out, split_keys(&mut self.hs)))
    }
}
