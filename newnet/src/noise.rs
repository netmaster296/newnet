// Noise_IK handshake machine with identity binding.
// msg1 = -> e, es, s, ss:  ep1 || tag(empty transit) || sealed(name, cert, tsig(h0))
// msg2 = <- e, ee, se:     ep2 || sealed(name, cert, tsig(h_after_msg1))
// tsig_init covers h0 = HASH(protocol || responder_static); the responder
// checks it against the registry record for the claimed name. tsig_resp
// covers the running hash after msg1, binding msg2 to this session.

use ed25519_dalek::{Signature, Signer};

use crate::crypto::{self, CipherState, NoiseError, PeerRecord, SplitKeys};
use crate::identity::{self, Identity};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

fn u16_str(s: &str) -> Vec<u8> {
    let mut v = (s.len() as u16).to_le_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v
}

fn read_str(b: &[u8], off: usize) -> Option<(String, usize)> {
    if off + 2 > b.len() {
        return None;
    }
    let n = u16::from_le_bytes(b[off..off + 2].try_into().unwrap()) as usize;
    if off + 2 + n > b.len() {
        return None;
    }
    String::from_utf8(b[off + 2..off + 2 + n].to_vec()).ok().map(|s| (s, off + 2 + n))
}

fn parse_payload(pt: &[u8]) -> Result<(String, Vec<u8>, Signature), NoiseError> {
    let (name, off) = read_str(pt, 0).ok_or(NoiseError::BadPayload)?;
    if off + identity::CERT_LEN + 64 != pt.len() {
        return Err(NoiseError::BadPayload);
    }
    let cert = pt[off..off + identity::CERT_LEN].to_vec();
    let sig = Signature::from_slice(&pt[off + identity::CERT_LEN..])
        .map_err(|_| NoiseError::BadPayload)?;
    Ok((name, cert, sig))
}

fn pub32(b: &[u8]) -> Option<[u8; 32]> {
    b.get(..32).map(|s| s.try_into().unwrap())
}

#[derive(Clone)]
pub struct InitiatorHandshake {
    cs: CipherState,
    h: [u8; 32], // after msg1 mixes
    h0: [u8; 32],
    epriv: StaticSecret,
    spriv: StaticSecret,
    rs: XPublic,
    peer_ed: ed25519_dalek::VerifyingKey,
}

impl InitiatorHandshake {
    // rs/cert come from the registry record or pin. Deterministic eph only
    // for tests; pass None for a random ephemeral in the demo.
    pub fn new(id: &Identity, rec: &PeerRecord, eph: Option<[u8; 32]>) -> Result<Self, NoiseError> {
        if !rec.cert.is_empty() {
            let info = identity::verify_cert(&rec.ed, &rec.cert, 0)
                .map_err(|_| NoiseError::AuthFailed)?;
            if info.x25519 != *rec.x.as_bytes() {
                return Err(NoiseError::AuthFailed);
            }
        }
        let h0 = crypto::sha256(&[&crypto::pad_protocol(), rec.x.as_bytes()]);
        let epriv = StaticSecret::from(eph.unwrap_or_else(|| {
            let mut b = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut b);
            b
        }));
        let cs = CipherState::new();
        Ok(InitiatorHandshake {
            cs,
            h: h0,
            h0,
            epriv,
            spriv: id.x_static.clone(),
            rs: rec.x,
            peer_ed: rec.ed,
        })
    }

    pub fn msg1_body(&mut self, id: &Identity, my_name: &str) -> Vec<u8> {
        let ep1 = XPublic::from(&self.epriv);
        self.h = crypto::sha256(&[&self.h, ep1.as_bytes()]);
        self.cs.mix_key(&crypto::dh(&self.epriv, &self.rs)); // es
        let tsig = id.ed_sign.sign(&self.h0);
        let mut pt = u16_str(my_name);
        pt.extend_from_slice(&id.make_cert(u64::MAX));
        pt.extend_from_slice(tsig.to_bytes().as_slice());
        let tag = self.cs.encrypt(&[], &[]);
        let ct = self.cs.encrypt(&[], &pt);
        self.h = crypto::sha256(&[&self.h, &tag, &ct]);
        self.cs.mix_key(&crypto::dh(&self.spriv, &self.rs)); // ss
        let mut body = ep1.as_bytes().to_vec();
        body.extend_from_slice(&tag);
        body.extend_from_slice(&ct);
        body
    }

    pub fn msg2_accept(&mut self, body: &[u8]) -> Result<SplitKeys, NoiseError> {
        if body.len() < 32 {
            return Err(NoiseError::BadPayload);
        }
        let ep2 = XPublic::from(pub32(&body[..32]).ok_or(NoiseError::BadPayload)?);
        // Token order: e, ee, se mix before the payload decrypts.
        self.cs.mix_key(&crypto::dh(&self.epriv, &ep2)); // ee
        self.cs.mix_key(&crypto::dh(&self.epriv, &self.rs)); // se: initiator's e x responder's s
        let pt = self.cs.decrypt(&[], &body[32..])?;
        let (_name, cert, tsig) = parse_payload(&pt)?;
        let info = identity::verify_cert(&self.peer_ed, &cert, 0)
            .map_err(|_| NoiseError::AuthFailed)?;
        if info.x25519 != *self.rs.as_bytes() {
            return Err(NoiseError::AuthFailed);
        }
        self.peer_ed
            .verify_strict(&self.h, &tsig)
            .map_err(|_| NoiseError::AuthFailed)?;
        let transcript = crypto::sha256(&[&self.h, body]);
        let (a, b) = self.cs.split(&transcript);
        Ok(SplitKeys { a_to_b_gen0: a, b_to_a_gen0: b, transcript_hash: transcript })
    }
}

pub struct ResponderHandshake {
    cs: CipherState,
    h: [u8; 32], // after msg1 mixes
    transcript: [u8; 32],
    id: Identity,
    peer_name: String,
    ep1: XPublic,
    epriv: StaticSecret,
}

impl ResponderHandshake {
    pub fn start(
        id: &Identity,
        body: &[u8],
        lookup: &dyn Fn(&str) -> Option<PeerRecord>,
        eph: Option<[u8; 32]>,
    ) -> Result<Self, NoiseError> {
        if body.len() < 32 + 16 + 1 {
            return Err(NoiseError::BadPayload);
        }
        let ep1 = XPublic::from(pub32(&body[..32]).ok_or(NoiseError::BadPayload)?);
        let h0 = crypto::sha256(&[&crypto::pad_protocol(), id.x_pub.as_bytes()]);
        let mut cs = CipherState::new();
        cs.mix_key(&crypto::dh(&id.x_static, &ep1)); // es
        let tag = &body[32..48];
        let ct = &body[48..];
        let _ = cs.decrypt(&[], tag)?; // empty transit, tag only (nonce 0)
        let pt = cs.decrypt(&[], ct)?;
        let (name, cert, tsig) = parse_payload(&pt)?;
        let rec = lookup(&name).ok_or(NoiseError::UnknownName)?;
        let info = identity::verify_cert(&rec.ed, &cert, 0)
            .map_err(|_| NoiseError::AuthFailed)?;
        if info.x25519 != *rec.x.as_bytes() {
            return Err(NoiseError::AuthFailed);
        }
        // Initiator proved possession of the Ed25519 bound to the record.
        rec.ed.verify_strict(&h0, &tsig).map_err(|_| NoiseError::AuthFailed)?;
        let mut h = crypto::sha256(&[&h0, ep1.as_bytes()]);
        h = crypto::sha256(&[&h, tag, ct]);
        cs.mix_key(&crypto::dh(&id.x_static, &XPublic::from(info.x25519))); // ss
        let epriv = StaticSecret::from(eph.unwrap_or_else(|| {
            let mut b = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut b);
            b
        }));
        Ok(ResponderHandshake { cs, h, transcript: h, id: id.clone(), peer_name: name, ep1, epriv })
    }

    pub fn msg2_body(&mut self, my_name: &str) -> Vec<u8> {
        let ep2 = XPublic::from(&self.epriv);
        self.cs.mix_key(&crypto::dh(&self.epriv, &self.ep1)); // ee
        self.cs.mix_key(&crypto::dh(&self.id.x_static, &self.ep1)); // se
        let tsig = self.id.ed_sign.sign(&self.h);
        let mut pt = u16_str(my_name);
        pt.extend_from_slice(&self.id.make_cert(u64::MAX));
        pt.extend_from_slice(tsig.to_bytes().as_slice());
        let ct = self.cs.encrypt(&[], &pt);
        let mut body = ep2.as_bytes().to_vec();
        body.extend_from_slice(&ct);
        self.transcript = crypto::sha256(&[&self.h, &body]);
        body
    }

    pub fn peer_name(&self) -> &str {
        &self.peer_name
    }

    pub fn split(&self) -> SplitKeys {
        let (a, b) = self.cs.split(&self.transcript);
        SplitKeys { a_to_b_gen0: a, b_to_a_gen0: b, transcript_hash: self.transcript }
    }
}
