// Unreliable datagram frames: same session crypto, no retransmit.

use crate::session::Session;
use crate::streams::{Frame, FRAME_DGRAM};

// One message per frame. Capped by the 1200-byte datagram budget.
pub const MAX_DGRAM_PAYLOAD: usize = 1100;

pub fn send_datagram(s: &mut Session, msg: &[u8]) -> Option<Vec<u8>> {
    if msg.len() > MAX_DGRAM_PAYLOAD || s.state != crate::session::State::Open {
        return None;
    }
    let f = Frame { ftype: FRAME_DGRAM, id: 0, off: 0, cum: 0, sacks: vec![], data: msg.to_vec() };
    Some(s.seal_frame(&f))
}

// Drain received datagrams out of the session.
pub fn take_datagrams(s: &mut Session) -> Vec<Vec<u8>> {
    std::mem::take(&mut s.dgram_in)
}
