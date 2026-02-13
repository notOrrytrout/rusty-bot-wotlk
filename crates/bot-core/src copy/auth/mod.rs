// srp/mod.rs
//
// High-level SRP interface for login orchestration

pub mod challenge;
pub mod handshake;

pub struct RealmdSession {
    pub session_key: Vec<u8>,
    pub a_pub: Vec<u8>,
    pub m1: Vec<u8>,
    pub character_count: usize,
}
