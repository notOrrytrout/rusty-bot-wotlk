// src/srp/challenge.rs
//
// Builds SRP login challenge packets for realm authentication

pub fn build_logon_challenge(username: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x00); // AUTH_LOGON_CHALLENGE opcode
    buf.push(0x08); // protocol version

    buf.push(0x00); // game name tag
    buf.extend_from_slice(b"WOW\0"); // game name

    buf.push(0x03); // version major
    buf.push(0x03); // version minor
    buf.push(0x05); // version patch
    buf.extend_from_slice(&0x12345678u32.to_le_bytes()); // build

    // Platform, OS, Locale, Timezone, IP (all zeroes here)
    buf.extend_from_slice(&0u16.to_le_bytes()); // platform
    buf.extend_from_slice(&0u16.to_le_bytes()); // os
    buf.extend_from_slice(&0u16.to_le_bytes()); // locale
    buf.extend_from_slice(&0u32.to_le_bytes()); // timezone
    buf.extend_from_slice(&0u32.to_le_bytes()); // IP

    buf.push(username.len() as u8);
    buf.extend_from_slice(username.as_bytes());

    buf
}
