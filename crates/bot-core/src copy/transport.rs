// transport.rs
//
// Handles encryption and transmission of packets over TCP using RC4.

use cipher::consts::U16;
use rc4::{Rc4, StreamCipher};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

use crate::packets::Packet;

/// Encrypting transport structure that wraps an OwnedWriteHalf and RC4 state.
pub struct Transport {
    write_half: OwnedWriteHalf,
    write_cipher: Rc4<U16>,
}

impl Transport {
    /// Creates a new encrypted transport with an OwnedWriteHalf and initialized RC4 cipher.
    pub fn new(write_half: OwnedWriteHalf, write_cipher: Rc4<U16>) -> Self {
        Self {
            write_half,
            write_cipher,
        }
    }

    /// Encrypts and sends a binary packet to the server.
    pub async fn send(&mut self, packet: &Packet) -> anyhow::Result<()> {
        let mut buf = packet.to_bytes();
        self.write_cipher.apply_keystream(&mut buf);
        self.write_half.write_all(&buf).await?;
        Ok(())
    }
}
