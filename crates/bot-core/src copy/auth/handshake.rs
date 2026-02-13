// handshake.rs
//
// Handles SRP6 cryptographic handshake using external crate
// src/srp/handshake.rs
//
// Handles SRP6 cryptographic handshake using external crate
// src/srp/handshake.rs
//
// Handles SRP6 cryptographic handshake using external crate

use anyhow::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::Sha1;
use srp::{client::SrpClient, client::SrpClientVerifier, groups::G_2048};

/// Result of the client-side SRP handshake
pub struct SrpResult {
    pub a: Vec<u8>,
    pub a_pub: Vec<u8>,
    pub m1: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// Performs the SRP6 client-side handshake using raw credentials and challenge
pub fn perform_srp_handshake(
    username: &str,
    password: &str,
    salt: &[u8],
    b_pub: &[u8],
) -> Result<SrpResult> {
    // Generate random 512-bit private ephemeral 'a'
    let mut a_bytes = [0u8; 64];
    let mut rng = OsRng;
    rng.fill_bytes(&mut a_bytes);

    // Construct SRP client
    let client = SrpClient::<Sha1>::new(&G_2048);

    // Compute public A = g^a mod N
    let a_pub = client.compute_public_ephemeral(&a_bytes);

    // Process SRP reply and generate verifier
    let verifier: SrpClientVerifier<Sha1> = client
        .process_reply(
            &a_bytes,
            username.as_bytes(),
            password.as_bytes(),
            salt,
            b_pub,
        )
        .map_err(|e| anyhow::anyhow!("SRP process_reply failed: {:?}", e))?;

    Ok(SrpResult {
        a: a_bytes.to_vec(),
        a_pub,
        m1: verifier.proof().to_vec(),
        session_key: verifier.key().to_vec(),
    })
}
