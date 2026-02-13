use crate::auth::challenge::build_logon_challenge;
use anyhow::{Context, Result};
use byteorder::LittleEndian;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::{Digest, Sha1};
use srp::client::SrpClient;

use cipher::{consts::U16, KeyInit};
use rc4::Rc4;
use srp::groups::G_2048;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};

/// Holds result of a successful SRP handshake with realmd
pub struct RealmdSession {
    pub session_key: Vec<u8>,
    pub a_pub: Vec<u8>,
    pub m1: Vec<u8>,
    pub character_count: usize,
}

/// Performs SRP6 login handshake with realmd
pub async fn login_realmd(addr: &str, username: &str, password: &str) -> Result<RealmdSession> {
    let mut stream = TcpStream::connect(addr).await.context("connect realmd")?;
    let auth_challenge = build_logon_challenge(username);
    stream.write_all(&auth_challenge).await?;

    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[1] != 0x00 {
        anyhow::bail!("Realmd login rejected: status 0x{:02X}", header[1]);
    }

    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await?;
    let mut cursor = Cursor::new(&buf[..n]);

    let b_len = byteorder::ReadBytesExt::read_u8(&mut cursor)?;
    let mut b_pub = vec![0u8; b_len as usize];
    std::io::Read::read_exact(&mut cursor, &mut b_pub)?;

    let g_len = byteorder::ReadBytesExt::read_u8(&mut cursor)?;
    let mut _g = vec![0u8; g_len as usize];
    std::io::Read::read_exact(&mut cursor, &mut _g)?;

    let n_len = byteorder::ReadBytesExt::read_u8(&mut cursor)?;
    let mut _n = vec![0u8; n_len as usize];
    std::io::Read::read_exact(&mut cursor, &mut _n)?;

    let mut salt = [0u8; 32];
    std::io::Read::read_exact(&mut cursor, &mut salt)?;

    let mut _version = [0u8; 16];
    std::io::Read::read_exact(&mut cursor, &mut _version)?;
    let _flags = byteorder::ReadBytesExt::read_u8(&mut cursor)?;

    // Generate private ephemeral `a`
    let mut a_bytes = [0u8; 64];
    OsRng.try_fill_bytes(&mut a_bytes);
    let a = BigUint::from_bytes_be(&a_bytes);

    // Compute A = g^a mod N
    let client = SrpClient::<Sha1>::new(&G_2048);
    let a_pub_big = client.compute_a_pub(&a);
    let a_pub = a_pub_big.to_bytes_be();

    let client = SrpClient::<Sha1>::new(&G_2048);

    let verifier = client
        .process_reply(
            &a_bytes,
            username.as_bytes(),
            password.as_bytes(),
            &salt,
            &b_pub,
        )
        .map_err(|e| anyhow::anyhow!("SRP verification failed: {:?}", e))?;

    let m1 = verifier.proof().to_vec();
    let session_key = verifier.key().to_vec();

    let mut proof = Vec::new();
    proof.push(0x01); // AUTH_LOGON_PROOF
    proof.extend_from_slice(&a_pub);
    proof.extend_from_slice(&m1);
    stream.write_all(&proof).await?;

    let mut resp = [0u8; 3];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 {
        anyhow::bail!("Auth proof rejected: 0x{:02X}", resp[1]);
    }

    // Receive CHAR_ENUM packet (opcode: 0x3F6)
    let mut header = [0u8; 6];
    stream.read_exact(&mut header).await?;
    let size = u16::from_le_bytes([header[0], header[1]]) as usize;
    let opcode = u16::from_le_bytes([header[2], header[3]]);
    if opcode != 0x3F6 {
        anyhow::bail!("Expected CHAR_ENUM, got opcode: 0x{:04X}", opcode);
    }

    let mut payload = vec![0u8; size - 2];
    stream.read_exact(&mut payload).await?;
    let mut cur = Cursor::new(&payload);
    let character_count = byteorder::ReadBytesExt::read_u8(&mut cur)? as usize;

    Ok(RealmdSession {
        session_key,
        a_pub: a_pub.to_vec(),
        m1,
        character_count,
    })
}

/// Encrypted connection to worldserver
pub struct WorldSession {
    pub read_half: OwnedReadHalf,
    pub write_half: OwnedWriteHalf,
    pub read_cipher: Rc4<U16>,
    pub write_cipher: Rc4<U16>,
}

/// Derives RC4 key from SRP session_key and logs into world
pub async fn login_world(addr: &str, sess: &RealmdSession) -> Result<WorldSession> {
    let stream = TcpStream::connect(addr)
        .await
        .context("connect worldserver")?;
    let (read_half, write_half) = stream.into_split();

    let mut hasher = Sha1::new();
    hasher.update(b"WoW");
    hasher.update(&sess.session_key);
    let rc4_key = hasher.finalize();
    let rc4_key = &rc4_key[..16];

    let read_cipher = Rc4::<U16>::new_from_slice(rc4_key)?;
    let write_cipher = Rc4::<U16>::new_from_slice(rc4_key)?;

    Ok(WorldSession {
        read_half,
        write_half,
        read_cipher,
        write_cipher,
    })
}

/// Selects a character by index from the CHAR_ENUM packet.
pub async fn select_character(
    read_half: &mut OwnedReadHalf,
    character_index: usize,
) -> Result<u64> {
    let mut header = [0u8; 6];
    read_half.read_exact(&mut header).await?;
    let size = u16::from_le_bytes([header[0], header[1]]) as usize;
    let opcode = u16::from_le_bytes([header[2], header[3]]);
    if opcode != 0x3F6 {
        anyhow::bail!("Expected CHAR_ENUM (0x3F6), got: 0x{:04X}", opcode);
    }

    let mut payload = vec![0u8; size - 2];
    read_half.read_exact(&mut payload).await?;
    let mut cur = Cursor::new(&payload);

    let num_chars = byteorder::ReadBytesExt::read_u8(&mut cur)? as usize;
    if character_index >= num_chars {
        anyhow::bail!(
            "Character index {} out of bounds ({} available)",
            character_index,
            num_chars
        );
    }

    for i in 0..num_chars {
        let guid = byteorder::ReadBytesExt::read_u64::<LittleEndian>(&mut cur)?;
        if i == character_index {
            return Ok(guid);
        }
        cur.set_position(cur.position() + 40);
    }

    anyhow::bail!("Character not found")
}
