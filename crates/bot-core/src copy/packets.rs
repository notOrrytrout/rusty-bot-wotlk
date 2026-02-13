use bincode::config::standard;
use bincode::Encode;
use byteorder::{LittleEndian, WriteBytesExt};

#[derive(Encode, Debug)]
pub enum PacketType {
    TalkToNpc(u64),
    OpenVendor(u64),
    AcceptQuest(u64),

    Say(String),
    Yell(String),

    MoveForward,
    MoveBackward,
    TurnLeft,
    TurnRight,
    Jump,
    CastSpell(u8),
}

impl PacketType {
    pub fn opcode(&self) -> u8 {
        match self {
            PacketType::MoveForward => 0x01,
            PacketType::MoveBackward => 0x02,
            PacketType::TurnLeft => 0x03,
            PacketType::TurnRight => 0x04,
            PacketType::Jump => 0x05,
            PacketType::CastSpell(_) => 0x06,
            PacketType::TalkToNpc(_) => 0x07,
            PacketType::OpenVendor(_) => 0x08,
            PacketType::AcceptQuest(_) => 0x09,
            PacketType::Say(_) => 0x0A,
            PacketType::Yell(_) => 0x0B,
        }
    }
}

#[derive(Debug, Encode)]
pub struct Packet {
    pub player_guid: u64,
    pub timestamp: u64,
    pub packet_type: PacketType,
}

impl Packet {
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload = bincode::encode_to_vec(self, standard()).unwrap();

        let mut buf = Vec::with_capacity(4 + payload.len());
        let size = (4 + payload.len()) as u16;
        buf.write_u16::<LittleEndian>(size).unwrap();
        buf.write_u16::<LittleEndian>(self.packet_type.opcode().into())
            .unwrap();
        buf.extend_from_slice(&payload);
        buf
    }
}

use anyhow::Result;

use crate::world::world_state::WorldState;

/// Parses a server packet and applies it to the shared world state.
///
/// # Arguments
/// * `opcode` - The opcode of the incoming packet
/// * `payload` - Decrypted packet payload
/// * `state` - Mutable reference to the bot's world state
///
/// # Returns
/// A Result indicating success or failure
pub fn parse_packet(opcode: u16, payload: &[u8], state: &mut WorldState) -> Result<()> {
    match opcode {
        0xA9 => {
            // Example: SMSG_UPDATE_OBJECT
            state.apply_update_object(payload)?;
        }
        _ => {
            println!("[parse_packet] Unhandled opcode: 0x{:X}", opcode);
        }
    }
    Ok(())
}

/// Parses a list of u32 values from the packet payload (used for spells, inventory, etc.)
pub fn parse_u32_list(payload: &[u8]) -> Result<Vec<u32>> {
    use byteorder::{LittleEndian, ReadBytesExt};
    use std::io::Cursor;

    let mut cursor = Cursor::new(payload);
    let mut values = Vec::new();
    while (cursor.position() as usize) < payload.len() {
        values.push(cursor.read_u32::<LittleEndian>()?);
    }
    Ok(values)
}

/// Parses a spell list packet
pub fn parse_spell_list(payload: &[u8]) -> Result<Vec<u32>> {
    parse_u32_list(payload)
}

/// Parses a talent list packet
pub fn parse_talent_list(payload: &[u8]) -> Result<Vec<u32>> {
    parse_u32_list(payload)
}

/// Parses inventory items
pub fn parse_inventory_list(payload: &[u8]) -> Result<Vec<u32>> {
    parse_u32_list(payload)
}

/// Parses equipped items
pub fn parse_equipped_list(payload: &[u8]) -> Result<Vec<u32>> {
    parse_u32_list(payload)
}

/// Parses a UTF-8 string message (used for chat or combat logs)
pub fn parse_string(payload: &[u8]) -> Result<String> {
    Ok(String::from_utf8_lossy(payload).to_string())
}
