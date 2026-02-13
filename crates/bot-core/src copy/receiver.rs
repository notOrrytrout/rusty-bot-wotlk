// receiver.rs
//
// Reads incoming packets from the server, decrypts them, and updates world state.

use std::io::Cursor;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::Mutex; // only needed for reading from the TCP stream

use cipher::{consts::U16, StreamCipher};
use rc4::Rc4;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::packets::{parse_inventory_list, parse_packet, parse_spell_list, parse_talent_list};
use crate::player::equipment::EquippedItem;
use crate::player::inventory::InventoryItem;
use crate::player::player_state::PlayerCurrentState;
use crate::player::talents::{Talent, Talents};
use crate::utils::reader::read_cstring;
use crate::world::world_state::WorldState;

/// Starts the packet receiver loop
pub async fn start_receiver(
    mut read_half: OwnedReadHalf,
    mut read_cipher: Rc4<U16>,
    world_state: Arc<Mutex<WorldState>>,
) {
    let mut buf = vec![0u8; 4096];

    loop {
        if let Err(e) = read_half.read_exact(&mut buf[..6]).await {
            eprintln!("[receiver] header read failed: {:?}", e);
            break;
        }
        read_cipher.apply_keystream(&mut buf[..6]);

        let size = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let opcode = u16::from_le_bytes([buf[2], buf[3]]);

        if let Err(e) = read_half.read_exact(&mut buf[6..(size + 4)]).await {
            eprintln!("[receiver] payload read failed: {:?}", e);
            break;
        }
        read_cipher.apply_keystream(&mut buf[6..(size + 4)]);

        let payload = &buf[4..(size + 4)];

        let mut ws = world_state.lock().await;
        if let Err(e) = parse_packet(opcode, payload, &mut ws) {
            eprintln!("[receiver] packet parse error: {:?}", e);
        }

        ws.increment_tick();
    }
}

/// Dispatches known packet types to specific handlers
pub async fn process_packet(
    opcode: u16,
    payload: &[u8],
    guid: u64,
    world: &Arc<Mutex<WorldState>>,
) {
    let mut world = world.lock().await;
    if let Some(player) = world.players.get_mut(&guid) {
        match opcode {
            0x127 => {
                // SMSG_LEARNED_SPELL
                if let Ok(spells) = parse_spell_list(payload) {
                    player.update_spells(spells);
                }
            }

            0x132 => {
                // SMSG_TALENTS_INFO
                if let Ok(ids) = parse_talent_list(payload) {
                    let structured: Talents = ids
                        .into_iter()
                        .map(|id| Talent {
                            tab: 0,
                            talent_id: id,
                        })
                        .collect();
                    player.update_talents(structured);
                }
            }

            0x28B => {
                // Inventory
                if let Ok(item_ids) = parse_inventory_list(payload) {
                    let inventory = item_ids
                        .into_iter()
                        .enumerate()
                        .map(|(i, item_id)| InventoryItem {
                            bag_index: i as u8,
                            item_entry: item_id,
                        })
                        .collect();
                    player.update_inventory(inventory);
                }
            }

            0x28C => {
                // Equipment
                if let Ok(item_ids) = parse_inventory_list(payload) {
                    let equipment = item_ids
                        .into_iter()
                        .enumerate()
                        .map(|(i, item_id)| EquippedItem {
                            slot: i as u8,
                            item_entry: item_id,
                        })
                        .collect();
                    player.update_equipment(equipment);
                }
            }

            0x14A => {
                // SMSG_ATTACKERSTATEUPDATE
                handle_combat_event(payload, &mut world).await;
            }

            0x96 => {
                // SMSG_MESSAGECHAT
                parse_chat_message(payload, &mut *world);
            }

            _ => {
                println!("[receiver] Unhandled opcode: 0x{:X}", opcode);
            }
        }
    }
}

/// Handles character list from SMSG_CHAR_ENUM (0x3B)
pub async fn handle_char_enum(payload: &[u8], world: &Arc<Mutex<WorldState>>) {
    let mut cursor = Cursor::new(payload);
    if let Ok(count) = ReadBytesExt::read_u8(&mut cursor) {
        let mut world = world.lock().await;
        for _ in 0..count {
            let guid = ReadBytesExt::read_u64::<LittleEndian>(&mut cursor).unwrap_or(0);
            let name_len = ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);
            let mut name_bytes = vec![0u8; name_len as usize];
            let _ = cursor.read_exact(&mut name_bytes);
            let name = String::from_utf8_lossy(&name_bytes).into_owned();

            let race = ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);
            let class = ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);
            let gender = ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);
            let level = ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);
            let zone = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor).unwrap_or(0);
            let map = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor).unwrap_or(0);
            let x = ReadBytesExt::read_f32::<LittleEndian>(&mut cursor).unwrap_or(0.0);
            let y = ReadBytesExt::read_f32::<LittleEndian>(&mut cursor).unwrap_or(0.0);
            let z = ReadBytesExt::read_f32::<LittleEndian>(&mut cursor).unwrap_or(0.0);

            let mut player = PlayerCurrentState::new(guid);
            player.level = level;
            player.race = race;
            player.class = class;
            player.gender = gender;
            player.map_id = map;
            player.zone_id = zone;
            player.position.x = x;
            player.position.y = y;
            player.position.z = z;

            world.players.insert(guid, player);
            println!("[char_enum] Character: {} (GUID {:X})", name, guid);
        }
    }
}

/// Handles basic combat log message (SMSG_ATTACKERSTATEUPDATE)
pub async fn handle_combat_event(payload: &[u8], world: &mut WorldState) {
    let msg = String::from_utf8_lossy(payload).to_string();
    world.add_combat_message(msg.clone());
    println!("[combat] {}", msg);
}

/// Parses in-band chat messages (SMSG_MESSAGECHAT)
pub fn parse_chat_message(payload: &[u8], world: &mut WorldState) {
    let mut cursor = Cursor::new(payload);

    let _chat_type = ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);
    let _language = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor).unwrap_or(0);
    let _sender_guid = ReadBytesExt::read_u64::<LittleEndian>(&mut cursor).unwrap_or(0);
    let _receiver_guid = ReadBytesExt::read_u64::<LittleEndian>(&mut cursor).unwrap_or(0);

    let channel_name = read_cstring(&mut cursor).unwrap_or_default();
    let sender_name = read_cstring(&mut cursor).unwrap_or_default();
    let message = read_cstring(&mut cursor).unwrap_or_default();
    let _chat_tag = ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);

    let full_message = if !channel_name.is_empty() {
        format!("[{}] {}: {}", channel_name, sender_name, message)
    } else {
        format!("{}: {}", sender_name, message)
    };

    world.add_chat_message(full_message);
}
