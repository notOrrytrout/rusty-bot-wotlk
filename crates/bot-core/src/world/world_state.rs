use std::collections::HashMap;
use std::num::Wrapping;

use anyhow::Result;

use crate::player::constants::{
    UNIT_FIELD_FLAGS, UNIT_FIELD_HEALTH, UNIT_FIELD_LEVEL, UNIT_FIELD_MAXHEALTH, UNIT_FIELD_POWER,
    UNIT_FIELD_POWER_TYPE, VISIBLE_ITEM_ENTRY_SPACING,
};
use crate::player::equipment::EquippedItem;
use crate::player::inventory::InventoryItem;
use crate::player::player_state::PowerType;
use crate::player::spells::KnownSpell;
use crate::player::{other_state::OtherPlayerState, player_state::PlayerCurrentState};
use crate::world::npc_state::NpcCurrentState;

const PLAYER_FIELD_PACK_SLOT_1: u32 = 0x012D; // Slot 0
const PLAYER_FIELD_PACK_SLOT_LAST: u32 = 0x013C; // Slot 15

const PLAYER_FIELD_SPELL_ID_0: u32 = 0x0094;
const PLAYER_FIELD_SPELL_ID_LAST: u32 = 0x00D3;

const PLAYER_VISIBLE_ITEM_0_ENTRYID: u32 = 47;
const PLAYER_VISIBLE_ITEM_18_ENTRYID: u32 = 83;

#[derive(Default)]
pub struct WorldState {
    pub players: HashMap<u64, PlayerCurrentState>,
    pub other_players: HashMap<u64, OtherPlayerState>,
    pub npcs: HashMap<u64, NpcCurrentState>,
    pub chat_log: Vec<String>,
    pub combat_log: Vec<String>,
    pub tick: Wrapping<u64>,
}

impl WorldState {
    pub fn new() -> Self {
        Self {
            players: HashMap::new(),
            other_players: HashMap::new(),
            npcs: HashMap::new(),
            chat_log: Vec::new(),
            combat_log: Vec::new(),
            tick: Wrapping(0),
        }
    }

    pub fn add_chat_message(&mut self, message: String) {
        self.chat_log.push(message);
        if self.chat_log.len() > 10 {
            self.chat_log.remove(0);
        }
    }

    pub fn add_combat_message(&mut self, message: String) {
        self.combat_log.push(message);
        if self.combat_log.len() > 10 {
            self.combat_log.remove(0);
        }
    }

    pub fn increment_tick(&mut self) {
        self.tick += Wrapping(1);
    }

    pub fn apply_update_object(&mut self, payload: &[u8]) -> Result<()> {
        let mut cursor = std::io::Cursor::new(payload);

        while (cursor.position() as usize) < payload.len() {
            let _update_type = cursor.get_u8(); // 0=create, 1=update, 2=destroy
            let guid = cursor.get_u64_le();
            let type_id = cursor.get_u8();
            let entry = cursor.get_u32_le();

            let mask_count = cursor.get_u32_le();
            let mut field_mask = Vec::with_capacity(mask_count as usize);
            for _ in 0..mask_count {
                field_mask.push(cursor.get_u32_le());
            }

            let mut field_ids = Vec::new();
            let mut values = Vec::new();
            for (block_index, mask) in field_mask.iter().enumerate() {
                for bit_index in 0..32 {
                    if mask & (1 << bit_index) != 0 {
                        let field_id = block_index as u32 * 32 + bit_index;
                        let value = cursor.get_u32_le();
                        field_ids.push(field_id);
                        values.push(value);
                    }
                }
            }

            match type_id {
                4 => {
                    let player = self
                        .players
                        .entry(guid)
                        .or_insert_with(|| PlayerCurrentState::new(guid));

                    for (field_id, value) in field_ids.into_iter().zip(values.into_iter()) {
                        match field_id {
                            UNIT_FIELD_HEALTH => player.health = value,
                            UNIT_FIELD_MAXHEALTH => player.max_health = value,
                            UNIT_FIELD_POWER_TYPE => {
                                player.power_type = PowerType::from(value as u8)
                            }
                            UNIT_FIELD_POWER => player.power = value,
                            UNIT_FIELD_LEVEL => player.level = value as u8,
                            UNIT_FIELD_FLAGS => player.flags = value,

                            PLAYER_VISIBLE_ITEM_0_ENTRYID..=PLAYER_VISIBLE_ITEM_18_ENTRYID => {
                                let slot = (field_id - PLAYER_VISIBLE_ITEM_0_ENTRYID)
                                    / VISIBLE_ITEM_ENTRY_SPACING;
                                if slot as usize >= player.equipment.len() {
                                    player.equipment.resize(
                                        slot as usize + 1,
                                        EquippedItem {
                                            slot: slot as u8,
                                            item_entry: 0,
                                        },
                                    );
                                }
                                player.equipment[slot as usize] = EquippedItem {
                                    slot: slot as u8,
                                    item_entry: value,
                                };
                            }

                            PLAYER_FIELD_PACK_SLOT_1..=PLAYER_FIELD_PACK_SLOT_LAST => {
                                let slot = field_id - PLAYER_FIELD_PACK_SLOT_1;
                                if slot as usize >= player.inventory.len() {
                                    player.inventory.resize(
                                        slot as usize + 1,
                                        InventoryItem {
                                            bag_index: slot as u8,
                                            item_entry: 0,
                                        },
                                    );
                                }
                                player.inventory[slot as usize] = InventoryItem {
                                    bag_index: slot as u8,
                                    item_entry: value,
                                };
                            }

                            PLAYER_FIELD_SPELL_ID_0..=PLAYER_FIELD_SPELL_ID_LAST => {
                                if !player.known_spells.iter().any(|s| s.id == value) {
                                    player.known_spells.push(KnownSpell {
                                        id: value,
                                        name: None,
                                    });
                                }
                            }

                            _ => {
                                player.set_dynamic_field(field_id, value.to_le_bytes().to_vec());
                            }
                        }
                    }
                }
                3 => {
                    let npc = self
                        .npcs
                        .entry(guid)
                        .or_insert_with(|| NpcCurrentState::new(guid, entry));
                    npc.set_fields(&field_mask, &values);
                }
                _ => {
                    let other = self
                        .other_players
                        .entry(guid)
                        .or_insert_with(|| OtherPlayerState::new(guid));
                    other.set_fields(&field_mask, &values);
                }
            }
        }

        Ok(())
    }
}

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

trait CursorExt {
    fn get_u8(&mut self) -> u8;
    fn get_u64_le(&mut self) -> u64;
    fn get_u32_le(&mut self) -> u32;
}

impl CursorExt for Cursor<&[u8]> {
    fn get_u8(&mut self) -> u8 {
        self.read_u8().unwrap_or(0)
    }

    fn get_u64_le(&mut self) -> u64 {
        self.read_u64::<LittleEndian>().unwrap_or(0)
    }

    fn get_u32_le(&mut self) -> u32 {
        self.read_u32::<LittleEndian>().unwrap_or(0)
    }
}
