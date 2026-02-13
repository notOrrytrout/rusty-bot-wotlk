use std::collections::HashMap;
use std::num::Wrapping;

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

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

// WoW 3.3.5a update field indices (AzerothCore `UpdateFields.h`).
const OBJECT_FIELD_ENTRY: u32 = 0x0003;

// WoW 3.3.5a type IDs (AzerothCore `TypeID`).
const TYPEID_UNIT: u8 = 3;
const TYPEID_PLAYER: u8 = 4;

// WoW 3.3.5a SMSG_UPDATE_OBJECT update types (AzerothCore `OBJECT_UPDATE_TYPE`).
const UPDATETYPE_VALUES: u8 = 0;
const UPDATETYPE_MOVEMENT: u8 = 1;
const UPDATETYPE_CREATE_OBJECT: u8 = 2;
const UPDATETYPE_CREATE_OBJECT2: u8 = 3;
const UPDATETYPE_OUT_OF_RANGE_OBJECTS: u8 = 4;

// WoW 3.3.5a update flags (AzerothCore `OBJECT_UPDATE_FLAGS`).
const UPDATEFLAG_LIVING: u16 = 0x0020;
const UPDATEFLAG_TRANSPORT: u16 = 0x0002;
const UPDATEFLAG_HAS_TARGET: u16 = 0x0004;
const UPDATEFLAG_UNKNOWN: u16 = 0x0008;
const UPDATEFLAG_LOWGUID: u16 = 0x0010;
const UPDATEFLAG_VEHICLE: u16 = 0x0080;
const UPDATEFLAG_POSITION: u16 = 0x0100;
const UPDATEFLAG_STATIONARY_POSITION: u16 = 0x0040;
const UPDATEFLAG_ROTATION: u16 = 0x0200;

// WoW 3.3.5a movement flags (subset; see gateway-proxy `wotlk::movement`).
const MOVEMENTFLAG_ONTRANSPORT: u32 = 0x0000_0200;
const MOVEMENTFLAG_SWIMMING: u32 = 0x0020_0000;
const MOVEMENTFLAG_FLYING: u32 = 0x0200_0000;
const MOVEMENTFLAG_JUMPING: u32 = 0x0000_1000;
const MOVEMENTFLAG_SPLINE_ELEVATION: u32 = 0x0400_0000;
const MOVEMENTFLAG_SPLINE_ENABLED: u32 = 0x0800_0000;

// Extra flags (subset; see gateway-proxy `wotlk::movement`).
const MOVEMENTFLAG2_ALWAYS_ALLOW_PITCHING: u16 = 0x0020;
const MOVEMENTFLAG2_INTERPOLATED_MOVEMENT: u16 = 0x0400;

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
        let mut cur = Cursor::new(payload);
        let block_count = cur.read_u32::<LittleEndian>()?;

        for _ in 0..block_count {
            let update_type = cur.read_u8()?;
            match update_type {
                UPDATETYPE_OUT_OF_RANGE_OBJECTS => {
                    let n = cur.read_u32::<LittleEndian>()?;
                    for _ in 0..n {
                        let guid = read_packed_guid(&mut cur)?;
                        self.players.remove(&guid);
                        self.other_players.remove(&guid);
                        self.npcs.remove(&guid);
                    }
                }
                UPDATETYPE_CREATE_OBJECT | UPDATETYPE_CREATE_OBJECT2 => {
                    let guid = read_packed_guid(&mut cur)?;
                    let type_id = cur.read_u8()?;
                    let movement = parse_movement_update(&mut cur)?;
                    let (mask, values, entry_opt) = parse_values_update(&mut cur)?;

                    match type_id {
                        TYPEID_PLAYER => {
                            let player = self
                                .players
                                .entry(guid)
                                .or_insert_with(|| PlayerCurrentState::new(guid));
                            if let Some(mv) = movement {
                                player.update_position(
                                    mv.pos,
                                    mv.movement_flags,
                                    mv.timestamp as u64,
                                );
                                player.speed_walk = mv.speed_walk;
                                player.speed_run = mv.speed_run;
                                player.speed_swim = mv.speed_swim;
                                player.speed_turn = mv.speed_turn;
                            }
                            apply_player_fields(player, &mask, &values);
                        }
                        TYPEID_UNIT => {
                            let entry = entry_opt.unwrap_or(0);
                            let npc = self
                                .npcs
                                .entry(guid)
                                .or_insert_with(|| NpcCurrentState::new(guid, entry));
                            if npc.entry == 0 {
                                npc.entry = entry;
                            }
                            if let Some(mv) = movement {
                                npc.position = mv.pos;
                                npc.movement_flags = mv.movement_flags;
                                npc.timestamp = mv.timestamp as u64;
                            }
                            npc.set_fields(&mask, &values);
                        }
                        _ => {
                            // Treat all non-player types as "NPC-like" for now so observation/goal
                            // logic can navigate to them. This includes gameobjects (TYPEID_GAMEOBJECT=5),
                            // dynamic objects, corpses, etc.
                            let entry = entry_opt.unwrap_or(0);
                            let npc = self
                                .npcs
                                .entry(guid)
                                .or_insert_with(|| NpcCurrentState::new(guid, entry));
                            if npc.entry == 0 {
                                npc.entry = entry;
                            }
                            if let Some(mv) = movement {
                                npc.position = mv.pos;
                                npc.movement_flags = mv.movement_flags;
                                npc.timestamp = mv.timestamp as u64;
                            }
                            npc.set_fields(&mask, &values);
                        }
                    }
                }
                UPDATETYPE_VALUES => {
                    let guid = read_packed_guid(&mut cur)?;
                    let (mask, values, entry_opt) = parse_values_update(&mut cur)?;

                    if let Some(player) = self.players.get_mut(&guid) {
                        apply_player_fields(player, &mask, &values);
                    } else if let Some(npc) = self.npcs.get_mut(&guid) {
                        if let Some(entry) = entry_opt {
                            npc.entry = entry;
                        }
                        npc.set_fields(&mask, &values);
                    } else if let Some(other) = self.other_players.get_mut(&guid) {
                        other.set_fields(&mask, &values);
                    } else {
                        // Unknown object; ignore. We'll learn about its type on a create update.
                    }
                }
                UPDATETYPE_MOVEMENT => {
                    let guid = read_packed_guid(&mut cur)?;
                    let movement = parse_movement_update(&mut cur)?;
                    if let Some(mv) = movement {
                        if let Some(player) = self.players.get_mut(&guid) {
                            player.update_position(mv.pos, mv.movement_flags, mv.timestamp as u64);
                            player.speed_walk = mv.speed_walk;
                            player.speed_run = mv.speed_run;
                            player.speed_swim = mv.speed_swim;
                            player.speed_turn = mv.speed_turn;
                        } else if let Some(npc) = self.npcs.get_mut(&guid) {
                            npc.position = mv.pos;
                            npc.movement_flags = mv.movement_flags;
                            npc.timestamp = mv.timestamp as u64;
                        } else if let Some(other) = self.other_players.get_mut(&guid) {
                            other.position = mv.pos;
                            other.movement_flags = mv.movement_flags;
                            other.timestamp = mv.timestamp as u64;
                        }
                    }
                }
                _ => {
                    // Unknown/unsupported update type. Bail to avoid desyncing the cursor.
                    anyhow::bail!("unsupported SMSG_UPDATE_OBJECT update_type={update_type}");
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ParsedMovement {
    pos: crate::player::player_state::Position,
    movement_flags: u32,
    timestamp: u32,
    speed_walk: f32,
    speed_run: f32,
    speed_swim: f32,
    speed_turn: f32,
}

fn read_packed_guid(cur: &mut Cursor<&[u8]>) -> Result<u64> {
    let mask = cur.read_u8()?;
    if mask == 0 {
        return Ok(0);
    }
    let mut guid: u64 = 0;
    for i in 0..8 {
        if (mask & (1 << i)) != 0 {
            let b = cur.read_u8()? as u64;
            guid |= b << (i * 8);
        }
    }
    Ok(guid)
}

fn parse_values_update(cur: &mut Cursor<&[u8]>) -> Result<(Vec<u32>, Vec<u32>, Option<u32>)> {
    let mask_count = cur.read_u8()? as usize;
    let mut field_mask = Vec::with_capacity(mask_count);
    for _ in 0..mask_count {
        field_mask.push(cur.read_u32::<LittleEndian>()?);
    }

    let mut entry: Option<u32> = None;
    let mut values = Vec::new();
    for (block_index, &mask) in field_mask.iter().enumerate() {
        for bit_index in 0..32u32 {
            if (mask & (1 << bit_index)) != 0 {
                let field_id = block_index as u32 * 32 + bit_index;
                let value = cur.read_u32::<LittleEndian>()?;
                if field_id == OBJECT_FIELD_ENTRY {
                    entry = Some(value);
                }
                values.push(value);
            }
        }
    }

    Ok((field_mask, values, entry))
}

fn parse_movement_update(cur: &mut Cursor<&[u8]>) -> Result<Option<ParsedMovement>> {
    let update_flags = cur.read_u16::<LittleEndian>()?;

    // We only need position/timestamp for visibility and simple navigation goals.
    if (update_flags & UPDATEFLAG_LIVING) != 0 {
        let movement_flags = cur.read_u32::<LittleEndian>()?;
        let movement_extra_flags = cur.read_u16::<LittleEndian>()?;
        let timestamp = cur.read_u32::<LittleEndian>()?;
        let x = cur.read_f32::<LittleEndian>()?;
        let y = cur.read_f32::<LittleEndian>()?;
        let z = cur.read_f32::<LittleEndian>()?;
        let o = cur.read_f32::<LittleEndian>()?;

        if (movement_flags & MOVEMENTFLAG_ONTRANSPORT) != 0 {
            let _transport_guid = read_packed_guid(cur)?;
            let _ = cur.read_f32::<LittleEndian>()?;
            let _ = cur.read_f32::<LittleEndian>()?;
            let _ = cur.read_f32::<LittleEndian>()?;
            let _ = cur.read_f32::<LittleEndian>()?;
            let _ = cur.read_u32::<LittleEndian>()?;
            let _ = cur.read_u8()?;
            if (movement_extra_flags & MOVEMENTFLAG2_INTERPOLATED_MOVEMENT) != 0 {
                let _ = cur.read_u32::<LittleEndian>()?;
            }
        }

        if (movement_flags & (MOVEMENTFLAG_SWIMMING | MOVEMENTFLAG_FLYING)) != 0
            || (movement_extra_flags & MOVEMENTFLAG2_ALWAYS_ALLOW_PITCHING) != 0
        {
            let _pitch = cur.read_f32::<LittleEndian>()?;
        }

        let _fall_time = cur.read_u32::<LittleEndian>()?;

        if (movement_flags & MOVEMENTFLAG_JUMPING) != 0 {
            let _ = cur.read_f32::<LittleEndian>()?;
            let _ = cur.read_f32::<LittleEndian>()?;
            let _ = cur.read_f32::<LittleEndian>()?;
            let _ = cur.read_f32::<LittleEndian>()?;
        }

        if (movement_flags & MOVEMENTFLAG_SPLINE_ELEVATION) != 0 {
            let _ = cur.read_f32::<LittleEndian>()?;
        }

        // Speeds follow `BuildMovementPacket` in `Object::BuildMovementUpdate` for living units.
        let speed_walk = cur.read_f32::<LittleEndian>()?;
        let speed_run = cur.read_f32::<LittleEndian>()?;
        let _speed_run_back = cur.read_f32::<LittleEndian>()?;
        let speed_swim = cur.read_f32::<LittleEndian>()?;
        let _speed_swim_back = cur.read_f32::<LittleEndian>()?;
        let _speed_flight = cur.read_f32::<LittleEndian>()?;
        let _speed_flight_back = cur.read_f32::<LittleEndian>()?;
        let speed_turn = cur.read_f32::<LittleEndian>()?;
        let _speed_pitch = cur.read_f32::<LittleEndian>()?;

        if (movement_flags & MOVEMENTFLAG_SPLINE_ENABLED) != 0 {
            skip_movespline_create(cur)?;
        }

        consume_movement_extras(cur, update_flags)?;

        Ok(Some(ParsedMovement {
            pos: crate::player::player_state::Position {
                x,
                y,
                z,
                orientation: o,
            },
            movement_flags,
            timestamp,
            speed_walk,
            speed_run,
            speed_swim,
            speed_turn,
        }))
    } else if (update_flags & UPDATEFLAG_POSITION) != 0 {
        // For non-living position updates, we only consume enough bytes to keep the cursor aligned.
        // Format (AzerothCore `Object::BuildMovementUpdate`):
        // - packed transport guid or 0
        // - x,y,z
        // - (trans offsets if on transport else repeats x,y,z)
        // - o
        // - corpse-o or 0f
        let _transport = read_packed_guid(cur)?;
        let x = cur.read_f32::<LittleEndian>()?;
        let y = cur.read_f32::<LittleEndian>()?;
        let z = cur.read_f32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;
        let o = cur.read_f32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;

        consume_movement_extras(cur, update_flags)?;

        Ok(Some(ParsedMovement {
            pos: crate::player::player_state::Position {
                x,
                y,
                z,
                orientation: o,
            },
            movement_flags: 0,
            timestamp: 0,
            speed_walk: 0.0,
            speed_run: 0.0,
            speed_swim: 0.0,
            speed_turn: 0.0,
        }))
    } else if (update_flags & UPDATEFLAG_STATIONARY_POSITION) != 0 {
        let x = cur.read_f32::<LittleEndian>()?;
        let y = cur.read_f32::<LittleEndian>()?;
        let z = cur.read_f32::<LittleEndian>()?;
        let o = cur.read_f32::<LittleEndian>()?;

        consume_movement_extras(cur, update_flags)?;

        Ok(Some(ParsedMovement {
            pos: crate::player::player_state::Position {
                x,
                y,
                z,
                orientation: o,
            },
            movement_flags: 0,
            timestamp: 0,
            speed_walk: 0.0,
            speed_run: 0.0,
            speed_swim: 0.0,
            speed_turn: 0.0,
        }))
    } else {
        consume_movement_extras(cur, update_flags)?;
        Ok(None)
    }
}

fn consume_movement_extras(cur: &mut Cursor<&[u8]>, update_flags: u16) -> Result<()> {
    // Extra data is appended in this exact order (AzerothCore `Object::BuildMovementUpdate`).
    if (update_flags & UPDATEFLAG_UNKNOWN) != 0 {
        let _ = cur.read_u32::<LittleEndian>()?;
    }
    if (update_flags & UPDATEFLAG_LOWGUID) != 0 {
        let _ = cur.read_u32::<LittleEndian>()?;
    }
    if (update_flags & UPDATEFLAG_HAS_TARGET) != 0 {
        let _ = read_packed_guid(cur)?;
    }
    if (update_flags & UPDATEFLAG_TRANSPORT) != 0 {
        let _ = cur.read_u32::<LittleEndian>()?;
    }
    if (update_flags & UPDATEFLAG_VEHICLE) != 0 {
        let _ = cur.read_u32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;
    }
    if (update_flags & UPDATEFLAG_ROTATION) != 0 {
        let _ = cur.read_i64::<LittleEndian>()?;
    }
    Ok(())
}

fn skip_movespline_create(cur: &mut Cursor<&[u8]>) -> Result<()> {
    // Matches AzerothCore `Movement::PacketBuilder::WriteCreate`.
    // We don't interpret it; we only consume bytes to keep the cursor aligned.
    let flags_raw = cur.read_u32::<LittleEndian>()?;

    // Facing info is mutually exclusive; see `MoveSplineFlag::Mask_Final_Facing`.
    // Final_Point: 3 floats; Final_Target: u64 raw guid; Final_Angle: f32.
    const FINAL_POINT: u32 = 0x0000_8000;
    const FINAL_TARGET: u32 = 0x0001_0000;
    const FINAL_ANGLE: u32 = 0x0002_0000;

    if (flags_raw & FINAL_ANGLE) != 0 {
        let _ = cur.read_f32::<LittleEndian>()?;
    } else if (flags_raw & FINAL_TARGET) != 0 {
        let _ = cur.read_u64::<LittleEndian>()?;
    } else if (flags_raw & FINAL_POINT) != 0 {
        let _ = cur.read_f32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;
    }

    // timePassed, duration, id
    let _ = cur.read_u32::<LittleEndian>()?;
    let _ = cur.read_u32::<LittleEndian>()?;
    let _ = cur.read_u32::<LittleEndian>()?;

    // duration_mod, duration_mod_next, vertical_acceleration
    let _ = cur.read_f32::<LittleEndian>()?;
    let _ = cur.read_f32::<LittleEndian>()?;
    let _ = cur.read_f32::<LittleEndian>()?;

    // effect_start_time
    let _ = cur.read_u32::<LittleEndian>()?;

    let nodes = cur.read_u32::<LittleEndian>()? as usize;
    for _ in 0..nodes {
        let _ = cur.read_f32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;
        let _ = cur.read_f32::<LittleEndian>()?;
    }

    let _ = cur.read_u8()?;

    let _ = cur.read_f32::<LittleEndian>()?;
    let _ = cur.read_f32::<LittleEndian>()?;
    let _ = cur.read_f32::<LittleEndian>()?;

    Ok(())
}

fn apply_player_fields(player: &mut PlayerCurrentState, field_mask: &[u32], values: &[u32]) {
    let mut index = 0usize;
    for (block_index, &mask) in field_mask.iter().enumerate() {
        for bit_index in 0..32u32 {
            if (mask & (1 << bit_index)) != 0 {
                let field_id = block_index as u32 * 32 + bit_index;
                let value = values.get(index).copied().unwrap_or(0);
                match field_id {
                    UNIT_FIELD_HEALTH => player.health = value,
                    UNIT_FIELD_MAXHEALTH => player.max_health = value,
                    UNIT_FIELD_POWER_TYPE => player.power_type = PowerType::from(value as u8),
                    UNIT_FIELD_POWER => player.power = value,
                    UNIT_FIELD_LEVEL => player.level = value as u8,
                    UNIT_FIELD_FLAGS => player.flags = value,

                    PLAYER_VISIBLE_ITEM_0_ENTRYID..=PLAYER_VISIBLE_ITEM_18_ENTRYID => {
                        let slot =
                            (field_id - PLAYER_VISIBLE_ITEM_0_ENTRYID) / VISIBLE_ITEM_ENTRY_SPACING;
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

                    _ => player.set_dynamic_field(field_id, value.to_le_bytes().to_vec()),
                }
                index += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s = s.trim();
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn update_object_empty_ok() {
        let mut ws = WorldState::new();
        ws.apply_update_object(&hex("00000000")).unwrap();
        assert!(ws.players.is_empty());
        assert!(ws.other_players.is_empty());
        assert!(ws.npcs.is_empty());
    }

    #[test]
    fn update_object_out_of_range_removes() {
        // From a real dump (AzerothCore): one update block with 4 out-of-range packed guids.
        let payload =
            hex("010000000404000000db980a8f0530f1db760b730330f1dbc80b7a0330f1dbf00a8d0730f1");

        // Decode the expected GUIDs to seed the state.
        let mut cur = Cursor::new(payload.as_slice());
        let blocks = cur.read_u32::<LittleEndian>().unwrap();
        assert_eq!(blocks, 1);
        let typ = cur.read_u8().unwrap();
        assert_eq!(typ, UPDATETYPE_OUT_OF_RANGE_OBJECTS);
        let n = cur.read_u32::<LittleEndian>().unwrap();
        assert_eq!(n, 4);
        let guids: Vec<u64> = (0..n)
            .map(|_| read_packed_guid(&mut cur).unwrap())
            .collect();
        assert!(guids.iter().all(|g| *g != 0));

        let mut ws = WorldState::new();
        for (i, guid) in guids.iter().copied().enumerate() {
            match i % 3 {
                0 => {
                    ws.players.insert(guid, PlayerCurrentState::new(guid));
                }
                1 => {
                    ws.other_players.insert(guid, OtherPlayerState::new(guid));
                }
                _ => {
                    ws.npcs.insert(guid, NpcCurrentState::new(guid, 1));
                }
            }
        }

        ws.apply_update_object(&payload).unwrap();
        for guid in guids {
            assert!(!ws.players.contains_key(&guid));
            assert!(!ws.other_players.contains_key(&guid));
            assert!(!ws.npcs.contains_key(&guid));
        }
    }

    #[test]
    fn update_object_create_object_sets_npc_entry_and_position() {
        // Synthetic create packet for a unit (TYPEID_UNIT), with living movement and a values
        // update containing OBJECT_FIELD_ENTRY.
        let guid: u64 = 0x1122_3344_5566_7788;
        let entry: u32 = 12345;

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // 1 block
        payload.push(UPDATETYPE_CREATE_OBJECT);

        // Packed guid: mask=0xFF plus bytes in little-endian order.
        payload.push(0xFF);
        payload.extend_from_slice(&guid.to_le_bytes());

        payload.push(TYPEID_UNIT);

        // Movement update flags: living.
        payload.extend_from_slice(&UPDATEFLAG_LIVING.to_le_bytes());
        // Unit::BuildMovementPacket fields.
        payload.extend_from_slice(&0u32.to_le_bytes()); // movement_flags
        payload.extend_from_slice(&0u16.to_le_bytes()); // movement_extra_flags
        payload.extend_from_slice(&123u32.to_le_bytes()); // time
        payload.extend_from_slice(&1.0f32.to_le_bytes()); // x
        payload.extend_from_slice(&2.0f32.to_le_bytes()); // y
        payload.extend_from_slice(&3.0f32.to_le_bytes()); // z
        payload.extend_from_slice(&4.0f32.to_le_bytes()); // o
        payload.extend_from_slice(&0u32.to_le_bytes()); // fall_time

        // Speeds (9 floats) following movement packet.
        for _ in 0..9 {
            payload.extend_from_slice(&0.0f32.to_le_bytes());
        }

        // Values update: 1 mask block, bit 3 set.
        payload.push(1u8); // mask block count
        payload.extend_from_slice(&8u32.to_le_bytes()); // mask
        payload.extend_from_slice(&entry.to_le_bytes()); // value for field 3

        let mut ws = WorldState::new();
        ws.apply_update_object(&payload).unwrap();

        let npc = ws.npcs.get(&guid).expect("npc inserted");
        assert_eq!(npc.entry, entry);
        assert_eq!(npc.position.x, 1.0);
        assert_eq!(npc.position.y, 2.0);
        assert_eq!(npc.position.z, 3.0);
        assert_eq!(npc.position.orientation, 4.0);
    }

    #[test]
    fn update_object_values_update_parses_real_dump_without_guid_zero() {
        // Real dump from user: 1 update block, UPDATETYPE_VALUES, packed guid + mask+values.
        let payload = hex(
            "0100000000db980a8f0530f10500000c0000000008008004000000000000000000e10a000d020030f1008008000000000001000000",
        );
        let mut ws = WorldState::new();
        // Seed an object so the VALUES update applies somewhere (type not encoded in VALUES).
        ws.other_players.insert(
            0xf13000058f000a98,
            OtherPlayerState::new(0xf13000058f000a98),
        );
        ws.apply_update_object(&payload).unwrap();
        assert!(!ws.other_players.contains_key(&0));
    }

    #[test]
    fn update_object_create_gameobject_stationary_with_extras_parses() {
        // Real dump from user: create object (TYPEID_GAMEOBJECT=5) with stationary position
        // plus extra updateflag data (transport + lowguid + rotation).
        let payload = hex(
            "0100000002c111c01f055202ae4e04c66439cf440000000061fdc03f1100000092d8cf040000000000000000011f630300110000000000c01f2100000048e802000000803f161d0000280000000000803f0000dafecb250400010f00ff",
        );
        let mut ws = WorldState::new();
        ws.apply_update_object(&payload).unwrap();
        // TYPEID_GAMEOBJECT should be routed to npcs (NPC-like) so observation isn't misleading.
        assert_eq!(ws.npcs.len(), 1);
        assert!(ws.other_players.is_empty());
    }
}
