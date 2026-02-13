use std::collections::HashMap;

use crate::player::equipment::Equipment;
use crate::player::inventory::Inventory;
use crate::player::spells::KnownSpell;
use crate::player::talents::Talents;

use super::spells::Spells;

#[derive(Debug, Clone, Default)]
pub struct Position {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub orientation: f32,
}

#[derive(Debug, Clone)]
pub enum PowerType {
    Mana,
    Rage,
    Focus,
    Energy,
    ComboPoints,
    RunicPower,
    SoulShards,
    LunarPower,
    HolyPower,
    Alternate,
    Psi,
    Chi,
    Unknown(u8),
}

impl From<u8> for PowerType {
    fn from(val: u8) -> Self {
        match val {
            0 => PowerType::Mana,
            1 => PowerType::Rage,
            2 => PowerType::Focus,
            3 => PowerType::Energy,
            4 => PowerType::ComboPoints,
            5 => PowerType::RunicPower,
            6 => PowerType::SoulShards,
            7 => PowerType::LunarPower,
            8 => PowerType::HolyPower,
            9 => PowerType::Alternate,
            10 => PowerType::Psi,
            11 => PowerType::Chi,
            other => PowerType::Unknown(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlayerCurrentState {
    pub guid: u64,
    pub position: Position,
    pub movement_flags: u32,
    pub timestamp: u64,
    pub speed_run: f32,
    pub speed_walk: f32,
    pub speed_swim: f32,
    pub speed_turn: f32,
    pub health: u32,
    pub max_health: u32,
    pub power_type: PowerType,
    pub power: u32,
    pub level: u8,
    pub race: u8,
    pub class: u8,
    pub gender: u8,
    pub map_id: u32,
    pub zone_id: u32,
    pub auras: Vec<u32>,
    pub flags: u32,
    pub dynamic_fields: HashMap<u32, Vec<u8>>,
    pub known_talents: Talents,
    pub inventory: Inventory,
    pub known_spells: Spells,
    pub equipment: Equipment,
}

impl PlayerCurrentState {
    pub fn new(guid: u64) -> Self {
        Self {
            guid,
            position: Position::default(),
            movement_flags: 0,
            timestamp: 0,
            speed_run: 0.0,
            speed_walk: 0.0,
            speed_swim: 0.0,
            speed_turn: 0.0,
            health: 0,
            max_health: 0,
            power_type: PowerType::Unknown(0),
            power: 0,
            level: 0,
            race: 0,
            class: 0,
            gender: 0,
            map_id: 0,
            zone_id: 0,
            auras: Vec::new(),
            flags: 0,
            dynamic_fields: HashMap::new(),
            known_talents: Vec::new(),
            inventory: Vec::new(),
            equipment: Vec::new(),
            known_spells: Vec::new(),
        }
    }

    pub fn update_spells(&mut self, spell_ids: Vec<u32>) {
        for id in spell_ids {
            if !self.known_spells.iter().any(|s| s.id == id) {
                self.known_spells.push(KnownSpell { id, name: None });
            }
        }
    }

    pub fn update_talents(&mut self, talents: Talents) {
        self.known_talents = talents;
    }

    pub fn update_inventory(&mut self, items: Inventory) {
        self.inventory = items;
    }

    pub fn update_equipment(&mut self, items: Equipment) {
        self.equipment = items;
    }

    pub fn update_health(&mut self, current: u32, max: u32) {
        self.health = current;
        self.max_health = max;
    }

    pub fn update_power(&mut self, power_type: PowerType, power: u32) {
        self.power_type = power_type;
        self.power = power;
    }

    pub fn update_position(&mut self, pos: Position, flags: u32, timestamp: u64) {
        self.position = pos;
        self.movement_flags = flags;
        self.timestamp = timestamp;
    }

    pub fn set_dynamic_field(&mut self, field_id: u32, data: Vec<u8>) {
        self.dynamic_fields.insert(field_id, data);
    }

    pub fn set_fields(&mut self, _mask: &[u32], values: &[u32]) {
        self.dynamic_fields.clear();
        for (i, &val) in values.iter().enumerate() {
            self.dynamic_fields
                .insert(i as u32, val.to_le_bytes().to_vec());
        }
    }
}
