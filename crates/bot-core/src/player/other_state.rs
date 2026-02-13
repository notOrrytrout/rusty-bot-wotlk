use std::collections::HashMap;

use super::player_state::{Position, PowerType};

#[derive(Debug, Clone)]
pub struct OtherPlayerState {
    pub guid: u64,
    pub position: Position,
    pub movement_flags: u32,
    pub timestamp: u64,
    pub health: u32,
    pub max_health: u32,
    pub power_type: PowerType,
    pub power: u32,
    pub level: u8,
    pub race: u8,
    pub class: u8,
    pub gender: u8,
    pub auras: Vec<u32>,
    pub flags: u32,
    pub dynamic_fields: HashMap<u32, Vec<u8>>,
}

impl OtherPlayerState {
    pub fn new(guid: u64) -> Self {
        Self {
            guid,
            position: Position::default(),
            movement_flags: 0,
            timestamp: 0,
            health: 0,
            max_health: 0,
            power_type: PowerType::Unknown(0),
            power: 0,
            level: 0,
            race: 0,
            class: 0,
            gender: 0,
            auras: vec![],
            flags: 0,
            dynamic_fields: HashMap::new(),
        }
    }

    pub fn set_fields(&mut self, mask: &[u32], values: &[u32]) {
        self.dynamic_fields.clear();
        let mut index = 0;
        for (block, &bits) in mask.iter().enumerate() {
            for bit in 0..32 {
                if bits & (1 << bit) != 0 {
                    let field_id = (block * 32 + bit) as u32;
                    let value = values.get(index).copied().unwrap_or(0);
                    match field_id {
                        0x10 => self.health = value,
                        0x11 => self.max_health = value,
                        0x18 => self.power_type = PowerType::from(value as u8),
                        0x19 => self.power = value,
                        0x20 => self.level = value as u8,
                        0x2A => self.flags = value,
                        _ => {
                            self.dynamic_fields
                                .insert(field_id, value.to_le_bytes().to_vec());
                        }
                    }
                    index += 1;
                }
            }
        }
    }
}
