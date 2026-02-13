use std::collections::HashMap;

use crate::player::player_state::Position;

#[derive(Debug, Clone)]
pub struct NpcCurrentState {
    pub guid: u64,
    pub entry: u32,
    pub position: Position,
    pub movement_flags: u32,
    pub timestamp: u64,
    pub health: u32,
    pub max_health: u32,
    pub flags: u32,
    pub auras: Vec<u32>,
    pub dynamic_fields: HashMap<u32, Vec<u8>>,
}

impl NpcCurrentState {
    pub fn new(guid: u64, entry: u32) -> Self {
        Self {
            guid,
            entry,
            position: Position::default(),
            movement_flags: 0,
            timestamp: 0,
            health: 0,
            max_health: 0,
            flags: 0,
            auras: vec![],
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
