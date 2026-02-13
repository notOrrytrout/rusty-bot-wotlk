// utils/spellbook.rs

use crate::player::spells::Spells;

pub fn find_spell_by_id(spells: &Spells, id: u32) -> Option<String> {
    spells
        .iter()
        .find(|s| s.id == id)
        .map(|s| s.name.clone().unwrap_or_else(|| format!("spell_{}", s.id)))
}

pub fn render_known_spells(spells: &Spells) -> Vec<String> {
    spells
        .iter()
        .map(|s| {
            if let Some(name) = &s.name {
                format!("{} (id: {})", name, s.id)
            } else {
                format!("spell_{}", s.id)
            }
        })
        .collect()
}
