// utils/talents.rs

use crate::player::talents::Talents;

pub fn render_talent_summary(talents: &Talents) -> String {
    if talents.is_empty() {
        return "No talents selected.".to_string();
    }

    let mut lines = Vec::new();
    for t in talents {
        lines.push(format!("Talent tab {} → id {}", t.tab, t.talent_id));
    }

    lines.join(", ")
}
