
pub fn slot_name(slot: u8) -> &'static str {
    match slot {
        0 => "Head",
        1 => "Neck",
        2 => "Shoulder",
        3 => "Shirt",
        4 => "Chest",
        5 => "Waist",
        6 => "Legs",
        7 => "Feet",
        8 => "Wrist",
        9 => "Hands",
        10 => "Finger 1",
        11 => "Finger 2",
        12 => "Trinket 1",
        13 => "Trinket 2",
        14 => "Back",
        15 => "Main Hand",
        16 => "Off Hand",
        17 => "Ranged",
        18 => "Tabard",
        _ => "Unknown",
    }
}
