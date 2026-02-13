#[derive(Debug, Clone)]
pub struct EquippedItem {
    pub slot: u8,
    pub item_entry: u32,
}

pub type Equipment = Vec<EquippedItem>;
