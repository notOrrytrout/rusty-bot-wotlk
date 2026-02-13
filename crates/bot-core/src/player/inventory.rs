#[derive(Debug, Clone)]
pub struct InventoryItem {
    pub bag_index: u8,
    pub item_entry: u32,
}

pub type Inventory = Vec<InventoryItem>;
