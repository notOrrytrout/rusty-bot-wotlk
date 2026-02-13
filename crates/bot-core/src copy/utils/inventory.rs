// utils/inventory.rs

use crate::player::inventory::Inventory;

pub fn inventory_slot_name(slot: u8) -> &'static str {
    match slot {
        0 => "Backpack Slot 0",
        1 => "Backpack Slot 1",
        2 => "Backpack Slot 2",
        3 => "Backpack Slot 3",
        4 => "Bag 1",
        5 => "Bag 2",
        6 => "Bag 3",
        _ => "Unknown Slot",
    }
}

pub fn find_item_by_id(inventory: &Inventory, item_id: u32) -> Option<u8> {
    inventory
        .iter()
        .find(|item| item.item_entry == item_id)
        .map(|item| item.bag_index)
}
