use std::fmt;

pub const UNIT_FIELD_HEALTH: u32 = 0x0006;
pub const UNIT_FIELD_MAXHEALTH: u32 = 0x0007;
pub const UNIT_FIELD_POWER_TYPE: u32 = 0x0008;
pub const UNIT_FIELD_POWER: u32 = 0x0009;
pub const UNIT_FIELD_LEVEL: u32 = 0x0030;
pub const UNIT_FIELD_FLAGS: u32 = 0x0035;
pub const VISIBLE_ITEM_ENTRY_SPACING: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Race {
    Human = 1,
    Orc = 2,
    Dwarf = 3,
    NightElf = 4,
    Undead = 5,
    Tauren = 6,
    Gnome = 7,
    Troll = 8,
    Goblin = 9,
    BloodElf = 10,
    Draenei = 11,
    Worgen = 22,
    Pandaren = 24,
    Unknown,
}

impl Race {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Race::Human,
            2 => Race::Orc,
            3 => Race::Dwarf,
            4 => Race::NightElf,
            5 => Race::Undead,
            6 => Race::Tauren,
            7 => Race::Gnome,
            8 => Race::Troll,
            9 => Race::Goblin,
            10 => Race::BloodElf,
            11 => Race::Draenei,
            22 => Race::Worgen,
            24 => Race::Pandaren,
            _ => Race::Unknown,
        }
    }
}

impl fmt::Display for Race {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Warrior = 1,
    Paladin = 2,
    Hunter = 3,
    Rogue = 4,
    Priest = 5,
    DeathKnight = 6,
    Shaman = 7,
    Mage = 8,
    Warlock = 9,
    Monk = 10,
    Druid = 11,
    DemonHunter = 12,
    Unknown,
}

impl Class {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Class::Warrior,
            2 => Class::Paladin,
            3 => Class::Hunter,
            4 => Class::Rogue,
            5 => Class::Priest,
            6 => Class::DeathKnight,
            7 => Class::Shaman,
            8 => Class::Mage,
            9 => Class::Warlock,
            10 => Class::Monk,
            11 => Class::Druid,
            12 => Class::DemonHunter,
            _ => Class::Unknown,
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gender {
    Male = 0,
    Female = 1,
    NonBinary = 2,
    Unknown,
}

impl Gender {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Gender::Male,
            1 => Gender::Female,
            2 => Gender::NonBinary,
            _ => Gender::Unknown,
        }
    }
}

impl fmt::Display for Gender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
