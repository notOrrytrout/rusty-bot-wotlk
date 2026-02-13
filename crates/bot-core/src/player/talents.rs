#[derive(Debug, Clone)]
pub struct Talent {
    pub tab: u8,
    pub talent_id: u32,
}

pub type Talents = Vec<Talent>;
