#[derive(Debug, Clone, PartialEq)]
pub struct KnownSpell {
    pub id: u32,
    pub name: Option<String>,
}

pub type Spells = Vec<KnownSpell>;

impl PartialEq<u32> for KnownSpell {
    fn eq(&self, other: &u32) -> bool {
        self.id == *other
    }
}
