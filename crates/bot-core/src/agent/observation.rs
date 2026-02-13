use serde::{Deserialize, Serialize};

use crate::world::world_state::WorldState;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EntitySummary {
    pub guid: u64,
    #[serde(default)]
    pub entry: Option<u32>,
    pub pos: Vec3,
    #[serde(default)]
    pub hp: Option<(u32, u32)>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SelfSummary {
    pub guid: u64,
    pub pos: Vec3,
    pub orient: f32,
    pub hp: (u32, u32),
    pub level: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Observation {
    pub tick: u64,
    pub self_state: Option<SelfSummary>,
    #[serde(default)]
    pub npcs_nearby: Vec<EntitySummary>,
    #[serde(default)]
    pub players_nearby: Vec<EntitySummary>,
    #[serde(default)]
    pub chat_log: Vec<String>,
    #[serde(default)]
    pub combat_log: Vec<String>,
}

fn dist_sq(a: &Vec3, b: &Vec3) -> f32 {
    let dx = a.x - b.x;
    let dy = a.y - b.y;
    let dz = a.z - b.z;
    dx * dx + dy * dy + dz * dz
}

impl Observation {
    pub fn from_world(world: &WorldState, self_guid: u64) -> Self {
        let tick = world.tick.0;

        let self_state = world.players.get(&self_guid).map(|p| SelfSummary {
            guid: self_guid,
            pos: Vec3 {
                x: p.position.x,
                y: p.position.y,
                z: p.position.z,
            },
            orient: p.position.orientation,
            hp: (p.health, p.max_health),
            level: p.level,
        });

        let self_pos = self_state.as_ref().map(|s| s.pos);

        let mut npcs: Vec<EntitySummary> = world
            .npcs
            .values()
            .map(|n| EntitySummary {
                guid: n.guid,
                entry: Some(n.entry),
                pos: Vec3 {
                    x: n.position.x,
                    y: n.position.y,
                    z: n.position.z,
                },
                hp: Some((n.health, n.max_health)),
            })
            .collect();

        let mut others: Vec<EntitySummary> = world
            .other_players
            .iter()
            .map(|(guid, p)| EntitySummary {
                guid: *guid,
                entry: None,
                pos: Vec3 {
                    x: p.position.x,
                    y: p.position.y,
                    z: p.position.z,
                },
                hp: Some((p.health, p.max_health)),
            })
            .collect();

        if let Some(self_pos) = self_pos.as_ref() {
            npcs.sort_by(|a, b| {
                dist_sq(&a.pos, self_pos)
                    .partial_cmp(&dist_sq(&b.pos, self_pos))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            others.sort_by(|a, b| {
                dist_sq(&a.pos, self_pos)
                    .partial_cmp(&dist_sq(&b.pos, self_pos))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        // Hard caps to keep prompts stable.
        npcs.truncate(24);
        others.truncate(24);

        Self {
            tick,
            self_state,
            npcs_nearby: npcs,
            players_nearby: others,
            chat_log: world.chat_log.iter().cloned().take(10).collect(),
            combat_log: world.combat_log.iter().cloned().take(10).collect(),
        }
    }
}

