use serde::{Deserialize, Serialize};

use crate::world::world_state::WorldState;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct DerivedFacts {
    /// True if the current movement flags are non-zero.
    pub moving: bool,
    /// Change in position since the last observation frame (if available).
    #[serde(default)]
    pub self_pos_delta: Option<Vec3>,
    /// Euclidean distance moved since the last observation frame (if available).
    #[serde(default)]
    pub self_dist_moved: Option<f32>,
    /// Change in orientation since the last observation frame (if available).
    #[serde(default)]
    pub self_orient_delta: Option<f32>,
    /// Absolute orientation delta since the last observation frame (if available).
    #[serde(default)]
    pub self_abs_orient_delta: Option<f32>,
    /// Change in the client movement timestamp (if available).
    #[serde(default)]
    pub self_movement_time_delta: Option<i64>,
    /// Placeholder for higher level stuck detection (executor will set this later).
    #[serde(default)]
    pub stuck_suspected: bool,
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
    pub movement_flags: u32,
    pub movement_time: u64,
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
    #[serde(default)]
    pub derived: DerivedFacts,
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
            movement_flags: p.movement_flags,
            movement_time: p.timestamp,
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
            derived: DerivedFacts::default(),
        }
    }
}

#[derive(Debug, Default)]
pub struct ObservationBuilder {
    last_self_pos: Option<Vec3>,
    last_orient: Option<f32>,
    last_movement_time: Option<u64>,
}

impl ObservationBuilder {
    pub fn build(&mut self, world: &WorldState, self_guid: u64) -> Observation {
        let mut obs = Observation::from_world(world, self_guid);

        if let Some(self_state) = obs.self_state.as_ref() {
            obs.derived.moving = self_state.movement_flags != 0;

            if let Some(prev_pos) = self.last_self_pos {
                let delta = Vec3 {
                    x: self_state.pos.x - prev_pos.x,
                    y: self_state.pos.y - prev_pos.y,
                    z: self_state.pos.z - prev_pos.z,
                };
                let dist = (delta.x * delta.x + delta.y * delta.y + delta.z * delta.z).sqrt();
                obs.derived.self_pos_delta = Some(delta);
                obs.derived.self_dist_moved = Some(dist);
            }

            if let Some(prev_time) = self.last_movement_time {
                obs.derived.self_movement_time_delta =
                    Some(self_state.movement_time as i64 - prev_time as i64);
            }

            if let Some(prev_orient) = self.last_orient {
                let mut delta = self_state.orient - prev_orient;
                // Wrap to [-pi, pi] to avoid discontinuity when crossing 2*pi.
                const PI: f32 = std::f32::consts::PI;
                if delta > PI {
                    delta -= 2.0 * PI;
                } else if delta < -PI {
                    delta += 2.0 * PI;
                }
                obs.derived.self_orient_delta = Some(delta);
                obs.derived.self_abs_orient_delta = Some(delta.abs());
            }

            self.last_self_pos = Some(self_state.pos);
            self.last_orient = Some(self_state.orient);
            self.last_movement_time = Some(self_state.movement_time);
        } else {
            self.last_self_pos = None;
            self.last_orient = None;
            self.last_movement_time = None;
        }

        obs
    }
}
