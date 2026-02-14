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
    /// True if the player appears to be moving or turning based on movement flags.
    pub moving: bool,
    /// Best-effort combat indicator. V0 heuristic: true for a short window after combat-related
    /// server packets were observed and appended to `WorldState.combat_log`.
    #[serde(default)]
    pub in_combat: bool,
    /// True if we have observed the real client correcting an injected movement template recently.
    #[serde(default)]
    pub client_correction_seen_recently: bool,
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
    /// First-pass stuck detection: repeated translation movement with negligible position change.
    #[serde(default)]
    pub stuck_suspected: bool,
    /// Number of consecutive frames that looked like "trying to translate but not making progress".
    #[serde(default)]
    pub stuck_frames: u32,
    /// Best-effort reason string (short and stable) for why we suspect we're stuck.
    #[serde(default)]
    pub stuck_reason: Option<String>,
    /// Best-effort "who is attacking us" guid, if known.
    #[serde(default)]
    pub attacker_guid: Option<u64>,
    /// Spell ids currently on cooldown (capped) based on server observations.
    /// This is a prompt/debug aid; strategy code should consult cooldown maps directly when possible.
    #[serde(default)]
    pub spells_on_cooldown: Vec<u32>,
    /// Cooldowns with expiry ticks (capped), used by deterministic strategy selection.
    #[serde(default)]
    pub spell_cooldowns: Vec<SpellCooldownSummary>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SpellCooldownSummary {
    pub spell_id: u32,
    pub until_tick: u64,
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
    /// WoW class id (1..=11 for WotLK). Kept numeric to avoid baking protocol enums into prompts.
    pub class: u8,
    /// WoW race id.
    pub race: u8,
    pub gender: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Observation {
    pub tick: u64,
    /// Self GUID as tracked by the proxy (0 if unknown).
    #[serde(default)]
    pub self_guid: u64,
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
            class: p.class,
            race: p.race,
            gender: p.gender,
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
            self_guid,
            self_state,
            npcs_nearby: npcs,
            players_nearby: others,
            chat_log: world.chat_log.iter().take(10).cloned().collect(),
            combat_log: world.combat_log.iter().take(10).cloned().collect(),
            derived: DerivedFacts::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ObservationInputs {
    pub self_guid: u64,
    pub client_correction_seen_recently: bool,
}

#[derive(Debug, Default)]
pub struct ObservationBuilder {
    last_self_pos: Option<Vec3>,
    last_orient: Option<f32>,
    last_movement_time: Option<u64>,
    stuck_frames: u32,
    last_combat_log_len: usize,
    last_combat_tick: Option<u64>,
}

impl ObservationBuilder {
    pub fn build(&mut self, world: &WorldState, inputs: ObservationInputs) -> Observation {
        let mut obs = Observation::from_world(world, inputs.self_guid);
        obs.derived.client_correction_seen_recently = inputs.client_correction_seen_recently;

        // Combat heuristic: if combat log has grown recently, treat us as "in combat" for a short window.
        // This is intentionally crude until we have structured combat state from packets/auras.
        let combat_len = world.combat_log.len();
        if combat_len > self.last_combat_log_len {
            self.last_combat_tick = Some(world.tick.0);
        }
        self.last_combat_log_len = combat_len;

        const COMBAT_RECENT_TICKS: u64 = 50;
        obs.derived.in_combat = self
            .last_combat_tick
            .map(|t| world.tick.0.saturating_sub(t) <= COMBAT_RECENT_TICKS)
            .unwrap_or(false);

        // If we have a "last attacker" signal, treat that as combat too (more direct than log growth).
        if let (Some(att), Some(tick)) = (world.last_attacker_guid, world.last_attacked_tick)
            && world.tick.0.saturating_sub(tick) <= COMBAT_RECENT_TICKS
        {
            obs.derived.attacker_guid = Some(att);
            obs.derived.in_combat = true;
        }

        // Cooldown snapshot: list a capped set of spells currently on cooldown and their expiry ticks.
        let mut cds: Vec<SpellCooldownSummary> = world
            .spell_cooldowns_until_tick
            .iter()
            .filter_map(|(spell_id, until)| {
                if world.tick.0 < *until {
                    Some(SpellCooldownSummary {
                        spell_id: *spell_id,
                        until_tick: *until,
                    })
                } else {
                    None
                }
            })
            .collect();
        cds.sort_by_key(|c| c.spell_id);
        cds.truncate(64);
        obs.derived.spell_cooldowns = cds;
        obs.derived.spells_on_cooldown = obs
            .derived
            .spell_cooldowns
            .iter()
            .map(|c| c.spell_id)
            .take(32)
            .collect();

        if let Some(self_state) = obs.self_state.as_ref() {
            const MOVE_MASK: u32 =
                0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020;
            obs.derived.moving = (self_state.movement_flags & MOVE_MASK) != 0;

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

            // Stuck detection v0: if we're translating (not just turning) and time is advancing
            // but our position isn't changing, treat it as "stuck suspected".
            const TRANSLATE_MASK: u32 = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008;
            const STUCK_DIST_EPSILON: f32 = 0.05;
            const STUCK_FRAME_THRESHOLD: u32 = 6;
            let translating = (self_state.movement_flags & TRANSLATE_MASK) != 0;
            let time_advancing = obs
                .derived
                .self_movement_time_delta
                .map(|d| d != 0)
                .unwrap_or(false);
            let dist = obs.derived.self_dist_moved;
            if translating
                && time_advancing
                && dist.map(|d| d < STUCK_DIST_EPSILON).unwrap_or(false)
            {
                self.stuck_frames = self.stuck_frames.saturating_add(1);
            } else {
                self.stuck_frames = 0;
            }
            obs.derived.stuck_frames = self.stuck_frames;
            if self.stuck_frames >= STUCK_FRAME_THRESHOLD {
                obs.derived.stuck_suspected = true;
                let mut reason = "translating_no_progress".to_string();
                if inputs.client_correction_seen_recently {
                    reason.push_str(" client_correction_recent");
                }
                obs.derived.stuck_reason = Some(reason);
            }
        } else {
            self.last_self_pos = None;
            self.last_orient = None;
            self.last_movement_time = None;
            self.stuck_frames = 0;
        }

        obs
    }
}
