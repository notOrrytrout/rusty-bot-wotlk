use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::ToolInvocation;
use super::goal::GoalPlan;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoalState {
    Active,
    Completed,
    Blocked,
    Aborted,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Ok,
    Failed,
    Retryable,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ToolResult {
    pub status: ToolStatus,
    pub reason: String,
    #[serde(default)]
    pub facts: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct HistoryEntry {
    pub tool: ToolInvocation,
    pub result: ToolResult,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentMemory {
    pub goal: Option<String>,
    #[serde(default)]
    pub goal_id: Option<u64>,
    #[serde(default)]
    pub goal_state: Option<GoalState>,
    #[serde(default)]
    pub goal_state_reason: Option<String>,
    #[serde(skip)]
    next_goal_id: u64,
    #[serde(skip)]
    missing_self_frames: u32,
    #[serde(skip)]
    idle_frames: u32,
    #[serde(skip)]
    kill_missing_target_frames: u32,
    #[serde(skip)]
    kill_saw_combat: bool,
    #[serde(skip)]
    pub goal_plan: Option<GoalPlan>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub history: VecDeque<HistoryEntry>,
    pub history_limit: usize,
}

impl Default for AgentMemory {
    fn default() -> Self {
        Self {
            goal: None,
            goal_id: None,
            goal_state: None,
            goal_state_reason: None,
            next_goal_id: 1,
            missing_self_frames: 0,
            idle_frames: 0,
            kill_missing_target_frames: 0,
            kill_saw_combat: false,
            goal_plan: None,
            last_error: None,
            history: VecDeque::new(),
            history_limit: 12,
        }
    }
}

impl AgentMemory {
    pub fn set_goal(&mut self, goal: impl Into<String>) {
        let goal = goal.into();
        self.goal_plan = GoalPlan::parse(&goal);
        self.goal = Some(goal);
        let id = self.next_goal_id;
        self.next_goal_id = self.next_goal_id.saturating_add(1);
        self.goal_id = Some(id);
        self.goal_state = Some(GoalState::Active);
        self.goal_state_reason = None;
        self.missing_self_frames = 0;
        self.idle_frames = 0;
        self.kill_missing_target_frames = 0;
        self.kill_saw_combat = false;
    }

    pub fn clear_goal(&mut self) {
        self.goal = None;
        self.goal_id = None;
        self.goal_state = None;
        self.goal_state_reason = None;
        self.missing_self_frames = 0;
        self.idle_frames = 0;
        self.kill_missing_target_frames = 0;
        self.kill_saw_combat = false;
        self.goal_plan = None;
    }

    pub fn complete_goal(&mut self, reason: impl Into<String>) {
        if self.goal.is_some() {
            self.goal_state = Some(GoalState::Completed);
            self.goal_state_reason = Some(reason.into());
        }
    }

    pub fn block_goal(&mut self, reason: impl Into<String>) {
        if self.goal.is_some() {
            self.goal_state = Some(GoalState::Blocked);
            self.goal_state_reason = Some(reason.into());
        }
    }

    pub fn abort_goal(&mut self, reason: impl Into<String>) {
        if self.goal.is_some() {
            self.goal_state = Some(GoalState::Aborted);
            self.goal_state_reason = Some(reason.into());
        }
    }

    pub fn record(&mut self, tool: ToolInvocation, result: ToolResult) {
        let status = result.status.clone();
        self.last_error = match status {
            ToolStatus::Ok => None,
            ToolStatus::Failed | ToolStatus::Retryable => Some(result.reason.clone()),
        };

        // Preserve a copy for goal completion checks below.
        let tool_for_goal = tool.clone();
        self.history.push_back(HistoryEntry { tool, result });
        while self.history.len() > self.history_limit {
            self.history.pop_front();
        }

        // Goal completion: if we're running a goto+interact goal and we successfully interacted,
        // mark the goal completed.
        if status == ToolStatus::Ok
            && let Some(plan) = self.goal_plan.as_ref()
            && plan.wants_interact()
            && matches!(tool_for_goal.call, super::ToolCall::Interact(_))
        {
            self.complete_goal("interacted");
        }
    }

    pub fn tick_goal_v0(&mut self, obs: &crate::agent::observation::Observation) {
        if self.goal.is_none() {
            return;
        }
        if self.goal_state != Some(GoalState::Active) {
            return;
        }

        // If we can't even see ourselves for a bit, we can't act reliably.
        let has_self = obs.self_guid != 0 && obs.self_state.is_some();
        if !has_self {
            self.missing_self_frames = self.missing_self_frames.saturating_add(1);
        } else {
            self.missing_self_frames = 0;
        }
        if self.missing_self_frames >= 10 {
            self.block_goal("no_self_state");
            return;
        }

        // Kill goals: completion/blocking based on target visibility + health.
        if let Some(plan) = self.goal_plan.as_ref() {
            let is_kill = matches!(
                plan.kind,
                super::goal::GoalKind::KillGuid { .. } | super::goal::GoalKind::KillNpcEntry { .. }
            );
            if is_kill {
                if obs.derived.in_combat {
                    self.kill_saw_combat = true;
                }

                let target_guid = plan.last_target_guid;
                let target = target_guid.and_then(|g| {
                    obs.npcs_nearby
                        .iter()
                        .find(|e| e.guid == g)
                        .or_else(|| obs.players_nearby.iter().find(|e| e.guid == g))
                });

                if let Some(t) = target {
                    self.kill_missing_target_frames = 0;
                    if let Some((hp, _max)) = t.hp
                        && hp == 0
                    {
                        self.complete_goal("target_dead");
                        return;
                    }
                } else {
                    // If we haven't selected a target yet, don't penalize.
                    if target_guid.is_some() {
                        self.kill_missing_target_frames =
                            self.kill_missing_target_frames.saturating_add(1);
                    } else {
                        self.kill_missing_target_frames = 0;
                    }

                    // If the target vanished after we saw combat, assume it died/despawned.
                    if self.kill_saw_combat
                        && !obs.derived.in_combat
                        && self.kill_missing_target_frames >= 10
                    {
                        self.complete_goal("target_gone");
                        return;
                    }

                    // Otherwise, if we can't see the target for a while, block (avoids wandering).
                    if self.kill_missing_target_frames >= 20 {
                        self.block_goal("target_not_visible");
                        return;
                    }
                }
            }
        }

        // Minimal completion heuristic for "stop/idle" type goals.
        let goal = self.goal.as_deref().unwrap_or("").to_ascii_lowercase();
        let wants_idle = goal.contains("idle") || goal.contains("stop");
        if wants_idle && !obs.derived.moving {
            self.idle_frames = self.idle_frames.saturating_add(1);
        } else {
            self.idle_frames = 0;
        }
        if wants_idle && self.idle_frames >= 3 {
            self.complete_goal("idle");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::observation::{DerivedFacts, Observation, SelfSummary, Vec3};

    fn obs_with_self(moving: bool) -> Observation {
        Observation {
            tick: 1,
            self_guid: 1,
            self_state: Some(SelfSummary {
                guid: 1,
                pos: Vec3 {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                orient: 0.0,
                movement_flags: 0,
                movement_time: 1,
                hp: (1, 1),
                level: 1,
                class: 1,
                race: 1,
                gender: 0,
            }),
            npcs_nearby: vec![],
            players_nearby: vec![],
            chat_log: vec![],
            combat_log: vec![],
            loot: None,
            derived: DerivedFacts {
                moving,
                ..DerivedFacts::default()
            },
        }
    }

    fn obs_missing_self() -> Observation {
        Observation {
            tick: 1,
            self_guid: 0,
            self_state: None,
            npcs_nearby: vec![],
            players_nearby: vec![],
            chat_log: vec![],
            combat_log: vec![],
            loot: None,
            derived: DerivedFacts::default(),
        }
    }

    fn obs_with_npc(guid: u64, hp: u32, max_hp: u32, in_combat: bool) -> Observation {
        Observation {
            tick: 1,
            self_guid: 1,
            self_state: Some(SelfSummary {
                guid: 1,
                pos: Vec3 {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                orient: 0.0,
                movement_flags: 0,
                movement_time: 1,
                hp: (1, 1),
                level: 1,
                class: 1,
                race: 1,
                gender: 0,
            }),
            npcs_nearby: vec![crate::agent::observation::EntitySummary {
                guid,
                entry: Some(55),
                pos: Vec3 {
                    x: 1.0,
                    y: 0.0,
                    z: 0.0,
                },
                hp: Some((hp, max_hp)),
            }],
            players_nearby: vec![],
            chat_log: vec![],
            combat_log: vec![],
            loot: None,
            derived: DerivedFacts {
                in_combat,
                ..DerivedFacts::default()
            },
        }
    }

    #[test]
    fn goal_blocks_when_self_state_missing_for_many_frames() {
        let mut mem = AgentMemory::default();
        mem.set_goal("do something");
        assert_eq!(mem.goal_state, Some(GoalState::Active));

        for _ in 0..10 {
            mem.tick_goal_v0(&obs_missing_self());
        }

        assert_eq!(mem.goal_state, Some(GoalState::Blocked));
        assert_eq!(mem.goal_state_reason.as_deref(), Some("no_self_state"));
    }

    #[test]
    fn goal_completes_for_stop_idle_goals_when_not_moving_for_a_few_frames() {
        let mut mem = AgentMemory::default();
        mem.set_goal("stop moving");

        for _ in 0..3 {
            mem.tick_goal_v0(&obs_with_self(false));
        }

        assert_eq!(mem.goal_state, Some(GoalState::Completed));
        assert_eq!(mem.goal_state_reason.as_deref(), Some("idle"));
    }

    #[test]
    fn kill_goal_completes_when_target_hp_zero() {
        let mut mem = AgentMemory::default();
        mem.set_goal("kill npc_entry=55");
        mem.goal_plan.as_mut().unwrap().last_target_guid = Some(9);

        mem.tick_goal_v0(&obs_with_npc(9, 0, 10, true));
        assert_eq!(mem.goal_state, Some(GoalState::Completed));
        assert_eq!(mem.goal_state_reason.as_deref(), Some("target_dead"));
    }
}
