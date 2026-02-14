use std::collections::BTreeMap;

use super::ToolInvocation;
use super::goal::GoalKind;
use super::memory::{AgentMemory, GoalState, ToolResult, ToolStatus};
use super::observation::Observation;
use super::wire::{CastArgs, ToolCall};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionId {
    /// If we know who is attacking us, hit them back.
    DefendAttacker,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionCandidate {
    pub id: ActionId,
    /// Higher wins. Keep this integer to ensure deterministic ordering.
    pub relevance: u32,
    /// Minimum number of observation ticks to wait after a successful execution of this action.
    pub cooldown_ticks: u64,
    /// Optional spell id gate: if present and the spell is on cooldown, this action is suppressed.
    pub spell_id: Option<u32>,
    pub tool: ToolInvocation,
}

pub trait Strategy: std::fmt::Debug + Send {
    fn name(&self) -> &'static str;
    fn candidates(&mut self, obs: &Observation, mem: &AgentMemory) -> Vec<ActionCandidate>;
}

#[derive(Debug, Default)]
pub struct BaseCombatStrategy;

impl Strategy for BaseCombatStrategy {
    fn name(&self) -> &'static str {
        "base_combat"
    }

    fn candidates(&mut self, obs: &Observation, mem: &AgentMemory) -> Vec<ActionCandidate> {
        let Some(attacker_guid) = obs.derived.attacker_guid else {
            return vec![];
        };
        if attacker_guid == 0 {
            return vec![];
        }
        if !obs.derived.in_combat {
            return vec![];
        }

        // Don't fight the deterministic kill goal driver.
        let kill_goal_active = mem.goal_state == Some(GoalState::Active)
            && mem
                .goal_plan
                .as_ref()
                .map(|p| {
                    matches!(
                        p.kind,
                        GoalKind::KillGuid { .. } | GoalKind::KillNpcEntry { .. }
                    )
                })
                .unwrap_or(false);
        if kill_goal_active {
            return vec![];
        }

        vec![ActionCandidate {
            id: ActionId::DefendAttacker,
            relevance: 10_000,
            // Prevent rapid-fire spam when the executor becomes idle again quickly.
            cooldown_ticks: 3,
            spell_id: None,
            tool: ToolInvocation {
                call: ToolCall::Cast(CastArgs {
                    slot: 1,
                    guid: Some(attacker_guid),
                }),
                confirm: false,
            },
        }]
    }
}

#[derive(Debug)]
pub struct StrategyEngine {
    strategies: Vec<Box<dyn Strategy>>,
    last_executed_tick: BTreeMap<ActionId, u64>,
    last_offered: Option<(ActionId, ToolInvocation)>,
}

impl Default for StrategyEngine {
    fn default() -> Self {
        Self::new(vec![Box::new(BaseCombatStrategy)])
    }
}

impl StrategyEngine {
    pub fn new(strategies: Vec<Box<dyn Strategy>>) -> Self {
        Self {
            strategies,
            last_executed_tick: BTreeMap::new(),
            last_offered: None,
        }
    }

    pub fn next_action(&mut self, obs: &Observation, mem: &AgentMemory) -> Option<ActionCandidate> {
        let mut best_by_id: BTreeMap<ActionId, ActionCandidate> = BTreeMap::new();

        for strat in self.strategies.iter_mut() {
            for cand in strat.candidates(obs, mem) {
                if let Some(spell_id) = cand.spell_id {
                    let on_cd = obs
                        .derived
                        .spell_cooldowns
                        .iter()
                        .any(|c| c.spell_id == spell_id && obs.tick < c.until_tick);
                    if on_cd {
                        continue;
                    }
                }

                // Cooldown filter (based on the last *successful* execution).
                if cand.cooldown_ticks > 0
                    && let Some(last) = self.last_executed_tick.get(&cand.id)
                    && obs.tick.saturating_sub(*last) < cand.cooldown_ticks
                {
                    continue;
                }

                match best_by_id.get(&cand.id) {
                    None => {
                        best_by_id.insert(cand.id, cand);
                    }
                    Some(existing) => {
                        if cand.relevance > existing.relevance {
                            best_by_id.insert(cand.id, cand);
                        }
                    }
                }
            }
        }

        let best = best_by_id.into_values().max_by(|a, b| {
            a.relevance
                .cmp(&b.relevance)
                // Deterministic tie-breaker.
                .then_with(|| b.id.cmp(&a.id))
        });

        if let Some(best) = best.clone() {
            self.last_offered = Some((best.id, best.tool.clone()));
        }

        best
    }

    pub fn note_tool_result(&mut self, obs_tick: u64, tool: &ToolInvocation, result: &ToolResult) {
        if result.status != ToolStatus::Ok {
            return;
        }

        let Some((id, offered_tool)) = self.last_offered.as_ref() else {
            return;
        };
        if offered_tool != tool {
            return;
        }

        self.last_executed_tick.insert(*id, obs_tick);
        self.last_offered = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::observation::{DerivedFacts, Observation, SelfSummary, Vec3};

    fn base_obs(tick: u64) -> Observation {
        Observation {
            tick,
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
                movement_time: tick,
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
            derived: DerivedFacts::default(),
        }
    }

    #[derive(Debug)]
    struct TestStrategy {
        cand: ActionCandidate,
    }

    impl Strategy for TestStrategy {
        fn name(&self) -> &'static str {
            "test"
        }

        fn candidates(&mut self, _obs: &Observation, _mem: &AgentMemory) -> Vec<ActionCandidate> {
            vec![self.cand.clone()]
        }
    }

    #[test]
    fn engine_dedupes_by_action_id_and_keeps_highest_relevance() {
        let tool_a = ToolInvocation {
            call: ToolCall::RequestIdle,
            confirm: false,
        };
        let tool_b = ToolInvocation {
            call: ToolCall::RequestJump,
            confirm: false,
        };

        let s1 = TestStrategy {
            cand: ActionCandidate {
                id: ActionId::DefendAttacker,
                relevance: 10,
                cooldown_ticks: 0,
                spell_id: None,
                tool: tool_a.clone(),
            },
        };
        let s2 = TestStrategy {
            cand: ActionCandidate {
                id: ActionId::DefendAttacker,
                relevance: 20,
                cooldown_ticks: 0,
                spell_id: None,
                tool: tool_b.clone(),
            },
        };

        let mut engine = StrategyEngine::new(vec![Box::new(s1), Box::new(s2)]);
        let obs = base_obs(1);
        let mem = AgentMemory::default();
        let best = engine.next_action(&obs, &mem).expect("best");
        assert_eq!(best.relevance, 20);
        assert_eq!(best.tool, tool_b);
    }

    #[test]
    fn engine_respects_cooldown_ticks_after_successful_execution() {
        let tool = ToolInvocation {
            call: ToolCall::RequestJump,
            confirm: false,
        };
        let s = TestStrategy {
            cand: ActionCandidate {
                id: ActionId::DefendAttacker,
                relevance: 10,
                cooldown_ticks: 3,
                spell_id: None,
                tool: tool.clone(),
            },
        };
        let mut engine = StrategyEngine::new(vec![Box::new(s)]);
        let mem = AgentMemory::default();

        // Tick 1: propose action.
        let obs1 = base_obs(1);
        let cand = engine.next_action(&obs1, &mem).expect("action");
        assert_eq!(cand.tool, tool);
        engine.note_tool_result(
            1,
            &tool,
            &ToolResult {
                status: ToolStatus::Ok,
                reason: "ok".to_string(),
                facts: serde_json::Value::Null,
            },
        );

        // Tick 2: still cooling down.
        let obs2 = base_obs(2);
        assert!(engine.next_action(&obs2, &mem).is_none());

        // Tick 4: cooldown satisfied (since=3).
        let obs4 = base_obs(4);
        assert!(engine.next_action(&obs4, &mem).is_some());
    }

    #[test]
    fn engine_suppresses_actions_when_spell_is_on_cooldown() {
        let tool = ToolInvocation {
            call: ToolCall::RequestJump,
            confirm: false,
        };
        let s = TestStrategy {
            cand: ActionCandidate {
                id: ActionId::DefendAttacker,
                relevance: 10,
                cooldown_ticks: 0,
                spell_id: Some(116),
                tool: tool.clone(),
            },
        };
        let mut engine = StrategyEngine::new(vec![Box::new(s)]);
        let mut obs = base_obs(5);
        obs.derived.spell_cooldowns = vec![crate::agent::observation::SpellCooldownSummary {
            spell_id: 116,
            until_tick: 10,
        }];
        let mem = AgentMemory::default();

        assert!(engine.next_action(&obs, &mem).is_none());

        obs.tick = 10;
        assert!(engine.next_action(&obs, &mem).is_some());
    }
}
