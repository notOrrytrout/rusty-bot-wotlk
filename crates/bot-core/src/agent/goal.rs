use super::observation::{EntitySummary, Observation, Vec3};
use super::wire::{MoveDirection, RequestMoveArgs, RequestTurnArgs, TurnDirection};
use super::{ToolCall, ToolInvocation};

#[derive(Debug, Clone, PartialEq)]
pub enum GoalKind {
    FollowGuid(u64),
    FollowNpcEntry(u32),
    GotoGuid { guid: u64, interact: bool },
    GotoNpcEntry { entry: u32, interact: bool },
    KillGuid { guid: u64, slot: u8 },
    KillNpcEntry { entry: u32, slot: u8 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct GoalPlan {
    pub kind: GoalKind,
    pub stop_distance: f32,
    pub last_target_guid: Option<u64>,
    pub interacted: bool,
}

impl GoalPlan {
    pub fn parse(text: &str) -> Option<Self> {
        let t = text.trim().to_ascii_lowercase();
        if t.is_empty() {
            return None;
        }

        // Very small grammar on purpose; keep it predictable.
        //
        // Examples:
        // - "follow guid=123"
        // - "follow npc_entry=123"
        // - "goto guid=123 interact"
        // - "goto npc_entry=123 interact"
        // - "kill guid=123"
        // - "kill npc_entry=123 slot=1"
        let interact = t.contains("interact");
        let stop_distance = 3.5_f32;
        let slot = extract_u32_kv(&t, "slot")
            .or_else(|| extract_u32_kv(&t, "cast_slot"))
            .unwrap_or(1)
            .clamp(1, 12) as u8;

        let (verb, rest) = t.split_once(' ').unwrap_or((t.as_str(), ""));

        let guid = extract_u64_kv(&t, "guid")
            .or_else(|| extract_u64_kv(&t, "target_guid"))
            .or_else(|| extract_u64_after_prefix(&t, "follow "))
            .or_else(|| extract_u64_after_prefix(&t, "goto "));

        let entry = extract_u32_kv(&t, "entry")
            .or_else(|| extract_u32_kv(&t, "npc_entry"))
            .or_else(|| extract_u32_kv(&t, "npc"));

        let kind = match verb {
            "follow" => {
                if let Some(g) = guid {
                    GoalKind::FollowGuid(g)
                } else if let Some(e) = entry {
                    GoalKind::FollowNpcEntry(e)
                } else {
                    return None;
                }
            }
            "goto" | "go" => {
                if let Some(g) = guid {
                    GoalKind::GotoGuid { guid: g, interact }
                } else if let Some(e) = entry {
                    GoalKind::GotoNpcEntry { entry: e, interact }
                } else {
                    // allow "go to ..." as two tokens
                    if verb == "go" && rest.starts_with("to") {
                        if let Some(g) = guid {
                            GoalKind::GotoGuid { guid: g, interact }
                        } else if let Some(e) = entry {
                            GoalKind::GotoNpcEntry { entry: e, interact }
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
            }
            "kill" | "attack" => {
                // Kill is deterministic v0: select -> approach -> attackswing (`cast` tool in proxy).
                if let Some(g) = guid {
                    GoalKind::KillGuid { guid: g, slot }
                } else if let Some(e) = entry {
                    GoalKind::KillNpcEntry { entry: e, slot }
                } else {
                    return None;
                }
            }
            _ => return None,
        };

        let stop_distance = match &kind {
            GoalKind::KillGuid { .. } | GoalKind::KillNpcEntry { .. } => 4.0,
            _ => stop_distance,
        };

        Some(Self {
            kind,
            stop_distance,
            last_target_guid: None,
            interacted: false,
        })
    }

    pub fn wants_interact(&self) -> bool {
        matches!(
            self.kind,
            GoalKind::GotoGuid { interact: true, .. }
                | GoalKind::GotoNpcEntry { interact: true, .. }
        )
    }

    pub fn step(&mut self, obs: &Observation) -> Option<ToolInvocation> {
        let self_state = obs.self_state.as_ref()?;
        let self_pos = self_state.pos;
        let self_orient = self_state.orient;

        let (target_guid, target_pos) = self.pick_target(obs)?;

        // Ensure the target is selected once (helps with follow-up interact/attack semantics).
        if self.last_target_guid != Some(target_guid) {
            self.last_target_guid = Some(target_guid);
            self.interacted = false;
            return Some(ToolInvocation {
                call: ToolCall::TargetGuid(super::wire::TargetGuidArgs { guid: target_guid }),
                confirm: false,
            });
        }

        let dx = target_pos.x - self_pos.x;
        let dy = target_pos.y - self_pos.y;
        let dist = (dx * dx + dy * dy).sqrt();
        let desired = dy.atan2(dx);
        let delta = wrap_pi(desired - self_orient);

        // If close enough and we want to interact, do it once.
        if dist <= self.stop_distance {
            if self.wants_interact() && !self.interacted {
                self.interacted = true;
                return Some(ToolInvocation {
                    call: ToolCall::Interact(super::wire::InteractArgs { guid: target_guid }),
                    confirm: false,
                });
            }

            // If close enough and this is a kill goal, stop then attack.
            if matches!(
                self.kind,
                GoalKind::KillGuid { .. } | GoalKind::KillNpcEntry { .. }
            ) {
                // If we're still moving, stop first so we don't overlap movement and attack.
                if obs.derived.moving {
                    return Some(ToolInvocation {
                        call: ToolCall::RequestStop(super::wire::RequestStopArgs {
                            kind: super::wire::StopKind::Move,
                        }),
                        confirm: false,
                    });
                }

                // Ensure we are roughly facing the target before swinging.
                if delta.abs() > 0.5 {
                    let direction = if delta > 0.0 {
                        TurnDirection::Left
                    } else {
                        TurnDirection::Right
                    };
                    let ms =
                        ((delta.abs() / std::f32::consts::PI) * 900.0).clamp(150.0, 900.0) as u32;
                    return Some(ToolInvocation {
                        call: ToolCall::RequestTurn(RequestTurnArgs {
                            direction,
                            duration_ms: ms,
                        }),
                        confirm: false,
                    });
                }

                let slot = match self.kind {
                    GoalKind::KillGuid { slot, .. } | GoalKind::KillNpcEntry { slot, .. } => slot,
                    _ => 1,
                };
                return Some(ToolInvocation {
                    call: ToolCall::Cast(super::wire::CastArgs {
                        slot,
                        guid: Some(target_guid),
                    }),
                    confirm: false,
                });
            }

            // Otherwise ensure we're not running.
            if obs.derived.moving {
                return Some(ToolInvocation {
                    call: ToolCall::RequestStop(super::wire::RequestStopArgs {
                        kind: super::wire::StopKind::Move,
                    }),
                    confirm: false,
                });
            }
            return None;
        }

        // Turn first if we're not roughly facing the target.
        if delta.abs() > 0.35 {
            let direction = if delta > 0.0 {
                TurnDirection::Left
            } else {
                TurnDirection::Right
            };
            let ms = ((delta.abs() / std::f32::consts::PI) * 900.0).clamp(150.0, 900.0) as u32;
            return Some(ToolInvocation {
                call: ToolCall::RequestTurn(RequestTurnArgs {
                    direction,
                    duration_ms: ms,
                }),
                confirm: false,
            });
        }

        // Move forward in short bursts; observation completion checks stop it quickly.
        let ms = (dist * 400.0).clamp(200.0, 900.0) as u32;
        Some(ToolInvocation {
            call: ToolCall::RequestMove(RequestMoveArgs {
                direction: MoveDirection::Forward,
                duration_ms: ms,
            }),
            confirm: false,
        })
    }

    fn pick_target(&self, obs: &Observation) -> Option<(u64, Vec3)> {
        match self.kind {
            GoalKind::FollowGuid(guid) | GoalKind::GotoGuid { guid, .. } => {
                find_guid(obs, guid).map(|e| (e.guid, e.pos))
            }
            GoalKind::FollowNpcEntry(entry) | GoalKind::GotoNpcEntry { entry, .. } => {
                // Not "nearest npc in world", but nearest *visible* matching entry.
                obs.npcs_nearby
                    .iter()
                    .find(|n| n.entry == Some(entry))
                    .map(|e| (e.guid, e.pos))
            }
            GoalKind::KillGuid { guid, .. } => find_guid(obs, guid).map(|e| (e.guid, e.pos)),
            GoalKind::KillNpcEntry { entry, .. } => obs
                .npcs_nearby
                .iter()
                .find(|n| n.entry == Some(entry))
                .map(|e| (e.guid, e.pos)),
        }
    }
}

fn find_guid(obs: &Observation, guid: u64) -> Option<&EntitySummary> {
    obs.npcs_nearby
        .iter()
        .find(|e| e.guid == guid)
        .or_else(|| obs.players_nearby.iter().find(|e| e.guid == guid))
}

fn wrap_pi(mut v: f32) -> f32 {
    const PI: f32 = std::f32::consts::PI;
    while v > PI {
        v -= 2.0 * PI;
    }
    while v < -PI {
        v += 2.0 * PI;
    }
    v
}

fn extract_u64_kv(s: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}=");
    let idx = s.find(&needle)?;
    let after = &s[idx + needle.len()..];
    let num = after
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    if num.is_empty() {
        None
    } else {
        num.parse().ok()
    }
}

fn extract_u32_kv(s: &str, key: &str) -> Option<u32> {
    extract_u64_kv(s, key).and_then(|v| u32::try_from(v).ok())
}

fn extract_u64_after_prefix(s: &str, prefix: &str) -> Option<u64> {
    let after = s.strip_prefix(prefix)?;
    let num = after
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    if num.is_empty() {
        None
    } else {
        num.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::observation::{DerivedFacts, Observation, SelfSummary};

    fn base_obs(
        self_orient: f32,
        npc_guid: u64,
        entry: u32,
        npc_x: f32,
        npc_y: f32,
    ) -> Observation {
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
                orient: self_orient,
                movement_flags: 0,
                movement_time: 1,
                hp: (1, 1),
                level: 1,
                class: 1,
                race: 1,
                gender: 0,
            }),
            npcs_nearby: vec![EntitySummary {
                guid: npc_guid,
                entry: Some(entry),
                pos: Vec3 {
                    x: npc_x,
                    y: npc_y,
                    z: 0.0,
                },
                hp: Some((10, 10)),
            }],
            players_nearby: vec![],
            chat_log: vec![],
            combat_log: vec![],
            derived: DerivedFacts::default(),
        }
    }

    #[test]
    fn parse_follow_guid() {
        let p = GoalPlan::parse("follow guid=123").unwrap();
        assert_eq!(p.kind, GoalKind::FollowGuid(123));
    }

    #[test]
    fn parse_goto_entry_interact() {
        let p = GoalPlan::parse("goto npc_entry=55 interact").unwrap();
        assert_eq!(
            p.kind,
            GoalKind::GotoNpcEntry {
                entry: 55,
                interact: true
            }
        );
    }

    #[test]
    fn parse_kill_guid_defaults_slot_1() {
        let p = GoalPlan::parse("kill guid=123").unwrap();
        assert_eq!(p.kind, GoalKind::KillGuid { guid: 123, slot: 1 });
        assert_eq!(p.stop_distance, 4.0);
    }

    #[test]
    fn parse_kill_entry_with_slot() {
        let p = GoalPlan::parse("kill npc_entry=55 slot=7").unwrap();
        assert_eq!(p.kind, GoalKind::KillNpcEntry { entry: 55, slot: 7 });
        assert_eq!(p.stop_distance, 4.0);
    }

    #[test]
    fn step_targets_then_moves() {
        let mut plan = GoalPlan::parse("goto npc_entry=55").unwrap();
        let obs = base_obs(0.0, 9, 55, 10.0, 0.0);

        let first = plan.step(&obs).unwrap();
        assert!(matches!(first.call, ToolCall::TargetGuid(_)));

        let second = plan.step(&obs).unwrap();
        assert!(matches!(second.call, ToolCall::RequestMove(_)));
    }

    #[test]
    fn kill_steps_target_then_move_then_cast() {
        let mut plan = GoalPlan::parse("kill npc_entry=55 slot=2").unwrap();
        let far = base_obs(0.0, 9, 55, 10.0, 0.0);

        let first = plan.step(&far).unwrap();
        assert!(matches!(first.call, ToolCall::TargetGuid(_)));

        let second = plan.step(&far).unwrap();
        assert!(matches!(second.call, ToolCall::RequestMove(_)));

        // Close enough: should cast (unless moving; base_obs has moving=false).
        let mut near = base_obs(0.0, 9, 55, 3.0, 0.0);
        // Pretend we already moved close by updating self position.
        near.self_state.as_mut().unwrap().pos.x = 0.5;
        let third = plan.step(&near).unwrap();
        match third.call {
            ToolCall::Cast(args) => {
                assert_eq!(args.slot, 2);
                assert_eq!(args.guid, Some(9));
            }
            other => panic!("expected cast, got {other:?}"),
        }
    }
}
