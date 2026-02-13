use serde_json::json;

use super::memory::AgentMemory;
use super::observation::Observation;
use super::tools;

#[derive(Debug, Clone)]
pub struct PromptConfig {
    pub tool_call_contract: String,
    pub tool_list: String,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            tool_call_contract: "Return exactly one <tool_call>...</tool_call> block and nothing else.\nInside the block, return JSON object: {\"name\":\"...\",\"arguments\":{...}} (optional: \"confirm\": true).\nDo not include markdown, code fences, or any other text.\n\nFormat:\n<tool_call>\n{\"name\":\"request_idle\",\"arguments\":{}}\n</tool_call>"
                .to_string(),
            tool_list: tools::tool_list_text(),
        }
    }
}

pub fn build_control_prompt(
    system_prompt: &str,
    obs: &Observation,
    mem: &AgentMemory,
    cfg: &PromptConfig,
) -> String {
    let state = json!({
        "tick": obs.tick,
        "self_guid": obs.self_guid,
        "self": obs.self_state,
        "npcs_nearby": obs.npcs_nearby,
        "players_nearby": obs.players_nearby,
        "chat_log": obs.chat_log,
        "combat_log": obs.combat_log,
        "derived": obs.derived,
        "goal": mem.goal,
        "goal_id": mem.goal_id,
        "last_error": mem.last_error,
        "history": mem.history,
    });

    let state_json = serde_json::to_string_pretty(&state).unwrap_or_else(|_| "{}".to_string());

    format!(
        "{system_prompt}\n\n[STATE_JSON]\n{state_json}\n\n[TOOLS]\n{}\n\n[CONTRACT]\n{}\n",
        cfg.tool_list, cfg.tool_call_contract
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::memory::{HistoryEntry, ToolResult, ToolStatus};
    use crate::agent::observation::{DerivedFacts, Observation, SelfSummary, Vec3};
    use crate::agent::wire::{RequestEmoteArgs, ToolCall, ToolInvocation};

    fn base_obs() -> Observation {
        Observation {
            tick: 123,
            self_guid: 42,
            self_state: Some(SelfSummary {
                guid: 42,
                pos: Vec3 {
                    x: 1.0,
                    y: 2.0,
                    z: 3.0,
                },
                orient: 0.5,
                movement_flags: 0,
                movement_time: 99,
                hp: (100, 100),
                level: 1,
            }),
            npcs_nearby: vec![],
            players_nearby: vec![],
            chat_log: vec!["hello".to_string()],
            combat_log: vec![],
            derived: DerivedFacts {
                moving: false,
                client_correction_seen_recently: true,
                stuck_suspected: false,
                ..DerivedFacts::default()
            },
        }
    }

    fn extract_section(prompt: &str, header: &str) -> String {
        let marker = format!("\n[{header}]\n");
        let start = prompt
            .find(&marker)
            .unwrap_or_else(|| panic!("missing section {header}"));
        let after = &prompt[start + marker.len()..];
        let end = after.find("\n\n[").unwrap_or(after.len());
        after[..end].to_string()
    }

    #[test]
    fn prompt_includes_tools_and_contract_sections() {
        let obs = base_obs();
        let mem = AgentMemory::default();
        let cfg = PromptConfig::default();
        let prompt = build_control_prompt("system", &obs, &mem, &cfg);

        assert!(prompt.contains("[TOOLS]"));
        assert!(prompt.contains("Allowed tool calls:"));
        assert!(prompt.contains("request_idle"));

        assert!(prompt.contains("[CONTRACT]"));
        assert!(prompt.contains("exactly one <tool_call>"));
        assert!(prompt.contains("<tool_call>"));
        assert!(prompt.contains("\"name\""));
        assert!(prompt.contains("\"arguments\""));
    }

    #[test]
    fn state_json_is_well_formed_and_contains_key_fields() {
        let obs = base_obs();
        let mut mem = AgentMemory::default();
        mem.set_goal("do a thing");
        mem.last_error = Some("bad output".to_string());
        mem.history.push_back(HistoryEntry {
            tool: ToolInvocation {
                call: ToolCall::RequestEmote(RequestEmoteArgs {
                    key: "wave".to_string(),
                }),
                confirm: false,
            },
            result: ToolResult {
                status: ToolStatus::Ok,
                reason: "done".to_string(),
                facts: serde_json::Value::Null,
            },
        });
        let cfg = PromptConfig::default();
        let prompt = build_control_prompt("system", &obs, &mem, &cfg);

        assert!(prompt.contains("[STATE_JSON]"));
        let state_json = extract_section(&prompt, "STATE_JSON");
        let v: serde_json::Value = serde_json::from_str(&state_json).expect("state json parses");

        assert_eq!(v.get("tick").and_then(|v| v.as_u64()), Some(123));
        assert_eq!(v.get("self_guid").and_then(|v| v.as_u64()), Some(42));
        assert!(v.get("derived").is_some());
        assert_eq!(v.get("goal").and_then(|v| v.as_str()), Some("do a thing"));
        assert_eq!(v.get("goal_id").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(
            v.get("last_error").and_then(|v| v.as_str()),
            Some("bad output")
        );
        assert!(v.get("history").is_some());
    }
}
