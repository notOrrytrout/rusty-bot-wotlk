use serde_json::json;

use super::memory::AgentMemory;
use super::observation::Observation;

#[derive(Debug, Clone)]
pub struct PromptConfig {
    pub tool_call_contract: String,
    pub tool_list: String,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            tool_call_contract: "Return exactly one <tool_call> JSON block and nothing else.\n\nFormat:\n<tool_call>\n{\"name\":\"request_idle\",\"arguments\":{}}\n</tool_call>".to_string(),
            tool_list: "Allowed tool calls:\n- request_move {\"direction\":\"forward|backward|left|right\",\"duration_ms\":150..5000}\n- request_turn {\"direction\":\"left|right\",\"duration_ms\":150..5000}\n- request_stop {\"kind\":\"move|turn|strafe|all\"}\n- request_jump {}\n- request_emote {\"key\":\"wave|hello|bye|cheer|dance|laugh|clap|salute\"}\n- request_idle {}".to_string(),
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
        "self": obs.self_state,
        "npcs_nearby": obs.npcs_nearby,
        "players_nearby": obs.players_nearby,
        "chat_log": obs.chat_log,
        "combat_log": obs.combat_log,
        "goal": mem.goal,
        "last_error": mem.last_error,
        "history": mem.history,
    });

    let state_json = serde_json::to_string_pretty(&state).unwrap_or_else(|_| "{}".to_string());

    format!(
        "{system_prompt}\n\n[STATE_JSON]\n{state_json}\n\n[TOOLS]\n{}\n\n[CONTRACT]\n{}\n",
        cfg.tool_list, cfg.tool_call_contract
    )
}
