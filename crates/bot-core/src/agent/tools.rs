use std::time::Duration;

use super::memory::ToolResult;
use super::wire::{RequestMoveArgs, RequestStopArgs, RequestTurnArgs, StopKind};
use super::{ToolCall, ToolInvocation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolId {
    RequestMove,
    RequestTurn,
    RequestStop,
    RequestJump,
    RequestEmote,
    RequestIdle,
    TargetGuid,
    TargetNearestNpc,
    Interact,
    Cast,
    Loot,
}

pub trait Tool {
    fn id(&self) -> ToolId;
    fn name(&self) -> &'static str;
    fn prompt_signature(&self) -> &'static str;
    fn is_continuous(&self) -> bool;
    fn requires_confirm(&self) -> bool;
}

impl Tool for ToolId {
    fn id(&self) -> ToolId {
        *self
    }

    fn name(&self) -> &'static str {
        match self {
            ToolId::RequestMove => "request_move",
            ToolId::RequestTurn => "request_turn",
            ToolId::RequestStop => "request_stop",
            ToolId::RequestJump => "request_jump",
            ToolId::RequestEmote => "request_emote",
            ToolId::RequestIdle => "request_idle",
            ToolId::TargetGuid => "target_guid",
            ToolId::TargetNearestNpc => "target_nearest_npc",
            ToolId::Interact => "interact",
            ToolId::Cast => "cast",
            ToolId::Loot => "loot",
        }
    }

    fn prompt_signature(&self) -> &'static str {
        match self {
            ToolId::RequestMove => {
                "request_move {\"direction\":\"forward|backward|left|right\",\"duration_ms\":150..5000}"
            }
            ToolId::RequestTurn => {
                "request_turn {\"direction\":\"left|right\",\"duration_ms\":150..5000}"
            }
            ToolId::RequestStop => "request_stop {\"kind\":\"move|turn|strafe|all\"}",
            ToolId::RequestJump => "request_jump {}",
            ToolId::RequestEmote => {
                "request_emote {\"key\":\"wave|hello|bye|cheer|dance|laugh|clap|salute\"}"
            }
            ToolId::RequestIdle => "request_idle {}",
            ToolId::TargetGuid => "target_guid {\"guid\":123}",
            ToolId::TargetNearestNpc => "target_nearest_npc {\"entry\":123} (entry optional)",
            ToolId::Interact => "interact {\"guid\":123}",
            ToolId::Cast => "cast {\"slot\":1..12,\"guid\":123} (guid optional)",
            ToolId::Loot => "loot {\"guid\":123}",
        }
    }

    fn is_continuous(&self) -> bool {
        matches!(self, ToolId::RequestMove | ToolId::RequestTurn)
    }

    fn requires_confirm(&self) -> bool {
        // Movement/emotes are always safe. This is scaffolding for future destructive tools (vendor, delete, mail, etc).
        false
    }
}

static TOOL_REGISTRY: &[ToolId] = &[
    ToolId::RequestMove,
    ToolId::RequestTurn,
    ToolId::RequestStop,
    ToolId::RequestJump,
    ToolId::RequestEmote,
    ToolId::RequestIdle,
    ToolId::TargetGuid,
    ToolId::TargetNearestNpc,
    ToolId::Interact,
    ToolId::Cast,
    ToolId::Loot,
];

pub fn registry() -> &'static [ToolId] {
    TOOL_REGISTRY
}

pub fn tool_list_text() -> String {
    let mut out = String::from("Allowed tool calls:\n");
    for tool in registry() {
        out.push_str("- ");
        out.push_str(tool.prompt_signature());
        out.push('\n');
    }
    // Preserve the historical formatting with no trailing newline at the end of the section.
    out.trim_end().to_string()
}

pub trait ToolMeta {
    fn is_continuous(&self) -> bool;
    fn default_timeout(&self) -> Duration;
    fn auto_stop_after(&self) -> Option<ToolInvocation>;
    fn requires_confirm(&self) -> bool;
}

impl ToolMeta for ToolInvocation {
    fn is_continuous(&self) -> bool {
        is_continuous(&self.call)
    }

    fn default_timeout(&self) -> Duration {
        default_timeout(&self.call)
    }

    fn auto_stop_after(&self) -> Option<ToolInvocation> {
        auto_stop_after(&self.call)
    }

    fn requires_confirm(&self) -> bool {
        requires_confirm(&self.call)
    }
}

pub fn tool_id_for_call(tool: &ToolCall) -> ToolId {
    match tool {
        ToolCall::RequestMove(_) => ToolId::RequestMove,
        ToolCall::RequestTurn(_) => ToolId::RequestTurn,
        ToolCall::RequestStop(_) => ToolId::RequestStop,
        ToolCall::RequestJump => ToolId::RequestJump,
        ToolCall::RequestEmote(_) => ToolId::RequestEmote,
        ToolCall::RequestIdle => ToolId::RequestIdle,
        ToolCall::TargetGuid(_) => ToolId::TargetGuid,
        ToolCall::TargetNearestNpc(_) => ToolId::TargetNearestNpc,
        ToolCall::Interact(_) => ToolId::Interact,
        ToolCall::Cast(_) => ToolId::Cast,
        ToolCall::Loot(_) => ToolId::Loot,
    }
}

pub fn is_continuous(tool: &ToolCall) -> bool {
    tool_id_for_call(tool).is_continuous()
}

pub fn default_timeout(tool: &ToolCall) -> Duration {
    match tool {
        ToolCall::RequestMove(RequestMoveArgs { duration_ms, .. }) => {
            Duration::from_millis((*duration_ms).into())
        }
        ToolCall::RequestTurn(RequestTurnArgs { duration_ms, .. }) => {
            Duration::from_millis((*duration_ms).into())
        }
        ToolCall::TargetGuid(_) => Duration::from_millis(900),
        ToolCall::TargetNearestNpc(_) => Duration::from_millis(900),
        ToolCall::Interact(_) => Duration::from_millis(1200),
        ToolCall::Cast(_) => Duration::from_millis(1400),
        ToolCall::Loot(_) => Duration::from_millis(3500),
        ToolCall::RequestEmote(_) => Duration::from_millis(1800),
        ToolCall::RequestJump => Duration::from_millis(900),
        ToolCall::RequestStop(_) => Duration::from_millis(700),
        ToolCall::RequestIdle => Duration::from_millis(700),
    }
}

pub fn auto_stop_after(tool: &ToolCall) -> Option<ToolInvocation> {
    match tool {
        ToolCall::RequestMove(_) => Some(ToolInvocation {
            call: ToolCall::RequestStop(RequestStopArgs {
                kind: StopKind::Move,
            }),
            confirm: false,
        }),
        ToolCall::RequestTurn(_) => Some(ToolInvocation {
            call: ToolCall::RequestStop(RequestStopArgs {
                kind: StopKind::Turn,
            }),
            confirm: false,
        }),
        _ => None,
    }
}

pub fn requires_confirm(_tool: &ToolCall) -> bool {
    tool_id_for_call(_tool).requires_confirm()
}

pub fn ok(reason: impl Into<String>) -> ToolResult {
    ToolResult {
        status: super::memory::ToolStatus::Ok,
        reason: reason.into(),
        facts: serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::parse_tool_call;

    fn sample_call_for(tool: ToolId) -> &'static str {
        match tool {
            ToolId::RequestMove => {
                "<tool_call>{\"name\":\"request_move\",\"arguments\":{\"direction\":\"forward\",\"duration_ms\":200}}</tool_call>"
            }
            ToolId::RequestTurn => {
                "<tool_call>{\"name\":\"request_turn\",\"arguments\":{\"direction\":\"left\",\"duration_ms\":200}}</tool_call>"
            }
            ToolId::RequestStop => {
                "<tool_call>{\"name\":\"request_stop\",\"arguments\":{\"kind\":\"all\"}}</tool_call>"
            }
            ToolId::RequestJump => {
                "<tool_call>{\"name\":\"request_jump\",\"arguments\":{}}</tool_call>"
            }
            ToolId::RequestEmote => {
                "<tool_call>{\"name\":\"request_emote\",\"arguments\":{\"key\":\"wave\"}}</tool_call>"
            }
            ToolId::RequestIdle => {
                "<tool_call>{\"name\":\"request_idle\",\"arguments\":{}}</tool_call>"
            }
            ToolId::TargetGuid => {
                "<tool_call>{\"name\":\"target_guid\",\"arguments\":{\"guid\":42}}</tool_call>"
            }
            ToolId::TargetNearestNpc => {
                "<tool_call>{\"name\":\"target_nearest_npc\",\"arguments\":{}}</tool_call>"
            }
            ToolId::Interact => {
                "<tool_call>{\"name\":\"interact\",\"arguments\":{\"guid\":42}}</tool_call>"
            }
            ToolId::Cast => {
                "<tool_call>{\"name\":\"cast\",\"arguments\":{\"slot\":1,\"guid\":42}}</tool_call>"
            }
            ToolId::Loot => {
                "<tool_call>{\"name\":\"loot\",\"arguments\":{\"guid\":42}}</tool_call>"
            }
        }
    }

    #[test]
    fn registry_tool_signatures_parse_via_wire_contract() {
        for tool in registry() {
            let raw = sample_call_for(*tool);
            let inv = parse_tool_call(raw)
                .unwrap_or_else(|e| panic!("tool {} should parse, got {e:#}", tool.name()));
            assert_eq!(tool_id_for_call(&inv.call), *tool);
        }
    }

    #[test]
    fn tool_list_text_includes_every_registry_signature() {
        let text = tool_list_text();
        for tool in registry() {
            assert!(
                text.contains(tool.prompt_signature()),
                "missing signature for {}",
                tool.name()
            );
        }
    }
}
