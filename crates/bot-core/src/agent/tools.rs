use std::time::Duration;

use super::memory::ToolResult;
use super::wire::{RequestMoveArgs, RequestStopArgs, RequestTurnArgs, StopKind};
use super::{ToolCall, ToolInvocation};

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

pub fn is_continuous(tool: &ToolCall) -> bool {
    matches!(tool, ToolCall::RequestMove(_) | ToolCall::RequestTurn(_))
}

pub fn default_timeout(tool: &ToolCall) -> Duration {
    match tool {
        ToolCall::RequestMove(RequestMoveArgs { duration_ms, .. }) => {
            Duration::from_millis((*duration_ms).into())
        }
        ToolCall::RequestTurn(RequestTurnArgs { duration_ms, .. }) => {
            Duration::from_millis((*duration_ms).into())
        }
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
    // Movement/emotes are always safe. This is scaffolding for future destructive tools (vendor, delete, mail, etc).
    false
}

pub fn ok(reason: impl Into<String>) -> ToolResult {
    ToolResult {
        status: super::memory::ToolStatus::Ok,
        reason: reason.into(),
        facts: serde_json::Value::Null,
    }
}
