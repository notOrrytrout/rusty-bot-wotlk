use std::time::Duration;

use super::memory::ToolResult;
use super::wire::{RequestMoveArgs, RequestStopArgs, RequestTurnArgs, StopKind};
use super::ToolCall;

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

pub fn auto_stop_after(tool: &ToolCall) -> Option<ToolCall> {
    match tool {
        ToolCall::RequestMove(_) => Some(ToolCall::RequestStop(RequestStopArgs {
            kind: StopKind::Move,
        })),
        ToolCall::RequestTurn(_) => Some(ToolCall::RequestStop(RequestStopArgs {
            kind: StopKind::Turn,
        })),
        _ => None,
    }
}

pub fn ok(reason: impl Into<String>) -> ToolResult {
    ToolResult {
        status: super::memory::ToolStatus::Ok,
        reason: reason.into(),
        facts: serde_json::Value::Null,
    }
}

