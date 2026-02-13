use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::memory::{ToolResult, ToolStatus};
use super::tools::{auto_stop_after, default_timeout, is_continuous};
use super::ToolCall;

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutorState {
    Idle,
    Waiting {
        tool: ToolCall,
        issued_at: Instant,
        timeout: Duration,
        stop_after: Option<ToolCall>,
    },
}

#[derive(Debug, Clone)]
pub struct Executor {
    queue: VecDeque<ToolCall>,
    pub state: ExecutorState,
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            state: ExecutorState::Idle,
        }
    }
}

impl Executor {
    pub fn is_idle(&self) -> bool {
        matches!(self.state, ExecutorState::Idle)
    }

    pub fn offer_llm_tool(&mut self, tool: ToolCall) {
        // V1 behavior: a single "next action" from the LLM. Clear any queued follow-ups,
        // but preserve the currently-running action.
        self.queue.clear();
        self.queue.push_back(tool);
    }

    pub fn next_to_execute(&mut self) -> Option<ToolCall> {
        if !self.is_idle() {
            return None;
        }
        self.queue.pop_front()
    }

    pub fn start(&mut self, tool: ToolCall, now: Instant) {
        let timeout = default_timeout(&tool);
        let stop_after = auto_stop_after(&tool);
        self.state = ExecutorState::Waiting {
            tool,
            issued_at: now,
            timeout,
            stop_after,
        };
    }

    pub fn tick_timeout(&mut self, now: Instant) -> Option<(ToolCall, ToolResult)> {
        let ExecutorState::Waiting {
            tool,
            issued_at,
            timeout,
            stop_after,
        } = &self.state
        else {
            return None;
        };

        if now.saturating_duration_since(*issued_at) < *timeout {
            return None;
        }

        let tool = tool.clone();
        let stop_after = stop_after.clone();
        self.state = ExecutorState::Idle;

        if let Some(stop_tool) = stop_after {
            // Ensure we stop continuous movement even if the LLM never asks for it.
            self.queue.push_front(stop_tool);
        } else if is_continuous(&tool) {
            // Should never happen, but prefer safety.
            self.queue.push_front(ToolCall::RequestIdle);
        }

        Some((
            tool,
            ToolResult {
                status: ToolStatus::Retryable,
                reason: "timeout".to_string(),
                facts: serde_json::Value::Null,
            },
        ))
    }

    pub fn complete(&mut self, result: ToolResult) -> Option<(ToolCall, ToolResult)> {
        let ExecutorState::Waiting { tool, stop_after, .. } = &self.state else {
            return None;
        };
        let tool = tool.clone();
        let stop_after = stop_after.clone();
        self.state = ExecutorState::Idle;

        if let Some(stop_tool) = stop_after {
            self.queue.push_front(stop_tool);
        }

        Some((tool, result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::wire::{MoveDirection, RequestMoveArgs};

    #[test]
    fn continuous_move_auto_stops() {
        let mut ex = Executor::default();
        ex.offer_llm_tool(ToolCall::RequestMove(RequestMoveArgs {
            direction: MoveDirection::Forward,
            duration_ms: 150,
        }));

        let tool = ex.next_to_execute().expect("tool");
        let now = Instant::now();
        ex.start(tool, now);

        // Advance past timeout; executor should schedule stop tool.
        let _ = ex.tick_timeout(now + Duration::from_millis(200));
        let next = ex.next_to_execute().expect("stop");
        match next {
            ToolCall::RequestStop(_) => {}
            other => panic!("expected stop, got {other:?}"),
        }
    }
}
