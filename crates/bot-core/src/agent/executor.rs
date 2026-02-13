use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::memory::{ToolResult, ToolStatus};
use super::observation::Observation;
use super::tools::{auto_stop_after, default_timeout, is_continuous};
use super::{ToolCall, ToolInvocation};

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutorState {
    Idle,
    Waiting {
        tool: ToolInvocation,
        issued_at: Instant,
        timeout: Duration,
        stop_after: Option<ToolInvocation>,
    },
}

#[derive(Debug, Clone)]
pub struct Executor {
    queue: VecDeque<ToolInvocation>,
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

    pub fn offer_llm_tool(&mut self, tool: ToolInvocation) {
        // V1 behavior: a single "next action" from the LLM. Clear any queued follow-ups,
        // but preserve the currently-running action.
        self.queue.clear();
        self.queue.push_back(tool);
    }

    pub fn next_to_execute(&mut self) -> Option<ToolInvocation> {
        if !self.is_idle() {
            return None;
        }
        self.queue.pop_front()
    }

    pub fn start(&mut self, tool: ToolInvocation, now: Instant) {
        let timeout = default_timeout(&tool.call);
        let stop_after = auto_stop_after(&tool.call);
        self.state = ExecutorState::Waiting {
            tool,
            issued_at: now,
            timeout,
            stop_after,
        };
    }

    pub fn tick_timeout(&mut self, now: Instant) -> Option<(ToolInvocation, ToolResult)> {
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
        } else if is_continuous(&tool.call) {
            // Should never happen, but prefer safety.
            self.queue.push_front(ToolInvocation {
                call: ToolCall::RequestIdle,
                confirm: false,
            });
        }

        let cont = is_continuous(&tool.call);
        Some((
            tool,
            ToolResult {
                status: if cont {
                    ToolStatus::Ok
                } else {
                    ToolStatus::Retryable
                },
                reason: if cont {
                    "duration_elapsed".to_string()
                } else {
                    "timeout".to_string()
                },
                facts: serde_json::Value::Null,
            },
        ))
    }

    pub fn tick_observation(&mut self, obs: &Observation) -> Option<(ToolInvocation, ToolResult)> {
        let ExecutorState::Waiting {
            tool, stop_after, ..
        } = &self.state
        else {
            return None;
        };

        if obs.self_state.is_none() {
            return None;
        }

        let moved = obs
            .derived
            .self_dist_moved
            .map(|d| d >= 0.25)
            .unwrap_or(false)
            || obs
                .derived
                .self_movement_time_delta
                .map(|d| d != 0)
                .unwrap_or(false);
        let turned = obs
            .derived
            .self_abs_orient_delta
            .map(|d| d >= 0.05)
            .unwrap_or(false);

        let complete = match tool {
            ToolInvocation {
                call: ToolCall::RequestMove(_),
                ..
            } => moved,
            ToolInvocation {
                call: ToolCall::RequestTurn(_),
                ..
            } => turned,
            _ => false,
        };
        if !complete {
            return None;
        }

        let tool = tool.clone();
        let stop_after = stop_after.clone();
        self.state = ExecutorState::Idle;
        if let Some(stop_tool) = stop_after {
            self.queue.push_front(stop_tool);
        }

        let reason = if matches!(tool.call, ToolCall::RequestTurn(_)) {
            "turned"
        } else {
            "moved"
        };
        Some((
            tool,
            ToolResult {
                status: ToolStatus::Ok,
                reason: reason.to_string(),
                facts: serde_json::Value::Null,
            },
        ))
    }

    pub fn complete(&mut self, result: ToolResult) -> Option<(ToolInvocation, ToolResult)> {
        let ExecutorState::Waiting {
            tool, stop_after, ..
        } = &self.state
        else {
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
        ex.offer_llm_tool(ToolInvocation {
            call: ToolCall::RequestMove(RequestMoveArgs {
                direction: MoveDirection::Forward,
                duration_ms: 150,
            }),
            confirm: false,
        });

        let tool = ex.next_to_execute().expect("tool");
        let now = Instant::now();
        ex.start(tool, now);

        // Advance past timeout; executor should schedule stop tool.
        let _ = ex.tick_timeout(now + Duration::from_millis(200));
        let next = ex.next_to_execute().expect("stop");
        match next.call {
            ToolCall::RequestStop(_) => {}
            other => panic!("expected stop, got {other:?}"),
        }
    }
}
