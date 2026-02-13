use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::memory::{ToolResult, ToolStatus};
use super::observation::Observation;
use super::tools::{auto_stop_after, default_timeout, is_continuous};
use super::{ToolCall, ToolInvocation};

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 4,
            base_backoff: Duration::from_millis(150),
            max_backoff: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutorState {
    Idle,
    Backoff {
        tool: ToolInvocation,
        next_attempt_at: Instant,
        attempt: u32,
        last_reason: String,
    },
    Waiting {
        tool: ToolInvocation,
        issued_at: Instant,
        timeout: Duration,
        stop_after: Option<ToolInvocation>,
        attempt: u32,
    },
}

#[derive(Debug, Clone)]
pub struct Executor {
    queue: VecDeque<ToolInvocation>,
    pub state: ExecutorState,
    pub retry: RetryPolicy,
    pending_attempt: Option<u32>,
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            state: ExecutorState::Idle,
            retry: RetryPolicy::default(),
            pending_attempt: None,
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
        self.pending_attempt = None;
        if matches!(self.state, ExecutorState::Backoff { .. }) {
            // If the LLM chooses something else, abandon any internal retry backoff.
            self.state = ExecutorState::Idle;
        }
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
        let attempt = self.pending_attempt.take().unwrap_or(0);
        self.state = ExecutorState::Waiting {
            tool,
            issued_at: now,
            timeout,
            stop_after,
            attempt,
        };
    }

    pub fn tick_backoff(&mut self, now: Instant) {
        let ExecutorState::Backoff {
            tool,
            next_attempt_at,
            attempt,
            last_reason: _,
        } = &self.state
        else {
            return;
        };

        if now < *next_attempt_at {
            return;
        }

        let tool = tool.clone();
        let attempt = *attempt;
        self.state = ExecutorState::Idle;

        // Re-run the same tool after backoff. Store attempt count by re-starting with it.
        // We don't expose attempt in ToolInvocation; it's internal reliability behavior.
        self.pending_attempt = Some(attempt);
        self.queue.push_front(tool);
    }

    pub fn tick_timeout(&mut self, now: Instant) -> Option<(ToolInvocation, ToolResult)> {
        let ExecutorState::Waiting {
            tool,
            issued_at,
            timeout,
            stop_after,
            attempt: _,
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

    fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        // attempt=1 -> base_backoff * 2^0; attempt=2 -> base_backoff * 2^1; ...
        let pow = attempt.saturating_sub(1).min(10);
        let ms = self.retry.base_backoff.as_millis() as u64;
        let factor = 1u64.checked_shl(pow).unwrap_or(u64::MAX);
        let backoff_ms = ms.saturating_mul(factor);
        let backoff = Duration::from_millis(backoff_ms);
        backoff.min(self.retry.max_backoff)
    }

    pub fn complete(
        &mut self,
        now: Instant,
        mut result: ToolResult,
    ) -> Option<(ToolInvocation, ToolResult)> {
        let ExecutorState::Waiting {
            tool,
            stop_after,
            attempt,
            ..
        } = &self.state
        else {
            return None;
        };
        let tool = tool.clone();
        let stop_after = stop_after.clone();
        let attempt = *attempt;

        // Retry policy: if the tool execution is retryable, schedule it again with backoff and
        // suppress stop-after followups (we didn't successfully start a continuous action).
        if result.status == ToolStatus::Retryable {
            let next_attempt = attempt.saturating_add(1);
            if next_attempt <= self.retry.max_retries {
                let delay = self.backoff_for_attempt(next_attempt);
                self.state = ExecutorState::Backoff {
                    tool: tool.clone(),
                    next_attempt_at: now + delay,
                    attempt: next_attempt,
                    last_reason: result.reason.clone(),
                };
            } else {
                self.state = ExecutorState::Idle;
                result.status = ToolStatus::Failed;
                result.reason = format!("retry_exhausted: {}", result.reason);
            }
            return Some((tool, result));
        }

        self.state = ExecutorState::Idle;

        if result.status == ToolStatus::Ok && is_continuous(&tool.call) {
            if let Some(stop_tool) = stop_after {
                self.queue.push_front(stop_tool);
            }
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

    #[test]
    fn retryable_results_schedule_backoff_and_retry() {
        let mut ex = Executor::default();
        let tool = ToolInvocation {
            call: ToolCall::RequestMove(RequestMoveArgs {
                direction: MoveDirection::Forward,
                duration_ms: 150,
            }),
            confirm: false,
        };

        let now = Instant::now();
        ex.start(tool.clone(), now);
        let (done_tool, done_res) = ex
            .complete(
                now,
                ToolResult {
                    status: ToolStatus::Retryable,
                    reason: "rate_limited".to_string(),
                    facts: serde_json::Value::Null,
                },
            )
            .expect("complete");
        assert_eq!(done_tool, tool);
        assert_eq!(done_res.status, ToolStatus::Retryable);

        match ex.state {
            ExecutorState::Backoff { attempt, .. } => assert_eq!(attempt, 1),
            other => panic!("expected backoff, got {other:?}"),
        }

        // After backoff expiry, the tool should be queued again.
        ex.tick_backoff(now + Duration::from_secs(10));
        assert!(matches!(ex.state, ExecutorState::Idle));
        let next = ex.next_to_execute().expect("retry tool");
        assert_eq!(next, tool);
    }
}
