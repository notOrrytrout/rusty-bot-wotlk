use std::time::{Duration, Instant};

use super::memory::{ToolResult, ToolStatus};
use super::ToolCall;

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutorState {
    Idle,
    Waiting {
        tool: ToolCall,
        issued_at: Instant,
        timeout: Duration,
    },
}

#[derive(Debug, Clone)]
pub struct Executor {
    pub state: ExecutorState,
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            state: ExecutorState::Idle,
        }
    }
}

impl Executor {
    pub fn is_idle(&self) -> bool {
        matches!(self.state, ExecutorState::Idle)
    }

    pub fn start(&mut self, tool: ToolCall, timeout: Duration) {
        self.state = ExecutorState::Waiting {
            tool,
            issued_at: Instant::now(),
            timeout,
        };
    }

    pub fn tick_timeout(&mut self) -> Option<(ToolCall, ToolResult)> {
        let ExecutorState::Waiting {
            tool,
            issued_at,
            timeout,
        } = &self.state
        else {
            return None;
        };

        if issued_at.elapsed() < *timeout {
            return None;
        }

        let tool = tool.clone();
        self.state = ExecutorState::Idle;
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
        let ExecutorState::Waiting { tool, .. } = &self.state else {
            return None;
        };
        let tool = tool.clone();
        self.state = ExecutorState::Idle;
        Some((tool, result))
    }
}

