use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::ToolInvocation;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Ok,
    Failed,
    Retryable,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ToolResult {
    pub status: ToolStatus,
    pub reason: String,
    #[serde(default)]
    pub facts: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct HistoryEntry {
    pub tool: ToolInvocation,
    pub result: ToolResult,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentMemory {
    pub goal: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub history: VecDeque<HistoryEntry>,
    pub history_limit: usize,
}

impl Default for AgentMemory {
    fn default() -> Self {
        Self {
            goal: None,
            last_error: None,
            history: VecDeque::new(),
            history_limit: 12,
        }
    }
}

impl AgentMemory {
    pub fn set_goal(&mut self, goal: impl Into<String>) {
        self.goal = Some(goal.into());
    }

    pub fn clear_goal(&mut self) {
        self.goal = None;
    }

    pub fn record(&mut self, tool: ToolInvocation, result: ToolResult) {
        self.last_error = match result.status {
            ToolStatus::Ok => None,
            ToolStatus::Failed | ToolStatus::Retryable => Some(result.reason.clone()),
        };

        self.history.push_back(HistoryEntry { tool, result });
        while self.history.len() > self.history_limit {
            self.history.pop_front();
        }
    }
}
