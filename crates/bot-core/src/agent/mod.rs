//! Agent framework primitives: tool-call parsing/validation and shared types.
//!
//! This is intentionally small to start: we lock down the `<tool_call>...</tool_call>` contract
//! and translate it into typed tool calls.
//!
//! Execution currently lives in the proxy. This module provides the stable contracts and
//! scaffolding (observation, memory, prompt building) that the proxy can use.

pub mod executor;
pub mod game_api;
pub mod r#loop;
pub mod memory;
pub mod observation;
pub mod prompt;
pub mod tools;
pub mod wire;

pub use wire::{
    extract_tool_call_json, parse_tool_call, ToolCall, ToolCallWire, ToolParseError,
};

pub use r#loop::AgentLoop;
