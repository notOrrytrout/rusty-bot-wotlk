//! Agent framework primitives: tool-call parsing/validation and shared types.
//!
//! This is intentionally small to start: we lock down the `<tool_call>...</tool_call>` contract
//! and translate it into typed tool calls. Execution lives in the proxy for now.

mod wire;

pub use wire::{
    extract_tool_call_json, parse_tool_call, ToolCall, ToolCallWire, ToolParseError,
};

