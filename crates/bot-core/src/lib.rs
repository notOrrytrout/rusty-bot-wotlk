//! Shared bot core primitives: world model, vision prompt, and LLM client.
//!
//! This crate is extracted from `testllm/` so multiple binaries (proxy, headless
//! experiments, etc.) can share the same state model + prompting/LLM adapters.

pub mod llm;
pub mod agent;
pub mod player;
pub mod vision;
pub mod world;
