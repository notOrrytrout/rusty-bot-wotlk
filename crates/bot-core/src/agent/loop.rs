use super::executor::Executor;
use super::memory::AgentMemory;
use super::observation::{Observation, ObservationBuilder};
use super::prompt::{PromptConfig, build_control_prompt};
use super::{ToolInvocation, parse_tool_call};

#[derive(Debug)]
pub struct AgentLoop {
    pub system_prompt: String,
    pub prompt_cfg: PromptConfig,
    pub memory: AgentMemory,
    pub executor: Executor,
    pub observation_builder: ObservationBuilder,
}

impl AgentLoop {
    pub fn new(system_prompt: impl Into<String>) -> Self {
        Self {
            system_prompt: system_prompt.into(),
            prompt_cfg: PromptConfig::default(),
            memory: AgentMemory::default(),
            executor: Executor::default(),
            observation_builder: ObservationBuilder::default(),
        }
    }

    pub fn build_prompt(&self, obs: &Observation) -> String {
        build_control_prompt(&self.system_prompt, obs, &self.memory, &self.prompt_cfg)
    }

    pub fn parse_llm_tool_call(&self, raw_llm_text: &str) -> anyhow::Result<ToolInvocation> {
        parse_tool_call(raw_llm_text)
    }
}
