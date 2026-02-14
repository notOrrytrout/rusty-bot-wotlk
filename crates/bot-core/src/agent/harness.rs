use std::future::Future;
use std::pin::Pin;
use std::time::Instant;
use std::{error::Error, fmt};

use super::game_api::GameApi;
use super::memory::{ToolResult, ToolStatus};
use super::tools::ToolMeta;
use super::{AgentLoop, ToolInvocation};

pub trait LlmClient: Send + Sync {
    fn complete<'a>(
        &'a self,
        prompt: String,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>>;
}

/// Signals that the harness should skip LLM polling this tick (e.g. rate limited).
#[derive(Debug)]
pub struct LlmCallSuppressed;

impl fmt::Display for LlmCallSuppressed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "llm_call_suppressed")
    }
}

impl Error for LlmCallSuppressed {}

#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub enable_repair: bool,
    /// Optional prompt suffix appended to the agent-built prompt before calling the LLM.
    pub prompt_suffix: Option<String>,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            enable_repair: true,
            prompt_suffix: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HarnessOutcome {
    /// Observation was processed; no state transition happened.
    Observed,
    /// A tool was offered to the executor from an LLM response.
    Offered { tool: ToolInvocation },
    /// A tool was executed via the API (may still be waiting on observation for continuous tools).
    Executed {
        tool: ToolInvocation,
        result: ToolResult,
    },
    /// A tool completion (observation/timeout/result) was recorded into memory.
    Completed {
        tool: ToolInvocation,
        result: ToolResult,
    },
}

/// One deterministic "tick" of the agent runner logic.
///
/// This is intentionally small and pure: it does not own any timers, threads, or network clients.
/// The gateway-proxy has its own loop; this exists to support deterministic tests and future runner extraction.
pub async fn tick(
    agent: &mut AgentLoop,
    api: &dyn GameApi,
    llm: &dyn LlmClient,
    cfg: HarnessConfig,
    now: Instant,
) -> anyhow::Result<HarnessOutcome> {
    // Observe first. If observation fails, bubble up; callers can choose to continue.
    let obs = api.observe().await?;
    agent.memory.tick_goal_v0(&obs);

    // Combat safety: if combat is detected while a continuous movement tool is active, preempt it
    // with an immediate stop. This keeps the bot from endlessly running while taking damage.
    if obs.derived.in_combat {
        let should_stop = match &agent.executor.state {
            super::executor::ExecutorState::Waiting { tool, .. } => matches!(
                tool.call,
                super::ToolCall::RequestMove(_) | super::ToolCall::RequestTurn(_)
            ),
            _ => false,
        };
        if should_stop {
            agent.executor.offer_llm_tool(super::ToolInvocation {
                call: super::ToolCall::RequestStop(super::wire::RequestStopArgs {
                    kind: super::wire::StopKind::All,
                }),
                confirm: false,
            });
        }
    }

    // Completion checks.
    if let Some((tool, result)) = agent.executor.tick_observation(&obs) {
        agent
            .strategy_engine
            .note_tool_result(obs.tick, &tool, &result);
        agent.memory.record(tool.clone(), result.clone());
        return Ok(HarnessOutcome::Completed { tool, result });
    }
    if let Some((tool, result)) = agent.executor.tick_timeout(now) {
        agent
            .strategy_engine
            .note_tool_result(obs.tick, &tool, &result);
        agent.memory.record(tool.clone(), result.clone());
        return Ok(HarnessOutcome::Completed { tool, result });
    }

    // Execute any queued tools (e.g. auto-stop) before polling the LLM.
    agent.executor.tick_backoff(now);
    if let Some(tool) = agent.executor.next_to_execute() {
        agent.executor.start(tool.clone(), now);
        let res = api.execute_tool(tool.clone()).await?;

        // Continuous tools run until observation/timeouts say they're complete.
        if tool.is_continuous() && res.status == ToolStatus::Ok {
            return Ok(HarnessOutcome::Executed { tool, result: res });
        }

        if let Some((done_tool, done_res)) = agent.executor.complete(now, res) {
            agent
                .strategy_engine
                .note_tool_result(obs.tick, &done_tool, &done_res);
            agent.memory.record(done_tool.clone(), done_res.clone());
            return Ok(HarnessOutcome::Completed {
                tool: done_tool,
                result: done_res,
            });
        }

        return Ok(HarnessOutcome::Observed);
    }

    // Strategy driver: if the executor is idle and has no queued work, allow deterministic
    // strategies (combat behaviors, etc) to offer a tool before goal stepping or LLM polling.
    if agent.executor.is_idle()
        && agent.executor.queued_len() == 0
        && let Some(cand) = agent.strategy_engine.next_action(&obs, &agent.memory)
    {
        let tool = cand.tool;
        agent.executor.offer_llm_tool(tool.clone());
        return Ok(HarnessOutcome::Offered { tool });
    }

    // Goal driver: if the executor is idle and has no queued work, allow a deterministic goal step
    // to offer the next tool before polling the LLM.
    if agent.executor.is_idle()
        && agent.executor.queued_len() == 0
        && agent.memory.goal_state == Some(super::memory::GoalState::Active)
        && let Some(plan) = agent.memory.goal_plan.as_mut()
        && let Some(tool) = plan.step(&obs)
    {
        agent.executor.offer_llm_tool(tool.clone());
        return Ok(HarnessOutcome::Offered { tool });
    }

    // If idle and nothing queued, ask the LLM for the next tool call.
    if agent.executor.is_idle() {
        let mut prompt_str = agent.build_prompt(&obs);
        if let Some(suffix) = cfg.prompt_suffix.as_deref() {
            prompt_str.push_str(suffix);
        }

        let raw = match llm.complete(prompt_str.clone()).await {
            Ok(raw) => raw,
            Err(err) => {
                if err.is::<LlmCallSuppressed>() {
                    return Ok(HarnessOutcome::Observed);
                }
                return Err(err);
            }
        };

        let tool = match agent.parse_llm_tool_call(&raw) {
            Ok(tool) => Some(tool),
            Err(err) => {
                agent.memory.last_error = Some(format!("{err:#}"));

                if !cfg.enable_repair {
                    None
                } else {
                    let repair_instruction = "Your previous response was invalid.\nReturn exactly one <tool_call>...</tool_call> block and nothing else.\nThe JSON must be an object with keys: name, arguments (and optional: confirm, schema_version=1).\n";
                    let repair_prompt = format!(
                        "{prompt_str}\n\n[REPAIR]\n{repair_instruction}\n[INVALID_OUTPUT]\n{raw}\n"
                    );
                    let repair_raw = match llm.complete(repair_prompt).await {
                        Ok(raw) => raw,
                        Err(err) => {
                            if err.is::<LlmCallSuppressed>() {
                                return Ok(HarnessOutcome::Observed);
                            }
                            return Err(err);
                        }
                    };
                    match agent.parse_llm_tool_call(&repair_raw) {
                        Ok(tool) => Some(tool),
                        Err(err) => {
                            agent.memory.last_error = Some(format!("repair_parse_failed: {err:#}"));
                            None
                        }
                    }
                }
            }
        };

        if let Some(tool) = tool {
            agent.executor.offer_llm_tool(tool.clone());
            return Ok(HarnessOutcome::Offered { tool });
        }
    }

    Ok(HarnessOutcome::Observed)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::agent::memory::ToolResult;
    use crate::agent::observation::{DerivedFacts, Observation, SelfSummary, Vec3};
    use crate::agent::wire::{MoveDirection, RequestMoveArgs, RequestStopArgs, StopKind};
    use crate::agent::{ToolCall, ToolInvocation};

    #[derive(Default)]
    struct FakeGameApi {
        observations: Mutex<VecDeque<anyhow::Result<Observation>>>,
        tool_results: Mutex<VecDeque<anyhow::Result<ToolResult>>>,
        executed: Mutex<Vec<ToolInvocation>>,
    }

    impl FakeGameApi {
        fn push_observation(&self, obs: Observation) {
            self.observations.lock().unwrap().push_back(Ok(obs));
        }

        fn push_tool_result(&self, res: ToolResult) {
            self.tool_results.lock().unwrap().push_back(Ok(res));
        }

        fn executed_tools(&self) -> Vec<ToolInvocation> {
            self.executed.lock().unwrap().clone()
        }
    }

    impl GameApi for FakeGameApi {
        fn observe<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Observation>> + Send + 'a>> {
            Box::pin(async move {
                self.observations
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| anyhow::bail!("no observation queued"))
            })
        }

        fn execute_tool<'a>(
            &'a self,
            tool: ToolInvocation,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<ToolResult>> + Send + 'a>> {
            Box::pin(async move {
                self.executed.lock().unwrap().push(tool);
                self.tool_results
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| anyhow::anyhow!("no tool result queued"))?
            })
        }
    }

    #[derive(Default)]
    struct FakeLlm {
        responses: Mutex<VecDeque<anyhow::Result<String>>>,
        prompts: Mutex<Vec<String>>,
    }

    impl FakeLlm {
        fn push_response(&self, raw: impl Into<String>) {
            self.responses.lock().unwrap().push_back(Ok(raw.into()));
        }

        fn prompt_count(&self) -> usize {
            self.prompts.lock().unwrap().len()
        }
    }

    impl LlmClient for FakeLlm {
        fn complete<'a>(
            &'a self,
            prompt: String,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
            Box::pin(async move {
                self.prompts.lock().unwrap().push(prompt);
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| anyhow::bail!("no llm response queued"))
            })
        }
    }

    fn base_obs(tick: u64) -> Observation {
        Observation {
            tick,
            self_guid: 1,
            self_state: Some(SelfSummary {
                guid: 1,
                pos: Vec3 {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                orient: 0.0,
                movement_flags: 0,
                movement_time: tick,
                hp: (1, 1),
                level: 1,
                class: 1,
                race: 1,
                gender: 0,
            }),
            npcs_nearby: vec![],
            players_nearby: vec![],
            chat_log: vec![],
            combat_log: vec![],
            loot: None,
            derived: DerivedFacts::default(),
        }
    }

    fn tool_call_move_forward(duration_ms: u32) -> String {
        format!(
            "<tool_call>{{\"name\":\"request_move\",\"arguments\":{{\"direction\":\"forward\",\"duration_ms\":{duration_ms}}}}}</tool_call>"
        )
    }

    #[tokio::test]
    async fn harness_continuous_move_completes_and_auto_stops() -> anyhow::Result<()> {
        let api = Arc::new(FakeGameApi::default());
        let llm = Arc::new(FakeLlm::default());
        let mut agent = AgentLoop::new("system");

        // Tick 1: observe -> LLM -> offer move tool.
        api.push_observation(base_obs(1));
        llm.push_response(tool_call_move_forward(150));
        let now = Instant::now();
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;
        assert!(matches!(out, HarnessOutcome::Offered { .. }));

        // Tick 2: execute move (continuous OK keeps waiting on observation).
        api.push_observation(base_obs(2));
        api.push_tool_result(ToolResult {
            status: ToolStatus::Ok,
            reason: "injected".to_string(),
            facts: serde_json::Value::Null,
        });
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;
        assert!(matches!(out, HarnessOutcome::Executed { .. }));

        // Tick 3: observe movement delta -> complete move and enqueue stop.
        let mut moved = base_obs(3);
        moved.derived.self_dist_moved = Some(0.30);
        api.push_observation(moved);
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;
        assert!(matches!(
            out,
            HarnessOutcome::Completed {
                result: ToolResult {
                    status: ToolStatus::Ok,
                    ..
                },
                ..
            }
        ));

        // Tick 4: execute the auto-stop.
        api.push_observation(base_obs(4));
        api.push_tool_result(ToolResult {
            status: ToolStatus::Ok,
            reason: "stopped".to_string(),
            facts: serde_json::Value::Null,
        });
        let _ = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;

        let executed = api.executed_tools();
        assert_eq!(executed.len(), 2);
        assert!(matches!(
            executed[0].call,
            ToolCall::RequestMove(RequestMoveArgs {
                direction: MoveDirection::Forward,
                duration_ms: 150
            })
        ));
        assert!(matches!(
            executed[1].call,
            ToolCall::RequestStop(RequestStopArgs {
                kind: StopKind::Move
            })
        ));

        Ok(())
    }

    #[tokio::test]
    async fn harness_preempts_continuous_movement_when_in_combat() -> anyhow::Result<()> {
        let api = Arc::new(FakeGameApi::default());
        let llm = Arc::new(FakeLlm::default());
        let mut agent = AgentLoop::new("system");

        // Tick 1: offer move.
        api.push_observation(base_obs(1));
        llm.push_response(tool_call_move_forward(500));
        let now = Instant::now();
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;
        assert!(matches!(out, HarnessOutcome::Offered { .. }));

        // Tick 2: execute move (continuous OK keeps waiting on observation).
        api.push_observation(base_obs(2));
        api.push_tool_result(ToolResult {
            status: ToolStatus::Ok,
            reason: "injected".to_string(),
            facts: serde_json::Value::Null,
        });
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;
        assert!(matches!(out, HarnessOutcome::Executed { .. }));

        // Tick 3: combat detected -> preempt move with a stop (no extra LLM poll).
        let mut obs = base_obs(3);
        obs.derived.in_combat = true;
        api.push_observation(obs);
        api.push_tool_result(ToolResult {
            status: ToolStatus::Ok,
            reason: "stopped".to_string(),
            facts: serde_json::Value::Null,
        });
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;
        assert!(matches!(out, HarnessOutcome::Completed { .. }));
        assert_eq!(llm.prompt_count(), 1);

        let executed = api.executed_tools();
        assert_eq!(executed.len(), 2);
        assert!(matches!(executed[0].call, ToolCall::RequestMove(_)));
        assert!(matches!(executed[1].call, ToolCall::RequestStop(_)));

        Ok(())
    }

    #[tokio::test]
    async fn harness_defends_against_last_attacker_when_in_combat() -> anyhow::Result<()> {
        let api = Arc::new(FakeGameApi::default());
        let llm = Arc::new(FakeLlm::default());
        let mut agent = AgentLoop::new("system");

        let mut obs = base_obs(1);
        obs.derived.in_combat = true;
        obs.derived.attacker_guid = Some(9);
        api.push_observation(obs);

        let now = Instant::now();
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;

        match out {
            HarnessOutcome::Offered { tool } => match tool.call {
                ToolCall::Cast(args) => {
                    assert_eq!(args.slot, 1);
                    assert_eq!(args.guid, Some(9));
                }
                other => panic!("expected cast, got {other:?}"),
            },
            other => panic!("expected offered, got {other:?}"),
        }

        // This defensive step should not have required an LLM poll.
        assert_eq!(llm.prompt_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn harness_goal_goto_entry_offers_tools_without_llm_poll() -> anyhow::Result<()> {
        let api = Arc::new(FakeGameApi::default());
        let llm = Arc::new(FakeLlm::default());
        let mut agent = AgentLoop::new("system");
        agent.memory.set_goal("goto npc_entry=55 interact");

        // Observation includes the matching NPC.
        let mut obs = base_obs(1);
        obs.npcs_nearby
            .push(crate::agent::observation::EntitySummary {
                guid: 9,
                entry: Some(55),
                pos: Vec3 {
                    x: 10.0,
                    y: 0.0,
                    z: 0.0,
                },
                hp: None,
            });
        api.push_observation(obs);

        let now = Instant::now();
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;

        // First tool should be targeting, and no LLM prompt should have been made.
        assert!(matches!(out, HarnessOutcome::Offered { .. }));
        assert_eq!(llm.prompt_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn harness_repair_reprompt_is_one_shot() -> anyhow::Result<()> {
        let api = FakeGameApi::default();
        let llm = FakeLlm::default();
        let mut agent = AgentLoop::new("system");

        api.push_observation(base_obs(1));
        llm.push_response("this is not a tool call");
        llm.push_response(tool_call_move_forward(150));

        let now = Instant::now();
        let out = tick(&mut agent, &api, &llm, HarnessConfig::default(), now).await?;
        assert!(matches!(out, HarnessOutcome::Offered { .. }));
        assert_eq!(llm.prompt_count(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn harness_invalid_llm_output_never_executes_tools() -> anyhow::Result<()> {
        let api = Arc::new(FakeGameApi::default());
        let llm = Arc::new(FakeLlm::default());
        let mut agent = AgentLoop::new("system");

        api.push_observation(base_obs(1));
        llm.push_response("not a tool call");
        llm.push_response("still not a tool call");

        let now = Instant::now();
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;

        assert!(matches!(out, HarnessOutcome::Observed));
        assert_eq!(api.executed_tools().len(), 0);
        assert_eq!(llm.prompt_count(), 2);
        assert!(agent.memory.last_error.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn harness_stuck_move_fails_and_auto_stops() -> anyhow::Result<()> {
        let api = Arc::new(FakeGameApi::default());
        let llm = Arc::new(FakeLlm::default());
        let mut agent = AgentLoop::new("system");

        // Tick 1: offer move.
        api.push_observation(base_obs(1));
        llm.push_response(tool_call_move_forward(150));
        let now = Instant::now();
        let _ = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;

        // Tick 2: execute move.
        api.push_observation(base_obs(2));
        api.push_tool_result(ToolResult {
            status: ToolStatus::Ok,
            reason: "injected".to_string(),
            facts: serde_json::Value::Null,
        });
        let _ = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;

        // Tick 3: stuck suspected -> move completes with Failed and stop is queued.
        let mut stuck = base_obs(3);
        stuck.derived.stuck_suspected = true;
        stuck.derived.stuck_reason = Some("translating_no_progress".to_string());
        api.push_observation(stuck);
        let out = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;
        assert!(matches!(
            out,
            HarnessOutcome::Completed {
                result: ToolResult {
                    status: ToolStatus::Failed,
                    ..
                },
                ..
            }
        ));

        // Tick 4: execute auto-stop.
        api.push_observation(base_obs(4));
        api.push_tool_result(ToolResult {
            status: ToolStatus::Ok,
            reason: "stopped".to_string(),
            facts: serde_json::Value::Null,
        });
        let _ = tick(
            &mut agent,
            api.as_ref(),
            llm.as_ref(),
            HarnessConfig::default(),
            now,
        )
        .await?;

        let executed = api.executed_tools();
        assert_eq!(executed.len(), 2);
        assert!(matches!(executed[0].call, ToolCall::RequestMove(_)));
        assert!(matches!(executed[1].call, ToolCall::RequestStop(_)));

        Ok(())
    }

    #[tokio::test]
    async fn harness_retryable_result_enters_backoff_and_does_not_poll_llm() -> anyhow::Result<()> {
        let api = FakeGameApi::default();
        let llm = FakeLlm::default();
        let mut agent = AgentLoop::new("system");

        // Tick 1: offer move.
        api.push_observation(base_obs(1));
        llm.push_response(tool_call_move_forward(150));
        let now = Instant::now();
        let _ = tick(&mut agent, &api, &llm, HarnessConfig::default(), now).await?;
        assert_eq!(llm.prompt_count(), 1);

        // Tick 2: execute move but tool execution returns Retryable -> enters backoff.
        api.push_observation(base_obs(2));
        api.push_tool_result(ToolResult {
            status: ToolStatus::Retryable,
            reason: "rate_limited".to_string(),
            facts: serde_json::Value::Null,
        });
        let out = tick(&mut agent, &api, &llm, HarnessConfig::default(), now).await?;
        assert!(matches!(
            out,
            HarnessOutcome::Completed {
                result: ToolResult {
                    status: ToolStatus::Retryable,
                    ..
                },
                ..
            }
        ));
        assert_eq!(llm.prompt_count(), 1);

        // Tick 3: before backoff expiry, should not poll LLM.
        api.push_observation(base_obs(3));
        let _ = tick(
            &mut agent,
            &api,
            &llm,
            HarnessConfig::default(),
            now + Duration::from_millis(50),
        )
        .await?;
        assert_eq!(llm.prompt_count(), 1);

        // Tick 4: after backoff, tool should be re-queued and executed again.
        api.push_observation(base_obs(4));
        api.push_tool_result(ToolResult {
            status: ToolStatus::Ok,
            reason: "injected".to_string(),
            facts: serde_json::Value::Null,
        });
        let out = tick(
            &mut agent,
            &api,
            &llm,
            HarnessConfig::default(),
            now + Duration::from_secs(10),
        )
        .await?;
        assert!(matches!(out, HarnessOutcome::Executed { .. }));

        Ok(())
    }
}
