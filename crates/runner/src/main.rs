use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::Context;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, tcp::OwnedReadHalf, tcp::OwnedWriteHalf};
use tokio::sync::Mutex;

use rusty_bot_core::agent::game_api::GameApi;
use rusty_bot_core::agent::harness::{HarnessConfig, LlmClient, tick as harness_tick};
use rusty_bot_core::agent::memory::ToolResult;
use rusty_bot_core::agent::observation::Observation;
use rusty_bot_core::agent::tools::{Tool, tool_id_for_call};
use rusty_bot_core::agent::{AgentLoop, ToolCall, ToolInvocation};
use rusty_bot_core::llm::{OllamaConfig, query_ollama_generate};

struct ControlConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

struct RemoteGameApi {
    conn: Mutex<ControlConn>,
}

impl RemoteGameApi {
    async fn connect(addr: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect control port {addr}"))?;
        let (read, write) = stream.into_split();
        Ok(Self {
            conn: Mutex::new(ControlConn {
                reader: BufReader::new(read),
                writer: write,
            }),
        })
    }

    async fn request_json(&self, req: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let line = format!("{req}\n");
        let mut conn = self.conn.lock().await;
        conn.writer
            .write_all(line.as_bytes())
            .await
            .context("control write")?;
        conn.writer.flush().await.ok();

        let mut resp_line = String::new();
        let n = conn
            .reader
            .read_line(&mut resp_line)
            .await
            .context("control read")?;
        if n == 0 {
            anyhow::bail!("control connection closed");
        }
        let v: serde_json::Value =
            serde_json::from_str(resp_line.trim()).context("invalid control json response")?;
        Ok(v)
    }

    fn invocation_to_wire_json(tool: &ToolInvocation) -> serde_json::Value {
        let tool_id = tool_id_for_call(&tool.call);
        let name = tool_id.name();
        let arguments = match &tool.call {
            ToolCall::RequestIdle => json!({}),
            ToolCall::RequestMove(args) => serde_json::to_value(args).unwrap_or(json!({})),
            ToolCall::RequestTurn(args) => serde_json::to_value(args).unwrap_or(json!({})),
            ToolCall::RequestStop(args) => serde_json::to_value(args).unwrap_or(json!({})),
            ToolCall::RequestJump => json!({}),
            ToolCall::RequestEmote(args) => serde_json::to_value(args).unwrap_or(json!({})),
            ToolCall::TargetGuid(args) => serde_json::to_value(args).unwrap_or(json!({})),
            ToolCall::TargetNearestNpc(args) => serde_json::to_value(args).unwrap_or(json!({})),
            ToolCall::Interact(args) => serde_json::to_value(args).unwrap_or(json!({})),
            ToolCall::Cast(args) => serde_json::to_value(args).unwrap_or(json!({})),
            ToolCall::Loot(args) => serde_json::to_value(args).unwrap_or(json!({})),
        };

        json!({
            "schema_version": 1,
            "name": name,
            "confirm": tool.confirm,
            "arguments": arguments,
        })
    }
}

impl GameApi for RemoteGameApi {
    fn observe<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Observation>> + Send + 'a>> {
        Box::pin(async move {
            let v = self.request_json(json!({ "op": "observation" })).await?;
            if v.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                anyhow::bail!("observation failed: {}", v);
            }
            let obs = v
                .get("observation")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing observation in response"))?;
            serde_json::from_value(obs).context("decode observation")
        })
    }

    fn execute_tool<'a>(
        &'a self,
        tool: ToolInvocation,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<ToolResult>> + Send + 'a>> {
        Box::pin(async move {
            let tool_wire = Self::invocation_to_wire_json(&tool);
            let v = self
                .request_json(json!({ "op": "tool_execute", "tool": tool_wire }))
                .await?;
            if v.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                anyhow::bail!("tool_execute failed: {}", v);
            }
            let res = v
                .get("result")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing result in response"))?;
            serde_json::from_value(res).context("decode tool result")
        })
    }
}

struct RunnerLlm {
    cfg: OllamaConfig,
}

impl LlmClient for RunnerLlm {
    fn complete<'a>(
        &'a self,
        prompt: String,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        Box::pin(async move { query_ollama_generate(&prompt, &self.cfg).await })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Defaults from environment variables.
    let mut control_addr = std::env::var("RUSTY_BOT_PROXY_CONTROL_ADDR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1:7878".to_string());

    let mut endpoint = std::env::var("RUSTY_BOT_LLM_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11435/api/generate".to_string());
    let mut model = std::env::var("RUSTY_BOT_LLM_MODEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "mock".to_string());
    let mut system_prompt = std::env::var("RUSTY_BOT_LLM_SYSTEM_PROMPT").unwrap_or_else(|_| {
        "You control a WoW character. Choose exactly one tool call per tick based on STATE_JSON. Prefer safe, minimal actions."
            .to_string()
    });

    let mut goal = std::env::var("RUSTY_BOT_GOAL")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let mut tick_ms: u64 = std::env::var("RUSTY_BOT_AGENT_TICK_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(350);

    // Override with command-line flags.
    // Flags are simple `--flag value` pairs.
    // Unknown flags are ignored with a warning.
    apply_runner_cli_overrides(
        std::env::args().skip(1),
        &mut control_addr,
        &mut endpoint,
        &mut model,
        &mut system_prompt,
        &mut goal,
        &mut tick_ms,
    )?;

    let api = RemoteGameApi::connect(&control_addr).await?;
    let llm = RunnerLlm {
        cfg: OllamaConfig { endpoint, model },
    };

    let mut agent = AgentLoop::new(system_prompt);
    if let Some(goal) = goal {
        agent.memory.set_goal(goal);
    }

    let mut tick = tokio::time::interval(Duration::from_millis(tick_ms));
    loop {
        tick.tick().await;
        let now = Instant::now();
        let _ = harness_tick(&mut agent, &api, &llm, HarnessConfig::default(), now).await?;
    }
}


fn apply_runner_cli_overrides(
    args: impl IntoIterator<Item = String>,
    control_addr: &mut String,
    endpoint: &mut String,
    model: &mut String,
    system_prompt: &mut String,
    goal: &mut Option<String>,
    tick_ms: &mut u64,
) -> anyhow::Result<()> {
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        if !arg.starts_with("--") {
            eprintln!("Unexpected positional argument: {}", arg);
            continue;
        }

        let flag = arg.trim_start_matches("--");
        let Some(val) = it.next() else {
            anyhow::bail!("Expected value after flag: --{flag}");
        };

        match flag {
            "control-addr" => *control_addr = val,
            "llm-endpoint" => *endpoint = val,
            "llm-model" => *model = val,
            "llm-system-prompt" => *system_prompt = val,
            "goal" => *goal = Some(val),
            "tick-ms" => {
                *tick_ms = val
                    .parse()
                    .with_context(|| format!("tick-ms must be a number, got: {val}"))?;
            }
            _ => eprintln!("Unknown flag: --{}", flag),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_bot_core::agent::wire::{MoveDirection, RequestMoveArgs};

    #[test]
    fn invocation_wire_includes_schema_version() {
        let inv = ToolInvocation {
            call: ToolCall::RequestMove(RequestMoveArgs {
                direction: MoveDirection::Forward,
                duration_ms: 200,
            }),
            confirm: false,
        };
        let v = RemoteGameApi::invocation_to_wire_json(&inv);
        assert_eq!(v.get("schema_version").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(v.get("name").and_then(|v| v.as_str()), Some("request_move"));
    }

    #[test]
    fn runner_cli_overrides_apply() {
        let mut control_addr = "127.0.0.1:7878".to_string();
        let mut endpoint = "http://127.0.0.1:11435/api/generate".to_string();
        let mut model = "mock".to_string();
        let mut system_prompt = "default".to_string();
        let mut goal: Option<String> = None;
        let mut tick_ms: u64 = 350;

        apply_runner_cli_overrides(
            vec![
                "--control-addr".to_string(),
                "10.0.0.2:9999".to_string(),
                "--llm-endpoint".to_string(),
                "http://example.invalid/api/generate".to_string(),
                "--llm-model".to_string(),
                "llama".to_string(),
                "--llm-system-prompt".to_string(),
                "prompt".to_string(),
                "--goal".to_string(),
                "win".to_string(),
                "--tick-ms".to_string(),
                "123".to_string(),
            ],
            &mut control_addr,
            &mut endpoint,
            &mut model,
            &mut system_prompt,
            &mut goal,
            &mut tick_ms,
        )
        .unwrap();

        assert_eq!(control_addr, "10.0.0.2:9999");
        assert_eq!(endpoint, "http://example.invalid/api/generate");
        assert_eq!(model, "llama");
        assert_eq!(system_prompt, "prompt");
        assert_eq!(goal.as_deref(), Some("win"));
        assert_eq!(tick_ms, 123);
    }
}
