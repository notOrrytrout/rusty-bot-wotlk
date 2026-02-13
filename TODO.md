# Rusty Bot WotLK Client: Agent Framework TODO

This file is the single checklist we will use to drive work from the current “demo LLM injector” into a real, reliable LLM-driven agent framework.

Scope target: WoW WotLK 3.3.5a-style gameplay automation via the existing gateway proxy that can observe traffic and inject client-like actions.

---

## Already Implemented (Repo Evidence)

### Gateway Proxy (Core)
- [x] Gateway proxy sits between a real WoW client and the server; observes traffic and can inject actions. (`README.md`)
- [x] Proxy binary exists and runs via `cargo run -p rusty-bot-proxy`. (`crates/gateway-proxy/src/main.rs`)
- [x] Config loading exists (TOML). Default config path is under `config/wow/wotlk/connection.toml` (or `RUSTY_BOT_CONFIG_DIR`). (`README.md`, `scripts/run_runner_with_mock.sh`)
- [x] Gateway mode supports `auth_mode = "dual_srp"` (and the proxy currently requires it). (`config/wow/wotlk/connection.toml`, `crates/gateway-proxy/src/proxy.rs`)
- [x] SRP + RC4 primitives exist for WotLK auth/session crypto. (`crates/gateway-proxy/src/wotlk.rs`)

### Observation / World State
- [x] Server packet observation updates a shared `WorldState` on some opcodes:
  - `SMSG_UPDATE_OBJECT` -> updates `WorldState` objects (partial implementation). (`crates/gateway-proxy/src/proxy.rs`, `crates/bot-core/src/world/world_state.rs`)
  - `SMSG_MESSAGECHAT` -> chat log (basic parsing). (`crates/gateway-proxy/src/proxy.rs`)
  - `SMSG_ATTACKERSTATEUPDATE` -> combat log placeholder message. (`crates/gateway-proxy/src/proxy.rs`)
- [x] Client movement observation updates the local player position/orientation/timestamp in `WorldState` when movement packets can be parsed. (`crates/gateway-proxy/src/proxy.rs`)

### Bot Core (World Model + Vision + LLM Adapter)
- [x] `rusty-bot-core` crate exists with world model + vision prompt + minimal LLM client. (`crates/bot-core/src/lib.rs`)
- [x] `WorldState` holds players/NPCs/other players, chat/combat logs, and a tick counter. (`crates/bot-core/src/world/world_state.rs`)
- [x] `WorldState.apply_update_object()` populates partial fields for:
  - player health/max health/level/power type/power/flags
  - visible equipment entries (via visible-item fields)
  - backpack slots (partial)
  - known spells (via player spell id fields)
  - NPC basic fields (health/max health/flags + dynamic fields)
  (`crates/bot-core/src/world/world_state.rs`, `crates/bot-core/src/world/npc_state.rs`)
- [x] Vision prompt generator exists and prints `[BOT_VISION]` sections including player state, nearby NPCs/players, chat/combat logs, talents, inventory, equipment. (`crates/bot-core/src/vision.rs`)
- [x] LLM adapter exists for Ollama-style `POST /api/generate` returning `{"response": "..."}`. (`crates/bot-core/src/llm.rs`)

### Control + Demo LLM Loop (Current “Agent” Prototype)
- [x] Proxy exposes a control TCP port that accepts raw injection lines: `"<opcode_hex> <body_hex>"`. (`crates/gateway-proxy/src/proxy.rs`)
- [x] Demo LLM injector loop exists (polls an Ollama-style endpoint on an interval) and injects one discrete command at a time. (`crates/gateway-proxy/src/proxy.rs`)
- [x] Demo command sanitizer supports (at least): `move forward/backward/left/right`, `move stop`, `turn left/right`, `turn stop`, `strafe stop`, `jump`, `emote <key>` (emotes partial). (`crates/gateway-proxy/src/proxy.rs`)
- [x] Demo injection uses a real-client movement packet template when available; includes simple time advancement and “emergency stop” behavior on LLM failure. (`crates/gateway-proxy/src/proxy.rs`)
- [x] Mock LLM server exists for local dev (`/api/generate`, `/api/chat`) with rotating canned responses. (`scripts/mock_ollama.py`, `scripts/run_runner_with_mock.sh`)

---

## Definitions (What We Are Building Next)

Guiding principle: the LLM chooses *high-level* tool calls; Rust code provides reliability (validation, execution, timeouts, completion checks, retries, safety rails).

MVP high-level goals (first set to support end-to-end):
- [ ] Follow a moving target (player or NPC).
- [ ] Go to nearest NPC and interact (start simple: just approach + interact).
- [ ] Kill a target (very crude: target + cast by slot, stop moving in combat).
- [ ] Loot (requires new observation/state).

---

## Roadmap: Agent Framework (Detailed To-Do)

### 0) Baseline (Prep)
- [x] Create branch `local/agent-framework`.
- [x] Run `cargo test` at workspace root and record current state (pass/fail) in this file under “Notes”.
- [x] Add a single command to run the proxy demo in one line (document only; no code change needed yet):
  - [x] `bash scripts/run_runner_with_mock.sh`
- [x] Inventory runtime env vars currently used by the demo loop (documented from code):
  - [x] `RUSTY_BOT_CONFIG_DIR`
  - [x] `RUSTY_BOT_DEMO`
  - [x] `RUSTY_BOT_REAL_CLIENT`
  - [x] `RUSTY_BOT_LLM_ENDPOINT`
  - [x] `RUSTY_BOT_LLM_MODEL`
  - [x] `RUSTY_BOT_DEMO_USE_VISION`
  - [x] `RUSTY_BOT_LLM_PROMPT`
  - [x] `RUSTY_BOT_DEMO_ECHO_TO_CLIENT`
  - [x] `RUSTY_BOT_DEMO_SUPPRESS_CLIENT_MOVEMENT`

### 1) Contracts (Schemas + Interfaces)
- [ ] Decide where the agent runs:
  - [x] In-proxy process (decision for v1).
  - [ ] Separate runner process (defer until after tool + observation schema stabilizes).
- [ ] Define the LLM output contract:
  - [x] Must emit exactly one `<tool_call>...</tool_call>` block and nothing else.
  - [x] The JSON inside must be an object: `{"name":"...","arguments":{...}}`.
  - [ ] Future: add `schema_version` once we move past the demo tool set.
- [ ] Define tool-call schema (Rust structs + serde):
  - [x] `ToolCallWire { name, arguments }` (wire format inside `<tool_call>`).
  - [x] `name` is validated against a closed set.
  - [x] `arguments` is a per-tool typed struct (v1 parses/validates per tool).
- [ ] Define tool-result schema:
  - [x] `ToolResult { status: ok|failed|retryable, reason, facts }` (request ids deferred).
  - [x] `facts` is a small JSON map for next-turn context.
- [ ] Define `Observation` schema (stable JSON; capped lists):
  - [x] Self state summary
  - [x] Nearby entities summary (top N by distance)
  - [x] Last chat lines (cap)
  - [x] Last combat lines (cap)
  - [x] Derived flags: `moving`, `stuck_suspected` (and deltas for completion checks)
  - [ ] Derived flags: `in_combat` (placeholder until supported)
- [x] Define a `GameApi` trait boundary (agent calls this; proxy implements it):
  - [x] “Inject action” surface (prefer high-level, not opcodes)
  - [x] “Read observation inputs” surface (world snapshot)

### 2) Implement `bot-core` Agent Module (Framework Code)
Add a new module under:
`crates/bot-core/src/agent/`

- [x] `mod.rs` exports:
  - [x] `AgentLoop`
  - [x] `Observation` (type exists; will expand as we add derived facts)
  - [x] `ToolCall`
  - [x] `ToolResult` (type exists; wire-up to execution is next)
  - [x] `Executor` (scaffold exists)
  - [x] `GameApi` trait (trait exists; proxy integration will implement it)
- [x] `observation.rs`:
  - [x] Build `Observation` from `WorldState` (v1).
  - [x] Derived facts (delta-based) needed for completion checks (position + movement time deltas).
- [x] `tools.rs`:
  - [ ] `Tool` trait + tool registry/dispatcher.
  - [x] Tool definitions for MVP movement set (spec helpers: timeout + auto-stop).
- [x] `executor.rs`:
  - [x] Action queue (single-step from LLM + auto-stop follow-up).
  - [x] Timeouts (scaffold).
  - [ ] Retry policy plumbing (max retries, backoff).
  - [ ] Mutual exclusion for continuous movement.
  - [ ] Enforce “stop-after-continuous” even if the LLM forgets.
- [x] `prompt.rs`:
  - [x] Prompt builder using `Observation`, current goal, and allowed tool list (v1).
  - [ ] Hard “JSON only” formatting rules (needs to reflect `<tool_call>` contract, plus stricter guardrails).
  - [x] Include last tool error + history to help the LLM iterate.
- [x] `memory.rs`:
  - [x] Short-term memory: last N tool calls/results; last error string.
  - [ ] Current goal text and a goal id (goal text exists; goal id later).
- [x] Wire into `crates/bot-core/src/lib.rs`.

Acceptance checks
- [x] `cargo test -p rusty-bot-core` passes.
- [ ] Agent module does not depend on gateway-proxy crate types.

### 3) Tooling MVP (Start Small, Make It Reliable)
Initial tool set (based on what demo supports today):
- [ ] `move { direction: forward|backward|left|right, duration_ms }`
- [ ] `turn { direction: left|right, duration_ms }`
- [ ] `stop { kind: move|turn|strafe|all }`
- [ ] `jump {}`
- [ ] `emote { key }`

For each tool:
- [ ] Validate args strictly (reject unknown enums, clamp duration ranges).
- [ ] Define completion logic (timeout + minimal observation deltas).
- [ ] Define retry policy.

Acceptance checks
- [ ] Continuous tools never leave the character “stuck turning/running” if the LLM hangs (executor must auto-stop).

### 4) Proxy Integration (Implement `GameApi`)
- [x] Introduce a proxy-side `GameApi` implementation that wraps existing injection channels + world state.
- [ ] Extract the movement-template injection logic from the demo into reusable methods:
  - [ ] “get template”
  - [ ] “build movement packet for command”
  - [ ] “apply injection guard”
  - [ ] “send packet” (upstream/both routing)
- [x] Replace (or gate behind a new flag) `run_demo_llm_injector` with an agent loop tick:
  - [x] Periodic tick reads observation
  - [x] If executor idle, call LLM for next tool
  - [x] Execute tool and wait for completion (v1: observation + duration-based completion)

Acceptance checks
- [ ] Agent runs with the same `RUSTY_BOT_LLM_ENDPOINT` and still supports `RUSTY_BOT_DEMO_USE_VISION=1`.
- [ ] LLM down/unreachable triggers emergency stop behavior and keeps loop alive.

### 5) LLM Adapter Hardening (Parsing + Guardrails)
- [ ] Strict JSON parse of LLM output into `ToolCall`.
- [ ] On JSON parse failure:
  - [ ] Do not inject anything.
  - [ ] Record an error in memory.
  - [ ] Reprompt with a tighter “return only JSON” instruction and the invalid output included as context.
- [ ] Add rate limiting:
  - [ ] Max LLM calls per minute
  - [ ] Max injections per second
- [ ] Add “dangerous action” gate framework (not used in MVP tools, but required for future):
  - [ ] “requires_confirm” tool metadata
  - [ ] “confirm=true” must be present in args to execute

### 6) Observation Improvements (Make Planning Actually Work)
- [ ] Cap lists and sort nearby entities by distance (top N).
- [ ] Add derived fields needed for completion checks:
  - [ ] `self_guid` (already tracked in injection guard)
  - [ ] `self_pos` and `self_orient`
  - [ ] `last_position_delta`
  - [ ] `client_correction_seen_recently` (already tracked)
- [ ] Add stuck detection v0:
  - [ ] Count repeated move attempts with negligible position delta
  - [ ] Surface `stuck_suspected=true` and a reason

### 7) Goal System (High-Level Commands)
- [ ] Add goal input:
  - [ ] startup env var: `RUSTY_BOT_GOAL`
  - [ ] runtime update (recommended): control port command
- [ ] Define goal lifecycle states:
  - [ ] `active`, `completed`, `blocked`, `aborted`
- [ ] Add goal completion heuristics for the MVP goals.

### 8) Control Port Upgrade (Optional but High Leverage)
Current: raw `opcode_hex body_hex`.

Add a JSON-lines control mode (keep old behavior for manual injection):
- [ ] `{"cmd":"goal_set","goal":"..."}`
- [ ] `{"cmd":"agent_pause"}` / `{"cmd":"agent_resume"}`
- [ ] `{"cmd":"agent_status"}`

Acceptance checks
- [ ] Can query status without a debugger: current goal, last tool, last result, last error.

### 9) Testing Harness (So We Can Move Fast Without Regressions)
- [ ] Unit tests in `rusty-bot-core`:
  - [ ] ToolCall JSON parsing and validation
  - [ ] Executor stop-after-continuous behavior
  - [ ] Retry/backoff logic
  - [ ] Prompt builder includes tool list + “JSON only”
- [ ] Add a “dry run” fake `GameApi` for deterministic integration tests:
  - [ ] Record tool executions
  - [ ] Simulate observation deltas and timeouts

Acceptance checks
- [ ] `cargo test` workspace passes without a server or client running.
- [ ] A test proves: invalid LLM output => zero injections executed.

### 10) First Real Capabilities (After Framework Is Stable)
These depend on new packet support + state tracking; keep them blocked until framework above is solid.
- [ ] Targeting tools:
  - [ ] `target_guid { guid }`
  - [ ] `target_nearest_npc { entry?: u32 }`
- [ ] `interact { guid }` (packet support + completion checks)
- [ ] “Follow target” goal v1 (turn + move + stop loops)
- [ ] Combat v0 (very crude):
  - [ ] `cast { slot }`
  - [ ] stop moving when combat detected
  - [ ] detect “something happened” via combat log/state deltas
- [ ] Loot v0 (requires state additions; define later)

---

## Notes (Keep Short, Update As We Go)
- Date: 2026-02-13
- Workspace: `<repo-root>`
- Baseline: `cargo test` (workspace) PASS (0 tests) on 2026-02-13
