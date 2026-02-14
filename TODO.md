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
  - `SMSG_UPDATE_OBJECT` -> updates `WorldState` objects (block count, packed GUIDs, create/values/movement, out-of-range removals; still partial field coverage). (`crates/gateway-proxy/src/proxy.rs`, `crates/bot-core/src/world/world_state.rs`)
  - `SMSG_MESSAGECHAT` -> chat log (basic parsing). (`crates/gateway-proxy/src/proxy.rs`)
  - `SMSG_ATTACKERSTATEUPDATE` -> combat log placeholder message. (`crates/gateway-proxy/src/proxy.rs`)
- [x] Client movement observation updates the local player position/orientation/timestamp in `WorldState` when movement packets can be parsed. (`crates/gateway-proxy/src/proxy.rs`)

### Bot Core (World Model + Vision + LLM Adapter)
- [x] `rusty-bot-core` crate exists with world model + vision prompt + minimal LLM client. (`crates/bot-core/src/lib.rs`)
- [x] `WorldState` holds players/NPCs/other players, chat/combat logs, and a tick counter. (`crates/bot-core/src/world/world_state.rs`)
- [x] `WorldState.apply_update_object()` populates partial fields for:
  - entity position/orientation/timestamp for create + movement update types (subset of movement formats)
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
- [x] Control TCP port also accepts NDJSON control messages for agent commands (`op=status|agent_enable|set_goal|clear_goal|inject`). (`crates/gateway-proxy/src/proxy.rs`)
- [x] In-proxy agent loop polls an Ollama-style endpoint on an interval and injects one tool call at a time. (`crates/gateway-proxy/src/proxy.rs`)
- [x] Injection uses a real-client movement packet template when available; includes “emergency stop” behavior on LLM failure. (`crates/gateway-proxy/src/proxy.rs`)
- [x] Mock LLM server exists for local dev (`/api/generate`, `/api/chat`) with rotating canned responses. (`scripts/mock_ollama.py`, `scripts/run_runner_with_mock.sh`)

---

## Needs Attention (Repo Hygiene / Docs)

- [x] Fix/replace stale crate-level README: `crates/bot-core/README.md` currently describes a different project (AzerothClient), incorrect license, and features not present in this repo.
- [x] Decide what to do with stray/duplicate file `crates/bot-core/Cargo copy.toml` (appears to be an accidental duplicate; delete or document why it exists).

---

## Definitions (What We Are Building Next)

Guiding principle: the LLM chooses *high-level* tool calls; Rust code provides reliability (validation, execution, timeouts, completion checks, retries, safety rails).

MVP high-level goals (first set to support end-to-end):
- [x] Follow a moving target (player or NPC). (v0: deterministic goal step with visible target guid/entry)
- [x] Go to NPC and interact (start simple: approach + interact). (v0: deterministic goal step with visible npc entry/guid)
- [x] Kill a target (very crude: target + cast by slot, stop moving in combat). (v0: `kill ...` goal + `cast` uses attackswing)
- [ ] Loot (requires new observation/state).

---

## Roadmap: Agent Framework (Detailed To-Do)

### 0) Baseline (Prep)
- [x] Create branch `local/agent-framework`.
- [x] Run `cargo test` at workspace root and record current state (pass/fail) in this file under “Notes”.
- [x] Add a single command to run the proxy demo in one line (document only; no code change needed yet):
  - [x] `bash scripts/run_runner_with_mock.sh`
- [x] Inventory runtime env vars currently used (from code + scripts):
  - [x] `RUSTY_BOT_CONFIG_DIR`
  - [x] `RUSTY_BOT_AGENT_ENABLED`
  - [x] `RUSTY_BOT_REAL_CLIENT` (scripts only; not read by proxy code)
  - [x] `RUSTY_BOT_LLM_ENDPOINT`
  - [x] `RUSTY_BOT_LLM_MODEL`
  - [x] `RUSTY_BOT_LLM_SYSTEM_PROMPT`
  - [x] `RUSTY_BOT_AGENT_USE_VISION`
  - [x] `RUSTY_BOT_GOAL`
  - [x] `RUSTY_BOT_LLM_MAX_CALLS_PER_MIN`
  - [x] `RUSTY_BOT_INJECT_MAX_PER_SEC`
  - [x] `RUSTY_BOT_HUMAN_OVERRIDE_MS`
  - [x] `RUSTY_BOT_DUMP_UPDATE_OBJECT` (debug; prints first few SMSG_UPDATE_OBJECT payload prefixes)
  - [x] `RUSTY_BOT_DUMP_UPDATE_OBJECT_LIMIT`
  - [x] `RUSTY_BOT_UNSAFE_ECHO_INJECTED_TO_CLIENT`
  - [x] `RUSTY_BOT_SUPPRESS_CLIENT_MOVEMENT`

### 1) Contracts (Schemas + Interfaces)
- [x] Decide where the agent runs:
  - [x] In-proxy process (decision for v1).
- [x] Define the LLM output contract:
  - [x] Must emit exactly one `<tool_call>...</tool_call>` block and nothing else.
  - [x] The JSON inside must be an object: `{"name":"...","arguments":{...}}`.
- [x] Define tool-call schema (Rust structs + serde):
  - [x] `ToolCallWire { name, arguments }` (wire format inside `<tool_call>`).
  - [x] `name` is validated against a closed set.
  - [x] `arguments` is a per-tool typed struct (v1 parses/validates per tool).
- [x] Define tool-result schema:
  - [x] `ToolResult { status: ok|failed|retryable, reason, facts }` (request ids deferred).
  - [x] `facts` is a small JSON map for next-turn context.
- [x] Define `Observation` schema (stable JSON; capped lists):
  - [x] Self state summary
  - [x] Nearby entities summary (top N by distance)
  - [x] Last chat lines (cap)
  - [x] Last combat lines (cap)
  - [x] Derived flags: `moving`, `stuck_suspected` (and deltas for completion checks)
  - [x] Derived flags: `in_combat` (v0 heuristic; will improve with real combat state)
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
  - [x] `Tool` trait + tool registry/dispatcher.
  - [x] Tool definitions for MVP movement set (spec helpers: timeout + auto-stop).
- [x] `executor.rs`:
  - [x] Action queue (single-step from LLM + auto-stop follow-up).
  - [x] Timeouts (scaffold).
  - [x] Retry policy plumbing (max retries, backoff).
  - [x] Mutual exclusion for continuous movement (continuous tools are preempted with a stop-first).
  - [x] Enforce “stop-after-continuous” even if the LLM forgets.
- [x] `prompt.rs`:
  - [x] Prompt builder using `Observation`, current goal, and allowed tool list (v1).
  - [x] Hard “JSON only” formatting rules (explicit `<tool_call>` contract; no markdown/code fences).
  - [x] Include last tool error + history to help the LLM iterate.
- [x] `memory.rs`:
  - [x] Short-term memory: last N tool calls/results; last error string.
  - [x] Current goal text and a goal id (goal text exists; goal id later).
- [x] Wire into `crates/bot-core/src/lib.rs`.

Acceptance checks
- [x] `cargo test -p rusty-bot-core` passes.
- [x] Agent module does not depend on gateway-proxy crate types.

### 3) Tooling MVP (Start Small, Make It Reliable)
Initial tool set (based on what demo supports today):
- [x] `request_move { direction: forward|backward|left|right, duration_ms }`
- [x] `request_turn { direction: left|right, duration_ms }`
- [x] `request_stop { kind: move|turn|strafe|all }`
- [x] `request_jump {}`
- [x] `request_emote { key }`

For each tool:
  - [x] Validate args strictly (reject unknown enums, clamp duration ranges).
  - [x] Define completion logic (timeout + minimal observation deltas).
  - [x] Define retry policy (executor backoff for `Retryable` results).

Acceptance checks
- [x] Continuous tools never leave the character “stuck turning/running” if the LLM hangs (executor must auto-stop).

### 4) Proxy Integration (Implement `GameApi`)
- [x] Introduce a proxy-side `GameApi` implementation that wraps existing injection channels + world state.
- [x] Extract the movement-template injection logic from the demo into reusable methods:
  - [x] “get template”
  - [x] “build movement packet for command”
  - [x] “apply injection guard”
  - [x] “send packet” (upstream/both routing)
- [x] Remove legacy demo injector and run the agent loop tick in-proxy:
  - [x] Periodic tick reads observation
  - [x] If executor idle, call LLM for next tool
  - [x] Execute tool and wait for completion (v1: observation + duration-based completion)

Acceptance checks
- [x] Agent runs with the same `RUSTY_BOT_LLM_ENDPOINT` and still supports `RUSTY_BOT_AGENT_USE_VISION=1`.
- [x] LLM down/unreachable triggers emergency stop behavior and keeps loop alive.

### Release Hygiene (Later)
- [ ] Major release: default verbose proxy/agent debug logging OFF (make it opt-in via env/config); keep current defaults during active development.

### Deferred / Later (Not Needed For MVP Loop Stability)
- [ ] Separate runner process (proxy stays “dumb”, runner connects over control/IPC and drives it)
- [ ] Add `schema_version` to the `<tool_call>` JSON once we move past the demo tool set

### 5) LLM Adapter Hardening (Parsing + Guardrails)
- [x] Strict JSON parse of LLM output into `<tool_call>` -> `ToolInvocation` (validated).
- [x] On JSON parse failure:
  - [x] Do not inject anything.
  - [x] Record an error in memory.
  - [x] Reprompt with a tighter instruction and the invalid output included as context (one-shot repair).
- [x] Add rate limiting:
  - [x] Max LLM calls per minute (`RUSTY_BOT_LLM_MAX_CALLS_PER_MIN`)
  - [x] Max injections per second (`RUSTY_BOT_INJECT_MAX_PER_SEC`)
- [x] Add “dangerous action” gate framework (not used in MVP tools, but required for future):
  - [x] “requires_confirm” tool metadata (scaffold)
  - [x] “confirm=true” must be present in args to execute (scaffold)

### 6) Observation Improvements (Make Planning Actually Work)
- [x] Cap lists and sort nearby entities by distance (top N).
- [x] Add derived fields needed for completion checks:
  - [x] `self_guid` (top-level `Observation.self_guid`)
  - [x] `self_pos` and `self_orient` (`Observation.self_state.pos`, `Observation.self_state.orient`)
  - [x] `last_position_delta` (`Observation.derived.self_pos_delta` + `self_dist_moved`)
  - [x] `client_correction_seen_recently` (`Observation.derived.client_correction_seen_recently`)
- [x] Add stuck detection v0:
  - [x] Count repeated move attempts with negligible position delta (`ObservationBuilder.stuck_frames`)
  - [x] Surface `stuck_suspected=true` and a reason (`Observation.derived.stuck_reason`)
- [x] Track combat attacker GUID and spell cooldowns from server packets:
  - [x] `SMSG_ATTACKERSTATEUPDATE` -> `derived.attacker_guid` (best-effort)
  - [x] `SMSG_SPELL_COOLDOWN` / `SMSG_COOLDOWN_EVENT` / `SMSG_MODIFY_COOLDOWN` -> tick-based spell cooldown map (best-effort)

### 7) Testing Harness (So We Can Move Fast Without Regressions)
- [x] Unit tests in `rusty-bot-core`:
  - [x] ToolCall JSON parsing and validation (`crates/bot-core/src/agent/wire.rs`)
  - [x] Executor stop-after-continuous behavior (`crates/bot-core/src/agent/executor.rs`)
  - [x] Retry/backoff logic (`crates/bot-core/src/agent/executor.rs`)
  - [x] Prompt builder includes tool list + “JSON only” (snapshot tests still TBD)
- [x] Add a “dry run” fake `GameApi` for deterministic integration tests:
  - [x] Record tool executions (`crates/bot-core/src/agent/harness.rs`)
  - [x] Simulate observation deltas and timeouts (`crates/bot-core/src/agent/harness.rs`)

Acceptance checks
- [x] `cargo test` workspace passes without a server or client running.
- [x] A test proves: invalid LLM output => zero injections executed. (`crates/bot-core/src/agent/harness.rs`)
- [x] Cooldown packets and attacker state parsing have unit tests in `gateway-proxy`.

### 8) Goal System (High-Level Commands)
- [x] Add goal input:
  - [x] startup env var: `RUSTY_BOT_GOAL`
  - [x] runtime update (recommended): control port command (`crates/gateway-proxy/src/proxy.rs`)
- [x] Define goal lifecycle states:
  - [x] `active`, `completed`, `blocked`, `aborted` (v0 state tracking)
- [x] Add goal completion heuristics for the MVP goals. (v0 heuristics: stop/idle completion + blocked when self-state missing)

### 9) Control Port Upgrade (Optional but High Leverage)
Current: raw `opcode_hex body_hex`.

Add a JSON-lines control mode (keep old behavior for manual injection):
- [x] Define control protocol schema (`serde` enums)
- [x] Implement JSON parsing (NDJSON, one JSON object per line)
- [x] Reject invalid control messages (reply `{"ok":false,"error":"..."}`)
- [x] Add `version` field for protocol (optional; defaults to v1 if omitted)

Agent controls:
- [x] Pause/resume agent loop (`{"op":"agent_enable","enabled":false|true}`)
- [x] Set/clear goal (`{"op":"set_goal","goal":"..."}`, `{"op":"clear_goal"}`)
- [x] Query status (`{"op":"status"}` includes goal + last_error + executor_state)
- [x] Force emergency stop (disable agent sends stop packets)
- [x] Inject manual *tool call* (not raw packet injection) (`{"op":"tool","tool":{...}}`)
- [x] Execute a discrete tool immediately (bypasses executor loop) (`{"op":"tool_execute","tool":{...}}`)
- [x] Query current observation snapshot (`{"op":"observation"}`)

Raw injection (existing + kept):
- [x] Inject raw packet via JSON wrapper (`{"op":"inject","opcode":"0x....","body_hex":"..."}`) or legacy `opcode_hex body_hex`

Acceptance checks
- [x] Can query status without a debugger: enabled, current goal, last error, executor state.

### 10) First Real Capabilities (After Framework Is Stable)
These depend on new packet support + state tracking; keep them blocked until framework above is solid.
- [x] Targeting tools:
  - [x] Tool-call schema + validation exists in `rusty-bot-core` (`crates/bot-core/src/agent/wire.rs`)
  - [x] Proxy packet injection (v0) for `target_guid` and `target_nearest_npc` (`crates/gateway-proxy/src/proxy.rs`)
  - [x] `target_guid { guid }` (v0: `CMSG_SET_SELECTION`)
  - [x] `target_nearest_npc { entry?: u32 }` (v0: chooses nearest from `WorldState`)
- [x] `interact { guid }` (packet support + completion checks) (v0: `CMSG_GOSSIP_HELLO`)
  - [x] Tool-call schema + validation exists in `rusty-bot-core` (`crates/bot-core/src/agent/wire.rs`)
  - [x] Proxy packet injection (v0) for `interact` via `CMSG_GOSSIP_HELLO` (`crates/gateway-proxy/src/proxy.rs`)
- [x] “Follow target” goal v1 (turn + move + stop loops)
- [x] Combat v0 (very crude):
  - [x] Tool-call schema + validation exists in `rusty-bot-core` (`crates/bot-core/src/agent/wire.rs`)
  - [x] Proxy packet injection (v0) for `cast` implemented as `CMSG_ATTACKSWING` when `guid` is provided (`crates/gateway-proxy/src/proxy.rs`)
  - [x] `cast { slot, guid? }` (v0: implemented as attackswing; real cast/use-action is later)
  - [x] stop moving when combat detected (v0: preempt continuous movement when `derived.in_combat`)
  - [x] detect “something happened” via combat log/state deltas (v0: `derived.in_combat`)
- [ ] Loot v0 (requires state additions; define later)

---

## Notes (Keep Short, Update As We Go)
- Date: 2026-02-14
- Workspace: `<repo-root>`
- Baseline: `cargo test` (workspace) PASS on 2026-02-14
