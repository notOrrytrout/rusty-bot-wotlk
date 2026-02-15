<!--
This is the "current" TODO list. Historical roadmap/checklists live in:
- TODOstage1.md
-->

# Rusty Bot WotLK: TODO (Stage 2)

Last refreshed: 2026-02-14

This file replaces `TODOstage1.md` as the active backlog. Stage 1 built a working proxy + external runner + tool-call contract and a minimal goal system; Stage 2 is about protocol correctness, reliability, and expanding real gameplay capabilities without guessing opcodes/packet shapes.

## Current State (Repo Evidence)

- CI runs `cargo fmt --check`, `cargo clippy --all-targets`, `cargo test`. (`.github/workflows/ci.yml`)
- Workspace tests are passing locally as of 2026-02-14. (`cargo test`)
- External runner exists and drives the proxy over control port (`op=observation`, `op=tool_execute`). (`crates/runner/src/main.rs`)
- Tool-call surface currently includes: `request_move`, `request_turn`, `request_stop`, `request_jump`, `request_emote`, `request_idle`, `target_guid`, `target_nearest_npc`, `interact`, `cast`, `loot`. (`crates/bot-core/src/agent/tools.rs`)
- `cast` is currently implemented as `CMSG_ATTACKSWING` (not a real spell cast). (`crates/gateway-proxy/src/proxy.rs`)

## P0: Protocol Correctness (No Guessing)

- [ ] Replace the current “hand-coded opcode constants” approach with generated or verified mappings.
- [ ] Add a test that fails if opcode IDs used by packet builders drift from the server source.
- [ ] Confirm `CMSG_AUTH_SESSION_OPCODE` in `crates/gateway-proxy/src/proxy.rs` against the server source and cover it with a test (or generate it).

## P0: Runner/Proxy Reliability

- [ ] Make runner reconnect behavior deterministic: on control disconnect, retry with backoff and stop sending tool executions until observation is healthy again. (`crates/runner/src/main.rs`)
- [ ] Add a proxy-side “emergency stop” control op that always works (even when the agent loop is disabled) and add a unit test for its JSON parsing. (`crates/gateway-proxy/src/proxy.rs`)
- [ ] Add integration tests (Rust) that spin up the control listener and assert `op=observation` returns schema-compatible JSON and `op=tool_execute` returns a `ToolResult` with `ok|failed|retryable`.

## P1: Real Combat (Replace `cast` = attackswing)

- [ ] Define what `cast { slot }` actually means (action bar slot? spell id? macro?) and lock that contract down in `rusty-bot-core`.
- [ ] Implement a real casting path in the proxy (packet builder + completion signal) with opcode IDs verified from AzerothCore.
- [ ] Add unit tests for the new cast packet builder(s) using known-good fixture bytes (or server-verified field expectations).
- [ ] Update goal execution to use the real cast when available and fall back to attackswing only when explicitly requested.

## P1: Loot Robustness

- [ ] Promote loot from “fire-and-forget” to “state-driven”: only autostore visible slots once `SMSG_LOOT_RESPONSE` for that guid has been observed.
- [ ] Add a completion rule for `loot` (all items removed + money cleared, or explicit error) and cover it with tests.
- [ ] Add a “loot after kill” goal step (opt-in) and a harness test demonstrating it issues `loot` only when a loot window is present.

## P1: Navigation Beyond Burst Move/Turn

- [ ] Add a higher-level navigation tool (e.g. `move_to { x,y,stop_distance }`) implemented as a deterministic loop of move/turn/stop, with stuck recovery.
- [ ] Add stuck recovery primitives: “back up”, “random turn”, “jump”, and a bounded retry policy; cover with harness tests.
- [ ] Make movement completion checks rely on observed position deltas (not just timeouts) and test “no motion => retryable”.

## P2: Observation/World Model Depth

- [ ] Expand `WorldState` parsing coverage for combat-related state needed for completion checks (target selection change, in-combat flags, cast start/stop).
- [ ] Add eviction/caps for long-running sessions (objects, chat/combat logs, loot) and tests proving caps are enforced.
- [ ] Add a small “golden packet” test suite for key server packets we parse (store hex fixtures and assert decoded structs).

## P2: UX and Docs

- [ ] Document the control protocol (NDJSON request/response shapes) with copy-pastable examples (including `tool_execute` wire format).
- [ ] Add runner CLI flags for the main env vars (`RUSTY_BOT_PROXY_CONTROL_ADDR`, `RUSTY_BOT_LLM_ENDPOINT`, `RUSTY_BOT_LLM_MODEL`, `RUSTY_BOT_AGENT_TICK_MS`, `RUSTY_BOT_GOAL`) and keep env vars as overrides.
- [ ] Add a “real client smoke test checklist” section: how to validate target/interact/cast/loot with minimal risk.

## P3: Test/Quality Improvements

- [ ] Add property tests for `<tool_call>...</tool_call>` parsing to ensure it rejects unknown tools, rejects extra fields when `deny_unknown_fields` is intended, and never executes injections on parse failure (keep the existing harness hard gate).
- [ ] Add fuzzing targets (optional) for control-port parsing.
- [ ] Add fuzzing targets (optional) for `SMSG_UPDATE_OBJECT` parsing.
