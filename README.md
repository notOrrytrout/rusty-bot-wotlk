# rusty-bot-wotlk

`rusty-bot-wotlk` is a bot-oriented gateway proxy and runtime for building an event/state-aware WoW WotLK bot.

Current shape:

- **Gateway proxy** (`crates/gateway-proxy/`): sits between a real WoW client and the server, observes traffic, and can inject client-like actions.
- **Bot core** (`crates/bot-core/`): shared world model + vision prompt + LLM adapter primitives.
- **LLM adapter** (`scripts/mock_ollama.py` + env wiring): the LLM speaks a player-level intent language (no opcodes); code translates intents into packets.

## Running (Mock LLM)

This starts a local mock LLM server and the standalone gateway proxy, and also clears stale listeners from previous runs:

```bash
cd <repo-root>
bash scripts/run_runner_with_mock.sh
```

Config is loaded from `config/wow/wotlk/connection.toml` by default (or from `RUSTY_BOT_CONFIG_DIR` if set).

### In-Game Smoke Tests (Real Client + Agent)

The proxy listens for a real WoW client on the configured addresses:
- Login: `config/wow/wotlk/connection.toml` -> `[gateway.proxy].login_listen`
- World: `config/wow/wotlk/connection.toml` -> `[gateway.proxy].world_listen`

The bot logic runs inside the proxy process. By default it uses the new **agent loop** (tool-call based). You can force the legacy demo loop by setting `RUSTY_BOT_AGENT=0`.

#### 1) Start The Proxy + Mock LLM (Tool Calls)

This is the default. The script will start:
- `scripts/mock_ollama.py` (Ollama-compatible `/api/generate`)
- `rusty-bot-proxy` (gateway proxy)

```bash
cd <repo-root>
bash scripts/run_runner_with_mock.sh
```

#### 2) Connect Your Real WoW Client To The Proxy

Point your WoW client at the proxy login listener (default is `127.0.0.1:3724` from `config/wow/wotlk/connection.toml`).

Once you log in and enter the world, the proxy should start printing bot/agent logs (and the agent will begin issuing movement tool calls).

#### 3) Force Deterministic Actions (Recommended For Testing)

The mock LLM can be driven deterministically.

Move forward for ~900ms on each tick:
```bash
cd <repo-root>
MOCK_OLLAMA_RESPONSE="move forward" bash scripts/run_runner_with_mock.sh
```

Stop movement on each tick:
```bash
cd <repo-root>
MOCK_OLLAMA_RESPONSE="move stop" bash scripts/run_runner_with_mock.sh
```

Send an explicit tool call (exactly one block, preserved as-is):
```bash
cd <repo-root>
MOCK_OLLAMA_RESPONSE='<tool_call>{"name":"request_move","arguments":{"direction":"forward","duration_ms":600}}</tool_call>' \
  bash scripts/run_runner_with_mock.sh
```

Test emotes (requires `MOCK_OLLAMA_INCLUDE_EMOTES=1` to rotate emotes automatically, or set a response directly):
```bash
cd <repo-root>
MOCK_OLLAMA_RESPONSE="emote wave" bash scripts/run_runner_with_mock.sh
```

#### 4) Toggle Agent vs Legacy Demo Loop

Agent loop (default):
```bash
cd <repo-root>
RUSTY_BOT_AGENT=1 bash scripts/run_runner_with_mock.sh
```

Legacy demo loop:
```bash
cd <repo-root>
RUSTY_BOT_AGENT=0 bash scripts/run_runner_with_mock.sh
```

#### 5) (Optional) Set A Goal String

This is included in the agent prompt as context (the current tool set is still movement-only):
```bash
cd <repo-root>
RUSTY_BOT_GOAL="walk in a small square" bash scripts/run_runner_with_mock.sh
```

## Switching To A Real LLM

Set `RUSTY_BOT_LLM_ENDPOINT` to an Ollama-style `POST /api/generate` endpoint returning a JSON object with a `"response"` string.

## Acknowledgments

This repo contains code that was copied/ported from the repo `https://github.com/tench-rt/tentacli.git`(Apache License 2.0). In particular:

- `crates/gateway-proxy/src/wotlk.rs` SRP implementation was ported from `tentacli` WotLK login SRP (`src/plugins/wow/wotlk/login/srp.rs`).
- `crates/gateway-proxy/src/wotlk.rs` RC4 implementation/keys were ported from `tentacli` WotLK realm RC4 (`src/plugins/wow/wotlk/realm/rc4.rs`).
- `crates/gateway-proxy/src/wotlk.rs` movement structs/flags were ported from `tentacli` WotLK movement types (`src/plugins/wow/wotlk/realm/object/types/movement.rs`).
