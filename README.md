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

## Switching To A Real LLM

Set `RUSTY_BOT_LLM_ENDPOINT` to an Ollama-style `POST /api/generate` endpoint returning a JSON object with a `"response"` string.

## Acknowledgments

This repo contains code that was copied/ported from the repo `https://github.com/tench-rt/tentacli.git`(Apache License 2.0). In particular:

- `crates/gateway-proxy/src/wotlk.rs` SRP implementation was ported from `tentacli` WotLK login SRP (`src/plugins/wow/wotlk/login/srp.rs`).
- `crates/gateway-proxy/src/wotlk.rs` RC4 implementation/keys were ported from `tentacli` WotLK realm RC4 (`src/plugins/wow/wotlk/realm/rc4.rs`).
- `crates/gateway-proxy/src/wotlk.rs` movement structs/flags were ported from `tentacli` WotLK movement types (`src/plugins/wow/wotlk/realm/object/types/movement.rs`).
