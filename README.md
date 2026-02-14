# rusty-bot-wotlk

`rusty-bot-wotlk` is a bot-oriented gateway proxy and runtime for building an event/state-aware WoW WotLK bot.

Current shape:

- **Gateway proxy** (`crates/gateway-proxy/`): sits between a real WoW client and the server, observes traffic, and can inject client-like actions.
- **Bot core** (`crates/bot-core/`): shared world model + vision prompt + LLM adapter primitives.
- **LLM adapter** (`scripts/mock_ollama.py` + env wiring): the LLM speaks a player-level intent language (no opcodes); code translates intents into packets.

## Getting Started

Install `git`, then clone the repo and enter the workspace.

### macOS / Linux (Terminal)

```bash
git clone https://github.com/notOrrytrout/rusty-bot-wotlk
cd rusty-bot-wotlk
```

Pull updates later:

```bash
cd rusty-bot-wotlk
git pull
```

### Windows (PowerShell)

```powershell
git clone https://github.com/notOrrytrout/rusty-bot-wotlk
cd .\\rusty-bot-wotlk
```

Pull updates later:

```powershell
cd .\\rusty-bot-wotlk
git pull
```

### Windows (Git Bash)

```bash
git clone https://github.com/notOrrytrout/rusty-bot-wotlk
cd rusty-bot-wotlk
git pull
```

## Running (Mock LLM)

This starts a local mock LLM server and the standalone gateway proxy, and also clears stale listeners from previous runs:

```bash
bash scripts/run_runner_with_mock.sh
```

### Windows: Running The `.exe` (No Bash)

On Windows, double-clicking `rusty-bot-proxy.exe` launches a normal console program. If it immediately closes, it usually means it hit an error and Windows closed the console window before you could read it.

Recommended: run it from PowerShell so you can see logs and errors.

1) Open PowerShell in the folder containing `rusty-bot-proxy.exe`
```powershell
cd C:\\path\\to\\rusty-bot-wotlk
```

2) Point the proxy at the repo-style `config/` folder (so it can find `config\\wow\\wotlk\\connection.toml`)
```powershell
$env:RUSTY_BOT_CONFIG_DIR = ".\\config"
```

3) (Optional) Start the mock LLM in a second terminal
```powershell
py .\\scripts\\mock_ollama.py
```

4) Run the proxy
```powershell
.\rusty-bot-proxy.exe
```

If you want to double-click something, create a `run_proxy.bat` next to the `.exe`:
```bat
@echo off
set RUSTY_BOT_CONFIG_DIR=.\config
set RUSTY_BOT_AGENT_ENABLED=1
REM Optional: use the local mock LLM (start it separately with: py .\scripts\mock_ollama.py)
REM set RUSTY_BOT_LLM_ENDPOINT=http://127.0.0.1:11435/api/generate
rusty-bot-proxy.exe
pause
```

## Control Panel (Optional)

If you want a simple interactive menu instead of manually typing `nc` JSON lines, run:

```bash
python3 scripts/control_panel.py
```

Config is loaded from `config/wow/wotlk/connection.toml` by default (or from `RUSTY_BOT_CONFIG_DIR` if set).

### In-Game Smoke Tests (Real Client + Agent)

The proxy listens for a real WoW client on the configured addresses:
- Login: `config/wow/wotlk/connection.toml` -> `[gateway.proxy].login_listen`
- World: `config/wow/wotlk/connection.toml` -> `[gateway.proxy].world_listen`

Preferred: run the agent loop in a separate process (`rusty-bot-runner`) that talks to the proxy over the control port.

Legacy (optional): the bot logic can also run inside the proxy process (in-proxy agent loop). It starts disabled by default unless `RUSTY_BOT_AGENT_ENABLED=1` is set, and can be enabled/disabled at runtime via the control port (`op=agent_enable`). To enable the in-proxy agent task, set `RUSTY_BOT_IN_PROXY_AGENT=1`.

#### External Runner

1) Start the proxy (and a mock or real LLM endpoint)

2) In another terminal, run:

```bash
cargo run -p rusty-bot-runner
```

#### 1) Start The Proxy + Mock LLM (Tool Calls)

This is the default. The script will start:
- `scripts/mock_ollama.py` (Ollama-compatible `/api/generate`)
- `rusty-bot-proxy` (gateway proxy)

```bash
cd rusty-bot-wotlk
bash scripts/run_runner_with_mock.sh
```

#### 2) Connect Your Real WoW Client To The Proxy

Point your WoW client at the proxy login listener (default is `127.0.0.1:3724` from `config/wow/wotlk/connection.toml`).

Once you log in and enter the world, the proxy should start printing bot/agent logs (and the agent will begin issuing movement tool calls).

#### 3) Force Deterministic Actions (Recommended For Testing)

The mock LLM can be driven deterministically.

Move forward for ~900ms on each tick:
```bash
cd rusty-bot-wotlk
MOCK_OLLAMA_RESPONSE="move forward" bash scripts/run_runner_with_mock.sh
```

Stop movement on each tick:
```bash
cd rusty-bot-wotlk
MOCK_OLLAMA_RESPONSE="move stop" bash scripts/run_runner_with_mock.sh
```

Send an explicit tool call (exactly one block, preserved as-is):
```bash
cd rusty-bot-wotlk
MOCK_OLLAMA_RESPONSE='<tool_call>{"name":"request_move","arguments":{"direction":"forward","duration_ms":600}}</tool_call>' \
  bash scripts/run_runner_with_mock.sh
```

Test emotes (requires `MOCK_OLLAMA_INCLUDE_EMOTES=1` to rotate emotes automatically, or set a response directly):
```bash
cd rusty-bot-wotlk
MOCK_OLLAMA_RESPONSE="emote wave" bash scripts/run_runner_with_mock.sh
```

#### 4) Enable / Disable Agent Loop

Enable agent loop at startup:
```bash
cd rusty-bot-wotlk
RUSTY_BOT_AGENT_ENABLED=1 bash scripts/run_runner_with_mock.sh
```

Start disabled (then enable later via control port):
```bash
cd rusty-bot-wotlk
RUSTY_BOT_AGENT_ENABLED=0 bash scripts/run_runner_with_mock.sh
```

Optional:
- `RUSTY_BOT_AGENT_USE_VISION=1` to append the legacy vision section to the prompt (default: 1)
- `RUSTY_BOT_SUPPRESS_CLIENT_MOVEMENT=1` to suppress real-client movement packets to the server (default: 0)

#### 5) (Optional) Set A Goal String

This is included in the agent prompt as context (the current tool set is still movement-only):
```bash
cd rusty-bot-wotlk
RUSTY_BOT_GOAL="walk in a small square" bash scripts/run_runner_with_mock.sh
```

## Switching To A Real LLM

Set `RUSTY_BOT_LLM_ENDPOINT` to an Ollama-style `POST /api/generate` endpoint returning a JSON object with a `"response"` string.

## Acknowledgments

This repo contains code that was copied/ported from the repo `https://github.com/tench-rt/tentacli.git`(Apache License 2.0). In particular:

- `crates/gateway-proxy/src/wotlk.rs` SRP implementation was ported from `tentacli` WotLK login SRP (`src/plugins/wow/wotlk/login/srp.rs`).
- `crates/gateway-proxy/src/wotlk.rs` RC4 implementation/keys were ported from `tentacli` WotLK realm RC4 (`src/plugins/wow/wotlk/realm/rc4.rs`).
- `crates/gateway-proxy/src/wotlk.rs` movement structs/flags were ported from `tentacli` WotLK movement types (`src/plugins/wow/wotlk/realm/object/types/movement.rs`).

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0-only). See `LICENSE`.

This repository also includes code derived from `tentacli` (Apache License 2.0). See `THIRD_PARTY_NOTICES.md` and `LICENSES/Apache-2.0.txt`.
