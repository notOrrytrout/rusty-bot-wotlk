# AzerothClient Bot Framework

**AzerothClient** is a Rust-based high-performance protocol client and AI bot framework for World of Warcraft 3.3.5a (AzerothCore). It supports large-scale bot deployment using LLM-driven decision making via [Ollama](https://ollama.com) and can scale to hundreds or thousands of concurrent bots with real-time server interaction.

---

## Features

- SRP6 + RC4-based login to realmd and worldserver
- Full player/NPC/other object state tracking
- `SMSG_UPDATE_OBJECT` parsing for live world data
- Structured LLM-readable `[BOT_VISION]` prompt generator
- LLM integration with Ollama or OpenAI-style APIs
- Virtual keyboard for AI command parsing (e.g., `press W`, `cast 2`)
- Support for scaling to 1000+ bots across a single or multiple servers

---

## Requirements

- Rust (latest stable) — [Install via rustup](https://rustup.rs)
- Ollama LLM running locally (e.g., `llama3`, `codellama`, etc.)
- AzerothCore 3.3.5a server running realmd and worldserver
- Bot accounts created in the `account` table (`bot0`, `bot1`, etc.)

---

## Building

### Linux / macOS

```bash
git clone https://github.com/your-org/azeroth_client.git
cd azeroth_client
cargo build --release
```

### Windows

Install the [Rust toolchain for Windows](https://rustup.rs/) and run:

```powershell
git clone https://github.com/your-org/azeroth_client.git
cd azeroth_client
cargo build --release
```

---

## Configuration

Edit `config.toml`:

```toml
[ollama]
model = "llama3"               # The name of the local Ollama model
url = "http://localhost:11434" # Base URL of your Ollama instance

[bot]
character_index = 0            # Which character to use per account (0 = first)
```

- Accounts should be named `bot0`, `bot1`, ..., `botN`
- All bots use the same password by default (`"password"`)
- You can configure up to 1500 bots in `main.rs`

---

## How It Works

1. Each bot logs into `realmd` and `worldserver`
2. Parses `SMSG_CHAR_ENUM` to select a character
3. Listens to server packets, updating a full world model
4. Generates a `[BOT_VISION]` prompt
5. Sends the prompt to an LLM
6. Interprets and sends in-game actions via virtual keyboard (e.g., `press W`, `cast 3`)

---

## Running

To launch bots:

```bash
cargo run --release
```

> All configured bots will start automatically, staggered to prevent overload.

---

## License

MIT © 2025 YourName / YourOrg

---

## Notes

- You can extend this with scripting, visual dashboards, or offline replay
- Designed to interoperate with AzerothCore but could be adapted to other 3.3.5a emulators
