# rusty-bot-core

`rusty-bot-core` is the shared library crate for `/rusty-bot-wotlk`.

It contains:
- The world/state model populated by the gateway proxy (`WorldState`)
- A stable, capped `Observation` schema for agent prompts (`agent::observation`)
- The `<tool_call>...</tool_call>` parsing + validation contract (`agent::wire`)
- The agent loop framework pieces (prompt builder, executor, memory, test harness)
- Legacy vision prompt generation (`vision.rs`) used as an optional prompt suffix by the proxy

This crate intentionally does not depend on the gateway proxy implementation. The proxy (`crates/gateway-proxy/`) owns the networking/protocol parsing and implements the `agent::game_api::GameApi` boundary.

## Tests

From repo root:

```bash
cargo test -p rusty-bot-core
```

## License

This repository is GPL-3.0-only. See `/LICENSE` at repo root.
