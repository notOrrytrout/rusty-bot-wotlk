#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-11435}"
CFG_OVERRIDE_PATH="${3:-}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CFG_PATH="${RUSTY_BOT_LLM_SETUP_CFG_PATH:-}"
LOG_PATH="${MOCK_OLLAMA_LOG_PATH:-/tmp/mock_ollama_setup_test.log}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required"
  exit 1
fi

if [ -n "$CFG_OVERRIDE_PATH" ]; then
  CFG_PATH="$CFG_OVERRIDE_PATH"
fi

if [ -z "$CFG_PATH" ] && [ -n "${RUSTY_BOT_CONFIG_DIR:-}" ]; then
  # Align with proxy ConfigLoader lookup behavior.
  CFG_DIR="${RUSTY_BOT_CONFIG_DIR}"
  if [ -f "${CFG_DIR}/wow/wotlk/connection.toml" ]; then
    CFG_PATH="${CFG_DIR}/wow/wotlk/connection.toml"
  fi
fi

if [ -z "$CFG_PATH" ]; then
  # Preferred: config lives in this repo under config/wow/wotlk/connection.toml
  if [ -f "${ROOT_DIR}/config/wow/wotlk/connection.toml" ]; then
    CFG_PATH="${ROOT_DIR}/config/wow/wotlk/connection.toml"
  fi
fi

if [ -z "$CFG_PATH" ]; then
  # No further fallbacks.
  true
fi

if [ ! -f "$CFG_PATH" ]; then
  echo "missing config: $CFG_PATH"
  exit 1
fi

toml_get() {
  local section="$1"
  local key="$2"
  awk -v section="$section" -v key="$key" '
    /^[[:space:]]*\[/ {
      in_section = ($0 ~ ("^[[:space:]]*\\[" section "\\][[:space:]]*$"))
      next
    }
    in_section && $0 ~ ("^[[:space:]]*" key "[[:space:]]*=") {
      sub(/^[^=]*=[[:space:]]*/, "", $0)
      gsub(/[[:space:]]+$/, "", $0)
      print $0
      exit
    }
  ' "$CFG_PATH"
}

python3 "$ROOT_DIR/scripts/mock_ollama.py" --host "$HOST" --port "$PORT" >"$LOG_PATH" 2>&1 &
PID=$!
trap 'kill "$PID" >/dev/null 2>&1 || true' EXIT

for _ in {1..50}; do
  if curl -fsS "http://$HOST:$PORT/health" >/dev/null 2>/dev/null; then
    break
  fi
  sleep 0.1
done

HEALTH_JSON="$(curl -fsS "http://$HOST:$PORT/health")"
GEN_JSON="$(curl -fsS -X POST "http://$HOST:$PORT/api/generate" -H 'Content-Type: application/json' -d '{"model":"mock","prompt":"test setup","stream":false}')"
CHAT_JSON="$(curl -fsS -X POST "http://$HOST:$PORT/api/chat" -H 'Content-Type: application/json' -d '{"model":"mock","messages":[{"role":"user","content":"hi"}],"stream":false}')"

if command -v rg >/dev/null 2>&1; then
  echo "$HEALTH_JSON" | rg -q '"ok"[[:space:]]*:[[:space:]]*true' || { echo "health check failed: $HEALTH_JSON"; exit 1; }
  echo "$GEN_JSON" | rg -q '"response"' || { echo "generate endpoint failed: $GEN_JSON"; exit 1; }
  echo "$CHAT_JSON" | rg -q '"message"' || { echo "chat endpoint failed: $CHAT_JSON"; exit 1; }
else
  echo "$HEALTH_JSON" | grep -q '"ok":[[:space:]]*true' || { echo "health check failed: $HEALTH_JSON"; exit 1; }
  echo "$GEN_JSON" | grep -q '"response"' || { echo "generate endpoint failed: $GEN_JSON"; exit 1; }
  echo "$CHAT_JSON" | grep -q '"message"' || { echo "chat endpoint failed: $CHAT_JSON"; exit 1; }
fi

BOT_ENABLED="$(toml_get "bot" "enabled" || true)"
BOT_REQUIRES_REAL_CLIENT="$(toml_get "bot" "requires_real_client" || true)"
MOVEMENT_MODE="$(toml_get "movement" "mode" || true)"

echo "stub.health: $HEALTH_JSON"
echo "stub.generate: $GEN_JSON"
echo "stub.chat: $CHAT_JSON"
echo "config.path: $CFG_PATH"
echo "config.bot.enabled: ${BOT_ENABLED:-<missing>}"
echo "config.bot.requires_real_client: ${BOT_REQUIRES_REAL_CLIENT:-<missing>}"
echo "config.movement.mode: ${MOVEMENT_MODE:-<missing>}"
echo "env.RUSTY_BOT_REAL_CLIENT: ${RUSTY_BOT_REAL_CLIENT:-<unset>}"

if [ "${BOT_ENABLED}" = "true" ]; then
  if [ "${MOVEMENT_MODE}" != "\"input\"" ]; then
    echo "setup invalid: [movement].mode must be \"input\" when [bot].enabled=true"
    exit 1
  fi
  if [ "${BOT_REQUIRES_REAL_CLIENT}" != "true" ]; then
    echo "setup invalid: [bot].requires_real_client must be true when [bot].enabled=true"
    exit 1
  fi
  REAL_MARKER="${RUSTY_BOT_REAL_CLIENT:-}"
  if [ "${REAL_MARKER}" != "1" ] && [ "${REAL_MARKER}" != "true" ] && [ "${REAL_MARKER}" != "TRUE" ]; then
    echo "setup invalid: set RUSTY_BOT_REAL_CLIENT=1 before starting the proxy"
    exit 1
  fi
  echo "llm setup test: OK (bot contract satisfied + stub server reachable)"
else
  echo "llm setup test: OK (stub server reachable; bot currently disabled in connection.toml)"
fi
