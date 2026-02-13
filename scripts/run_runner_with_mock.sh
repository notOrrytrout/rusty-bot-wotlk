#!/usr/bin/env bash
set -euo pipefail

# Starts the local mock LLM + standalone gateway proxy.
#
# Usage:
#   ./scripts/run_runner_with_mock.sh [host] [port]
#
# Optional env:
#   RUSTY_BOT_CONFIG_DIR (default: <repo>/config)
#   MOCK_OLLAMA_INCLUDE_EMOTES=1 to include emotes in the rotating responses
#   MOCK_OLLAMA_TOOL_CALLS=1 to emit `<tool_call>{...}</tool_call>` wrapped JSON responses (default: 1)
#   RUSTY_BOT_DEMO=1 (default: 1)
#   RUSTY_BOT_REAL_CLIENT=1 (default: 1) - required by bot contract if bot is enabled in config

HOST="${1:-127.0.0.1}"
PORT="${2:-11435}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required"
  exit 1
fi

CFG_DIR="${RUSTY_BOT_CONFIG_DIR:-${ROOT_DIR}/config}"

toml_get() {
  local cfg_path="$1"
  local section="$2"
  local key="$3"
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
  ' "$cfg_path"
}

port_from_addr() {
  local addr="$1"
  # addr is TOML string like "127.0.0.1:7878" (quotes included)
  addr="${addr%\"}"
  addr="${addr#\"}"
  echo "${addr##*:}"
}

kill_listeners_on_port() {
  local port="$1"
  if [ -z "$port" ]; then
    return 0
  fi
  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(lsof -nP -ti "TCP:${port}" -sTCP:LISTEN 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      echo "killing listeners on TCP:${port}: ${pids}"
      kill $pids >/dev/null 2>&1 || true
      sleep 0.2
      kill -9 $pids >/dev/null 2>&1 || true
    fi
  else
    echo "warning: lsof not found; cannot auto-kill listeners on port ${port}"
  fi
}

cleanup_stale_pids() {
  # If a previous run got orphaned, prefer cleaning by pidfile and ports.
  local pidfiles=(
    "/tmp/rusty_bot_mock_ollama.pid"
  )
  local f pid
  for f in "${pidfiles[@]}"; do
    if [ -f "$f" ]; then
      pid="$(cat "$f" 2>/dev/null || true)"
      if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
        echo "killing stale pidfile process pid=${pid} file=${f}"
        kill "$pid" >/dev/null 2>&1 || true
        sleep 0.2
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
      rm -f "$f" >/dev/null 2>&1 || true
    fi
  done
}

cleanup_stale_pids

# Free ports used by this demo.
# - mock LLM: $PORT
# - gateway proxy (from config if present; else defaults)
CFG_PATH="${CFG_DIR}/wow/wotlk/connection.toml"
kill_listeners_on_port "${PORT}"

if [ -f "${CFG_PATH}" ]; then
  LOGIN_LISTEN="$(toml_get "${CFG_PATH}" "gateway.proxy" "login_listen" || true)"
  WORLD_LISTEN="$(toml_get "${CFG_PATH}" "gateway.proxy" "world_listen" || true)"
  CONTROL_LISTEN="$(toml_get "${CFG_PATH}" "gateway.proxy" "control_listen" || true)"
  kill_listeners_on_port "$(port_from_addr "${LOGIN_LISTEN:-\"127.0.0.1:3725\"}")"
  kill_listeners_on_port "$(port_from_addr "${WORLD_LISTEN:-\"127.0.0.1:8086\"}")"
  kill_listeners_on_port "$(port_from_addr "${CONTROL_LISTEN:-\"127.0.0.1:7878\"}")"
else
  # Reasonable defaults, in case the config isn't there.
  kill_listeners_on_port "3725"
  kill_listeners_on_port "8086"
  kill_listeners_on_port "7878"
fi

MOCK_OLLAMA_TOOL_CALLS="${MOCK_OLLAMA_TOOL_CALLS:-1}" \
python3 "${ROOT_DIR}/scripts/mock_ollama.py" --host "${HOST}" --port "${PORT}" >/tmp/mock_ollama.log 2>&1 &
MOCK_PID=$!
echo "${MOCK_PID}" >/tmp/rusty_bot_mock_ollama.pid
trap 'kill "${MOCK_PID}" >/dev/null 2>&1 || true; rm -f /tmp/rusty_bot_mock_ollama.pid >/dev/null 2>&1 || true' EXIT

for _ in {1..50}; do
  if curl -fsS "http://${HOST}:${PORT}/health" >/dev/null 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if ! curl -fsS "http://${HOST}:${PORT}/health" >/dev/null 2>/dev/null; then
  echo "mock LLM failed to start (see /tmp/mock_ollama.log)"
  exit 1
fi

echo "mock LLM: http://${HOST}:${PORT}"
echo "config dir: ${CFG_DIR}"

RUSTY_BOT_CONFIG_DIR="${CFG_DIR}" \
RUSTY_BOT_DEMO="${RUSTY_BOT_DEMO:-1}" \
RUSTY_BOT_REAL_CLIENT="${RUSTY_BOT_REAL_CLIENT:-1}" \
RUSTY_BOT_LLM_ENDPOINT="${RUSTY_BOT_LLM_ENDPOINT:-http://${HOST}:${PORT}/api/generate}" \
cargo run -p rusty-bot-proxy
