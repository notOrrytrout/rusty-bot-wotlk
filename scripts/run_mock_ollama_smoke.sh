#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-11435}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

python3 "$ROOT_DIR/scripts/mock_ollama.py" --host "$HOST" --port "$PORT" >/tmp/mock_ollama_smoke.log 2>&1 &
PID=$!
trap 'kill "$PID" >/dev/null 2>&1 || true' EXIT

# wait for server to be ready
for _ in {1..30}; do
  if curl -fsS "http://$HOST:$PORT/health" >/dev/null 2>/dev/null; then
    break
  fi
  sleep 0.1
done

HEALTH_JSON="$(curl -fsS "http://$HOST:$PORT/health")"
GEN_JSON="$(curl -fsS -X POST "http://$HOST:$PORT/api/generate" -H 'Content-Type: application/json' -d '{"model":"mock","prompt":"test","stream":false}')"
CHAT_JSON="$(curl -fsS -X POST "http://$HOST:$PORT/api/chat" -H 'Content-Type: application/json' -d '{"model":"mock","messages":[],"stream":false}')"

echo "health: $HEALTH_JSON"
echo "generate: $GEN_JSON"
echo "chat: $CHAT_JSON"

if command -v rg >/dev/null 2>&1; then
  echo "$GEN_JSON" | rg -q '"response"' || { echo "missing generate response"; exit 1; }
  echo "$CHAT_JSON" | rg -q '"message"' || { echo "missing chat message"; exit 1; }
else
  echo "$GEN_JSON" | grep -q '"response"' || { echo "missing generate response"; exit 1; }
  echo "$CHAT_JSON" | grep -q '"message"' || { echo "missing chat message"; exit 1; }
fi

echo "mock_ollama smoke: OK"
