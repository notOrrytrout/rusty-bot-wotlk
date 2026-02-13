#!/usr/bin/env python3
"""Lightweight local mock for Ollama-style APIs used in development.

Endpoints:
- POST /api/generate
- POST /api/chat

Returns deterministic single-command responses suitable for the bot demo loop.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import cycle
from typing import Any

DEFAULT_RESPONSE = os.environ.get(
    "MOCK_OLLAMA_RESPONSE",
    "move forward",
)

ROTATING_RESPONSES = [
    "move forward",
    "move left",
    "move right",
    "move backward",
    "move stop",
    "jump",
]

if os.environ.get("MOCK_OLLAMA_INCLUDE_EMOTES", "").lower() in ("1", "true", "yes"):
    # Proxy demo mode supports `emote <key>`; keep this opt-in so movement-only tests remain stable.
    ROTATING_RESPONSES.extend([
        "emote wave",
        "emote cheer",
        "emote dance",
        "emote laugh",
    ])

_response_cycle = cycle(ROTATING_RESPONSES)
_response_lock = threading.Lock()


def next_rotating_response() -> str:
    with _response_lock:
        return next(_response_cycle)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Handler(BaseHTTPRequestHandler):
    server_version = "MockOllama/0.1"

    def _send_json(self, payload: dict[str, Any], code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_ndjson(self, payloads: list[dict[str, Any]], code: int = 200) -> None:
        lines = b"".join((json.dumps(item) + "\n").encode("utf-8") for item in payloads)
        self.send_response(code)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(lines)))
        self.end_headers()
        self.wfile.write(lines)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json({"ok": True, "time": now_iso()})
            return

        self._send_json({"error": "not found"}, code=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        data = self._read_json()
        if self.path == "/api/generate":
            self.handle_generate(data)
            return
        if self.path == "/api/chat":
            self.handle_chat(data)
            return

        self._send_json({"error": "not found"}, code=HTTPStatus.NOT_FOUND)

    def handle_generate(self, data: dict[str, Any]) -> None:
        model = str(data.get("model") or "mock-llm")
        stream = bool(data.get("stream", False))
        prompt = str(data.get("prompt") or "")
        response = str(data.get("response") or DEFAULT_RESPONSE)
        if "response" not in data and "MOCK_OLLAMA_RESPONSE" not in os.environ:
            response = next_rotating_response()

        if stream:
            self._send_ndjson(
                [
                    {
                        "model": model,
                        "created_at": now_iso(),
                        "response": response,
                        "done": False,
                    },
                    {
                        "model": model,
                        "created_at": now_iso(),
                        "response": "",
                        "done": True,
                    },
                ]
            )
            return

        self._send_json(
            {
                "model": model,
                "created_at": now_iso(),
                "response": response,
                "done": True,
                "prompt_eval_count": len(prompt.split()),
                "eval_count": len(response.split()),
            }
        )

    def handle_chat(self, data: dict[str, Any]) -> None:
        model = str(data.get("model") or "mock-llm")
        stream = bool(data.get("stream", False))
        response = str(data.get("response") or DEFAULT_RESPONSE)
        if "response" not in data and "MOCK_OLLAMA_RESPONSE" not in os.environ:
            response = next_rotating_response()

        if stream:
            self._send_ndjson(
                [
                    {
                        "model": model,
                        "created_at": now_iso(),
                        "message": {"role": "assistant", "content": response},
                        "done": False,
                    },
                    {
                        "model": model,
                        "created_at": now_iso(),
                        "message": {"role": "assistant", "content": ""},
                        "done": True,
                    },
                ]
            )
            return

        self._send_json(
            {
                "model": model,
                "created_at": now_iso(),
                "message": {"role": "assistant", "content": response},
                "done": True,
            }
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{now_iso()}] {self.address_string()} {fmt % args}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a local mock Ollama API server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=11435, help="Bind port")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock_ollama listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
