#!/usr/bin/env python3
"""
Interactive control panel for rusty-bot-wotlk proxy control port.

Talks NDJSON to the proxy control listener (default 127.0.0.1:7878) and provides a
simple "buttons via numbered menu" workflow to:
- refresh observation and list nearby NPCs/players
- select a target by index
- set/clear goal strings (follow/goto/interact)
- execute tools (target/interact/cast/movement/emote)
- paste/send arbitrary JSON control lines
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def _prompt(msg: str) -> str:
    try:
        return input(msg)
    except EOFError:
        return ""


def _prompt_int(msg: str, *, default: Optional[int] = None) -> Optional[int]:
    raw = _prompt(msg).strip()
    if not raw:
        return default
    try:
        return int(raw, 10)
    except ValueError:
        return None


def _prompt_yes_no(msg: str, *, default: bool = False) -> bool:
    raw = _prompt(msg).strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes", "true", "1")


class ControlClient:
    def __init__(self, host: str, port: int, version: int = 1, timeout_s: float = 1.5):
        self.host = host
        self.port = port
        self.version = version
        self.timeout_s = timeout_s

    def request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        msg = dict(payload)
        # Control protocol supports optional version; keep it explicit.
        msg.setdefault("version", self.version)
        line = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")

        with socket.create_connection((self.host, self.port), timeout=self.timeout_s) as sock:
            sock.sendall(line)
            f = sock.makefile("rb")
            resp = f.readline()
            if not resp:
                raise RuntimeError("no response from control port")
            try:
                return json.loads(resp.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise RuntimeError(f"invalid json response: {resp!r}") from e


@dataclass
class SelectedEntity:
    kind: str  # "npc" or "player"
    guid: int
    entry: Optional[int] = None


def _fmt_pos(pos: Dict[str, Any]) -> str:
    try:
        return f"({pos.get('x'):.2f},{pos.get('y'):.2f},{pos.get('z'):.2f})"
    except Exception:
        return str(pos)


def _print_entities(obs: Dict[str, Any]) -> None:
    self_guid = obs.get("self_guid")
    self_state = obs.get("self_state") or {}
    if self_state:
        pos = self_state.get("pos") or {}
        print(
            f"\nSelf: guid={self_guid} pos={_fmt_pos(pos)} orient={self_state.get('orient')} "
            f"move_flags={self_state.get('movement_flags')} time={self_state.get('movement_time')}"
        )
    else:
        print(f"\nSelf: guid={self_guid} (no self_state yet; move your character to seed it)")

    npcs = obs.get("npcs_nearby") or []
    players = obs.get("players_nearby") or []

    print("\nNPCs nearby:")
    if not npcs:
        print("  <none>")
    for i, n in enumerate(npcs):
        guid = n.get("guid")
        entry = n.get("entry")
        hp = n.get("hp")
        pos = n.get("pos") or {}
        print(f"  [{i}] guid={guid} entry={entry} hp={hp} pos={_fmt_pos(pos)}")

    print("\nPlayers nearby:")
    if not players:
        print("  <none>")
    for i, p in enumerate(players):
        guid = p.get("guid")
        hp = p.get("hp")
        pos = p.get("pos") or {}
        print(f"  [{i}] guid={guid} hp={hp} pos={_fmt_pos(pos)}")


def _pick_entity(obs: Dict[str, Any]) -> Optional[SelectedEntity]:
    print("\nPick entity type:")
    print("  1) NPC")
    print("  2) Player")
    t = _prompt_int("choice [1/2]: ")
    if t == 1:
        npcs = obs.get("npcs_nearby") or []
        if not npcs:
            print("no NPCs in last observation; choose (2) to refresh, or pick Player")
            return None
        print("indices are 0-based (first item is 0)")
        idx = _prompt_int(f"npc index [0..{len(npcs)-1}]: ")
        # Common UX: users type 1 when there's only one item (index 0).
        if idx is not None and idx == len(npcs):
            idx -= 1
        if idx is None or idx < 0 or idx >= len(npcs):
            print("invalid npc index")
            return None
        n = npcs[idx]
        return SelectedEntity(kind="npc", guid=int(n["guid"]), entry=n.get("entry"))
    if t == 2:
        players = obs.get("players_nearby") or []
        if not players:
            print("no Players in last observation; choose (2) to refresh")
            return None
        print("indices are 0-based (first item is 0)")
        idx = _prompt_int(f"player index [0..{len(players)-1}]: ")
        if idx is not None and idx == len(players):
            idx -= 1
        if idx is None or idx < 0 or idx >= len(players):
            print("invalid player index")
            return None
        p = players[idx]
        return SelectedEntity(kind="player", guid=int(p["guid"]), entry=None)
    print("invalid choice")
    return None


def _goal_menu(obs: Dict[str, Any], selected: Optional[SelectedEntity]) -> Optional[str]:
    print("\nGoal presets:")
    print("  1) follow selected guid")
    print("  2) follow npc_entry (prompt)")
    print("  3) goto selected guid")
    print("  4) goto npc_entry (prompt)")
    print("  5) goto selected guid + interact")
    print("  6) goto npc_entry + interact")
    print("  7) stop moving (idle)")
    print("  8) custom goal text (paste)")
    print("  9) goto guid (prompt)")
    print("  10) goto guid + interact (prompt)")

    choice = _prompt_int("choice [1-10]: ")
    if choice == 1:
        if not selected:
            print("no selected entity; refresh observation and select one first")
            return None
        return f"follow guid={selected.guid}"
    if choice == 2:
        entry = _prompt_int("npc_entry: ")
        if entry is None:
            print("invalid entry")
            return None
        if entry > 10_000_000:
            print("that looks like a GUID, not an npc_entry id; use (9) goto guid (prompt) instead")
            return None
        return f"follow npc_entry={entry}"
    if choice == 3:
        if not selected:
            print("no selected entity; refresh observation and select one first")
            return None
        return f"goto guid={selected.guid}"
    if choice == 4:
        entry = _prompt_int("npc_entry: ")
        if entry is None:
            print("invalid entry")
            return None
        if entry > 10_000_000:
            print("that looks like a GUID, not an npc_entry id; use (9) goto guid (prompt) instead")
            return None
        return f"goto npc_entry={entry}"
    if choice == 5:
        if not selected:
            print("no selected entity; refresh observation and select one first")
            return None
        return f"goto guid={selected.guid} interact"
    if choice == 6:
        entry = _prompt_int("npc_entry: ")
        if entry is None:
            print("invalid entry")
            return None
        if entry > 10_000_000:
            print("that looks like a GUID, not an npc_entry id; use (10) goto guid + interact instead")
            return None
        return f"goto npc_entry={entry} interact"
    if choice == 7:
        return "stop moving"
    if choice == 8:
        txt = _prompt("goal text: ").strip()
        return txt or None
    if choice == 9:
        guid = _prompt_int("guid: ")
        if guid is None:
            print("invalid guid")
            return None
        return f"goto guid={guid}"
    if choice == 10:
        guid = _prompt_int("guid: ")
        if guid is None:
            print("invalid guid")
            return None
        return f"goto guid={guid} interact"
    print("invalid choice")
    return None


def _tool_menu(selected: Optional[SelectedEntity]) -> Optional[Dict[str, Any]]:
    print("\nTool actions:")
    print("  1) target selected")
    print("  2) interact selected")
    print("  3) cast/attack selected (v0 attackswing)")
    print("  4) move forward 600ms")
    print("  5) stop all")
    print("  6) emote wave")
    print("  7) custom tool JSON (name+arguments)")

    choice = _prompt_int("choice [1-7]: ")
    if choice in (1, 2, 3) and not selected:
        print("no selected entity; refresh observation and select one first")
        return None

    if choice == 1:
        return {"op": "tool_execute", "tool": {"name": "target_guid", "arguments": {"guid": selected.guid}}}
    if choice == 2:
        return {"op": "tool_execute", "tool": {"name": "interact", "arguments": {"guid": selected.guid}}}
    if choice == 3:
        # Current proxy implementation uses attackswing and requires guid.
        slot = _prompt_int("slot [1..12] (ignored for v0): ", default=1) or 1
        return {"op": "tool_execute", "tool": {"name": "cast", "arguments": {"slot": int(slot), "guid": selected.guid}}}
    if choice == 4:
        return {"op": "tool_execute", "tool": {"name": "request_move", "arguments": {"direction": "forward", "duration_ms": 600}}}
    if choice == 5:
        return {"op": "tool_execute", "tool": {"name": "request_stop", "arguments": {"kind": "all"}}}
    if choice == 6:
        return {"op": "tool_execute", "tool": {"name": "request_emote", "arguments": {"key": "wave"}}}
    if choice == 7:
        name = _prompt("tool name (e.g. request_move): ").strip()
        args_txt = _prompt("arguments JSON (e.g. {\"direction\":\"forward\",\"duration_ms\":400}): ").strip()
        try:
            args = json.loads(args_txt) if args_txt else {}
        except json.JSONDecodeError:
            print("invalid arguments JSON")
            return None
        return {"op": "tool_execute", "tool": {"name": name, "arguments": args}}
    print("invalid choice")
    return None


def run_interactive(client: ControlClient) -> int:
    last_obs: Optional[Dict[str, Any]] = None
    selected: Optional[SelectedEntity] = None

    while True:
        print("\n=== rusty-bot control panel ===")
        print(f"control: {client.host}:{client.port}")
        print(f"selected: {selected.kind} guid={selected.guid} entry={selected.entry}" if selected else "selected: <none>")
        print("  1) status")
        print("  2) observation (refresh + list)")
        print("  3) select entity (from last observation)")
        print("  4) agent enable/disable")
        print("  5) set goal (preset builder)")
        print("  6) clear goal")
        print("  7) tool action (menu)")
        print("  8) send custom control JSON line (paste)")
        print("  9) quit")

        choice = _prompt_int("choice [1-9]: ")
        if choice == 9:
            return 0

        try:
            if choice == 1:
                resp = client.request({"op": "status"})
                print(_pretty(resp))
            elif choice == 2:
                resp = client.request({"op": "observation"})
                print(_pretty({"ok": resp.get("ok"), "op": resp.get("op")}))
                obs = resp.get("observation") or {}
                last_obs = obs
                _print_entities(obs)
            elif choice == 3:
                if not last_obs:
                    print("no observation yet; choose (2) first")
                    continue
                sel = _pick_entity(last_obs)
                if sel:
                    selected = sel
            elif choice == 4:
                st = client.request({"op": "status"})
                enabled = bool(st.get("enabled"))
                print(f"agent currently enabled={enabled}")
                next_enabled = _prompt_yes_no("enable agent? [y/N]: ", default=False)
                resp = client.request({"op": "agent_enable", "enabled": bool(next_enabled)})
                print(_pretty(resp))
            elif choice == 5:
                if not last_obs:
                    # Not strictly required, but makes guid selection easy.
                    print("tip: refresh observation first (2) so you can pick a guid")
                goal = _goal_menu(last_obs or {}, selected)
                if not goal:
                    continue
                resp = client.request({"op": "set_goal", "goal": goal})
                print(_pretty(resp))
                # Show status after set so it's obvious it took effect.
                st = client.request({"op": "status"})
                print(_pretty(st))
                if not bool(st.get("enabled")):
                    print("note: agent is disabled; enable it with (4) or the goal won't execute")
                if int(st.get("self_guid") or 0) == 0:
                    print("note: self_guid is 0; move your character a bit (WASD) so the proxy learns your GUID")
                if not bool(st.get("movement_template_present", True)):
                    print("note: no movement template yet; move your character a bit (WASD) so injected movement can reuse it")
            elif choice == 6:
                resp = client.request({"op": "clear_goal"})
                print(_pretty(resp))
            elif choice == 7:
                payload = _tool_menu(selected)
                if not payload:
                    continue
                resp = client.request(payload)
                print(_pretty(resp))
            elif choice == 8:
                line = _prompt("paste JSON (no surrounding quotes): ").strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    print("invalid json")
                    continue
                resp = client.request(payload)
                print(_pretty(resp))
            else:
                print("invalid choice")
        except Exception as e:
            print(f"error: {e}")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="rusty-bot-wotlk proxy control panel")
    p.add_argument("--host", default="127.0.0.1", help="control host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=7878, help="control port (default: 7878)")
    p.add_argument("--version", type=int, default=1, help="control protocol version (default: 1)")
    p.add_argument("--timeout", type=float, default=1.5, help="socket timeout seconds (default: 1.5)")
    args = p.parse_args(argv)

    client = ControlClient(args.host, args.port, version=args.version, timeout_s=args.timeout)
    return run_interactive(client)


if __name__ == "__main__":
    raise SystemExit(main())
