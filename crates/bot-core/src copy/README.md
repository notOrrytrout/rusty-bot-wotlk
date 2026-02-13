# 🧠 LLM-Controlled World of Warcraft Bot (Packet Interface)

This project is a **World of Warcraft automation framework** that controls a WoW client **exclusively through structured packet communication**, guided by a **local language model** (via [Ollama](https://ollama.ai/)).

---

##  Project Highlights

- 🧠 Controlled by an LLM (no hardcoded logic)
-  Sends and receives real game packets (no keyboard hooks or memory injection)
-  Reconstructs and maintains a full internal world state
-  Authenticates using SRP6 protocol to WoW private servers
-  Simulates a player — chats, casts, moves, interacts

---

##  Project Structure

```text
llm-bot/
 main.rs               # Entry point: launches bots
 bot_launcher.rs       # Bootstraps login + game loop
 config.rs             # Loads bot config
 input.rs              # Maps LLM text to PacketType
 llm.rs                # Communicates with local LLM
 builder.rs            # Turns PacketType into Packet
 packets.rs            # Defines and serializes game packets
 receiver.rs           # Parses server packets, updates state
 transport.rs          # Handles RC4 encryption + TCP
 vision.rs             # Builds readable game prompts for LLM

 login.rs              # Realm/server login flow using SRP

 player/               # The bot's character state
    mod.rs
    player_state.rs   # Stats, spells, inventory
    equipment.rs
    inventory.rs
    spells.rs
    talents.rs
    other_state.rs

 world/                # World/NPCs/players state
    mod.rs
    npc_state.rs
    world_state.rs

 srp/                  # Secure Remote Password auth
    mod.rs
    handshake.rs
    challenge.rs

 utils/                # Binary parsing helpers
     mod.rs
     bitflags.rs
     reader.rs
```

---

##  Bot Lifecycle

1. **Login**: Performs SRP authentication and enters the game world
2. **World Sync**: Parses live packets to build `WorldState`
3. **LLM Prompting**: Constructs a prompt with all known game state
4. **LLM Decision**: Receives text like `/cast 2`, `/say hello`
5. **Packet Generation**: Converts LLM text → packet → server

---

##  Supported LLM Commands (Examples)

```text
/press W
/jump
/cast 3
/say Hello
/yell For the Horde!
/talkto 1234567890
/openvendor 1234567890
/acceptquest 1234567890
```

These commands are parsed into structured packets and sent to the WoW server directly.

---

##  Future Plans

- Context-aware memory for LLM (short-term tactical history)
- More packet types: quests, emotes, talent trainer, loot
- Offline replay from packet logs
- LLM multi-agent support (party behavior)

---

##  License

MIT — use, learn, extend, explore.
