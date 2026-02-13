use std::fmt::Write;

use crate::world::world_state::WorldState;

/// Generate a structured string representation of the world state for an LLM.
///
/// Extracted from `testllm/src/vision.rs`.
pub fn generate_prompt(world: &WorldState, self_guid: u64) -> String {
    let mut prompt = String::new();

    writeln!(prompt, "[BOT_VISION]").unwrap();
    writeln!(prompt, "Tick: {}", world.tick).unwrap();

    writeln!(prompt, "\n[SCREEN]").unwrap();
    writeln!(prompt, "- MiniMap: visible").unwrap();
    writeln!(prompt, "- OpenWindows: [Inventory, Spellbook]").unwrap();
    writeln!(
        prompt,
        "- ChatLog: {}",
        if world.chat_log.is_empty() {
            "empty"
        } else {
            "visible"
        }
    )
    .unwrap();

    writeln!(prompt, "\n[PLAYER]").unwrap();
    if let Some(player) = world.players.get(&self_guid) {
        writeln!(prompt, "GUID: {}", self_guid).unwrap();
        writeln!(
            prompt,
            "Position: x={:.1} y={:.1} z={:.1} orient={:.2}",
            player.position.x, player.position.y, player.position.z, player.position.orientation
        )
        .unwrap();
        writeln!(prompt, "Health: {} / {}", player.health, player.max_health).unwrap();
        writeln!(
            prompt,
            "Power: {} / ? ({:?})",
            player.power, player.power_type
        )
        .unwrap();
        writeln!(
            prompt,
            "Speed: run={:.2} walk={:.2} swim={:.2}",
            player.speed_run, player.speed_walk, player.speed_swim
        )
        .unwrap();
        writeln!(
            prompt,
            "Level: {} Class: {} Race: {} Gender: {}",
            player.level, player.class, player.race, player.gender
        )
        .unwrap();
        writeln!(prompt, "Flags: 0x{:08X}", player.flags).unwrap();
        writeln!(prompt, "Active Auras: {:?}", player.auras).unwrap();
    } else {
        writeln!(prompt, "Player state not found.").unwrap();
    }

    writeln!(prompt, "\n[NPCS_NEARBY]").unwrap();
    for npc in world.npcs.values() {
        writeln!(
            prompt,
            "- GUID: {} Entry: {} Pos(x={:.1}, y={:.1}, z={:.1}) HP: {}/{} Flags: 0x{:08X}",
            npc.guid,
            npc.entry,
            npc.position.x,
            npc.position.y,
            npc.position.z,
            npc.health,
            npc.max_health,
            npc.flags
        )
        .unwrap();
    }

    writeln!(prompt, "\n[PLAYERS_NEARBY]").unwrap();
    for (guid, player) in &world.other_players {
        writeln!(
            prompt,
            "- GUID: {} Pos(x={:.1}, y={:.1}, z={:.1}) HP: {}/{} Class: {} Level: {}",
            guid,
            player.position.x,
            player.position.y,
            player.position.z,
            player.health,
            player.max_health,
            player.class,
            player.level
        )
        .unwrap();
    }

    writeln!(prompt, "\n[CHAT_LOG]").unwrap();
    if world.chat_log.is_empty() {
        writeln!(prompt, "- (empty)").unwrap();
    } else {
        for msg in &world.chat_log {
            writeln!(prompt, "- {}", msg).unwrap();
        }
    }

    writeln!(prompt, "\n[COMBAT_LOG]").unwrap();
    if world.combat_log.is_empty() {
        writeln!(prompt, "- (empty)").unwrap();
    } else {
        for msg in &world.combat_log {
            writeln!(prompt, "- {}", msg).unwrap();
        }
    }

    writeln!(prompt, "\n[TALENTS]").unwrap();
    if let Some(player) = world.players.get(&self_guid) {
        if player.known_talents.is_empty() {
            writeln!(prompt, "- No known talents").unwrap();
        } else {
            for id in &player.known_talents {
                writeln!(prompt, "- Talent: {:?}", id).unwrap();
            }
        }
    }

    writeln!(prompt, "\n[INVENTORY]").unwrap();
    if let Some(player) = world.players.get(&self_guid) {
        if player.inventory.is_empty() {
            writeln!(prompt, "- Empty").unwrap();
        } else {
            for item in &player.inventory {
                writeln!(prompt, "- Item ID: {}", item.item_entry).unwrap();
            }
        }
    }

    writeln!(prompt, "\n[EQUIPMENT]").unwrap();
    if let Some(player) = world.players.get(&self_guid) {
        if player.equipment.is_empty() {
            writeln!(prompt, "- No equipped items").unwrap();
        } else {
            for item in &player.equipment {
                writeln!(prompt, "- Slot {}: Item ID {}", item.slot, item.item_entry).unwrap();
            }
        }
    }

    prompt
}
