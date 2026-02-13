// input.rs
//
// Virtual keyboard interface for LLM-issued commands.
// Parses text instructions like "press W" or "cast 1" into PacketType actions.

use crate::packets::PacketType;

/// [LLM KEYBOARD PROTOCOL]
///
/// COMMAND FORMAT:
/// - press <key>
/// - release <key>
/// - cast <1-9>
///
/// SUPPORTED KEYS:
/// - W, A, S, D for movement
/// - SPACE for jump
/// - 1 through 9 for spell casting
///
/// EXAMPLES:
/// - press W
/// - release S
/// - cast 3

/// Interprets a single LLM-issued command and maps it to a game action.
pub fn interpret_llm_input(input: &str) -> Option<PacketType> {
    let normalized = input.trim();
    let normalized_words = normalized
        .to_ascii_lowercase()
        .replace('_', " ")
        .replace('-', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    // Case-insensitive matching, preserve actual casing for /say, etc.
    let upper = normalized.to_uppercase();

    // Proxy demo terms (single command):
    // - move forward/backward/left/right/stop
    // - turn left/right/stop
    // - jump
    // Note: headless PacketType currently has no explicit strafe/stop variants, so:
    // - move left/right is treated as turn left/right
    // - stop commands are treated as no-ops
    match normalized_words.as_str() {
        "move forward" => return Some(PacketType::MoveForward),
        "move backward" => return Some(PacketType::MoveBackward),
        "move left" => return Some(PacketType::TurnLeft),
        "move right" => return Some(PacketType::TurnRight),
        "turn left" => return Some(PacketType::TurnLeft),
        "turn right" => return Some(PacketType::TurnRight),
        "jump" => return Some(PacketType::Jump),
        "move stop" | "turn stop" | "stop" => return None,
        _ => {}
    }

    if upper.starts_with("PRESS ") {
        let key = normalized[6..].trim().to_uppercase();
        match key.as_str() {
            "W" => Some(PacketType::MoveForward),
            "A" => Some(PacketType::TurnLeft),
            "S" => Some(PacketType::MoveBackward),
            "D" => Some(PacketType::TurnRight),
            "SPACE" => Some(PacketType::Jump),
            _ => None,
        }
    } else if upper.starts_with("RELEASE ") {
        // You can define release logic as needed
        // For now, treat it as a no-op or None
        None
    } else if upper.starts_with("CAST ") {
        let key = normalized[5..].trim();
        if let Ok(n) = key.parse::<u8>() {
            if (1..=9).contains(&n) {
                return Some(PacketType::CastSpell(n));
            }
        }
        None
    } else if upper.starts_with("/SAY ") {
        let text = normalized[5..].trim().to_string();
        Some(PacketType::Say(text))
    } else if upper.starts_with("/YELL ") {
        let text = normalized[6..].trim().to_string();
        Some(PacketType::Yell(text))
    } else if upper.starts_with("/TALKTO ") {
        if let Ok(guid) = normalized[8..].trim().parse::<u64>() {
            Some(PacketType::TalkToNpc(guid))
        } else {
            None
        }
    } else if upper.starts_with("/OPENVENDOR ") {
        if let Ok(guid) = normalized[12..].trim().parse::<u64>() {
            Some(PacketType::OpenVendor(guid))
        } else {
            None
        }
    } else if upper.starts_with("/ACCEPTQUEST ") {
        if let Ok(guid) = normalized[13..].trim().parse::<u64>() {
            Some(PacketType::AcceptQuest(guid))
        } else {
            None
        }
    } else {
        None
    }
}
