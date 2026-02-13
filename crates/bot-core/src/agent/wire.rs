use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const TOOL_CALL_START: &str = "<tool_call>";
pub const TOOL_CALL_END: &str = "</tool_call>";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ToolCallWire {
    pub name: String,
    #[serde(default)]
    pub confirm: bool,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolParseError {
    MissingToolCallBlock,
    MultipleToolCallBlocks,
    InvalidJson,
    UnsupportedToolName(String),
    InvalidArguments(String),
}

impl std::fmt::Display for ToolParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolParseError::MissingToolCallBlock => write!(f, "missing <tool_call> block"),
            ToolParseError::MultipleToolCallBlocks => write!(f, "multiple <tool_call> blocks"),
            ToolParseError::InvalidJson => write!(f, "invalid tool call json"),
            ToolParseError::UnsupportedToolName(name) => {
                write!(f, "unsupported tool name: {name}")
            }
            ToolParseError::InvalidArguments(msg) => write!(f, "invalid tool arguments: {msg}"),
        }
    }
}

impl std::error::Error for ToolParseError {}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MoveDirection {
    Forward,
    Backward,
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TurnDirection {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopKind {
    Move,
    Turn,
    Strafe,
    All,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RequestMoveArgs {
    pub direction: MoveDirection,
    pub duration_ms: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RequestTurnArgs {
    pub direction: TurnDirection,
    pub duration_ms: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RequestStopArgs {
    pub kind: StopKind,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RequestEmoteArgs {
    pub key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TargetGuidArgs {
    pub guid: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TargetNearestNpcArgs {
    #[serde(default)]
    pub entry: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct InteractArgs {
    pub guid: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CastArgs {
    pub slot: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ToolInvocation {
    pub call: ToolCall,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum ToolCall {
    RequestIdle,
    RequestMove(RequestMoveArgs),
    RequestTurn(RequestTurnArgs),
    RequestStop(RequestStopArgs),
    RequestJump,
    RequestEmote(RequestEmoteArgs),
    TargetGuid(TargetGuidArgs),
    TargetNearestNpc(TargetNearestNpcArgs),
    Interact(InteractArgs),
    Cast(CastArgs),
}

fn clamp_duration_ms(ms: u32) -> u32 {
    ms.clamp(150, 5_000)
}

fn validate_nonzero_guid(guid: u64, tool_name: &'static str) -> Result<u64, ToolParseError> {
    if guid == 0 {
        return Err(ToolParseError::InvalidArguments(format!(
            "{tool_name}: guid must be nonzero"
        )));
    }
    Ok(guid)
}

fn validate_cast_slot(slot: u8) -> Result<u8, ToolParseError> {
    // V0: clamp tool surface to a small, safe actionbar range. This can be expanded later.
    if slot == 0 || slot > 12 {
        return Err(ToolParseError::InvalidArguments(
            "cast: slot must be 1..=12".to_string(),
        ));
    }
    Ok(slot)
}

fn parse_args<T: for<'de> Deserialize<'de>>(
    val: serde_json::Value,
    tool_name: &'static str,
) -> Result<T, ToolParseError> {
    serde_json::from_value::<T>(val)
        .map_err(|e| ToolParseError::InvalidArguments(format!("{tool_name}: {e}")))
}

fn validate_emote_key(key: &str) -> bool {
    // Keep it strict for now: a single "word" key. The proxy maps it to text emote ids.
    !key.trim().is_empty() && key.split_whitespace().count() == 1
}

impl TryFrom<ToolCallWire> for ToolCall {
    type Error = ToolParseError;

    fn try_from(wire: ToolCallWire) -> Result<Self, Self::Error> {
        let name = wire.name.trim().to_ascii_lowercase();
        match name.as_str() {
            "request_idle" => Ok(ToolCall::RequestIdle),
            "request_jump" => Ok(ToolCall::RequestJump),
            "request_move" => {
                let mut args = parse_args::<RequestMoveArgs>(wire.arguments, "request_move")?;
                args.duration_ms = clamp_duration_ms(args.duration_ms);
                Ok(ToolCall::RequestMove(args))
            }
            "request_turn" => {
                let mut args = parse_args::<RequestTurnArgs>(wire.arguments, "request_turn")?;
                args.duration_ms = clamp_duration_ms(args.duration_ms);
                Ok(ToolCall::RequestTurn(args))
            }
            "request_stop" => {
                let args = parse_args::<RequestStopArgs>(wire.arguments, "request_stop")?;
                Ok(ToolCall::RequestStop(args))
            }
            "request_emote" => {
                let mut args = parse_args::<RequestEmoteArgs>(wire.arguments, "request_emote")?;
                args.key = args.key.trim().to_ascii_lowercase();
                if !validate_emote_key(&args.key) {
                    return Err(ToolParseError::InvalidArguments(
                        "request_emote: key must be a single word".to_string(),
                    ));
                }
                Ok(ToolCall::RequestEmote(args))
            }
            "target_guid" => {
                let mut args = parse_args::<TargetGuidArgs>(wire.arguments, "target_guid")?;
                args.guid = validate_nonzero_guid(args.guid, "target_guid")?;
                Ok(ToolCall::TargetGuid(args))
            }
            "target_nearest_npc" => {
                let args =
                    parse_args::<TargetNearestNpcArgs>(wire.arguments, "target_nearest_npc")?;
                Ok(ToolCall::TargetNearestNpc(args))
            }
            "interact" => {
                let mut args = parse_args::<InteractArgs>(wire.arguments, "interact")?;
                args.guid = validate_nonzero_guid(args.guid, "interact")?;
                Ok(ToolCall::Interact(args))
            }
            "cast" => {
                let mut args = parse_args::<CastArgs>(wire.arguments, "cast")?;
                args.slot = validate_cast_slot(args.slot)?;
                Ok(ToolCall::Cast(args))
            }
            other => Err(ToolParseError::UnsupportedToolName(other.to_string())),
        }
    }
}

impl TryFrom<ToolCallWire> for ToolInvocation {
    type Error = ToolParseError;

    fn try_from(wire: ToolCallWire) -> Result<Self, Self::Error> {
        let confirm = wire.confirm;
        let call = ToolCall::try_from(ToolCallWire {
            name: wire.name,
            confirm,
            arguments: wire.arguments,
        })?;
        Ok(Self { call, confirm })
    }
}

/// Extracts the JSON inside the first `<tool_call>...</tool_call>` block.
///
/// If there are multiple blocks, returns `None` so the caller can treat it as invalid.
pub fn extract_tool_call_json(script: &str) -> Option<String> {
    let start = script.find(TOOL_CALL_START)? + TOOL_CALL_START.len();
    let rest = &script[start..];
    let end_rel = rest.find(TOOL_CALL_END)?;
    let end = start + end_rel;

    // Reject multiple tool call blocks to keep the contract simple.
    let after_end = &script[end + TOOL_CALL_END.len()..];
    if after_end.contains(TOOL_CALL_START) {
        return None;
    }

    Some(script[start..end].trim().to_string())
}

/// Parses a full LLM response into a validated `ToolCall`.
///
/// Contract:
/// - Exactly one `<tool_call>...</tool_call>` block
/// - The JSON is an object `{ "name": "...", "arguments": { ... } }`
pub fn parse_tool_call(script: &str) -> anyhow::Result<ToolInvocation> {
    let json_str = extract_tool_call_json(script).ok_or(ToolParseError::MissingToolCallBlock)?;

    let wire: ToolCallWire = serde_json::from_str(&json_str)
        .map_err(|_| ToolParseError::InvalidJson)
        .with_context(|| format!("tool_call_json={json_str}"))?;

    let invocation = ToolInvocation::try_from(wire)?;
    Ok(invocation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ok() {
        let s = "x\n<tool_call>\n{\"name\":\"request_idle\",\"arguments\":{}}\n</tool_call>\n";
        let got = extract_tool_call_json(s).unwrap();
        assert_eq!(got, "{\"name\":\"request_idle\",\"arguments\":{}}");
    }

    #[test]
    fn extract_rejects_multiple() {
        let s = "<tool_call>{\"name\":\"request_idle\",\"arguments\":{}}</tool_call>\n<tool_call>{\"name\":\"request_idle\",\"arguments\":{}}</tool_call>";
        assert!(extract_tool_call_json(s).is_none());
    }

    #[test]
    fn parse_move_clamps_duration() {
        let s = "<tool_call>{\"name\":\"request_move\",\"arguments\":{\"direction\":\"forward\",\"duration_ms\":999999}}</tool_call>";
        let inv = parse_tool_call(s).unwrap();
        match inv.call {
            ToolCall::RequestMove(args) => assert_eq!(args.duration_ms, 5_000),
            _ => panic!("expected move"),
        }
    }

    #[test]
    fn parse_emote_requires_single_word() {
        let s = "<tool_call>{\"name\":\"request_emote\",\"arguments\":{\"key\":\"wave now\"}}</tool_call>";
        let err = parse_tool_call(s).unwrap_err();
        assert!(format!("{err}").contains("key must be a single word"));
    }

    #[test]
    fn parse_confirm_flag() {
        let s =
            "<tool_call>{\"name\":\"request_idle\",\"confirm\":true,\"arguments\":{}}</tool_call>";
        let inv = parse_tool_call(s).unwrap();
        assert!(inv.confirm);
        assert!(matches!(inv.call, ToolCall::RequestIdle));
    }

    #[test]
    fn parse_target_guid_requires_nonzero() {
        let s = "<tool_call>{\"name\":\"target_guid\",\"arguments\":{\"guid\":0}}</tool_call>";
        let err = parse_tool_call(s).unwrap_err();
        assert!(format!("{err}").contains("guid must be nonzero"));
    }

    #[test]
    fn parse_cast_slot_range() {
        let s = "<tool_call>{\"name\":\"cast\",\"arguments\":{\"slot\":0}}</tool_call>";
        let err = parse_tool_call(s).unwrap_err();
        assert!(format!("{err}").contains("slot must be 1..=12"));
    }
}
