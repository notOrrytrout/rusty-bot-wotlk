use crate::packets::{Packet, PacketType};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn build_packet(packet_type: PacketType, guid: u64) -> Packet {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    Packet {
        player_guid: guid,
        timestamp,
        packet_type,
    }
}
