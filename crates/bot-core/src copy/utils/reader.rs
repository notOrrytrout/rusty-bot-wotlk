// reader.rs
// Utility for reading binary formats

use std::io::{Cursor, Read};

pub fn read_cstring(cursor: &mut Cursor<&[u8]>) -> Option<String> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if cursor.read_exact(&mut byte).is_err() {
            return None;
        }
        if byte[0] == 0 {
            break;
        }
        buf.push(byte[0]);
    }

    String::from_utf8(buf).ok()
}
