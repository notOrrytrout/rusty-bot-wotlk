// bitflags.rs
// Definitions for unit flags, object flags, etc.

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct UnitFlags: u32 {
        const NONE        = 0x0;
        const AGGRESSIVE  = 0x1;
        const ELITE       = 0x2;
        const INVISIBLE   = 0x4;
        const FLYING      = 0x8;
        const IMMUNE      = 0x10;
        // Add more as needed
    }
}
