//! Unit tests for opcode constants.

/// Test that the `CMSG_AUTH_SESSION_OPCODE` matches the value defined in
/// AzerothCore (0x01ED).  This ensures the Rust constant stays in sync with
/// the server definition.
#[test]
fn test_cmsg_auth_session_opcode_value() {
    // The value is defined in `proxy.rs`.
    use rusty_bot_proxy::proxy::CMSG_AUTH_SESSION_OPCODE;
    assert_eq!(
        CMSG_AUTH_SESSION_OPCODE, 0x01ed,
        "Opcode mismatch for CMSG_AUTH_SESSION"
    );
}
