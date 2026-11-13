//! Preparing arbitrary bytes as an outgoing message for each receipt form, then checking it against the guaranteed
//! limits. Whatever prepares holds no bare line break and names a recipient to send to.

#![no_main]

use libfuzzer_sys::fuzz_target;
use postacert::{Limits, OutgoingMessage, ReceiptKind};

fuzz_target!(|input: &[u8]| {
    for receipt in [ReceiptKind::Full, ReceiptKind::Short, ReceiptKind::Summary] {
        let Ok(outgoing) = OutgoingMessage::prepare(input, receipt) else {
            continue;
        };
        assert!(
            !has_bare_line_break(outgoing.as_bytes()),
            "the prepared message holds a bare line break"
        );
        assert!(
            !outgoing.forward_paths().is_empty(),
            "the prepared message has no recipient"
        );
        let _ = outgoing.check_limits(Limits::GUARANTEED);
    }
});

/// Whether `bytes` hold a line feed not after a carriage return, or a carriage return not before a line feed.
fn has_bare_line_break(bytes: &[u8]) -> bool {
    bytes.iter().enumerate().any(|(at, byte)| match byte {
        b'\n' => at.checked_sub(1).and_then(|before| bytes.get(before)) != Some(&b'\r'),
        b'\r' => bytes.get(at + 1) != Some(&b'\n'),
        _ => false,
    })
}
