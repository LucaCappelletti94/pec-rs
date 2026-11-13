//! Reading arbitrary bytes as a short delivery receipt and checking its hashes against a sent message, with either
//! line end policy, for panics in pairing what the receipt carries with the sent attachments.

#![no_main]

use libfuzzer_sys::fuzz_target;
use postacert::{Message, TextLineEnds};

/// The sent message of the short receipt fixture `delivery-short.eml`.
const SENT: &[u8] = include_bytes!("../../tests/fixtures/original/attachments.eml");

fuzz_target!(|input: &[u8]| {
    let Ok(receipt) = Message::parse(input) else {
        return;
    };
    for line_ends in [TextLineEnds::Canonical, TextLineEnds::CanonicalOrLf] {
        let _ = receipt.attachment_hashes(SENT, line_ends);
        let _ = receipt.check_attachments(SENT, line_ends);
    }
});
