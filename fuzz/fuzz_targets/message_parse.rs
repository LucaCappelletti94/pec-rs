//! Reading arbitrary bytes as a PEC message, for panics in the parser and its accessors.

#![no_main]

use libfuzzer_sys::fuzz_target;
use postacert::Message;

fuzz_target!(|input: &[u8]| {
    let Ok(message) = Message::parse(input) else {
        return;
    };
    let _ = message.kind();
    let _ = message.security_error();
    let _ = message.subject();
    let _ = message.message_id();
    let _ = message.reference_message_id();
    let _ = message.original_message();
    if let Some(data) = message.certification_data() {
        let _ = data.to_xml();
    }
});
