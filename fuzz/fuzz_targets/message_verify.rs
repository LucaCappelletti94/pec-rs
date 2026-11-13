//! Verifying arbitrary bytes as a PEC message against the test CA and its CRL, so the BER and DER decoding of the
//! signature meets fuzzed input.

#![no_main]

use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;
use postacert::Message;

/// The test CA that issued the signer of every message fixture.
const ANCHOR: &[u8] = include_bytes!("../../tests/fixtures/pki/anchors/agid-like.der");

/// The test CA's CRL, fresh at [`AT`].
const CRL: &[u8] = include_bytes!("../../tests/fixtures/pki/crls/current.der");

/// 2030-01-01T00:00:00Z, when the fixtures' signer is valid and [`CRL`] is fresh.
const AT: Timestamp = Timestamp::constant(1_893_456_000, 0);

fuzz_target!(|input: &[u8]| {
    let Ok(message) = Message::parse(input) else {
        return;
    };
    let _ = message.verify(&[ANCHOR], &[CRL], AT);
});
