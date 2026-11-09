//! Reading arbitrary text as `daticert.xml`. Whatever reads must write and read back unchanged.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pec::CertificationData;

fuzz_target!(|input: &[u8]| {
    let Ok(text) = core::str::from_utf8(input) else {
        return;
    };
    let Ok(data) = CertificationData::from_xml(text) else {
        return;
    };
    let written = data.to_xml().expect("read certification data writes");
    let reread = CertificationData::from_xml(&written).expect("written certification data reads");
    assert_eq!(reread, data, "the round trip changed the data");
});
