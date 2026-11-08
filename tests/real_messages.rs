//! Real PEC messages read from a local folder that never enters the repository.
//!
//! Set `PEC_REAL_MESSAGES` to a folder of `.eml` files fetched from a PEC mailbox to run it. CI leaves it unset.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use pec::{Message, MessageKind};

#[test]
fn every_real_pec_message_parses() {
    let Some(folder) = std::env::var_os("PEC_REAL_MESSAGES") else {
        return;
    };
    let mut checked = 0;
    for entry in std::fs::read_dir(&folder).expect("the folder is readable") {
        let path = entry.expect("the entry is readable").path();
        let raw = std::fs::read(&path).expect("the file is readable");
        let name = path.display();
        let text = String::from_utf8_lossy(&raw);
        let headers = text
            .split("\r\n\r\n")
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !headers.contains("\nx-ricevuta:") && !headers.contains("\nx-trasporto:") {
            continue;
        }
        let message = Message::parse(&raw).unwrap_or_else(|error| panic!("{name}: {error}"));
        match message.kind() {
            MessageKind::Certified(kind) => {
                assert_eq!(
                    message.certification_data().expect("certified").kind,
                    kind,
                    "{name}"
                );
            }
            MessageKind::Anomaly => assert!(message.original_message().is_some(), "{name}"),
        }
        checked += 1;
    }
    assert!(checked > 0, "no PEC message in {}", folder.display());
}
