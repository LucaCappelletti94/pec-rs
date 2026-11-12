# pec

[![CI](https://github.com/LucaCappelletti94/pec-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/pec-rs/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/pec-rs/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/pec-rs)
[![crates.io](https://img.shields.io/crates/v/pec.svg)](https://crates.io/crates/pec)
[![docs.rs](https://docs.rs/pec/badge.svg)](https://docs.rs/pec)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/pec-rs/blob/main/LICENSE)

Reading PEC messages, Italian certified email, in Rust.

- every receipt, notice and envelope a PEC provider generates, told apart by kind and checked against its subject
- the certification data of `daticert.xml`, read and written
- the original message out of a transport envelope or a delivery receipt, and the arrived message out of an anomaly envelope
- short-receipt hashes identified and checked against the sent message, including named roots, nested attachments and carried user files, with ambiguous assignments rejected

The crate works on bytes already fetched, so any SMTP or IMAP client can feed it. It follows the AgID technical rules annexed to DM 2 November 2005.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use pec::{Kind, Message, MessageKind};

let raw = std::fs::read("tests/fixtures/messages/delivery-full.eml")?;
let receipt = Message::parse(&raw)?;
assert_eq!(receipt.kind(), MessageKind::Certified(Kind::Delivery));
assert_eq!(receipt.subject(), "Invio fattura 00012");

let data = receipt.certification_data().expect("every receipt has one");
assert_eq!(data.data.delivered_to.as_deref(), Some("ufficio.fatture@pec.example.it"));
assert_eq!(data.data.at.timestamp().to_string(), "2026-11-08T09:15:00Z");
assert!(receipt.original_message().is_some());
# Ok(())
# }
```
