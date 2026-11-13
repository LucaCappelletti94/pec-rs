# postacert

[![CI](https://github.com/LucaCappelletti94/postacert/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/postacert/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/postacert/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/postacert)
[![crates.io](https://img.shields.io/crates/v/postacert.svg)](https://crates.io/crates/postacert)
[![docs.rs](https://docs.rs/postacert/badge.svg)](https://docs.rs/postacert)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/postacert/blob/main/LICENSE)

Parsing PEC messages, Italian certified email, and reading and writing their `daticert.xml` certification data, in Rust.

- every receipt, notice and envelope a PEC provider generates, told apart by kind and checked against its subject
- the certification data of `daticert.xml`, read and written
- the original message out of a transport envelope or a delivery receipt, and the arrived message out of an anomaly envelope
- short-receipt hashes identified and checked against the sent message, including named roots, nested attachments and carried user files, with ambiguous assignments rejected
- the provider's S/MIME signature checked against the signed part, in the DER or BER form providers send, and its signer against AgID's provider CAs and their CRLs at a given time

The crate works on bytes already fetched, so any SMTP or IMAP client can feed it. It follows the AgID technical rules annexed to DM 2 November 2005.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use postacert::{Kind, Message, MessageKind};

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
