# pec

[![CI](https://github.com/LucaCappelletti94/pec-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/pec-rs/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/pec-rs/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/pec-rs)
[![crates.io](https://img.shields.io/crates/v/pec.svg)](https://crates.io/crates/pec)
[![docs.rs](https://docs.rs/pec/badge.svg)](https://docs.rs/pec)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/pec-rs/blob/main/LICENSE)

Reading PEC messages, Italian certified email, in Rust.

- the certification data of `daticert.xml`, read and written, with the instant each receipt certifies

It follows the AgID technical rules annexed to DM 2 November 2005.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use pec::{CertificationData, Kind, ReceiptKind};

let xml = std::fs::read_to_string("tests/fixtures/daticert/delivery-full.xml")?;
let data = CertificationData::from_xml(&xml)?;
assert_eq!(data.kind, Kind::Delivery);
assert_eq!(data.data.receipt, Some(ReceiptKind::Full));
assert_eq!(data.data.delivered_to.as_deref(), Some("ufficio.fatture@pec.example.it"));
assert_eq!(data.data.at.timestamp().to_string(), "2026-11-08T09:15:00Z");
assert_eq!(CertificationData::from_xml(&data.to_xml()?)?, data);
# Ok(())
# }
```
