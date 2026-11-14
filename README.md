# postacert

[![CI](https://github.com/LucaCappelletti94/postacert/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/postacert/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/postacert/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/postacert)
[![crates.io](https://img.shields.io/crates/v/postacert.svg)](https://crates.io/crates/postacert)
[![docs.rs](https://docs.rs/postacert/badge.svg)](https://docs.rs/postacert)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/postacert/blob/main/LICENSE)

postacert reads and checks PEC messages, Italian certified email, on bytes any SMTP or IMAP client has fetched. It tells every receipt, notice and envelope apart, verifies the provider's signature against AgID's CAs and CRLs, tracks each recipient's delivery, and builds outgoing messages the provider accepts at submission. It follows the AgID technical rules annexed to DM 2 November 2005.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use postacert::{Delivery, Mailbox, Message, OutgoingMessage, Status};

// The crate reads no clock, so the caller dates the message.
let date = "2026-11-08T10:14:58+01:00[+01:00]".parse().expect("a date with its offset");
let sent = OutgoingMessage::builder(
    Mailbox::named("Mario Rossi", "mario.rossi@pec.example.it")?,
    Mailbox::new("ufficio.fatture@pec.example.it")?,
    "<20261108101458.0001@client.example.it>".parse()?,
    date,
)
.subject("Invio fattura 00012")
.text("Fattura in allegato.")
.build()?;
// Send `sent.as_bytes()` from `sent.reverse_path()` to `sent.forward_paths()`, then track the receipts.
let mut delivery = Delivery::new(sent.message_id().clone());

// Real receipts verify against `postacert::AGID_PROVIDER_CAS` and AgID's CRL, these fixtures against a test CA.
let raw = std::fs::read("tests/fixtures/messages/delivery-full.eml")?;
let anchor = std::fs::read("tests/fixtures/pki/anchors/agid-like.der")?;
let crl = std::fs::read("tests/fixtures/pki/crls/current.der")?;
let at = "2030-01-01T00:00:00Z".parse().expect("an RFC 3339 instant");
let receipt = Message::parse(&raw)?;
delivery.record(&receipt.verify(&[&anchor], &[&crl], at)?)?;
assert!(matches!(
    delivery.status("ufficio.fatture@pec.example.it"),
    Some(Status::Delivered(_))
));
# Ok(())
# }
```
