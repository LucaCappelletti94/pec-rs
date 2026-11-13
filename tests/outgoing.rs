//! Checking a message before its submission to the sender's PEC provider (§6.3.1), and asking for a receipt form
//! (§6.5.2.2, §6.5.2.3).

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use postacert::{Error, Limits, MessageId, OutgoingError, OutgoingMessage, ReceiptKind};

/// The sender.
const FROM: &str = "From: Mario Rossi <mario.rossi@pec.example.it>";
/// Two primary recipients, one of them outside PEC.
const TO: &str = "To: ufficio.fatture@pec.example.it, Paolo Bianchi <paolo.bianchi@example.com>";
/// A recipient in copy, and a primary one again with its domain in another case.
const CC: &str = "Cc: protocollo@pec.example.it, Ufficio <ufficio.fatture@PEC.Example.IT>";
/// The subject.
const SUBJECT: &str = "Subject: Invio fattura 00012";
/// The date the client wrote.
const DATE: &str = "Date: Sun, 8 Nov 2026 10:14:58 +0100";
/// The identifier the client gave the message.
const MESSAGE_ID: &str = "Message-ID: <20261108101458.0001@client.example.it>";

/// The header fields of a message that passes every check.
fn valid() -> Vec<&'static str> {
    vec![FROM, TO, CC, SUBJECT, DATE, MESSAGE_ID]
}

/// The valid header fields with `field` added last.
fn with(field: &'static str) -> Vec<&'static str> {
    let mut fields = valid();
    fields.push(field);
    fields
}

/// The valid header fields with the one starting `name:` replaced by `fields`.
fn replacing(name: &str, fields: &[&'static str]) -> Vec<&'static str> {
    let prefix = format!("{name}:");
    let mut all = Vec::new();
    for field in valid() {
        if field.starts_with(&prefix) {
            all.extend_from_slice(fields);
        } else {
            all.push(field);
        }
    }
    all
}

/// A message with `fields` as its header, CRLF line ends and a short text body.
fn message(fields: &[&str]) -> Vec<u8> {
    let mut raw = fields.join("\r\n");
    raw.push_str("\r\n\r\nFattura in allegato.\r\n");
    raw.into_bytes()
}

/// The message with `fields` checked for short delivery receipts.
fn prepared(fields: &[&str]) -> Result<OutgoingMessage, Error> {
    OutgoingMessage::prepare(&message(fields), ReceiptKind::Short)
}

/// Asserts that the message with `fields` is refused for `reason`.
#[track_caller]
fn refused(fields: &[&str], reason: OutgoingError) {
    assert_eq!(prepared(fields), Err(Error::Outgoing(reason)));
}

#[test]
fn the_receipt_form_is_written_last_in_the_header() {
    for (kind, field) in [
        (ReceiptKind::Full, "X-TipoRicevuta: completa"),
        (ReceiptKind::Short, "X-TipoRicevuta: breve"),
        (ReceiptKind::Summary, "X-TipoRicevuta: sintetica"),
    ] {
        let outgoing = OutgoingMessage::prepare(&message(&valid()), kind).expect("a valid message");
        assert_eq!(outgoing.as_bytes(), message(&with(field)), "{kind:?}");
    }
}

#[test]
fn the_envelope_is_the_sender_and_each_distinct_recipient() {
    let outgoing = prepared(&valid()).expect("a valid message");
    assert_eq!(outgoing.reverse_path(), "mario.rossi@pec.example.it");
    assert_eq!(
        outgoing.forward_paths(),
        [
            "ufficio.fatture@pec.example.it",
            "paolo.bianchi@example.com",
            "protocollo@pec.example.it"
        ]
    );
    // A local part in another case names another mailbox.
    let outgoing = prepared(&replacing("Cc", &["Cc: Ufficio.Fatture@pec.example.it"]))
        .expect("a valid message");
    assert_eq!(
        outgoing.forward_paths(),
        [
            "ufficio.fatture@pec.example.it",
            "paolo.bianchi@example.com",
            "Ufficio.Fatture@pec.example.it"
        ]
    );
}

#[test]
fn group_members_are_recipients() {
    let outgoing = prepared(&replacing(
        "Cc",
        &["Cc: Protocollo: protocollo@pec.example.it, archivio@pec.example.it;"],
    ))
    .expect("a valid message");
    assert_eq!(
        outgoing.forward_paths(),
        [
            "ufficio.fatture@pec.example.it",
            "paolo.bianchi@example.com",
            "protocollo@pec.example.it",
            "archivio@pec.example.it"
        ]
    );
}

#[test]
fn the_message_id_is_the_one_the_client_wrote() {
    let outgoing = prepared(&valid()).expect("a valid message");
    let expected: MessageId = "<20261108101458.0001@client.example.it>"
        .parse()
        .expect("an identifier");
    assert_eq!(outgoing.message_id(), &expected);
}

#[test]
fn a_bare_line_feed_or_carriage_return_is_refused() {
    // CR and LF only occur together (RFC 5322 §2.3), and an SMTP client sends the bytes as given.
    let refused_at = |raw: &[u8], at: usize| {
        assert_eq!(
            OutgoingMessage::prepare(raw, ReceiptKind::Short),
            Err(Error::Outgoing(OutgoingError::BareLineBreak(at)))
        );
    };
    let crlf = message(&valid());
    let lf: Vec<u8> = crlf.iter().copied().filter(|&byte| byte != b'\r').collect();
    refused_at(&lf, FROM.len());
    refused_at(
        &[crlf.as_slice(), b"riga con\ra capo\r\n"].concat(),
        crlf.len() + "riga con".len(),
    );
    refused_at(&[b"\n".as_slice(), &crlf].concat(), 0);
    refused_at(&[crlf.as_slice(), b"\r"].concat(), crlf.len());
}

#[test]
fn a_message_without_a_body_gets_the_receipt_form_at_its_end() {
    let mut raw = valid().join("\r\n");
    raw.push_str("\r\n");
    let outgoing =
        OutgoingMessage::prepare(raw.as_bytes(), ReceiptKind::Short).expect("a valid message");
    assert_eq!(
        outgoing.as_bytes(),
        format!("{raw}X-TipoRicevuta: breve\r\n").as_bytes()
    );
    // A last field without its line break gets one first.
    let raw = valid().join("\r\n");
    let outgoing =
        OutgoingMessage::prepare(raw.as_bytes(), ReceiptKind::Short).expect("a valid message");
    assert_eq!(
        outgoing.as_bytes(),
        format!("{raw}\r\nX-TipoRicevuta: breve\r\n").as_bytes()
    );
}

#[test]
fn a_receipt_form_already_asked_for_is_kept() {
    for field in ["X-TipoRicevuta: breve", "X-TipoRicevuta:   breve  "] {
        let outgoing = prepared(&with(field)).expect("a valid message");
        assert_eq!(outgoing.as_bytes(), message(&with(field)), "{field}");
    }
}

#[test]
fn another_receipt_form_already_asked_for_is_refused() {
    refused(
        &with("X-TipoRicevuta: sintetica"),
        OutgoingError::ReceiptKind("sintetica".to_owned()),
    );
    refused(
        &with("X-TipoRicevuta: Breve"),
        OutgoingError::ReceiptKind("Breve".to_owned()),
    );
    let mut fields = with("X-TipoRicevuta: breve");
    fields.push("X-TipoRicevuta: completa");
    refused(&fields, OutgoingError::ReceiptKind("completa".to_owned()));
}

#[test]
fn the_sender_is_one_mailbox_in_one_field() {
    refused(&replacing("From", &[]), OutgoingError::From);
    refused(
        &replacing("From", &[FROM, "From: anna.verdi@pec.example.it"]),
        OutgoingError::From,
    );
    refused(
        &replacing(
            "From",
            &["From: mario.rossi@pec.example.it, anna.verdi@pec.example.it"],
        ),
        OutgoingError::From,
    );
    refused(
        &replacing("From", &["From: Ufficio: mario.rossi@pec.example.it;"]),
        OutgoingError::From,
    );
}

#[test]
fn the_primary_recipients_are_in_one_field_naming_one_at_least() {
    refused(&replacing("To", &[]), OutgoingError::To);
    refused(
        &replacing("To", &[TO, "To: anna.verdi@pec.example.it"]),
        OutgoingError::To,
    );
    refused(
        &replacing("To", &["To: undisclosed-recipients:;"]),
        OutgoingError::To,
    );
}

#[test]
fn the_copy_recipients_are_in_one_field_at_most() {
    refused(
        &replacing("Cc", &[CC, "Cc: anna.verdi@pec.example.it"]),
        OutgoingError::Cc,
    );
    let outgoing = prepared(&replacing("Cc", &[])).expect("a valid message");
    assert_eq!(
        outgoing.forward_paths(),
        [
            "ufficio.fatture@pec.example.it",
            "paolo.bianchi@example.com"
        ]
    );
}

#[test]
fn a_hidden_recipient_is_refused() {
    refused(&with("Bcc: anna.verdi@pec.example.it"), OutgoingError::Bcc);
    let mut fields = with("Bcc:");
    fields.push("Bcc: anna.verdi@pec.example.it");
    refused(&fields, OutgoingError::Bcc);
    // An empty Bcc field names nobody.
    let outgoing = prepared(&with("Bcc:")).expect("a valid message");
    assert_eq!(outgoing.forward_paths().len(), 3);
}

#[test]
fn every_address_is_a_dot_atom_address() {
    for (field, address) in [
        (
            "To: Mario <\"mario rossi\"@pec.example.it>",
            "\"mario rossi\"@pec.example.it",
        ),
        ("To: perché@pec.example.it", "perché@pec.example.it"),
        ("To: mario.rossi@[192.0.2.1]", "mario.rossi@[192.0.2.1]"),
        (
            "To: mario..rossi@pec.example.it",
            "mario..rossi@pec.example.it",
        ),
        ("To: .mario@pec.example.it", ".mario@pec.example.it"),
        ("To: mario.rossi@", "mario.rossi@"),
        ("To: mario.rossi@pec.example.", "mario.rossi@pec.example."),
    ] {
        assert_eq!(
            prepared(&replacing("To", &[field])),
            Err(Error::Outgoing(OutgoingError::Address(address.to_owned()))),
            "{field}"
        );
    }
    // A mailbox without an address, such as a bare name, is named by an empty address.
    refused(
        &replacing("From", &["From: mario.rossi"]),
        OutgoingError::Address(String::new()),
    );
    refused(
        &replacing("Cc", &["Cc: Mario Rossi"]),
        OutgoingError::Address(String::new()),
    );
    let outgoing = prepared(&replacing("To", &["To: o'brien+fatture@pec.example.it"]))
        .expect("a valid message");
    assert_eq!(
        outgoing.forward_paths()[0],
        "o'brien+fatture@pec.example.it"
    );
}

#[test]
fn the_message_has_one_valid_identifier() {
    refused(&replacing("Message-ID", &[]), OutgoingError::MessageId);
    refused(
        &replacing(
            "Message-ID",
            &[MESSAGE_ID, "Message-ID: <altro@client.example.it>"],
        ),
        OutgoingError::MessageId,
    );
    refused(
        &replacing("Message-ID", &["Message-ID: <senza-dominio>"]),
        OutgoingError::MessageId,
    );
    // One field holds one identifier, so a second one is refused instead of choosing either (RFC 5322 §3.6.4).
    refused(
        &replacing(
            "Message-ID",
            &["Message-ID: <uno@client.example.it> <due@client.example.it>"],
        ),
        OutgoingError::MessageId,
    );
    let outgoing = prepared(&replacing(
        "Message-ID",
        &["Message-ID:\r\n <20261108101458.0001@client.example.it>"],
    ))
    .expect("a folded field");
    let expected: MessageId = "<20261108101458.0001@client.example.it>"
        .parse()
        .expect("an identifier");
    assert_eq!(outgoing.message_id(), &expected);
}

#[test]
fn the_message_has_one_valid_date() {
    refused(&replacing("Date", &[]), OutgoingError::Date);
    refused(
        &replacing("Date", &[DATE, "Date: Mon, 9 Nov 2026 08:30:00 +0100"]),
        OutgoingError::Date,
    );
    refused(&replacing("Date", &["Date: ieri"]), OutgoingError::Date);
}

#[test]
fn bytes_that_are_not_a_message_are_refused() {
    assert_eq!(
        OutgoingMessage::prepare(b"", ReceiptKind::Full),
        Err(Error::NotMime)
    );
}

/// The valid message with `body` as its body, checked for short delivery receipts.
fn with_body(body: &str) -> OutgoingMessage {
    let mut raw = valid().join("\r\n");
    raw.push_str("\r\n\r\n");
    raw.push_str(body);
    OutgoingMessage::prepare(raw.as_bytes(), ReceiptKind::Short).expect("a valid message")
}

/// The valid message with `count` distinct primary recipients and no copy recipient.
fn with_recipients(count: usize) -> OutgoingMessage {
    let addresses: Vec<String> = (0..count)
        .map(|n| format!("ufficio{n}@pec.example.it"))
        .collect();
    let to = format!("To: {}", addresses.join(", "));
    let mut fields: Vec<&str> = valid()
        .into_iter()
        .filter(|field| !field.starts_with("To:") && !field.starts_with("Cc:"))
        .collect();
    fields.push(&to);
    prepared(&fields).expect("a valid message")
}

/// Limits of `recipients` and `size_times_recipients` bytes.
const fn limits(recipients: usize, size_times_recipients: u64) -> Limits {
    Limits {
        recipients,
        size_times_recipients,
    }
}

/// The length of `outgoing` in bytes.
fn length(outgoing: &OutgoingMessage) -> u64 {
    u64::try_from(outgoing.as_bytes().len()).expect("a length")
}

#[test]
fn the_recipients_are_within_the_limit() {
    let outgoing = prepared(&valid()).expect("a valid message");
    assert_eq!(outgoing.check_limits(limits(3, u64::MAX)), Ok(()));
    assert_eq!(
        outgoing.check_limits(limits(2, u64::MAX)),
        Err(Error::Outgoing(OutgoingError::TooManyRecipients {
            recipients: 3,
            limit: 2
        }))
    );
}

#[test]
fn the_size_times_the_recipients_is_within_the_limit() {
    let outgoing = prepared(&valid()).expect("a valid message");
    let total = 3 * length(&outgoing);
    assert_eq!(outgoing.check_limits(limits(50, total)), Ok(()));
    assert_eq!(
        outgoing.check_limits(limits(50, total - 1)),
        Err(Error::Outgoing(OutgoingError::TooLarge {
            total,
            limit: total - 1
        }))
    );
}

#[test]
fn a_message_without_a_final_line_break_counts_the_crlf_smtp_adds() {
    // SMTP ends the last line with the first CRLF of `<CRLF>.<CRLF>` (RFC 5321 §4.1.1.4), and the size counts it.
    let outgoing = with_body("Fattura in allegato.");
    let total = 3 * (length(&outgoing) + 2);
    assert_eq!(outgoing.check_limits(limits(50, total)), Ok(()));
    assert_eq!(
        outgoing.check_limits(limits(50, total - 1)),
        Err(Error::Outgoing(OutgoingError::TooLarge {
            total,
            limit: total - 1
        }))
    );
}

#[test]
fn every_provider_accepts_fifty_recipients_and_thirty_megabytes_in_all() {
    // Three recipients share 30,000,000 bytes, so a message of 10,000,000 bytes fits and one byte more does not.
    let header = usize::try_from(length(&with_body("\r\n"))).expect("a length");
    let fits = with_body(&format!("{}\r\n", "a".repeat(10_000_000 - header)));
    assert_eq!(length(&fits), 10_000_000);
    assert_eq!(fits.check_limits(Limits::GUARANTEED), Ok(()));
    let over = with_body(&format!("{}\r\n", "a".repeat(10_000_001 - header)));
    assert_eq!(
        over.check_limits(Limits::GUARANTEED),
        Err(Error::Outgoing(OutgoingError::TooLarge {
            total: 30_000_003,
            limit: 30_000_000
        }))
    );
    assert_eq!(with_recipients(50).check_limits(Limits::GUARANTEED), Ok(()));
    assert_eq!(
        with_recipients(51).check_limits(Limits::GUARANTEED),
        Err(Error::Outgoing(OutgoingError::TooManyRecipients {
            recipients: 51,
            limit: 50
        }))
    );
}
