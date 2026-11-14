//! Building an outgoing message that the sender's PEC provider accepts (§6.3.1), asking for a receipt form
//! (§6.5.2.2, §6.5.2.3).

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use base64ct::{Base64, Encoding};
use jiff::Zoned;
use jiff::civil::DateTime;
use jiff::tz::{Offset, TimeZone};
use mail_parser::MessageParser;
use postacert::{
    Error, Mailbox, MessageId, OutgoingError, OutgoingMessage, OutgoingMessageBuilder, ReceiptKind,
};

/// The date the messages are built at.
fn date() -> Zoned {
    "2026-11-08T10:14:58+01:00[+01:00]"
        .parse()
        .expect("a date with its offset")
}

/// The identifier `text`.
fn id(text: &str) -> MessageId {
    text.parse().expect("a message identifier")
}

/// The mailbox at `address`.
fn mailbox(address: &str) -> Mailbox {
    Mailbox::new(address).expect("a dot-atom address")
}

/// The mailbox `name` at `address`.
fn named(name: &str, address: &str) -> Mailbox {
    Mailbox::named(name, address).expect("a display name and a dot-atom address")
}

/// A message from Mario Rossi to the invoice office.
fn builder() -> OutgoingMessageBuilder {
    OutgoingMessage::builder(
        named("Mario Rossi", "mario.rossi@pec.example.it"),
        mailbox("ufficio.fatture@pec.example.it"),
        id("<20261108101458.0001@client.example.it>"),
        date(),
    )
}

/// A subject long enough to fold, of Italian words.
const LONG_SUBJECT: &str = "Invio della fattura elettronica numero 00012 relativa alla fornitura di materiale di \
     cancelleria per gli uffici della sede centrale nel mese di ottobre";

/// A subject long enough to fold, outside ASCII.
const LONG_ACCENTED_SUBJECT: &str = "Fattura n° 12 — consegna caffè e tè per l'ufficio di Città di Castello, \
     più la nota di credito già concordata con l'amministrazione";

/// A body with accents, a line longer than 76 columns and line breaks of every form.
const TEXT: &str = "Buongiorno,\nin allegato la fattura n° 12 per la fornitura di caffè e tè.\r\nQuesta riga \
     supera di molto i settantasei caratteri ammessi per una riga di testo codificata.\rCordiali saluti\n";

/// An HTML version of [`TEXT`], with accents, a line longer than 76 columns and line breaks of every form.
const HTML: &str = "<p>Buongiorno,<br>\nin allegato la fattura n° 12 per la fornitura di caffè e tè.</p>\r\n<p>Questa \
     riga supera di molto i settantasei caratteri ammessi per una riga di testo codificata.</p>\r<p>Cordiali \
     saluti</p>\n";

/// A message to attach, in 7-bit bytes.
const ATTACHED: &str = "From: mario.rossi@pec.example.it\r\nTo: ufficio.fatture@pec.example.it\r\nSubject: Fattura \
     00011\r\n\r\nFattura in allegato.\r\n";

/// A message to attach, in 8-bit bytes.
const ATTACHED_8BIT: &str = "Subject: Città\r\n\r\nCaffè e tè.\r\n";

/// Every byte value, over more than one base64 line.
fn binary() -> Vec<u8> {
    (0..=255_u8).cycle().take(1000).collect()
}

/// The content types of the parts of `built` as mail-parser reads them, in order, `text/plain` for a part without one
/// (RFC 2045 §5.2).
fn content_types(built: &OutgoingMessage) -> Vec<String> {
    let parsed = MessageParser::default()
        .parse(built.as_bytes())
        .expect("MIME");
    parsed
        .parts()
        .map(|part| {
            part.content_type().map_or_else(
                || "text/plain".to_owned(),
                |content_type| {
                    format!(
                        "{}/{}",
                        content_type.ctype(),
                        content_type.subtype().unwrap_or_default()
                    )
                },
            )
        })
        .collect()
}

/// `text` with every line break written as CRLF.
fn crlf(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

/// Builders covering every header and body form the builder writes.
fn variants() -> Vec<OutgoingMessageBuilder> {
    vec![
        builder(),
        builder()
            .subject("Invio fattura 00012")
            .text("Fattura in allegato."),
        builder().subject(LONG_SUBJECT).text(TEXT),
        builder()
            .subject(LONG_ACCENTED_SUBJECT)
            .text("Città: Perugia"),
        builder()
            .to(named("Ufficio Protocollo", "protocollo@pec.example.it"))
            .cc(named("Rossi, Mario", "mario.rossi@example.com"))
            .cc(named("Niccolò Bianchi", "niccolo.bianchi@pec.example.it"))
            .reply_to(mailbox("segreteria@pec.example.it"))
            .in_reply_to(id("<previous.0001@client.example.it>"))
            .references([
                id("<first.0001@client.example.it>"),
                id("<previous.0001@client.example.it>"),
            ]),
        builder().receipt(ReceiptKind::Short),
        builder().receipt(ReceiptKind::Summary),
        builder()
            .subject("Invio fattura 00012")
            .text(TEXT)
            .html(HTML),
        builder().html("<p>Fattura in allegato.</p>"),
        builder().text("Fattura in allegato.").attachment(
            "fattura.pdf",
            "application/pdf",
            binary(),
        ),
        builder()
            .text(TEXT)
            .html(HTML)
            .attachment("nota caffè.txt", "text/plain", "Totale 41 €\r\n".as_bytes())
            .attached_message(ATTACHED.as_bytes())
            .attached_message(ATTACHED_8BIT.as_bytes()),
    ]
}

#[test]
fn built_messages_pass_prepare_unchanged() {
    for (index, variant) in variants().into_iter().enumerate() {
        let built = variant.build().expect("a buildable message");
        for kind in [ReceiptKind::Full, ReceiptKind::Short, ReceiptKind::Summary] {
            let prepared = OutgoingMessage::prepare(built.as_bytes(), kind);
            let asked = MessageParser::default()
                .parse(built.as_bytes())
                .expect("MIME")
                .headers()
                .all("X-TipoRicevuta")
                .map(|field| String::from_utf8_lossy(field.raw_value().trim_ascii()).into_owned())
                .collect::<Vec<_>>();
            if asked == [token(kind)] {
                assert_eq!(prepared.as_ref(), Ok(&built), "variant {index}, {kind:?}");
            } else {
                assert!(prepared.is_err(), "variant {index}, {kind:?}");
            }
        }
    }
}

/// The `X-TipoRicevuta` value of `kind` (§6.5.2.2).
const fn token(kind: ReceiptKind) -> &'static str {
    match kind {
        ReceiptKind::Full => "completa",
        ReceiptKind::Short => "breve",
        ReceiptKind::Summary => "sintetica",
    }
}

#[test]
fn the_receipt_form_is_written_and_full_by_default() {
    for (variant, kind) in [
        (builder(), ReceiptKind::Full),
        (builder().receipt(ReceiptKind::Short), ReceiptKind::Short),
        (
            builder().receipt(ReceiptKind::Summary),
            ReceiptKind::Summary,
        ),
    ] {
        let built = variant.build().expect("a buildable message");
        let parsed = MessageParser::default()
            .parse(built.as_bytes())
            .expect("MIME");
        let values = parsed
            .headers()
            .all("X-TipoRicevuta")
            .map(|field| String::from_utf8_lossy(field.raw_value().trim_ascii()).into_owned())
            .collect::<Vec<_>>();
        assert_eq!(values, [token(kind)], "{kind:?}");
    }
}

#[test]
fn mail_parser_reads_back_every_field() {
    let built = builder()
        .to(named("Ufficio Protocollo", "protocollo@pec.example.it"))
        .cc(named("Rossi, Mario", "mario.rossi@example.com"))
        .cc(named(
            "Niccolò \"il Magnifico\" Bianchi",
            "niccolo.bianchi@pec.example.it",
        ))
        .cc(named(
            r#"Studio "Rossi" \ Bianchi"#,
            "studio@pec.example.it",
        ))
        .reply_to(named("Segreteria — Sede", "segreteria@pec.example.it"))
        .in_reply_to(id("<previous.0001@client.example.it>"))
        .references([
            id("<first.0001@client.example.it>"),
            id("<previous.0001@client.example.it>"),
        ])
        .subject(LONG_ACCENTED_SUBJECT)
        .text(TEXT)
        .build()
        .expect("a buildable message");
    let parsed = MessageParser::default()
        .parse(built.as_bytes())
        .expect("MIME");
    let mailboxes = |list: Option<mail_parser::AddressList<'_>>| {
        list.expect("an address list")
            .mailboxes()
            .map(|mailbox| {
                (
                    mailbox.name().map(str::to_owned),
                    mailbox.address().map(str::to_owned),
                )
            })
            .collect::<Vec<_>>()
    };
    let pair =
        |name: Option<&str>, address: &str| (name.map(str::to_owned), Some(address.to_owned()));
    assert_eq!(
        mailboxes(parsed.from()),
        [pair(Some("Mario Rossi"), "mario.rossi@pec.example.it")]
    );
    assert_eq!(
        mailboxes(parsed.to()),
        [
            pair(None, "ufficio.fatture@pec.example.it"),
            pair(Some("Ufficio Protocollo"), "protocollo@pec.example.it"),
        ]
    );
    assert_eq!(
        mailboxes(parsed.cc()),
        [
            pair(Some("Rossi, Mario"), "mario.rossi@example.com"),
            pair(
                Some("Niccolò \"il Magnifico\" Bianchi"),
                "niccolo.bianchi@pec.example.it"
            ),
            pair(Some(r#"Studio "Rossi" \ Bianchi"#), "studio@pec.example.it"),
        ]
    );
    assert_eq!(
        mailboxes(parsed.reply_to()),
        [pair(Some("Segreteria — Sede"), "segreteria@pec.example.it")]
    );
    assert_eq!(parsed.subject(), Some(LONG_ACCENTED_SUBJECT));
    assert_eq!(
        parsed.message_id(),
        Some("20261108101458.0001@client.example.it")
    );
    assert_eq!(
        parsed
            .in_reply_to()
            .expect("In-Reply-To")
            .iter()
            .collect::<Vec<_>>(),
        ["previous.0001@client.example.it"]
    );
    assert_eq!(
        parsed
            .references()
            .expect("References")
            .iter()
            .collect::<Vec<_>>(),
        [
            "first.0001@client.example.it",
            "previous.0001@client.example.it"
        ]
    );
    assert_eq!(
        parsed.date().expect("a Date").to_timestamp(),
        date().timestamp().as_second()
    );
    assert_eq!(
        parsed.body_text(0).expect("a text body"),
        crlf(TEXT).as_str()
    );
    assert_eq!(
        built.message_id(),
        &id("<20261108101458.0001@client.example.it>")
    );
}

#[test]
fn an_html_version_goes_after_the_text_in_a_multipart_alternative() {
    let built = builder()
        .text(TEXT)
        .html(HTML)
        .build()
        .expect("a buildable message");
    assert_well_formed(&built);
    assert_eq!(
        content_types(&built),
        ["multipart/alternative", "text/plain", "text/html"]
    );
    let parsed = MessageParser::default()
        .parse(built.as_bytes())
        .expect("MIME");
    assert_eq!(
        parsed.body_text(0).expect("a text body"),
        crlf(TEXT).as_str()
    );
    assert_eq!(
        parsed.body_html(0).expect("an HTML body"),
        crlf(HTML).as_str()
    );
}

#[test]
fn a_text_holding_another_messages_delimiters_reads_back_as_written() {
    let other = builder()
        .text("Fattura in allegato.")
        .html(HTML)
        .build()
        .expect("a buildable message");
    let (header, _) = header_and_body(&other);
    let boundary = header
        .split_once("boundary=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(boundary, _)| boundary)
        .expect("a boundary");
    let text = format!("Fattura in allegato.\r\n--{boundary}\r\n\r\n--{boundary}--");
    let built = builder()
        .text(text.as_str())
        .html(HTML)
        .build()
        .expect("a buildable message");
    let parsed = MessageParser::default()
        .parse(built.as_bytes())
        .expect("MIME");
    assert_eq!(parsed.body_text(0).expect("a text body"), text.as_str());
    assert_eq!(
        parsed.body_html(0).expect("an HTML body"),
        crlf(HTML).as_str()
    );
}

#[test]
fn attachments_follow_the_body_in_order() {
    let built = builder()
        .text(TEXT)
        .html(HTML)
        .attachment("fattura.pdf", "application/pdf", binary())
        .attached_message(ATTACHED.as_bytes())
        .attachment("nota.txt", "text/plain", b"Totale 41\r\n")
        .build()
        .expect("a buildable message");
    assert_well_formed(&built);
    // mail-parser lists the attached message's own body after it.
    assert_eq!(
        content_types(&built),
        [
            "multipart/mixed",
            "multipart/alternative",
            "text/plain",
            "text/html",
            "application/pdf",
            "message/rfc822",
            "text/plain",
            "text/plain"
        ]
    );
    let parsed = MessageParser::default()
        .parse(built.as_bytes())
        .expect("MIME");
    assert_eq!(
        parsed.body_text(0).expect("a text body"),
        crlf(TEXT).as_str()
    );
    assert_eq!(
        parsed.body_html(0).expect("an HTML body"),
        crlf(HTML).as_str()
    );
    let attachments = parsed
        .attachments()
        .map(|part| {
            (
                part.attachment_name().map(str::to_owned),
                part.nested().map_or_else(
                    || part.decoded().into_owned(),
                    |message| message.raw().to_vec(),
                ),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        attachments,
        [
            (Some("fattura.pdf".to_owned()), binary()),
            (None, ATTACHED.as_bytes().to_vec()),
            (Some("nota.txt".to_owned()), b"Totale 41\r\n".to_vec()),
        ]
    );
}

#[test]
fn attachment_names_read_back_as_written() {
    // A quoted name takes a line with ` filename=""`, 12 columns, so 66 characters fill column 78.
    let fits = format!("{}.pdf", "a".repeat(62));
    let long = format!("{}.pdf", "a".repeat(63));
    let euros = "€".repeat(40);
    for (name, quoted) in [
        ("fattura.pdf", true),
        (fits.as_str(), true),
        (long.as_str(), false),
        (r#"Fattura "bozza" C:\00012.pdf"#, true),
        (" spazi  doppi ", true),
        ("fattura caffè.pdf", false),
        ("riga\r\nnuova\t.pdf", false),
        (euros.as_str(), false),
    ] {
        let built = builder()
            .attachment(name, "application/pdf", b"%PDF-1.7")
            .build()
            .expect("a buildable message");
        assert_well_formed(&built);
        let text = core::str::from_utf8(built.as_bytes()).expect("ASCII");
        assert_eq!(text.contains(" filename=\""), quoted, "{name:?}");
        assert_eq!(text.contains(" filename*0*=utf-8''"), !quoted, "{name:?}");
        let parsed = MessageParser::default()
            .parse(built.as_bytes())
            .expect("MIME");
        let names = parsed
            .attachments()
            .map(|part| part.attachment_name().map(str::to_owned))
            .collect::<Vec<_>>();
        assert_eq!(names, [Some(name.to_owned())], "{name:?}");
    }
}

#[test]
fn attachments_take_discrete_content_types() {
    for valid in [
        "application/pdf",
        "text/plain",
        "application/vnd.ms-excel",
        "image/svg+xml",
        "Application/PDF",
    ] {
        let built = builder()
            .attachment("allegato", valid, b"x")
            .build()
            .expect("a discrete type/subtype");
        assert_eq!(
            content_types(&built).last(),
            Some(&valid.to_ascii_lowercase()),
            "{valid}"
        );
    }
    for invalid in [
        "",
        "application",
        "application/",
        "/pdf",
        "application/pdf; name=x",
        "application/p df",
        "application/pdf/x",
        "text/(plain)",
        "application/pdf\u{e8}",
        "multipart/mixed",
        "Message/rfc822",
    ] {
        assert_eq!(
            builder().attachment("allegato", invalid, b"x").build(),
            Err(Error::Outgoing(OutgoingError::ContentType(
                invalid.to_owned()
            ))),
            "{invalid:?}"
        );
    }
    // "Content-Type: " takes 14 columns, so a content type of 984 characters fills a line of 998.
    for (length, valid) in [(984, true), (985, false)] {
        let content_type = format!("application/{}", "x".repeat(length - "application/".len()));
        let built = builder()
            .attachment("allegato", content_type.as_str(), b"x")
            .build();
        if valid {
            built.expect("a line of 998 columns");
        } else {
            assert_eq!(
                built,
                Err(Error::Outgoing(OutgoingError::LineTooLong("Content-Type")))
            );
        }
    }
}

#[test]
fn an_empty_attachment_name_is_refused() {
    assert_eq!(
        builder()
            .attachment("fattura.pdf", "application/pdf", b"x")
            .attachment("", "application/pdf", b"y")
            .build(),
        Err(Error::Outgoing(OutgoingError::AttachmentName(1)))
    );
}

#[test]
fn attached_messages_neither_7bit_nor_8bit_carries_are_refused() {
    let line = |length: usize| format!("{}\r\n", "x".repeat(length));
    for (raw, at) in [
        ("a\nb".to_owned(), Some(1)),
        ("\nb".to_owned(), Some(0)),
        ("a\rb".to_owned(), Some(1)),
        ("a\r".to_owned(), Some(1)),
        ("a\0b\r\n".to_owned(), Some(1)),
        (line(999), Some(998)),
        (format!("{}{}", line(10), line(999)), Some(12 + 998)),
        (line(998), None),
        (format!("Subject: x\r\n\r\n{}", line(998)), None),
    ] {
        let built = builder()
            .attachment("fattura.pdf", "application/pdf", b"x")
            .attached_message(raw.as_bytes())
            .build();
        match at {
            Some(at) => assert_eq!(
                built,
                Err(Error::Outgoing(OutgoingError::AttachedMessage {
                    attachment: 1,
                    at
                })),
                "{raw:?}"
            ),
            None => assert_eq!(
                MessageParser::default()
                    .parse(built.expect("a message 8bit carries").as_bytes())
                    .expect("MIME")
                    .attachments()
                    .filter_map(|part| part.nested().map(|message| message.raw().to_vec()))
                    .collect::<Vec<_>>(),
                [raw.as_bytes().to_vec()],
                "{raw:?}"
            ),
        }
    }
}

#[test]
fn an_8bit_attached_message_makes_the_message_8bit() {
    for (raw, encoding) in [(ATTACHED, "7bit"), (ATTACHED_8BIT, "8bit")] {
        let built = builder()
            .attached_message(raw.as_bytes())
            .build()
            .expect("a buildable message");
        let (header, _) = header_and_body(&built);
        assert_eq!(
            header.contains("\r\nContent-Transfer-Encoding: 8bit"),
            encoding == "8bit",
            "{encoding}"
        );
        assert_eq!(built.as_bytes().is_ascii(), encoding == "7bit");
        let parsed = MessageParser::default()
            .parse(built.as_bytes())
            .expect("MIME");
        let part = parsed.attachments().next().expect("the attached message");
        assert_eq!(part.content_transfer_encoding(), Some(encoding));
        assert_eq!(part.nested().expect("a message").raw(), raw.as_bytes());
    }
}

#[test]
fn text_that_looks_encoded_reads_back_as_written() {
    for text in [
        "=?utf-8?B?ZXZpbA==?=",
        " leading and trailing ",
        "double  space",
        "tab\there",
    ] {
        let built = builder()
            .to(named(text, "protocollo@pec.example.it"))
            .subject(text)
            .build()
            .expect("a buildable message");
        let parsed = MessageParser::default()
            .parse(built.as_bytes())
            .expect("MIME");
        assert_eq!(parsed.subject(), Some(text), "{text:?}");
        let names = parsed
            .to()
            .expect("To")
            .mailboxes()
            .map(|mailbox| mailbox.name().map(str::to_owned))
            .collect::<Vec<_>>();
        assert_eq!(names, [None, Some(text.to_owned())], "{text:?}");
    }
}

#[test]
fn the_envelope_is_the_sender_and_each_distinct_recipient() {
    let built = builder()
        .to(mailbox("paolo.bianchi@example.com"))
        .cc(mailbox("protocollo@pec.example.it"))
        .cc(named("Ufficio", "ufficio.fatture@PEC.Example.IT"))
        .cc(mailbox("Ufficio.Fatture@pec.example.it"))
        .build()
        .expect("a buildable message");
    assert_eq!(built.reverse_path(), "mario.rossi@pec.example.it");
    assert_eq!(
        built.forward_paths(),
        [
            "ufficio.fatture@pec.example.it",
            "paolo.bianchi@example.com",
            "protocollo@pec.example.it",
            "Ufficio.Fatture@pec.example.it"
        ]
    );
}

#[test]
fn lines_fold_within_78_columns() {
    let mut many = builder().subject(LONG_SUBJECT).text(TEXT);
    for index in 0..12 {
        many = many.cc(named(
            &format!("Ufficio numero {index}"),
            &format!("ufficio.{index}@pec.example.it"),
        ));
    }
    for built in [
        many.build().expect("a buildable message"),
        builder()
            .subject(LONG_ACCENTED_SUBJECT)
            .text(TEXT)
            .build()
            .expect("a buildable message"),
    ] {
        let text = core::str::from_utf8(built.as_bytes()).expect("ASCII");
        let (header, body) = text.split_once("\r\n\r\n").expect("a header and a body");
        for line in header.split("\r\n") {
            assert!(line.len() <= 78, "{line:?}");
        }
        for line in body.split("\r\n") {
            assert!(line.len() <= 76, "{line:?}");
        }
    }
}

#[test]
fn text_line_breaks_are_written_as_crlf() {
    let built = builder()
        .text("uno\ndue\rtre\r\nquattro")
        .build()
        .expect("a buildable message");
    let parsed = MessageParser::default()
        .parse(built.as_bytes())
        .expect("MIME");
    assert_eq!(
        parsed.body_text(0).expect("a text body"),
        "uno\r\ndue\r\ntre\r\nquattro"
    );
    OutgoingMessage::prepare(built.as_bytes(), ReceiptKind::Full).expect("CRLF line ends only");
}

#[test]
fn mailboxes_hold_dot_atom_addresses() {
    for address in [
        "mario rossi@pec.example.it",
        "\"mario\"@pec.example.it",
        "mario@[192.0.2.1]",
        "@pec.example.it",
        "mario.rossi",
        "mario..rossi@pec.example.it",
    ] {
        assert_eq!(
            Mailbox::new(address),
            Err(Error::Outgoing(OutgoingError::Address(address.to_owned()))),
            "{address:?}"
        );
    }
    let mailbox = mailbox("mario.rossi@pec.example.it");
    assert_eq!(mailbox.address(), "mario.rossi@pec.example.it");
    assert_eq!(mailbox.name(), None);
    let named = named("Mario Rossi", "mario.rossi@pec.example.it");
    assert_eq!(named.name(), Some("Mario Rossi"));
}

#[test]
fn control_characters_are_refused() {
    let injected = "Mario\r\nBcc: spia@example.com";
    assert_eq!(
        Mailbox::named(injected, "mario.rossi@pec.example.it"),
        Err(Error::Outgoing(OutgoingError::DisplayName(
            injected.to_owned()
        )))
    );
    for subject in [injected, "Fattura\u{7}", "Fattura\u{85}"] {
        assert_eq!(
            builder().subject(subject).build(),
            Err(Error::Outgoing(OutgoingError::Subject(subject.to_owned()))),
            "{subject:?}"
        );
    }
}

#[test]
fn identifiers_outside_ascii_are_refused() {
    let accented = "fattura.caffè@client.example.it";
    for (field, variant) in [
        (
            "Message-ID",
            OutgoingMessage::builder(
                mailbox("mario.rossi@pec.example.it"),
                mailbox("ufficio.fatture@pec.example.it"),
                id(accented),
                date(),
            ),
        ),
        ("In-Reply-To", builder().in_reply_to(id(accented))),
        (
            "References",
            builder().references([id("<20261107090000.0001@client.example.it>"), id(accented)]),
        ),
    ] {
        assert_eq!(
            variant.build(),
            Err(Error::Outgoing(OutgoingError::Identifier(
                accented.to_owned()
            ))),
            "{field}"
        );
    }
}

#[test]
fn dates_the_header_cannot_hold_are_refused() {
    for (time, offset, valid) in [
        ("1899-12-31T23:59:59", 0, false),
        ("1900-01-01T00:00:00", 0, true),
        ("3000-12-31T23:59:59", 0, true),
        ("3001-01-01T00:00:00", 0, false),
        ("2026-11-08T10:14:58", 86_340, true),
        ("2026-11-08T10:14:58", -86_340, true),
        ("2026-11-08T10:14:58", 86_400, false),
        ("2026-11-08T10:14:58", -86_400, false),
        ("2026-11-08T10:14:58", 3_630, false),
    ] {
        let date = time
            .parse::<DateTime>()
            .expect("a civil date and time")
            .to_zoned(TimeZone::fixed(
                Offset::from_seconds(offset).expect("an offset jiff holds"),
            ))
            .expect("a date in jiff's range");
        let built = OutgoingMessage::builder(
            mailbox("mario.rossi@pec.example.it"),
            mailbox("ufficio.fatture@pec.example.it"),
            id("<20261108101458.0001@client.example.it>"),
            date,
        )
        .build();
        let text = format!("{time} {offset}");
        if valid {
            let built = built.expect("a date the header holds");
            assert_eq!(
                OutgoingMessage::prepare(built.as_bytes(), ReceiptKind::Full).as_ref(),
                Ok(&built),
                "{text}"
            );
        } else {
            assert_eq!(built, Err(Error::Outgoing(OutgoingError::Date)), "{text}");
        }
    }
}

#[test]
fn a_word_too_long_for_one_line_is_refused() {
    // A field folds before a long word, which then takes a line with one space before it, so a word of 997 columns
    // fills a line of 998: an address alone, or an identifier of 995 characters between angle brackets.
    let address =
        |length: usize| format!("{}@example.it", "a".repeat(length - "@example.it".len()));
    let identifier = |length: usize| id(&format!("<{}>", address(length)));
    let from = |from: Mailbox, message_id: MessageId| {
        OutgoingMessage::builder(
            from,
            mailbox("ufficio.fatture@pec.example.it"),
            message_id,
            date(),
        )
    };
    for (length, valid) in [(997, true), (998, false)] {
        let long = || mailbox(&address(length));
        for (field, variant) in [
            (
                "From",
                from(long(), id("<20261108101458.0001@client.example.it>")),
            ),
            ("Reply-To", builder().reply_to(long())),
            ("To", builder().to(long())),
            ("Cc", builder().cc(long())),
        ] {
            check_word_length(field, variant, valid, length);
        }
    }
    for (length, valid) in [(995, true), (996, false)] {
        for (field, variant) in [
            (
                "Message-ID",
                from(mailbox("mario.rossi@pec.example.it"), identifier(length)),
            ),
            ("In-Reply-To", builder().in_reply_to(identifier(length))),
            ("References", builder().references([identifier(length)])),
        ] {
            check_word_length(field, variant, valid, length);
        }
    }
}

/// Asserts that `variant` builds when `valid`, and is refused for a word too long for a line of `field` otherwise.
#[track_caller]
fn check_word_length(
    field: &'static str,
    variant: OutgoingMessageBuilder,
    valid: bool,
    length: usize,
) {
    let built = variant.build();
    if valid {
        built.expect("a line of 998 columns");
    } else {
        assert_eq!(
            built,
            Err(Error::Outgoing(OutgoingError::LineTooLong(field))),
            "{field} {length}"
        );
    }
}

/// The header of `built`, unfolded, and its body.
fn header_and_body(built: &OutgoingMessage) -> (String, String) {
    let text = core::str::from_utf8(built.as_bytes()).expect("an ASCII message");
    let (header, body) = text.split_once("\r\n\r\n").expect("a header and a body");
    (header.replace("\r\n ", " "), body.to_owned())
}

/// Asserts what RFC 5322, RFC 2045 and RFC 2047 ask of the bytes of `built`, which a lenient reader would forgive:
/// 7-bit bytes and no control character but CR and LF in line breaks and tab, header lines within 78 columns, encoded
/// words of at most 75 characters each holding whole UTF-8 characters, body lines within 76 columns ending in no white
/// space, and every quoted-printable `=` escaping two uppercase hexadecimal digits or breaking the line.
#[track_caller]
fn assert_well_formed(built: &OutgoingMessage) {
    let raw = built.as_bytes();
    assert!(raw.is_ascii(), "8-bit bytes");
    assert!(
        raw.iter()
            .all(|byte| !byte.is_ascii_control() || matches!(byte, b'\t' | b'\r' | b'\n')),
        "a control character"
    );
    let text = core::str::from_utf8(raw).expect("ASCII");
    let (header, body) = text.split_once("\r\n\r\n").expect("a header and a body");
    for line in header.split("\r\n") {
        assert!(line.len() <= 78, "{line:?}");
        for word in line.split(' ').filter(|word| word.starts_with("=?")) {
            assert!(word.len() <= 75, "{word:?}");
            let payload = word
                .strip_prefix("=?utf-8?B?")
                .and_then(|rest| rest.strip_suffix("?="))
                .expect("a UTF-8 base64 encoded word");
            assert!(!payload.is_empty(), "an empty encoded word in {line:?}");
            let decoded = Base64::decode_vec(payload).expect("base64");
            String::from_utf8(decoded).expect("whole UTF-8 characters");
        }
    }
    assert_body_well_formed(header, body);
}

/// Asserts that the lines of `body` stay within 76 columns ending in no white space, and that every `=` of a
/// quoted-printable body escapes two uppercase hexadecimal digits or breaks the line, for each part in turn when
/// `header` makes it a multipart.
#[track_caller]
fn assert_body_well_formed(header: &str, body: &str) {
    let unfolded = header.replace("\r\n ", " ");
    if let Some((_, rest)) = unfolded.split_once("; boundary=\"") {
        let boundary = rest.split_once('"').expect("a quoted boundary").0;
        let parts = body
            .strip_prefix(&format!("--{boundary}\r\n"))
            .and_then(|rest| rest.strip_suffix(&format!("\r\n--{boundary}--")))
            .expect("parts between delimiter lines");
        for part in parts.split(&format!("\r\n--{boundary}\r\n")) {
            let (header, body) = part
                .split_once("\r\n\r\n")
                .expect("a part header and a body");
            for line in header.split("\r\n") {
                assert!(line.len() <= 78, "{line:?}");
            }
            assert_body_well_formed(header, body);
        }
        return;
    }
    if unfolded.contains("Content-Type: message/rfc822") {
        // An attached message goes as given, in lines of up to 998 octets (RFC 5322 §2.1.1).
        for line in body.split("\r\n") {
            assert!(line.len() <= 998, "{line:?}");
        }
        return;
    }
    let quoted_printable = unfolded.contains("Content-Transfer-Encoding: quoted-printable");
    for line in body.split("\r\n") {
        assert!(line.len() <= 76, "{line:?}");
        assert!(!line.ends_with([' ', '\t']), "{line:?}");
        if quoted_printable {
            for (at, _) in line.match_indices('=') {
                let escape = line.get(at + 1..at + 3);
                let breaks_line = at + 1 == line.len();
                let hex = escape.is_some_and(|digits| {
                    digits
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
                });
                assert!(hex || breaks_line, "{line:?}");
            }
        }
    }
}

#[test]
fn written_bytes_follow_the_rfcs() {
    let long_word = "x".repeat(79);
    let names = [
        "Rossi, Mario",
        &format!("Rossi, {}", "a".repeat(70)),
        "Niccolò Bianchi",
        "€".repeat(40).as_str(),
    ]
    .map(str::to_owned);
    let subjects = [
        String::new(),
        "€".repeat(40),
        "è".repeat(50),
        format!("Fattura\t{}", "x".repeat(100)),
        format!("Invio {long_word}"),
        LONG_SUBJECT.to_owned(),
        LONG_ACCENTED_SUBJECT.to_owned(),
    ];
    let texts = [
        String::new(),
        "Fattura in allegato.".to_owned(),
        "Fattura \nok\t".to_owned(),
        "a=41b, totale = 41 €\t \nCordiali saluti ".to_owned(),
        "x".repeat(100),
        "€".repeat(80),
        TEXT.to_owned(),
    ];
    for name in &names {
        let built = builder()
            .to(named(name, "protocollo@pec.example.it"))
            .build()
            .expect("a buildable message");
        assert_well_formed(&built);
    }
    for subject in &subjects {
        let built = builder()
            .subject(subject.as_str())
            .build()
            .expect("a buildable message");
        assert_well_formed(&built);
        let parsed = MessageParser::default()
            .parse(built.as_bytes())
            .expect("MIME");
        if !subject.is_empty() {
            assert_eq!(parsed.subject(), Some(subject.as_str()), "{subject:?}");
        }
    }
    for text in &texts {
        for (variant, html) in [
            (builder().text(text.as_str()), false),
            (builder().text(TEXT).html(text.as_str()), true),
        ] {
            let built = variant.build().expect("a buildable message");
            assert_well_formed(&built);
            let parsed = MessageParser::default()
                .parse(built.as_bytes())
                .expect("MIME");
            let read = if html {
                parsed.body_html(0)
            } else {
                parsed.body_text(0)
            };
            assert_eq!(
                read.unwrap_or_default(),
                crlf(text).as_str(),
                "{text:?}, HTML {html}"
            );
        }
    }
}

#[test]
fn printable_ascii_is_written_as_it_is() {
    let word = "a".repeat(76);
    let built = builder()
        .cc(named("Rossi, Mario", "mario.rossi@example.com"))
        .cc(named(
            "Studio Associato Rossi, Bianchi e Verdi",
            "studio@pec.example.it",
        ))
        .subject(format!("Invio {word}"))
        .text("Fattura in allegato.\r\nCordiali saluti")
        .build()
        .expect("a buildable message");
    let (header, body) = header_and_body(&built);
    for expected in [
        "From: Mario Rossi <mario.rossi@pec.example.it>",
        "\"Rossi, Mario\" <mario.rossi@example.com>",
        "\"Studio Associato Rossi, Bianchi e Verdi\" <studio@pec.example.it>",
        &format!("Subject: Invio {word}"),
        "Content-Transfer-Encoding: 7bit",
    ] {
        assert!(header.contains(expected), "{expected:?} in {header:?}");
    }
    assert_eq!(body, "Fattura in allegato.\r\nCordiali saluti");
    // Quoted-printable keeps printable characters and inner spaces as they are.
    let built = builder()
        .text("Totale 41 €\r\nCordiali saluti")
        .build()
        .expect("a buildable message");
    let (header, body) = header_and_body(&built);
    assert!(header.contains("Content-Transfer-Encoding: quoted-printable"));
    assert_eq!(body, "Totale 41 =E2=82=AC\r\nCordiali saluti");
}

#[test]
fn a_field_folds_only_before_a_word_that_would_pass_column_78() {
    // "Subject:" and two words with a space before each: 8 + 1 + 60 + 1 + 8 is 78 columns.
    let first = "a".repeat(60);
    for (second, folded) in [("b".repeat(8), false), ("b".repeat(9), true)] {
        let built = builder()
            .subject(format!("{first} {second}"))
            .build()
            .expect("a buildable message");
        let text = core::str::from_utf8(built.as_bytes()).expect("ASCII");
        let expected = if folded {
            format!("\r\nSubject: {first}\r\n {second}\r\n")
        } else {
            format!("\r\nSubject: {first} {second}\r\n")
        };
        assert!(text.contains(&expected), "{expected:?} in {text:?}");
    }
}
