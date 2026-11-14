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
    let quoted_printable = header.contains("Content-Transfer-Encoding: quoted-printable");
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
        let built = builder()
            .text(text.as_str())
            .build()
            .expect("a buildable message");
        assert_well_formed(&built);
        let parsed = MessageParser::default()
            .parse(built.as_bytes())
            .expect("MIME");
        assert_eq!(
            parsed.body_text(0).unwrap_or_default(),
            crlf(text).as_str(),
            "{text:?}"
        );
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
