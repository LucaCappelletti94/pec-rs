//! Classifying PEC messages and opening their envelopes, §6 of the technical rules.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use pec::{Error, Kind, Message, MessageId, MessageKind};

/// Reads a fixture file under `tests/fixtures`.
fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists")
}

/// Reads a signed message fixture.
fn message(name: &str) -> Vec<u8> {
    fixture(&format!("messages/{name}"))
}

/// `bytes` with every occurrence of `from` replaced by `to`.
fn replaced(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = core::str::from_utf8(bytes).expect("ascii fixture");
    assert!(text.contains(from), "{from:?} is in the fixture");
    text.replace(from, to).into_bytes()
}

const SUBJECT: &str = "Invio fattura 00012";

#[test]
fn every_fixture_is_classified() {
    let cases = [
        (
            "acceptance.eml",
            MessageKind::Certified(Kind::Acceptance),
            false,
            SUBJECT,
        ),
        (
            "non-acceptance-virus.eml",
            MessageKind::Certified(Kind::NonAcceptance),
            true,
            SUBJECT,
        ),
        (
            "taken-in-charge.eml",
            MessageKind::Certified(Kind::TakenInCharge),
            false,
            SUBJECT,
        ),
        (
            "delivery-full.eml",
            MessageKind::Certified(Kind::Delivery),
            false,
            SUBJECT,
        ),
        (
            "delivery-summary.eml",
            MessageKind::Certified(Kind::Delivery),
            false,
            SUBJECT,
        ),
        (
            "delivery-error.eml",
            MessageKind::Certified(Kind::DeliveryError),
            false,
            SUBJECT,
        ),
        (
            "timeout-warning.eml",
            MessageKind::Certified(Kind::DeliveryTimeoutWarning),
            false,
            SUBJECT,
        ),
        (
            "virus-detected.eml",
            MessageKind::Certified(Kind::VirusDetected),
            false,
            SUBJECT,
        ),
        (
            "transport.eml",
            MessageKind::Certified(Kind::Transport),
            false,
            SUBJECT,
        ),
        (
            "anomaly.eml",
            MessageKind::Anomaly,
            false,
            "Richiesta informazioni",
        ),
    ];
    for (name, kind, security_error, subject) in cases {
        let raw = message(name);
        let parsed = Message::parse(&raw).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(parsed.kind(), kind, "{name}");
        assert_eq!(parsed.security_error(), security_error, "{name}");
        assert_eq!(parsed.subject(), subject, "{name}");
        match kind {
            MessageKind::Certified(kind) => {
                let data = parsed.certification_data().expect(name);
                assert_eq!(data.kind, kind, "{name}");
                assert_eq!(
                    parsed.reference_message_id().map(MessageId::as_str),
                    Some("20261108101458.0001@client.example.it"),
                    "{name}"
                );
            }
            MessageKind::Anomaly => assert!(parsed.certification_data().is_none(), "{name}"),
        }
    }
}

/// The transport envelope and the full delivery receipt carry the original message unmodified, §6.3.4 and §6.5.2.1.
#[test]
fn original_message_is_extracted() {
    let original = fixture("original/certified.eml");
    for name in ["transport.eml", "delivery-full.eml"] {
        let raw = message(name);
        let parsed = Message::parse(&raw).expect(name);
        assert_eq!(
            parsed.original_message(),
            Some(original.as_slice()),
            "{name}"
        );
    }
    for name in [
        "acceptance.eml",
        "delivery-summary.eml",
        "delivery-error.eml",
    ] {
        let raw = message(name);
        assert_eq!(
            Message::parse(&raw).expect(name).original_message(),
            None,
            "{name}"
        );
    }
}

/// The anomaly envelope carries the arrived message and no certification data, §6.4.2.
#[test]
fn anomaly_carries_the_arrived_message() {
    let raw = message("anomaly.eml");
    let parsed = Message::parse(&raw).expect("valid");
    assert_eq!(
        parsed.original_message(),
        Some(fixture("original/ordinary.eml").as_slice())
    );
    assert_eq!(
        parsed.message_id().map(MessageId::as_str),
        Some("20261108093000.4242@mail.example.com")
    );
}

#[test]
fn subject_prefix_must_match_the_kind() {
    let raw = replaced(
        &message("acceptance.eml"),
        "Subject: ACCETTAZIONE:",
        "Subject: CONSEGNA:",
    );
    assert!(matches!(
        Message::parse(&raw),
        Err(Error::SubjectMismatch { .. })
    ));
    let raw = replaced(
        &message("non-acceptance-virus.eml"),
        "X-VerificaSicurezza: errore\r\n",
        "",
    );
    assert!(matches!(
        Message::parse(&raw),
        Err(Error::SubjectMismatch { .. })
    ));
}

#[test]
fn certification_data_must_match_the_kind() {
    let raw = replaced(
        &replaced(
            &message("acceptance.eml"),
            "X-Ricevuta: accettazione",
            "X-Ricevuta: presa-in-carico",
        ),
        "Subject: ACCETTAZIONE:",
        "Subject: PRESA IN CARICO:",
    );
    let result = Message::parse(&raw);
    assert!(
        matches!(
            result,
            Err(Error::KindMismatch {
                header: Kind::TakenInCharge,
                data: Kind::Acceptance
            })
        ),
        "{result:?}"
    );
}

#[test]
fn security_header_only_on_virus_notices() {
    let raw = replaced(
        &message("acceptance.eml"),
        "X-Ricevuta: accettazione",
        "X-Ricevuta: accettazione\r\nX-VerificaSicurezza: errore",
    );
    assert!(matches!(
        Message::parse(&raw),
        Err(Error::UnexpectedSecurityHeader(MessageKind::Certified(
            Kind::Acceptance
        )))
    ));
}

#[test]
fn certified_kinds_need_their_certification_data() {
    let raw = replaced(&message("acceptance.eml"), "daticert.xml", "other.xml");
    assert!(matches!(
        Message::parse(&raw),
        Err(Error::MissingCertificationData)
    ));
}

#[test]
fn envelopes_need_their_message() {
    let raw = replaced(
        &message("transport.eml"),
        "Content-Type: message/rfc822",
        "Content-Type: application/octet-stream",
    );
    assert!(matches!(Message::parse(&raw), Err(Error::MissingOriginal)));
    let raw = replaced(
        &message("anomaly.eml"),
        "Content-Type: message/rfc822",
        "Content-Type: application/octet-stream",
    );
    assert!(matches!(Message::parse(&raw), Err(Error::MissingOriginal)));
}

#[test]
fn non_pec_messages_are_rejected() {
    assert!(matches!(
        Message::parse(&fixture("original/ordinary.eml")),
        Err(Error::NotPec)
    ));
    let raw = replaced(
        &message("acceptance.eml"),
        "X-Ricevuta: accettazione",
        "X-Ricevuta: accettazione\r\nX-Trasporto: errore",
    );
    assert!(matches!(Message::parse(&raw), Err(Error::ConflictingKind)));
    let raw = replaced(
        &message("acceptance.eml"),
        "X-Ricevuta: accettazione",
        "X-Ricevuta: posta-certificata",
    );
    assert!(matches!(Message::parse(&raw), Err(Error::UnknownKind(_))));
    let raw = replaced(
        &message("transport.eml"),
        "X-Trasporto: posta-certificata",
        "X-Trasporto: busta",
    );
    assert!(matches!(Message::parse(&raw), Err(Error::UnknownKind(_))));
    let raw = replaced(
        &message("transport.eml"),
        "X-Trasporto: posta-certificata",
        "X-Trasporto: accettazione",
    );
    assert!(
        matches!(Message::parse(&raw), Err(Error::UnknownKind(kind)) if kind == "accettazione")
    );
    assert!(matches!(Message::parse(b""), Err(Error::NotMime)));
}

/// §7.3.3 fixes the certification data as UTF-8.
#[test]
fn certification_data_must_be_utf8() {
    let raw = message("acceptance.eml");
    let text = core::str::from_utf8(&raw).expect("ascii fixture");
    let marker = "filename=\"daticert.xml\"\r\nContent-Transfer-Encoding: base64\r\n\r\n";
    let start = text.find(marker).expect("the daticert part") + marker.len();
    let end = start
        + text[start..]
            .find("\r\n--pec-inner")
            .expect("the part ends");
    // `//4=` is the base64 of the bytes 0xFF 0xFE, which no UTF-8 text starts with.
    let raw = format!("{}//4={}", &text[..start], &text[end..]).into_bytes();
    assert!(matches!(
        Message::parse(&raw),
        Err(Error::CertificationData(_))
    ));
}

/// A kind header that is not even UTF-8 names no kind the rules define.
#[test]
fn garbled_kind_header_is_unknown() {
    let raw = message("acceptance.eml");
    let from: &[u8] = b"X-Ricevuta: accettazione";
    let at = raw
        .windows(from.len())
        .position(|window| window == from)
        .expect("the header");
    let mut garbled = raw[..at].to_vec();
    garbled.extend_from_slice(b"X-Ricevuta: accettazion\xff");
    garbled.extend_from_slice(&raw[at + from.len()..]);
    assert!(
        matches!(Message::parse(&garbled), Err(Error::UnknownKind(kind)) if kind == "accettazion\u{fffd}")
    );
}

/// The anomaly envelope carries no `X-Riferimento-Message-ID`, and one that is not UTF-8 names no identifier.
#[test]
fn reference_message_id_needs_a_readable_header() {
    let raw = message("anomaly.eml");
    assert_eq!(
        Message::parse(&raw).expect("valid").reference_message_id(),
        None
    );
    let raw = message("acceptance.eml");
    let from: &[u8] = b"X-Riferimento-Message-ID: <";
    let at = raw
        .windows(from.len())
        .position(|window| window == from)
        .expect("the header");
    let mut garbled = raw[..at + from.len()].to_vec();
    garbled.push(0xff);
    garbled.extend_from_slice(&raw[at + from.len()..]);
    assert_eq!(
        Message::parse(&garbled)
            .expect("valid")
            .reference_message_id(),
        None
    );
}

/// Every `tipo` of §7.4 reads into its kind, and nothing else does.
#[test]
fn every_tipo_parses() {
    let cases = [
        ("accettazione", Kind::Acceptance),
        ("non-accettazione", Kind::NonAcceptance),
        ("presa-in-carico", Kind::TakenInCharge),
        ("avvenuta-consegna", Kind::Delivery),
        ("posta-certificata", Kind::Transport),
        ("errore-consegna", Kind::DeliveryError),
        ("preavviso-errore-consegna", Kind::DeliveryTimeoutWarning),
        ("rilevazione-virus", Kind::VirusDetected),
    ];
    for (text, kind) in cases {
        assert_eq!(text.parse::<Kind>(), Ok(kind), "{text}");
    }
    assert_eq!(
        "Accettazione".parse::<Kind>(),
        Err(Error::UnknownKind("Accettazione".to_owned()))
    );
}

/// The original `Message-ID` reads the same from the header and from `daticert.xml`, which is how a receipt is matched
/// to the message it certifies.
#[test]
fn reference_message_id_matches_the_certification_data() {
    for name in ["acceptance.eml", "delivery-full.eml", "transport.eml"] {
        let raw = message(name);
        let parsed = Message::parse(&raw).expect(name);
        let data = parsed.certification_data().expect(name);
        assert_eq!(
            parsed.reference_message_id(),
            data.data.message_id.as_ref(),
            "{name}"
        );
    }
}

/// An identifier reads the same with or without its angle brackets, and anything that is not one is refused.
#[test]
fn message_ids_parse_in_either_form() {
    let bare: MessageId = "a.1@example.it".parse().expect("bare");
    let bracketed: MessageId = " <a.1@example.it> ".parse().expect("bracketed");
    assert_eq!(bare, bracketed);
    assert_eq!(bare.as_str(), "a.1@example.it");
    assert_eq!(bare.to_string(), "<a.1@example.it>");
    for invalid in [
        "",
        "<>",
        "example.it",
        "@example.it",
        "a@",
        "<a@example.it",
        "a@example.it>",
        "a b@example.it",
        "<a<b@example.it>",
    ] {
        assert_eq!(
            invalid.parse::<MessageId>(),
            Err(Error::InvalidMessageId(invalid.to_owned())),
            "{invalid:?}"
        );
    }
}
