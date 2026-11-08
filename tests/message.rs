//! Classifying PEC messages and opening their envelopes, §6 of the technical rules.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use pec::{Error, Kind, Message, MessageKind};

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
    let text = std::str::from_utf8(bytes).expect("ascii fixture");
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
                    parsed.reference_message_id(),
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
        parsed.message_id(),
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
    assert!(matches!(Message::parse(b""), Err(Error::NotMime)));
}
