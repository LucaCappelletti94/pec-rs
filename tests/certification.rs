//! The certification data of `daticert.xml`, §7.4 of the technical rules.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use jiff::civil::{Date, Time};
use jiff::tz::Offset;
use pec::{
    CertificationData, CertifiedAt, Data, Error, ErrorCode, Header, Kind, ReceiptKind, Recipient,
    RecipientKind,
};

/// Reads a `daticert.xml` fixture.
fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/daticert/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists")
}

/// The acceptance fixture with `edit` applied to its text.
fn edited(edit: impl FnOnce(String) -> String) -> Result<CertificationData, Error> {
    CertificationData::from_xml(&edit(fixture("acceptance.xml")))
}

const FIXTURES: [&str; 9] = [
    "acceptance.xml",
    "delivery-error.xml",
    "delivery-full.xml",
    "delivery-summary.xml",
    "non-acceptance-virus.xml",
    "taken-in-charge.xml",
    "timeout-warning.xml",
    "transport.xml",
    "virus-detected.xml",
];

#[test]
fn acceptance_reads_every_field() {
    let data = CertificationData::from_xml(&fixture("acceptance.xml")).expect("valid");
    let expected = CertificationData {
        kind: Kind::Acceptance,
        error: ErrorCode::None,
        header: Header {
            sender: "mario.rossi@pec.example.it".to_owned(),
            recipients: vec![
                Recipient {
                    address: "ufficio.fatture@pec.example.it".to_owned(),
                    kind: RecipientKind::Certified,
                },
                Recipient {
                    address: "info@example.com".to_owned(),
                    kind: RecipientKind::External,
                },
            ],
            reply_to: "mario.rossi@pec.example.it".to_owned(),
            subject: Some("Invio fattura 00012".to_owned()),
        },
        data: Data {
            provider: "Gestore PEC di Esempio S.p.A.".to_owned(),
            at: CertifiedAt::new(
                Date::new(2026, 11, 8).expect("date"),
                Time::new(10, 15, 0, 0).expect("time"),
                Offset::from_hours(1).expect("offset"),
            )
            .expect("a representable instant"),
            identifier: "opec001.20261108101500.00001.01.1.1@pec.example.it".to_owned(),
            message_id: Some("<20261108101458.0001@client.example.it>".to_owned()),
            receipt: None,
            delivered_to: None,
            received_for: vec![],
            extended_error: None,
        },
    };
    assert_eq!(data, expected);
}

#[test]
fn delivery_and_error_fields_read() {
    let full = CertificationData::from_xml(&fixture("delivery-full.xml")).expect("valid");
    assert_eq!(full.kind, Kind::Delivery);
    assert_eq!(full.data.receipt, Some(ReceiptKind::Full));
    assert_eq!(
        full.data.delivered_to.as_deref(),
        Some("ufficio.fatture@pec.example.it")
    );
    let summary = CertificationData::from_xml(&fixture("delivery-summary.xml")).expect("valid");
    assert_eq!(summary.data.receipt, Some(ReceiptKind::Summary));
    let error = CertificationData::from_xml(&fixture("delivery-error.xml")).expect("valid");
    assert_eq!(error.kind, Kind::DeliveryError);
    assert_eq!(error.error, ErrorCode::NoRecipient);
    assert_eq!(
        error.data.extended_error.as_deref(),
        Some("5.1.1 - Utente non riconosciuto")
    );
    let taken = CertificationData::from_xml(&fixture("taken-in-charge.xml")).expect("valid");
    assert_eq!(taken.kind, Kind::TakenInCharge);
    assert_eq!(taken.data.received_for, ["ufficio.fatture@pec.example.it"]);
}

/// Without the `errore` attribute the error is the DTD default, `nessuno`.
#[test]
fn missing_error_attribute_is_none() {
    let taken = CertificationData::from_xml(&fixture("taken-in-charge.xml")).expect("valid");
    assert!(!fixture("taken-in-charge.xml").contains("errore="));
    assert_eq!(taken.error, ErrorCode::None);
}

#[test]
fn every_fixture_round_trips() {
    for name in FIXTURES {
        let data = CertificationData::from_xml(&fixture(name)).expect(name);
        let written = data.to_xml().expect(name);
        assert!(
            written.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
            "{name}"
        );
        assert_eq!(
            CertificationData::from_xml(&written).expect(name),
            data,
            "{name}"
        );
    }
}

#[test]
fn every_kind_and_error_code_round_trips() {
    let base = CertificationData::from_xml(&fixture("acceptance.xml")).expect("valid");
    let kinds = [
        Kind::Acceptance,
        Kind::NonAcceptance,
        Kind::TakenInCharge,
        Kind::Delivery,
        Kind::Transport,
        Kind::DeliveryError,
        Kind::DeliveryTimeoutWarning,
        Kind::VirusDetected,
    ];
    let errors = [
        ErrorCode::None,
        ErrorCode::NoRecipient,
        ErrorCode::NoDomain,
        ErrorCode::Virus,
        ErrorCode::Other,
    ];
    for kind in kinds {
        for error in errors {
            let data = CertificationData {
                kind,
                error,
                ..base.clone()
            };
            let written = data.to_xml().expect("writes");
            assert_eq!(CertificationData::from_xml(&written).expect("reads"), data);
        }
    }
}

/// The DTD requires at least one `destinatari`.
#[test]
fn no_recipient_is_rejected() {
    let result = edited(|xml| {
        xml.lines()
            .filter(|line| !line.contains("<destinatari"))
            .collect::<Vec<_>>()
            .join("\n")
    });
    assert!(
        matches!(result, Err(Error::CertificationData(_))),
        "{result:?}"
    );
}

#[test]
fn unknown_kind_is_rejected() {
    let result = edited(|xml| xml.replace("tipo=\"accettazione\"", "tipo=\"consegna\""));
    assert!(
        matches!(result, Err(Error::CertificationData(_))),
        "{result:?}"
    );
}

/// §7.2 fixes the day as `gg/mm/aaaa`, the time as `hh:mm:ss` and the zone as `[+|-]hhmm`.
#[test]
fn malformed_dates_are_rejected() {
    let cases = [
        ("<giorno>08/11/2026</giorno>", "<giorno>2026-11-08</giorno>"),
        ("<giorno>08/11/2026</giorno>", "<giorno>8/11/2026</giorno>"),
        ("<giorno>08/11/2026</giorno>", "<giorno>31/02/2026</giorno>"),
        ("<ora>10:15:00</ora>", "<ora>10:15</ora>"),
        ("<ora>10:15:00</ora>", "<ora>24:00:00</ora>"),
        ("zona=\"+0100\"", "zona=\"+01:00\""),
        ("zona=\"+0100\"", "zona=\"0100\""),
        ("zona=\"+0100\"", "zona=\"+0160\""),
    ];
    for (from, to) in cases {
        let result = edited(|xml| xml.replace(from, to));
        assert!(
            matches!(result, Err(Error::CertificationData(_))),
            "{to}: {result:?}"
        );
    }
}

#[test]
fn certified_at_is_an_instant() {
    let data = CertificationData::from_xml(&fixture("acceptance.xml")).expect("valid");
    assert_eq!(data.data.at.timestamp().to_string(), "2026-11-08T09:15:00Z");
    let west = edited(|xml| xml.replace("zona=\"+0100\"", "zona=\"-0430\"")).expect("valid");
    assert_eq!(
        west.data.at.offset(),
        Offset::from_seconds(-(4 * 3600 + 30 * 60)).expect("offset")
    );
    assert_eq!(west.data.at.timestamp().to_string(), "2026-11-08T14:45:00Z");
    assert_eq!(
        CertificationData::from_xml(&west.to_xml().expect("writes")).expect("reads"),
        west
    );
}
