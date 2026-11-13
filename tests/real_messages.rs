//! Real PEC messages read from a local folder that never enters the repository.
//!
//! Set `PEC_REAL_MESSAGES` to a folder of `.eml` files fetched from a PEC mailbox to run it, with the AgID CRLs in
//! `.crl` files beside them. CI leaves it unset.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

extern crate alloc;

use alloc::collections::BTreeMap;
use std::path::PathBuf;

use jiff::Timestamp;
use mail_parser::MessageParser;
use postacert::{
    AGID_PROVIDER_CAS, Delivery, Error, Message, MessageId, MessageKind, SignatureError, Status,
};

/// The folder `PEC_REAL_MESSAGES` names, with the files read from it.
struct RealFolder {
    /// The folder.
    path: PathBuf,
    /// Each PEC message in it, with its path.
    messages: Vec<(PathBuf, Vec<u8>)>,
    /// The CRLs in it.
    crls: Vec<Vec<u8>>,
}

/// Reads the folder `PEC_REAL_MESSAGES` names, or returns `None` when the variable is unset.
fn real_folder() -> Option<RealFolder> {
    let path = PathBuf::from(std::env::var_os("PEC_REAL_MESSAGES")?);
    let (mut messages, mut crls) = (Vec::new(), Vec::new());
    for entry in std::fs::read_dir(&path).expect("the folder is readable") {
        let file = entry.expect("the entry is readable").path();
        let raw = std::fs::read(&file).expect("the file is readable");
        if file.extension().is_some_and(|extension| extension == "crl") {
            crls.push(raw);
        } else if is_pec(&raw) {
            messages.push((file, raw));
        }
    }
    Some(RealFolder {
        path,
        messages,
        crls,
    })
}

/// Whether a message carries `X-Ricevuta` or `X-Trasporto`, which only a PEC provider writes.
fn is_pec(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    let headers = text
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    headers.contains("\nx-ricevuta:") || headers.contains("\nx-trasporto:")
}

/// The message's `Date`. Each message was received around it, which falls inside its signer's validity.
fn date(raw: &[u8]) -> Timestamp {
    MessageParser::default()
        .parse(raw)
        .and_then(|parsed| parsed.date())
        .and_then(|date| Timestamp::from_second(date.to_timestamp()).ok())
        .expect("a Date field")
}

#[test]
fn every_real_pec_message_parses() {
    let Some(RealFolder {
        path: folder,
        messages,
        crls,
    }) = real_folder()
    else {
        return;
    };
    let crls: Vec<&[u8]> = crls.iter().map(Vec::as_slice).collect();
    let mut verified = 0;
    for (path, raw) in &messages {
        let name = path.display();
        let message = Message::parse(raw).unwrap_or_else(|error| panic!("{name}: {error}"));
        match message.kind() {
            MessageKind::Certified(kind) => {
                assert_eq!(
                    message.certification_data().expect("certified").kind,
                    kind,
                    "{name}"
                );
            }
            MessageKind::Anomaly => assert!(message.original_message().is_some(), "{name}"),
        }
        // A signer whose certificate expired before every CRL here has no usable CRL, so it names its own.
        match message.verify(AGID_PROVIDER_CAS, &crls, date(raw)) {
            Ok(receipt) => {
                assert!(
                    !receipt.signature().signer_certificate().is_empty(),
                    "{name}"
                );
                verified += 1;
            }
            Err(Error::Signature(SignatureError::NoUsableCrl { urls })) => assert!(
                urls.iter().any(|url| url == "http://ca1.agid.gov.it/CRL"),
                "{name}: {urls:?}"
            ),
            Err(error) => panic!("{name}: {error}"),
        }
    }
    assert!(
        !messages.is_empty(),
        "no PEC message in {}",
        folder.display()
    );
    assert!(
        crls.is_empty() || verified > 0,
        "no real message verifies against the CRLs"
    );
}

#[test]
fn real_receipts_track_each_sent_message() {
    let Some(RealFolder { messages, crls, .. }) = real_folder() else {
        return;
    };
    let crls: Vec<&[u8]> = crls.iter().map(Vec::as_slice).collect();
    let mut deliveries: BTreeMap<MessageId, Delivery> = BTreeMap::new();
    for (path, raw) in &messages {
        let message = Message::parse(raw).expect("a PEC message");
        // Messages whose signer has no usable CRL here cannot be recorded, as the test above shows.
        let Ok(receipt) = message.verify(AGID_PROVIDER_CAS, &crls, date(raw)) else {
            continue;
        };
        let Some(sent) = message
            .certification_data()
            .and_then(|data| data.data.message_id.clone())
        else {
            continue;
        };
        deliveries
            .entry(sent.clone())
            .or_insert_with(|| Delivery::new(sent))
            .record(&receipt)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    }
    let mut delivered = 0;
    for (sent, delivery) in &deliveries {
        for (recipient, status) in delivery.recipients() {
            println!("{sent} {recipient} {status:?}");
            assert_ne!(status, Status::Conflicting, "{sent} {recipient}");
            delivered += usize::from(matches!(status, Status::Delivered(_)));
        }
    }
    assert!(
        crls.is_empty() || delivered > 0,
        "no real message reaches Delivered"
    );
}
