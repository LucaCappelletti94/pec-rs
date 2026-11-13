//! Real PEC messages read from a local folder that never enters the repository.
//!
//! Set `PEC_REAL_MESSAGES` to a folder of `.eml` files fetched from a PEC mailbox to run it, with the AgID CRLs in
//! `.crl` files beside them. CI leaves it unset.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use mail_parser::MessageParser;
use postacert::{AGID_PROVIDER_CAS, Error, Message, MessageKind, SignatureError};

#[test]
fn every_real_pec_message_parses() {
    let Some(folder) = std::env::var_os("PEC_REAL_MESSAGES") else {
        return;
    };
    let paths: Vec<_> = std::fs::read_dir(&folder)
        .expect("the folder is readable")
        .map(|entry| entry.expect("the entry is readable").path())
        .collect();
    let crls: Vec<Vec<u8>> = paths
        .iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "crl"))
        .map(|path| std::fs::read(path).expect("the CRL is readable"))
        .collect();
    let crls: Vec<&[u8]> = crls.iter().map(Vec::as_slice).collect();
    let (mut verified, mut checked) = (0, 0);
    for path in &paths {
        let raw = std::fs::read(path).expect("the file is readable");
        let name = path.display();
        let text = String::from_utf8_lossy(&raw);
        let headers = text
            .split("\r\n\r\n")
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !headers.contains("\nx-ricevuta:") && !headers.contains("\nx-trasporto:") {
            continue;
        }
        let message = Message::parse(&raw).unwrap_or_else(|error| panic!("{name}: {error}"));
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
        // Each message was received around its Date, which falls inside its signer's validity.
        let date = MessageParser::default()
            .parse(&raw)
            .and_then(|parsed| parsed.date())
            .and_then(|date| jiff::Timestamp::from_second(date.to_timestamp()).ok())
            .expect("a Date field");
        // A signer whose certificate expired before every CRL here has no usable CRL, so it names its own.
        match message.verify(AGID_PROVIDER_CAS, &crls, date) {
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
        checked += 1;
    }
    assert!(checked > 0, "no PEC message in {}", folder.display());
    assert!(
        crls.is_empty() || verified > 0,
        "no real message verifies against the CRLs"
    );
}
