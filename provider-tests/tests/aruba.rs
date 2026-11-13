//! Sends PEC messages through Aruba from a mailbox to itself and checks the receipts with the crate.
//!
//! Runs only when `PEC_ARUBA_CONFIG` names the credential file, see the README.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing step"
)]

mod common;

use std::thread::sleep;
use std::time::{Duration, Instant};

use common::{RECEIPT_WAIT, Receipts, fetch, message, receipt_form, token};
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use postacert::{AttachmentCheck, Error, Message, ReceiptKind, TextLineEnds};
use serde::Deserialize;

/// The mailbox the messages leave from and arrive at.
#[derive(Deserialize)]
struct Account {
    /// The PEC address, also the login.
    address: String,
    /// The password.
    password: String,
}

/// Sends `raw` from the mailbox to itself over SMTPS.
fn send(account: &Account, raw: &[u8]) {
    let address = account.address.parse().expect("the address is valid");
    let envelope = Envelope::new(Some(address), vec![account.address.parse().expect("valid")])
        .expect("an envelope");
    SmtpTransport::relay("smtps.pec.aruba.it")
        .expect("the relay host is valid")
        .credentials(Credentials::new(
            account.address.clone(),
            account.password.clone(),
        ))
        .build()
        .send_raw(&envelope, raw)
        .expect("the provider accepts the message");
}

/// Every message in the inbox whose subject holds `token`, over IMAPS.
fn fetch_tls(account: &Account, token: &str) -> Vec<Vec<u8>> {
    let tls = native_tls::TlsConnector::new().expect("a TLS connector");
    let client = imap::connect(("imaps.pec.aruba.it", 993), "imaps.pec.aruba.it", &tls)
        .expect("the IMAP server answers");
    let mut session = client
        .login(&account.address, &account.password)
        .map_err(|(error, _)| error)
        .expect("the login succeeds");
    let messages = fetch(&mut session, token);
    session.logout().expect("the logout succeeds");
    messages
}

#[test]
fn aruba_receipts_verify() {
    let Some(path) = std::env::var_os("PEC_ARUBA_CONFIG") else {
        return;
    };
    let account: Account =
        toml::from_str(&std::fs::read_to_string(path).expect("the credential file is readable"))
            .expect("the credential file holds address and password");
    let token = token();
    let short_subject = format!("postacert ricevuta breve {token}");
    let summary_subject = format!("postacert ricevuta sintetica {token}");
    let short_sent = message(&account.address, &account.address, "breve", &short_subject);
    let summary_sent = message(
        &account.address,
        &account.address,
        "sintetica",
        &summary_subject,
    );
    send(&account, &short_sent);
    send(&account, &summary_sent);

    let deadline = Instant::now() + RECEIPT_WAIT;
    let mut short = Receipts::default();
    let mut summary = Receipts::default();
    while !(short.complete() && summary.complete()) {
        assert!(
            Instant::now() < deadline,
            "the receipts arrive within {RECEIPT_WAIT:?}"
        );
        sleep(Duration::from_secs(20));
        for raw in fetch_tls(&account, &token) {
            let breve =
                Message::parse(&raw).is_ok_and(|message| message.subject() == short_subject);
            if breve {
                short.file(raw, &short_subject);
            } else {
                summary.file(raw, &summary_subject);
            }
        }
    }

    let short_transport = short.transport.expect("complete");
    let short_delivery = short.delivery.expect("complete");
    assert_eq!(receipt_form(&short_transport), Some(ReceiptKind::Short));
    assert_eq!(receipt_form(&short_delivery), Some(ReceiptKind::Short));
    // Aruba hashes the canonical form, replaces the parts with a Content-Disposition and leaves in place one named
    // only by its Content-Type.
    assert_eq!(
        Message::parse(&short_delivery)
            .expect("a valid receipt")
            .check_attachments(&short_sent, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Matches(Some("righe.txt".to_owned())),
            AttachmentCheck::Carried(Some("dati.bin".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );

    let summary_delivery = summary.delivery.expect("complete");
    assert_eq!(receipt_form(&summary_delivery), Some(ReceiptKind::Summary));
    let summary_receipt = Message::parse(&summary_delivery).expect("a valid receipt");
    assert_eq!(summary_receipt.original_message(), None);
    assert_eq!(
        summary_receipt.check_attachments(&summary_sent, TextLineEnds::Canonical),
        Err(Error::NotShortReceipt)
    );
}
