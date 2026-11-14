//! Sends PEC messages through the OpenPEC container between two of its mailboxes and checks the receipts with the
//! crate.
//!
//! Runs only when `PEC_OPENPEC_SMTP` and `PEC_OPENPEC_IMAP` name the container's SMTP and IMAP addresses, see the
//! README.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing step"
)]

mod built;
mod common;

use std::net::TcpStream;
use std::thread::sleep;
use std::time::{Duration, Instant};

use built::built;
use common::{
    RECEIPT_WAIT, Receipts, assert_about, envelope, fetch, outgoing, receipt_form, token,
};
use lettre::{SmtpTransport, Transport};
use postacert::{AttachmentCheck, Error, Message, OutgoingMessage, ReceiptKind, TextLineEnds};

/// The mailbox the messages leave from, which gets the acceptance and the delivery receipt.
const SENDER: &str = "mittente@pec.test";

/// The mailbox the messages go to, which gets the transport envelope.
const RECIPIENT: &str = "destinatario@pec.test";

/// The password the container gives every mailbox.
const PASSWORD: &str = "prova";

/// Sends `outgoing` over plain SMTP to `address`, `host:port`, with the envelope the crate gives it.
fn send(address: &str, outgoing: &OutgoingMessage) {
    let (host, port) = address.rsplit_once(':').expect("host:port");
    SmtpTransport::builder_dangerous(host)
        .port(port.parse().expect("a port number"))
        .build()
        .send_raw(&envelope(outgoing), outgoing.as_bytes())
        .expect("the provider accepts the message");
}

/// Every message in `user`'s inbox whose subject holds `token`, over plain IMAP to `address`.
fn fetch_plain(address: &str, user: &str, token: &str) -> Vec<Vec<u8>> {
    let mut client =
        imap::Client::new(TcpStream::connect(address).expect("the IMAP server answers"));
    client.read_greeting().expect("a greeting");
    let mut session = client
        .login(user, PASSWORD)
        .map_err(|(error, _)| error)
        .expect("the login succeeds");
    let messages = fetch(&mut session, token);
    session.logout().expect("the logout succeeds");
    messages
}

#[test]
fn openpec_receipts_verify() {
    let (Some(smtp), Some(imap)) = (
        std::env::var("PEC_OPENPEC_SMTP").ok(),
        std::env::var("PEC_OPENPEC_IMAP").ok(),
    ) else {
        return;
    };
    let token = token();
    let short_subject = format!("postacert ricevuta breve {token}");
    let summary_subject = format!("postacert ricevuta sintetica {token}");
    let built_subject = format!("postacert messaggio costruito {token}");
    let short_sent = outgoing(
        SENDER,
        RECIPIENT,
        &short_subject,
        &format!("breve.{token}@postacert.test"),
        ReceiptKind::Short,
    );
    let summary_sent = outgoing(
        SENDER,
        RECIPIENT,
        &summary_subject,
        &format!("sintetica.{token}@postacert.test"),
        ReceiptKind::Summary,
    );
    let built_sent = built(
        SENDER,
        RECIPIENT,
        &built_subject,
        &format!("costruito.{token}@postacert.test"),
        ReceiptKind::Short,
    );
    send(&smtp, &short_sent);
    send(&smtp, &summary_sent);
    send(&smtp, &built_sent);

    let deadline = Instant::now() + RECEIPT_WAIT;
    let mut short = Receipts::default();
    let mut summary = Receipts::default();
    let mut built_receipts = Receipts::default();
    while !(short.complete() && summary.complete() && built_receipts.complete()) {
        assert!(
            Instant::now() < deadline,
            "the receipts arrive within {RECEIPT_WAIT:?}"
        );
        sleep(Duration::from_secs(5));
        for user in [SENDER, RECIPIENT] {
            for raw in fetch_plain(&imap, user, &token) {
                let subject = Message::parse(&raw)
                    .map(|message| message.subject().to_owned())
                    .unwrap_or_default();
                if subject == short_subject {
                    short.file(raw, &short_subject);
                } else if subject == built_subject {
                    built_receipts.file(raw, &built_subject);
                } else {
                    summary.file(raw, &summary_subject);
                }
            }
        }
    }

    let short_transport = short.transport.expect("complete");
    let short_delivery = short.delivery.expect("complete");
    assert_eq!(receipt_form(&short_transport), Some(ReceiptKind::Short));
    assert_eq!(receipt_form(&short_delivery), Some(ReceiptKind::Short));
    for raw in [
        &short.acceptance.expect("complete"),
        &short_transport,
        &short_delivery,
    ] {
        assert_about(raw, &short_sent);
    }
    let receipt = Message::parse(&short_delivery).expect("a valid receipt");
    // OpenPEC hashes text and attached messages with LF line ends and names each hash after a temporary file, so the
    // attachments pair by digest once LF is accepted.
    assert_eq!(
        receipt.check_attachments(short_sent.as_bytes(), TextLineEnds::CanonicalOrLf),
        Ok(vec![
            AttachmentCheck::Matches(Some("righe.txt".to_owned())),
            AttachmentCheck::Matches(Some("dati.bin".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
    assert!(
        receipt
            .check_attachments(short_sent.as_bytes(), TextLineEnds::Canonical)
            .expect("a short receipt")
            .contains(&AttachmentCheck::Missing(Some("righe.txt".to_owned()))),
        "the canonical form alone misses OpenPEC's LF hash"
    );

    let summary_delivery = summary.delivery.expect("complete");
    assert_eq!(receipt_form(&summary_delivery), Some(ReceiptKind::Summary));
    for raw in [
        &summary.acceptance.expect("complete"),
        &summary.transport.expect("complete"),
        &summary_delivery,
    ] {
        assert_about(raw, &summary_sent);
    }
    let summary_receipt = Message::parse(&summary_delivery).expect("a valid receipt");
    assert_eq!(summary_receipt.original_message(), None);
    assert_eq!(
        summary_receipt.check_attachments(summary_sent.as_bytes(), TextLineEnds::CanonicalOrLf),
        Err(Error::NotShortReceipt)
    );

    // A built message asking for a short receipt has its PDF and its attached message checked as matching.
    let built_delivery = built_receipts.delivery.expect("complete");
    assert_eq!(receipt_form(&built_delivery), Some(ReceiptKind::Short));
    for raw in [
        &built_receipts.acceptance.expect("complete"),
        &built_receipts.transport.expect("complete"),
        &built_delivery,
    ] {
        assert_about(raw, &built_sent);
    }
    let built_receipt = Message::parse(&built_delivery).expect("a valid receipt");
    assert_eq!(
        built_receipt.check_attachments(built_sent.as_bytes(), TextLineEnds::CanonicalOrLf),
        Ok(vec![
            AttachmentCheck::Matches(Some("fattura.pdf".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
}
