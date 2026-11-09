//! Sends PEC messages through the OpenPEC container between two of its mailboxes and checks the receipts with the
//! crate.
//!
//! Runs only when `PEC_OPENPEC_SMTP` and `PEC_OPENPEC_IMAP` name the container's SMTP and IMAP addresses, see the
//! README.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing step"
)]

mod common;

use std::net::TcpStream;
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::{RECEIPT_WAIT, Receipts, fetch, message, receipt_form, token};
use lettre::address::Envelope;
use lettre::{SmtpTransport, Transport};
use pec::{AttachmentCheck, Error, Message, ReceiptKind, TextLineEnds};

/// The mailbox the messages leave from, which gets the acceptance and the delivery receipt.
const SENDER: &str = "mittente@pec.test";

/// The mailbox the messages go to, which gets the transport envelope.
const RECIPIENT: &str = "destinatario@pec.test";

/// The password the container gives every mailbox.
const PASSWORD: &str = "prova";

/// Sends `raw` from the sender to the recipient over plain SMTP to `address`, `host:port`.
fn send(address: &str, raw: &[u8]) {
    let (host, port) = address.rsplit_once(':').expect("host:port");
    let envelope = Envelope::new(
        Some(SENDER.parse().expect("valid")),
        vec![RECIPIENT.parse().expect("valid")],
    )
    .expect("an envelope");
    SmtpTransport::builder_dangerous(host)
        .port(port.parse().expect("a port number"))
        .build()
        .send_raw(&envelope, raw)
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
    let short_subject = format!("pec-rs ricevuta breve {token}");
    let summary_subject = format!("pec-rs ricevuta sintetica {token}");
    let short_sent = message(SENDER, RECIPIENT, "breve", &short_subject);
    let summary_sent = message(SENDER, RECIPIENT, "sintetica", &summary_subject);
    send(&smtp, &short_sent);
    send(&smtp, &summary_sent);

    let deadline = Instant::now() + RECEIPT_WAIT;
    let mut short = Receipts::default();
    let mut summary = Receipts::default();
    while !(short.complete() && summary.complete()) {
        assert!(
            Instant::now() < deadline,
            "the receipts arrive within {RECEIPT_WAIT:?}"
        );
        sleep(Duration::from_secs(5));
        for user in [SENDER, RECIPIENT] {
            for raw in fetch_plain(&imap, user, &token) {
                let breve =
                    Message::parse(&raw).is_ok_and(|message| message.subject() == short_subject);
                if breve {
                    short.file(raw, &short_subject);
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
    let receipt = Message::parse(&short_delivery).expect("a valid receipt");
    // OpenPEC hashes text and attached messages with LF line ends and names each hash after a temporary file, so the
    // attachments pair by digest once LF is accepted.
    assert_eq!(
        receipt.check_attachments(&short_sent, TextLineEnds::CanonicalOrLf),
        Ok(vec![
            AttachmentCheck::Matches(Some("righe.txt".to_owned())),
            AttachmentCheck::Matches(Some("dati.bin".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
    assert!(
        receipt
            .check_attachments(&short_sent, TextLineEnds::Canonical)
            .expect("a short receipt")
            .contains(&AttachmentCheck::Missing(Some("righe.txt".to_owned()))),
        "the canonical form alone misses OpenPEC's LF hash"
    );

    let summary_delivery = summary.delivery.expect("complete");
    assert_eq!(receipt_form(&summary_delivery), Some(ReceiptKind::Summary));
    let summary_receipt = Message::parse(&summary_delivery).expect("a valid receipt");
    assert_eq!(summary_receipt.original_message(), None);
    assert_eq!(
        summary_receipt.check_attachments(&summary_sent, TextLineEnds::CanonicalOrLf),
        Err(Error::NotShortReceipt)
    );
}
