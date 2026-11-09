//! Sends PEC messages through Aruba from a mailbox to itself and checks the receipts with the crate.
//!
//! Runs only when `PEC_ARUBA_CONFIG` names the credential file, see the README.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing step"
)]

use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use pec::{AttachmentCheck, Error, Kind, Message, MessageKind, ReceiptKind};
use serde::Deserialize;

/// The mailbox the messages leave from and arrive at.
#[derive(Deserialize)]
struct Account {
    /// The PEC address, also the login.
    address: String,
    /// The password.
    password: String,
}

/// How long the provider gets to deliver every receipt.
const RECEIPT_WAIT: Duration = Duration::from_secs(600);

/// A message to `address` from itself asking for the `receipt` form, with a quoted-printable text attachment
/// written with literal line breaks, a base64 binary one, and an attached message without a file name.
fn message(address: &str, receipt: &str, subject: &str) -> Vec<u8> {
    format!(
        "From: {address}\r\n\
         To: {address}\r\n\
         Subject: {subject}\r\n\
         X-TipoRicevuta: {receipt}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"pec-test\"\r\n\
         \r\n\
         --pec-test\r\n\
         Content-Type: text/plain; charset=\"utf-8\"\r\n\
         \r\n\
         Messaggio di prova delle ricevute di avvenuta consegna.\r\n\
         --pec-test\r\n\
         Content-Type: text/plain; charset=\"utf-8\"\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\
         Content-Disposition: attachment; filename=\"righe.txt\"\r\n\
         \r\n\
         Prima riga della nota.\r\n\
         Seconda riga con =C3=A8.\r\n\
         \r\n\
         --pec-test\r\n\
         Content-Type: application/octet-stream; name=\"dati.bin\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         AAECAwQFBgcICQoLDA0ODxAREhP/\r\n\
         --pec-test\r\n\
         Content-Type: message/rfc822\r\n\
         Content-Disposition: attachment\r\n\
         \r\n\
         From: anna.verdi@example.com\r\n\
         To: {address}\r\n\
         Subject: Messaggio inoltrato\r\n\
         \r\n\
         Testo del messaggio inoltrato.\r\n\
         \r\n\
         --pec-test--\r\n"
    )
    .into_bytes()
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

/// Every message in the inbox whose subject holds `token`, read without marking it read.
fn fetch(account: &Account, token: &str) -> Vec<Vec<u8>> {
    let tls = native_tls::TlsConnector::new().expect("a TLS connector");
    let client = imap::connect(("imaps.pec.aruba.it", 993), "imaps.pec.aruba.it", &tls)
        .expect("the IMAP server answers");
    let mut session = client
        .login(&account.address, &account.password)
        .map_err(|(error, _)| error)
        .expect("the login succeeds");
    session.examine("INBOX").expect("the inbox opens read-only");
    let uids = session
        .uid_search(format!("SUBJECT \"{token}\""))
        .expect("the search succeeds");
    let mut messages = Vec::new();
    for uid in uids {
        let fetched = session
            .uid_fetch(uid.to_string(), "BODY.PEEK[]")
            .expect("the fetch succeeds");
        messages.extend(
            fetched
                .iter()
                .filter_map(|fetch| fetch.body().map(<[u8]>::to_vec)),
        );
    }
    session.logout().expect("the logout succeeds");
    messages
}

/// The raw acceptance, transport envelope and delivery receipt for the message whose subject is `subject`.
#[derive(Default)]
struct Receipts {
    /// The acceptance receipt.
    acceptance: Option<Vec<u8>>,
    /// The transport envelope, which reaches the inbox since the message is addressed to it.
    transport: Option<Vec<u8>>,
    /// The delivery receipt.
    delivery: Option<Vec<u8>>,
}

impl Receipts {
    /// Files each fetched message under its kind when its subject is `subject`.
    fn file(&mut self, raw: Vec<u8>, subject: &str) {
        let Ok(message) = Message::parse(&raw) else {
            return;
        };
        if message.subject() != subject {
            return;
        }
        let slot = match message.kind() {
            MessageKind::Certified(Kind::Acceptance) => &mut self.acceptance,
            MessageKind::Certified(Kind::Transport) => &mut self.transport,
            MessageKind::Certified(Kind::Delivery) => &mut self.delivery,
            _ => return,
        };
        *slot = Some(raw);
    }

    /// Whether all three arrived.
    const fn complete(&self) -> bool {
        self.acceptance.is_some() && self.transport.is_some() && self.delivery.is_some()
    }
}

/// The receipt form `daticert.xml` names.
fn receipt_form(raw: &[u8]) -> Option<ReceiptKind> {
    Message::parse(raw)
        .expect("a valid PEC message")
        .certification_data()
        .expect("certification data")
        .data
        .receipt
}

#[test]
fn aruba_receipts_verify() {
    let Some(path) = std::env::var_os("PEC_ARUBA_CONFIG") else {
        return;
    };
    let account: Account =
        toml::from_str(&std::fs::read_to_string(path).expect("the credential file is readable"))
            .expect("the credential file holds address and password");
    let token = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
        .to_string();
    let short_subject = format!("pec-rs ricevuta breve {token}");
    let summary_subject = format!("pec-rs ricevuta sintetica {token}");
    let short_sent = message(&account.address, "breve", &short_subject);
    let summary_sent = message(&account.address, "sintetica", &summary_subject);
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
        for raw in fetch(&account, &token) {
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
    // Aruba replaces the parts with a Content-Disposition and leaves in place one named only by its Content-Type.
    assert_eq!(
        Message::parse(&short_delivery)
            .expect("a valid receipt")
            .check_attachments(&short_sent),
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
        summary_receipt.check_attachments(&summary_sent),
        Err(Error::NotShortReceipt)
    );
}
