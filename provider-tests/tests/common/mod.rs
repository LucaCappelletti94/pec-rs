//! What the provider tests share: the message they send, filing what comes back, and reading it.

use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postacert::{Kind, Message, MessageKind, ReceiptKind};

/// How long a provider gets to deliver every receipt.
pub const RECEIPT_WAIT: Duration = Duration::from_secs(600);

/// A token that makes this run's subjects unique, the seconds since 1970.
pub fn token() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
        .to_string()
}

/// A message from `from` to `to` asking for the `receipt` form, with a quoted-printable text attachment written
/// with literal line breaks, a base64 binary one named only by its `Content-Type`, and an attached message without
/// a file name.
pub fn message(from: &str, to: &str, receipt: &str, subject: &str) -> Vec<u8> {
    format!(
        "From: {from}\r\n\
         To: {to}\r\n\
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
         To: {to}\r\n\
         Subject: Messaggio inoltrato\r\n\
         \r\n\
         Testo del messaggio inoltrato.\r\n\
         \r\n\
         --pec-test--\r\n"
    )
    .into_bytes()
}

/// Every message in the inbox of `session` whose subject holds `token`, read without marking it read.
pub fn fetch<T: Read + Write>(session: &mut imap::Session<T>, token: &str) -> Vec<Vec<u8>> {
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
    messages
}

/// The raw acceptance, transport envelope and delivery receipt for one message sent.
#[derive(Default)]
pub struct Receipts {
    /// The acceptance receipt.
    pub acceptance: Option<Vec<u8>>,
    /// The transport envelope, in the recipient's inbox.
    pub transport: Option<Vec<u8>>,
    /// The delivery receipt.
    pub delivery: Option<Vec<u8>>,
}

impl Receipts {
    /// Files a fetched message under its kind when its subject is `subject`.
    pub fn file(&mut self, raw: Vec<u8>, subject: &str) {
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
    pub const fn complete(&self) -> bool {
        self.acceptance.is_some() && self.transport.is_some() && self.delivery.is_some()
    }
}

/// The receipt form `daticert.xml` names.
pub fn receipt_form(raw: &[u8]) -> Option<ReceiptKind> {
    Message::parse(raw)
        .expect("a valid PEC message")
        .certification_data()
        .expect("certification data")
        .data
        .receipt
}
