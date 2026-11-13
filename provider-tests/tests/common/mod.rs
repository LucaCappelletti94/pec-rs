//! What the provider tests share: the message they send, filing what comes back, and reading it.

use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lettre::address::Envelope;
use postacert::{Kind, Limits, Message, MessageKind, OutgoingMessage, ReceiptKind};

/// How long a provider gets to deliver every receipt.
pub const RECEIPT_WAIT: Duration = Duration::from_secs(600);

/// The current time as an RFC 5322 date in UTC, with the `-0000` zone of a client stating no local offset (RFC 5322
/// §3.3).
fn now() -> String {
    jiff::fmt::rfc2822::DateTimePrinter::new()
        .timestamp_to_string(&jiff::Timestamp::now())
        .expect("the current time prints as an RFC 2822 date")
}

/// A token that makes this run's subjects unique, the seconds since 1970.
pub fn token() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
        .to_string()
}

/// A message from `from` to `to` asking for `receipt` delivery receipts, written by hand so the encodings under test
/// stay exact, then checked for submission and against the limits every provider accepts. It carries a
/// quoted-printable text attachment written with literal line breaks, a base64 binary one named only by its
/// `Content-Type`, and an attached message without a file name.
pub fn outgoing(
    from: &str,
    to: &str,
    subject: &str,
    message_id: &str,
    receipt: ReceiptKind,
) -> OutgoingMessage {
    let date = now();
    let raw = format!(
        "From: {from}\r\n\
         To: {to}\r\n\
         Subject: {subject}\r\n\
         Date: {date}\r\n\
         Message-ID: <{message_id}>\r\n\
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
    );
    let outgoing = OutgoingMessage::prepare(raw.as_bytes(), receipt)
        .expect("the message passes the provider's checks");
    outgoing
        .check_limits(Limits::GUARANTEED)
        .expect("the message is within every provider's limits");
    outgoing
}

/// The SMTP envelope of `outgoing`, from its reverse path to its forward paths (§6.3.1).
pub fn envelope(outgoing: &OutgoingMessage) -> Envelope {
    let forward_paths = outgoing
        .forward_paths()
        .iter()
        .map(|path| path.parse().expect("a valid forward path"))
        .collect();
    let reverse_path = outgoing
        .reverse_path()
        .parse()
        .expect("a valid reverse path");
    Envelope::new(Some(reverse_path), forward_paths).expect("an envelope")
}

/// Asserts that the receipt `raw` is about `outgoing`, whose `Message-ID` its signed `msgid` carries (§6.3).
#[track_caller]
pub fn assert_about(raw: &[u8], outgoing: &OutgoingMessage) {
    let receipt = Message::parse(raw).expect("a valid PEC message");
    let data = receipt.certification_data().expect("certification data");
    assert_eq!(data.data.message_id.as_ref(), Some(outgoing.message_id()));
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
