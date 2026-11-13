//! Checking a message the caller built before its submission to the sender's PEC provider (§6.3.1), and asking for a
//! delivery receipt form (§6.5.2.2, §6.5.2.3).

use mail_parser::{Address, HeaderName, Headers, Mailbox, MessageParser};

use crate::mailbox::{is_dot_atom_address, same_mailbox};
use crate::{Error, MessageId, ReceiptKind};

/// The name of the field asking for a delivery receipt form, with the separator after it (§6.5.2.2).
const RECEIPT_FIELD: &[u8] = b"X-TipoRicevuta: ";

/// Why the sender's provider would refuse a message at submission (§6.3.1), or why its receipts could not be tracked.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OutgoingError {
    /// The message lacks exactly one `From` field naming exactly one mailbox (§6.3.1, RFC 5322 §3.6.2).
    #[error("the message needs one From field naming one mailbox")]
    From,
    /// The message lacks exactly one `To` field naming at least one mailbox (§6.3.1, RFC 5322 §3.6.3).
    #[error("the message needs one To field naming a mailbox")]
    To,
    /// The message has more than one `Cc` field (RFC 5322 §3.6.3).
    #[error("the message has more than one Cc field")]
    Cc,
    /// A `Bcc` field names a recipient, which the provider never accepts (§6.1, §6.3.1).
    #[error("a Bcc field names a recipient")]
    Bcc,
    /// A `From`, `To` or `Cc` address is not a `local@domain` of two dot-atoms, and is empty when the mailbox has no
    /// address (§6.3.1, RFC 5322 §3.4.1).
    #[error("{0:?} is not a dot-atom address")]
    Address(String),
    /// The message lacks exactly one `Message-ID` field holding a valid identifier, which its receipts are tracked by
    /// (§6.3, RFC 5322 §3.6.4).
    #[error("the message needs one valid Message-ID field")]
    MessageId,
    /// The message lacks exactly one `Date` field holding a valid date (RFC 5322 §3.6.1).
    #[error("the message needs one valid Date field")]
    Date,
    /// An `X-TipoRicevuta` field already asks for another receipt form, with the value it holds (§6.5.2.2).
    #[error("X-TipoRicevuta already asks for {0:?}")]
    ReceiptKind(String),
}

/// A message the caller built, checked for submission to the sender's PEC provider and asking for a delivery receipt
/// form.
///
/// The provider refuses a message without one `From` mailbox and a `To` mailbox, one naming a `Bcc` recipient, and one
/// whose SMTP envelope differs from its `From`, `To` and `Cc` addresses (§6.3.1). Send
/// [`as_bytes`](Self::as_bytes) from [`reverse_path`](Self::reverse_path) to
/// [`forward_paths`](Self::forward_paths). An SMTP client that derives the envelope from the header, as lettre does
/// unless given one, also sends to the `Bcc` recipients it removed from the header, and the provider refuses that.
#[derive(Debug, PartialEq, Eq)]
pub struct OutgoingMessage {
    /// The message with `X-TipoRicevuta`.
    raw: Vec<u8>,
    /// The `Message-ID` the caller gave the message.
    message_id: MessageId,
    /// The `From` address.
    reverse_path: String,
    /// The distinct `To` and `Cc` addresses, in the order the fields name them.
    forward_paths: Vec<String>,
}

impl OutgoingMessage {
    /// Checks a message the caller built and asks for `receipt` delivery receipts with `X-TipoRicevuta` (§6.5.2.2,
    /// §6.5.2.3), written after the last header field with the line break that field ends with.
    ///
    /// A message already asking for `receipt` is kept as it is. The provider replaces the message's `Message-ID` and
    /// keeps it as `msgid` in every receipt (§6.3), so [`message_id`](Self::message_id) starts the
    /// [`Delivery`](crate::Delivery) that tracks them.
    ///
    /// ```
    /// use postacert::{OutgoingMessage, ReceiptKind};
    ///
    /// let raw = b"From: Mario Rossi <mario.rossi@pec.example.it>\r\n\
    ///     To: ufficio.fatture@pec.example.it\r\n\
    ///     Subject: Invio fattura 00012\r\n\
    ///     Date: Sun, 8 Nov 2026 10:14:58 +0100\r\n\
    ///     Message-ID: <20261108101458.0001@client.example.it>\r\n\
    ///     \r\n\
    ///     Fattura in allegato.\r\n";
    /// let outgoing = OutgoingMessage::prepare(raw, ReceiptKind::Short)?;
    /// assert_eq!(outgoing.reverse_path(), "mario.rossi@pec.example.it");
    /// assert_eq!(outgoing.forward_paths(), ["ufficio.fatture@pec.example.it"]);
    /// assert!(outgoing.as_bytes().ends_with(b"X-TipoRicevuta: breve\r\n\r\nFattura in allegato.\r\n"));
    /// # Ok::<(), postacert::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotMime`] when the bytes are not a message, or [`Error::Outgoing`] naming the first check the
    /// message fails.
    pub fn prepare(raw: &[u8], receipt: ReceiptKind) -> Result<Self, Error> {
        let parsed = MessageParser::default().parse(raw).ok_or(Error::NotMime)?;
        let headers = parsed.headers();
        let reverse_path = sender(&headers)?.to_owned();
        let forward_paths = recipients(&headers)?;
        let message_id = message_id(&headers)?;
        if headers.all(HeaderName::Date).count() != 1 || headers.date().is_none() {
            return Err(OutgoingError::Date.into());
        }
        let token = receipt.token();
        let mut asked = false;
        for field in headers.all("X-TipoRicevuta") {
            let value = field.raw_value().trim_ascii();
            if value != token.as_bytes() {
                let value = String::from_utf8_lossy(value).into_owned();
                return Err(OutgoingError::ReceiptKind(value).into());
            }
            asked = true;
        }
        let raw = if asked {
            raw.to_vec()
        } else {
            with_receipt_field(raw, &headers, token)
        };
        Ok(Self {
            raw,
            message_id,
            reverse_path,
            forward_paths,
        })
    }

    /// The message to send, with `X-TipoRicevuta`.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.raw.as_slice()
    }

    /// The `Message-ID` the caller gave the message, which its receipts carry as `msgid` (§6.3).
    #[must_use]
    pub const fn message_id(&self) -> &MessageId {
        &self.message_id
    }

    /// The SMTP reverse path, the `From` address (§6.3.1).
    #[must_use]
    pub const fn reverse_path(&self) -> &str {
        self.reverse_path.as_str()
    }

    /// The SMTP forward paths, each distinct `To` and `Cc` address in the order the fields name them (§6.3.1).
    #[must_use]
    pub const fn forward_paths(&self) -> &[String] {
        self.forward_paths.as_slice()
    }
}

/// The address of the only mailbox the only `From` field names.
fn sender<'m>(headers: &Headers<'m>) -> Result<&'m str, OutgoingError> {
    if headers.all(HeaderName::From).count() != 1 {
        return Err(OutgoingError::From);
    }
    let from = headers.from().ok_or(OutgoingError::From)?;
    let mut items = from.iter();
    match (items.next(), items.next()) {
        (Some(Address::Mailbox(mailbox)), None) => address(mailbox),
        _ => Err(OutgoingError::From),
    }
}

/// The distinct addresses of the mailboxes the `To` and `Cc` fields name, group members included, in order.
fn recipients(headers: &Headers<'_>) -> Result<Vec<String>, OutgoingError> {
    if headers.all(HeaderName::To).count() != 1 {
        return Err(OutgoingError::To);
    }
    if headers.all(HeaderName::Cc).count() > 1 {
        return Err(OutgoingError::Cc);
    }
    let hidden = headers.all(HeaderName::Bcc).any(|field| {
        field
            .value()
            .as_address()
            .is_some_and(|list| list.first().is_some())
    });
    if hidden {
        return Err(OutgoingError::Bcc);
    }
    let to = headers
        .to()
        .filter(|list| list.first().is_some())
        .ok_or(OutgoingError::To)?;
    let copies = headers.cc().into_iter().flat_map(|list| list.mailboxes());
    let mut paths: Vec<String> = Vec::new();
    for mailbox in to.mailboxes().chain(copies) {
        let address = address(mailbox)?;
        if !paths.iter().any(|path| same_mailbox(path, address)) {
            paths.push(address.to_owned());
        }
    }
    Ok(paths)
}

/// The address of `mailbox` when it is a dot-atom address.
fn address(mailbox: Mailbox<'_>) -> Result<&str, OutgoingError> {
    let address = mailbox.address().unwrap_or_default();
    if is_dot_atom_address(address) {
        Ok(address)
    } else {
        Err(OutgoingError::Address(address.to_owned()))
    }
}

/// The identifier of the only `Message-ID` field.
fn message_id(headers: &Headers<'_>) -> Result<MessageId, OutgoingError> {
    if headers.all(HeaderName::MessageId).count() != 1 {
        return Err(OutgoingError::MessageId);
    }
    headers
        .message_id()
        .and_then(|id| id.parse().ok())
        .ok_or(OutgoingError::MessageId)
}

/// `raw` with an `X-TipoRicevuta` field holding `token` after its last header field, with the line break that field
/// ends with, or CRLF when it ends the message unterminated.
fn with_receipt_field(raw: &[u8], headers: &Headers<'_>, token: &str) -> Vec<u8> {
    // The offset lies inside `raw`, so it fits a `usize`.
    let end = headers
        .iter()
        .next_back()
        .and_then(|field| usize::try_from(field.offset_end()).ok())
        .unwrap_or(raw.len());
    let (head, tail) = raw.split_at_checked(end).unwrap_or((raw, &[]));
    let line_break: &[u8] = if head.ends_with(b"\n") && !head.ends_with(b"\r\n") {
        b"\n"
    } else {
        b"\r\n"
    };
    let mut out =
        Vec::with_capacity(raw.len() + RECEIPT_FIELD.len() + token.len() + 2 * line_break.len());
    out.extend_from_slice(head);
    if !head.ends_with(b"\n") {
        out.extend_from_slice(line_break);
    }
    out.extend_from_slice(RECEIPT_FIELD);
    out.extend_from_slice(token.as_bytes());
    out.extend_from_slice(line_break);
    out.extend_from_slice(tail);
    out
}
