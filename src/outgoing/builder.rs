//! Building an outgoing message the sender's PEC provider accepts (§6.3.1).

use core::{mem, slice};

use jiff::Zoned;

use super::{OutgoingError, OutgoingMessage, write};
use crate::mailbox::{has_control, same_mailbox};
use crate::{Error, Mailbox, MessageId, ReceiptKind};

/// The content type of the text body.
const PLAIN: &str = "text/plain; charset=utf-8";
/// The content type of the HTML version of the text body.
const HTML: &str = "text/html; charset=utf-8";

/// An outgoing message being built, from [`OutgoingMessage::builder`].
///
/// It has a sender, one or more `To` recipients, an identifier and a date from the start, and no way to name a `Bcc`
/// recipient, so it holds nothing the provider refuses at submission (§6.1, §6.3.1).
#[derive(Clone, Debug)]
#[must_use]
pub struct OutgoingMessageBuilder {
    /// The sender, the `From` field.
    from: Mailbox,
    /// The primary recipients, the `To` field, never empty.
    to: Vec<Mailbox>,
    /// The recipients in copy, the `Cc` field.
    cc: Vec<Mailbox>,
    /// Where replies go, the `Reply-To` field.
    reply_to: Vec<Mailbox>,
    /// The identifier, the `Message-ID` field.
    message_id: MessageId,
    /// The message this one replies to, the `In-Reply-To` field.
    in_reply_to: Option<MessageId>,
    /// The thread, the `References` field.
    references: Vec<MessageId>,
    /// The date, the `Date` field.
    date: Zoned,
    /// The subject, the `Subject` field.
    subject: Option<String>,
    /// The text body.
    text: String,
    /// The HTML version of the text body.
    html: Option<String>,
    /// The attachments, after the body in this order.
    attachments: Vec<Attachment>,
    /// The delivery receipt form asked for, the `X-TipoRicevuta` field.
    receipt: ReceiptKind,
}

/// An attachment of an outgoing message.
#[derive(Clone, Debug)]
enum Attachment {
    /// A file, written base64.
    File {
        /// The file name.
        name: String,
        /// The discrete `type/subtype` of the content.
        content_type: String,
        /// The content.
        bytes: Vec<u8>,
    },
    /// A message, written as given.
    Message(Vec<u8>),
}

impl OutgoingMessage {
    /// Starts a message from `from` to `to`, identified by `message_id` and dated `date`, with an empty text body,
    /// asking for full delivery receipts.
    ///
    /// The crate reads no clock and draws no randomness, so the caller gives the identifier and the date, and the
    /// identifier starts the [`Delivery`](crate::Delivery) that tracks the receipts (§6.3).
    ///
    /// ```
    /// use postacert::{Mailbox, OutgoingMessage, ReceiptKind};
    ///
    /// let date = "2026-11-08T10:14:58+01:00[+01:00]".parse().expect("a date with its offset");
    /// let outgoing = OutgoingMessage::builder(
    ///     Mailbox::named("Mario Rossi", "mario.rossi@pec.example.it")?,
    ///     Mailbox::new("ufficio.fatture@pec.example.it")?,
    ///     "<20261108101458.0001@client.example.it>".parse()?,
    ///     date,
    /// )
    /// .cc(Mailbox::new("protocollo@pec.example.it")?)
    /// .subject("Invio fattura 00012")
    /// .text("Fattura in allegato.")
    /// .receipt(ReceiptKind::Short)
    /// .build()?;
    /// assert_eq!(outgoing.reverse_path(), "mario.rossi@pec.example.it");
    /// assert_eq!(outgoing.forward_paths(), ["ufficio.fatture@pec.example.it", "protocollo@pec.example.it"]);
    /// # Ok::<(), postacert::Error>(())
    /// ```
    pub fn builder(
        from: Mailbox,
        to: Mailbox,
        message_id: MessageId,
        date: Zoned,
    ) -> OutgoingMessageBuilder {
        OutgoingMessageBuilder {
            from,
            to: vec![to],
            cc: Vec::new(),
            reply_to: Vec::new(),
            message_id,
            in_reply_to: None,
            references: Vec::new(),
            date,
            subject: None,
            text: String::new(),
            html: None,
            attachments: Vec::new(),
            receipt: ReceiptKind::Full,
        }
    }
}

impl OutgoingMessageBuilder {
    /// Adds a primary recipient after those given so far.
    pub fn to(mut self, mailbox: Mailbox) -> Self {
        self.to.push(mailbox);
        self
    }

    /// Adds a recipient in copy after those given so far.
    pub fn cc(mut self, mailbox: Mailbox) -> Self {
        self.cc.push(mailbox);
        self
    }

    /// Adds a mailbox replies go to, after those given so far.
    pub fn reply_to(mut self, mailbox: Mailbox) -> Self {
        self.reply_to.push(mailbox);
        self
    }

    /// Marks the message as a reply to the message `id`.
    pub fn in_reply_to(mut self, id: MessageId) -> Self {
        self.in_reply_to = Some(id);
        self
    }

    /// Adds the messages of the thread, oldest first, after those given so far.
    pub fn references(mut self, ids: impl IntoIterator<Item = MessageId>) -> Self {
        self.references.extend(ids);
        self
    }

    /// Sets the subject.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Sets the text body, whose line breaks of any form are written as CRLF (RFC 2046 §4.1.1).
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }

    /// Sets the HTML version of the text body, which goes after the text in a `multipart/alternative` (RFC 2046
    /// §5.1.4), its line breaks of any form written as CRLF.
    pub fn html(mut self, html: impl Into<String>) -> Self {
        self.html = Some(html.into());
        self
    }

    /// Attaches the file `name` holding `bytes` of the type `content_type`, a `type/subtype` such as
    /// `application/pdf`, after the attachments given so far.
    pub fn attachment(
        mut self,
        name: impl Into<String>,
        content_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        self.attachments.push(Attachment::File {
            name: name.into(),
            content_type: content_type.into(),
            bytes: bytes.into(),
        });
        self
    }

    /// Attaches the message `raw` as `message/rfc822`, written as given, after the attachments given so far.
    pub fn attached_message(mut self, raw: impl Into<Vec<u8>>) -> Self {
        self.attachments.push(Attachment::Message(raw.into()));
        self
    }

    /// Asks for `receipt` delivery receipts with `X-TipoRicevuta` (§6.5.2.2, §6.5.2.3).
    pub const fn receipt(mut self, receipt: ReceiptKind) -> Self {
        self.receipt = receipt;
        self
    }

    /// Writes the message, with the envelope to send it with.
    ///
    /// Text outside printable ASCII goes as UTF-8, in encoded words in the header (RFC 2047) and quoted-printable in
    /// the body (RFC 2045 §6.7), and every field folds within 78 columns where its words allow (RFC 5322 §2.1.1). The
    /// body is the text, or a `multipart/alternative` of the text and then its HTML version (RFC 2046 §5.1.4), and the
    /// attachments follow it in order in a `multipart/mixed` (RFC 2046 §5.1.3).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Outgoing`] with [`OutgoingError::Subject`] when the subject holds a control character other
    /// than tab, with [`OutgoingError::Date`] when the date has a year outside 1900 to 3000 or a zone offset that is
    /// not whole minutes under a day, with [`OutgoingError::Identifier`] when a message identifier holds a character
    /// outside ASCII, or with [`OutgoingError::LineTooLong`] when a field holds a word too long for one line. An
    /// attachment fails with [`OutgoingError::AttachmentName`] for an empty name and with [`OutgoingError::ContentType`]
    /// for a content type that is not a discrete `type/subtype`, and an attached message fails with
    /// [`OutgoingError::AttachedMessage`] when it holds a NUL, a bare line break or a line over 998 octets.
    pub fn build(mut self) -> Result<OutgoingMessage, Error> {
        if let Some(subject) = self
            .subject
            .as_deref()
            .filter(|subject| has_control(subject))
        {
            return Err(OutgoingError::Subject(subject.to_owned()).into());
        }
        self.check_attachments()?;
        let mut raw = Vec::new();
        write::field(&mut raw, "Date", &write::date(&self.date)?)?;
        write::field(
            &mut raw,
            "From",
            &write::mailboxes(slice::from_ref(&self.from)),
        )?;
        if !self.reply_to.is_empty() {
            write::field(&mut raw, "Reply-To", &write::mailboxes(&self.reply_to))?;
        }
        write::field(&mut raw, "To", &write::mailboxes(&self.to))?;
        if !self.cc.is_empty() {
            write::field(&mut raw, "Cc", &write::mailboxes(&self.cc))?;
        }
        write::field(
            &mut raw,
            "Message-ID",
            &write::identifiers(slice::from_ref(&self.message_id))?,
        )?;
        if let Some(id) = &self.in_reply_to {
            write::field(
                &mut raw,
                "In-Reply-To",
                &write::identifiers(slice::from_ref(id))?,
            )?;
        }
        if !self.references.is_empty() {
            write::field(
                &mut raw,
                "References",
                &write::identifiers(&self.references)?,
            )?;
        }
        if let Some(subject) = &self.subject {
            write::field(&mut raw, "Subject", &write::unstructured(subject))?;
        }
        write::fixed_field(&mut raw, "X-TipoRicevuta", self.receipt.token());
        write::fixed_field(&mut raw, "MIME-Version", "1.0");
        if self.attachments.is_empty() {
            self.write_body(&mut raw);
        } else {
            let mut parts = Vec::with_capacity(1 + self.attachments.len());
            let mut body = Vec::new();
            self.write_body(&mut body);
            parts.push(body);
            for attachment in &self.attachments {
                let mut part = Vec::new();
                match attachment {
                    Attachment::File {
                        name,
                        content_type,
                        bytes,
                    } => write::file(&mut part, name, content_type, bytes)?,
                    Attachment::Message(message) => write::message(&mut part, message),
                }
                parts.push(part);
            }
            write::multipart(&mut raw, "multipart/mixed", &parts);
        }
        let mut forward_paths: Vec<String> = Vec::new();
        for mailbox in self.to.iter().chain(&self.cc) {
            if !forward_paths
                .iter()
                .any(|path| same_mailbox(path, mailbox.address()))
            {
                forward_paths.push(mailbox.address().to_owned());
            }
        }
        Ok(OutgoingMessage {
            raw,
            message_id: self.message_id,
            reverse_path: self.from.address().to_owned(),
            forward_paths,
        })
    }

    /// Checks that each attachment has a name and a discrete content type, and that each attached message goes 7bit
    /// or 8bit.
    ///
    /// # Errors
    ///
    /// Returns [`OutgoingError::AttachmentName`], [`OutgoingError::ContentType`] or
    /// [`OutgoingError::AttachedMessage`] for the first attachment that fails.
    fn check_attachments(&mut self) -> Result<(), OutgoingError> {
        for (index, attachment) in self.attachments.iter_mut().enumerate() {
            match attachment {
                Attachment::File { name, .. } if name.is_empty() => {
                    return Err(OutgoingError::AttachmentName(index));
                }
                Attachment::File { content_type, .. } if !write::is_discrete(content_type) => {
                    return Err(OutgoingError::ContentType(mem::take(content_type)));
                }
                Attachment::Message(raw) => {
                    if let Some(at) = write::unsendable(raw) {
                        return Err(OutgoingError::AttachedMessage {
                            attachment: index,
                            at,
                        });
                    }
                }
                Attachment::File { .. } => {}
            }
        }
        Ok(())
    }

    /// Writes the content fields of the body, a blank line and the body, the text alone or a `multipart/alternative`
    /// of the text and then its HTML version (RFC 2046 §5.1.4).
    fn write_body(&self, out: &mut Vec<u8>) {
        match &self.html {
            None => write::text(out, PLAIN, &self.text),
            Some(html) => {
                let mut plain = Vec::new();
                write::text(&mut plain, PLAIN, &self.text);
                let mut alternative = Vec::new();
                write::text(&mut alternative, HTML, html);
                write::multipart(out, "multipart/alternative", &[plain, alternative]);
            }
        }
    }
}
