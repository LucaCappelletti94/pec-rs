//! Building an outgoing message from arbitrary builder input. Whatever builds passes `prepare` unchanged, and
//! mail-parser reads back its subject, display names, bodies, attachment names and bytes, and attached messages as
//! given.
//!
//! Addresses and identifiers come from small valid sets, which `outgoing_prepare` and `message_parse` already fuzz, so
//! the input reaches the writer.

#![no_main]

use std::borrow::Cow;

use jiff::Timestamp;
use jiff::tz::{Offset, TimeZone};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use mail_parser::{AddressList, MessageParser};
use postacert::{Mailbox, MessageId, OutgoingMessage, OutgoingMessageBuilder, ReceiptKind};

/// The builder input.
#[derive(Arbitrary, Debug)]
struct Input {
    from: Recipient,
    to: Recipient,
    more_to: Vec<Recipient>,
    cc: Vec<Recipient>,
    reply_to: Vec<Recipient>,
    message_id: u16,
    in_reply_to: Option<u16>,
    references: Vec<u16>,
    seconds: i64,
    offset: i32,
    subject: Option<String>,
    text: String,
    html: Option<String>,
    attachments: Vec<Attachment>,
    receipt: Receipt,
}

/// A mailbox, its display name and one of a few addresses.
#[derive(Arbitrary, Debug)]
struct Recipient {
    name: Option<String>,
    address: u8,
}

/// An attachment, a file or a message.
#[derive(Arbitrary, Debug)]
enum Attachment {
    File {
        name: String,
        content_type: ContentType,
        bytes: Vec<u8>,
    },
    Message(Vec<u8>),
}

/// A content type, a common one or any text.
#[derive(Arbitrary, Debug)]
enum ContentType {
    Pdf,
    Text,
    OctetStream,
    Other(String),
}

/// The receipt form asked for.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Receipt {
    Full,
    Short,
    Summary,
}

fuzz_target!(|input: Input| {
    let receipt = match input.receipt {
        Receipt::Full => ReceiptKind::Full,
        Receipt::Short => ReceiptKind::Short,
        Receipt::Summary => ReceiptKind::Summary,
    };
    let Some(date) = Timestamp::from_second(input.seconds)
        .ok()
        .zip(Offset::from_seconds(input.offset).ok())
        .map(|(timestamp, offset)| timestamp.to_zoned(TimeZone::fixed(offset)))
    else {
        return;
    };
    let mut builder = OutgoingMessage::builder(
        mailbox(&input.from),
        mailbox(&input.to),
        identifier(input.message_id),
        date,
    )
    .receipt(receipt)
    .text(input.text.as_str());
    for recipient in &input.more_to {
        builder = builder.to(mailbox(recipient));
    }
    for recipient in &input.cc {
        builder = builder.cc(mailbox(recipient));
    }
    for recipient in &input.reply_to {
        builder = builder.reply_to(mailbox(recipient));
    }
    if let Some(id) = input.in_reply_to {
        builder = builder.in_reply_to(identifier(id));
    }
    builder = builder.references(input.references.iter().map(|&id| identifier(id)));
    if let Some(subject) = &input.subject {
        builder = builder.subject(subject.as_str());
    }
    if let Some(html) = &input.html {
        builder = builder.html(html.as_str());
    }
    builder = attach(builder, &input.attachments);
    let Ok(built) = builder.build() else {
        return;
    };
    assert_eq!(
        OutgoingMessage::prepare(built.as_bytes(), receipt).as_ref(),
        Ok(&built),
        "prepare changed the built message"
    );
    let parsed = MessageParser::default()
        .parse(built.as_bytes())
        .expect("mail-parser reads the built message");
    if let Some(subject) = input
        .subject
        .as_deref()
        .filter(|subject| !subject.is_empty())
    {
        assert_eq!(parsed.subject(), Some(subject), "subject");
    }
    assert_eq!(names(parsed.from()), [name(&input.from)], "From");
    let to = core::iter::once(&input.to).chain(&input.more_to);
    assert_eq!(names(parsed.to()), to.map(name).collect::<Vec<_>>(), "To");
    if !input.cc.is_empty() {
        assert_eq!(
            names(parsed.cc()),
            input.cc.iter().map(name).collect::<Vec<_>>(),
            "Cc"
        );
    }
    if !input.reply_to.is_empty() {
        let reply_to = input.reply_to.iter().map(name).collect::<Vec<_>>();
        assert_eq!(names(parsed.reply_to()), reply_to, "Reply-To");
    }
    assert_eq!(
        parsed.body_text(0).unwrap_or_default(),
        crlf(&input.text),
        "text body"
    );
    if let Some(html) = &input.html {
        assert_eq!(
            parsed.body_html(0).unwrap_or_default(),
            crlf(html),
            "HTML body"
        );
    }
    let attachments = parsed
        .attachments()
        .map(|part| {
            (
                part.attachment_name(),
                part.nested()
                    .map_or_else(|| part.decoded(), |message| Cow::Borrowed(message.raw())),
            )
        })
        .collect::<Vec<_>>();
    let expected = input
        .attachments
        .iter()
        .map(|attachment| match attachment {
            Attachment::File { name, bytes, .. } => {
                (Some(name.as_str()), Cow::Borrowed(bytes.as_slice()))
            }
            Attachment::Message(raw) => (None, Cow::Borrowed(raw.as_slice())),
        })
        .collect::<Vec<_>>();
    assert_eq!(attachments, expected, "attachments");
});

/// The mailbox of `recipient`, without its display name when the name is not one a mailbox takes.
fn mailbox(recipient: &Recipient) -> Mailbox {
    let address = address(recipient.address);
    recipient
        .name
        .as_deref()
        .and_then(|name| Mailbox::named(name, &address).ok())
        .unwrap_or_else(|| Mailbox::new(&address).expect("a dot-atom address"))
}

/// The display name the mailbox of `recipient` holds.
fn name(recipient: &Recipient) -> Option<String> {
    mailbox(recipient).name().map(str::to_owned)
}

/// One of a few dot-atom addresses.
fn address(index: u8) -> String {
    format!("utente.{}@pec.example.it", index % 8)
}

/// One of the identifiers numbered by `index`.
fn identifier(index: u16) -> MessageId {
    format!("<{index}.0001@client.example.it>")
        .parse()
        .expect("a message identifier")
}

/// `builder` with `attachments` added in order.
fn attach(
    mut builder: OutgoingMessageBuilder,
    attachments: &[Attachment],
) -> OutgoingMessageBuilder {
    for attachment in attachments {
        builder = match attachment {
            Attachment::File {
                name,
                content_type,
                bytes,
            } => {
                let content_type = match content_type {
                    ContentType::Pdf => "application/pdf",
                    ContentType::Text => "text/plain",
                    ContentType::OctetStream => "application/octet-stream",
                    ContentType::Other(other) => other.as_str(),
                };
                builder.attachment(name.as_str(), content_type, bytes.as_slice())
            }
            Attachment::Message(raw) => builder.attached_message(raw.as_slice()),
        };
    }
    builder
}

/// The display names of the mailboxes of `list`, in order.
fn names(list: Option<AddressList<'_>>) -> Vec<Option<String>> {
    list.expect("an address list")
        .mailboxes()
        .map(|mailbox| mailbox.name().map(str::to_owned))
        .collect()
}

/// `text` with every line break written as CRLF.
fn crlf(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}
