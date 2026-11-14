//! The message the loopback and OpenPEC tests send beside the hand-written one, written by the crate's builder.

use postacert::{Limits, Mailbox, OutgoingMessage, ReceiptKind};

/// A message from `from` to `to` asking for `receipt` delivery receipts, written by the crate's builder, then checked
/// against the limits every provider accepts. Its text has a line starting with a dot, which SMTP sends doubled (RFC
/// 5321 §4.5.2), and an HTML version, and it carries a PDF and an attached message.
pub fn built(
    from: &str,
    to: &str,
    subject: &str,
    message_id: &str,
    receipt: ReceiptKind,
) -> OutgoingMessage {
    let outgoing = OutgoingMessage::builder(
        Mailbox::named("Mittente di prova", from).expect("a dot-atom address"),
        Mailbox::new(to).expect("a dot-atom address"),
        format!("<{message_id}>")
            .parse()
            .expect("a message identifier"),
        jiff::Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC),
    )
    .subject(subject)
    .text("Messaggio di prova scritto dal builder, con caffè.\n.Riga che inizia con un punto.\n")
    .html("<p>Messaggio di prova scritto dal builder, con caffè.</p>\n<p>.Riga che inizia con un punto.</p>\n")
    .attachment("fattura.pdf", "application/pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    .attached_message(
        b"From: anna.verdi@example.com\r\nSubject: Messaggio inoltrato\r\n\r\nTesto del messaggio inoltrato.\r\n"
            .as_slice(),
    )
    .receipt(receipt)
    .build()
    .expect("the builder writes the message");
    outgoing
        .check_limits(Limits::GUARANTEED)
        .expect("the message is within every provider's limits");
    outgoing
}
