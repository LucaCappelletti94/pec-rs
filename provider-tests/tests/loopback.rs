//! Sends a prepared message through lettre to an SMTP server on the loopback interface and checks the bytes the server
//! stores, which no provider shows.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing step"
)]

mod built;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

use built::built;
use lettre::address::Envelope;
use lettre::{SmtpTransport, Transport};
use postacert::{OutgoingMessage, ReceiptKind};

/// A message with a line starting with a dot, which SMTP sends doubled (RFC 5321 §4.5.2).
const MESSAGE: &[u8] = b"From: mario.rossi@pec.example.it\r\n\
    To: ufficio.fatture@pec.example.it\r\n\
    Date: Fri, 13 Nov 2026 12:00:00 +0100\r\n\
    Message-ID: <loopback@client.example.it>\r\n\
    \r\n\
    Fattura in allegato.\r\n\
    .Riga che inizia con un punto.\r\n";

/// Answers one SMTP session on `listener` and returns the message data it stores, without the transparency dots and
/// the terminating `.` line (RFC 5321 §4.1.1.4, §4.5.2).
fn stored(listener: &TcpListener) -> Vec<u8> {
    let (stream, _) = listener.accept().expect("a connection");
    let mut writer = stream
        .try_clone()
        .expect("a second handle on the connection");
    let mut reader = BufReader::new(stream);
    writer
        .write_all(b"220 loopback\r\n")
        .expect("the greeting is sent");
    let mut data = Vec::new();
    let mut in_data = false;
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line).expect("a line") == 0 {
            return data;
        }
        if in_data {
            if line == b".\r\n" {
                in_data = false;
                writer
                    .write_all(b"250 stored\r\n")
                    .expect("the reply is sent");
            } else {
                data.extend_from_slice(line.strip_prefix(b".").unwrap_or(&line));
            }
            continue;
        }
        let reply: &[u8] = if line.starts_with(b"DATA") {
            in_data = true;
            b"354 go on\r\n"
        } else if line.starts_with(b"QUIT") {
            b"221 bye\r\n"
        } else {
            b"250 ok\r\n"
        };
        writer.write_all(reply).expect("the reply is sent");
        if line.starts_with(b"QUIT") {
            return data;
        }
    }
}

/// Sends `outgoing` through lettre to a server on the loopback interface and returns the bytes the server stores.
fn sent(outgoing: &OutgoingMessage) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let port = listener.local_addr().expect("a local address").port();
    let server = thread::spawn(move || stored(&listener));
    let envelope = Envelope::new(
        Some(
            outgoing
                .reverse_path()
                .parse()
                .expect("a valid reverse path"),
        ),
        outgoing
            .forward_paths()
            .iter()
            .map(|path| path.parse().expect("a valid forward path"))
            .collect(),
    )
    .expect("an envelope");
    SmtpTransport::builder_dangerous("127.0.0.1")
        .port(port)
        .build()
        .send_raw(&envelope, outgoing.as_bytes())
        .expect("the server stores the message");
    server.join().expect("the server finishes")
}

#[test]
fn lettre_sends_a_prepared_message_as_prepared() {
    let outgoing = OutgoingMessage::prepare(MESSAGE, ReceiptKind::Full).expect("a valid message");
    // lettre 0.11.23 writes a CRLF before the terminating `.` line even after the message's own final CRLF, so the
    // server stores one more, empty, line than the message holds (RFC 5321 §4.1.1.4).
    assert_eq!(sent(&outgoing), [outgoing.as_bytes(), b"\r\n"].concat());
}

#[test]
fn lettre_sends_a_built_message_as_built() {
    let outgoing = built(
        "mario.rossi@pec.example.it",
        "ufficio.fatture@pec.example.it",
        "Fattura in allegato",
        "loopback.built@client.example.it",
        ReceiptKind::Full,
    );
    // A built message ends without a line break, which lettre's CRLF before the terminating `.` line ends.
    assert_eq!(sent(&outgoing), [outgoing.as_bytes(), b"\r\n"].concat());
}
