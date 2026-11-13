//! Short delivery receipts, whose original carries a SHA-1 in place of each attachment, §6.5.2.2.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use core::fmt::Write as _;
use pec::{AttachmentCheck, Error, Message, TextLineEnds};
use sha1::{Digest, Sha1};

/// Reads a signed message fixture.
fn message(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/messages/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists")
}

/// Reads a message the sender sent, as kept on the sender's side.
fn sent(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/original/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists")
}

/// The checks of a short receipt fixture against a sent message, accepting text hashed in canonical form only.
fn checks(receipt: &str, sent: &[u8]) -> Result<Vec<AttachmentCheck>, Error> {
    checks_with(receipt, sent, TextLineEnds::Canonical)
}

/// The checks of a short receipt fixture against a sent message, accepting the given text line ends.
fn checks_with(
    receipt: &str,
    sent: &[u8],
    line_ends: TextLineEnds,
) -> Result<Vec<AttachmentCheck>, Error> {
    Message::parse(&message(receipt))
        .expect("a valid receipt")
        .check_attachments(sent, line_ends)
}

/// Every attachment of `attachments.eml` matching its hash.
fn all_match() -> Vec<AttachmentCheck> {
    vec![
        AttachmentCheck::Matches(Some("fattura.xml".to_owned())),
        AttachmentCheck::Matches(Some("nota.txt".to_owned())),
        AttachmentCheck::Matches(None),
    ]
}

/// `bytes` with every occurrence of `from` replaced by `to`.
fn replaced(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = core::str::from_utf8(bytes).expect("ascii fixture");
    assert!(text.contains(from), "{from:?} is in the fixture");
    text.replace(from, to).into_bytes()
}

/// The 20 bytes written as 40 hexadecimal digits.
fn sha1(hex: &str) -> [u8; 20] {
    let mut digest = [0; 20];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).expect("ascii"), 16).expect("hex");
    }
    digest
}

/// The name and digest of every hash the receipt carries, in order.
fn hashes(raw: &[u8], sent: &[u8]) -> Vec<(String, [u8; 20])> {
    Message::parse(raw)
        .expect("a valid short receipt")
        .attachment_hashes(sent, TextLineEnds::Canonical)
        .expect("valid generated hashes")
        .iter()
        .map(|hash| (hash.name().to_owned(), *hash.sha1()))
        .collect()
}

/// The hashes of `fattura.xml`, `nota.txt` and the attached message, which a provider names `null` when the
/// attachment has no file name.
fn expected() -> Vec<(String, [u8; 20])> {
    vec![
        (
            "fattura.xml".to_owned(),
            sha1("ff20c898b2ab8b020f1f3d3f07fff7bc37a988a5"),
        ),
        (
            "nota.txt".to_owned(),
            sha1("6a07a23ff2f2c1f378da855d1ae1218bb1ab539c"),
        ),
        (
            "null".to_owned(),
            sha1("5668ebdfec476cfb773752c7875f9c9dd778b778"),
        ),
    ]
}

/// Each `.hash` part names the replaced file and holds its SHA-1 in upper or lower case, as providers differ.
#[test]
fn short_receipt_carries_one_hash_per_attachment() {
    assert_eq!(
        hashes(&message("delivery-short.eml"), &sent("attachments.eml")),
        expected()
    );
}

/// A signed original keeps its signature part, and the hashes replace the attachments inside the signed part.
#[test]
fn signed_original_carries_its_hashes_inside_the_signed_part() {
    assert_eq!(
        hashes(
            &message("delivery-short-signed.eml"),
            &sent("attachments-signed.eml")
        ),
        expected()
    );
}

/// An encrypted original is left whole, since its attachments cannot be found inside the CMS object.
#[test]
fn encrypted_original_carries_no_hash() {
    assert_eq!(
        hashes(
            &message("delivery-short-encrypted.eml"),
            &sent("encrypted.eml")
        ),
        Vec::new()
    );
}

/// Only a short receipt replaces attachments, so a full receipt keeps a sender's own attachment named `.hash` as it
/// is, whatever it holds.
#[test]
fn full_receipt_reads_no_hash() {
    let raw = message("delivery-full-user-hash.eml");
    assert_eq!(hashes(&raw, &sent("user-hash.eml")), Vec::new());
}

/// A `.hash` part holds exactly 40 hexadecimal digits.
#[test]
fn malformed_hash_is_refused() {
    let digits = "FF20C898B2AB8B020F1F3D3F07FFF7BC37A988A5";
    for broken in [
        &digits[..38],
        &digits[..39],
        "FF20C898B2AB8B020F1F3D3F07FFF7BC37A988A500",
        "FF20C898B2AB8B020F1F3D3F07FFF7BC37A988A5A",
        "GF20C898B2AB8B020F1F3D3F07FFF7BC37A988A5",
        "FF20C898B2AB8B020F1F3D3F07FFF7BC37A988AG",
    ] {
        let raw = replaced(&message("delivery-short.eml"), digits, broken);
        let receipt = Message::parse(&raw).expect("the envelope is readable");
        let original = sent("attachments.eml");
        for result in [
            receipt
                .attachment_hashes(&original, TextLineEnds::Canonical)
                .map(|_| ()),
            receipt
                .check_attachments(&original, TextLineEnds::Canonical)
                .map(|_| ()),
        ] {
            assert_eq!(
                result,
                Err(Error::InvalidAttachmentHash("fattura.xml.hash".to_owned())),
                "{broken}"
            );
        }
    }
}

/// A line end after the digits is not part of the hash.
#[test]
fn hash_may_end_with_a_line_end() {
    let digits = "FF20C898B2AB8B020F1F3D3F07FFF7BC37A988A5";
    let raw = replaced(
        &message("delivery-short.eml"),
        digits,
        &format!("{digits}\r\n"),
    );
    assert_eq!(hashes(&raw, &sent("attachments.eml")), expected());
}

/// An attachment the provider left in place is not one of the hashes.
#[test]
fn unreplaced_attachment_is_no_hash() {
    let raw = replaced(&message("delivery-short.eml"), "nota.txt.hash", "nota.txt");
    let mut expected = expected();
    expected.remove(1);
    assert_eq!(hashes(&raw, &sent("attachments.eml")), expected);
}

/// The hash of each sent attachment is the SHA-1 of its decoded content, headers included for an attached message.
/// The attached message has no file name, so it is found by its digest.
#[test]
fn sent_attachments_match_their_hashes() {
    assert_eq!(
        checks("delivery-short.eml", &sent("attachments.eml")),
        Ok(all_match())
    );
}

/// A signed message carries its attachments inside the signed part.
#[test]
fn signed_attachments_match_their_hashes() {
    assert_eq!(
        checks("delivery-short-signed.eml", &sent("attachments-signed.eml")),
        Ok(all_match())
    );
}

/// An encrypted message has no attachment a provider could replace, so there is nothing to check.
#[test]
fn encrypted_message_has_nothing_to_check() {
    assert_eq!(
        checks("delivery-short-encrypted.eml", &sent("encrypted.eml")),
        Ok(Vec::new())
    );
}

/// An attachment that changed after the receipt differs from the hash under its name.
#[test]
fn changed_attachment_differs() {
    let changed = replaced(&sent("attachments.eml"), "Nota con", "Nota sul");
    assert_eq!(
        checks("delivery-short.eml", &changed),
        Ok(vec![
            AttachmentCheck::Matches(Some("fattura.xml".to_owned())),
            AttachmentCheck::Differs("nota.txt".to_owned()),
            AttachmentCheck::Matches(None),
        ])
    );
}

/// A sent attachment without a hash in the receipt is missing from it, and a hash that no sent attachment has is
/// reported as not sent. A renamed attachment is still found by its digest.
#[test]
fn unmatched_attachments_and_hashes_are_reported() {
    let renamed = replaced(&sent("attachments.eml"), "fattura.xml", "fattura-bis.xml");
    let changed = replaced(&renamed, "Ordine numero 42", "Ordine numero 43");
    assert_eq!(
        checks("delivery-short.eml", &changed),
        Ok(vec![
            AttachmentCheck::Matches(Some("fattura-bis.xml".to_owned())),
            AttachmentCheck::Matches(Some("nota.txt".to_owned())),
            AttachmentCheck::Missing(None),
            AttachmentCheck::NotSent(Some("null".to_owned())),
        ])
    );
}

/// A provider may leave an attachment in place instead of its hash, as Aruba does for a part named only by its
/// `Content-Type`, and the receipt then carries the attachment itself.
#[test]
fn kept_attachment_is_carried() {
    assert_eq!(
        checks("delivery-short-kept.eml", &sent("attachments-kept.eml")),
        Ok(vec![
            AttachmentCheck::Carried(Some("fattura.xml".to_owned())),
            AttachmentCheck::Matches(Some("nota.txt".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
}

#[test]
fn carried_attached_message_preserves_headers_and_body() {
    let original = sent("attachments.eml");
    let attached = core::str::from_utf8(&original)
        .expect("ASCII sent fixture")
        .split_once("Content-Type: message/rfc822\r\n")
        .expect("attached message")
        .1
        .split_once("\r\n--pec-sent--")
        .expect("closing MIME boundary")
        .0;
    let raw = replaced(
        &message("delivery-short.eml"),
        concat!(
            "Content-Type: text/plain; name=\"null.hash\"\r\n",
            "Content-Disposition: attachment; filename=\"null.hash\"\r\n",
            "Content-Transfer-Encoding: 7bit\r\n\r\n",
            "5668EBDFEC476CFB773752C7875F9C9DD778B778",
        ),
        &format!("Content-Type: message/rfc822\r\n{attached}"),
    );
    let receipt = Message::parse(&raw).expect("receipt carrying the attached message");
    assert_eq!(hashes(&raw, &original), expected()[..2]);
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Matches(Some("fattura.xml".to_owned())),
            AttachmentCheck::Matches(Some("nota.txt".to_owned())),
            AttachmentCheck::Carried(None),
        ])
    );
    for (from, to) in [
        ("Subject: Ordine di acquisto", "Subject: Ordine modificato"),
        ("Ordine numero 42", "Ordine numero 43"),
    ] {
        let changed = replaced(&raw, from, to);
        let receipt = Message::parse(&changed).expect("receipt carrying a changed message");
        assert_eq!(
            receipt.check_attachments(&original, TextLineEnds::Canonical),
            Ok(vec![
                AttachmentCheck::Matches(Some("fattura.xml".to_owned())),
                AttachmentCheck::Matches(Some("nota.txt".to_owned())),
                AttachmentCheck::Missing(None),
                AttachmentCheck::NotSent(None),
            ]),
            "{from}"
        );
    }
}

const FORWARDED_MESSAGE: &str = "From: a@example.test\r\nSubject: caffè\r\n\r\nhello\r\n";
const FORWARDED_BASE64: &str = "RnJvbTogYUBleGFtcGxlLnRlc3QNClN1YmplY3Q6IGNhZmbDqA0KDQpoZWxsbw0K";

/// Wraps an attached message with its declared transfer encoding.
fn attached_message(encoding: &str, body: &str) -> Vec<u8> {
    format!(
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"forwarded\"\r\n\r\n--forwarded\r\nContent-Type: message/global\r\nContent-Disposition: attachment; filename=\"forwarded.eml\"\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n{body}\r\n--forwarded--\r\n"
    )
    .into_bytes()
}

#[test]
fn encoded_attached_message_hashes_match() {
    let original = attached_message("base64", FORWARDED_BASE64);
    let lf = FORWARDED_MESSAGE.replace("\r\n", "\n");
    for (line_ends, content) in [
        (TextLineEnds::Canonical, FORWARDED_MESSAGE),
        (TextLineEnds::CanonicalOrLf, lf.as_str()),
    ] {
        let hash = hex_digest(content.as_bytes());
        let raw = receipt_with(&text_attachments(&[("forwarded.eml.hash", &hash)]));
        let receipt = Message::parse(&raw).expect("a short receipt");
        assert_eq!(
            receipt.check_attachments(&original, line_ends),
            Ok(vec![AttachmentCheck::Matches(Some(
                "forwarded.eml".to_owned()
            ))])
        );
        let hashes = receipt
            .attachment_hashes(&original, line_ends)
            .expect("an unambiguous generated hash");
        assert_eq!(
            hashes
                .iter()
                .map(|hash| (hash.name(), *hash.sha1()))
                .collect::<Vec<_>>(),
            vec![("forwarded.eml", sha1(&hash))]
        );
    }
}

#[test]
fn reencoded_attached_messages_are_carried() {
    let plain = attached_message("8bit", FORWARDED_MESSAGE);
    let encoded = attached_message("base64", FORWARDED_BASE64);
    for (original, evidence) in [(&plain, &encoded), (&encoded, &plain)] {
        let raw = receipt_with(evidence);
        let receipt = Message::parse(&raw).expect("a short receipt");
        assert_eq!(
            receipt.check_attachments(original, TextLineEnds::Canonical),
            Ok(vec![AttachmentCheck::Carried(Some(
                "forwarded.eml".to_owned()
            ))])
        );
        assert_eq!(
            receipt.attachment_hashes(original, TextLineEnds::Canonical),
            Ok(Vec::new())
        );
    }
}

/// A kept attachment that is not the sent one differs, and when the sent one is renamed as well the receipt's copy
/// is reported as not sent.
#[test]
fn changed_kept_attachment_differs() {
    let changed = replaced(
        &sent("attachments-kept.eml"),
        "PD94bWwgdmVyc2lvbj0iMS4w",
        "PD94bWwgdmVyc2lvbj0iMS4x",
    );
    assert_eq!(
        checks("delivery-short-kept.eml", &changed),
        Ok(vec![
            AttachmentCheck::Differs("fattura.xml".to_owned()),
            AttachmentCheck::Matches(Some("nota.txt".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
    let renamed = replaced(&changed, "fattura.xml", "fattura-bis.xml");
    assert_eq!(
        checks("delivery-short-kept.eml", &renamed),
        Ok(vec![
            AttachmentCheck::Missing(Some("fattura-bis.xml".to_owned())),
            AttachmentCheck::Matches(Some("nota.txt".to_owned())),
            AttachmentCheck::Matches(None),
            AttachmentCheck::NotSent(Some("fattura.xml".to_owned())),
        ])
    );
}

/// Only a short receipt that carries the original holds hashes to check.
#[test]
fn other_receipts_cannot_be_checked() {
    for name in ["delivery-full.eml", "delivery-summary.eml", "transport.eml"] {
        assert_eq!(
            checks(name, &sent("attachments.eml")),
            Err(Error::NotShortReceipt),
            "{name}"
        );
    }
}

/// The sent message has to be MIME.
#[test]
fn sent_message_must_be_mime() {
    assert_eq!(checks("delivery-short.eml", b""), Err(Error::NotMime));
}

/// A provider that hashes text and attached messages with LF line ends, as OpenPEC does, differs from the
/// canonical CRLF form unless the caller accepts LF as well.
#[test]
fn lf_hashes_match_only_when_accepted() {
    let sent = sent("attachments-lines.eml");
    assert_eq!(
        checks("delivery-short-lf.eml", &sent),
        Ok(vec![
            AttachmentCheck::Differs("righe.txt".to_owned()),
            AttachmentCheck::Missing(None),
            AttachmentCheck::NotSent(Some("null".to_owned())),
        ])
    );
    assert_eq!(
        checks_with("delivery-short-lf.eml", &sent, TextLineEnds::CanonicalOrLf),
        Ok(vec![
            AttachmentCheck::Matches(Some("righe.txt".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
}

/// Accepting LF as well still accepts the canonical form, and leaves binary attachments alone.
#[test]
fn canonical_hashes_match_when_lf_is_accepted() {
    assert_eq!(
        checks_with(
            "delivery-short.eml",
            &sent("attachments.eml"),
            TextLineEnds::CanonicalOrLf
        ),
        Ok(all_match())
    );
}

/// The LF form pairs by digest too, for a provider that renames the hash, as OpenPEC does.
#[test]
fn renamed_text_hashed_with_lf_pairs_by_digest() {
    let raw = replaced(
        &message("delivery-short-lf.eml"),
        "righe.txt.hash",
        "righe-1.txt.hash",
    );
    let receipt = Message::parse(&raw).expect("a valid receipt");
    assert_eq!(
        receipt.check_attachments(&sent("attachments-lines.eml"), TextLineEnds::CanonicalOrLf),
        Ok(vec![
            AttachmentCheck::Matches(Some("righe.txt".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
}

/// Wraps one multipart's children in an unnamed multipart container.
fn nested(raw: &[u8], boundary: &str) -> Vec<u8> {
    let raw = replaced(
        raw,
        &format!("boundary=\"{boundary}\""),
        "boundary=\"nested-container\"",
    );
    let text = core::str::from_utf8(&raw).expect("ascii fixture");
    let text = text.replacen(
        &format!("--{boundary}\r\n"),
        &format!(
            "--nested-container\r\nContent-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n"
        ),
        1,
    );
    replaced(
        text.as_bytes(),
        &format!("--{boundary}--"),
        &format!("--{boundary}--\r\n--nested-container--"),
    )
}

#[test]
fn nested_attachments_are_checked() {
    let raw = nested(&message("delivery-short.eml"), "pec-short");
    let original = nested(&sent("attachments.eml"), "pec-sent");
    let receipt = Message::parse(&raw).expect("nested receipt");
    assert_eq!(hashes(&raw, &original), expected());
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(all_match())
    );
    let changed = replaced(&original, "Nota con", "Nota sul");
    assert_eq!(
        receipt.check_attachments(&changed, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Matches(Some("fattura.xml".to_owned())),
            AttachmentCheck::Differs("nota.txt".to_owned()),
            AttachmentCheck::Matches(None),
        ])
    );
}

#[test]
fn carried_hash_suffix_is_not_a_generated_hash() {
    let original = replaced(
        &sent("attachments-kept.eml"),
        "fattura.xml",
        "document.hash",
    );
    let raw = replaced(
        &message("delivery-short-kept.eml"),
        "fattura.xml",
        "document.hash",
    );
    let receipt = Message::parse(&raw).expect("a carried user file");
    assert_eq!(hashes(&raw, &original), expected()[1..]);
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Carried(Some("document.hash".to_owned())),
            AttachmentCheck::Matches(Some("nota.txt".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
}

#[test]
fn carried_text_hash_files_use_sent_content() {
    for content in [
        "0000000000000000000000000000000000000000",
        "user data rather than hexadecimal digits",
    ] {
        let original = replaced(&sent("attachments-kept.eml"), "nota.txt", "document.hash");
        let original = replaced(
            &original,
            "Nota con una lettera accentata: =C3=A8.=0A",
            content,
        );
        let raw = replaced(
            &message("delivery-short-kept.eml"),
            "nota.txt.hash",
            "document.hash",
        );
        let raw = replaced(&raw, "6A07A23FF2F2C1F378DA855D1AE1218BB1AB539C", content);
        let receipt = Message::parse(&raw).expect("a carried text file");
        assert_eq!(hashes(&raw, &original), expected()[2..]);
        assert_eq!(
            receipt.check_attachments(&original, TextLineEnds::Canonical),
            Ok(vec![
                AttachmentCheck::Carried(Some("fattura.xml".to_owned())),
                AttachmentCheck::Carried(Some("document.hash".to_owned())),
                AttachmentCheck::Matches(None),
            ]),
            "{content}"
        );
    }
}

#[test]
fn duplicate_names_pair_by_content() {
    let original = replaced(&sent("attachments-kept.eml"), "nota.txt", "fattura.xml");
    let raw = replaced(
        &message("delivery-short-kept.eml"),
        "nota.txt.hash",
        "fattura.xml.hash",
    );
    let receipt = Message::parse(&raw).expect("same-named attachments");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Carried(Some("fattura.xml".to_owned())),
            AttachmentCheck::Matches(Some("fattura.xml".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
}

#[test]
fn changed_duplicate_does_not_consume_another_attachments_hash() {
    let original = replaced(&sent("attachments.eml"), "nota.txt", "fattura.xml");
    let original = replaced(
        &original,
        "PD94bWwgdmVyc2lvbj0iMS4w",
        "PD94bWwgdmVyc2lvbj0iMS4x",
    );
    let raw = replaced(
        &message("delivery-short.eml"),
        "nota.txt.hash",
        "fattura.xml.hash",
    );
    let raw = replaced(&raw, "FF20C898B2AB8B020F1F3D3F07FFF7BC37A988A5", "SWAP");
    let raw = replaced(
        &raw,
        "6a07a23ff2f2c1f378da855d1ae1218bb1ab539c",
        "FF20C898B2AB8B020F1F3D3F07FFF7BC37A988A5",
    );
    let raw = replaced(&raw, "SWAP", "6a07a23ff2f2c1f378da855d1ae1218bb1ab539c");
    let receipt = Message::parse(&raw).expect("same-named hashes");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Differs("fattura.xml".to_owned()),
            AttachmentCheck::Matches(Some("fattura.xml".to_owned())),
            AttachmentCheck::Matches(None),
        ])
    );
}

/// Builds named text attachments from quoted-printable payloads.
fn text_attachments(parts: &[(&str, &str)]) -> Vec<u8> {
    let mut raw = String::from(
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"assignment\"\r\n\r\n",
    );
    for (name, body) in parts {
        write!(
            raw,
            "--assignment\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{body}\r\n"
        )
        .expect("writing a string");
    }
    raw.push_str("--assignment--\r\n");
    raw.into_bytes()
}

/// Wraps a replacement original in the short receipt fixture.
fn receipt_with(original: &[u8]) -> Vec<u8> {
    let raw = message("delivery-short.eml");
    let raw = core::str::from_utf8(&raw).expect("ASCII fixture");
    let marker = "Content-Disposition: inline; filename=\"postacert.eml\"\r\n\r\n";
    let start = raw.find(marker).expect("original header") + marker.len();
    let end = start
        + raw[start..]
            .find("\r\n--pec-inner--")
            .expect("original end");
    let mut result = Vec::with_capacity(start + original.len() + raw.len() - end);
    result.extend_from_slice(&raw.as_bytes()[..start]);
    result.extend_from_slice(original);
    result.extend_from_slice(&raw.as_bytes()[end..]);
    result
}

/// Hexadecimal SHA-1 of a decoded payload.
fn hex_digest(payload: &[u8]) -> String {
    let mut hex = String::with_capacity(40);
    for byte in Sha1::digest(payload) {
        write!(hex, "{byte:02x}").expect("writing a string");
    }
    hex
}

#[test]
fn named_single_part_roots_are_checked() {
    let original = b"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=\"only.txt\"\r\n\r\ndata";
    let hash = hex_digest(b"data");
    let raw = receipt_with(
        format!("Content-Type: text/plain\r\nContent-Disposition: attachment; filename=\"only.txt.hash\"\r\n\r\n{hash}").as_bytes(),
    );
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        hashes(&raw, original),
        vec![("only.txt".to_owned(), sha1(&hash))]
    );
    assert_eq!(
        receipt.check_attachments(original, TextLineEnds::Canonical),
        Ok(vec![AttachmentCheck::Matches(Some("only.txt".to_owned()))])
    );
    assert_eq!(
        receipt.check_attachments(
            &replaced(original, "data", "tampered"),
            TextLineEnds::Canonical
        ),
        Ok(vec![AttachmentCheck::Differs("only.txt".to_owned())])
    );
}

#[test]
fn checksum_chain_uses_a_complete_assignment() {
    let hash = hex_digest(b"data");
    let checksum_hash = hex_digest(hash.as_bytes());
    let original = text_attachments(&[("document", "data"), ("document.hash", &hash)]);
    let raw = receipt_with(&text_attachments(&[
        ("document.hash", &hash),
        ("document.hash.hash", &checksum_hash),
    ]));
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Matches(Some("document".to_owned())),
            AttachmentCheck::Matches(Some("document.hash".to_owned())),
        ])
    );
    assert_eq!(
        hashes(&raw, &original),
        vec![
            ("document".to_owned(), sha1(&hash)),
            ("document.hash".to_owned(), sha1(&checksum_hash)),
        ]
    );
}

#[test]
fn indistinguishable_checksum_interpretations_are_rejected() {
    let hash = hex_digest(b"data");
    let original = text_attachments(&[("document", "data"), ("document.hash", &hash)]);
    let raw = receipt_with(&text_attachments(&[("document.hash", &hash)]));
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Err(Error::AmbiguousAttachments)
    );
    assert_eq!(
        receipt.attachment_hashes(&original, TextLineEnds::Canonical),
        Err(Error::AmbiguousAttachments)
    );
}

#[test]
fn line_ending_alternatives_reserve_required_hashes() {
    let canonical = hex_digest(b"a\r\nb");
    let lf = hex_digest(b"a\nb");
    let originals = [
        text_attachments(&[("text", "a=0D=0Ab"), ("text", "a=0Ab")]),
        text_attachments(&[("text", "a=0Ab"), ("text", "a=0D=0Ab")]),
    ];
    for original in originals {
        for hashes in [[&lf, &canonical], [&canonical, &lf]] {
            let raw = receipt_with(&text_attachments(&[
                ("text.hash", hashes[0]),
                ("text.hash", hashes[1]),
            ]));
            let receipt = Message::parse(&raw).expect("a short receipt");
            assert_eq!(
                receipt.check_attachments(&original, TextLineEnds::CanonicalOrLf),
                Ok(vec![AttachmentCheck::Matches(Some("text".to_owned())); 2])
            );
            assert_eq!(
                receipt
                    .attachment_hashes(&original, TextLineEnds::CanonicalOrLf)
                    .expect("unambiguous hashes")
                    .iter()
                    .map(|hash| *hash.sha1())
                    .collect::<Vec<_>>(),
                hashes.map(|hash| sha1(hash))
            );
        }
    }
}

#[test]
fn identical_receipt_copies_preserve_interpretation_counts() {
    let hash = hex_digest(b"data");
    let original = text_attachments(&[("document", "data"), ("document.hash", &hash)]);
    let raw = receipt_with(&text_attachments(&[("document.hash", hash.as_str()); 3]));
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Matches(Some("document".to_owned())),
            AttachmentCheck::Carried(Some("document.hash".to_owned())),
            AttachmentCheck::NotSent(Some("document.hash".to_owned())),
        ])
    );
    assert_eq!(
        hashes(&raw, &original),
        vec![("document".to_owned(), sha1(&hash))]
    );
}

#[test]
fn distinguishable_receipt_assignments_are_ambiguous() {
    let hash = hex_digest(b"data");
    let cases = [
        (
            text_attachments(&[("document", "data")]),
            text_attachments(&[("first.hash", &hash), ("second.hash", &hash)]),
        ),
        (
            text_attachments(&[("document", "data"), ("document.hash", "checksum")]),
            text_attachments(&[
                ("document.hash", "0000000000000000000000000000000000000000"),
                ("document.hash", "1111111111111111111111111111111111111111"),
            ]),
        ),
        (
            text_attachments(&[("document", "data"); 2]),
            text_attachments(&[("document.hash", &hash)]),
        ),
    ];
    for (original, evidence) in cases {
        let raw = receipt_with(&evidence);
        let receipt = Message::parse(&raw).expect("a short receipt");
        assert_eq!(
            receipt.check_attachments(&original, TextLineEnds::Canonical),
            Err(Error::AmbiguousAttachments)
        );
        assert_eq!(
            receipt.attachment_hashes(&original, TextLineEnds::Canonical),
            Err(Error::AmbiguousAttachments)
        );
    }
}

#[test]
fn identical_generated_extras_remain_in_receipt_order() {
    let hash = hex_digest(b"data");
    let independent = hex_digest(b"independent");
    let original = text_attachments(&[("document", "data"), ("other", "independent")]);
    let raw = receipt_with(&text_attachments(&[
        ("document.hash", &hash),
        ("document.hash", &hash),
        ("other.hash", &independent),
    ]));
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Matches(Some("document".to_owned())),
            AttachmentCheck::Matches(Some("other".to_owned())),
            AttachmentCheck::NotSent(Some("document".to_owned())),
        ])
    );
    assert_eq!(
        hashes(&raw, &original),
        vec![
            ("document".to_owned(), sha1(&hash)),
            ("document".to_owned(), sha1(&hash)),
            ("other".to_owned(), sha1(&independent)),
        ]
    );
}

#[test]
fn filename_differences_take_priority_over_renamed_content() {
    let hash = hex_digest(b"second");
    let original = text_attachments(&[("first", "first"), ("second", "second")]);
    let raw = receipt_with(&text_attachments(&[("first.hash", &hash)]));
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Differs("first".to_owned()),
            AttachmentCheck::Missing(Some("second".to_owned())),
        ])
    );
}

#[test]
fn empty_attachment_sides_report_missing_and_unsent_evidence() {
    let empty = text_attachments(&[]);
    let original = text_attachments(&[("document", "data")]);
    let raw = receipt_with(&empty);
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![AttachmentCheck::Missing(Some("document".to_owned()))])
    );
    assert_eq!(
        receipt.check_attachments(&empty, TextLineEnds::Canonical),
        Ok(vec![])
    );
    let hash = hex_digest(b"data");
    let raw = receipt_with(&text_attachments(&[
        ("document.hash", &hash),
        ("extra", "extra"),
    ]));
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&empty, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::NotSent(Some("document".to_owned())),
            AttachmentCheck::NotSent(Some("extra".to_owned())),
        ])
    );
    assert_eq!(
        hashes(&raw, &empty),
        vec![("document".to_owned(), sha1(&hash))]
    );
}

#[test]
fn renamed_generated_digest_needs_no_hash_suffix() {
    let hash = hex_digest(b"data");
    let unrelated = hex_digest(b"unrelated");
    let original = text_attachments(&[("document", "data")]);
    let raw = receipt_with(&text_attachments(&[
        ("checksum.txt", &hash),
        ("unrelated.txt", &unrelated),
    ]));
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Matches(Some("document".to_owned())),
            AttachmentCheck::NotSent(Some("unrelated.txt".to_owned())),
        ])
    );
    assert_eq!(
        hashes(&raw, &original),
        vec![("checksum.txt".to_owned(), sha1(&hash))]
    );
}

#[test]
fn carried_digest_text_retains_full_filename_priority() {
    let hash = hex_digest(b"data");
    let original = text_attachments(&[("document", "data"), ("checksum.txt", &hash)]);
    let raw = receipt_with(&text_attachments(&[("checksum.txt", &hash)]));
    let receipt = Message::parse(&raw).expect("a short receipt");
    assert_eq!(
        receipt.check_attachments(&original, TextLineEnds::Canonical),
        Ok(vec![
            AttachmentCheck::Missing(Some("document".to_owned())),
            AttachmentCheck::Carried(Some("checksum.txt".to_owned())),
        ])
    );
    assert_eq!(hashes(&raw, &original), vec![]);
}
