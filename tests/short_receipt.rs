//! Short delivery receipts, whose original carries a SHA-1 in place of each attachment, §6.5.2.2.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use pec::{AttachmentCheck, Error, Message, TextLineEnds};

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
fn hashes(raw: &[u8]) -> Vec<(String, [u8; 20])> {
    Message::parse(raw)
        .expect("a valid short receipt")
        .attachment_hashes()
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
    assert_eq!(hashes(&message("delivery-short.eml")), expected());
}

/// A signed original keeps its signature part, and the hashes replace the attachments inside the signed part.
#[test]
fn signed_original_carries_its_hashes_inside_the_signed_part() {
    assert_eq!(hashes(&message("delivery-short-signed.eml")), expected());
}

/// An encrypted original is left whole, since its attachments cannot be found inside the CMS object.
#[test]
fn encrypted_original_carries_no_hash() {
    assert_eq!(hashes(&message("delivery-short-encrypted.eml")), Vec::new());
}

/// Only a short receipt replaces attachments, so a full receipt keeps a sender's own attachment named `.hash` as it
/// is, whatever it holds.
#[test]
fn full_receipt_reads_no_hash() {
    let raw = message("delivery-full-user-hash.eml");
    assert_eq!(hashes(&raw), Vec::new());
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
        assert_eq!(
            Message::parse(&raw).map(|_| ()),
            Err(Error::InvalidAttachmentHash("fattura.xml.hash".to_owned())),
            "{broken}"
        );
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
    assert_eq!(hashes(&raw), expected());
}

/// An attachment the provider left in place is not one of the hashes.
#[test]
fn unreplaced_attachment_is_no_hash() {
    let raw = replaced(&message("delivery-short.eml"), "nota.txt.hash", "nota.txt");
    let mut expected = expected();
    expected.remove(1);
    assert_eq!(hashes(&raw), expected);
}

/// The hash of each sent attachment is the SHA-1 of its decoded content, or of an attached message as sent. The
/// attached message has no file name, so it is found by its digest.
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

/// A provider that hashes a text attachment with LF line ends, as OpenPEC does, differs from the canonical CRLF
/// form unless the caller accepts LF as well.
#[test]
fn text_hashed_with_lf_matches_only_when_accepted() {
    let sent = sent("attachments-lines.eml");
    assert_eq!(
        checks("delivery-short-lf.eml", &sent),
        Ok(vec![AttachmentCheck::Differs("righe.txt".to_owned())])
    );
    assert_eq!(
        checks_with("delivery-short-lf.eml", &sent, TextLineEnds::CanonicalOrLf),
        Ok(vec![AttachmentCheck::Matches(Some("righe.txt".to_owned()))])
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
        Ok(vec![AttachmentCheck::Matches(Some("righe.txt".to_owned()))])
    );
}
