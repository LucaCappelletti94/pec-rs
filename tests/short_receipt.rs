//! Short delivery receipts, whose original carries a SHA-1 in place of each attachment, §6.5.2.2.

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use pec::{Error, Message};

/// Reads a signed message fixture.
fn message(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/messages/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists")
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
