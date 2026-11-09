//! The SHA-1 a short delivery receipt carries in place of each attachment of the original message, §6.5.2.2.

use mail_parser::{MessagePart, MessageRef};

use crate::Error;

/// An attachment of the original message that a short delivery receipt replaced with its SHA-1 (§6.5.2.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttachmentHash {
    /// The file name of the `.hash` part without that suffix.
    name: String,
    /// The digest the `.hash` part holds.
    sha1: [u8; 20],
}

impl AttachmentHash {
    /// The file name of the replaced attachment. A provider names an attachment that has none as it sees fit,
    /// and Aruba writes `null`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The SHA-1 (RFC 3174) of the attachment's transfer-decoded content, or of the bytes of an attached message
    /// as they were sent.
    #[must_use]
    pub const fn sha1(&self) -> &[u8; 20] {
        &self.sha1
    }
}

/// Reads the `.hash` parts of the original message a short delivery receipt carries, in order.
///
/// They replace the top-level parts of the original, or those of the signed part of a `multipart/signed`
/// original. An `application/pkcs7-mime` original is a single part and carries none.
pub(crate) fn read(original: MessageRef<'_>) -> Result<Vec<AttachmentHash>, Error> {
    let root = original.root_part();
    let content = if is_signed(&root) {
        root.children().next()
    } else {
        Some(root)
    };
    let mut hashes = Vec::new();
    for part in content.iter().flat_map(MessagePart::children) {
        let Some(file) = part.attachment_name() else {
            continue;
        };
        let Some(name) = file.strip_suffix(".hash") else {
            continue;
        };
        let sha1 = digest(part.decoded().trim_ascii())
            .ok_or_else(|| Error::InvalidAttachmentHash(file.to_owned()))?;
        hashes.push(AttachmentHash {
            name: name.to_owned(),
            sha1,
        });
    }
    Ok(hashes)
}

/// Whether the part is `multipart/signed`.
fn is_signed(part: &MessagePart<'_>) -> bool {
    part.content_type().is_some_and(|content_type| {
        content_type.ctype().eq_ignore_ascii_case("multipart")
            && content_type
                .subtype()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("signed"))
    })
}

/// The 20 bytes written as exactly 40 hexadecimal digits of either case.
fn digest(hex: &[u8]) -> Option<[u8; 20]> {
    let (pairs, []) = hex.as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != 20 {
        return None;
    }
    let mut sha1 = [0; 20];
    for (byte, [high, low]) in sha1.iter_mut().zip(pairs) {
        *byte = nibble(*high)? << 4 | nibble(*low)?;
    }
    Some(sha1)
}

/// The value of one hexadecimal digit.
const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}
