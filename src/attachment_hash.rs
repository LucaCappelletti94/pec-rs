//! The SHA-1 a short delivery receipt carries in place of each attachment of the original message, and checking it
//! against the message the sender sent, §6.5.2.2.

use mail_parser::{MessageParser, MessagePart, MessageRef};
use sha1::{Digest, Sha1};

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

/// How one attachment of the sent message, or one hash of a short delivery receipt, compares (§6.5.2.2).
///
/// An attachment is paired with the hash under its file name, and failing that with a hash holding its SHA-1,
/// since a provider names an attachment without a file name as it sees fit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AttachmentCheck {
    /// The receipt carries the SHA-1 of this sent attachment, named by its file name when it has one.
    Matches(Option<String>),
    /// The receipt carries a hash under this sent attachment's name, and it is not the attachment's SHA-1.
    Differs(String),
    /// The receipt carries no hash for this sent attachment, named by its file name when it has one.
    Missing(Option<String>),
    /// The receipt carries this hash, named as the receipt names it, and no sent attachment has it.
    NotSent(String),
}

/// Reads the `.hash` parts of the original message a short delivery receipt carries, in order.
///
/// They replace the top-level parts of the original, or those of the signed part of a `multipart/signed`
/// original. An `application/pkcs7-mime` original is a single part and carries none.
pub(crate) fn read(original: MessageRef<'_>) -> Result<Vec<AttachmentHash>, Error> {
    let mut hashes = Vec::new();
    for part in replaceable(original) {
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

/// Checks the hashes of a short delivery receipt against the attachments of the message the sender sent: the parts
/// with a file name and the attached messages, hashed as the provider hashes them.
///
/// The checks follow the order of the sent attachments, then the hashes no sent attachment has.
pub(crate) fn check(hashes: &[AttachmentHash], sent: &[u8]) -> Result<Vec<AttachmentCheck>, Error> {
    let parsed = MessageParser::default().parse(sent).ok_or(Error::NotMime)?;
    let attachments: Vec<(Option<&str>, [u8; 20])> = replaceable(parsed.root())
        .filter(|part| part.attachment_name().is_some() || part.is_message())
        .map(|part| {
            let sha1 = if part.is_message() {
                Sha1::digest(part.raw_body())
            } else {
                Sha1::digest(part.decoded())
            };
            (part.attachment_name(), sha1.into())
        })
        .collect();
    let mut paired = vec![false; hashes.len()];
    let mut take = |found: &dyn Fn(&AttachmentHash) -> bool| {
        let index = (0..hashes.len()).find(|&index| !paired[index] && found(&hashes[index]))?;
        paired[index] = true;
        Some(&hashes[index])
    };
    let by_name: Vec<Option<AttachmentCheck>> = attachments
        .iter()
        .map(|&(name, sha1)| {
            let name = name?;
            let hash = take(&|hash| hash.name == name)?;
            Some(if hash.sha1 == sha1 {
                AttachmentCheck::Matches(Some(name.to_owned()))
            } else {
                AttachmentCheck::Differs(name.to_owned())
            })
        })
        .collect();
    let mut checks: Vec<AttachmentCheck> = attachments
        .iter()
        .zip(by_name)
        .map(|(&(name, sha1), check)| {
            check.unwrap_or_else(|| {
                let name = name.map(str::to_owned);
                if take(&|hash| hash.sha1 == sha1).is_some() {
                    AttachmentCheck::Matches(name)
                } else {
                    AttachmentCheck::Missing(name)
                }
            })
        })
        .collect();
    checks.extend(
        hashes
            .iter()
            .zip(paired)
            .filter(|&(_, paired)| !paired)
            .map(|(hash, _)| AttachmentCheck::NotSent(hash.name.clone())),
    );
    Ok(checks)
}

/// The parts a provider may replace with their hash: the top-level parts, or those of the signed part of a
/// `multipart/signed` message. An `application/pkcs7-mime` message is a single part and has none.
fn replaceable(message: MessageRef<'_>) -> impl Iterator<Item = MessagePart<'_>> {
    let root = message.root_part();
    let content = if root.is_content_type("multipart", "signed") {
        root.children().next()
    } else {
        Some(root)
    };
    content.into_iter().flat_map(|part| part.children())
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
