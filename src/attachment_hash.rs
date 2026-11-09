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

/// How one attachment of the sent message, or one thing the receipt carries in its place, compares (§6.5.2.2).
///
/// An attachment is paired with what the receipt carries under its file name, and failing that with what holds its
/// SHA-1, since a provider names an attachment without a file name as it sees fit. What the receipt carries is a
/// hash, or the attachment itself when the provider left it in place, as Aruba does for a part named only by its
/// `Content-Type`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AttachmentCheck {
    /// The receipt carries the SHA-1 of this sent attachment, named by its file name when it has one.
    Matches(Option<String>),
    /// The receipt carries this sent attachment itself, unchanged, named by its file name when it has one.
    Carried(Option<String>),
    /// The receipt carries a hash or an attachment under this sent attachment's name, and it is not the same.
    Differs(String),
    /// The receipt carries nothing for this sent attachment, named by its file name when it has one.
    Missing(Option<String>),
    /// The receipt carries this hash or attachment, named as the receipt names it, and no sent attachment is it.
    NotSent(Option<String>),
}

/// The line ends a provider may have hashed a text attachment with (§6.5.2.2).
///
/// The rules hash "the whole content of the attachment" without naming a form. MIME's canonical form of text ends
/// lines with CRLF (RFC 2049 §4), which Aruba hashes, while OpenPEC hashes the text with the LF line ends it writes
/// to disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextLineEnds {
    /// Only the canonical CRLF form.
    Canonical,
    /// The canonical form, or the same text with LF line ends.
    CanonicalOrLf,
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
        let Some(name) = replaced_name(file) else {
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

/// The file name a `.hash` part stands for, `None` when `file` names no hash.
fn replaced_name(file: &str) -> Option<&str> {
    file.strip_suffix(".hash")
}

/// Checks a short delivery receipt against the attachments of the message the sender sent: the parts with a file
/// name and the attached messages, hashed as the provider hashes them.
///
/// Each is paired with a hash of the receipt or with an attachment its `original` still carries. The checks follow
/// the order of the sent attachments, then list what the receipt carries for no sent attachment.
pub(crate) fn check(
    hashes: &[AttachmentHash],
    original: MessageRef<'_>,
    sent: &[u8],
    line_ends: TextLineEnds,
) -> Result<Vec<AttachmentCheck>, Error> {
    let parsed = MessageParser::default().parse(sent).ok_or(Error::NotMime)?;
    let outgoing = attachments(parsed.root(), line_ends);
    let candidates: Vec<Candidate<'_>> = hashes
        .iter()
        .map(|hash| Candidate {
            name: Some(&hash.name),
            sha1: hash.sha1,
            carried: false,
        })
        .chain(
            attachments(original, TextLineEnds::Canonical)
                .into_iter()
                .filter(|attachment| attachment.name.and_then(replaced_name).is_none())
                .map(|attachment| Candidate {
                    name: attachment.name,
                    sha1: attachment.sha1,
                    carried: true,
                }),
        )
        .collect();
    let mut paired = vec![false; candidates.len()];
    let mut take = |found: &dyn Fn(&Candidate<'_>) -> bool| {
        let index =
            (0..candidates.len()).find(|&index| !paired[index] && found(&candidates[index]))?;
        paired[index] = true;
        Some(&candidates[index])
    };
    let by_name: Vec<Option<AttachmentCheck>> = outgoing
        .iter()
        .map(|attachment| {
            let name = attachment.name?;
            let candidate = take(&|candidate| candidate.name == Some(name))?;
            Some(if attachment.has(&candidate.sha1) {
                candidate.found(Some(name.to_owned()))
            } else {
                AttachmentCheck::Differs(name.to_owned())
            })
        })
        .collect();
    let mut checks: Vec<AttachmentCheck> = outgoing
        .iter()
        .zip(by_name)
        .map(|(attachment, check)| {
            check.unwrap_or_else(|| {
                let name = attachment.name.map(str::to_owned);
                match take(&|candidate| attachment.has(&candidate.sha1)) {
                    Some(candidate) => candidate.found(name),
                    None => AttachmentCheck::Missing(name),
                }
            })
        })
        .collect();
    checks.extend(
        candidates
            .iter()
            .zip(paired)
            .filter(|&(_, paired)| !paired)
            .map(|(candidate, _)| AttachmentCheck::NotSent(candidate.name.map(str::to_owned))),
    );
    Ok(checks)
}

/// Something a short receipt's original carries for an attachment: its hash, or the attachment itself.
struct Candidate<'a> {
    /// The file name, without `.hash` for a hash.
    name: Option<&'a str>,
    /// The SHA-1 the hash holds, or that of the carried attachment.
    sha1: [u8; 20],
    /// Whether this is the attachment itself.
    carried: bool,
}

impl Candidate<'_> {
    /// The check of a sent attachment, named `name`, that this candidate stands for.
    const fn found(&self, name: Option<String>) -> AttachmentCheck {
        if self.carried {
            AttachmentCheck::Carried(name)
        } else {
            AttachmentCheck::Matches(name)
        }
    }
}

/// An attachment as a provider finds it, with the SHA-1 a provider gives it.
struct Attachment<'a> {
    /// The file name, when the part has one.
    name: Option<&'a str>,
    /// The SHA-1 of the transfer-decoded content, or of the bytes as sent for an attached message.
    sha1: [u8; 20],
    /// The SHA-1 of the same text with LF line ends, when the caller accepts that form and it differs.
    lf_sha1: Option<[u8; 20]>,
}

impl Attachment<'_> {
    /// Whether `sha1` is a digest a provider may have given this attachment.
    fn has(&self, sha1: &[u8; 20]) -> bool {
        self.sha1 == *sha1 || self.lf_sha1.as_ref() == Some(sha1)
    }
}

/// The attachments of a message as a provider finds them: the parts with a file name and the attached messages.
fn attachments(message: MessageRef<'_>, line_ends: TextLineEnds) -> Vec<Attachment<'_>> {
    replaceable(message)
        .filter(|part| part.attachment_name().is_some() || part.is_message())
        .map(|part| {
            if part.is_message() {
                return Attachment {
                    name: part.attachment_name(),
                    sha1: Sha1::digest(part.raw_body()).into(),
                    lf_sha1: None,
                };
            }
            let decoded = part.decoded();
            let lf_sha1 = (line_ends == TextLineEnds::CanonicalOrLf && is_text(&part))
                .then(|| lf_form(&decoded))
                .flatten()
                .map(|text| Sha1::digest(text).into());
            Attachment {
                name: part.attachment_name(),
                sha1: Sha1::digest(&decoded).into(),
                lf_sha1,
            }
        })
        .collect()
}

/// Whether the part is text, `text/*` or without a `Content-Type`, which RFC 2045 §5.2 makes `text/plain`.
fn is_text(part: &MessagePart<'_>) -> bool {
    part.content_type()
        .is_none_or(|content_type| content_type.ctype().eq_ignore_ascii_case("text"))
}

/// `text` with every CRLF turned into LF, `None` when it holds no CRLF.
fn lf_form(text: &[u8]) -> Option<Vec<u8>> {
    if !text.windows(2).any(|pair| pair == b"\r\n") {
        return None;
    }
    let mut lf = Vec::with_capacity(text.len());
    let mut bytes = text.iter().peekable();
    while let Some(&byte) = bytes.next() {
        if byte != b'\r' || bytes.peek() != Some(&&b'\n') {
            lf.push(byte);
        }
    }
    Some(lf)
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
