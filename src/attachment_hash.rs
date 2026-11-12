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

/// The line ends a provider may have hashed a text attachment or an attached message with (§6.5.2.2).
///
/// The rules hash "the whole content of the attachment" without naming a form. MIME's canonical form of text ends
/// lines with CRLF (RFC 2049 §4), which Aruba hashes, while OpenPEC hashes text and attached messages with the LF
/// line ends it writes to disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextLineEnds {
    /// Only the canonical CRLF form.
    Canonical,
    /// The canonical form, or the same text or message with LF line ends.
    CanonicalOrLf,
}

/// Identifies generated hashes using the sent message, preserving receipt order.
pub(crate) fn read(
    original: MessageRef<'_>,
    sent: &[u8],
    line_ends: TextLineEnds,
) -> Result<Vec<AttachmentHash>, Error> {
    let parsed = MessageParser::default().parse(sent).ok_or(Error::NotMime)?;
    let comparison = Comparison::new(original, parsed.root(), line_ends)?;
    Ok(comparison
        .candidates
        .iter()
        .filter(|candidate| !candidate.carried)
        .filter_map(|candidate| {
            Some(AttachmentHash {
                name: candidate.hash_name()?.to_owned(),
                sha1: candidate.hash?,
            })
        })
        .collect())
}

/// The file name a `.hash` part stands for, `None` when `file` names no hash.
fn replaced_name(file: &str) -> Option<&str> {
    file.strip_suffix(".hash")
}

/// Compares sent attachments with receipt evidence, followed by unpaired receipt parts.
pub(crate) fn check(
    original: MessageRef<'_>,
    sent: &[u8],
    line_ends: TextLineEnds,
) -> Result<Vec<AttachmentCheck>, Error> {
    let parsed = MessageParser::default().parse(sent).ok_or(Error::NotMime)?;
    let comparison = Comparison::new(original, parsed.root(), line_ends)?;
    let mut checks = Vec::with_capacity(
        comparison.outgoing.len()
            + comparison
                .candidates
                .iter()
                .filter(|candidate| !candidate.paired)
                .count(),
    );
    checks.extend(
        comparison
            .outgoing
            .iter()
            .zip(comparison.pairs)
            .map(|(attachment, pair)| match pair {
                Some(Pair {
                    changed_name: Some(name),
                    ..
                }) => AttachmentCheck::Differs(name.to_owned()),
                Some(pair) => {
                    comparison.candidates[pair.candidate].found(attachment.name.map(str::to_owned))
                }
                None => AttachmentCheck::Missing(attachment.name.map(str::to_owned)),
            }),
    );
    checks.extend(
        comparison
            .candidates
            .iter()
            .filter(|candidate| !candidate.paired)
            .map(|candidate| AttachmentCheck::NotSent(candidate.name().map(str::to_owned))),
    );
    Ok(checks)
}

/// A one-to-one interpretation of receipt parts against sent attachments.
struct Comparison<'r, 's> {
    /// Attachments in sent order.
    outgoing: Vec<Attachment<'s>>,
    /// Evidence in receipt order.
    candidates: Vec<Candidate<'r>>,
    /// The evidence assigned to each sent attachment.
    pairs: Vec<Option<Pair<'s>>>,
}

impl<'r, 's> Comparison<'r, 's> {
    /// Resolves exact named matches before name-only differences and renamed content.
    fn new(
        original: MessageRef<'r>,
        sent: MessageRef<'s>,
        line_ends: TextLineEnds,
    ) -> Result<Self, Error> {
        let outgoing = attachments(sent, line_ends);
        let mut candidates: Vec<_> = replaceable(original).map(Candidate::new).collect();
        let mut pairs = vec![None; outgoing.len()];
        pair(
            &outgoing,
            &mut candidates,
            &mut pairs,
            true,
            |sent, candidate| {
                sent.name.is_some() && sent.name == candidate.file && sent.sha1 == candidate.sha1
            },
        );
        pair(
            &outgoing,
            &mut candidates,
            &mut pairs,
            false,
            |sent, candidate| {
                sent.name.is_some()
                    && sent.name == candidate.hash_name()
                    && candidate.hash.is_some_and(|hash| sent.has(&hash))
            },
        );
        pair(
            &outgoing,
            &mut candidates,
            &mut pairs,
            true,
            |sent, candidate| sent.name.is_some() && sent.name == candidate.file,
        );
        pair(
            &outgoing,
            &mut candidates,
            &mut pairs,
            false,
            |sent, candidate| sent.name.is_some() && sent.name == candidate.hash_name(),
        );
        pair(
            &outgoing,
            &mut candidates,
            &mut pairs,
            false,
            |sent, candidate| candidate.hash.is_some_and(|hash| sent.has(&hash)),
        );
        pair(
            &outgoing,
            &mut candidates,
            &mut pairs,
            true,
            |sent, candidate| sent.sha1 == candidate.sha1,
        );
        for candidate in &mut candidates {
            if !candidate.paired && !candidate.carried {
                candidate.carried = outgoing
                    .iter()
                    .any(|sent| sent.name.is_some() && sent.name == candidate.file);
            }
            if let Some(file) = candidate.file
                && !candidate.carried
                && candidate.hash.is_none()
            {
                return Err(Error::InvalidAttachmentHash(file.to_owned()));
            }
        }
        Ok(Self {
            outgoing,
            candidates,
            pairs,
        })
    }
}

/// Receipt evidence assigned to one sent attachment.
#[derive(Clone, Copy)]
struct Pair<'a> {
    /// The receipt candidate's index.
    candidate: usize,
    /// The shared filename when the content differs.
    changed_name: Option<&'a str>,
}

/// Assigns unpaired candidates satisfying one comparison phase.
fn pair<'s>(
    outgoing: &[Attachment<'s>],
    candidates: &mut [Candidate<'_>],
    pairs: &mut [Option<Pair<'s>>],
    carried: bool,
    matches: impl Fn(&Attachment<'s>, &Candidate<'_>) -> bool,
) {
    for (sent, pair) in outgoing.iter().zip(pairs) {
        if pair.is_some() {
            continue;
        }
        if let Some((index, candidate)) = candidates
            .iter_mut()
            .enumerate()
            .find(|(_, candidate)| !candidate.paired && matches(sent, candidate))
        {
            candidate.paired = true;
            candidate.carried = carried;
            let equal = if carried {
                sent.sha1 == candidate.sha1
            } else {
                candidate.hash.is_some_and(|hash| sent.has(&hash))
            };
            *pair = Some(Pair {
                candidate: index,
                changed_name: sent.name.filter(|_| !equal),
            });
        }
    }
}

/// A receipt attachment with both its carried bytes and possible generated digest.
struct Candidate<'a> {
    /// The complete filename, including any `.hash` suffix.
    file: Option<&'a str>,
    /// The digest of this part's content.
    sha1: [u8; 20],
    /// A digest written inside a `.hash` part.
    hash: Option<[u8; 20]>,
    /// Whether the part represents carried content.
    carried: bool,
    /// Whether a sent attachment consumed this part.
    paired: bool,
}

impl<'a> Candidate<'a> {
    /// Reads both interpretations without rejecting a user file's contents.
    fn new(part: MessagePart<'a>) -> Self {
        let decoded;
        let content: &[u8] = if part.is_message() {
            part.raw_body()
        } else {
            decoded = part.decoded();
            &decoded
        };
        let file = part.attachment_name();
        let hash_name = file.and_then(replaced_name);
        Self {
            file,
            sha1: Sha1::digest(content).into(),
            hash: hash_name.and_then(|_| digest(content.trim_ascii())),
            carried: hash_name.is_none(),
            paired: false,
        }
    }

    /// The filename a generated hash would replace.
    fn hash_name(&self) -> Option<&'a str> {
        self.file.and_then(replaced_name)
    }

    /// The filename under the resolved interpretation.
    fn name(&self) -> Option<&'a str> {
        if self.carried {
            self.file
        } else {
            self.hash_name()
        }
    }

    /// The successful check for the resolved interpretation.
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
    /// The SHA-1 of the same text or message with LF line ends, when the caller accepts that form and it differs.
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
        .map(|part| {
            let decoded;
            let content: &[u8] = if part.is_message() {
                part.raw_body()
            } else {
                decoded = part.decoded();
                &decoded
            };
            let lf_sha1 = (line_ends == TextLineEnds::CanonicalOrLf
                && (part.is_message() || is_text(&part)))
            .then(|| lf_form(content))
            .flatten()
            .map(|lf| Sha1::digest(lf).into());
            Attachment {
                name: part.attachment_name(),
                sha1: Sha1::digest(content).into(),
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

/// Visits attachments without entering named containers, attached messages or the root signature.
fn replaceable(message: MessageRef<'_>) -> impl Iterator<Item = MessagePart<'_>> {
    let root = message.root_part();
    let content = if root.is_content_type("multipart", "signed") {
        root.children().next()
    } else {
        Some(root)
    };
    let range = content.map(|part| part.offset_header()..part.offset_end());
    let mut after = 0;
    let skip_root = root.is_content_type("application", "pkcs7-mime")
        || root.is_content_type("application", "x-pkcs7-mime");
    message
        .parts()
        .skip(usize::from(skip_root))
        .filter(move |part| {
            let offset = part.offset_header();
            if offset < after || !range.as_ref().is_some_and(|range| range.contains(&offset)) {
                return false;
            }
            if part.attachment_name().is_none() && !part.is_message() {
                return false;
            }
            after = part.offset_end();
            true
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
