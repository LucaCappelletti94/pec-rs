//! Writing the header fields and the body of an outgoing message (RFC 5322 §2.1.1 and §3, RFC 2045 §6.7, RFC 2046
//! §5.1, RFC 2047).

use base64ct::{Base64, Encoding};
use jiff::Zoned;
use sha2::{Digest, Sha256};

use crate::mailbox::is_atext;
use crate::{Mailbox, MessageId, OutgoingError};

/// The column a field folds before, as RFC 5322 §2.1.1 asks.
const FOLD: usize = 78;
/// The longest line, CRLF excluded, that RFC 5322 §2.1.1 allows and SMTP carries (RFC 5321 §4.5.3.1.6).
const LONGEST_LINE: usize = 998;
/// The longest word written as it is, so that it fits one line with the space before it.
const LONGEST_PLAIN_WORD: usize = FOLD - 2;
/// The most UTF-8 bytes one encoded word carries, 60 base64 characters, so the word stays within 75 (RFC 2047 §2).
const ENCODED_WORD_BYTES: usize = 45;
/// The longest quoted-printable line, CRLF excluded (RFC 2045 §6.7 rule 5).
const QUOTED_PRINTABLE_LINE: usize = 76;
/// The longest base64 line, CRLF excluded (RFC 2045 §6.8).
const BASE64_LINE: usize = 76;
/// The characters of a token besides letters and digits, every printable ASCII character but the tspecials (RFC 2045
/// §5.1).
const TOKEN_PUNCTUATION: &[u8] = b"!#$%&'*+-.^_`{|}~";
/// The characters RFC 2231 §7 writes as they are in a parameter value besides letters and digits, those of a token but
/// `*`, `'` and `%`.
const ATTRIBUTE_PUNCTUATION: &[u8] = b"!#$&+-.^_`{|}~";
/// The digits quoted-printable writes an octet with (RFC 2045 §6.7 rule 1).
const HEX: &[u8; 16] = b"0123456789ABCDEF";
/// Day names as RFC 5322 §3.3 writes them, from Monday.
const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
/// Month names as RFC 5322 §3.3 writes them, from January.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
/// The years mail-parser reads a `Date` field with, so that a built message passes
/// [`prepare`](crate::OutgoingMessage::prepare).
const YEARS: core::ops::RangeInclusive<i16> = 1900..=3000;
/// Seconds in a day, the first zone offset a `Date` field cannot hold (RFC 5322 §3.3).
const DAY_SECONDS: u32 = 86_400;

/// Writes the field `name` holding `words`, each after one space, folding before a word that would pass column 78.
pub(super) fn field(
    out: &mut Vec<u8>,
    name: &'static str,
    words: &[String],
) -> Result<(), OutgoingError> {
    out.extend_from_slice(name.as_bytes());
    out.push(b':');
    let mut column = name.len() + 1;
    for word in words {
        if column + 1 + word.len() > FOLD {
            out.extend_from_slice(b"\r\n");
            column = 0;
        }
        out.push(b' ');
        out.extend_from_slice(word.as_bytes());
        column += 1 + word.len();
        if column > LONGEST_LINE {
            return Err(OutgoingError::LineTooLong(name));
        }
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// Writes the field `name` holding `value`, a short fixed value that needs no folding.
pub(super) fn fixed_field(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// The words of a mailbox list, each mailbox but the last followed by a comma (RFC 5322 §3.4).
pub(super) fn mailboxes<'a>(list: impl IntoIterator<Item = &'a Mailbox>) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    for mailbox in list {
        if let Some(last) = words.last_mut() {
            last.push(',');
        }
        match mailbox.name() {
            Some(name) => {
                words.extend(phrase(name));
                words.push(format!("<{}>", mailbox.address()));
            }
            None => words.push(mailbox.address().to_owned()),
        }
    }
    words
}

/// The words of a list of message identifiers, each between angle brackets (RFC 5322 §3.6.4).
///
/// # Errors
///
/// Returns [`OutgoingError::Identifier`] when an identifier holds a character outside ASCII.
pub(super) fn identifiers<'a>(
    ids: impl IntoIterator<Item = &'a MessageId>,
) -> Result<Vec<String>, OutgoingError> {
    ids.into_iter()
        .map(|id| {
            if id.as_str().is_ascii() {
                Ok(id.to_string())
            } else {
                Err(OutgoingError::Identifier(id.as_str().to_owned()))
            }
        })
        .collect()
}

/// The words of a display name: atoms when it is atoms and single spaces, a quoted string when it is other
/// printable ASCII, and encoded words otherwise (RFC 5322 §3.2.5, RFC 2047 §5).
fn phrase(name: &str) -> Vec<String> {
    if is_plain(name, is_atext) {
        name.split(' ').map(str::to_owned).collect()
    } else if is_plain(name, |byte| byte.is_ascii_graphic()) && name.len() + 2 <= LONGEST_PLAIN_WORD
    {
        let mut quoted = String::with_capacity(name.len() + 2);
        quoted.push('"');
        for character in name.chars() {
            if matches!(character, '"' | '\\') {
                quoted.push('\\');
            }
            quoted.push(character);
        }
        quoted.push('"');
        vec![quoted]
    } else {
        encoded_words(name)
    }
}

/// The words of unstructured text such as a subject: the text itself when it is printable ASCII and single spaces,
/// and encoded words otherwise (RFC 5322 §3.2.5, RFC 2047 §5).
pub(super) fn unstructured(text: &str) -> Vec<String> {
    if is_plain(text, |byte| byte.is_ascii_graphic()) {
        text.split(' ').map(str::to_owned).collect()
    } else {
        encoded_words(text)
    }
}

/// Whether `text` reads back as written when written as it is: words of `allowed` bytes, each short enough for one
/// line, joined by single spaces, and nothing a reader would decode as an encoded word.
fn is_plain(text: &str, allowed: impl Fn(u8) -> bool) -> bool {
    !text.contains("=?")
        && text.split(' ').all(|word| {
            !word.is_empty() && word.len() <= LONGEST_PLAIN_WORD && word.bytes().all(&allowed)
        })
}

/// `text` as UTF-8 base64 encoded words of at most 75 characters, split between characters (RFC 2047 §2, §5).
fn encoded_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut start = 0;
    for (index, character) in text.char_indices() {
        if index + character.len_utf8() - start > ENCODED_WORD_BYTES {
            words.push(encoded_word(&text[start..index]));
            start = index;
        }
    }
    if start < text.len() {
        words.push(encoded_word(&text[start..]));
    }
    words
}

/// One UTF-8 base64 encoded word (RFC 2047 §2, §4.1).
fn encoded_word(text: &str) -> String {
    format!("=?utf-8?B?{}?=", Base64::encode_string(text.as_bytes()))
}

/// The words of a `Date` field, the local time and the zone offset as RFC 5322 §3.3 writes them.
///
/// The year has to be one mail-parser reads, from 1900 to 3000, and the offset whole minutes under a day, which is all
/// the field holds.
pub(super) fn date(date: &Zoned) -> Result<Vec<String>, OutgoingError> {
    let offset = date.offset().seconds();
    let minutes = offset.unsigned_abs() / 60;
    if !YEARS.contains(&date.year()) || offset % 60 != 0 || offset.unsigned_abs() >= DAY_SECONDS {
        return Err(OutgoingError::Date);
    }
    let time = date.datetime();
    let day = DAYS[usize::from(time.weekday().to_monday_zero_offset().unsigned_abs())];
    let month = MONTHS[usize::from(time.month().unsigned_abs() - 1)];
    Ok(vec![
        format!("{day},"),
        time.day().to_string(),
        month.to_owned(),
        format!("{:04}", time.year()),
        format!(
            "{:02}:{:02}:{:02}",
            time.hour(),
            time.minute(),
            time.second()
        ),
        format!(
            "{}{:02}{:02}",
            if offset < 0 { '-' } else { '+' },
            minutes / 60,
            minutes % 60
        ),
    ])
}

/// Writes the `Content-Type` field `content_type` and the transfer encoding of `text`, a blank line and its body,
/// its line breaks of any form written as CRLF (RFC 2046 §4.1.1).
///
/// The body is 7bit when every line is printable ASCII and tabs, at most 76 columns, and ends in neither, and
/// quoted-printable otherwise, so no line passes 76 columns and none ends in white space a transport could strip.
pub(super) fn text(out: &mut Vec<u8>, content_type: &str, text: &str) {
    let lines = lines(text);
    let seven_bit = lines.iter().all(|line| {
        line.len() <= QUOTED_PRINTABLE_LINE
            && line
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t'))
            && !line.ends_with([' ', '\t'])
    });
    fixed_field(out, "Content-Type", content_type);
    fixed_field(
        out,
        "Content-Transfer-Encoding",
        if seven_bit {
            "7bit"
        } else {
            "quoted-printable"
        },
    );
    out.extend_from_slice(b"\r\n");
    out.reserve(text.len());
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(b"\r\n");
        }
        if seven_bit {
            out.extend_from_slice(line.as_bytes());
        } else {
            quoted_printable(line.as_bytes(), out);
        }
    }
}

/// Writes the `Content-Type` field of the multipart type `media_type` with the boundary of `parts`, a blank line and
/// the parts, each after a delimiter line, then the close delimiter (RFC 2046 §5.1.1). A part outside 7-bit bytes
/// labels the multipart `8bit` (RFC 2045 §6.4).
///
/// The boundary is `=_` and the 64 uppercase hexadecimal digits of the SHA-256 of the parts, so equal parts build
/// equal bytes, and a part holds a delimiter line only by holding the hash of the parts it is among. The boundary
/// parameter takes a line of its own, which it fills to column 78.
pub(super) fn multipart(out: &mut Vec<u8>, media_type: &str, parts: &[Vec<u8>]) {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let mut boundary = [b'_'; 66];
    boundary[0] = b'=';
    let (digits, _) = boundary[2..].as_chunks_mut::<2>();
    for (pair, byte) in digits.iter_mut().zip(hasher.finalize()) {
        *pair = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]];
    }
    out.extend_from_slice(b"Content-Type: ");
    out.extend_from_slice(media_type.as_bytes());
    out.extend_from_slice(b";\r\n boundary=\"");
    out.extend_from_slice(&boundary);
    out.extend_from_slice(b"\"\r\n");
    if !parts.iter().all(|part| part.is_ascii()) {
        fixed_field(out, "Content-Transfer-Encoding", "8bit");
    }
    out.extend_from_slice(b"\r\n");
    for part in parts {
        out.extend_from_slice(b"--");
        out.extend_from_slice(&boundary);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"--");
    out.extend_from_slice(&boundary);
    out.extend_from_slice(b"--");
}

/// Writes the fields of the file `name` holding `bytes` of the type `content_type`, a blank line and the bytes base64
/// in lines of 76 columns (RFC 2045 §6.8, RFC 2183).
///
/// # Errors
///
/// Returns [`OutgoingError::LineTooLong`] when the content type is too long for one line.
pub(super) fn file(
    out: &mut Vec<u8>,
    name: &str,
    content_type: &str,
    bytes: &[u8],
) -> Result<(), OutgoingError> {
    if "Content-Type: ".len() + content_type.len() > LONGEST_LINE {
        return Err(OutgoingError::LineTooLong("Content-Type"));
    }
    fixed_field(out, "Content-Type", content_type);
    fixed_field(out, "Content-Transfer-Encoding", "base64");
    let mut words = filename(name);
    words.insert(0, "attachment;".to_owned());
    field(out, "Content-Disposition", &words)?;
    out.extend_from_slice(b"\r\n");
    let encoded = Base64::encode_string(bytes);
    for (index, line) in encoded.as_bytes().chunks(BASE64_LINE).enumerate() {
        if index > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(line);
    }
    Ok(())
}

/// Writes the fields of the attached message `raw`, a blank line and the message as given (RFC 2046 §5.2.1), `8bit`
/// when it holds a byte outside ASCII.
pub(super) fn message(out: &mut Vec<u8>, raw: &[u8]) {
    fixed_field(out, "Content-Type", "message/rfc822");
    fixed_field(
        out,
        "Content-Transfer-Encoding",
        if raw.is_ascii() { "7bit" } else { "8bit" },
    );
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(raw);
}

/// The words of the `filename` parameter of `name` (RFC 2183 §2.3), a quoted string when `name` is printable ASCII and
/// fits one line with the space before it, and UTF-8 percent-encoded sections otherwise, each within one line (RFC
/// 2231 §3, §4).
fn filename(name: &str) -> Vec<String> {
    let escapes = name
        .bytes()
        .filter(|byte| matches!(byte, b'"' | b'\\'))
        .count();
    if name.bytes().all(|byte| matches!(byte, b' '..=b'~'))
        && "filename=\"\"".len() + name.len() + escapes < FOLD
    {
        let mut word = String::with_capacity("filename=\"\"".len() + name.len() + escapes);
        word.push_str("filename=\"");
        for character in name.chars() {
            if matches!(character, '"' | '\\') {
                word.push('\\');
            }
            word.push(character);
        }
        word.push('"');
        return vec![word];
    }
    let mut words = Vec::new();
    let mut word = String::from("filename*0*=utf-8''");
    for byte in name.bytes() {
        let literal = byte.is_ascii_alphanumeric() || ATTRIBUTE_PUNCTUATION.contains(&byte);
        // The section and the `;` after it, when another follows, stay within one line with the space before them.
        if word.len() + if literal { 1 } else { 3 } + ";".len() >= FOLD {
            word.push(';');
            words.push(word);
            word = format!("filename*{}*=", words.len());
        }
        if literal {
            word.push(char::from(byte));
        } else {
            word.push('%');
            word.push(char::from(HEX[usize::from(byte >> 4)]));
            word.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    words.push(word);
    words
}

/// Whether `content_type` is a `type/subtype` of two tokens (RFC 2045 §5.1), neither a `multipart` nor a `message`
/// type, the composite types base64 cannot carry (RFC 2045 §6.4).
pub(super) fn is_discrete(content_type: &str) -> bool {
    content_type.split_once('/').is_some_and(|(kind, subtype)| {
        is_token(kind)
            && is_token(subtype)
            && !kind.eq_ignore_ascii_case("multipart")
            && !kind.eq_ignore_ascii_case("message")
    })
}

/// Whether `text` is a token, letters, digits and the punctuation of [`TOKEN_PUNCTUATION`] (RFC 2045 §5.1).
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(&byte))
}

/// The offset of the first byte that neither 7bit nor 8bit carries in `raw` (RFC 2045 §2.7, §2.8), a NUL, a line feed
/// not after a carriage return, a carriage return not before a line feed, or the octet after the 998th of a line.
pub(super) fn unsendable(raw: &[u8]) -> Option<usize> {
    let mut line_start = 0;
    for (at, &byte) in raw.iter().enumerate() {
        match byte {
            b'\r' if raw.get(at + 1) == Some(&b'\n') => {}
            b'\n' if at.checked_sub(1).and_then(|before| raw.get(before)) == Some(&b'\r') => {
                line_start = at + 1;
            }
            0 | b'\r' | b'\n' => return Some(at),
            _ if at - line_start >= LONGEST_LINE => return Some(at),
            _ => {}
        }
    }
    None
}

/// The lines of `text`, split at CRLF, LF and CR alike.
fn lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(['\r', '\n']) {
        lines.push(&rest[..at]);
        let skip = if rest[at..].starts_with("\r\n") { 2 } else { 1 };
        rest = &rest[at + skip..];
    }
    lines.push(rest);
    lines
}

/// Writes `line` quoted-printable, with soft line breaks keeping every line within 76 columns (RFC 2045 §6.7).
fn quoted_printable(line: &[u8], out: &mut Vec<u8>) {
    let mut column = 0;
    for (index, &byte) in line.iter().enumerate() {
        let literal = (byte.is_ascii_graphic() && byte != b'=')
            || (matches!(byte, b' ' | b'\t') && index + 1 < line.len());
        let width = if literal { 1 } else { 3 };
        if column + width >= QUOTED_PRINTABLE_LINE {
            out.extend_from_slice(b"=\r\n");
            column = 0;
        }
        if literal {
            out.push(byte);
        } else {
            out.extend_from_slice(&[
                b'=',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 0x0f)],
            ]);
        }
        column += width;
    }
}
