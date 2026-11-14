//! Message identifiers, read the same way from headers and from `daticert.xml`.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

/// A message identifier, the `msg-id` of RFC 5322 §3.6.4, held without its angle brackets.
///
/// PEC carries the same identifier in several places: a message's `Message-ID`, the `X-Riferimento-Message-ID` of
/// the receipts and envelopes for it, and the `msgid` and `identificativo` of `daticert.xml` (§6.3, §7.4). Some write
/// it between angle brackets and some without, so reading accepts both and compares the identifier itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(String);

impl MessageId {
    /// The identifier without angle brackets, `id-left@id-right`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for MessageId {
    type Err = Error;

    /// Reads an identifier with or without its angle brackets, ignoring surrounding whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessageId`] when the brackets are unbalanced, or when the identifier holds whitespace,
    /// a control character or a bracket, none of which RFC 5322 §3.6.4 allows, or lacks an `@` with text on both sides.
    fn from_str(value: &str) -> Result<Self, Error> {
        let trimmed = value.trim();
        let inner = match (trimmed.strip_prefix('<'), trimmed.ends_with('>')) {
            (Some(rest), true) => rest.strip_suffix('>').unwrap_or(rest),
            (None, false) => trimmed,
            _ => return Err(Error::InvalidMessageId(value.to_owned())),
        };
        let valid = inner
            .split_once('@')
            .is_some_and(|(left, right)| !left.is_empty() && !right.is_empty())
            && !inner
                .contains(|c: char| c.is_whitespace() || c.is_control() || c == '<' || c == '>');
        if valid {
            Ok(Self(inner.to_owned()))
        } else {
            Err(Error::InvalidMessageId(value.to_owned()))
        }
    }
}

impl fmt::Display for MessageId {
    /// Writes the identifier between angle brackets, as a `Message-ID` header carries it.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<{}>", self.0)
    }
}

impl Serialize for MessageId {
    /// Writes the identifier without angle brackets, the form of `identificativo`.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MessageId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Writes an optional identifier between angle brackets, the form providers give `msgid`.
#[expect(
    clippy::ref_option,
    reason = "serde's `serialize_with` passes the field by reference"
)]
pub(crate) fn serialize_bracketed<S: Serializer>(
    id: &Option<MessageId>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    id.as_ref().map(Bracketed).serialize(serializer)
}

/// An identifier written between angle brackets.
struct Bracketed<'a>(&'a MessageId);

impl Serialize for Bracketed<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self.0)
    }
}
