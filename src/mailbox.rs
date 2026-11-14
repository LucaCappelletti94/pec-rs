//! Mailboxes an outgoing message names, and comparing and validating their addresses.

use crate::{Error, OutgoingError};

/// A mailbox an outgoing message names, an address with an optional display name (RFC 5322 §3.4).
///
/// The address is a `local@domain` of two dot-atoms, the form the provider accepts for the sender and each recipient
/// (§6.3.1, RFC 5322 §3.4.1).
///
/// ```
/// use postacert::Mailbox;
///
/// let mailbox = Mailbox::named("Mario Rossi", "mario.rossi@pec.example.it")?;
/// assert_eq!(mailbox.name(), Some("Mario Rossi"));
/// assert_eq!(mailbox.address(), "mario.rossi@pec.example.it");
/// # Ok::<(), postacert::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    /// The display name, never empty.
    name: Option<String>,
    /// The `local@domain` address.
    address: String,
}

impl Mailbox {
    /// The mailbox at `address`, with no display name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Outgoing`] with [`OutgoingError::Address`] when `address` is not a `local@domain` of two
    /// dot-atoms.
    pub fn new(address: impl Into<String>) -> Result<Self, Error> {
        let address = address.into();
        if is_dot_atom_address(&address) {
            Ok(Self {
                name: None,
                address,
            })
        } else {
            Err(OutgoingError::Address(address).into())
        }
    }

    /// The mailbox at `address` displayed as `name`, or with no display name when `name` is empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Outgoing`] with [`OutgoingError::DisplayName`] when `name` holds a control character other
    /// than tab, or with [`OutgoingError::Address`] when `address` is not a `local@domain` of two dot-atoms.
    pub fn named(name: impl Into<String>, address: impl Into<String>) -> Result<Self, Error> {
        let name = name.into();
        if has_control(&name) {
            return Err(OutgoingError::DisplayName(name).into());
        }
        let mut mailbox = Self::new(address)?;
        mailbox.name = Some(name).filter(|name| !name.is_empty());
        Ok(mailbox)
    }

    /// The display name, `None` when the mailbox has none.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The `local@domain` address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Whether `text` holds a control character other than tab, which no header field may carry (RFC 5322 §2.2).
pub(crate) fn has_control(text: &str) -> bool {
    text.chars()
        .any(|character| character.is_control() && character != '\t')
}

/// Whether two addresses name the same mailbox, the local part compared exactly and the host without case (RFC 5280
/// §7.5).
pub(crate) fn same_mailbox(left: &str, right: &str) -> bool {
    left.rsplit_once('@')
        .zip(right.rsplit_once('@'))
        .is_some_and(|((left_local, left_host), (right_local, right_host))| {
            left_local == right_local && left_host.eq_ignore_ascii_case(right_host)
        })
}

/// The key a mailbox is compared by, its local part as written and its domain in lower case.
pub(crate) fn mailbox_key(address: &str) -> String {
    let mut key = address.to_owned();
    if let Some((local, _)) = address.rsplit_once('@') {
        key[local.len()..].make_ascii_lowercase();
    }
    key
}

/// Whether `address` is a `local@domain` whose two sides are each a dot-atom (RFC 5322 §3.4.1, §3.2.3).
///
/// A quoted local part or a domain literal is refused, since RFC 5321 §4.1.2 asks mailboxes to avoid quoted local
/// parts and a PEC domain is a name in the provider index (§7.5).
pub(crate) fn is_dot_atom_address(address: &str) -> bool {
    address
        .split_once('@')
        .is_some_and(|(local, domain)| is_dot_atom(local) && is_dot_atom(domain))
}

/// Whether `text` is one or more runs of `atext` joined by single dots (RFC 5322 §3.2.3).
fn is_dot_atom(text: &str) -> bool {
    text.split('.')
        .all(|atom| !atom.is_empty() && atom.bytes().all(is_atext))
}

/// Whether `byte` is an `atext` character (RFC 5322 §3.2.3).
pub(crate) fn is_atext(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
}
