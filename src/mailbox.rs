//! Comparing and validating mailbox addresses.

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
fn is_atext(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
}
