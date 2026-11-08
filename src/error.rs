//! The errors of reading PEC certification data.

/// Why a `daticert.xml` could not be read as PEC.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The `daticert.xml` does not follow the DTD of §7.4.
    #[error("invalid daticert.xml: {0}")]
    CertificationData(String),
}
