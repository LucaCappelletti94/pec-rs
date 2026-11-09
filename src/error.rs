//! The errors of reading a PEC message or its certification data.

use crate::{Kind, MessageKind};

/// Why a message or a `daticert.xml` could not be read as PEC.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input is not a MIME message.
    #[error("the input is not a MIME message")]
    NotMime,
    /// The message carries neither `X-Ricevuta` nor `X-Trasporto`, so no PEC provider generated it.
    #[error("the message carries neither X-Ricevuta nor X-Trasporto")]
    NotPec,
    /// The message carries both `X-Ricevuta` and `X-Trasporto`.
    #[error("the message carries both X-Ricevuta and X-Trasporto")]
    ConflictingKind,
    /// The `X-Ricevuta` or `X-Trasporto` value is not one the rules define.
    #[error("unknown PEC message kind {0:?}")]
    UnknownKind(String),
    /// The subject does not start with the prefix the rules give the message kind.
    #[error("the subject {subject:?} does not start with {expected:?}")]
    SubjectMismatch {
        /// The prefix the kind requires.
        expected: &'static str,
        /// The subject the message carries, empty when it has none.
        subject: String,
    },
    /// `X-VerificaSicurezza` appears on a kind the rules do not give it.
    #[error("X-VerificaSicurezza on a message of kind {0:?}")]
    UnexpectedSecurityHeader(MessageKind),
    /// The header names one kind and `daticert.xml` another.
    #[error("the header says {header:?} and daticert.xml says {data:?}")]
    KindMismatch {
        /// The kind of `X-Ricevuta` or `X-Trasporto`.
        header: Kind,
        /// The `tipo` of `daticert.xml`.
        data: Kind,
    },
    /// A receipt or transport envelope has no `daticert.xml` attachment.
    #[error("the message has no daticert.xml attachment")]
    MissingCertificationData,
    /// A transport or anomaly envelope has no attached message.
    #[error("the envelope has no attached message")]
    MissingOriginal,
    /// The `daticert.xml` does not follow the DTD of §7.4.
    #[error("invalid daticert.xml: {0}")]
    CertificationData(String),
    /// A message identifier is not an RFC 5322 `msg-id`.
    #[error("invalid message identifier {0:?}")]
    InvalidMessageId(String),
}
