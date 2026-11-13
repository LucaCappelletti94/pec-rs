//! Errors from reading PEC data and checking receipt attachments.

use crate::{Kind, MessageKind, OutgoingError, SignatureError};

/// Why PEC data could not be read or a receipt's attachments could not be checked.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input is not MIME or an attachment comparison reached a MIME parser limit.
    #[error("the input is not MIME or a MIME parser limit was reached")]
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
    /// A summary delivery receipt carries an original message, though it carries only `daticert.xml` (§6.5.2.3).
    #[error("the summary delivery receipt carries an original message")]
    OriginalInSummaryReceipt,
    /// A generated hash part identified against the sent message does not hold 40 hexadecimal digits (§6.5.2.2).
    #[error("the part {0:?} does not hold 40 hexadecimal digits")]
    InvalidAttachmentHash(String),
    /// Equally supported assignments disagree on attachment outcomes or receipt interpretations.
    #[error("the receipt attachments have ambiguous interpretations")]
    AmbiguousAttachments,
    /// The message is not a short delivery receipt carrying the original, so it holds no hashes to check (§6.5.2.2).
    #[error("the message is not a short delivery receipt carrying the original")]
    NotShortReceipt,
    /// The `daticert.xml` does not follow the DTD of §7.4.
    #[error("invalid daticert.xml: {0}")]
    CertificationData(String),
    /// A message identifier is not an RFC 5322 `msg-id`.
    #[error("invalid message identifier {0:?}")]
    InvalidMessageId(String),
    /// The message is not a `multipart/signed` S/MIME message, so it carries no provider signature (§6.1).
    #[error("the message is not a multipart/signed S/MIME message")]
    NotSigned,
    /// The provider's signature does not verify (§6.1).
    #[error("invalid provider signature: {0}")]
    Signature(#[from] SignatureError),
    /// A taken-in-charge receipt has no `ricezione`, or a receipt naming one recipient has no `consegna` (§7.4).
    #[error("the {0:?} receipt names no recipient")]
    MissingRecipient(Kind),
    /// The sender's provider would refuse the message at submission, or the message cannot be tracked (§6.3.1).
    #[error("the message would be refused at submission: {0}")]
    Outgoing(#[from] OutgoingError),
}
