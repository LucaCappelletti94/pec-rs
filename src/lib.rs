#![doc = include_str!("../README.md")]

extern crate alloc;

mod attachment_hash;
pub mod certification;
mod delivery;
mod error;
mod kind;
mod mailbox;
pub mod message;
mod message_id;
mod outgoing;
mod revocation;
mod signature;
mod trust;

pub use attachment_hash::{AttachmentCheck, AttachmentHash, TextLineEnds};
pub use certification::{
    CertificationData, CertifiedAt, Data, ErrorCode, Header, ReceiptKind, Recipient, RecipientKind,
};
pub use delivery::{Delivery, Recorded, Status};
pub use error::Error;
pub use kind::{Kind, MessageKind};
pub use mailbox::Mailbox;
pub use message::{Message, VerifiedMessage};
pub use message_id::MessageId;
pub use outgoing::{Limits, OutgoingError, OutgoingMessage, OutgoingMessageBuilder};
pub use signature::{ProviderSignature, SignatureError};
pub use trust::{AGID_CA_SMIME_RSA_2026, AGID_CA1, AGID_PROVIDER_CAS};
