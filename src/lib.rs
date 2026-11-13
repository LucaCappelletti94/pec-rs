#![doc = include_str!("../README.md")]

mod attachment_hash;
pub mod certification;
mod error;
mod kind;
pub mod message;
mod message_id;
mod revocation;
mod signature;
mod trust;

pub use attachment_hash::{AttachmentCheck, AttachmentHash, TextLineEnds};
pub use certification::{
    CertificationData, CertifiedAt, Data, ErrorCode, Header, ReceiptKind, Recipient, RecipientKind,
};
pub use error::Error;
pub use kind::{Kind, MessageKind};
pub use message::Message;
pub use message_id::MessageId;
pub use signature::{ProviderSignature, SignatureError};
pub use trust::{AGID_CA_SMIME_RSA_2026, AGID_CA1, AGID_PROVIDER_CAS};
