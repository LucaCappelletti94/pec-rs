#![doc = include_str!("../README.md")]

mod attachment_hash;
pub mod certification;
mod error;
mod kind;
pub mod message;
mod message_id;

pub use attachment_hash::AttachmentHash;
pub use certification::{
    CertificationData, CertifiedAt, Data, ErrorCode, Header, ReceiptKind, Recipient, RecipientKind,
};
pub use error::Error;
pub use kind::{Kind, MessageKind};
pub use message::Message;
pub use message_id::MessageId;
