#![doc = include_str!("../README.md")]

pub mod certification;
mod error;
mod kind;
pub mod message;

pub use certification::{
    CertificationData, CertifiedAt, Data, ErrorCode, Header, ReceiptKind, Recipient, RecipientKind,
};
pub use error::Error;
pub use kind::{Kind, MessageKind};
pub use message::Message;
