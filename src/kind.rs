//! The kinds of message a PEC provider generates.

use serde::{Deserialize, Serialize};

/// The kind of a certified message, the `tipo` of `daticert.xml` (§7.4).
///
/// Every kind but [`Kind::Transport`] is a receipt or notice named by `X-Ricevuta`. The transport envelope is named
/// by `X-Trasporto: posta-certificata`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Kind {
    /// `accettazione`: the sender's provider accepted the message (§6.3.3).
    #[serde(rename = "accettazione")]
    Acceptance,
    /// `non-accettazione`: the sender's provider refused the message, for a formal error or a virus (§6.3.2,
    /// §6.4.3.1).
    #[serde(rename = "non-accettazione")]
    NonAcceptance,
    /// `presa-in-carico`: the recipient's provider took the message over from the sender's (§6.4.1).
    #[serde(rename = "presa-in-carico")]
    TakenInCharge,
    /// `avvenuta-consegna`: the message reached the recipient's mailbox (§6.5.2).
    #[serde(rename = "avvenuta-consegna")]
    Delivery,
    /// `posta-certificata`: the transport envelope carrying the original message (§6.3.4).
    #[serde(rename = "posta-certificata")]
    Transport,
    /// `errore-consegna`: the message could not be delivered, for an error or a virus (§6.5.3, §6.4.3.3).
    #[serde(rename = "errore-consegna")]
    DeliveryError,
    /// `preavviso-errore-consegna`: no delivery receipt arrived within 12 or 24 hours (§6.3.5).
    #[serde(rename = "preavviso-errore-consegna")]
    DeliveryTimeoutWarning,
    /// `rilevazione-virus`: the recipient's provider found a virus, sent to the sender's provider (§6.4.3.2).
    #[serde(rename = "rilevazione-virus")]
    VirusDetected,
}

impl Kind {
    /// The value of `X-Ricevuta`, or of `X-Trasporto` for [`Kind::Transport`], and of the `tipo` attribute.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acceptance => "accettazione",
            Self::NonAcceptance => "non-accettazione",
            Self::TakenInCharge => "presa-in-carico",
            Self::Delivery => "avvenuta-consegna",
            Self::Transport => "posta-certificata",
            Self::DeliveryError => "errore-consegna",
            Self::DeliveryTimeoutWarning => "preavviso-errore-consegna",
            Self::VirusDetected => "rilevazione-virus",
        }
    }

    /// The receipt kind an `X-Ricevuta` value names. `posta-certificata` is not one, it travels in `X-Trasporto`.
    pub(crate) fn from_receipt_header(value: &str) -> Option<Self> {
        Some(match value {
            "accettazione" => Self::Acceptance,
            "non-accettazione" => Self::NonAcceptance,
            "presa-in-carico" => Self::TakenInCharge,
            "avvenuta-consegna" => Self::Delivery,
            "errore-consegna" => Self::DeliveryError,
            "preavviso-errore-consegna" => Self::DeliveryTimeoutWarning,
            "rilevazione-virus" => Self::VirusDetected,
            _ => return None,
        })
    }
}

/// What a message is, read from `X-Ricevuta` or `X-Trasporto`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// A receipt, a notice or a transport envelope, each carrying certification data.
    Certified(Kind),
    /// `X-Trasporto: errore`: a message that arrived without being valid PEC, wrapped by the recipient's provider
    /// with no certification data (§6.4.2).
    Anomaly,
}
