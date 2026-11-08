//! Reading a message a PEC provider generated: its kind, its certification data and the message it carries.

use mail_parser::{Headers, MessageParser, PartId};

use crate::{CertificationData, Error, Kind, MessageKind};

/// A receipt, notice or envelope a PEC provider generated, read from its raw bytes.
///
/// The provider's S/MIME signature is not checked here.
#[derive(Debug)]
pub struct Message<'a> {
    /// The parsed MIME tree, which owns any transfer-decoded buffer the original message lives in.
    parsed: mail_parser::Message<'a>,
    /// What the message is.
    kind: MessageKind,
    /// Whether `X-VerificaSicurezza: errore` is present.
    security_error: bool,
    /// The length of the subject prefix the kind requires.
    prefix_len: usize,
    /// The `daticert.xml` attachment, read.
    certification: Option<CertificationData>,
    /// The `message/rfc822` part holding the original or arrived message.
    original: Option<PartId>,
}

impl<'a> Message<'a> {
    /// Reads a message as delivered to a PEC mailbox.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not MIME, when no PEC header names a kind or the header names one the rules do
    /// not define, when the subject lacks the prefix of its kind (§6.3 to §6.5), when `X-VerificaSicurezza`
    /// appears outside the virus notices (§6.4.3), when a certified kind lacks its `daticert.xml` or that file is
    /// invalid or names another kind, and when an envelope lacks the message it wraps.
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        let parsed = MessageParser::default().parse(raw).ok_or(Error::NotMime)?;
        let root = parsed.root();
        let headers = root.headers();
        let kind = kind_of(&headers)?;
        let security_error =
            header_bytes(&headers, "X-VerificaSicurezza").is_some_and(|value| value == b"errore");
        if security_error
            && !matches!(
                kind,
                MessageKind::Certified(Kind::NonAcceptance | Kind::DeliveryError)
            )
        {
            return Err(Error::UnexpectedSecurityHeader(kind));
        }
        let prefix = subject_prefix(kind, security_error);
        let subject = headers.subject().unwrap_or_default();
        if !subject.starts_with(prefix) {
            return Err(Error::SubjectMismatch {
                expected: prefix,
                subject: subject.to_owned(),
            });
        }

        let mut certification_part = None;
        let mut original = None;
        for part in root.parts() {
            if certification_part.is_none() && part.attachment_name() == Some("daticert.xml") {
                certification_part = Some(part);
            } else if original.is_none()
                && part.is_message()
                && (kind == MessageKind::Anomaly || part.attachment_name() == Some("postacert.eml"))
            {
                original = Some(part.id());
            }
        }

        let certification = match kind {
            MessageKind::Anomaly => None,
            MessageKind::Certified(kind) => {
                let part = certification_part.ok_or(Error::MissingCertificationData)?;
                let bytes = part.decoded();
                let xml = std::str::from_utf8(&bytes).map_err(|_| {
                    Error::CertificationData("daticert.xml is not UTF-8".to_owned())
                })?;
                let data = CertificationData::from_xml(xml)?;
                if data.kind != kind {
                    return Err(Error::KindMismatch {
                        header: kind,
                        data: data.kind,
                    });
                }
                Some(data)
            }
        };
        if original.is_none()
            && matches!(
                kind,
                MessageKind::Anomaly | MessageKind::Certified(Kind::Transport)
            )
        {
            return Err(Error::MissingOriginal);
        }
        Ok(Self {
            parsed,
            kind,
            security_error,
            prefix_len: prefix.len(),
            certification,
            original,
        })
    }

    /// What the message is.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    /// Whether the message reports a virus, `X-VerificaSicurezza: errore` (§6.4.3).
    #[must_use]
    pub const fn security_error(&self) -> bool {
        self.security_error
    }

    /// The subject of the original message, without the prefix the provider added.
    #[must_use]
    pub fn subject(&self) -> &str {
        self.parsed
            .root()
            .headers()
            .subject()
            .and_then(|subject| subject.get(self.prefix_len..))
            .unwrap_or_default()
    }

    /// The `Message-ID` of this message, without angle brackets.
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        self.parsed.root().headers().message_id()
    }

    /// The `Message-ID` the sender's client gave the original message before its provider replaced it,
    /// `X-Riferimento-Message-ID`, without angle brackets (§6.3).
    #[must_use]
    pub fn reference_message_id(&self) -> Option<&str> {
        let value = std::str::from_utf8(header_bytes(
            &self.parsed.root().headers(),
            "X-Riferimento-Message-ID",
        )?)
        .ok()?;
        Some(
            value
                .strip_prefix('<')
                .and_then(|id| id.strip_suffix('>'))
                .unwrap_or(value),
        )
    }

    /// The `daticert.xml` of a receipt, notice or transport envelope. An anomaly envelope has none.
    #[must_use]
    pub const fn certification_data(&self) -> Option<&CertificationData> {
        self.certification.as_ref()
    }

    /// The raw bytes of the wrapped message: the original message of a transport envelope or of a full or short
    /// delivery receipt (`postacert.eml`, §7.3.2), or the arrived message of an anomaly envelope.
    #[must_use]
    pub fn original_message(&self) -> Option<&[u8]> {
        let part = self.parsed.part(self.original?)?;
        Some(part.nested()?.raw())
    }
}

/// The kind named by `X-Ricevuta` or `X-Trasporto`.
fn kind_of(headers: &Headers<'_>) -> Result<MessageKind, Error> {
    let unknown = |value: &[u8]| Error::UnknownKind(String::from_utf8_lossy(value).into_owned());
    match (
        header_bytes(headers, "X-Ricevuta"),
        header_bytes(headers, "X-Trasporto"),
    ) {
        (None, None) => Err(Error::NotPec),
        (Some(_), Some(_)) => Err(Error::ConflictingKind),
        (Some(value), None) => Kind::from_receipt_header(value)
            .map(MessageKind::Certified)
            .ok_or_else(|| unknown(value)),
        (None, Some(b"posta-certificata")) => Ok(MessageKind::Certified(Kind::Transport)),
        (None, Some(b"errore")) => Ok(MessageKind::Anomaly),
        (None, Some(value)) => Err(unknown(value)),
    }
}

/// The value of the first `name` header without surrounding whitespace, `None` when absent.
fn header_bytes<'m>(headers: &Headers<'m>, name: &str) -> Option<&'m [u8]> {
    Some(headers.get(name)?.raw_value().trim_ascii())
}

/// The subject prefix the rules give each kind, `[prefix][subject originale]`.
const fn subject_prefix(kind: MessageKind, security_error: bool) -> &'static str {
    match kind {
        MessageKind::Anomaly => "ANOMALIA MESSAGGIO: ",
        MessageKind::Certified(kind) => match kind {
            Kind::Acceptance => "ACCETTAZIONE: ",
            Kind::NonAcceptance if security_error => "AVVISO DI NON ACCETTAZIONE PER VIRUS: ",
            Kind::NonAcceptance => "AVVISO DI NON ACCETTAZIONE: ",
            Kind::TakenInCharge => "PRESA IN CARICO: ",
            Kind::Delivery => "CONSEGNA: ",
            Kind::Transport => "POSTA CERTIFICATA: ",
            Kind::DeliveryError if security_error => "AVVISO DI MANCATA CONSEGNA PER VIRUS: ",
            Kind::DeliveryError => "AVVISO DI MANCATA CONSEGNA: ",
            Kind::DeliveryTimeoutWarning => "AVVISO DI MANCATA CONSEGNA PER SUP. TEMPO MASSIMO: ",
            Kind::VirusDetected => "PROBLEMA DI SICUREZZA: ",
        },
    }
}
