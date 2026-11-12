//! The certification data a provider attaches as `daticert.xml`, per the DTD of §7.4.

use jiff::Timestamp;
use jiff::civil::{Date, Time};
use jiff::tz::Offset;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Kind, MessageId};

/// The content of a `daticert.xml` attachment, the root element `postacert`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "postacert")]
pub struct CertificationData {
    /// The kind of message the data certifies, the `tipo` attribute.
    #[serde(rename = "@tipo")]
    pub kind: Kind,
    /// The error the message reports, the `errore` attribute, `nessuno` when absent.
    #[serde(rename = "@errore", default)]
    pub error: ErrorCode,
    /// The header data of the original message, `intestazione`.
    #[serde(rename = "intestazione")]
    pub header: Header,
    /// The provider's data on the message, `dati`.
    #[serde(rename = "dati")]
    pub data: Data,
}

/// The `errore` attribute of `postacert`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    /// `nessuno`: no error.
    #[default]
    #[serde(rename = "nessuno")]
    None,
    /// `no-dest`: the recipient does not exist, on a delivery error.
    #[serde(rename = "no-dest")]
    NoRecipient,
    /// `no-dominio`: the recipient's domain does not exist, on a delivery error.
    #[serde(rename = "no-dominio")]
    NoDomain,
    /// `virus`: a virus, on a delivery error or a non-acceptance.
    #[serde(rename = "virus")]
    Virus,
    /// `altro`: any other error.
    #[serde(rename = "altro")]
    Other,
}

/// The header data of the original message, `intestazione`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The `From` of the original message, `mittente`.
    #[serde(rename = "mittente")]
    pub sender: String,
    /// Every `To` and `Cc` recipient of the original message, `destinatari`, at least one.
    #[serde(rename = "destinatari")]
    pub recipients: Vec<Recipient>,
    /// The `Reply-To` of the original message, `risposte`.
    #[serde(rename = "risposte")]
    pub reply_to: String,
    /// The `Subject` of the original message, `oggetto`.
    #[serde(rename = "oggetto", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// One recipient of the original message, a `destinatari` element.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// Whether the recipient is a PEC mailbox, the `tipo` attribute.
    #[serde(rename = "@tipo", default)]
    pub kind: RecipientKind,
    /// The recipient's address.
    #[serde(rename = "$text")]
    pub address: String,
}

/// The `tipo` attribute of `destinatari`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecipientKind {
    /// `certificato`: a PEC mailbox.
    #[default]
    #[serde(rename = "certificato")]
    Certified,
    /// `esterno`: an ordinary mailbox outside PEC.
    #[serde(rename = "esterno")]
    External,
}

/// The provider's data on the message, `dati`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Data {
    /// The provider certifying the data, `gestore-emittente`.
    #[serde(rename = "gestore-emittente")]
    pub provider: String,
    /// When the provider processed the message, `data`.
    #[serde(rename = "data")]
    pub at: CertifiedAt,
    /// The identifier the sender's provider gave the message, `identificativo`.
    #[serde(rename = "identificativo")]
    pub identifier: MessageId,
    /// The `Message-ID` the message carried before the provider replaced it, `msgid`.
    #[serde(
        rename = "msgid",
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::message_id::serialize_bracketed"
    )]
    pub message_id: Option<MessageId>,
    /// The delivery receipt format the sender asked for, `ricevuta`, on transport envelopes and delivery receipts.
    #[serde(
        rename = "ricevuta",
        default,
        skip_serializing_if = "Option::is_none",
        with = "receipt"
    )]
    pub receipt: Option<ReceiptKind>,
    /// The recipient the delivery was made or tried for, `consegna`.
    #[serde(rename = "consegna", default, skip_serializing_if = "Option::is_none")]
    pub delivered_to: Option<String>,
    /// The recipients a taken-in-charge receipt covers, `ricezione`.
    #[serde(rename = "ricezione", default, skip_serializing_if = "Vec::is_empty")]
    pub received_for: Vec<String>,
    /// The short description of the error, `errore-esteso`.
    #[serde(
        rename = "errore-esteso",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub extended_error: Option<String>,
}

/// The `tipo` attribute of `ricevuta`, the delivery receipt format (§6.5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReceiptKind {
    /// `completa`: the receipt carries the original message.
    #[serde(rename = "completa")]
    Full,
    /// `breve`: the receipt carries the original message with its attachments replaced by their hashes.
    #[serde(rename = "breve")]
    Short,
    /// `sintetica`: the receipt carries only the certification data.
    #[serde(rename = "sintetica")]
    Summary,
}

/// The `ricevuta` element, which carries the receipt format as its only attribute.
mod receipt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::ReceiptKind;

    /// The empty `ricevuta` element.
    #[derive(Serialize, Deserialize)]
    struct Element {
        /// The `tipo` attribute.
        #[serde(rename = "@tipo")]
        kind: ReceiptKind,
    }

    /// Writes the format as a `ricevuta` element.
    #[expect(
        clippy::ref_option,
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's `with` passes the field by reference"
    )]
    pub(super) fn serialize<S: Serializer>(
        kind: &Option<ReceiptKind>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        kind.map(|kind| Element { kind }).serialize(serializer)
    }

    /// Reads the format from a `ricevuta` element.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<ReceiptKind>, D::Error> {
        Ok(Option::<Element>::deserialize(deserializer)?.map(|element| element.kind))
    }
}

/// The local date, time and UTC offset a provider certifies, the `data` element (§7.2, §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CertifiedAt {
    /// The local date, `giorno`.
    date: Date,
    /// The local time, `ora`.
    time: Time,
    /// The difference between local time and UTC, the `zona` attribute.
    offset: Offset,
    /// The instant the three fields denote.
    timestamp: Timestamp,
}

impl CertifiedAt {
    /// The instant at `time` on `date`, local to `offset`.
    ///
    /// # Errors
    ///
    /// Fails when the year is negative, the time has fractional seconds, the offset has fractional minutes, or the instant exceeds [`Timestamp`]'s range.
    pub fn new(date: Date, time: Time, offset: Offset) -> Result<Self, jiff::Error> {
        if date.year() < 0 {
            return Err(jiff::Error::from_args(format_args!(
                "{date} has a negative year"
            )));
        }
        if time.subsec_nanosecond() != 0 {
            return Err(jiff::Error::from_args(format_args!(
                "{time} has a sub-second part"
            )));
        }
        if offset.seconds() % 60 != 0 {
            return Err(jiff::Error::from_args(format_args!(
                "{offset} has a sub-minute part"
            )));
        }
        let timestamp = offset.to_timestamp(date.to_datetime(time))?;
        Ok(Self {
            date,
            time,
            offset,
            timestamp,
        })
    }

    /// The local date.
    #[must_use]
    pub const fn date(&self) -> Date {
        self.date
    }

    /// The local time.
    #[must_use]
    pub const fn time(&self) -> Time {
        self.time
    }

    /// The difference between local time and UTC.
    #[must_use]
    pub const fn offset(&self) -> Offset {
        self.offset
    }

    /// The instant the provider certifies.
    #[must_use]
    pub const fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

/// The `data` element as written: `zona`, `giorno` and `ora`.
#[derive(Serialize, Deserialize)]
struct RawCertifiedAt {
    /// `[+|-]hhmm`.
    #[serde(rename = "@zona")]
    zone: String,
    /// `gg/mm/aaaa`.
    giorno: String,
    /// `hh:mm:ss`.
    ora: String,
}

impl Serialize for CertifiedAt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let seconds = self.offset.seconds();
        let sign = if seconds < 0 { '-' } else { '+' };
        let minutes = seconds.unsigned_abs() / 60;
        RawCertifiedAt {
            zone: format!("{sign}{:02}{:02}", minutes / 60, minutes % 60),
            giorno: format!(
                "{:02}/{:02}/{:04}",
                self.date.day(),
                self.date.month(),
                self.date.year()
            ),
            ora: format!(
                "{:02}:{:02}:{:02}",
                self.time.hour(),
                self.time.minute(),
                self.time.second()
            ),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CertifiedAt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawCertifiedAt::deserialize(deserializer)?;
        parse_certified_at(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "the date {:?} {:?} ({:?}) is not gg/mm/aaaa hh:mm:ss [+|-]hhmm",
                raw.giorno, raw.ora, raw.zone
            ))
        })
    }
}

/// Reads the three fields of `data`, `None` when any departs from §7.2.
fn parse_certified_at(raw: &RawCertifiedAt) -> Option<CertifiedAt> {
    let [d1, d2, b'/', m1, m2, b'/', y1, y2, y3, y4] = *raw.giorno.as_bytes() else {
        return None;
    };
    let [h1, h2, b':', n1, n2, b':', s1, s2] = *raw.ora.as_bytes() else {
        return None;
    };
    let [sign @ (b'+' | b'-'), zh1, zh2, zm1, zm2] = *raw.zone.as_bytes() else {
        return None;
    };
    let year = i16::try_from(digits(&[y1, y2, y3, y4])?).ok()?;
    let date = Date::new(year, digits2(m1, m2)?, digits2(d1, d2)?).ok()?;
    let time = Time::new(digits2(h1, h2)?, digits2(n1, n2)?, digits2(s1, s2)?, 0).ok()?;
    let (zone_hours, zone_minutes) = (i32::from(digits2(zh1, zh2)?), i32::from(digits2(zm1, zm2)?));
    if zone_minutes >= 60 {
        return None;
    }
    let seconds = (zone_hours * 60 + zone_minutes) * 60;
    let offset = Offset::from_seconds(if sign == b'-' { -seconds } else { seconds }).ok()?;
    CertifiedAt::new(date, time, offset).ok()
}

/// The value of ASCII decimal digits, `None` when any byte is not one.
fn digits(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

/// The value of two ASCII decimal digits.
fn digits2(tens: u8, units: u8) -> Option<i8> {
    i8::try_from(digits(&[tens, units])?).ok()
}

impl CertificationData {
    /// Reads a `daticert.xml`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CertificationData`] when the document does not follow the DTD of §7.4: an unknown `tipo`,
    /// a missing element, no `destinatari`, or a date, time or zone outside the format of §7.2.
    pub fn from_xml(xml: &str) -> Result<Self, Error> {
        quick_xml::de::from_str(xml).map_err(|error| Error::CertificationData(error.to_string()))
    }

    /// Writes the data as a `daticert.xml` in UTF-8, with its XML declaration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CertificationData`] when there are no recipients or serialization fails.
    pub fn to_xml(&self) -> Result<String, Error> {
        if self.header.recipients.is_empty() {
            return Err(Error::CertificationData(
                "at least one recipient is required".to_owned(),
            ));
        }
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        let mut serializer = quick_xml::se::Serializer::new(&mut xml);
        serializer.indent(' ', 2);
        self.serialize(serializer)
            .map_err(|error| Error::CertificationData(error.to_string()))?;
        xml.push('\n');
        Ok(xml)
    }
}
