//! The delivery state of each recipient of one sent message, from the receipts its providers certified (§6.3 to
//! §6.5.3).

use alloc::collections::{BTreeMap, BTreeSet};

use jiff::{SignedDuration, Timestamp};

use crate::{Error, ErrorCode, Kind, MessageId, RecipientKind, VerifiedMessage};

/// How long after the acceptance a timeout notice is the final one, sent 22 to 24 hours after sending (§6.3.5).
const FINAL_NOTICE: SignedDuration = SignedDuration::from_hours(22);

/// The receipts of one sent message, keyed by the `Message-ID` its client gave it, and the state of each recipient.
///
/// Receipts may be recorded in any order and more than once, and the state of a recipient is derived from every
/// certified fact recorded for it, so it never depends on the order they arrived in. Only a [`VerifiedMessage`] can be
/// recorded, so every fact comes from a receipt whose provider signature verified. A recipient's address is compared
/// with its local part exact and its domain without case.
#[derive(Clone, Debug)]
pub struct Delivery {
    /// The `msgid` every receipt for the message carries.
    message_id: MessageId,
    /// Every `identificativo` recorded, one per send of the message.
    identifiers: BTreeSet<MessageId>,
    /// The earliest certified time of an acceptance.
    accepted_at: Option<Timestamp>,
    /// The recipients of each distinct acceptance.
    listings: Vec<Listing>,
    /// The distinct error codes of the non-acceptances.
    refusals: Vec<ErrorCode>,
    /// Whether a receipt other than a non-acceptance was recorded.
    accepted_or_forwarded: bool,
    /// The facts recorded for each recipient a receipt named, by mailbox key.
    recipients: BTreeMap<String, Facts>,
}

/// The recipients one acceptance lists, by mailbox key (§6.3.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Listing {
    /// The recipients listed as `certificato`.
    certified: BTreeSet<String>,
    /// The recipients listed as `esterno`.
    external: BTreeSet<String>,
}

/// The facts the receipts naming one recipient certified, each with its certified time.
#[derive(Clone, Debug, Default)]
struct Facts {
    /// The latest taken-in-charge receipt naming the recipient in `ricezione`.
    taken_in_charge: Option<Timestamp>,
    /// The latest timeout notice naming the recipient in `consegna`.
    notice: Option<Timestamp>,
    /// The earliest delivery receipt naming the recipient in `consegna`.
    delivered: Option<Timestamp>,
    /// The distinct error codes of the delivery errors and virus detections naming the recipient in `consegna`.
    failures: Vec<ErrorCode>,
}

/// What one receipt certifies.
#[derive(Clone, Copy)]
enum Fact {
    /// An acceptance lists every recipient as `certificato` or `esterno` (§6.3.3).
    Listed,
    /// A non-acceptance refuses the whole message (§6.3.2).
    Refused,
    /// A taken-in-charge receipt names its recipients in `ricezione` (§6.4.1).
    TakenInCharge,
    /// A timeout notice names its recipient in `consegna` (§6.3.5).
    Notice,
    /// A delivery receipt names its recipient in `consegna` (§6.5.2).
    Delivered,
    /// A delivery error or a virus detection names its recipient in `consegna` (§6.5.3, §6.4.3.2).
    Failed,
}

/// What recording a receipt did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// The receipt is about the tracked message, and its facts are kept.
    Applied,
    /// The receipt is about another message, is a transport or anomaly envelope, or carries no certification data,
    /// so nothing changed.
    Unrelated,
}

/// The delivery state of one recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The sender's provider accepted the message for this PEC recipient (§6.3.3).
    Accepted,
    /// The recipient is outside PEC and gets ordinary mail with no receipt (§6.3.3).
    OutsidePec,
    /// The recipient's provider took the message in charge (§6.4.1).
    TakenInCharge,
    /// A timeout notice says the message was not delivered within 12 hours, and no taken-in-charge receipt is
    /// certified after it (§6.3.5).
    Delayed,
    /// The final timeout notice says the message was not delivered within 24 hours (§6.3.5).
    TimedOut,
    /// The recipient's provider delivered the message to the mailbox at the earliest certified time (§6.5.2).
    Delivered(Timestamp),
    /// A delivery error or a virus detection says the message will not be delivered, with its error code (§6.5.3,
    /// §6.4.3.2).
    Failed(ErrorCode),
    /// The sender's provider refused the whole message, with the error code of its non-acceptance (§6.3.2, §6.4.3.1).
    Refused(ErrorCode),
    /// The certified receipts contradict each other, with two sends under one `Message-ID`, a delivery and a failure,
    /// a refusal and another receipt, a recipient both inside and outside PEC or named while an acceptance does not
    /// list it, or failures or refusals with different error codes.
    Conflicting,
}

impl Delivery {
    /// Tracks the message the sender's client sent with `message_id`, the `msgid` its receipts carry.
    #[must_use]
    pub const fn new(message_id: MessageId) -> Self {
        Self {
            message_id,
            identifiers: BTreeSet::new(),
            accepted_at: None,
            listings: Vec::new(),
            refusals: Vec::new(),
            accepted_or_forwarded: false,
            recipients: BTreeMap::new(),
        }
    }

    /// Records the certified facts of a receipt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingRecipient`] when a taken-in-charge receipt has no `ricezione`, or a delivery receipt,
    /// delivery error, virus detection or timeout notice has no `consegna`. Nothing is recorded then.
    pub fn record(&mut self, receipt: &VerifiedMessage<'_, '_>) -> Result<Recorded, Error> {
        let Some(data) = receipt.message().certification_data() else {
            return Ok(Recorded::Unrelated);
        };
        if data.data.message_id.as_ref() != Some(&self.message_id) {
            return Ok(Recorded::Unrelated);
        }
        let (fact, named): (Fact, &[String]) = match data.kind {
            Kind::Transport => return Ok(Recorded::Unrelated),
            Kind::Acceptance => (Fact::Listed, &[]),
            Kind::NonAcceptance => (Fact::Refused, &[]),
            Kind::TakenInCharge => (Fact::TakenInCharge, &data.data.received_for),
            Kind::DeliveryTimeoutWarning => (Fact::Notice, data.data.delivered_to.as_slice()),
            Kind::Delivery => (Fact::Delivered, data.data.delivered_to.as_slice()),
            Kind::DeliveryError | Kind::VirusDetected => {
                (Fact::Failed, data.data.delivered_to.as_slice())
            }
        };
        if named.is_empty() && !matches!(fact, Fact::Listed | Fact::Refused) {
            return Err(Error::MissingRecipient(data.kind));
        }
        if !self.identifiers.contains(&data.data.identifier) {
            self.identifiers.insert(data.data.identifier.clone());
        }
        let at = data.data.at.timestamp();
        match fact {
            Fact::Listed => {
                let mut listing = Listing::default();
                for recipient in &data.header.recipients {
                    let key = mailbox_key(&recipient.address);
                    if !self.recipients.contains_key(&key) {
                        self.recipients.insert(key.clone(), Facts::default());
                    }
                    match recipient.kind {
                        RecipientKind::Certified => listing.certified.insert(key),
                        RecipientKind::External => listing.external.insert(key),
                    };
                }
                if !self.listings.contains(&listing) {
                    self.listings.push(listing);
                }
                keep_earliest(&mut self.accepted_at, at);
            }
            Fact::Refused => {
                for recipient in &data.header.recipients {
                    self.recipients
                        .entry(mailbox_key(&recipient.address))
                        .or_default();
                }
                push_distinct(&mut self.refusals, data.error);
            }
            Fact::TakenInCharge => {
                self.each_named(named, |facts| keep_latest(&mut facts.taken_in_charge, at));
            }
            Fact::Notice => self.each_named(named, |facts| keep_latest(&mut facts.notice, at)),
            Fact::Delivered => {
                self.each_named(named, |facts| keep_earliest(&mut facts.delivered, at));
            }
            Fact::Failed => {
                self.each_named(named, |facts| {
                    push_distinct(&mut facts.failures, data.error);
                });
            }
        }
        if !matches!(fact, Fact::Refused) {
            self.accepted_or_forwarded = true;
        }
        Ok(Recorded::Applied)
    }

    /// Applies `apply` to the facts of every recipient in `named`, adding the recipients not named before.
    fn each_named(&mut self, named: &[String], mut apply: impl FnMut(&mut Facts)) {
        for address in named {
            apply(self.recipients.entry(mailbox_key(address)).or_default());
        }
    }

    /// The state of `recipient`, or `None` when no recorded receipt names it.
    #[must_use]
    pub fn status(&self, recipient: &str) -> Option<Status> {
        let key = mailbox_key(recipient);
        self.recipients
            .get(&key)
            .map(|facts| self.derive(&key, facts))
    }

    /// Every recipient a recorded receipt names, with its state, ordered by the local part as written and then the
    /// domain in lower case.
    pub fn recipients(&self) -> impl Iterator<Item = (&str, Status)> {
        self.recipients
            .iter()
            .map(|(key, facts)| (key.as_str(), self.derive(key, facts)))
    }

    /// The state of the recipient with mailbox key `key` and facts `facts`, by the precedence of the model.
    fn derive(&self, key: &str, facts: &Facts) -> Status {
        let certified = self
            .listings
            .iter()
            .any(|listing| listing.certified.contains(key));
        let external = self
            .listings
            .iter()
            .any(|listing| listing.external.contains(key));
        let unlisted = self
            .listings
            .iter()
            .any(|listing| !listing.certified.contains(key) && !listing.external.contains(key));
        let forwarded = facts.taken_in_charge.is_some()
            || facts.notice.is_some()
            || facts.delivered.is_some()
            || !facts.failures.is_empty();
        if self.identifiers.len() > 1
            || unlisted
            || (certified && external)
            || (external && forwarded)
            || (facts.delivered.is_some() && !facts.failures.is_empty())
            || (!self.refusals.is_empty() && self.accepted_or_forwarded)
            || self.refusals.len() > 1
            || facts.failures.len() > 1
        {
            return Status::Conflicting;
        }
        if let [code] = *self.refusals {
            return Status::Refused(code);
        }
        if external {
            return Status::OutsidePec;
        }
        if let Some(at) = facts.delivered {
            return Status::Delivered(at);
        }
        if let [code] = *facts.failures {
            return Status::Failed(code);
        }
        if let Some(notice) = facts.notice {
            if self
                .accepted_at
                .is_some_and(|accepted| notice.duration_since(accepted) >= FINAL_NOTICE)
            {
                return Status::TimedOut;
            }
            if facts.taken_in_charge.is_none_or(|taken| taken <= notice) {
                return Status::Delayed;
            }
        }
        if facts.taken_in_charge.is_some() {
            Status::TakenInCharge
        } else {
            Status::Accepted
        }
    }
}

/// The key a mailbox is compared by, its local part as written and its domain in lower case.
fn mailbox_key(address: &str) -> String {
    let mut key = address.to_owned();
    if let Some((local, _)) = address.rsplit_once('@') {
        key[local.len()..].make_ascii_lowercase();
    }
    key
}

/// Keeps the earlier of a recorded time and a new one.
fn keep_earliest(recorded: &mut Option<Timestamp>, at: Timestamp) {
    *recorded = Some(recorded.map_or(at, |recorded| recorded.min(at)));
}

/// Keeps the later of a recorded time and a new one.
fn keep_latest(recorded: &mut Option<Timestamp>, at: Timestamp) {
    *recorded = Some(recorded.map_or(at, |recorded| recorded.max(at)));
}

/// Adds `code` to `codes` unless it is there already.
fn push_distinct(codes: &mut Vec<ErrorCode>, code: ErrorCode) {
    if !codes.contains(&code) {
        codes.push(code);
    }
}
