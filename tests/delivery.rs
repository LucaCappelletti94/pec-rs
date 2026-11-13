//! The delivery state of each recipient, derived from the receipts of one sent message (§6.3 to §6.5.3).

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

extern crate alloc;

use alloc::collections::BTreeMap;

use jiff::Timestamp;
use postacert::{Delivery, Error, ErrorCode, Kind, Message, Recorded, Status, VerifiedMessage};

/// The `Message-ID` the sender's client gave the message every fixture receipt is about.
const SENT: &str = "<20261108101458.0001@client.example.it>";
/// The recipient the acceptance lists as `certificato`.
const CERTIFIED: &str = "ufficio.fatture@pec.example.it";
/// The recipient the acceptance lists as `esterno`.
const EXTERNAL: &str = "info@example.com";
/// A recipient the acceptance does not list.
const UNLISTED: &str = "protocollo@pec.example.it";

/// Reads a file under `tests/fixtures`.
fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists")
}

/// The certified time of every fixture receipt but the late ones, 8 November 2026 at 10:15 in Italy.
fn fixture_time() -> Timestamp {
    "2026-11-08T09:15:00Z".parse().expect("an RFC 3339 instant")
}

/// A delivery tracking the message the fixtures are about.
fn tracked() -> Delivery {
    Delivery::new(SENT.parse().expect("a message identifier"))
}

/// Calls `check` with the fixture receipts `names` from `tests/fixtures/messages`, each verified under the test
/// anchor constrained as AgID's are, with a CRL that lists nothing.
fn with_receipts<T>(names: &[&str], check: impl FnOnce(&[VerifiedMessage<'_, '_>]) -> T) -> T {
    let raws: Vec<Vec<u8>> = names
        .iter()
        .map(|name| fixture(&format!("messages/{name}.eml")))
        .collect();
    let messages: Vec<Message<'_>> = raws
        .iter()
        .map(|raw| Message::parse(raw).expect("a PEC message"))
        .collect();
    let (anchor, crl) = (
        fixture("pki/anchors/agid-like.der"),
        fixture("pki/crls/current.der"),
    );
    let at = "2030-01-01T00:00:00Z".parse().expect("an RFC 3339 instant");
    let receipts: Vec<VerifiedMessage<'_, '_>> = messages
        .iter()
        .map(|message| {
            message
                .verify(&[&anchor], &[&crl], at)
                .expect("a verified receipt")
        })
        .collect();
    check(&receipts)
}

/// Every recipient's status in `delivery`.
fn recipients(delivery: &Delivery) -> BTreeMap<String, Status> {
    delivery
        .recipients()
        .map(|(recipient, status)| (recipient.to_owned(), status))
        .collect()
}

/// Every recipient's status after recording `receipts` in order, each of which must apply.
fn record_all<'r, 'm: 'r, 'a: 'm>(
    receipts: impl IntoIterator<Item = &'r VerifiedMessage<'m, 'a>>,
) -> BTreeMap<String, Status> {
    let mut delivery = tracked();
    for receipt in receipts {
        assert_eq!(delivery.record(receipt), Ok(Recorded::Applied));
    }
    recipients(&delivery)
}

/// Every recipient's status after recording the fixture receipts `names` in order.
fn statuses(names: &[&str]) -> BTreeMap<String, Status> {
    with_receipts(names, |receipts| record_all(receipts))
}

/// The recipients and statuses `pairs` as [`statuses`] returns them.
fn expected(pairs: &[(&str, Status)]) -> BTreeMap<String, Status> {
    pairs
        .iter()
        .map(|&(recipient, status)| (recipient.to_owned(), status))
        .collect()
}

/// Every order of `0..count`.
fn orders(count: usize) -> Vec<Vec<usize>> {
    let Some(last) = count.checked_sub(1) else {
        return vec![Vec::new()];
    };
    let mut all = Vec::new();
    for order in orders(last) {
        for position in 0..=order.len() {
            let mut longer = order.clone();
            longer.insert(position, last);
            all.push(longer);
        }
    }
    all
}

#[test]
fn acceptance_lists_certified_and_external_recipients() {
    assert_eq!(
        statuses(&["acceptance"]),
        expected(&[
            (CERTIFIED, Status::Accepted),
            (EXTERNAL, Status::OutsidePec)
        ])
    );
}

#[test]
fn an_external_recipient_named_by_another_receipt_conflicts() {
    assert_eq!(
        statuses(&["acceptance", "delivery-external"]),
        expected(&[
            (CERTIFIED, Status::Accepted),
            (EXTERNAL, Status::Conflicting)
        ])
    );
    assert_eq!(
        statuses(&["acceptance", "timeout-external"]),
        expected(&[
            (CERTIFIED, Status::Accepted),
            (EXTERNAL, Status::Conflicting)
        ])
    );
}

#[test]
fn non_acceptance_refuses_the_whole_message() {
    assert_eq!(
        statuses(&["non-acceptance-virus"]),
        expected(&[(CERTIFIED, Status::Refused(ErrorCode::Virus))])
    );
}

#[test]
fn a_refused_message_with_any_other_receipt_conflicts() {
    assert_eq!(
        statuses(&["non-acceptance-virus", "acceptance"]),
        expected(&[
            (CERTIFIED, Status::Conflicting),
            (EXTERNAL, Status::Conflicting)
        ])
    );
    assert_eq!(
        statuses(&["non-acceptance-virus", "taken-in-charge"]),
        expected(&[(CERTIFIED, Status::Conflicting)])
    );
}

#[test]
fn taken_in_charge_follows_the_acceptance() {
    assert_eq!(
        statuses(&["taken-in-charge"]),
        expected(&[(CERTIFIED, Status::TakenInCharge)])
    );
    assert_eq!(
        statuses(&["acceptance", "taken-in-charge"]),
        expected(&[
            (CERTIFIED, Status::TakenInCharge),
            (EXTERNAL, Status::OutsidePec)
        ])
    );
}

#[test]
fn a_notice_is_cleared_only_by_a_later_taken_in_charge() {
    // The notice and the first taken-in-charge receipt carry the same certified time.
    assert_eq!(
        statuses(&["acceptance", "taken-in-charge", "timeout-warning"]),
        expected(&[(CERTIFIED, Status::Delayed), (EXTERNAL, Status::OutsidePec)])
    );
    assert_eq!(
        statuses(&["acceptance", "timeout-warning", "taken-in-charge-late"]),
        expected(&[
            (CERTIFIED, Status::TakenInCharge),
            (EXTERNAL, Status::OutsidePec)
        ])
    );
    assert_eq!(
        statuses(&[
            "acceptance",
            "timeout-warning",
            "taken-in-charge-late",
            "taken-in-charge"
        ]),
        expected(&[
            (CERTIFIED, Status::TakenInCharge),
            (EXTERNAL, Status::OutsidePec)
        ])
    );
}

#[test]
fn a_notice_without_an_acceptance_delays() {
    assert_eq!(
        statuses(&["timeout-warning"]),
        expected(&[(CERTIFIED, Status::Delayed)])
    );
    // Without the acceptance's time, the final notice cannot be told from the first.
    assert_eq!(
        statuses(&["timeout-final"]),
        expected(&[(CERTIFIED, Status::Delayed)])
    );
}

#[test]
fn a_notice_22_hours_after_the_acceptance_times_out() {
    assert_eq!(
        statuses(&["acceptance", "timeout-warning", "timeout-final"]),
        expected(&[
            (CERTIFIED, Status::TimedOut),
            (EXTERNAL, Status::OutsidePec)
        ])
    );
    assert_eq!(
        statuses(&["acceptance", "taken-in-charge-late", "timeout-final"]),
        expected(&[
            (CERTIFIED, Status::TimedOut),
            (EXTERNAL, Status::OutsidePec)
        ])
    );
}

#[test]
fn delivery_outranks_every_notice() {
    let delivered = Status::Delivered(fixture_time());
    assert_eq!(
        statuses(&["delivery-full"]),
        expected(&[(CERTIFIED, delivered)])
    );
    assert_eq!(
        statuses(&[
            "acceptance",
            "taken-in-charge",
            "timeout-final",
            "delivery-summary"
        ]),
        expected(&[(CERTIFIED, delivered), (EXTERNAL, Status::OutsidePec)])
    );
}

#[test]
fn delivery_keeps_the_earliest_certified_time() {
    let delivered = expected(&[(CERTIFIED, Status::Delivered(fixture_time()))]);
    assert_eq!(statuses(&["delivery-full", "delivery-later"]), delivered);
    assert_eq!(statuses(&["delivery-later", "delivery-full"]), delivered);
}

#[test]
fn failure_outranks_every_notice() {
    assert_eq!(
        statuses(&["acceptance", "timeout-final", "delivery-error"]),
        expected(&[
            (CERTIFIED, Status::Failed(ErrorCode::NoRecipient)),
            (EXTERNAL, Status::OutsidePec)
        ])
    );
    assert_eq!(
        statuses(&["taken-in-charge", "virus-detected"]),
        expected(&[(CERTIFIED, Status::Failed(ErrorCode::Virus))])
    );
}

#[test]
fn a_delivery_and_a_failure_conflict() {
    assert_eq!(
        statuses(&["delivery-full", "delivery-error"]),
        expected(&[(CERTIFIED, Status::Conflicting)])
    );
}

#[test]
fn failures_with_different_codes_conflict() {
    assert_eq!(
        statuses(&["delivery-error", "virus-detected"]),
        expected(&[(CERTIFIED, Status::Conflicting)])
    );
}

#[test]
fn a_second_send_under_the_same_message_id_conflicts_for_every_recipient() {
    assert_eq!(
        statuses(&["acceptance", "delivery-other-send"]),
        expected(&[
            (CERTIFIED, Status::Conflicting),
            (EXTERNAL, Status::Conflicting)
        ])
    );
}

#[test]
fn a_recipient_the_acceptance_does_not_list_conflicts() {
    assert_eq!(
        statuses(&["delivery-unlisted"]),
        expected(&[(UNLISTED, Status::Delivered(fixture_time()))])
    );
    assert_eq!(
        statuses(&["delivery-unlisted", "acceptance"]),
        expected(&[
            (CERTIFIED, Status::Accepted),
            (EXTERNAL, Status::OutsidePec),
            (UNLISTED, Status::Conflicting)
        ])
    );
}

#[test]
fn the_same_receipt_again_changes_nothing() {
    for name in [
        "acceptance",
        "non-acceptance-virus",
        "taken-in-charge",
        "delivery-full",
        "delivery-error",
        "timeout-warning",
        "virus-detected",
    ] {
        with_receipts(&[name], |receipts| {
            assert_eq!(
                record_all(receipts.iter().chain(receipts)),
                record_all(receipts),
                "{name}"
            );
        });
    }
}

#[test]
fn status_does_not_depend_on_arrival_order() {
    for names in [
        &[
            "acceptance",
            "taken-in-charge",
            "timeout-warning",
            "taken-in-charge-late",
            "timeout-final",
            "delivery-full",
        ][..],
        &["acceptance", "timeout-warning", "taken-in-charge-late"],
        &[
            "acceptance",
            "delivery-unlisted",
            "delivery-external",
            "delivery-error",
        ],
        &["non-acceptance-virus", "acceptance", "taken-in-charge"],
        &["acceptance", "delivery-other-send", "timeout-final"],
    ] {
        with_receipts(names, |receipts| {
            let first = record_all(receipts);
            for order in orders(receipts.len()) {
                assert_eq!(
                    record_all(order.iter().map(|&index| &receipts[index])),
                    first,
                    "{names:?} in the order {order:?}"
                );
            }
        });
    }
}

#[test]
fn envelopes_and_receipts_for_other_messages_change_nothing() {
    with_receipts(
        &["transport", "transport-summary", "anomaly", "acceptance"],
        |receipts| {
            let mut delivery = tracked();
            for receipt in &receipts[..3] {
                assert_eq!(delivery.record(receipt), Ok(Recorded::Unrelated));
            }
            assert_eq!(recipients(&delivery), BTreeMap::new());
            let mut other =
                Delivery::new("<other@client.example.it>".parse().expect("an identifier"));
            assert_eq!(other.record(&receipts[3]), Ok(Recorded::Unrelated));
            assert_eq!(recipients(&other), BTreeMap::new());
        },
    );
}

#[test]
fn a_receipt_naming_no_recipient_is_refused_and_records_nothing() {
    with_receipts(&["timeout-warning", "delivery-unattributed"], |receipts| {
        let mut delivery = tracked();
        assert_eq!(delivery.record(&receipts[0]), Ok(Recorded::Applied));
        assert_eq!(
            delivery.record(&receipts[1]),
            Err(Error::MissingRecipient(Kind::Delivery))
        );
        assert_eq!(
            recipients(&delivery),
            expected(&[(CERTIFIED, Status::Delayed)])
        );
    });
}

#[test]
fn recipients_compare_their_domain_without_case() {
    with_receipts(&["acceptance"], |receipts| {
        let mut delivery = tracked();
        assert_eq!(delivery.record(&receipts[0]), Ok(Recorded::Applied));
        assert_eq!(
            delivery.status("ufficio.fatture@PEC.Example.IT"),
            Some(Status::Accepted)
        );
        assert_eq!(delivery.status("Ufficio.fatture@pec.example.it"), None);
        assert_eq!(delivery.status("ufficio.fatture"), None);
    });
}
