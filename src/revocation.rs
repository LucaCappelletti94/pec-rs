//! Whether the signer's certificate was revoked by the validation time, from the CRLs of the CA that issued it (RFC 5280
//! §5, ETSI EN 319 102-1 §5.2.5 and §5.2.6).

use cms::cert::x509::Certificate;
use cms::cert::x509::crl::CertificateList;
use cms::cert::x509::ext::Extension;
use cms::cert::x509::ext::pkix::CrlDistributionPoints;
use cms::cert::x509::ext::pkix::name::{DistributionPointName, GeneralName};
use cms::cert::x509::time::Time;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use jiff::Timestamp;
use rustls_pki_types::SignatureVerificationAlgorithm;

use crate::SignatureError;
use crate::signature::Hash;
use crate::trust::Rsa;

/// `id-ce-issuingDistributionPoint`, which scopes a CRL to part of its CA's certificates.
const ISSUING_DISTRIBUTION_POINT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.28");
/// `id-ce-deltaCRLIndicator`, which marks a CRL holding only the changes since a complete one.
const DELTA_CRL_INDICATOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.27");

/// Checks `signer`, issued by `issuer`, against the latest of `crls` from `issuer` that can vouch for it at `at`.
/// CRLs of other CAs are ignored.
pub(crate) fn check(
    signer: &Certificate,
    issuer: &Certificate,
    crls: &[&[u8]],
    at: Timestamp,
) -> Result<(), SignatureError> {
    let at_second = at.as_second();
    let mut latest: Option<(i64, CertificateList)> = None;
    for der in crls {
        let list = CertificateList::from_der(der).map_err(|_| SignatureError::InvalidCrl)?;
        if list.tbs_cert_list.issuer != *issuer.tbs_certificate().subject() {
            continue;
        }
        if !authentic(&list, issuer) {
            return Err(SignatureError::InvalidCrl);
        }
        let this_update = seconds(list.tbs_cert_list.this_update);
        if usable(&list, signer, issuer, at_second)
            && latest
                .as_ref()
                .is_none_or(|(latest, _)| this_update > *latest)
        {
            latest = Some((this_update, list));
        }
    }
    let Some((_, list)) = latest else {
        return Err(SignatureError::NoUsableCrl {
            urls: distribution_points(signer),
        });
    };
    let serial = signer.tbs_certificate().serial_number();
    let entry = list
        .tbs_cert_list
        .revoked_certificates
        .iter()
        .flatten()
        .find(|entry| entry.serial_number == *serial);
    let revoked_at = entry
        .map(|entry| seconds(entry.revocation_date))
        .filter(|revoked_at| *revoked_at <= at_second);
    // No later than `at`, so inside what `jiff` represents.
    revoked_at.map_or(Ok(()), |revoked_at| {
        Err(SignatureError::Revoked {
            revoked_at: Timestamp::from_second(revoked_at).unwrap_or(at),
        })
    })
}

/// Whether `issuer`'s key signed `list` with RSA and SHA-256 or SHA-512, and `list` has no extension that is critical
/// or changes what it covers, which the crate does not honour (RFC 5280 §5.2 and §5.3).
fn authentic(list: &CertificateList, issuer: &Certificate) -> bool {
    let algorithm = list.signature_algorithm.oid;
    let hash = [Hash::Sha256, Hash::Sha512]
        .into_iter()
        .find(|hash| hash.with_rsa() == algorithm);
    let key = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let tbs = list.tbs_cert_list.to_der().ok();
    let signed = hash.zip(tbs).is_some_and(|(hash, tbs)| {
        list.tbs_cert_list.signature == list.signature_algorithm
            && Rsa(hash)
                .verify_signature(key, &tbs, list.signature.raw_bytes())
                .is_ok()
    });
    signed
        && honoured(list.tbs_cert_list.crl_extensions.as_deref())
        && list
            .tbs_cert_list
            .revoked_certificates
            .iter()
            .flatten()
            .all(|entry| honoured(entry.crl_entry_extensions.as_deref()))
}

/// Whether none of `extensions` is critical, scopes the CRL or makes it a delta.
fn honoured(extensions: Option<&[Extension]>) -> bool {
    extensions.unwrap_or_default().iter().all(|extension| {
        !extension.critical
            && extension.extn_id != ISSUING_DISTRIBUTION_POINT
            && extension.extn_id != DELTA_CRL_INDICATOR
    })
}

/// Whether `list` can vouch for `signer` at `at`, in seconds. It is fresh while `at` is before its `nextUpdate`, the
/// default freshness of ETSI EN 319 102-1 §5.2.5. It was issued while the signer's certificate was unexpired, since a
/// CRL may drop an expired certificate (§5.2.6 NOTE 3), and while its CA's certificate was valid (§5.2.6).
fn usable(list: &CertificateList, signer: &Certificate, issuer: &Certificate, at: i64) -> bool {
    let this_update = seconds(list.tbs_cert_list.this_update);
    let (signer_validity, issuer_validity) = (
        signer.tbs_certificate().validity(),
        issuer.tbs_certificate().validity(),
    );
    list.tbs_cert_list
        .next_update
        .is_some_and(|next_update| at < seconds(next_update))
        && this_update <= seconds(signer_validity.not_after)
        && seconds(issuer_validity.not_before) <= this_update
        && this_update <= seconds(issuer_validity.not_after)
}

/// An X.509 time in seconds since the Unix epoch, which for the years X.509 allows fits an `i64`.
fn seconds(time: Time) -> i64 {
    i64::try_from(time.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
}

/// The URLs of `signer`'s CRL distribution points, in order.
fn distribution_points(signer: &Certificate) -> Vec<String> {
    let points = signer
        .tbs_certificate()
        .get_extension::<CrlDistributionPoints>()
        .ok()
        .flatten()
        .map_or_else(Vec::new, |(_, points)| points.0);
    points
        .into_iter()
        .filter_map(|point| match point.distribution_point {
            Some(DistributionPointName::FullName(names)) => Some(names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(url) => Some(url.to_string()),
            _ => None,
        })
        .collect()
}
