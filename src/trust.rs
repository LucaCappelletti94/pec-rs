//! Whether the signer of a provider signature is a PEC provider: a certificate one of the caller's anchors issued, valid
//! at the caller's time, for signing the email of the message's sender (§6.1, CPS `MO_AgID-CA` §7.1).
//!
//! `rustls-webpki` checks the chain but cannot check `rfc822Name` and `directoryName` name constraints
//! (rustls/webpki#445, #19), which every AgID CA carries, so the crate checks those two forms itself.

use core::time::Duration;

use cms::cert::x509::Certificate;
use cms::cert::x509::ext::pkix::constraints::name::GeneralSubtree;
use cms::cert::x509::ext::pkix::name::GeneralName;
use cms::cert::x509::ext::pkix::{KeyUsage, NameConstraints, SubjectAltName};
use cms::cert::x509::name::Name;
use der::asn1::AnyRef;
use der::{Decode, Encode};
use jiff::Timestamp;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Sign, PublicKey};
use rustls_pki_types::{
    AlgorithmIdentifier, CertificateDer, Der, InvalidSignature, SignatureVerificationAlgorithm,
    TrustAnchor, UnixTime, alg_id,
};
use sha2::digest::const_oid::AssociatedOid;
use sha2::{Digest, Sha256, Sha512};
use webpki::{EndEntityCert, VerifiedPath, anchor_from_trusted_cert};

use crate::signature::Hash;
use crate::{SignatureError, revocation};

/// `AgID CA1`, which issues PEC provider certificates until 2030-09-22 (SHA-256 `790EC428…278C1D`).
pub const AGID_CA1: &[u8] = include_bytes!("anchors/agid-ca1.der");

/// `AgID CA SMIME RSA 2026`, which issues PEC provider certificates until 2029-08-03 (SHA-256 `78A9F2A7…0CED80`).
pub const AGID_CA_SMIME_RSA_2026: &[u8] = include_bytes!("anchors/agid-ca-smime-rsa-2026.der");

/// The CAs AgID issues PEC provider certificates from, as anchors for [`crate::Message::provider_signature`].
pub const AGID_PROVIDER_CAS: &[&[u8]] = &[AGID_CA1, AGID_CA_SMIME_RSA_2026];

/// `id-kp-emailProtection`, the purpose of every provider certificate (CPS §7.1.2.3).
const EMAIL_PROTECTION: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 4];

/// The certificate signatures AgID's CAs make (CPS §7.1.3).
static ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] =
    &[&Rsa(Hash::Sha256), &Rsa(Hash::Sha512)];

/// RSA PKCS #1 v1.5 with a hash, for `rustls-webpki` without `ring`, which fails to build for `wasm32`, and for CRLs.
#[derive(Debug)]
pub(crate) struct Rsa(pub(crate) Hash);

impl SignatureVerificationAlgorithm for Rsa {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = PublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;
        match self.0 {
            Hash::Sha256 => verify_rsa::<Sha256>(&key, message, signature),
            Hash::Sha512 => verify_rsa::<Sha512>(&key, message, signature),
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            Hash::Sha256 => alg_id::RSA_PKCS1_SHA256,
            Hash::Sha512 => alg_id::RSA_PKCS1_SHA512,
        }
    }
}

/// Verifies an RSA PKCS #1 v1.5 signature over `message` hashed with `D`.
fn verify_rsa<D: Digest + AssociatedOid>(
    key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    key.verify(Pkcs1v15Sign::new::<D>(), &D::digest(message), signature)
        .map_err(|_| InvalidSignature)
}

/// The `rfc822Name` and `directoryName` subtrees of an anchor's name constraints (RFC 5280 §4.2.1.10).
struct Subtrees {
    /// The permitted subtrees.
    permitted: Vec<GeneralName>,
    /// The excluded subtrees.
    excluded: Vec<GeneralName>,
}

impl Subtrees {
    /// Whether the email addresses of `alt_names` and the directory names of `alt_names` and `subject` fall inside
    /// these subtrees.
    fn permit(&self, subject: &Name, alt_names: &[GeneralName]) -> bool {
        alt_names
            .iter()
            .filter_map(email)
            .all(|address| self.permit_email(address))
            && alt_names
                .iter()
                .filter_map(directory)
                .chain([subject])
                .all(|name| self.permit_directory(name))
    }

    /// Whether `address` is in a permitted `rfc822Name` subtree, when there is one, and in no excluded one.
    fn permit_email(&self, address: &str) -> bool {
        let mut permitted = self.permitted.iter().filter_map(email).peekable();
        (permitted.peek().is_none() || permitted.any(|base| email_within(address, base)))
            && !self
                .excluded
                .iter()
                .filter_map(email)
                .any(|base| email_within(address, base))
    }

    /// Whether `name` starts with a permitted `directoryName`, when there is one. Any excluded `directoryName`
    /// refuses, since a match by encoding could miss an exclusion written another way.
    fn permit_directory(&self, name: &Name) -> bool {
        let mut permitted = self.permitted.iter().filter_map(directory).peekable();
        (permitted.peek().is_none() || permitted.any(|base| starts_with(name, base)))
            && self.excluded.iter().find_map(directory).is_none()
    }
}

/// The address of an `rfc822Name`.
fn email(name: &GeneralName) -> Option<&str> {
    match name {
        GeneralName::Rfc822Name(address) => Some(address.as_str()),
        _ => None,
    }
}

/// The name of a `directoryName`.
const fn directory(name: &GeneralName) -> Option<&Name> {
    match name {
        GeneralName::DirectoryName(name) => Some(name),
        _ => None,
    }
}

/// Whether `address` is the mailbox `base`, a mailbox on the host `base`, or with a leading dot a mailbox on a
/// subdomain of it (RFC 5280 §4.2.1.10).
fn email_within(address: &str, base: &str) -> bool {
    let host = address.rsplit_once('@').map(|(_, host)| host.as_bytes());
    let base_bytes = base.as_bytes();
    if base.contains('@') {
        same_mailbox(address, base)
    } else if base.starts_with('.') {
        host.is_some_and(|host| {
            host.len() > base_bytes.len()
                && host[host.len() - base_bytes.len()..].eq_ignore_ascii_case(base_bytes)
        })
    } else {
        host.is_some_and(|host| host.eq_ignore_ascii_case(base_bytes))
    }
}

/// Whether two addresses name the same mailbox, the local part compared exactly and the host without case (RFC 5280
/// §7.5).
fn same_mailbox(left: &str, right: &str) -> bool {
    left.rsplit_once('@')
        .zip(right.rsplit_once('@'))
        .is_some_and(|((left_local, left_host), (right_local, right_host))| {
            left_local == right_local && left_host.eq_ignore_ascii_case(right_host)
        })
}

/// Whether `name` starts with the RDNs of `base`, each compared as encoded, as rustls/webpki#543 does.
fn starts_with(name: &Name, base: &Name) -> bool {
    let (name, base) = (name.as_ref(), base.as_ref());
    name.len() >= base.len() && name.iter().zip(base.iter()).all(|(rdn, base)| rdn == base)
}

/// Moves the `rfc822Name` and `directoryName` subtrees out of `subtrees`, returning them and the rest.
fn split(subtrees: Option<Vec<GeneralSubtree>>) -> (Vec<GeneralName>, Option<Vec<GeneralSubtree>>) {
    let (ours, rest): (Vec<_>, Vec<_>) =
        subtrees
            .unwrap_or_default()
            .into_iter()
            .partition(|subtree| {
                matches!(
                    subtree.base,
                    GeneralName::Rfc822Name(_) | GeneralName::DirectoryName(_)
                )
            });
    let ours = ours.into_iter().map(|subtree| subtree.base).collect();
    (ours, (!rest.is_empty()).then_some(rest))
}

/// What the crate checks with an anchor itself: its certificate, which signs its CRLs, and the subtrees `rustls-webpki`
/// cannot check.
struct Issuer {
    /// The anchor's certificate.
    certificate: Certificate,
    /// Its `rfc822Name` and `directoryName` subtrees.
    subtrees: Subtrees,
}

/// The anchor `rustls-webpki` checks, without the subtrees it cannot check, and what the crate checks with it.
fn anchor<'a>(der: &'a CertificateDer<'a>) -> Result<(TrustAnchor<'a>, Issuer), SignatureError> {
    let mut anchor = anchor_from_trusted_cert(der).map_err(|_| SignatureError::InvalidAnchor)?;
    let certificate = Certificate::from_der(der).map_err(|_| SignatureError::InvalidAnchor)?;
    let constraints = certificate
        .tbs_certificate()
        .get_extension::<NameConstraints>()
        .map_err(|_| SignatureError::InvalidAnchor)?;
    let (permitted, excluded) = constraints.map_or((None, None), |(_, constraints)| {
        (
            constraints.permitted_subtrees,
            constraints.excluded_subtrees,
        )
    });
    // RFC 5280 §4.2.1.10 fixes `minimum` at 0 and leaves `maximum` out for every name form, and `split` keeps neither.
    let bounded = permitted
        .iter()
        .chain(excluded.iter())
        .flatten()
        .any(|subtree| subtree.minimum != 0 || subtree.maximum.is_some());
    if bounded {
        return Err(SignatureError::InvalidAnchor);
    }
    let (permitted, permitted_subtrees) = split(permitted);
    let (excluded, excluded_subtrees) = split(excluded);
    let rest = NameConstraints {
        permitted_subtrees,
        excluded_subtrees,
    };
    let rest = rest.to_der().map_err(|_| SignatureError::InvalidAnchor)?;
    // `rustls-webpki` keeps the content of the extension's `SEQUENCE`, without its header.
    let value = AnyRef::from_der(&rest).map_err(|_| SignatureError::InvalidAnchor)?;
    anchor.name_constraints = Some(Der::from(value.value().to_vec()));
    Ok((
        anchor,
        Issuer {
            certificate,
            subtrees: Subtrees {
                permitted,
                excluded,
            },
        },
    ))
}

/// Names why `rustls-webpki` refused the signer.
fn chain_error(error: webpki::Error) -> SignatureError {
    match error {
        webpki::Error::UnknownIssuer => SignatureError::UnknownIssuer,
        webpki::Error::CertNotValidYet { .. } => SignatureError::NotYetValid,
        webpki::Error::CertExpired { .. } => SignatureError::Expired,
        webpki::Error::RequiredEkuNotFoundContext(_) | webpki::Error::EmptyEkuExtension => {
            SignatureError::NotForEmail
        }
        webpki::Error::NameConstraintViolation => SignatureError::OutsideNameConstraints,
        other => SignatureError::InvalidCertificate(other.to_string()),
    }
}

/// Checks that one of `anchors` issued `signer` (`signer_der` in DER), valid and unrevoked at `at` by the latest
/// usable of `crls`, for signing the email of `sender`. The path has no intermediate certificate, since both AgID CAs
/// have `pathLenConstraint` 0.
pub(crate) fn check(
    signer: &Certificate,
    signer_der: &[u8],
    sender: Option<&str>,
    anchors: &[&[u8]],
    crls: &[&[u8]],
    at: Timestamp,
) -> Result<(), SignatureError> {
    let anchors: Vec<CertificateDer<'_>> = anchors
        .iter()
        .map(|der| CertificateDer::from(*der))
        .collect();
    let (anchors, issuers): (Vec<_>, Vec<_>) = anchors
        .iter()
        .map(anchor)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    let alt_names = signer
        .tbs_certificate()
        .get_extension::<SubjectAltName>()
        .ok()
        .flatten()
        .map_or_else(Vec::new, |(_, names)| names.0);
    let issuer_of = |path: &VerifiedPath<'_>| {
        anchors
            .iter()
            .position(|anchor| core::ptr::eq(anchor, path.anchor()))
            .and_then(|index| issuers.get(index))
    };
    let within = |path: &VerifiedPath<'_>| {
        let permitted = issuer_of(path).is_some_and(|issuer| {
            issuer
                .subtrees
                .permit(signer.tbs_certificate().subject(), &alt_names)
        });
        if permitted {
            Ok(())
        } else {
            Err(webpki::Error::NameConstraintViolation)
        }
    };
    let end_entity = CertificateDer::from(signer_der);
    // Instants before 1970 read as the epoch, which precedes every certificate.
    let time = UnixTime::since_unix_epoch(Duration::from_secs(
        u64::try_from(at.as_second()).unwrap_or(0),
    ));
    let issuer = EndEntityCert::try_from(&end_entity)
        .and_then(|end_entity| {
            end_entity
                .verify_for_usage(
                    ALGORITHMS,
                    &anchors,
                    &[],
                    time,
                    webpki::KeyUsage::required(EMAIL_PROTECTION),
                    None,
                    Some(&within),
                )
                .map(|path| issuer_of(&path))
        })
        .map_err(chain_error)?
        .ok_or(SignatureError::UnknownIssuer)?;
    let signing = signer
        .tbs_certificate()
        .get_extension::<KeyUsage>()
        .ok()
        .flatten()
        .is_some_and(|(_, usage)| usage.digital_signature());
    if !signing {
        return Err(SignatureError::NotForSigning);
    }
    let sender_named = sender.is_some_and(|sender| {
        alt_names
            .iter()
            .filter_map(email)
            .any(|address| same_mailbox(sender, address))
    });
    if !sender_named {
        return Err(SignatureError::SenderMismatch);
    }
    revocation::check(signer, &issuer.certificate, crls, at)
}
