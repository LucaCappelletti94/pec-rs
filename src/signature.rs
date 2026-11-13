//! The S/MIME signature a PEC provider puts on every receipt, notice and envelope (§6.1).
//!
//! The provider signs the first part of a `multipart/signed` message with a detached CMS `SignedData` (RFC 5652) in
//! the second part. Only RSA PKCS #1 v1.5 with SHA-256 or SHA-512 is accepted, the algorithms AgID's provider CAs use
//! (CPS `MO_AgID-CA` §7.1.3).

use cms::cert::CertificateChoices;
use cms::cert::x509::Certificate;
use cms::cert::x509::attr::Attributes;
use cms::cert::x509::ext::pkix::SubjectKeyIdentifier;
use cms::cert::x509::time::Time;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{ObjectIdentifier, OctetString};
use der::referenced::OwnedToRef;
use der::{Choice, Decode, DecodeValue, Encode, EncodingRules, Writer};
use jiff::Timestamp;
use rsa::{Pkcs1v15Sign, PublicKey};
use sha2::digest::const_oid::AssociatedOid;
use sha2::{Digest, Sha256, Sha512};

/// `id-data`, the content type of the signed MIME part.
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// `id-signedData`.
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// The `content-type` signed attribute.
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// The `message-digest` signed attribute.
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// The `signing-time` signed attribute.
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// SHA-256.
const ID_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// SHA-512.
const ID_SHA_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
/// RSA without a hash of its own, which then comes from the signer's digest algorithm.
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `sha256WithRSAEncryption`.
const SHA_256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// `sha512WithRSAEncryption`.
const SHA_512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// Why a provider signature does not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The signature part is not a detached CMS `SignedData` with one signer carrying the `content-type` and
    /// `message-digest` signed attributes.
    #[error(
        "the signature is not a detached CMS SignedData with one signer and its signed attributes"
    )]
    Malformed,
    /// The certificate the signer names is not among the certificates the signature carries.
    #[error("the signer's certificate is not in the signature")]
    UnknownSigner,
    /// An algorithm other than RSA with SHA-256 or SHA-512, or a signature algorithm naming another hash than the
    /// digest algorithm.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(String),
    /// The signed part is not the one the provider signed.
    #[error("the signed part changed after signing")]
    ContentChanged,
    /// The signature does not verify with the key of the signer's certificate.
    #[error("the signature does not verify with the signer's key")]
    BadSignature,
}

/// A provider signature whose cryptography verifies. Whether its signer is a PEC provider is a separate check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderSignature {
    /// The signer's certificate in DER.
    signer: Vec<u8>,
    /// The `signing-time` signed attribute.
    claimed_signing_time: Option<Timestamp>,
}

impl ProviderSignature {
    /// The signer's certificate in DER.
    #[must_use]
    pub fn signer_certificate(&self) -> &[u8] {
        &self.signer
    }

    /// The time the provider claims to have signed (`signing-time`, RFC 5652 §11.3), which on its own proves nothing
    /// about when the signature was made.
    #[must_use]
    pub const fn claimed_signing_time(&self) -> Option<Timestamp> {
        self.claimed_signing_time
    }
}

/// The hash of a signature, which also names the RSA signature algorithm that uses it.
#[derive(Clone, Copy)]
enum Hash {
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Hash {
    /// The hash a digest algorithm names, `None` when it is not accepted.
    const fn named(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            ID_SHA_256 => Some(Self::Sha256),
            ID_SHA_512 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The RSA PKCS #1 v1.5 signature algorithm with this hash.
    const fn with_rsa(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => SHA_256_WITH_RSA,
            Self::Sha512 => SHA_512_WITH_RSA,
        }
    }
}

/// A DER writer feeding a hash, so the signed attributes are hashed without an encoded copy.
struct Hashing<D>(D);

impl<D: Digest> Writer for Hashing<D> {
    fn write(&mut self, slice: &[u8]) -> der::Result<()> {
        self.0.update(slice);
        Ok(())
    }
}

/// Verifies a detached `SignedData` in DER over the signed part `content`.
pub(crate) fn verify(
    content: &[u8],
    signature: &[u8],
) -> Result<ProviderSignature, SignatureError> {
    let signed_data: SignedData = ContentInfo::from_ber(signature)
        .ok()
        .filter(|info| info.content_type == ID_SIGNED_DATA)
        .and_then(|info| info.content.decode_as_encoding(EncodingRules::Ber).ok())
        .ok_or(SignatureError::Malformed)?;
    let mut signers = signed_data.signer_infos.0.iter();
    let (Some(signer), None) = (signers.next(), signers.next()) else {
        return Err(SignatureError::Malformed);
    };
    if signed_data.encap_content_info.econtent_type != ID_DATA
        || signed_data.encap_content_info.econtent.is_some()
    {
        return Err(SignatureError::Malformed);
    }
    let hash = Hash::named(signer.digest_alg.oid)
        .ok_or_else(|| SignatureError::UnsupportedAlgorithm(signer.digest_alg.oid.to_string()))?;
    let algorithm = signer.signature_algorithm.oid;
    if algorithm != RSA_ENCRYPTION && algorithm != hash.with_rsa() {
        return Err(SignatureError::UnsupportedAlgorithm(algorithm.to_string()));
    }
    let certificate = signed_data
        .certificates
        .as_ref()
        .and_then(|set| set.0.iter().find_map(|choice| named(choice, &signer.sid)))
        .ok_or(SignatureError::UnknownSigner)?;
    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(SignatureError::Malformed)?;
    let content_type: ObjectIdentifier =
        attribute(attrs, ID_CONTENT_TYPE).ok_or(SignatureError::Malformed)?;
    let digest: OctetString =
        attribute(attrs, ID_MESSAGE_DIGEST).ok_or(SignatureError::Malformed)?;
    if content_type != ID_DATA {
        return Err(SignatureError::Malformed);
    }
    let claimed_signing_time = attrs
        .iter()
        .any(|attr| attr.oid == ID_SIGNING_TIME)
        .then(|| signing_time(attrs))
        .transpose()?;
    let key_info = certificate.tbs_certificate().subject_public_key_info();
    let key = PublicKey::try_from(key_info.owned_to_ref())
        .map_err(|_| SignatureError::UnsupportedAlgorithm(key_info.algorithm.oid.to_string()))?;
    match hash {
        Hash::Sha256 => check::<Sha256>(content, &digest, attrs, &signer.signature, &key)?,
        Hash::Sha512 => check::<Sha512>(content, &digest, attrs, &signer.signature, &key)?,
    }
    let encoded = certificate.to_der();
    let signer = encoded.map_err(|_| SignatureError::Malformed)?;
    Ok(ProviderSignature {
        signer,
        claimed_signing_time,
    })
}

/// Checks the `message-digest` over the signed part and the signature over the signed attributes, with the hash `D`.
fn check<D: Digest + AssociatedOid>(
    content: &[u8],
    digest: &OctetString,
    attrs: &Attributes,
    signature: &OctetString,
    key: &PublicKey,
) -> Result<(), SignatureError> {
    if digest.as_bytes() != D::digest(content).as_slice() {
        return Err(SignatureError::ContentChanged);
    }
    let mut hashing = Hashing(D::new());
    let encoded = attrs.encode(&mut hashing);
    encoded.map_err(|_| SignatureError::Malformed)?;
    key.verify(
        Pkcs1v15Sign::new::<D>(),
        &hashing.0.finalize(),
        signature.as_bytes(),
    )
    .map_err(|_| SignatureError::BadSignature)
}

/// The certificate of `choice` when it is the one `sid` names.
fn named<'a>(choice: &'a CertificateChoices, sid: &SignerIdentifier) -> Option<&'a Certificate> {
    let CertificateChoices::Certificate(certificate) = choice else {
        return None;
    };
    let tbs = certificate.tbs_certificate();
    let matches = match sid {
        SignerIdentifier::IssuerAndSerialNumber(id) => {
            id.issuer == *tbs.issuer() && id.serial_number == *tbs.serial_number()
        }
        SignerIdentifier::SubjectKeyIdentifier(key_id) => tbs
            .get_extension::<SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .is_some_and(|(_, own)| own == *key_id),
    };
    matches.then_some(certificate)
}

/// The single value of the signed attribute `oid`, decoded, `None` when absent, repeated or of another type.
fn attribute<T: for<'a> Choice<'a> + for<'a> DecodeValue<'a>>(
    attrs: &Attributes,
    oid: ObjectIdentifier,
) -> Option<T> {
    let values = attrs.iter().find(|attr| attr.oid == oid)?.values.as_slice();
    values
        .first()
        .filter(|_| values.len() == 1)?
        .decode_as()
        .ok()
}

/// The `signing-time` signed attribute.
fn signing_time(attrs: &Attributes) -> Result<Timestamp, SignatureError> {
    let time: Time = attribute(attrs, ID_SIGNING_TIME).ok_or(SignatureError::Malformed)?;
    i64::try_from(time.to_unix_duration().as_secs())
        .ok()
        .and_then(|seconds| Timestamp::from_second(seconds).ok())
        .ok_or(SignatureError::Malformed)
}
