//! The provider's S/MIME signature over every receipt, notice and envelope, and the trust in its signer (§6.1).

#![expect(
    clippy::expect_used,
    reason = "test code: the expect message names the failing helper"
)]

use base64ct::{Base64, Encoding};
use cms::cert::x509::Certificate;
use cms::cert::x509::attr::Attribute;
use cms::cert::x509::ext::pkix::SubjectKeyIdentifier;
use cms::cert::{CertificateChoices, IssuerAndSerialNumber, OtherCertificateFormat};
use cms::content_info::ContentInfo;
use cms::der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use cms::der::{Decode, Encode, Tag};
use cms::signed_data::CertificateSet;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo, SignerInfos};
use jiff::Timestamp;
use postacert::{AGID_PROVIDER_CAS, Error, Message, ProviderSignature, SignatureError};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, PrivateKey};
use sha2::digest::const_oid::AssociatedOid;
use sha2::{Digest, Sha256, Sha512};

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const ID_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const ID_SHA_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA_256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const ECDSA_WITH_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Reads a file under `tests/fixtures`.
fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists")
}

/// The provider certificate every fixture is signed with, in DER.
fn provider_certificate() -> Vec<u8> {
    fixture("pki/provider.der")
}

/// Where the base64 of the `smime.p7s` part starts and ends in a signed fixture.
fn signature_span(raw: &[u8]) -> (usize, usize) {
    let text = core::str::from_utf8(raw).expect("ASCII fixture");
    let part = text
        .find("filename=\"smime.p7s\"")
        .expect("a signature part");
    let start = part
        + text[part..]
            .find("\r\n\r\n")
            .expect("the part's headers end")
        + 4;
    let end = start
        + text[start..]
            .find("\n------")
            .expect("the closing delimiter");
    (start, end)
}

/// The `SignedData` of a signed fixture.
fn signed_data(raw: &[u8]) -> SignedData {
    let (start, end) = signature_span(raw);
    let text: String = core::str::from_utf8(&raw[start..end])
        .expect("ASCII base64")
        .split_whitespace()
        .collect();
    let der = Base64::decode_vec(&text).expect("base64");
    ContentInfo::from_der(&der)
        .expect("a ContentInfo")
        .content
        .decode_as()
        .expect("a SignedData")
}

/// The fixture with its signature part replaced by `der`.
fn with_signature(raw: &[u8], der: &[u8]) -> Vec<u8> {
    let (start, end) = signature_span(raw);
    let base64 = Base64::encode_string(der);
    let mut wrapped = String::with_capacity(base64.len() + base64.len() / 32 + 2);
    for line in base64.as_bytes().chunks(64) {
        wrapped.push_str(core::str::from_utf8(line).expect("ASCII base64"));
        wrapped.push_str("\r\n");
    }
    [&raw[..start], wrapped.as_bytes(), &raw[end..]].concat()
}

/// `signed_data` as both real providers send it, its `ContentInfo` and `[0]` wrapper with indefinite lengths (BER).
fn indefinite(signed_data: &SignedData) -> Vec<u8> {
    let inner = signed_data.to_der().expect("encodable SignedData");
    let oid = ID_SIGNED_DATA.to_der().expect("encodable OID");
    [
        &[0x30, 0x80][..],
        &oid,
        &[0xa0, 0x80],
        &inner,
        &[0, 0, 0, 0],
    ]
    .concat()
}

/// The fixture carrying `signed_data` instead of its own.
fn with_signed_data(raw: &[u8], signed_data: &SignedData) -> Vec<u8> {
    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(signed_data).expect("encodable SignedData"),
    };
    with_signature(raw, &content_info.to_der().expect("encodable ContentInfo"))
}

/// Moves the only signer out of a `SignedData`.
fn take_signer(signed_data: &mut SignedData) -> SignerInfo {
    core::mem::replace(&mut signed_data.signer_infos, SignerInfos(SetOfVec::new()))
        .0
        .into_vec()
        .pop()
        .expect("a signer")
}

/// `signed_data` with `signers` as its signers.
fn with_signers(mut signed_data: SignedData, signers: Vec<SignerInfo>) -> SignedData {
    signed_data.signer_infos = SignerInfos(SetOfVec::try_from(signers).expect("distinct signers"));
    signed_data
}

/// Moves the signer's signed attributes out for editing.
fn take_attributes(signer: &mut SignerInfo) -> Vec<Attribute> {
    signer
        .signed_attrs
        .take()
        .expect("signed attributes")
        .into_vec()
}

/// An attribute with a single value.
fn attribute(oid: ObjectIdentifier, value: Any) -> Attribute {
    Attribute {
        oid,
        values: SetOfVec::try_from(vec![value]).expect("one value"),
    }
}

/// `attrs` with the value of the attribute `oid` replaced by `value`.
fn replaced(attrs: Vec<Attribute>, oid: ObjectIdentifier, value: Any) -> Vec<Attribute> {
    let mut value = Some(value);
    attrs
        .into_iter()
        .map(|attr| {
            value
                .take_if(|_| attr.oid == oid)
                .map_or(attr, |value| attribute(oid, value))
        })
        .collect()
}

/// Sets the signer's signed attributes and signs them with the provider key.
fn resign<D: Digest + AssociatedOid>(signer: &mut SignerInfo, attrs: Vec<Attribute>) {
    let attrs = SetOfVec::try_from(attrs).expect("distinct attributes");
    let digest = D::digest(attrs.to_der().expect("encodable attributes"));
    let key =
        PrivateKey::from_pkcs8_der(&fixture("pki/provider.key.der")).expect("the provider key");
    let signature = key
        .sign(Pkcs1v15Sign::new::<D>(), &digest)
        .expect("signable digest");
    signer.signed_attrs = Some(attrs);
    signer.signature = OctetString::new(signature).expect("an octet string");
}

/// The bytes the provider signed: the first part of the signed fixture.
fn signed_content(raw: &[u8]) -> &[u8] {
    let text = core::str::from_utf8(raw).expect("ASCII fixture");
    let boundary = text
        .split("boundary=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a boundary");
    let delimiter = format!("--{boundary}\r\n");
    let start = text.find(&delimiter).expect("the first delimiter") + delimiter.len();
    let end = start
        + text[start..]
            .find(&format!("\r\n--{boundary}"))
            .expect("the second delimiter");
    &raw[start..end]
}

/// A test anchor, the test CA with the name constraints its file is named after.
fn anchor(name: &str) -> Vec<u8> {
    fixture(&format!("pki/anchors/{name}.der"))
}

/// An instant written in RFC 3339.
fn time(text: &str) -> Timestamp {
    text.parse().expect("an RFC 3339 instant")
}

/// A validation time inside the validity of the whole test PKI.
fn now() -> Timestamp {
    time("2030-01-01T00:00:00Z")
}

/// A CRL of the test CA, with the update times or entries its file is named after.
fn crl(name: &str) -> Vec<u8> {
    fixture(&format!("pki/crls/{name}.der"))
}

/// The verification result of a fixture under `anchors` and `crls` at `at`.
fn verify_full(
    raw: &[u8],
    anchors: &[&[u8]],
    crls: &[&[u8]],
    at: Timestamp,
) -> Result<ProviderSignature, Error> {
    Message::parse(raw)
        .expect("a PEC message")
        .verify(anchors, crls, at)
        .map(|verified| verified.signature().clone())
}

/// The verification result of a fixture under `anchors` at `at`, with a CRL that lists nothing.
fn verify_with(raw: &[u8], anchors: &[&[u8]], at: Timestamp) -> Result<ProviderSignature, Error> {
    verify_full(raw, anchors, &[&crl("current")], at)
}

/// The verification result of a fixture under the test anchor constrained as AgID's are, with `crls` at `at`.
fn verify_crls(raw: &[u8], crls: &[&[u8]], at: Timestamp) -> Result<ProviderSignature, Error> {
    verify_full(raw, &[&anchor("agid-like")], crls, at)
}

/// The verification result of a fixture under the test anchor constrained as AgID's are.
fn verify(raw: &[u8]) -> Result<ProviderSignature, Error> {
    verify_with(raw, &[&anchor("agid-like")], now())
}

/// The fixture signed by the provider key under the test signer certificate `name`.
fn signed_by(raw: &[u8], name: &str) -> Vec<u8> {
    let certificate = Certificate::from_der(&fixture(&format!("pki/signers/{name}.der")))
        .expect("a signer certificate");
    let mut data = signed_data(raw);
    let mut only = take_signer(&mut data);
    only.sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: certificate.tbs_certificate().issuer().clone(),
        serial_number: certificate.tbs_certificate().serial_number().clone(),
    });
    data.certificates = Some(CertificateSet(
        SetOfVec::try_from(vec![CertificateChoices::Certificate(certificate)])
            .expect("one certificate"),
    ));
    with_signed_data(raw, &with_signers(data, vec![only]))
}

/// The acceptance fixture with `from` as its `From` field, or without one.
fn acceptance_from(from: Option<&str>) -> Vec<u8> {
    let raw = fixture("messages/acceptance.eml");
    let text = core::str::from_utf8(&raw).expect("ASCII fixture");
    let (head, tail) = text
        .split_once("From: posta-certificata@pec.example.it\r\n")
        .expect("a From field");
    let field = from.map_or_else(String::new, |from| format!("From: {from}\r\n"));
    format!("{head}{field}{tail}").into_bytes()
}

#[test]
fn indefinite_length_signature_verifies() {
    let raw = fixture("messages/acceptance.eml");
    let signature =
        verify(&with_signature(&raw, &indefinite(&signed_data(&raw)))).expect("a valid signature");
    assert_eq!(signature.signer_certificate(), provider_certificate());
}

#[test]
fn every_fixture_carries_the_provider_signature() {
    let certificate = provider_certificate();
    let folder = format!("{}/tests/fixtures/messages", env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for entry in std::fs::read_dir(folder).expect("the fixtures folder") {
        let path = entry.expect("a folder entry").path();
        let raw = std::fs::read(&path).expect("the fixture");
        let signature = verify(&raw).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(
            signature.signer_certificate(),
            certificate,
            "{}",
            path.display()
        );
        assert!(
            signature.claimed_signing_time().is_some(),
            "{}",
            path.display()
        );
        checked += 1;
    }
    assert_eq!(checked, 25);
}

#[test]
fn verification_yields_the_receipt_it_verified() {
    let raw = fixture("messages/delivery-full.eml");
    let message = Message::parse(&raw).expect("a PEC message");
    let verified = message
        .verify(&[&anchor("agid-like")], &[&crl("current")], now())
        .expect("a valid signature");
    assert_eq!(
        verified.message().certification_data(),
        message.certification_data()
    );
    assert_eq!(verified.message().message_id(), message.message_id());
    assert_eq!(
        verified.signature().signer_certificate(),
        provider_certificate()
    );
}

#[test]
fn changed_signed_content_is_detected() {
    let raw = fixture("messages/delivery-full.eml");
    let text = core::str::from_utf8(&raw).expect("ASCII fixture");
    let changed = text.replacen(
        "Ricevuta di avvenuta consegna",
        "Ricevuta di avvenuta consegnA",
        1,
    );
    assert_eq!(
        verify(changed.as_bytes()).expect_err("changed content"),
        Error::Signature(SignatureError::ContentChanged)
    );
}

#[test]
fn unsigned_message_has_no_provider_signature() {
    let raw = fixture("messages/delivery-full.eml");
    let text = core::str::from_utf8(&raw).expect("ASCII fixture");
    let headers = &text[..text.find("MIME-Version:").expect("a MIME-Version header")];
    let unsigned = [
        headers.as_bytes(),
        b"MIME-Version: 1.0\r\n",
        signed_content(&raw),
        b"\r\n",
    ]
    .concat();
    assert_eq!(
        verify(&unsigned).expect_err("no signature"),
        Error::NotSigned
    );
}

#[test]
fn signed_message_with_another_protocol_has_no_provider_signature() {
    let raw = fixture("messages/acceptance.eml");
    let text = core::str::from_utf8(&raw).expect("ASCII fixture");
    let pgp = text.replacen(
        "protocol=\"application/x-pkcs7-signature\"",
        "protocol=\"application/pgp-signature\"",
        1,
    );
    assert_eq!(
        verify(pgp.as_bytes()).expect_err("an OpenPGP signature"),
        Error::NotSigned
    );
}

#[test]
fn signature_part_must_hold_signed_data() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify(&with_signature(&raw, b"not a ContentInfo")).expect_err("not CMS"),
        Error::Signature(SignatureError::Malformed)
    );
}

#[test]
fn signature_must_be_detached() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    data.encap_content_info.econtent =
        Some(Any::new(Tag::OctetString, signed_content(&raw)).expect("content"));
    assert_eq!(
        verify(&with_signed_data(&raw, &data)).expect_err("encapsulated content"),
        Error::Signature(SignatureError::Malformed)
    );
}

#[test]
fn exactly_one_signer_is_accepted() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let first = take_signer(&mut data);
    let mut second = first.clone();
    second.sid = SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
        OctetString::new(vec![1, 2, 3]).expect("an octet string"),
    ));
    assert_eq!(
        verify(&with_signed_data(
            &raw,
            &with_signers(data, vec![first, second])
        ))
        .expect_err("two signers"),
        Error::Signature(SignatureError::Malformed)
    );
}

#[test]
fn signer_certificate_must_be_included() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    data.certificates = None;
    assert_eq!(
        verify(&with_signed_data(&raw, &data)).expect_err("no certificate"),
        Error::Signature(SignatureError::UnknownSigner)
    );
}

#[test]
fn other_certificate_formats_never_name_the_signer() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    data.certificates = Some(CertificateSet(
        SetOfVec::try_from(vec![CertificateChoices::Other(OtherCertificateFormat {
            other_cert_format: ID_DATA,
            other_cert: Any::encode_from(&ID_DATA).expect("encodable OID"),
        })])
        .expect("one certificate"),
    ));
    assert_eq!(
        verify(&with_signed_data(&raw, &data)).expect_err("no X.509 certificate"),
        Error::Signature(SignatureError::UnknownSigner)
    );
}

#[test]
fn signer_is_named_by_issuer_and_serial_number_together() {
    let raw = fixture("messages/acceptance.eml");
    let provider =
        Certificate::from_der(&provider_certificate()).expect("the provider certificate");
    let other = Certificate::from_der(&fixture("pki/signers/dns.der")).expect("another signer");
    for (issuer, serial_number) in [
        (
            provider.tbs_certificate().issuer(),
            other.tbs_certificate().serial_number(),
        ),
        (
            provider.tbs_certificate().subject(),
            provider.tbs_certificate().serial_number(),
        ),
    ] {
        let mut data = signed_data(&raw);
        let mut only = take_signer(&mut data);
        only.sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: issuer.clone(),
            serial_number: serial_number.clone(),
        });
        assert_eq!(
            verify(&with_signed_data(&raw, &with_signers(data, vec![only])))
                .expect_err("no certificate named"),
            Error::Signature(SignatureError::UnknownSigner)
        );
    }
}

#[test]
fn non_rsa_signer_key_is_refused() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let original = provider_certificate();
    // md2WithRSAEncryption has the length of rsaEncryption, so only the key's algorithm changes.
    let rsa_encryption = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let mut edited = provider_certificate();
    let at = edited
        .windows(rsa_encryption.len())
        .position(|window| window == rsa_encryption)
        .expect("an RSA key");
    edited[at + rsa_encryption.len() - 1] = 0x02;
    let mut edited = Some(Certificate::from_der(&edited).expect("the edited certificate"));
    let certificates = data
        .certificates
        .take()
        .expect("certificates")
        .0
        .into_vec()
        .into_iter()
        .map(|choice| match choice {
            CertificateChoices::Certificate(certificate)
                if certificate.to_der().expect("encodable certificate") == original =>
            {
                CertificateChoices::Certificate(edited.take().expect("one provider certificate"))
            }
            other => other,
        })
        .collect::<Vec<_>>();
    data.certificates = Some(CertificateSet(
        SetOfVec::try_from(certificates).expect("distinct certificates"),
    ));
    assert_eq!(
        verify(&with_signed_data(&raw, &data)).expect_err("not an RSA key"),
        Error::Signature(SignatureError::UnsupportedAlgorithm(
            "1.2.840.113549.1.1.2".to_owned()
        ))
    );
}

#[test]
fn signer_may_be_named_by_its_key_identifier() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let certificate =
        Certificate::from_der(&provider_certificate()).expect("the provider certificate");
    let (_, key_identifier) = certificate
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .expect("decodable extensions")
        .expect("a subject key identifier");
    let mut only = take_signer(&mut data);
    only.sid = SignerIdentifier::SubjectKeyIdentifier(key_identifier);
    let signature = verify(&with_signed_data(&raw, &with_signers(data, vec![only])))
        .expect("a valid signature");
    assert_eq!(signature.signer_certificate(), provider_certificate());
}

#[test]
fn sha1_digest_is_refused() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    only.digest_alg.oid = ID_SHA_1;
    assert_eq!(
        verify(&with_signed_data(&raw, &with_signers(data, vec![only]))).expect_err("SHA-1"),
        Error::Signature(SignatureError::UnsupportedAlgorithm(ID_SHA_1.to_string()))
    );
}

#[test]
fn non_rsa_signature_is_refused() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    only.signature_algorithm.oid = ECDSA_WITH_SHA_256;
    assert_eq!(
        verify(&with_signed_data(&raw, &with_signers(data, vec![only]))).expect_err("ECDSA"),
        Error::Signature(SignatureError::UnsupportedAlgorithm(
            ECDSA_WITH_SHA_256.to_string()
        ))
    );
}

#[test]
fn signature_hash_must_match_the_digest() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    only.digest_alg.oid = ID_SHA_512;
    only.signature_algorithm.oid = SHA_256_WITH_RSA;
    assert_eq!(
        verify(&with_signed_data(&raw, &with_signers(data, vec![only])))
            .expect_err("mismatched hash"),
        Error::Signature(SignatureError::UnsupportedAlgorithm(
            SHA_256_WITH_RSA.to_string()
        ))
    );
}

#[test]
fn sha256_with_rsa_encryption_verifies() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    only.signature_algorithm.oid = SHA_256_WITH_RSA;
    verify(&with_signed_data(&raw, &with_signers(data, vec![only]))).expect("a valid signature");
}

#[test]
fn sha512_with_plain_rsa_encryption_verifies() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    only.digest_alg.oid = ID_SHA_512;
    only.signature_algorithm.oid = RSA_ENCRYPTION;
    let digest = OctetString::new(Sha512::digest(signed_content(&raw)).to_vec()).expect("a digest");
    let attrs = replaced(
        take_attributes(&mut only),
        ID_MESSAGE_DIGEST,
        Any::encode_from(&digest).expect("encodable digest"),
    );
    resign::<Sha512>(&mut only, attrs);
    verify(&with_signed_data(&raw, &with_signers(data, vec![only]))).expect("a valid signature");
}

#[test]
fn signed_attributes_are_required() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    only.signed_attrs = None;
    assert_eq!(
        verify(&with_signed_data(&raw, &with_signers(data, vec![only])))
            .expect_err("no signed attributes"),
        Error::Signature(SignatureError::Malformed)
    );
}

#[test]
fn content_type_must_be_data() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    let attrs = replaced(
        take_attributes(&mut only),
        ID_CONTENT_TYPE,
        Any::encode_from(&ID_SIGNED_DATA).expect("encodable OID"),
    );
    resign::<Sha256>(&mut only, attrs);
    assert_eq!(
        verify(&with_signed_data(&raw, &with_signers(data, vec![only])))
            .expect_err("wrong content type"),
        Error::Signature(SignatureError::Malformed)
    );
}

#[test]
fn message_digest_is_required() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    let mut attrs = take_attributes(&mut only);
    attrs.retain(|attr| attr.oid != ID_MESSAGE_DIGEST);
    resign::<Sha256>(&mut only, attrs);
    assert_eq!(
        verify(&with_signed_data(&raw, &with_signers(data, vec![only]))).expect_err("no digest"),
        Error::Signature(SignatureError::Malformed)
    );
}

#[test]
fn signing_time_must_be_a_time() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    let attrs = replaced(
        take_attributes(&mut only),
        ID_SIGNING_TIME,
        Any::encode_from(&ID_DATA).expect("encodable OID"),
    );
    resign::<Sha256>(&mut only, attrs);
    assert_eq!(
        verify(&with_signed_data(&raw, &with_signers(data, vec![only]))).expect_err("not a time"),
        Error::Signature(SignatureError::Malformed)
    );
}

#[test]
fn signing_time_is_optional() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    let mut attrs = take_attributes(&mut only);
    attrs.retain(|attr| attr.oid != ID_SIGNING_TIME);
    resign::<Sha256>(&mut only, attrs);
    let signature = verify(&with_signed_data(&raw, &with_signers(data, vec![only])))
        .expect("a valid signature");
    assert_eq!(signature.claimed_signing_time(), None);
}

#[test]
fn forged_signature_is_detected() {
    let raw = fixture("messages/acceptance.eml");
    let mut data = signed_data(&raw);
    let mut only = take_signer(&mut data);
    let mut bytes = only.signature.into_bytes();
    bytes[0] ^= 1;
    only.signature = OctetString::new(bytes).expect("an octet string");
    assert_eq!(
        verify(&with_signed_data(&raw, &with_signers(data, vec![only])))
            .expect_err("forged signature"),
        Error::Signature(SignatureError::BadSignature)
    );
}

#[test]
fn signer_must_chain_to_a_given_anchor() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_with(&raw, AGID_PROVIDER_CAS, now()).expect_err("a test signer"),
        Error::Signature(SignatureError::UnknownIssuer)
    );
}

#[test]
fn subtree_bounds_refuse_the_anchor() {
    let raw = fixture("messages/acceptance.eml");
    for name in ["minimum", "maximum"] {
        assert_eq!(
            verify_with(&raw, &[&anchor(name)], now()).expect_err(name),
            Error::Signature(SignatureError::InvalidAnchor),
            "{name}"
        );
    }
}

#[test]
fn unreadable_anchor_constraints_refuse_the_anchor() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_with(&raw, &[&anchor("unreadable-constraints")], now())
            .expect_err("constraints the crate cannot read"),
        Error::Signature(SignatureError::InvalidAnchor)
    );
}

#[test]
fn anchor_must_be_a_certificate() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_with(&raw, &[b"not a certificate"], now()).expect_err("no anchor"),
        Error::Signature(SignatureError::InvalidAnchor)
    );
}

#[test]
fn signer_must_be_valid_at_the_validation_time() {
    let raw = fixture("messages/acceptance.eml");
    let anchor = anchor("agid-like");
    for (at, expected) in [
        ("2026-01-01T00:00:00Z", SignatureError::NotYetValid),
        ("1969-12-31T23:59:59Z", SignatureError::NotYetValid),
        ("2127-01-01T00:00:00Z", SignatureError::Expired),
    ] {
        assert_eq!(
            verify_with(&raw, &[&anchor], time(at)).expect_err(at),
            Error::Signature(expected),
            "{at}"
        );
    }
}

#[test]
fn email_constraints_follow_rfc_5280() {
    let raw = fixture("messages/acceptance.eml");
    for (name, permitted) in [
        ("agid-like", true),
        ("unconstrained", true),
        ("mailbox", true),
        ("subdomains", true),
        ("other-mailbox", false),
        ("subdomains-only", false),
        ("other-host", false),
        ("excluded-host", false),
    ] {
        let expected = if permitted {
            Ok(())
        } else {
            Err(Error::Signature(SignatureError::OutsideNameConstraints))
        };
        assert_eq!(
            verify_with(&raw, &[&anchor(name)], now()).map(|_| ()),
            expected,
            "{name}"
        );
    }
}

#[test]
fn subject_must_start_with_a_permitted_directory_name() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_with(&raw, &[&anchor("other-organisation")], now()).expect_err("another provider"),
        Error::Signature(SignatureError::OutsideNameConstraints)
    );
}

#[test]
fn excluded_directory_names_refuse_the_anchor() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_with(&raw, &[&anchor("excluded-organisation")], now())
            .expect_err("an exclusion the crate does not compare"),
        Error::Signature(SignatureError::OutsideNameConstraints)
    );
}

#[test]
fn constraints_on_other_name_forms_stay_enforced() {
    let raw = signed_by(&fixture("messages/acceptance.eml"), "dns");
    assert_eq!(
        verify(&raw).expect_err("an excluded DNS name"),
        Error::Signature(SignatureError::OutsideNameConstraints)
    );
    verify_with(&raw, &[&anchor("unconstrained")], now()).expect("no constraint");
}

#[test]
fn signer_must_allow_digital_signatures() {
    let raw = signed_by(&fixture("messages/acceptance.eml"), "no-signing");
    assert_eq!(
        verify(&raw).expect_err("a key for encipherment only"),
        Error::Signature(SignatureError::NotForSigning)
    );
}

#[test]
fn signer_must_be_for_email_protection() {
    let raw = signed_by(&fixture("messages/acceptance.eml"), "no-email");
    assert_eq!(
        verify(&raw).expect_err("a client authentication certificate"),
        Error::Signature(SignatureError::NotForEmail)
    );
}

#[test]
fn unknown_critical_extension_is_refused() {
    let raw = signed_by(&fixture("messages/acceptance.eml"), "critical");
    assert!(matches!(
        verify(&raw).expect_err("an unknown critical extension"),
        Error::Signature(SignatureError::InvalidCertificate(_))
    ));
}

#[test]
fn sha512_certificate_signature_verifies() {
    let raw = signed_by(&fixture("messages/acceptance.eml"), "sha512");
    verify(&raw).expect("a certificate signed with SHA-512");
}

#[test]
fn from_must_be_an_address_of_the_signer() {
    for (from, matches) in [
        (Some("posta-certificata@PEC.Example.IT"), true),
        (
            Some("\"Posta Certificata\" <posta-certificata@pec.example.it>"),
            true,
        ),
        (Some("Posta-Certificata@pec.example.it"), false),
        (Some("protocollo@pec.example.it"), false),
        (Some("posta-certificata"), false),
        (
            Some("attacker@example.it\r\nFrom: posta-certificata@pec.example.it"),
            false,
        ),
        (
            Some("posta-certificata@pec.example.it\r\nFrom: attacker@example.it"),
            false,
        ),
        (
            Some("posta-certificata@pec.example.it, protocollo@pec.example.it"),
            false,
        ),
        (Some("Gestore: posta-certificata@pec.example.it;"), false),
        (None, false),
    ] {
        let expected = if matches {
            Ok(())
        } else {
            Err(Error::Signature(SignatureError::SenderMismatch))
        };
        assert_eq!(
            verify(&acceptance_from(from)).map(|_| ()),
            expected,
            "{from:?}"
        );
    }
}

#[test]
fn a_crl_is_required() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_crls(&raw, &[], now()).expect_err("no CRL"),
        Error::Signature(SignatureError::NoUsableCrl { urls: Vec::new() })
    );
}

#[test]
fn missing_crl_names_where_the_signer_publishes_it() {
    let raw = signed_by(&fixture("messages/acceptance.eml"), "distribution-points");
    assert_eq!(
        verify_crls(&raw, &[], now()).expect_err("no CRL"),
        Error::Signature(SignatureError::NoUsableCrl {
            urls: vec![
                "http://crl.pec.example.it/CRL".to_owned(),
                "ldap://crl.pec.example.it/cn=PEC%20Test%20CA1".to_owned(),
            ]
        })
    );
    verify_crls(&raw, &[&crl("current")], now()).expect("a CRL of its CA");
}

#[test]
fn stale_crl_is_not_used() {
    let raw = fixture("messages/acceptance.eml");
    let stale = crl("stale");
    for at in ["2027-02-02T00:00:00Z", "2030-01-01T00:00:00Z"] {
        assert_eq!(
            verify_crls(&raw, &[&stale], time(at))
                .expect_err("nextUpdate at or before the validation time"),
            Error::Signature(SignatureError::NoUsableCrl { urls: Vec::new() }),
            "{at}"
        );
    }
    verify_crls(&raw, &[&stale], time("2027-02-01T23:59:59Z")).expect("fresh until nextUpdate");
}

#[test]
fn crl_issued_after_the_signer_expired_is_not_used() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_crls(&raw, &[&crl("after-expiry")], now()).expect_err("may have dropped the signer"),
        Error::Signature(SignatureError::NoUsableCrl { urls: Vec::new() })
    );
}

#[test]
fn crl_issued_before_its_ca_is_not_used() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_crls(&raw, &[&crl("before-ca")], now()).expect_err("thisUpdate before the CA"),
        Error::Signature(SignatureError::NoUsableCrl { urls: Vec::new() })
    );
}

#[test]
fn crls_of_other_cas_are_ignored() {
    let raw = fixture("messages/acceptance.eml");
    let other = crl("other-ca");
    assert_eq!(
        verify_crls(&raw, &[&other], now()).expect_err("only another CA's CRL"),
        Error::Signature(SignatureError::NoUsableCrl { urls: Vec::new() })
    );
    verify_crls(&raw, &[&other, &crl("current")], now()).expect("a CRL of the signer's CA");
}

#[test]
fn revocation_counts_from_its_date() {
    let raw = fixture("messages/acceptance.eml");
    let revoked = crl("revoked");
    verify_crls(&raw, &[&revoked], time("2026-12-31T23:59:59Z")).expect("revoked later");
    for at in ["2027-01-01T00:00:00Z", "2030-01-01T00:00:00Z"] {
        assert_eq!(
            verify_crls(&raw, &[&revoked], time(at)).expect_err(at),
            Error::Signature(SignatureError::Revoked {
                revoked_at: time("2027-01-01T00:00:00Z")
            }),
            "{at}"
        );
    }
}

#[test]
fn the_latest_crl_counts() {
    let raw = fixture("messages/acceptance.eml");
    let (current, revoked) = (crl("current"), crl("revoked"));
    for crls in [[&current[..], &revoked[..]], [&revoked[..], &current[..]]] {
        assert!(matches!(
            verify_crls(&raw, &crls, now()).expect_err("revoked in the later CRL"),
            Error::Signature(SignatureError::Revoked { .. })
        ));
    }
}

#[test]
fn crls_sharing_the_latest_update_decide_together() {
    let raw = fixture("messages/acceptance.eml");
    let (stale, revoked, fresh) = (crl("stale"), crl("revoked"), crl("tied-fresh"));
    for crls in [[&stale[..], &revoked[..]], [&revoked[..], &stale[..]]] {
        assert_eq!(
            verify_crls(&raw, &crls, time("2027-02-01T12:00:00Z"))
                .expect_err("revoked in a tied CRL"),
            Error::Signature(SignatureError::Revoked {
                revoked_at: time("2027-01-01T00:00:00Z")
            })
        );
    }
    for crls in [[&stale[..], &fresh[..]], [&fresh[..], &stale[..]]] {
        verify_crls(&raw, &crls, time("2027-02-03T00:00:00Z")).expect("a tied CRL is fresh");
    }
}

#[test]
fn forged_crl_is_refused() {
    let raw = fixture("messages/acceptance.eml");
    let mut forged = crl("current");
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_eq!(
        verify_crls(&raw, &[&forged], now()).expect_err("a broken CRL signature"),
        Error::Signature(SignatureError::InvalidCrl)
    );
}

#[test]
fn crl_with_a_critical_extension_is_refused() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_crls(&raw, &[&crl("critical")], now()).expect_err("an unknown critical extension"),
        Error::Signature(SignatureError::InvalidCrl)
    );
}

#[test]
fn unreadable_crl_is_refused() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_crls(&raw, &[b"not a CRL"], now()).expect_err("not a CRL"),
        Error::Signature(SignatureError::InvalidCrl)
    );
}

#[test]
fn signer_without_an_expiration_date_is_checked_against_the_crl() {
    let raw = signed_by(&fixture("messages/acceptance.eml"), "no-expiry");
    verify(&raw).expect("a CRL issued before 9999-12-31");
}

#[test]
fn an_older_fresh_crl_cannot_hide_a_newer_stale_one() {
    let raw = fixture("messages/acceptance.eml");
    let (current, stale, stale_revoked) = (crl("current"), crl("stale"), crl("stale-revoked"));
    for crls in [
        [&current[..], &stale_revoked[..]],
        [&stale_revoked[..], &current[..]],
    ] {
        assert_eq!(
            verify_crls(&raw, &crls, now()).expect_err("revoked in the newer CRL"),
            Error::Signature(SignatureError::Revoked {
                revoked_at: time("2027-01-01T00:00:00Z")
            })
        );
    }
    for crls in [[&current[..], &stale[..]], [&stale[..], &current[..]]] {
        assert_eq!(
            verify_crls(&raw, &crls, now()).expect_err("the newer CRL is stale"),
            Error::Signature(SignatureError::NoUsableCrl { urls: Vec::new() })
        );
    }
}

#[test]
fn crl_of_a_ca_not_allowed_to_sign_crls_is_refused() {
    let raw = fixture("messages/acceptance.eml");
    assert_eq!(
        verify_full(&raw, &[&anchor("no-crl-sign")], &[&crl("current")], now())
            .expect_err("a keyUsage without cRLSign"),
        Error::Signature(SignatureError::InvalidCrl)
    );
}
