/// AMD SEV-SNP attestation report signature verification and certificate chain validation.
///
/// Uses `ring` (already in the dependency tree via `dcap-qvl`) for:
/// - ECDSA P-384 SHA-384 report signature verification
/// - RSA-PSS SHA-384 certificate chain verification (ARK -> ASK -> VCEK)
///
/// Implements minimal X.509 DER parsing to extract only the fields needed:
/// - TBS Certificate (To-Be-Signed) bytes for signature input
/// - `SubjectPublicKeyInfo` for the signer's public key
/// - Signature value from the certificate
use alloc::{format, string::String, vec::Vec};
use ring::signature::{self, UnparsedPublicKey};

use super::collateral::SevSnpCollateral;
use super::report::SevSnpReport;

/// Verify the full SEV-SNP attestation: certificate chain + report signature.
///
/// Steps:
/// 1. Load embedded ARK certificate for the processor model
/// 2. Verify ASK certificate signature using ARK's RSA public key
/// 3. Verify VCEK certificate signature using ASK's RSA public key
/// 4. Verify report signature using VCEK's ECDSA P-384 public key
pub fn verify_attestation(
    raw_report: &[u8],
    report: &SevSnpReport,
    collateral: &SevSnpCollateral,
) -> Result<(), VerificationError> {
    // Step 1: Get embedded root certificates
    let ark_der =
        super::amd_root_certs::get_ark_der(&collateral.processor_model).ok_or_else(|| {
            VerificationError::UnsupportedProcessor(collateral.processor_model.clone())
        })?;

    let ask_der =
        match &collateral.ask_cert_der {
            Some(der) => der.as_slice(),
            None => super::amd_root_certs::get_ask_der(&collateral.processor_model).ok_or_else(
                || VerificationError::UnsupportedProcessor(collateral.processor_model.clone()),
            )?,
        };

    // Step 2: Verify ASK is signed by ARK (RSA-PSS SHA-384)
    verify_cert_signature(ark_der, ask_der, SignatureKind::RsaPss)
        .map_err(|e| VerificationError::AskSignature(format!("{e}")))?;

    // Step 3: Verify VCEK is signed by ASK (RSA-PSS SHA-384)
    verify_cert_signature(ask_der, &collateral.vcek_cert_der, SignatureKind::RsaPss)
        .map_err(|e| VerificationError::VcekSignature(format!("{e}")))?;

    // Step 4: Verify report signature using VCEK's ECDSA P-384 public key
    let vcek_pubkey = extract_subject_public_key_info_bytes(&collateral.vcek_cert_der)
        .map_err(|e| VerificationError::VcekPubKey(format!("{e}")))?;
    verify_report_signature(raw_report, report, &vcek_pubkey)?;

    Ok(())
}

/// Verify the ECDSA P-384 signature on the attestation report.
pub fn verify_report_signature(
    raw_report: &[u8],
    _report: &SevSnpReport,
    vcek_ec_pubkey_der: &[u8],
) -> Result<(), VerificationError> {
    let signed_data = SevSnpReport::signed_bytes(raw_report);
    let sig_bytes = SevSnpReport::signature_fixed(raw_report);

    let public_key =
        UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, vcek_ec_pubkey_der);

    public_key
        .verify(signed_data, &sig_bytes)
        .map_err(|_| VerificationError::ReportSignature)
}

#[derive(Debug)]
pub enum VerificationError {
    UnsupportedProcessor(String),
    AskSignature(String),
    VcekSignature(String),
    VcekPubKey(String),
    ReportSignature,
    DerParse(String),
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedProcessor(model) => {
                write!(f, "Unsupported processor model: {model}")
            }
            Self::AskSignature(e) => write!(f, "ASK signature verification failed: {e}"),
            Self::VcekSignature(e) => write!(f, "VCEK signature verification failed: {e}"),
            Self::VcekPubKey(e) => write!(f, "Failed to extract VCEK public key: {e}"),
            Self::ReportSignature => write!(f, "Report signature verification failed"),
            Self::DerParse(e) => write!(f, "DER parsing error: {e}"),
        }
    }
}

/// Which signature algorithm to use for certificate verification.
#[derive(Clone, Copy)]
enum SignatureKind {
    RsaPss,
}

/// Verify that `child_cert_der` was signed by the key in `parent_cert_der`.
fn verify_cert_signature(
    parent_cert_der: &[u8],
    child_cert_der: &[u8],
    kind: SignatureKind,
) -> Result<(), VerificationError> {
    let parent_spki = extract_subject_public_key_info_bytes(parent_cert_der)?;
    let child_tbs = extract_tbs_certificate_bytes(child_cert_der)?;
    let child_sig = extract_signature_value(child_cert_der)?;

    match kind {
        SignatureKind::RsaPss => {
            // AMD ARK/ASK use RSA 4096-bit with RSASSA-PSS SHA-384
            let public_key =
                UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA384, parent_spki);
            public_key
                .verify(child_tbs, &child_sig)
                .map_err(|_| VerificationError::DerParse("RSA-PSS signature mismatch".into()))
        }
    }
}

// =============================================================================
// Minimal X.509 DER parsing
//
// X.509 certificates have this top-level ASN.1 structure:
//
// Certificate ::= SEQUENCE {
//     tbsCertificate       TBSCertificate,        -- SEQUENCE (element 0)
//     signatureAlgorithm   AlgorithmIdentifier,    -- SEQUENCE (element 1)
//     signatureValue       BIT STRING              -- element 2
// }
//
// TBSCertificate ::= SEQUENCE {
//     ...
//     subjectPublicKeyInfo SubjectPublicKeyInfo,   -- element 6 (index 6)
//     ...
// }
//
// SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm            AlgorithmIdentifier,
//     subjectPublicKey     BIT STRING
// }
//
// We extract:
// - TBS Certificate raw bytes (for signature verification input)
// - SubjectPublicKeyInfo's subjectPublicKey bit string content (the actual key bytes)
// - Signature value bit string content
// =============================================================================

/// ASN.1 tag for SEQUENCE
const TAG_SEQUENCE: u8 = 0x30;
/// ASN.1 tag for BIT STRING
const TAG_BIT_STRING: u8 = 0x03;
/// ASN.1 tag for context-specific constructed [0] (version)
const TAG_CONTEXT_0: u8 = 0xA0;

/// Read a DER tag and length, returning (`content_start`, `content_length`, `total_element_length`).
fn der_read_tl(data: &[u8], offset: usize) -> Result<(usize, usize, usize), VerificationError> {
    if offset >= data.len() {
        return Err(VerificationError::DerParse("offset out of bounds".into()));
    }
    let len_start = offset + 1;
    if len_start >= data.len() {
        return Err(VerificationError::DerParse("truncated after tag".into()));
    }

    let first_len_byte = data[len_start];
    if first_len_byte < 0x80 {
        // Short form
        let content_start = len_start + 1;
        let content_length = first_len_byte as usize;
        let total = content_start - offset + content_length;
        Ok((content_start, content_length, total))
    } else {
        // Long form
        let num_len_bytes = (first_len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return Err(VerificationError::DerParse(
                "unsupported length encoding".into(),
            ));
        }
        let mut content_length: usize = 0;
        for i in 0..num_len_bytes {
            let idx = len_start + 1 + i;
            if idx >= data.len() {
                return Err(VerificationError::DerParse("truncated length".into()));
            }
            content_length = (content_length << 8) | (data[idx] as usize);
        }
        let content_start = len_start + 1 + num_len_bytes;
        let total = content_start - offset + content_length;
        Ok((content_start, content_length, total))
    }
}

/// Extract the raw TBS Certificate bytes from a DER-encoded X.509 certificate.
/// This is the first element of the outer SEQUENCE, including its tag and length.
fn extract_tbs_certificate_bytes(cert_der: &[u8]) -> Result<&[u8], VerificationError> {
    // Outer SEQUENCE
    if cert_der.is_empty() || cert_der[0] != TAG_SEQUENCE {
        return Err(VerificationError::DerParse("not a SEQUENCE".into()));
    }
    let (outer_content_start, _, _) = der_read_tl(cert_der, 0)?;

    // First element: TBS Certificate (also a SEQUENCE)
    let tbs_start = outer_content_start;
    let (_, _, tbs_total_len) = der_read_tl(cert_der, tbs_start)?;

    Ok(&cert_der[tbs_start..tbs_start + tbs_total_len])
}

/// Extract the signature value from a DER-encoded X.509 certificate.
/// This is the third element of the outer SEQUENCE (a BIT STRING).
fn extract_signature_value(cert_der: &[u8]) -> Result<Vec<u8>, VerificationError> {
    if cert_der.is_empty() || cert_der[0] != TAG_SEQUENCE {
        return Err(VerificationError::DerParse("not a SEQUENCE".into()));
    }
    let (outer_content_start, _, _) = der_read_tl(cert_der, 0)?;

    // Element 0: TBS Certificate
    let (_, _, tbs_total) = der_read_tl(cert_der, outer_content_start)?;
    let after_tbs = outer_content_start + tbs_total;

    // Element 1: SignatureAlgorithm
    let (_, _, sig_algo_total) = der_read_tl(cert_der, after_tbs)?;
    let after_sig_algo = after_tbs + sig_algo_total;

    // Element 2: SignatureValue (BIT STRING)
    if after_sig_algo >= cert_der.len() || cert_der[after_sig_algo] != TAG_BIT_STRING {
        return Err(VerificationError::DerParse(
            "expected BIT STRING for signature".into(),
        ));
    }
    let (sig_content_start, sig_content_length, _) = der_read_tl(cert_der, after_sig_algo)?;

    if sig_content_length == 0 {
        return Err(VerificationError::DerParse("empty signature".into()));
    }

    // BIT STRING has a leading "unused bits" byte; for RSA/ECDSA signatures it's always 0
    Ok(cert_der[sig_content_start + 1..sig_content_start + sig_content_length].to_vec())
}

/// Extract the public key bytes from a DER-encoded X.509 certificate's `SubjectPublicKeyInfo`.
///
/// Returns the content of the BIT STRING inside `SubjectPublicKeyInfo` (after the
/// "unused bits" byte), which is:
/// - For RSA keys: the DER-encoded `RSAPublicKey` SEQUENCE { modulus, exponent } (PKCS#1 format)
/// - For EC keys: the uncompressed EC point (0x04 || x || y)
///
/// This is what `ring`'s `UnparsedPublicKey` expects for both RSA and ECDSA algorithms.
fn extract_subject_public_key_info_bytes(cert_der: &[u8]) -> Result<Vec<u8>, VerificationError> {
    let (outer_content_start, _, _) = der_read_tl(cert_der, 0)?;

    // TBS Certificate is the first element
    let tbs_start = outer_content_start;
    let (tbs_content_start, _, _) = der_read_tl(cert_der, tbs_start)?;

    // Walk through TBS Certificate fields to find SubjectPublicKeyInfo (field index 6)
    // Fields: version[0], serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    // Note: version is context-tagged [0] and OPTIONAL (but always present in v3 certs)
    let mut pos = tbs_content_start;

    // If the first element is context [0] (version), skip it
    let mut field_index: usize = if pos < cert_der.len() && cert_der[pos] == TAG_CONTEXT_0 {
        let (_, _, total) = der_read_tl(cert_der, pos)?;
        pos += total;
        1 // version was field 0, next is serialNumber
    } else {
        0
    };

    // Skip fields until we reach subjectPublicKeyInfo (field index 6)
    while field_index < 6 {
        if pos >= cert_der.len() {
            return Err(VerificationError::DerParse(
                "unexpected end of TBS certificate".into(),
            ));
        }
        let (_, _, total) = der_read_tl(cert_der, pos)?;
        pos += total;
        field_index += 1;
    }

    // pos now points to SubjectPublicKeyInfo SEQUENCE
    if pos >= cert_der.len() || cert_der[pos] != TAG_SEQUENCE {
        return Err(VerificationError::DerParse(
            "expected SEQUENCE for SubjectPublicKeyInfo".into(),
        ));
    }

    // Extract the BIT STRING content inside SubjectPublicKeyInfo
    let (spki_content_start, _, _spki_total) = der_read_tl(cert_der, pos)?;

    // Inside SPKI: AlgorithmIdentifier SEQUENCE, then BIT STRING (the key)
    let (_, _, algo_total) = der_read_tl(cert_der, spki_content_start)?;
    let key_bitstring_pos = spki_content_start + algo_total;

    if key_bitstring_pos >= cert_der.len() || cert_der[key_bitstring_pos] != TAG_BIT_STRING {
        return Err(VerificationError::DerParse(
            "expected BIT STRING for public key".into(),
        ));
    }

    let (key_content_start, key_content_length, _) = der_read_tl(cert_der, key_bitstring_pos)?;

    if key_content_length == 0 {
        return Err(VerificationError::DerParse("empty public key".into()));
    }

    // BIT STRING leading byte is "unused bits" (should be 0 for both RSA and ECDSA keys)
    let key_bytes = &cert_der[key_content_start + 1..key_content_start + key_content_length];
    Ok(key_bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tbs_from_ark_milan() {
        let ark_der = super::super::amd_root_certs::ARK_MILAN_DER;
        let tbs = extract_tbs_certificate_bytes(ark_der).unwrap();
        // TBS should start with SEQUENCE tag
        assert_eq!(tbs[0], TAG_SEQUENCE);
        // TBS should be significantly shorter than the full cert
        assert!(tbs.len() < ark_der.len());
        assert!(tbs.len() > 100); // but not trivially small
    }

    #[test]
    fn test_extract_signature_from_ark_milan() {
        let ark_der = super::super::amd_root_certs::ARK_MILAN_DER;
        let sig = extract_signature_value(ark_der).unwrap();
        // RSA 4096-bit signature should be 512 bytes
        assert_eq!(sig.len(), 512);
    }

    #[test]
    fn test_extract_pubkey_from_ark_milan() {
        let ark_der = super::super::amd_root_certs::ARK_MILAN_DER;
        let key_bytes = extract_subject_public_key_info_bytes(ark_der).unwrap();
        // RSA 4096: PKCS#1 RSAPublicKey SEQUENCE should be ~520-530 bytes
        assert!(key_bytes.len() > 500);
        // Should start with SEQUENCE tag (RSAPublicKey { modulus, exponent })
        assert_eq!(key_bytes[0], TAG_SEQUENCE);
    }

    #[test]
    fn test_extract_pubkey_from_ask_milan() {
        let ask_der = super::super::amd_root_certs::ASK_MILAN_DER;
        let key_bytes = extract_subject_public_key_info_bytes(ask_der).unwrap();
        // RSA 4096: PKCS#1 RSAPublicKey should be ~520 bytes
        assert!(key_bytes.len() > 500);
    }

    #[test]
    fn test_verify_ask_signed_by_ark_milan() {
        let ark_der = super::super::amd_root_certs::ARK_MILAN_DER;
        let ask_der = super::super::amd_root_certs::ASK_MILAN_DER;
        let result = verify_cert_signature(ark_der, ask_der, SignatureKind::RsaPss);
        assert!(result.is_ok(), "ASK should be signed by ARK: {result:?}");
    }

    #[test]
    fn test_verify_ask_signed_by_ark_genoa() {
        let ark_der = super::super::amd_root_certs::ARK_GENOA_DER;
        let ask_der = super::super::amd_root_certs::ASK_GENOA_DER;
        let result = verify_cert_signature(ark_der, ask_der, SignatureKind::RsaPss);
        assert!(result.is_ok(), "ASK should be signed by ARK: {result:?}");
    }

    #[test]
    fn test_verify_ark_self_signed_milan() {
        let ark_der = super::super::amd_root_certs::ARK_MILAN_DER;
        let result = verify_cert_signature(ark_der, ark_der, SignatureKind::RsaPss);
        assert!(result.is_ok(), "ARK should be self-signed: {result:?}");
    }

    #[test]
    fn test_verify_ark_self_signed_genoa() {
        let ark_der = super::super::amd_root_certs::ARK_GENOA_DER;
        let result = verify_cert_signature(ark_der, ark_der, SignatureKind::RsaPss);
        assert!(result.is_ok(), "ARK should be self-signed: {result:?}");
    }

    #[test]
    fn test_cross_family_rejection() {
        // Milan ARK should NOT validate Genoa ASK
        let ark_milan = super::super::amd_root_certs::ARK_MILAN_DER;
        let ask_genoa = super::super::amd_root_certs::ASK_GENOA_DER;
        let result = verify_cert_signature(ark_milan, ask_genoa, SignatureKind::RsaPss);
        assert!(result.is_err(), "Cross-family verification should fail");
    }
}
