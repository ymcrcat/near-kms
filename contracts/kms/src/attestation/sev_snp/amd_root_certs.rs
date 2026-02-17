/// Embedded AMD root certificates (ARK and ASK) for SEV-SNP attestation verification.
///
/// These are the trust anchors — equivalent to Intel's SGX Root CA embedded in `dcap-qvl`.
/// AMD publishes these certificates at: <https://kdsintf.amd.com/vcek/v1/{model}/cert_chain>
///
/// The ARK (AMD Root Key) is the root of trust. It signs the ASK (AMD SEV Key),
/// which in turn signs chip-specific VCEK certificates.
///
/// Both ARK and ASK use RSA 4096-bit keys with RSASSA-PSS SHA-384 signatures.
/// AMD Root Key for Milan (EPYC 7003 series) in DER format.
pub const ARK_MILAN_DER: &[u8] = include_bytes!("../assets/ark_milan.der");

/// AMD SEV Key for Milan (EPYC 7003 series) in DER format.
pub const ASK_MILAN_DER: &[u8] = include_bytes!("../assets/ask_milan.der");

/// AMD Root Key for Genoa (EPYC 9004 series) in DER format.
pub const ARK_GENOA_DER: &[u8] = include_bytes!("../assets/ark_genoa.der");

/// AMD SEV Key for Genoa (EPYC 9004 series) in DER format.
pub const ASK_GENOA_DER: &[u8] = include_bytes!("../assets/ask_genoa.der");

/// Get the ARK certificate DER bytes for the given processor model.
pub fn get_ark_der(processor_model: &str) -> Option<&'static [u8]> {
    match processor_model {
        "Milan" => Some(ARK_MILAN_DER),
        "Genoa" | "Siena" => Some(ARK_GENOA_DER),
        _ => None,
    }
}

/// Get the ASK certificate DER bytes for the given processor model.
pub fn get_ask_der(processor_model: &str) -> Option<&'static [u8]> {
    match processor_model {
        "Milan" => Some(ASK_MILAN_DER),
        "Genoa" | "Siena" => Some(ASK_GENOA_DER),
        _ => None,
    }
}
