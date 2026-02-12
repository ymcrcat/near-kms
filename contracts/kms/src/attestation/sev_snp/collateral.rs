/// SEV-SNP collateral: certificates supplied by the caller for offline verification.
///
/// Following the same pattern as TDX DCAP collateral — the caller fetches these
/// from the AMD Key Distribution Service (KDS) before calling the contract.
use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
use alloc::string::ToString;

/// Collateral for AMD SEV-SNP attestation verification.
///
/// The caller provides:
/// - The VCEK certificate (chip-specific, obtained from AMD KDS)
/// - Optionally the ASK certificate (if not provided, the embedded one is used)
/// - The processor model name to select the correct embedded root certificate
#[derive(Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct SevSnpCollateral {
    /// VCEK certificate in DER format.
    /// The VCEK (Versioned Chip Endorsement Key) is unique per chip and TCB version.
    /// It contains an ECDSA P-384 public key used to sign attestation reports.
    pub vcek_cert_der: Vec<u8>,

    /// Optional ASK (AMD SEV Key) certificate in DER format.
    /// If not provided, the embedded ASK for the processor model is used.
    pub ask_cert_der: Option<Vec<u8>>,

    /// AMD processor generation: "Milan", "Genoa", or "Turin".
    /// Used to select the correct embedded AMD Root Key (ARK) certificate.
    pub processor_model: String,
}
