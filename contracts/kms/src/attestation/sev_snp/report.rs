/// AMD SEV-SNP Attestation Report parsing.
///
/// Reference: AMD SEV-SNP Firmware ABI Specification, Table 23
/// <https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf>
use alloc::vec::Vec;

/// Total size of the SEV-SNP attestation report (0x4A0 = 1184 bytes).
pub const REPORT_SIZE: usize = 0x4A0;
/// Size of the signed portion of the report (bytes 0x000..0x2A0 = 672 bytes).
const SIGNED_SIZE: usize = 0x2A0;
/// ECDSA P-384 signature algorithm identifier.
const SIG_ALGO_ECDSA_P384: u32 = 1;

/// P-384 field element size in bytes.
const P384_FIELD_SIZE: usize = 48;
/// AMD stores each signature component (R, S) in 72-byte little-endian fields.
const AMD_SIG_COMPONENT_SIZE: usize = 72;

// Field offsets within the report
const VERSION_OFFSET: usize = 0x000;
const GUEST_SVN_OFFSET: usize = 0x004;
const POLICY_OFFSET: usize = 0x008;
const FAMILY_ID_OFFSET: usize = 0x010;
const IMAGE_ID_OFFSET: usize = 0x020;
const VMPL_OFFSET: usize = 0x030;
const SIG_ALGO_OFFSET: usize = 0x034;
const CURRENT_TCB_OFFSET: usize = 0x038;
const PLATFORM_INFO_OFFSET: usize = 0x040;
const AUTHOR_KEY_EN_OFFSET: usize = 0x048;
const REPORT_DATA_OFFSET: usize = 0x050;
const MEASUREMENT_OFFSET: usize = 0x090;
const HOST_DATA_OFFSET: usize = 0x0C0;
const ID_KEY_DIGEST_OFFSET: usize = 0x0E0;
const AUTHOR_KEY_DIGEST_OFFSET: usize = 0x110;
const REPORT_ID_OFFSET: usize = 0x140;
const REPORT_ID_MA_OFFSET: usize = 0x160;
const REPORTED_TCB_OFFSET: usize = 0x180;
const CHIP_ID_OFFSET: usize = 0x1A0;
const COMMITTED_TCB_OFFSET: usize = 0x1E0;
const CURRENT_BUILD_OFFSET: usize = 0x1E8;
const CURRENT_MINOR_OFFSET: usize = 0x1E9;
const CURRENT_MAJOR_OFFSET: usize = 0x1EA;
const COMMITTED_BUILD_OFFSET: usize = 0x1EC;
const COMMITTED_MINOR_OFFSET: usize = 0x1ED;
const COMMITTED_MAJOR_OFFSET: usize = 0x1EE;
const LAUNCH_TCB_OFFSET: usize = 0x1F0;
const SIG_R_OFFSET: usize = 0x2A0;
const SIG_S_OFFSET: usize = SIG_R_OFFSET + AMD_SIG_COMPONENT_SIZE; // 0x2E8

/// Parsed AMD SEV-SNP attestation report.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct SevSnpReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: u64,
    pub platform_info: u64,
    pub author_key_en: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: u64,
    pub chip_id: [u8; 64],
    pub committed_tcb: u64,
    pub current_build: u8,
    pub current_minor: u8,
    pub current_major: u8,
    pub committed_build: u8,
    pub committed_minor: u8,
    pub committed_major: u8,
    pub launch_tcb: u64,
}

/// Errors that can occur when parsing a SEV-SNP report.
#[derive(Debug)]
pub enum ReportParseError {
    /// Report is not the expected 0x4A0 bytes.
    InvalidLength(usize),
    /// Version field is not >= 2 (SNP requires version 2+).
    UnsupportedVersion(u32),
    /// Signature algorithm is not ECDSA P-384 (value 1).
    UnsupportedSignatureAlgo(u32),
}

impl core::fmt::Display for ReportParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(f, "Invalid report length: {len}, expected {REPORT_SIZE}")
            }
            Self::UnsupportedVersion(v) => write!(f, "Unsupported version: {v}, expected >= 2"),
            Self::UnsupportedSignatureAlgo(a) => {
                write!(
                    f,
                    "Unsupported signature algo: {a}, expected {SIG_ALGO_ECDSA_P384}"
                )
            }
        }
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N].try_into().unwrap()
}

impl SevSnpReport {
    /// Parse a SEV-SNP attestation report from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReportParseError> {
        if bytes.len() != REPORT_SIZE {
            return Err(ReportParseError::InvalidLength(bytes.len()));
        }

        let version = read_u32_le(bytes, VERSION_OFFSET);
        if version < 2 {
            return Err(ReportParseError::UnsupportedVersion(version));
        }

        let signature_algo = read_u32_le(bytes, SIG_ALGO_OFFSET);
        if signature_algo != SIG_ALGO_ECDSA_P384 {
            return Err(ReportParseError::UnsupportedSignatureAlgo(signature_algo));
        }

        Ok(Self {
            version,
            guest_svn: read_u32_le(bytes, GUEST_SVN_OFFSET),
            policy: read_u64_le(bytes, POLICY_OFFSET),
            family_id: read_array(bytes, FAMILY_ID_OFFSET),
            image_id: read_array(bytes, IMAGE_ID_OFFSET),
            vmpl: read_u32_le(bytes, VMPL_OFFSET),
            signature_algo,
            current_tcb: read_u64_le(bytes, CURRENT_TCB_OFFSET),
            platform_info: read_u64_le(bytes, PLATFORM_INFO_OFFSET),
            author_key_en: read_u32_le(bytes, AUTHOR_KEY_EN_OFFSET),
            report_data: read_array(bytes, REPORT_DATA_OFFSET),
            measurement: read_array(bytes, MEASUREMENT_OFFSET),
            host_data: read_array(bytes, HOST_DATA_OFFSET),
            id_key_digest: read_array(bytes, ID_KEY_DIGEST_OFFSET),
            author_key_digest: read_array(bytes, AUTHOR_KEY_DIGEST_OFFSET),
            report_id: read_array(bytes, REPORT_ID_OFFSET),
            report_id_ma: read_array(bytes, REPORT_ID_MA_OFFSET),
            reported_tcb: read_u64_le(bytes, REPORTED_TCB_OFFSET),
            chip_id: read_array(bytes, CHIP_ID_OFFSET),
            committed_tcb: read_u64_le(bytes, COMMITTED_TCB_OFFSET),
            current_build: bytes[CURRENT_BUILD_OFFSET],
            current_minor: bytes[CURRENT_MINOR_OFFSET],
            current_major: bytes[CURRENT_MAJOR_OFFSET],
            committed_build: bytes[COMMITTED_BUILD_OFFSET],
            committed_minor: bytes[COMMITTED_MINOR_OFFSET],
            committed_major: bytes[COMMITTED_MAJOR_OFFSET],
            launch_tcb: read_u64_le(bytes, LAUNCH_TCB_OFFSET),
        })
    }

    /// Returns the signed portion of the raw report bytes (first 0x2A0 bytes).
    pub fn signed_bytes(raw: &[u8]) -> &[u8] {
        &raw[..SIGNED_SIZE]
    }

    /// Extract the ECDSA P-384 signature as (R, S) in big-endian format (48 bytes each).
    ///
    /// AMD stores R and S as 72-byte little-endian zero-padded values.
    /// We extract the first 48 bytes (the significant part) and reverse to big-endian.
    pub fn signature_r_s_be(raw: &[u8]) -> ([u8; P384_FIELD_SIZE], [u8; P384_FIELD_SIZE]) {
        let r_le = &raw[SIG_R_OFFSET..SIG_R_OFFSET + P384_FIELD_SIZE];
        let s_le = &raw[SIG_S_OFFSET..SIG_S_OFFSET + P384_FIELD_SIZE];

        let mut r_be = [0u8; P384_FIELD_SIZE];
        let mut s_be = [0u8; P384_FIELD_SIZE];
        for i in 0..P384_FIELD_SIZE {
            r_be[i] = r_le[P384_FIELD_SIZE - 1 - i];
            s_be[i] = s_le[P384_FIELD_SIZE - 1 - i];
        }

        (r_be, s_be)
    }

    /// Build the 96-byte fixed-length ECDSA P-384 signature (`r_be` || `s_be`) suitable
    /// for `ring::signature::ECDSA_P384_SHA384_FIXED`.
    pub fn signature_fixed(raw: &[u8]) -> Vec<u8> {
        let (r_be, s_be) = Self::signature_r_s_be(raw);
        let mut sig = Vec::with_capacity(P384_FIELD_SIZE * 2);
        sig.extend_from_slice(&r_be);
        sig.extend_from_slice(&s_be);
        sig
    }
}

/// Returns true if the given bytes look like a SEV-SNP attestation report.
/// Used for auto-detection (distinguishing from Intel TDX DCAP quotes).
pub fn is_sev_snp_report(bytes: &[u8]) -> bool {
    if bytes.len() != REPORT_SIZE {
        return false;
    }
    let version = read_u32_le(bytes, VERSION_OFFSET);
    let sig_algo = read_u32_le(bytes, SIG_ALGO_OFFSET);
    version >= 2 && sig_algo == SIG_ALGO_ECDSA_P384
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_report_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; REPORT_SIZE];
        // version = 2
        bytes[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&2u32.to_le_bytes());
        // signature_algo = 1 (ECDSA P-384)
        bytes[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        // policy
        bytes[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&0x30000u64.to_le_bytes());
        // Some report_data
        bytes[REPORT_DATA_OFFSET] = 0xAB;
        bytes[REPORT_DATA_OFFSET + 63] = 0xCD;
        // Some measurement
        bytes[MEASUREMENT_OFFSET] = 0x01;
        bytes[MEASUREMENT_OFFSET + 47] = 0x02;
        bytes
    }

    #[test]
    fn test_parse_valid_report() {
        let bytes = make_valid_report_bytes();
        let report = SevSnpReport::from_bytes(&bytes).unwrap();
        assert_eq!(report.version, 2);
        assert_eq!(report.signature_algo, 1);
        assert_eq!(report.policy, 0x30000);
        assert_eq!(report.report_data[0], 0xAB);
        assert_eq!(report.report_data[63], 0xCD);
        assert_eq!(report.measurement[0], 0x01);
        assert_eq!(report.measurement[47], 0x02);
    }

    #[test]
    fn test_parse_invalid_length() {
        let bytes = vec![0u8; 100];
        assert!(matches!(
            SevSnpReport::from_bytes(&bytes),
            Err(ReportParseError::InvalidLength(100))
        ));
    }

    #[test]
    fn test_parse_invalid_version() {
        let mut bytes = make_valid_report_bytes();
        bytes[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            SevSnpReport::from_bytes(&bytes),
            Err(ReportParseError::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn test_parse_invalid_sig_algo() {
        let mut bytes = make_valid_report_bytes();
        bytes[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            SevSnpReport::from_bytes(&bytes),
            Err(ReportParseError::UnsupportedSignatureAlgo(99))
        ));
    }

    #[test]
    fn test_signature_endianness_conversion() {
        let mut bytes = make_valid_report_bytes();
        // Write R in little-endian: [0x01, 0x02, 0x03, ...] padded with zeros
        bytes[SIG_R_OFFSET] = 0x01;
        bytes[SIG_R_OFFSET + 1] = 0x02;
        bytes[SIG_R_OFFSET + 2] = 0x03;
        // S: [0xAA, 0xBB, 0xCC, ...] padded with zeros
        bytes[SIG_S_OFFSET] = 0xAA;
        bytes[SIG_S_OFFSET + 1] = 0xBB;
        bytes[SIG_S_OFFSET + 2] = 0xCC;

        let (r_be, s_be) = SevSnpReport::signature_r_s_be(&bytes);
        // Big-endian: the byte at index P384_FIELD_SIZE-1 in LE becomes index 0 in BE
        assert_eq!(r_be[P384_FIELD_SIZE - 1], 0x01);
        assert_eq!(r_be[P384_FIELD_SIZE - 2], 0x02);
        assert_eq!(r_be[P384_FIELD_SIZE - 3], 0x03);
        assert_eq!(s_be[P384_FIELD_SIZE - 1], 0xAA);
        assert_eq!(s_be[P384_FIELD_SIZE - 2], 0xBB);
        assert_eq!(s_be[P384_FIELD_SIZE - 3], 0xCC);
    }

    #[test]
    fn test_is_sev_snp_report() {
        let bytes = make_valid_report_bytes();
        assert!(is_sev_snp_report(&bytes));

        // Wrong length
        assert!(!is_sev_snp_report(&bytes[..100]));

        // Wrong version
        let mut bad = bytes.clone();
        bad[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(!is_sev_snp_report(&bad));

        // Wrong sig_algo
        let mut bad = bytes;
        bad[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(!is_sev_snp_report(&bad));
    }

    #[test]
    fn test_signed_bytes_length() {
        let bytes = make_valid_report_bytes();
        assert_eq!(SevSnpReport::signed_bytes(&bytes).len(), SIGNED_SIZE);
    }

    #[test]
    fn test_signature_fixed_length() {
        let bytes = make_valid_report_bytes();
        assert_eq!(SevSnpReport::signature_fixed(&bytes).len(), 96);
    }
}
