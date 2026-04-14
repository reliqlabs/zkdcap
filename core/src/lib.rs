use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Public journal committed by the zkVM guest after DCAP verification.
/// This is the only data visible to the on-chain verifier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DcapJournal {
    /// SHA256 of the raw TDX quote bytes
    #[serde(with = "hex::serde")]
    pub quote_hash: [u8; 32],
    /// Whether dcap-qvl verification succeeded
    pub quote_verified: bool,
    /// TCB status string (e.g. "UpToDate", "OutOfDate")
    pub tcb_status: String,
    /// Advisory IDs from Intel
    pub advisory_ids: Vec<String>,
    /// TDX measurement registers (hex-encoded 48-byte values)
    pub mr_td: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
    /// 64-byte report_data (hex-encoded)
    pub report_data: String,
    /// Unix timestamp used for verification
    pub verification_timestamp: u64,
}

impl DcapJournal {
    /// Serialize to JSON bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("DcapJournal serialization cannot fail")
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }

    /// Compute SHA256 of raw quote bytes
    pub fn hash_quote(quote: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(quote);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}
