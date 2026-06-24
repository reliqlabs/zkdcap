use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub mod gnark;

/// Output proof format (SnarkJS-compatible).
#[derive(Serialize)]
pub struct ProofOutput {
    pub proof: serde_json::Value,
    pub public_inputs: Vec<String>,
}

/// SHA-256 of the raw TDX quote bytes (an informational quote identifier).
pub fn hash_quote(quote: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(quote);
    hasher.finalize().into()
}

/// Generate a Groth16 ZK proof for a raw TDX quote via the gnark backend.
///
/// Pipeline:
/// 1. Fetch collateral from Intel PCS
/// 2. Extract pre-verified inputs (cert chain validation on host)
/// 3. Dispatch to the gnark prove server over a unix socket
pub async fn prove_quote(quote: &[u8], socket_path: &str, gpu: bool) -> Result<ProofOutput> {
    tracing::info!("prove_quote: fetching Intel PCS collateral...");
    let collateral = dcap_qvl::collateral::get_collateral_from_pcs(quote)
        .await
        .context("failed to fetch collateral from Intel PCS")?;
    tracing::info!("prove_quote: PCS collateral fetched");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    tracing::info!("prove_quote: extracting pre-verified inputs...");
    let pre_verified =
        dcap_qvl::verify::rustcrypto::extract_pre_verified(quote, &collateral, now_secs)
            .context("failed to extract pre-verified inputs")?;
    tracing::info!("prove_quote: pre-verified inputs extracted");

    tracing::info!(gpu = gpu, "prove_quote: dispatching to gnark backend");
    gnark::generate_proof(quote, &pre_verified, now_secs, socket_path).await
}
