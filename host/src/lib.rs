use anyhow::{Context, Result};
use serde::Serialize;

pub mod gnark;
pub mod sp1;

/// Output proof format (SnarkJS-compatible)
#[derive(Serialize)]
pub struct ProofOutput {
    pub proof: serde_json::Value,
    pub public_inputs: Vec<String>,
    pub journal: String, // hex-encoded DcapJournal bytes
    pub zkvm: String,
}

/// Which proving backend to use.
#[derive(Debug, Clone)]
pub enum ProverBackend {
    /// SP1 Groth16 (CPU/GPU/Network selected by SP1_PROVER env at startup)
    Sp1,
    /// gnark server over unix socket
    Gnark {
        socket_path: String,
        gpu: bool,
    },
}

/// Generate a Groth16 ZK proof for a raw TDX quote.
///
/// Shared pipeline:
/// 1. Fetch collateral from Intel PCS
/// 2. Extract pre-verified inputs (cert chain validation on host)
/// 3. Dispatch to the selected backend for proof generation
pub async fn prove_quote(quote: &[u8], backend: &ProverBackend) -> Result<ProofOutput> {
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

    match backend {
        ProverBackend::Sp1 => {
            tracing::info!("prove_quote: dispatching to SP1 backend");
            sp1::generate_proof(quote, &pre_verified, now_secs).await
        }
        ProverBackend::Gnark {
            socket_path,
            gpu,
        } => {
            tracing::info!(gpu = gpu, "prove_quote: dispatching to gnark backend");
            gnark::generate_proof(quote, &pre_verified, now_secs, socket_path).await
        }
    }
}
