use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use sp1_sdk::env::{EnvProver, EnvProvingKey};
use sp1_sdk::{include_elf, Elf, Prover, ProveRequest, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use tokio::sync::OnceCell;

use crate::ProofOutput;

/// ELF binary of the SP1 guest program.
/// This must be built separately via `cd sp1-guest && cargo prove build`.
const GUEST_ELF: Elf = include_elf!("zkdcap-sp1-guest");

/// Cached prover + proving key — initialized once per process.
/// Uses EnvProver which selects CPU/CUDA/Network based on SP1_PROVER env var.
/// Default is "cpu". Set SP1_PROVER=cuda on GPU machines.
struct CachedProver {
    client: EnvProver,
    pk: EnvProvingKey,
}

static PROVER: OnceCell<CachedProver> = OnceCell::const_new();

async fn get_prover() -> Result<&'static CachedProver> {
    PROVER
        .get_or_try_init(|| async {
            let mode = std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into());
            tracing::info!(mode = %mode, "initializing SP1 prover + ProvingKey (one-time cost)...");
            let client = sp1_sdk::ProverClient::from_env().await;
            let pk = client.setup(GUEST_ELF).await.context("SP1 setup failed")?;
            Ok(CachedProver { client, pk })
        })
        .await
}

pub async fn generate_proof(
    quote: &[u8],
    pre_verified: &dcap_qvl::verify::PreVerifiedInputs,
    now_secs: u64,
) -> Result<ProofOutput> {
    let cached = get_prover().await?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&quote.to_vec());
    stdin.write(pre_verified);
    stdin.write(&now_secs);

    tracing::info!("generating SP1 Groth16 proof...");
    let proof: SP1ProofWithPublicValues = cached
        .client
        .prove(&cached.pk, stdin)
        .groth16()
        .await
        .context("SP1 Groth16 proving failed")?;

    let journal_bytes = proof.public_values.as_slice().to_vec();

    // Extract Groth16-specific fields from the proof
    let groth16 = match &proof.proof {
        SP1Proof::Groth16(g) => g,
        _ => bail!("expected Groth16 proof variant"),
    };

    let proof_json = convert_gnark_to_snarkjs(&groth16.encoded_proof)?;
    let public_inputs = groth16.public_inputs.to_vec();

    Ok(ProofOutput {
        proof: proof_json,
        public_inputs,
        journal: hex::encode(&journal_bytes),
        zkvm: "sp1".to_string(),
    })
}

/// Convert SP1's gnark-format Groth16 proof to SnarkJS-compatible JSON.
///
/// SP1 v6 uses gnark with Keccak commitment, producing 352 bytes:
///   - Ar.X  (32B) — G1 pi_a x
///   - Ar.Y  (32B) — G1 pi_a y
///   - Bs.X.A1 (32B) — G2 pi_b x imaginary
///   - Bs.X.A0 (32B) — G2 pi_b x real
///   - Bs.Y.A1 (32B) — G2 pi_b y imaginary
///   - Bs.Y.A0 (32B) — G2 pi_b y real
///   - Krs.X (32B) — G1 pi_c x
///   - Krs.Y (32B) — G1 pi_c y
///   - Commitment.X (32B) — G1 commitment x
///   - Commitment.Y (32B) — G1 commitment y
///   - CommitmentPok (32B) — scalar proof of knowledge
fn convert_gnark_to_snarkjs(encoded_proof_hex: &str) -> Result<serde_json::Value> {
    let proof_bytes =
        hex::decode(encoded_proof_hex).context("invalid hex in encoded_proof")?;

    if proof_bytes.len() != 352 {
        bail!(
            "expected 352-byte gnark proof (with commitment), got {} bytes",
            proof_bytes.len()
        );
    }

    let to_decimal = |slice: &[u8]| -> String {
        BigUint::from_bytes_be(slice).to_string()
    };

    // G1 point: pi_a (Ar)
    let ar_x = to_decimal(&proof_bytes[0..32]);
    let ar_y = to_decimal(&proof_bytes[32..64]);

    // G2 point: pi_b (Bs) — gnark stores A1 (imaginary) before A0 (real)
    let bs_x_a1 = to_decimal(&proof_bytes[64..96]); // imaginary
    let bs_x_a0 = to_decimal(&proof_bytes[96..128]); // real
    let bs_y_a1 = to_decimal(&proof_bytes[128..160]); // imaginary
    let bs_y_a0 = to_decimal(&proof_bytes[160..192]); // real

    // G1 point: pi_c (Krs)
    let krs_x = to_decimal(&proof_bytes[192..224]);
    let krs_y = to_decimal(&proof_bytes[224..256]);

    // Keccak commitment (SP1 v6 gnark)
    let commit_x = to_decimal(&proof_bytes[256..288]);
    let commit_y = to_decimal(&proof_bytes[288..320]);
    let commit_pok = to_decimal(&proof_bytes[320..352]);

    Ok(serde_json::json!({
        "pi_a": [ar_x, ar_y, "1"],
        "pi_b": [
            [bs_x_a0, bs_x_a1],
            [bs_y_a0, bs_y_a1],
            ["1", "0"]
        ],
        "pi_c": [krs_x, krs_y, "1"],
        "commitment": [commit_x, commit_y],
        "commitment_pok": commit_pok,
        "protocol": "groth16",
        "curve": "bn128"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_gnark_to_snarkjs() {
        // Create a synthetic 352-byte proof with known values (SP1 v6 with commitment)
        let mut proof_bytes = vec![0u8; 352];
        // Set Ar.X = 1
        proof_bytes[31] = 1;
        // Set Ar.Y = 2
        proof_bytes[63] = 2;
        // Set Bs.X.A1 = 3 (imaginary)
        proof_bytes[95] = 3;
        // Set Bs.X.A0 = 4 (real)
        proof_bytes[127] = 4;
        // Set Bs.Y.A1 = 5 (imaginary)
        proof_bytes[159] = 5;
        // Set Bs.Y.A0 = 6 (real)
        proof_bytes[191] = 6;
        // Set Krs.X = 7
        proof_bytes[223] = 7;
        // Set Krs.Y = 8
        proof_bytes[255] = 8;
        // Set Commitment.X = 9
        proof_bytes[287] = 9;
        // Set Commitment.Y = 10
        proof_bytes[319] = 10;
        // Set CommitmentPok = 11
        proof_bytes[351] = 11;

        let hex_proof = hex::encode(&proof_bytes);
        let result = convert_gnark_to_snarkjs(&hex_proof).unwrap();

        assert_eq!(result["pi_a"][0], "1");
        assert_eq!(result["pi_a"][1], "2");
        assert_eq!(result["pi_a"][2], "1");

        // pi_b[0] = [real, imaginary] = [A0, A1] = [4, 3]
        assert_eq!(result["pi_b"][0][0], "4");
        assert_eq!(result["pi_b"][0][1], "3");
        // pi_b[1] = [real, imaginary] = [A0, A1] = [6, 5]
        assert_eq!(result["pi_b"][1][0], "6");
        assert_eq!(result["pi_b"][1][1], "5");
        assert_eq!(result["pi_b"][2][0], "1");
        assert_eq!(result["pi_b"][2][1], "0");

        assert_eq!(result["pi_c"][0], "7");
        assert_eq!(result["pi_c"][1], "8");
        assert_eq!(result["pi_c"][2], "1");

        assert_eq!(result["commitment"][0], "9");
        assert_eq!(result["commitment"][1], "10");
        assert_eq!(result["commitment_pok"], "11");

        assert_eq!(result["protocol"], "groth16");
        assert_eq!(result["curve"], "bn128");
    }

    #[test]
    fn test_convert_rejects_wrong_size() {
        let hex_proof = hex::encode(&[0u8; 128]);
        assert!(convert_gnark_to_snarkjs(&hex_proof).is_err());
    }
}
