use anyhow::{bail, Context, Result};
use serde_json::json;
use std::io::{Read, Write};

use crate::ProofOutput;

/// Generate a Groth16 proof via the gnark server over a unix socket.
pub async fn generate_proof(
    quote: &[u8],
    pre_verified: &dcap_qvl::verify::PreVerifiedInputs,
    now_secs: u64,
    socket_path: &str,
) -> Result<ProofOutput> {
    let pre_json = build_pre_verified_json(pre_verified)?;
    let request_body = json!({
        "quote_hex": hex::encode(quote),
        "pre_verified_json": pre_json,
        "timestamp": now_secs,
    });
    let body_bytes = serde_json::to_vec(&request_body).context("failed to serialize request")?;

    let sock = socket_path.to_string();
    let response_body = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut stream = std::os::unix::net::UnixStream::connect(&sock)
            .with_context(|| format!("failed to connect to gnark server at {sock}"))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(300)))
            .ok();

        // Send raw HTTP request
        let request = format!(
            "POST /prove HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body_bytes.len()
        );
        stream.write_all(request.as_bytes())?;
        stream.write_all(&body_bytes)?;
        stream.flush()?;

        // Read full response
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(response)
    })
    .await
    .context("gnark prove task panicked")?
    .context("gnark prove request failed")?;

    // Parse HTTP response
    let response_str = String::from_utf8_lossy(&response_body);
    let body_start = response_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let status_line = response_str.lines().next().unwrap_or("");

    if !status_line.contains("200") {
        let body = &response_str[body_start..];
        bail!("gnark server returned {}: {}", status_line, body.trim());
    }

    let body = &response_body[body_start..];
    let proof_value: serde_json::Value =
        serde_json::from_slice(body).context("failed to parse gnark proof response")?;

    Ok(ProofOutput {
        proof: proof_value,
        public_inputs: Vec::new(),
        journal: String::new(),
        zkvm: "gnark".to_string(),
    })
}

/// Build the Go-compatible `PreVerifiedJSON` format from Rust `PreVerifiedInputs`.
///
/// The Go side expects hex strings for all byte fields, matching the `PreVerifiedJSON`
/// struct in `circuits/dcap-gnark/witness/types.go`.
fn build_pre_verified_json(
    pv: &dcap_qvl::verify::PreVerifiedInputs,
) -> Result<serde_json::Value> {
    // TcbInfo serializes directly — both Rust and Go use camelCase serde
    let tcb_info = serde_json::to_value(&pv.tcb_info).context("failed to serialize tcb_info")?;

    // QeIdentity needs manual conversion: byte fields → hex strings
    let qe_identity = build_qe_identity_json(&pv.qe_identity)?;

    Ok(json!({
        "tcb_info": tcb_info,
        "qe_identity": qe_identity,
        "pck_leaf_der": hex::encode(&pv.pck_leaf_der),
        "cpu_svn": hex::encode(pv.cpu_svn),
        "pce_svn": pv.pce_svn,
        "fmspc": hex::encode(pv.fmspc),
        "ppid": hex::encode(&pv.ppid),
    }))
}

/// Convert Rust `QeIdentity` to Go `QeIdentityJSON` format (hex strings for byte fields).
fn build_qe_identity_json(
    qe: &dcap_qvl::qe_identity::QeIdentity,
) -> Result<serde_json::Value> {
    // Serialize tcb_levels directly — both sides use the same JSON shape
    let tcb_levels = serde_json::to_value(&qe.tcb_levels).context("failed to serialize qe tcb_levels")?;

    Ok(json!({
        "id": qe.id,
        "version": qe.version,
        "issueDate": qe.issue_date,
        "nextUpdate": qe.next_update,
        "tcbEvaluationDataNumber": qe.tcb_evaluation_data_number,
        "miscselect": hex::encode(qe.miscselect),
        "miscselectMask": hex::encode(qe.miscselect_mask),
        "attributes": hex::encode(qe.attributes),
        "attributesMask": hex::encode(qe.attributes_mask),
        "mrsigner": hex::encode(qe.mrsigner),
        "isvprodid": qe.isvprodid,
        "tcbLevels": tcb_levels,
    }))
}
