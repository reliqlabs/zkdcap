//! One-shot helper to fetch and save test fixtures.
//! Run: cargo test --test save_fixtures --no-default-features --release -- --nocapture
//!
//! If fixtures/quote.bin exists, only fetches collateral from Intel PCS.
//! Otherwise, fetches quote from dstack first.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;

const DSTACK_APP: &str =
    "https://07f8fd641d50842c1388444af32a545416413885-8080.dstack-pha-prod5.phala.network";

#[derive(Deserialize)]
struct AttestationResponse {
    quote: String,
}

#[tokio::test]
async fn save_fixtures() {
    std::fs::create_dir_all("fixtures").unwrap();

    // Try loading existing quote first
    let quote_bytes = if let Ok(bytes) = std::fs::read("fixtures/quote.bin") {
        eprintln!("Using existing fixtures/quote.bin ({} bytes)", bytes.len());
        bytes
    } else {
        eprintln!("Fetching quote from dstack...");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build().unwrap();
        let resp: AttestationResponse = client
            .get(format!("{}/attestation", DSTACK_APP))
            .send().await.expect("fetch quote")
            .json().await.expect("parse json");
        let bytes = B64.decode(&resp.quote).expect("decode base64");
        std::fs::write("fixtures/quote.bin", &bytes).unwrap();
        eprintln!("Saved quote.bin: {} bytes", bytes.len());
        bytes
    };

    eprintln!("Fetching collateral from Intel PCS...");
    let collateral = dcap_qvl::collateral::get_collateral_from_pcs(&quote_bytes)
        .await.expect("fetch collateral");
    let collateral_json = serde_json::to_vec(&collateral).expect("serialize");
    std::fs::write("fixtures/collateral.json", &collateral_json).unwrap();
    eprintln!("Saved collateral.json: {} bytes", collateral_json.len());

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    std::fs::write("fixtures/timestamp.txt", now_secs.to_string()).unwrap();
    eprintln!("Saved timestamp.txt: {}", now_secs);

    eprintln!("Done! Fixtures saved to fixtures/");
}
