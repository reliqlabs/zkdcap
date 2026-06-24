//! Example: dstack TEE service with zkDCAP attestation proving.
//!
//! Demonstrates how to use zkdcap-host inside a dstack TEE to:
//! 1. Serve an HTTP endpoint
//! 2. Fetch the local TDX quote from dstack's attestation API
//! 3. Generate a Groth16 ZK proof of the DCAP attestation
//! 4. Return the proof for on-chain verification
//!
//! # Usage
//!
//! ```bash
//! # Requires a gnark-prove server on the unix socket (default /tmp/gnark.sock)
//! cargo run --release
//!
//! # Point at a specific gnark-prove socket
//! GNARK_SOCKET=/tmp/gnark.sock cargo run --release
//!
//! # Test it
//! curl http://localhost:3000/info              # raw info
//! curl http://localhost:3000/info?prove=true   # info + Groth16 proof
//! ```
//!
//! # Environment
//!
//! - `DSTACK_ATTESTATION_URL`: dstack attestation endpoint (default: http://localhost:8090/attestation)
//! - `PORT`: HTTP listen port (default: 3000)
//! - `GNARK_SOCKET`: path to the gnark-prove unix socket (default: /tmp/gnark.sock)
//! - `GNARK_GPU`: set to 1/true to request GPU proving

use axum::{extract::Query, response::Json, routing::get, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::time::Instant;

const DEFAULT_ATTESTATION_URL: &str = "http://localhost:8090/attestation";
const DEFAULT_PORT: u16 = 3000;

#[derive(Deserialize)]
struct InfoParams {
    prove: Option<String>,
}

#[derive(Deserialize)]
struct AttestationResponse {
    quote: String,
}

#[derive(Serialize)]
struct InfoResponse {
    version: String,
    quote_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prove_time_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn info_handler(Query(params): Query<InfoParams>) -> Json<InfoResponse> {
    let attestation_url =
        std::env::var("DSTACK_ATTESTATION_URL").unwrap_or(DEFAULT_ATTESTATION_URL.into());

    // Fetch TDX quote from dstack's local attestation API
    let client = reqwest::Client::new();
    let resp = match client.get(&attestation_url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Json(InfoResponse {
                version: env!("CARGO_PKG_VERSION").into(),
                quote_hash: None,
                proof: None,
                prove_time_ms: None,
                error: Some(format!("failed to fetch attestation: {e}")),
            })
        }
    };

    let att: AttestationResponse = match resp.json().await {
        Ok(a) => a,
        Err(e) => {
            return Json(InfoResponse {
                version: env!("CARGO_PKG_VERSION").into(),
                quote_hash: None,
                proof: None,
                prove_time_ms: None,
                error: Some(format!("invalid attestation response: {e}")),
            })
        }
    };

    let quote_bytes = B64.decode(&att.quote).unwrap_or_default();
    let quote_hash = hex::encode(zkdcap_host::hash_quote(&quote_bytes));

    // If ?prove=true, generate a ZK proof
    let should_prove = matches!(params.prove.as_deref(), Some("true" | "1"));

    if should_prove {
        let (socket_path, gpu) = resolve_backend();
        tracing::info!(socket_path, gpu, "generating proof...");

        let start = Instant::now();
        match zkdcap_host::prove_quote(&quote_bytes, &socket_path, gpu).await {
            Ok(output) => {
                let elapsed = start.elapsed();
                tracing::info!(ms = elapsed.as_millis(), "proof generated");

                Json(InfoResponse {
                    version: env!("CARGO_PKG_VERSION").into(),
                    quote_hash: Some(quote_hash),
                    proof: Some(serde_json::to_value(&output).unwrap()),
                    prove_time_ms: Some(elapsed.as_millis() as u64),
                    error: None,
                })
            }
            Err(e) => Json(InfoResponse {
                version: env!("CARGO_PKG_VERSION").into(),
                quote_hash: Some(quote_hash),
                proof: None,
                prove_time_ms: None,
                error: Some(format!("proving failed: {e:#}")),
            }),
        }
    } else {
        Json(InfoResponse {
            version: env!("CARGO_PKG_VERSION").into(),
            quote_hash: Some(quote_hash),
            proof: None,
            prove_time_ms: None,
            error: None,
        })
    }
}

fn resolve_backend() -> (String, bool) {
    let socket_path =
        std::env::var("GNARK_SOCKET").unwrap_or_else(|_| "/tmp/gnark.sock".to_string());
    let gpu = std::env::var("GNARK_GPU")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    (socket_path, gpu)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,dstack_prove_example=debug".into()),
        )
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let app = Router::new().route("/info", get(info_handler));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("bind");
    tracing::info!(port, "dstack-prove example listening");
    axum::serve(listener, app).await.expect("serve");
}
