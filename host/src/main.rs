use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

use zkdcap_host::prove_quote;

#[derive(Parser)]
#[command(name = "zkdcap-host", about = "Generate zkDCAP attestation proofs")]
struct Args {
    /// URL of the dstack attestation endpoint
    #[arg(long)]
    dstack_url: String,

    /// Output file for the proof
    #[arg(long, default_value = "proof.json")]
    output: PathBuf,

    /// Prover backend: gnark (CPU) or gnark-gpu
    #[arg(long, default_value = "gnark")]
    backend: String,

    /// Path to gnark-prove unix socket (only for gnark backend)
    #[arg(long, default_value = "/tmp/gnark.sock")]
    gnark_socket: String,
}

/// Attestation response from dstack
#[derive(Deserialize)]
struct AttestationResponse {
    quote: String, // hex-encoded
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (socket_path, gpu) = match args.backend.as_str() {
        "gnark" | "gnark-cpu" => (args.gnark_socket, false),
        "gnark-gpu" => (args.gnark_socket, true),
        other => anyhow::bail!("unknown backend '{other}' (use gnark or gnark-gpu)"),
    };

    // 1. Fetch quote from dstack
    println!("Fetching attestation from {}...", args.dstack_url);
    let client = reqwest::Client::new();
    let resp: AttestationResponse = client
        .get(&args.dstack_url)
        .send()
        .await
        .context("failed to fetch attestation")?
        .json()
        .await
        .context("failed to parse attestation response")?;

    let quote = hex::decode(&resp.quote).context("invalid hex in quote")?;
    println!("Quote fetched: {} bytes", quote.len());

    // 2. Generate proof (fetches collateral + proves)
    println!("Generating proof...");
    let output = prove_quote(&quote, &socket_path, gpu).await?;

    // 3. Write output
    let json = serde_json::to_string_pretty(&output)?;
    std::fs::write(&args.output, &json)?;
    println!("Proof written to {}", args.output.display());

    Ok(())
}
