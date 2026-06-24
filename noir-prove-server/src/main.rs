//! The single noir/bb DCAP prove service (it replaces the gnark prove server;
//! there is no parallel gnark service). It listens on a unix socket and, per
//! request, builds the Noir witness from a TDX quote + Intel collateral and
//! returns an UltraHonk proof plus the circuit's PACKED public inputs.
//!
//! Wire (what the enclave's RealQuoteProducer sends, raw HTTP/1.1 over the
//! socket, `Connection: close`):
//!   POST /prove  {"quote_hex": "...", "collateral_json": {...}, "timestamp": N}
//!   200          {"proof": "<base64>", "public_inputs": "<base64>"}
//!
//! Per request it runs `genprover -quote -collateral -timestamp > Prover.toml`,
//! then `nargo execute` (witness), then `bb prove -s ultra_honk`. The proof's
//! public_inputs ARE the circuit's packed `[Field; 17]` output (mr_td, rtmr0..3,
//! report_data, tcb_status, timestamp, cert_serial, fmspc); the enclave does not
//! construct them, only re-checks them. Requests are serialized (the shared
//! Prover.toml + witness paths); one enclave == one platform, so attestations
//! are infrequent.
//!
//! Config via env (all optional):
//!   ZKDCAP_PROVER_SOCKET  unix socket to listen on   (default /run/noir/prove.sock)
//!   NOIR_WORKSPACE        dcap-noir workspace root    (default .)
//!   GENPROVER_BIN NARGO_BIN BB_BIN                    (default genprover/nargo/bb on PATH)
//!
//! genprover is still a Go binary (the witness generator mirrors the gnark
//! builder); porting it to Rust is a follow-up. This service is Rust to match
//! the enclave and the rest of the stack — it links nothing, it orchestrates.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use base64::Engine as _;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::Mutex;

const ARTIFACT: &str = "dcap_full"; // package -> target/dcap_full.{json,gz}

#[derive(Deserialize)]
struct ProveRequest {
    quote_hex: String,
    collateral_json: serde_json::Value,
    timestamp: i64,
}

struct Server {
    workspace: PathBuf,
    dcap_dir: PathBuf,
    target: PathBuf,
    genprover: String,
    nargo: String,
    bb: String,
    vk_path: PathBuf,
    lock: Mutex<()>, // serialize: shared Prover.toml + target/*.gz
}

#[tokio::main]
async fn main() {
    let socket = env_or("ZKDCAP_PROVER_SOCKET", "/run/noir/prove.sock");
    let workspace = std::fs::canonicalize(env_or("NOIR_WORKSPACE", "."))
        .expect("NOIR_WORKSPACE path");
    let srv = Arc::new(Server {
        dcap_dir: workspace.join("crates/dcap"),
        target: workspace.join("target"),
        vk_path: workspace.join("target").join(format!("{ARTIFACT}.vk")),
        genprover: env_or("GENPROVER_BIN", "genprover"),
        nargo: env_or("NARGO_BIN", "nargo"),
        bb: env_or("BB_BIN", "bb"),
        workspace,
        lock: Mutex::new(()),
    });

    srv.prepare().await.expect("prepare circuit");

    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("bind socket");
    eprintln!("noir prove server listening on {socket} (workspace {})", srv.workspace.display());

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let srv = srv.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(srv, stream).await {
                eprintln!("conn: {e}");
            }
        });
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Server {
    /// Compile the circuit (if needed) and write the verification key once.
    async fn prepare(&self) -> Result<(), String> {
        if !self.target.join(format!("{ARTIFACT}.json")).exists() {
            self.run(&self.workspace, &self.nargo, &["compile", "--package", ARTIFACT]).await?;
        }
        self.run(
            &self.workspace,
            &self.bb,
            &[
                "write_vk",
                "-s",
                "ultra_honk",
                "-b",
                self.target.join(format!("{ARTIFACT}.json")).to_str().unwrap(),
                "-o",
                self.target.to_str().unwrap(),
            ],
        )
        .await?;
        // bb writes <target>/vk; normalize to the artifact name (overwrite any
        // stale vk so a recompiled circuit always proves under a fresh key).
        std::fs::rename(self.target.join("vk"), &self.vk_path)
            .map_err(|e| format!("rename vk: {e}"))?;
        Ok(())
    }

    async fn prove(&self, quote: &[u8], collateral: &serde_json::Value, ts: i64)
        -> Result<(Vec<u8>, Vec<u8>), String>
    {
        let tmp = tempdir()?;
        let quote_path = tmp.join("quote.bin");
        let coll_path = tmp.join("collateral.json");
        std::fs::write(&quote_path, quote).map_err(|e| format!("write quote: {e}"))?;
        std::fs::write(&coll_path, serde_json::to_vec(collateral).unwrap())
            .map_err(|e| format!("write collateral: {e}"))?;

        // Serialize: genprover writes the shared crates/dcap/Prover.toml and
        // `nargo execute` writes the shared target/<artifact>.gz witness.
        let _guard = self.lock.lock().await;

        let toml = self
            .run_stdout(
                &self.workspace,
                &self.genprover,
                &[
                    "-quote",
                    quote_path.to_str().unwrap(),
                    "-collateral",
                    coll_path.to_str().unwrap(),
                    "-timestamp",
                    &ts.to_string(),
                ],
            )
            .await?;
        std::fs::write(self.dcap_dir.join("Prover.toml"), &toml)
            .map_err(|e| format!("write Prover.toml: {e}"))?;
        self.run(&self.dcap_dir, &self.nargo, &["execute"]).await?;

        let proof_dir = tmp.join("proof");
        std::fs::create_dir_all(&proof_dir).map_err(|e| format!("mkdir proof: {e}"))?;
        self.run(
            &self.workspace,
            &self.bb,
            &[
                "prove",
                "-s",
                "ultra_honk",
                "-b",
                self.target.join(format!("{ARTIFACT}.json")).to_str().unwrap(),
                "-w",
                self.target.join(format!("{ARTIFACT}.gz")).to_str().unwrap(),
                "-k",
                self.vk_path.to_str().unwrap(),
                "-o",
                proof_dir.to_str().unwrap(),
            ],
        )
        .await?;

        let proof = std::fs::read(proof_dir.join("proof")).map_err(|e| format!("read proof: {e}"))?;
        let pi = std::fs::read(proof_dir.join("public_inputs"))
            .map_err(|e| format!("read public_inputs: {e}"))?;
        let _ = std::fs::remove_dir_all(&tmp);
        Ok((proof, pi))
    }

    async fn run(&self, dir: &Path, bin: &str, args: &[&str]) -> Result<(), String> {
        let out = Command::new(bin)
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::null())
            .output()
            .await
            .map_err(|e| format!("spawn {bin}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{bin} failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        Ok(())
    }

    async fn run_stdout(&self, dir: &Path, bin: &str, args: &[&str]) -> Result<Vec<u8>, String> {
        let out = Command::new(bin)
            .args(args)
            .current_dir(dir)
            .output()
            .await
            .map_err(|e| format!("spawn {bin}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{bin} failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        Ok(out.stdout)
    }
}

/// Read one HTTP/1.1 request, run the pipeline for POST /prove, write the JSON
/// response. The enclave is the only client and sends a single Content-Length
/// body with `Connection: close`, so a minimal parser suffices.
async fn handle(srv: Arc<Server>, mut stream: UnixStream) -> Result<(), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    // read until headers complete
    let header_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut tmp).await.map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("eof before headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let is_prove = head.starts_with("POST /prove");
    let content_len = content_length(&head);
    while buf.len() < header_end + content_len {
        let n = stream.read(&mut tmp).await.map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = &buf[header_end..(header_end + content_len).min(buf.len())];

    if !is_prove {
        return write_response(&mut stream, 404, b"not found").await;
    }
    let req: ProveRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return write_response(&mut stream, 400, format!("bad request: {e}").as_bytes()).await,
    };
    let quote = match hex::decode(req.quote_hex.trim()) {
        Ok(q) => q,
        Err(e) => return write_response(&mut stream, 400, format!("quote_hex: {e}").as_bytes()).await,
    };
    match srv.prove(&quote, &req.collateral_json, req.timestamp).await {
        Ok((proof, pi)) => {
            let b64 = base64::engine::general_purpose::STANDARD;
            let resp = serde_json::json!({
                "proof": b64.encode(proof),
                "public_inputs": b64.encode(pi),
            });
            write_response(&mut stream, 200, serde_json::to_vec(&resp).unwrap().as_slice()).await
        }
        Err(e) => {
            eprintln!("prove error: {e}");
            write_response(&mut stream, 500, format!("prove failed: {e}").as_bytes()).await
        }
    }
}

async fn write_response(stream: &mut UnixStream, code: u16, body: &[u8]) -> Result<(), String> {
    let reason = if code == 200 { "OK" } else { "ERR" };
    let ct = if code == 200 { "application/json" } else { "text/plain" };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.map_err(|e| format!("write head: {e}"))?;
    stream.write_all(body).await.map_err(|e| format!("write body: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn content_length(head: &str) -> usize {
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")) {
            return v.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn tempdir() -> Result<PathBuf, String> {
    let base = std::env::temp_dir();
    // unique-enough without extra deps: pid + a monotonic counter.
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let dir = base.join(format!("noirprove-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir tmp: {e}"))?;
    Ok(dir)
}
