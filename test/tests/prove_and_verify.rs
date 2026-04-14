//! Integration test for zkDCAP SP1 verification.
//!
//! Fixtures are loaded from `fixtures/` directory (quote.bin, collateral.json, timestamp.txt).
//! To refresh fixtures, run: cargo test --test save_fixtures --release -- --nocapture
//!
//! Run:
//!   cargo test --test prove_and_verify --release -- --nocapture

use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Instant;
use zkdcap_core::DcapJournal;

// ── Shared test fixture ─────────────────────────────────────────────

struct DcapFixture {
    quote_bytes: Vec<u8>,
    prepared: dcap_qvl::verify::PreparedCollateral,
    pre_verified: dcap_qvl::verify::PreVerifiedInputs,
    now_secs: u64,
}

static FIXTURE: OnceLock<DcapFixture> = OnceLock::new();

fn get_fixture() -> &'static DcapFixture {
    FIXTURE.get_or_init(|| {
        eprintln!("=== Loading fixtures from disk ===");
        let quote_bytes =
            std::fs::read("fixtures/quote.bin").expect("fixtures/quote.bin not found — run save_fixtures test first");
        let collateral_json =
            std::fs::read("fixtures/collateral.json").expect("fixtures/collateral.json not found — run save_fixtures test first");
        let now_secs: u64 = std::fs::read_to_string("fixtures/timestamp.txt")
            .expect("fixtures/timestamp.txt not found")
            .trim()
            .parse()
            .expect("invalid timestamp");

        eprintln!("Quote: {} bytes", quote_bytes.len());
        eprintln!("Collateral: {} bytes", collateral_json.len());
        eprintln!("Timestamp: {}", now_secs);

        let collateral: dcap_qvl::QuoteCollateralV3 =
            serde_json::from_slice(&collateral_json).expect("parse collateral JSON");

        // Verify locally to confirm fixtures are valid
        eprintln!("=== Local verification (rustcrypto) ===");
        let local_start = Instant::now();
        let report = dcap_qvl::verify::rustcrypto::verify(&quote_bytes, &collateral, now_secs)
            .expect("local DCAP verification failed");
        eprintln!("Local verification passed in {:?}", local_start.elapsed());
        eprintln!("TCB status: {}", report.status);

        let td = report.report.as_td10().expect("not TDX");
        eprintln!("mr_td:       {}", hex::encode(td.mr_td));
        eprintln!("rtmr3:       {}", hex::encode(td.rt_mr3));
        eprintln!("report_data: {}", hex::encode(td.report_data));

        // Prepare collateral for full guest (pre-parse JSON + PEM→DER)
        eprintln!("=== Preparing collateral ===");
        let prepared = dcap_qvl::verify::rustcrypto::prepare(&collateral, &quote_bytes)
            .expect("prepare_collateral failed");

        // Extract pre-verified inputs for lite guest
        eprintln!("=== Extracting pre-verified inputs ===");
        let pre_verified =
            dcap_qvl::verify::rustcrypto::extract_pre_verified(&quote_bytes, &collateral, now_secs)
                .expect("extract_pre_verified failed");
        eprintln!("Fixture ready");

        DcapFixture {
            quote_bytes,
            prepared,
            pre_verified,
            now_secs,
        }
    })
}

// ── Journal validation ──────────────────────────────────────────────

fn validate_journal(journal: &DcapJournal, fixture: &DcapFixture) {
    let expected_hash = Sha256::digest(&fixture.quote_bytes);
    assert_eq!(
        &journal.quote_hash[..],
        expected_hash.as_slice(),
        "quote_hash mismatch"
    );

    assert!(journal.quote_verified, "journal should report quote_verified=true");
    assert!(!journal.tcb_status.is_empty(), "tcb_status should be non-empty");
    assert!(!journal.mr_td.is_empty(), "mr_td should be non-empty");
    assert!(!journal.rtmr0.is_empty(), "rtmr0 should be non-empty");
    assert!(!journal.rtmr1.is_empty(), "rtmr1 should be non-empty");
    assert!(!journal.rtmr2.is_empty(), "rtmr2 should be non-empty");
    assert!(!journal.rtmr3.is_empty(), "rtmr3 should be non-empty");
    assert!(!journal.report_data.is_empty(), "report_data should be non-empty");
    assert_eq!(
        journal.verification_timestamp, fixture.now_secs,
        "timestamp should match"
    );

    eprintln!("  Journal validated:");
    eprintln!("    quote_verified: {}", journal.quote_verified);
    eprintln!("    tcb_status:     {}", journal.tcb_status);
    eprintln!("    mr_td:          {}", journal.mr_td);
    eprintln!("    rtmr3:          {}", journal.rtmr3);
    eprintln!("    advisory_ids:   {:?}", journal.advisory_ids);
}

// ── SP1 tests ────────────────────────────────────────────────────────

use sp1_sdk::{include_elf, Elf, Prover, ProveRequest, ProverClient, ProvingKey, SP1Proof, SP1Stdin};

const GUEST_ELF: Elf = include_elf!("zkdcap-sp1-guest");
const GUEST_FULL_ELF: Elf = include_elf!("zkdcap-sp1-guest-full");

/// Execute-only: full verification (steps 1-10, with cert chain) inside zkVM.
/// Uses PreparedCollateral for efficiency (pre-parsed JSON + PEM→DER).
#[tokio::test]
async fn test_sp1_full_execute_only() {
    let fixture = get_fixture();

    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.quote_bytes);
    stdin.write(&fixture.prepared);
    stdin.write(&fixture.now_secs);

    let client = ProverClient::from_env().await;

    eprintln!("\n=== SP1 Full: Execute (no proof) ===");
    let exec_start = Instant::now();
    let (mut output, report) = client
        .execute(GUEST_FULL_ELF, stdin)
        .await
        .expect("SP1 full execution failed");
    let exec_elapsed = exec_start.elapsed();
    let total_cycles = report.total_instruction_count();

    eprintln!("Execution time:  {:?}", exec_elapsed);
    eprintln!("Total cycles:    {}", total_cycles);

    let journal: DcapJournal = output.read();
    validate_journal(&journal, fixture);

    eprintln!("\n┌─────────────────────────────────────┐");
    eprintln!("│        SP1 Full (optimized)         │");
    eprintln!("├─────────────────────────────────────┤");
    eprintln!("│ Execute:  {:>25?} │", exec_elapsed);
    eprintln!("│ Cycles:   {:>25} │", total_cycles);
    eprintln!("└─────────────────────────────────────┘");
}

/// Execute-only: lite verification (steps 4-10 only) inside zkVM.
#[tokio::test]
async fn test_sp1_lite_execute_only() {
    let fixture = get_fixture();

    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.quote_bytes);
    stdin.write(&fixture.pre_verified);
    stdin.write(&fixture.now_secs);

    let client = ProverClient::from_env().await;

    eprintln!("\n=== SP1 Lite: Execute (no proof) ===");
    let exec_start = Instant::now();
    let (mut output, report) = client
        .execute(GUEST_ELF, stdin)
        .await
        .expect("SP1 lite execution failed");
    let exec_elapsed = exec_start.elapsed();
    let total_cycles = report.total_instruction_count();

    eprintln!("Execution time:  {:?}", exec_elapsed);
    eprintln!("Total cycles:    {}", total_cycles);

    let journal: DcapJournal = output.read();
    validate_journal(&journal, fixture);

    eprintln!("\n┌─────────────────────────────────────┐");
    eprintln!("│        SP1 Lite (optimized)         │");
    eprintln!("├─────────────────────────────────────┤");
    eprintln!("│ Execute:  {:>25?} │", exec_elapsed);
    eprintln!("│ Cycles:   {:>25} │", total_cycles);
    eprintln!("└─────────────────────────────────────┘");
}

#[tokio::test]
async fn test_sp1_execute_and_prove() {
    let fixture = get_fixture();

    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.quote_bytes);
    stdin.write(&fixture.pre_verified);
    stdin.write(&fixture.now_secs);

    let client = ProverClient::from_env().await;

    // ── Phase 1: Execute only (no proof) ──
    eprintln!("\n=== SP1: Execute (no proof) ===");
    let exec_start = Instant::now();
    let (mut output, report) = client
        .execute(GUEST_ELF, stdin.clone())
        .await
        .expect("SP1 execution failed");
    let exec_elapsed = exec_start.elapsed();

    let total_cycles = report.total_instruction_count();

    eprintln!("Execution time:  {:?}", exec_elapsed);
    eprintln!("Total cycles:    {}", total_cycles);

    let journal: DcapJournal = output.read();
    validate_journal(&journal, fixture);

    // ── Phase 2: Prove (core proof) ──
    eprintln!("\n=== SP1: Prove (core) ===");
    let pk = client.setup(GUEST_ELF).await
        .expect("SP1 setup failed");

    let prove_start = Instant::now();
    let mut proof = client
        .prove(&pk, stdin)
        .core()
        .await
        .expect("SP1 core proving failed");
    let prove_elapsed = prove_start.elapsed();

    eprintln!("Core prove time: {:?}", prove_elapsed);

    let journal: DcapJournal = proof.public_values.read();
    validate_journal(&journal, fixture);

    // Verify proof locally
    eprintln!("\n=== SP1: Verify proof ===");
    let verify_start = Instant::now();
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("SP1 proof verification failed");
    let verify_elapsed = verify_start.elapsed();
    eprintln!("Verify time: {:?}", verify_elapsed);

    // ── Summary ──
    eprintln!("\n┌─────────────────────────────────────┐");
    eprintln!("│          SP1 Timing Summary         │");
    eprintln!("├─────────────────────────────────────┤");
    eprintln!("│ Execute:  {:>25?} │", exec_elapsed);
    eprintln!("│ Prove:    {:>25?} │", prove_elapsed);
    eprintln!("│ Verify:   {:>25?} │", verify_elapsed);
    eprintln!("│ Total:    {:>25?} │", exec_elapsed + prove_elapsed + verify_elapsed);
    eprintln!("│ Cycles:   {:>25} │", total_cycles);
    eprintln!("└─────────────────────────────────────┘");
}

/// Full Groth16 proving pipeline: setup → prove → verify.
/// This is what the prove_middleware calls in production.
#[tokio::test]
async fn test_sp1_groth16_prove() {
    let fixture = get_fixture();

    let mut stdin = SP1Stdin::new();
    stdin.write(&fixture.quote_bytes);
    stdin.write(&fixture.pre_verified);
    stdin.write(&fixture.now_secs);

    let client = ProverClient::from_env().await;

    // ── Setup ──
    eprintln!("\n=== SP1 Groth16: Setup ===");
    let setup_start = Instant::now();
    let pk = client
        .setup(GUEST_ELF)
        .await
        .expect("SP1 setup failed");
    let setup_elapsed = setup_start.elapsed();
    eprintln!("Setup time: {:?}", setup_elapsed);

    // ── Prove (Groth16) ──
    eprintln!("\n=== SP1 Groth16: Prove ===");
    let prove_start = Instant::now();
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .await
        .expect("SP1 Groth16 proving failed");
    let prove_elapsed = prove_start.elapsed();
    eprintln!("Groth16 prove time: {:?}", prove_elapsed);

    // ── Validate journal ──
    let journal_bytes = proof.public_values.as_slice().to_vec();
    eprintln!("Journal: {} bytes", journal_bytes.len());

    // ── Extract Groth16 proof fields ──
    let groth16 = match &proof.proof {
        SP1Proof::Groth16(g) => g,
        other => panic!("expected Groth16 proof variant, got {:?}", std::mem::discriminant(other)),
    };
    eprintln!("Encoded proof: {} hex chars", groth16.encoded_proof.len());
    eprintln!("Public inputs: {:?}", groth16.public_inputs);

    // ── Verify ──
    eprintln!("\n=== SP1 Groth16: Verify ===");
    let verify_start = Instant::now();
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("SP1 Groth16 verification failed");
    let verify_elapsed = verify_start.elapsed();
    eprintln!("Verify time: {:?}", verify_elapsed);

    // ── Summary ──
    eprintln!("\n┌─────────────────────────────────────┐");
    eprintln!("│      SP1 Groth16 Timing Summary     │");
    eprintln!("├─────────────────────────────────────┤");
    eprintln!("│ Setup:    {:>25?} │", setup_elapsed);
    eprintln!("│ Prove:    {:>25?} │", prove_elapsed);
    eprintln!("│ Verify:   {:>25?} │", verify_elapsed);
    eprintln!("│ Total:    {:>25?} │", setup_elapsed + prove_elapsed + verify_elapsed);
    eprintln!("└─────────────────────────────────────┘");
}
