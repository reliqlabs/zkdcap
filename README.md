# zkDCAP — Zero-Knowledge DCAP Quote Verification

ZK proof system for Intel TDX DCAP attestation quotes. Generates a Groth16 proof that a TDX quote is valid, verifiable on-chain without replaying the full verification logic.

## Architecture

```
contracts/zkdcap/
├── core/              # Shared types (DcapJournal, etc.)
├── elf/               # Pre-built SP1 guest ELF binary (~742KB)
├── host/              # Host-side library: collateral fetch + proof generation
├── sp1-guest/         # SP1 lite guest (steps 4-10, uses PreVerifiedInputs)
├── sp1-guest-full/    # SP1 full guest (steps 1-10, uses PreparedCollateral)
├── test/              # Test fixtures (quote.bin, collateral.json, timestamp.txt)
├── verifier/          # On-chain Groth16 verifier contract
└── vkey-converter/    # SP1 verification key format converter
```

### Proof Pipeline

`prove_quote(raw_tdx_quote)` runs the full pipeline:

1. Fetch PCS collateral from Intel (cert chains, TCB info, QE identity)
2. Host-side cert chain validation → `PreVerifiedInputs` (steps 1-3)
3. SP1 Groth16 proof of steps 4-10 inside the zkVM (lite guest)

Output is a SnarkJS-compatible Groth16 proof (BN254) with SP1 v6 Keccak commitment fields.

### Proof Output Format

```json
{
  "pi_a": ["<x>", "<y>", "1"],
  "pi_b": [["<x_real>", "<x_imag>"], ["<y_real>", "<y_imag>"], ["1", "0"]],
  "pi_c": ["<x>", "<y>", "1"],
  "commitment": ["<x>", "<y>"],
  "commitment_pok": "<scalar>",
  "protocol": "groth16",
  "curve": "bn128",
  "public_inputs": ["..."],
  "journal": "<hex-encoded DcapJournal>",
  "zkvm": "sp1"
}
```

SP1 v6 Groth16 proofs are 352 bytes: 256B standard (pi_a + pi_b + pi_c) + 96B Keccak commitment (64B G1 point + 32B scalar proof-of-knowledge).

## Current Status

**Working end-to-end.** The async prove queue in oauth3 generates proofs via `?prove=true` on any API endpoint. Proof generation takes ~7 minutes on CPU (24 vCPU Phala CVM).

### Prover Modes

| Mode | Env | Status | Notes |
|------|-----|--------|-------|
| CPU | `SP1_PROVER=cpu` | Working | ~7 min on 24 vCPU, ~16 min on macOS arm64 |
| CUDA GPU | `SP1_PROVER=cuda` | Blocked | See below |
| Network | `SP1_PROVER=network` | Available | Remote GPU via Succinct prover network |
| Mock | `SP1_PROVER=mock` | Working | Instant, no real proof (testing only) |

## GPU (CUDA) Blocker

SP1 v6's CUDA prover (`sp1-gpu-server`) cannot run on NVIDIA GPUs in **Confidential Computing (CC) mode**, which is enabled on Phala dstack TEE nodes (H200).

**Root cause:** SP1 v6's GPU backend calls `cudaDeviceGetMemPool()` to use CUDA stream-ordered memory pools. CC-mode disables this API at the driver/firmware level, returning "operation not supported". `sp1-gpu-server` panics on this error.

This is not a configuration issue — it's a fundamental incompatibility between SP1 v6's GPU memory management and NVIDIA's TEE security restrictions. CC-mode disables several CUDA features to prevent GPU memory side-channel attacks.

### Error chain observed

```
1. sp1-gpu-server starts, initializes CUDA device 0
2. Calls cudaDeviceGetMemPool() for stream-ordered allocations
3. CC-mode driver returns: "operation not supported"
4. sp1-gpu-server panics at task.rs:192 — CudaRustError
5. oauth3 gets: "Could not connect to sp1-gpu-server socket"
```

### Options to Resolve

1. **CPU prover (current)** — Works now. ~7 min per proof on 24 vCPU. Acceptable for low-throughput use.

2. **SP1 Network Prover** — Remote GPU proving via Succinct's prover network. No local GPU needed. Requires:
   - `SP1_PROVER=network`
   - `NETWORK_PRIVATE_KEY=<secp256k1 hex private key>`
   - Funded account with `$PROVE` tokens at https://explorer.succinct.xyz
   - `sp1-sdk` feature `"network"` (already enabled)

3. **Wait for SP1 fix** — SP1 team could add a fallback path that avoids `cudaDeviceGetMemPool()` on CC-mode GPUs. No upstream issue filed yet.

4. **Non-CC GPU node** — If Phala offers GPU nodes without CC-mode, CUDA proving would work immediately. The Nix Docker image already bundles `sp1-gpu-server` and `libcudart.so`.

## Development

### Build guest ELF

```sh
cd sp1-guest && cargo prove build
```

The pre-built ELF is checked in at `elf/zkdcap-sp1-guest`.

### Run tests

```sh
# Unit tests (proof format, conversion)
cargo test -p zkdcap-host

# Full prove + verify (requires SP1 SDK, use --release)
cargo test --test prove_and_verify --release -- --nocapture

# Refresh test fixtures from live Intel PCS
cargo test --test save_fixtures --release -- --nocapture
```

### Circuit stats

- ~16M constraints (15,965,950)
- Groth16 on BN254
- SP1 v6 (Hypercube) with Keccak commitment scheme
