# zkDCAP — Zero-Knowledge DCAP Quote Verification

ZK proof system for Intel TDX DCAP attestation quotes. It produces a Groth16 proof
(gnark, BN254) that a TDX quote is valid, so a recipient can check the attestation
on-chain without replaying the full DCAP verification cryptography.

## Architecture

```
zkdcap/
├── core/                  # Shared Rust types (DcapJournal)
├── host/                  # Host library: Intel PCS collateral fetch + PCK cert-chain
│                          #   pre-verification, then dispatch to the gnark prover
├── circuits/dcap-gnark/   # gnark Groth16 circuit for DCAP steps 4-10, witness builder, CLI tools
├── examples/dstack-prove/ # Example dstack TEE HTTP service that proves its own quote
└── test/                  # Helper to capture shared fixtures (quote.bin, collateral.json, timestamp.txt)
```

DCAP verification is split between an untrusted host and the circuit:

- Steps 1-3 run on the host (`host/`, via `dcap-qvl`): fetch collateral from Intel PCS
  and validate the PCK certificate chain, producing `PreVerifiedInputs`.
- Steps 4-10 run in the circuit (`circuits/dcap-gnark/`) and are proven in zero knowledge.

## Proof pipeline

`prove_quote(raw_tdx_quote, ProverBackend::Gnark { socket_path, gpu })` in `host/`:

1. Fetch PCS collateral from Intel (cert chains, TCB info, QE identity).
2. Validate the cert chain on the host and extract `PreVerifiedInputs` (steps 1-3).
3. Send the quote, pre-verified inputs, and timestamp over a unix socket to a
   gnark-prove server, which builds the witness and returns a Groth16 proof of steps 4-10.

The gnark-prove server is a separate long-running process. It loads the constraint
system (`ccs.bin`) and proving key (`pk.bin`) at boot so it does not recompile the
circuit on every request.

## Circuit

`circuits/dcap-gnark/circuit` implements DCAP steps 4-10 on BN254:

- Step 4: QE report ECDSA P-256 signature, verified with the PCK public key.
- Step 5: `SHA-256(attest_key || qe_auth_data)` equals `qe_report.report_data[0:32]`.
- Step 6: QE identity policy (MRSIGNER, ISVPRODID, masked MISCSELECT, masked ATTRIBUTES).
- Step 7: ISV report ECDSA P-256 signature, verified with the attestation key.
- Step 8: platform TCB level match (FMSPC, PCE SVN, SGX and TDX component SVNs).
- Steps 9-10: merge the QE and platform TCB severities, assert the result is not
  `Revoked`, and bind the final `TcbStatus`.

### Public inputs

The circuit exposes the attested measurements directly as public inputs, bound from
the signed quote region (which the step-7 ISV signature authenticates):

`MrTd`, `Rtmr0`, `Rtmr1`, `Rtmr2`, `Rtmr3` (48 bytes each), `ReportData` (64 bytes),
`TcbStatus`, and `Timestamp`.

## On-chain verification

The verifying key is registered with Xion's ZK module:

```sh
cd circuits/dcap-gnark
go run ./cmd/keygen --ccs ccs.bin --pk pk.bin --vk vk.bin
xiond tx zk add-vkey --name zkdcap-gnark \
  --vkey-bytes $(base64 < vk.bin) \
  --proof-system PROOF_SYSTEM_GROTH16_GNARK
```

A proof can be checked against `vk.bin` with `cmd/verify-remote`, either from a saved
proof file or a running prover endpoint:

```sh
go run ./cmd/verify-remote -proof proof.json -vk vk.bin
go run ./cmd/verify-remote -url '<prover-endpoint>' -vk vk.bin
```

## Development

### Circuit (Go)

```sh
cd circuits/dcap-gnark
go test ./...          # compile the circuit and run prove/verify against fixtures
go run ./cmd/keygen    # compile + groth16.Setup -> ccs.bin, pk.bin, vk.bin
```

`TestCircuitCompile` logs the constraint count. Circuit fixtures live under
`circuits/dcap-gnark/testdata/fixtures/zkdcap/` (`quote.bin`, `pre_verified.json`,
`timestamp.txt`). Generate `pre_verified.json` from raw collateral with:

```sh
go run ./cmd/gen-fixture quote.bin collateral.json pre_verified.json
```

### Host (Rust)

```sh
cargo build -p zkdcap-host

# refresh the shared quote/collateral fixtures from live Intel PCS + dstack
cargo test -p zkdcap-test --test save_fixtures --release -- --nocapture
```

`zkdcap-host` connects to a gnark-prove server over a unix socket (default
`/tmp/gnark.sock`); start that server with the `pk.bin` and `ccs.bin` produced by
`cmd/keygen`. The `zkdcap-host` binary fetches a quote from a dstack attestation URL
and writes a proof:

```sh
cargo run -p zkdcap-host -- \
  --dstack-url '<attestation-url>' --backend gnark --gnark-socket /tmp/gnark.sock \
  --output proof.json
```
