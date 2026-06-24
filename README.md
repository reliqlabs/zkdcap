# zkDCAP — Zero-Knowledge DCAP Quote Verification

ZK proof system for Intel TDX DCAP attestation. It produces a succinct proof that a
TDX quote is valid under the full Intel DCAP trust chain, so a recipient can check the
attestation on-chain (Xion `x/zk`, which charges zero gas for proof verification)
without replaying the DCAP cryptography. Two interchangeable proving backends are
provided:

- **gnark / Groth16** (BN254) — the known-quantity path; per-circuit trusted setup, smallest proof.
- **Noir / Barretenberg UltraHonk** (BN254) — no per-circuit trusted setup; deployed and on-chain verified on xion-testnet-2.

Both circuits are **self-anchoring**: the Intel SGX Root CA public key is a hardcoded
constant, and the circuit validates the entire PCK certificate chain, the collateral
signatures, the TCB status, certificate/CRL revocation, and every freshness window in
zero knowledge. A forged proof cannot substitute its own trust anchor, key, quote, or
collateral. The host fetches Intel PCS collateral and builds the witness; it is not
trusted for any validation (the circuit re-derives everything from the signed bytes).

## What the circuit proves

- **A1 — PCK chain**: leaf ← Platform/Processor CA ← pinned Intel SGX Root CA (constant). Both links SHA-256 + ECDSA P-256 verified; the leaf subject public key binds the PCK key.
- **A2 — collateral**: TCB-Signing cert ← root; the TCB-Info and QE-Identity JSON are signed by the TCB-Signing key.
- **Steps 4-10**: QE report signature (by PCK), `report_data` binds the attestation key (G3), QE identity policy (MRSIGNER, ISVPRODID, masked MISCSELECT/ATTRIBUTES), ISV signature (by the attestation key), and the public measurement binding.
- **TCB status (G2/G5)**: every comparison value is read from the signed JSON (per-level SGX/TDX component SVNs, pcesvn, status→severity; QE isvsvn + status); canonical first-satisfiable level; merged severity asserted ≠ Revoked.
- **Revocation (G4)**: CRL non-membership for BOTH the PCK CRL and the Root CA CRL — each is a validly-signed CRL (C4 v2 tbsCertList structure anchor + C5 freshness window) and the target serial is absent from the revoked list.
- **Freshness/validity**: issueDate ≤ Timestamp ≤ nextUpdate on TCB-Info, QE-Identity, and both CRLs; notBefore ≤ Timestamp ≤ notAfter on every chain cert.

Public outputs: `MrTd`, `Rtmr0..3`, `ReportData`, `TcbStatus`, `Timestamp`, `CertSerial`, `Fmspc`, `TcbInfoEvalNum`, `QeIdEvalNum`, `ValidFrom`, `ValidUntil`. (The Noir circuit packs these into 21 BN254 field elements to fit the Xion `x/zk` public-input cap.)

`TcbInfoEvalNum`/`QeIdEvalNum` are the `tcbEvaluationDataNumber` of each signed blob, emitted separately (a single `min` let a stale TCB-Info ride a current QE-Identity past a monotone floor — see issue #4). `[ValidFrom, ValidUntil]` (packed `YYYYMMDDhhmmss`) is the intersection of every signed validity window (cert `notBefore/notAfter`, CRL `thisUpdate/nextUpdate`, collateral `issueDate/nextUpdate`). The proof attests that *some* instant inside that window was valid; the host still picks `Timestamp` inside it (note: `ValidFrom`/`ValidUntil` are collateral-determined, independent of the host `Timestamp`). **A consumer MUST therefore (a) range-check chain time against `[ValidFrom, ValidUntil]` rather than trusting the host-chosen `Timestamp`, and (b) reject either eval number below its monotonic per-FMSPC on-chain floor.** Together these close stale-collateral replay and stale-TCB selection (no in-circuit clock or counter exists, so the freshness/recency decision is the consumer's).

Both circuits were hardened over repeated adversarial fan-out audits (the gnark circuit converged to zero residuals over five rounds; the Noir circuit's two optimizations were checked sound-equivalent across six independent reviews).

## Layout

```
zkdcap/
├── core/                  # Shared Rust types (DcapJournal)
├── host/                  # Host: Intel PCS collateral fetch + witness build, dispatch to a prover
├── circuits/dcap-gnark/   # gnark Groth16 circuit + witness builder + CLI tools
├── circuits/dcap-noir/    # Noir / Barretenberg UltraHonk circuit (workspace: p256_one, certlink, dcap) + Go witness gen
├── examples/dstack-prove/ # Example dstack TEE service that proves its own quote
└── test/                  # Shared fixtures (quote.bin, collateral.json, timestamp.txt)
```

## gnark circuit (Groth16)

`circuits/dcap-gnark/circuit` implements the full self-anchoring verification on BN254
(chain.go / collateral.go / crl.go / tcbextract.go / extract.go / derive.go …). Field
extraction uses a `std/lookup` logderivlookup byte table (each read ~3 constraints).
It is the slower-per-gate but well-understood path; the CRL non-membership uses a
direct per-byte substring scan over both CRLs. Negative tests teeth-verify every gap
class (G1–G5, C1–C5, F1–F3, H1–H3).

```sh
cd circuits/dcap-gnark
go test ./...                       # compile + prove/verify against fixtures (TestCircuitCompile logs the constraint count)
go run ./cmd/keygen                 # compile + groth16.Setup -> ccs.bin, pk.bin, vk.bin
go run ./cmd/gen-fixture quote.bin collateral.json pre_verified.json
```

## Noir circuit (UltraHonk) — deployed

`circuits/dcap-noir/crates/dcap` is the Barretenberg UltraHonk circuit. Toolchain:
nargo 1.0.0-beta.19 + bb 4.0.4 (byte-compatible with Xion's `barretenberg-go` v0.4.0).

- **1,946,389 gates** (under 2²¹); prove ~5.4 s / ~4.4 GB RAM (Apple M5 Max), write_vk ~3.0 s, vk 3680 B, proof 16000 B; no per-circuit trusted setup.
- Two soundness-preserving optimizations vs the naive form: a rolling-fingerprint **product-accumulator** for CRL non-membership (a 20-byte serial is 160 bits < the BN254 field, so the big-endian window integer is injective; the product is zero iff some window matches), and a **prefix-sum** H1 status pin (one buffer scan replaces a per-level scan). Both audited sound-equivalent; crossing the 2²²→2²¹ dyadic bucket roughly halves prove time.
- Deployed on **xion-testnet-2** as vkey `dcap-ultrahonk-v1` (id 15) and on-chain verified (`verify-ultrahonk → {"verified":true}`).

```sh
cd circuits/dcap-noir
nargo test                          # inline gadget tests
tools/run_tests.sh                  # honest + negative harness
nargo execute --package dcap_full   # build witness -> target/dcap_full.gz
bb write_vk -s ultra_honk -b target/dcap_full.json -o vk
bb prove    -s ultra_honk -b target/dcap_full.json -w target/dcap_full.gz -k vk/vk -o proof
bb verify   -s ultra_honk -p proof/proof -k vk/vk -i proof/public_inputs
```

## On-chain verification (Xion `x/zk`)

Proof verification is a whitelisted query that charges **zero gas**; vkey upload is
permissionless (any account can `add-vkey`; only the original registrant can
`update-vkey`/`remove-vkey`).

```sh
# gnark Groth16
xiond tx zk add-vkey zkdcap-gnark vk.bin "zkDCAP gnark Groth16" gnark --from <key>

# Noir UltraHonk (as deployed)
xiond tx zk add-vkey dcap-ultrahonk-v1 circuits/dcap-noir/target/dcap_full.vk \
  "zkDCAP Noir UltraHonk" ultrahonk --from <key>
xiond query zk verify-ultrahonk proof/proof \
  --vkey-name dcap-ultrahonk-v1 --public-inputs-file proof/public_inputs
```

## Host (Rust)

`prove_quote(raw_tdx_quote, …)` in `host/` fetches PCS collateral from Intel, builds
the circuit witness, and dispatches to a prover. The gnark backend talks to a
long-running gnark-prove server over a unix socket (default `/tmp/gnark.sock`) that
loads `ccs.bin` + `pk.bin` at boot so it does not recompile per request.

```sh
cargo build -p zkdcap-host
cargo run -p zkdcap-host -- \
  --dstack-url '<attestation-url>' --backend gnark --gnark-socket /tmp/gnark.sock \
  --output proof.json
```

> The Rust workspace expects the `dcap-qvl` crate as a sibling checkout
> (`../dcap-qvl`) for host-side collateral parsing.
