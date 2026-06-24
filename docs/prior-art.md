# zkDCAP Prior-Art and Lessons-Learned Report

> Produced by a multi-agent prior-art sweep (33 agents, 73 raw findings → 63 unique →
> 16 deep-read and confirmed against real sources, plus an 18-item completeness pass).
> Claims about our own circuits were cross-checked against `chain.nr`, `tcb.nr`,
> `crl.nr`, and the gnark `chain.go` source.

## 1. Has anyone else done this?

Yes, the *problem* (compress an Intel DCAP quote + PCS collateral into one succinct
on-chain-verifiable proof) is well-trodden. The *approach* is not.

Every confirmed-real DCAP-specific effort is a **zkVM**: datachainlab/zkdcap, Automata
DCAP Attestation, Phala zk-sgx-attester, and the shared `dcap-rs`/`dcap-qvl` Rust QVL
lineage all compile the ordinary Intel QVL to RISC-V and prove the execution trace
(RISC Zero / SP1 / Pico), then wrap to Groth16/Plonk for EVM. None of them is a
hand-written native arithmetic circuit specialized to the DCAP relation. On the
native-circuit side, the closest neighbors (zkPassport, Self/OpenPassport, ZK Email)
are X.509/PKI-in-ZK projects in *different* trust domains; the zkTLS family (TLSNotary,
DECO, Reclaim, Mina o1js attestations) and the ZK-coprocessor family (Axiom, Brevis,
Herodotus, vlayer) share our "untrusted host re-derives a signed statement in ZK"
threat model but target a different cryptographic object (a live TLS session, a notary
signature, or an on-chain state root), not DCAP, TCB-status evaluation, or QE-identity
policy.

So: **no public, DCAP-specific native-circuit verifier exists that we could find.**
This is a defensible claim about the public landscape (the DCAP-specific repos, the
audited references, the native-circuit X.509 projects), not a proof of universal
absence: the search space across academic publications and private/hackathon work is
large, and a competitor could close the gap with application-defined precompiles (see
§2, RISC Zero) without ever shipping a native circuit. We are the native-circuit point
in a field that is otherwise entirely zkVM (for DCAP), native-but-different-domain
(passport/email PKI), or different-object (zkTLS, coprocessors).

**The single most important comparison is Automata DCAP Attestation (zkDCAP path).** It
is the audited (Trail of Bits Mar 2025, OpenZeppelin Oct 2025), production reference.
Two findings matter:

1. Its scope matches ours exactly: PCK chain to Intel SGX Root CA, ECDSA-P256 +
   SHA-256, QE report + attestation-key binding, TCB-Info / QE-Identity signed JSON,
   TCB-status convergence, dual-CRL revocation, V3/V4/V5 SGX+TDX. We can use it (and
   `dcap-rs`) as a bit-for-bit oracle. Automata runs the *same* audited Rust verifier in
   two modes: SP1 and RISC Zero zkVM guests (off-chain proof, EVM verify) and a
   pure-Solidity on-chain replay. The published SP1 DCAP program VKEY is
   `0x0021feaf3f6c78429dac7756fac5cfed39b606e34603443409733e13a1cf06cc`.
2. Its trust anchor **converges with ours**: `dcap-rs` hardcodes `INTEL_ROOT_CA_PEM`,
   and our gnark constant `intelRootCAX = 0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5`
   is the byte-for-byte X-coordinate of Automata's pinned SPKI
   (`MFkw...EC6nEwMDIYZOj/iPWsCzaEKi71OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==`).
   Same Intel root key. Our Noir circuit pins the same key (`INTEL_ROOT_X/Y` in
   `chain.nr`). This is a free correctness sanity check that we passed, and it traces
   directly to Intel's own QVL source, where the Intel SGX Root CA public key is the
   hardcoded trust anchor.

The difference from Automata is *where* the pin lives and *how* trust closes: they pin
in the guest **and** require on-chain PCCS hash-binding (a governed mirror), so their
on-chain verifier is not collateral-self-contained. We re-derive everything from signed
bytes inside one proof and the verifier needs only our vkey.

## 2. The landscape

| Group | Who | Approach | On-chain? | Relevance |
|---|---|---|---|---|
| **Direct zk-DCAP** | Automata DCAP Attestation | zkVM (SP1 + RISC Zero/Boundless), `dcap-rs` guest, Groth16/Plonk wrap; pinned root in guest + on-chain PCCS hash bind | EVM/Solana; SP1 Groth16 493k / Plonk 569k / R0 Groth16 522k gas; 4–5M gas full on-chain | **Closest competitor.** Audited (ToB + OZ), V3/V4/V5 SGX+TDX. Oracle + gas baseline. Same audited Rust runs both zk and Solidity paths. |
| **Direct zk-DCAP** | datachainlab/zkdcap | zkVM RISC Zero (r0vm), derived from `dcap-rs`; emits `sgx_intel_root_ca_hash` (keccak) for on-chain equality check; min TCB-eval-data-number + collateral validity-window intersection committed | EVM ~280–522k gas; also Go (bn256) verifier | Audited (Quantstamp), shipped in LCP client. Best-documented downstream. Journal/output + validity-intersection design worth copying. |
| **zkVM backend** | RISC Zero r0vm (precompiles + Bonsai) | General rv32im zk-STARK with accelerated precompiles: SHA-256, P-256 (secp256r1), secp256k1, RSA/bigint, BN254, BLS12-381. App-defined precompiles since zkVM 1.2 (~10x). Bonsai hosted proving + Groth16 wrap | EVM (Groth16 wrap, hundreds-k gas) | **The zkVM platform under Automata + datachainlab.** Its P-256 precompile is *documented by the platform itself* as a "verify TEE attestation" primitive. App-defined precompiles are the convergence threat to "native is smaller." |
| **zkVM backend** | Succinct SP1 + secp256r1 precompile | RISC-V zkVM; patched `p256`/`sha2`/`crypto-bigint` crates route to precompiles; auto-gen Solidity Groth16/Plonk verifier | EVM, SP1 Groth16 ~493k gas (<30s prove), Plonk ~569k (<2min) | The other Automata backend. Precompile built *specifically* to cut DCAP's dominant P-256 cost. Patched-crate semantics are a flagged audit hazard. Hyli: SP1/R0 p256 proving is RAM-heavy, "unusable client-side." |
| **zkVM attestation** | Phala zk-sgx-attester (`tolak`) | zkVM RISC Zero, unmodified webpki+ring guest; consumed by Flashbots | EVM ~250k gas | Pioneer (2023–24), **SGX-only, no CRL, no TDX**, ~8h CPU proving. Archived Dec 2025. The "superseded ancestor." Built by Phala, not Flashbots. |
| **Reference / oracle** | Intel QVL + QvE + PCCS | Native C++ reference verifier (QVL); same logic in an SGX enclave (QvE); Node.js collateral cache (PCCS) | None (off-chain / enclave) | **The authoritative spec our circuit arithmetizes.** Intel Root CA key is the hardcoded anchor here. QvE is conceptually what we replace (attestable verdict without an enclave or live Intel). Differential-test oracle + TCB-status state machine reference. |
| **Native QVL / oracle** | `dcap-rs` / `dcap-qvl` (Phala/Automata) | Pure-Rust QVL, the guest *logic* itself (no ZK on its own) | n/a (consumed by above) | Our host already uses `dcap-qvl`. Differential-test oracle for witness build + circuit re-derivation. |
| **Native consumer (non-ZK)** | Phala dstack / dcap-qvl pipeline | Off-chain native Rust verify (`dcap-qvl`) feeding a KMS; on-chain contracts hold only an authorization allowlist | Authorization policy only; **no on-chain crypto verify** | **Integration target, not rival.** Its hardening update shipped a real bug: `dcap-qvl` had skipped mandatory QE-identity validation. A direct correctness checklist for our QE-policy gadget. |
| **Native consumer (non-ZK)** | Flashbots Flashtestations / BuilderNet | Production TDX registry; on-chain DCAP via Automata pure-Solidity lib (native EVM replay) | EVM, **gas so heavy it exceeds RPC block windows** (needs archive nodes) | The "replay DCAP on-chain" baseline we beat. `BlockBuilderPolicy.sol` measurement allow-list is complementary: our `MrTd`/`Rtmr` outputs are drop-in for it. Early Automata demo skipped on-chain TCBInfo-sig check, a "what others skip" contrast. |
| **Adjacent X.509-in-ZK** | zkPassport | **Native Noir/UltraHonk BN254** (same backend as ours), Goblin Plonk / Client IVC recursion; CSCA via off-chain Merkle registry; single deterministic-address root verifier | EVM, amortized via Aztec recursion | **Same backend family.** `noir-ecdsa` / `noir_bigcurve` P-256 gadgets to diff against ours. Recursive proof compression is the lever we deliberately skip. No in-circuit CRL. |
| **Adjacent X.509-in-ZK** | Self / OpenPassport (selfxyz) | Native Circom/Groth16 (Noir WIP); CSCA/DSC in on-chain Merkle registry; 3-circuit split | Celo, pays gas | Native, audited (zkSecurity). 3-circuit decomposition pattern. No in-circuit revocation. |
| **Adjacent X.509-in-ZK** | ZK Email (PSE) | Native Circom/Halo2/Noir; RSA-2048+SHA256 DKIM; on-chain `DKIMRegistry.sol` | EVM ~1.5M gas; **also on Xion x/zk** | Precomputed/partial-SHA256 trick. `zk-regex` DFA selective disclosure. Precedent on our exact verification substrate. |
| **Adjacent X.509-in-ZK** | zk-X509 (Tokamak, arXiv 2603.25190) | zkVM SP1, x509-parser guest; mutable on-chain CA Merkle root | EVM ~300k gas | Concrete zkVM cost anchor: P-256 ~11.8M cycles, ~5min CPU/sig, +33% for CRL. Address-binding + nullifier patterns. |
| **Adjacent: signed-statement-in-ZK** | zkTLS family: TLSNotary, DECO, Reclaim; Mina o1js (`mina-attestations`, ZKON) | TLSNotary/DECO = MPC-TLS + zk selective-disclosure wrapper; Reclaim = signed-attestor proxy + zk-SNARK; Mina = native o1js ZkProgram, foreign-field ECDSA + SHA | Reclaim/Mina verify on-chain; TLSNotary/DECO off-chain (oracle) | **Same threat model, different object.** They prove a live TLS session or one credential sig and need a *live* notary/attestor. We prove an offline, already-signed PKI artifact with no live co-signer. Mina o1js ECDSA/SHA are gate-count sanity references. **None do CRL or PKI-chain depth.** |
| **Adjacent: ZK coprocessors** | Axiom, Brevis, Herodotus, vlayer | Axiom/Herodotus = halo2+KZG storage proofs vs on-chain state root; Brevis = data zkVM; vlayer = TLSNotary Web Proofs | EVM verifier contracts, pays gas | Axiom's `halo2-ecc` (secp256k1 ECDSA ~2s, open source) is the best public EC/field gadget-cost reference. Their authenticity primitive is Merkle inclusion vs an anchored block hash, which is why they avoid in-circuit sig replay and we cannot. **None do CRL non-membership or signed-JSON policy.** |
| **Native ZK gadgets** | noir-bignum / noir_bigcurve / noir-ecdsa | Noir gadget libs (Secp256r1 predefined); unconstrained-Jacobian + batched-inverse + affine-constrain | n/a (UltraHonk verifier ~2.4M gas downstream, community estimate) | The standard P-256/SHA-256 stack our Noir circuit sits on. ~2M constraints for one *explicitly emulated* P-256 verify is the per-sig anchor; the stdlib blackbox is far cheaper. |
| **Verifier stack (ours)** | Aztec Barretenberg UltraHonk + `bb write_solidity_verifier` | Honk (Sumcheck + Shplemini, BN254); auto-gen `HonkVerifier.sol` (keccak oracle); Goblin Plonk / Client IVC recursion | EVM verifier ~2.4M gas (**unsourced community estimate**; bb docs publish no number, warn "contract too big"/"stack too deep") | Our exact backend. EVM path is the cost we sidestep via Xion x/zk. Pin the exact `bb` version: UltraHonk soundness patches shipped (0.82.2, 2.0.3). |
| **P-256 benchmarks** | Hyli/vladfdp, Base | Native-circuit single-sig P-256 benches across Noir/Circom/gnark/Halo2; Hyli also benches in-browser zkVM p256 | Base measures EVM gas | Backend-tradeoff validation: UltraHonk ~2.4M gas vs Groth16 ~350–410k gas; Noir 5–50x faster proving. Hyli: SP1/R0 unusable client-side on RAM. |
| **On-chain TEE verifier (non-ZK cost baseline)** | Automata full-on-chain Solidity path; automata-on-chain-pccs | Re-runs QVL in Solidity; RIP-7212 P-256 precompile | EVM 4–5M gas (4M with RIP-7212) | The cost we beat. RIP-7212 precompile verifies a P-256 sig for ~3,450 gas; an in-Solidity P-256 lib (e.g. daimo-eth/p256-verifier, FCL) costs ~200–330k gas per verify. |
| **Verification substrate (ours)** | XION x/zk (Burnt Labs) | Native gnark-in-Go protocol verifier (Groth16 prod, UltraHonk deployed) | Cosmos query, **zero gas**, permissionless vkey | Where we deploy (`dcap-ultrahonk-v1`, id 15, on-chain `{"verified":true}`). Not a rival; our on-chain layer. |
| **Academic lineage (EPID/DAA)** | *(background only)* | Intel EPID / Direct Anonymous Attestation: group-signature anonymous attestation, the pre-DCAP scheme DCAP replaced | n/a | Lineage context only. DCAP moved attestation trust from EPID group sigs to an X.509 PCK chain + PCS collateral, which is the relation we arithmetize. Cite only as background, not a ZK datapoint. |

## 3. Where we are differentiated

1. **Native arithmetic circuit, not a zkVM.** Every DCAP competitor (Automata via SP1 +
   RISC Zero, datachainlab via r0vm, Phala, zk-X509 via SP1) proves a RISC-V execution
   trace. We hand-arithmetize SHA-256 + ECDSA-P256 + JSON re-derivation directly. The
   payoff is in the cost model: the zkVM camp pays millions of RISC-V cycles even
   *after* dedicated precompiles (Automata's headline optimization was 123M→3M cycles
   via secp256r1/SHA-2/crypto-bigint precompiles; zk-X509 reports ~11.8M cycles and
   ~5min CPU for *one* P-256 sig). Both SP1 and RISC Zero built a P-256 precompile
   *specifically because* P-256 ECDSA across the cert chain + QE/TCB sigs is the
   dominant DCAP cost, which is exactly the work a native circuit specializes. Our full
   chain is **1,945,749 gates, ~5.4s / 4.4GB on an M5 Max**, local, no prover network.
   For per-sig calibration: in the native-circuit benchmarks (noir_bigcurve / Base) one
   *explicitly emulated* P-256 verify is ~2M BN254 constraints, but our circuit does not
   emulate, it routes through the Barretenberg blackbox (confirmed in source, see point
   5 below), so that ~2M figure is the cost we *avoid*, not the cost we pay per
   signature. Do **not** read our 1.95M-gate total as "one P-256 sig's worth of work";
   it is the whole multi-signature relation built on the blackbox path, and the right
   comparison is cycles-saved-vs-zkVM, not constraints-vs-emulated-sig.

2. **Self-anchoring root as an in-proof constant.** The Intel SGX Root CA P-256 key is a
   hardcoded circuit constant (`INTEL_ROOT_X/Y` in `chain.nr`, `intelRootCAX/Y` in gnark
   `chain.go`), asserted against the witness root in `pin_root`, and the full PCK chain
   validates to it in-ZK. The verifier needs nothing but proof + vkey. Contrast:
   datachainlab emits a keccak root hash for the on-chain contract to check; RISC
   Zero-based DCAP commits `Keccak-256(Intel Root CA cert)` to the journal and pins it
   on-chain at runtime; Automata pins in-guest **but also** binds collateral to a mutable
   on-chain PCCS mirror; zkPassport/Self/ZK Email all use mutable, admin-governed
   on-chain Merkle/registry roots. Compile-time pinning removes a runtime on-chain
   equality check and a whole bug class ("verifier forgot to pin the right hash,"
   "policy contract points at a stale root"). We are the only one with **zero external
   mutable trust state**.

3. **Dual backend, same circuit semantics.** gnark/Groth16 (smallest proof, per-circuit
   setup) and Noir/UltraHonk (no per-circuit setup, deployed). This straddles the exact
   tradeoff the Base/Hyli benchmarks document (UltraHonk ~5–50x faster proving but
   ~2.4M-gas EVM verifier; Groth16 tiny constant proof + trusted setup), and it mirrors
   Automata's own SP1 Groth16-vs-Plonk wrap choice, confirming exposing both backends is
   a reasonable stance. Most prior art picks one.

4. **Xion x/zk zero-gas verification.** Verified as a whitelisted query at zero gas with
   permissionless vkey upload. This is concrete, not aspirational: the Noir UltraHonk
   circuit is **deployed on xion-testnet-2 as vkey `dcap-ultrahonk-v1` (id 15) and
   on-chain verified** (`verify-ultrahonk → {"verified":true}`). The gnark/Groth16 path
   is the in-dev second backend; the headline zero-gas claim rests on the deployed
   UltraHonk path, so state it precisely as "the deployed UltraHonk verifier on Xion x/zk
   charges zero gas," not "all our backends are live." Every DCAP competitor pays real
   EVM gas (250k–569k zk-wrapped via Groth16/Plonk, 4–5M full on-chain), including the
   RISC Zero/SP1 paths whose STARK receipts *must* be Groth16-wrapped (via Bonsai/SP1) to
   be EVM-cheap. This is a categorical on-chain-cost difference for the deployed path.

5. **Two native-circuit gadget optimizations with no zkVM analogue.** Both verified in
   source:
   - **CRL non-membership via a rolling-fingerprint product accumulator**
     (`serial_window_product`, `crl.nr`). A 20-byte serial is 160 bits < the 254-bit
     BN254 field, so the big-endian window integer is injective; `prod = Π(fp(p) - tgt)`
     is zero iff some window matches. One inverse total instead of one equality scan per
     position. Applied to **both** PCK and Root CA CRLs, each with a v2-CRL structural
     anchor (`CRL_TBS_HEAD_CTX`) and a thisUpdate ≤ ts ≤ nextUpdate freshness window. The
     zkVM and native-reference camps (QVL, `dcap-qvl`, zk-X509) do plain serial-in-list
     iteration / full-DER-CRL parse, which is free in a VM but has no efficiency story in
     a circuit, and the coprocessor and zkTLS families have *no* revocation gadget at all.
     This is a genuinely novel contribution in this space.
   - **Prefix-sum H1 status pin** (`status_cumsum` / `bind_one_level`, `tcb.nr`): one
     buffer scan of the `"tcbStatus":` anchor, reused by every TCB level, replacing a
     per-level scan.

   The ECDSA and SHA-256 primitives those gadgets sit on route through the Barretenberg
   blackbox, confirmed directly in source (not inferred from gate count):
   `std::ecdsa_secp256r1::verify_signature` in `der.nr` / `certlink/main.nr` /
   `p256_one/main.nr` and `sha256::sha256_var` in `der.nr` / `steps.nr`. The C++ blackbox,
   not an in-Noir field-emulated curve, is what keeps the whole relation at ~1.95M gates
   instead of ~2M *per signature*.

## 4. What we can learn / borrow

**Gadget techniques**

- **Blackbox routing is confirmed; keep it that way and batch inverses.** The Base/Hyli
  benchmarks are blunt: one explicitly emulated P-256 sig is ~2M BN254 constraints and
  won't fit a browser tab; the blackbox (C++, not expanded to constraints) is what makes
  it tractable. Our P-256/SHA-256 calls go through `std::ecdsa_secp256r1::verify_signature`
  and `sha256_var` (verified in `der.nr`, `certlink`, `p256_one`, `steps.nr`), so the
  blackbox path is in use, not assumed. The remaining action is gadget-internal: where we
  do any non-native field work around the blackboxes, match noir_bigcurve's
  unconstrained-Jacobian → batched modular inverse → affine-constrain strategy and
  noir-bignum's `evaluate_quadratic_expression` (constrain `a*b - q*p - r == 0 mod p` in
  one quadratic gate). Axiom's open-source `halo2-ecc` (secp256k1 ECDSA in ~2s) and Mina
  o1js's foreign-field ECDSA/SHA are the two best external references for sanity-checking
  those costs even though both target different curves.
- **Partial/precomputed SHA-256** (ZK Email's biggest hashing win, ~100 constraints/byte).
  If any signed collateral region has a large prefix where only a tail/window matters,
  hash the prefix outside the circuit and finish the trailing block in-circuit.
- **`zk-regex` DFA-transition proofs** (ZK Email) are a more flexible alternative to
  hand-rolled byte indexing if we ever need to expose a substring of signed JSON rather
  than the whole structured output. Not needed today; note for TCB-field selective
  disclosure.
- **Selective disclosure is a validated shared pattern.** TLSNotary's redaction +
  range-proofs and Reclaim's "reveal only chosen fields" mirror our choice to expose only
  `MrTd`/`Rtmr`/`ReportData`/`TcbStatus`/`Timestamp`/`CertSerial`/`Fmspc`. Confirm we are
  not leaking more in public inputs than a consumer needs.

**Set non-membership / CRL** — our product-accumulator is genuinely cheaper than every
prior approach (zkVM/QVL serial iteration, zk-X509's in-VM full-DER-CRL parse whose
cycles scale with list size, zkPassport/Self/coprocessors/zkTLS which have **no
in-circuit revocation at all**). This is a real novel contribution. Validate it against
the *semantics* of `dcap-qvl`/QVL, not their implementation: confirm we revoke on the
same serials they do (including the CRL freshness/nextUpdate windows). On the
**Platform-vs-Processor PCK CRL dual-source** case (QVL/Automata accept whichever PCK CA
CRL exists): source review shows this is already handled, not a gap.
`verify_crl_non_membership` (`crl.nr`) checks the PCK CRL signature against `pca_x/pca_y`,
the intermediate CA key *extracted from the actual chain cert* `int_tbs`
(`main.nr:194-197`), not a hardcoded Platform CA. The "Platform CA" strings in
`chain.nr:58-77` are comment naming; the data flow (`verify_chain_to_root` →
`extract_subject_pubkey(int_tbs, …)` → `cert_link`) is issuer-generic, so a PCK leaf
chaining through Processor CA is verified against the Processor CA key the same way. See
risk 4 (refuted on source review).

**zkVM-vs-circuit tradeoffs others document** — the consistent lesson across Automata
(123M→3M cycles), zk-X509 (~5min/sig CPU), Phala (~8h CPU), and the platform precompile
work (RISC Zero/SP1 both built a P-256 precompile to cut exactly this) is that
**ECDSA-P256 and SHA-256 dominate cost in a zkVM**, which is exactly the work a native
circuit specializes. This is our headline justification, and it is well-supported. The
countervailing lesson, equally consistent: zkVMs get **format coverage and
maintainability for free** (V3/V4/V5, SGX+TDX, audited, recompile-to-update) and reuse
the audited reference Rust (lower DCAP-logic spec risk, at the cost of a much larger
trusted base: the whole rv32im circuit plus every precompile). Our native circuit
inverts that tradeoff: single-shape and brittle to Intel quote-format churn, but a tiny
purpose-built trusted base. **Convergence watch: RISC Zero zkVM 1.2 added
application-defined precompiles (developer-pluggable accelerated circuits, ~10x). A
competitor could add a DCAP-specific fused X.509-parse/verify precompile inside r0vm and
approach native-circuit efficiency without leaving the zkVM.** Track this as the threat
to "native is smaller." Budget for circuit re-derivation + new vkey per format change,
and document which quote version(s) our vkey covers.

**On-chain verification patterns to borrow**

- **Expose collateral hashes and/or the root-CA hash as public outputs even though we pin
  in-circuit** (Automata + datachainlab + RISC Zero journal pattern). Cheap, aids
  auditability, lets a Xion-side policy detect/triage a root or collateral change without
  re-proving.
- **Commit an intersected collateral validity *range*, not just a single prover-chosen
  `Timestamp`** (datachainlab + RISC Zero pattern: emit `[max(notBefore), min(nextUpdate)]`
  across all collateral and let the on-chain consumer check block time against the range).
  This is the cleanest fix for risk 1; see §5.
- **Output schema discipline** (Automata's versioned journal: length prefix + body-type
  discriminator SGX/TD1.0/TD1.5 + timestamp + collateral hashes). Add a `quoteBodyType`
  discriminator to our packed outputs so one verifier can distinguish SGX vs TDX1.0 vs
  TDX1.5.
- **Keep `TcbStatus` as a multi-valued public output; do not collapse to a boolean.**
  Phala/dstack deprecated their catch-all `is_valid` boolean precisely because it hid
  `UpToDate` vs `SWHardeningNeeded` vs `OutOfDate` vs `ConfigurationNeeded` from the
  consumer. We already output `TcbStatus`; keep it, do not add a convenience accept/reject
  bit.
- **Make our public outputs registry-comparable.** Flashbots' BuilderNet maps RTMR values
  to vetted reproducible-build software via a measurement registry; our
  `MrTd`/`Rtmr0..3`/`ReportData` outputs are drop-in for a Flashtestations-style
  `BlockBuilderPolicy.sol` allow-list, except a consumer pays zero verification gas
  against our proof instead of replaying DCAP in Solidity. Document this path.
- **Multi-vkey acceptance window** (Automata's multi-program-identifier grace period;
  zkPassport's deterministic versioned root verifier). Plan our Xion vkey rotation as a
  grace-period roll-forward, not a hard cutover. Version the vkey id
  (`dcap-ultrahonk-v1`) so collateral/format changes don't break existing integrators.
- **Cross-check public-input packing against ZK Email on Xion x/zk** — they ship on the
  same module. Our 17-field BN254 packing must match exactly what the on-chain UltraHonk
  verifier deserializes (byte layout, fr ordering, endianness), or proofs that verify
  locally fail on-chain.
- **Pin the oracle hash and the `bb` version.** When targeting any EVM verifier you must
  generate vkey *and* proof with `--oracle_hash keccak` (Poseidon makes `HonkVerifier.sol`
  far more expensive); confirm which oracle hash Xion's x/zk expects so we don't ship a
  mismatched transcript. Barretenberg has shipped UltraHonk soundness patches (e.g.
  0.82.2, 2.0.3 in zkPassport's changelog), so pin the exact `bb` version used to produce
  our vkey/proof and track its CVEs: a backend soundness bug undermines self-anchoring
  regardless of circuit correctness.

**Things we may be reinventing** — the P-256 ECDSA gadget. zkPassport's `noir-ecdsa`
(built on `noir_bigcurve`, Secp256r1 predefined, in production) is maintained and
audited-by-usage. We route through the Noir stdlib blackbox rather than that library, so
we are not duplicating `noir-ecdsa` directly, but we should benchmark our blackbox path
against it to justify staying on stdlib. Note `noir_rsa` was archived (2025-05-01) and
ECDSA migrated to the zkpassport org; we're P-256-only so we dodge the RSA fragmentation
entirely. Mina o1js's foreign-field ECDSA is another reference if we ever leave the
blackbox.

**Soundness pitfalls others hit**

- **QE-identity validation is a real shipped CVE-class bug.** Phala/dstack's
  attestation-pipeline hardening found `dcap-qvl` had skipped *mandatory* QE-identity
  validation (a verifier could accept quotes from an unauthorized QE) and made
  QE-identity + TCB-status checks mandatory-by-default. Since we reuse `dcap-qvl` for
  witness building, this is a direct checklist item: confirm our circuit *hard-enforces*
  the full QE identity policy (MRSIGNER, ISVPRODID, masked MISCSELECT, masked ATTRIBUTES,
  ISVSVN floor from the signed QE-Identity JSON) and that none of it is
  witness-controlled/optional. This is exactly the check Phala forgot.
- **Validity-window edge cases shipped to production.** OpenZeppelin found a PCCS Router
  timestamp-validity bug in Automata (fixed v1.1). We enforce
  `issueDate ≤ Timestamp ≤ nextUpdate` and `notBefore ≤ Timestamp ≤ notAfter` per
  collateral object in-circuit (confirmed in `crl.nr` C5 and the README). Make **boundary
  timestamps on every collateral object's window** a priority audit target; the reference
  impl proves this bug class is real.
- **Under-constrained signals are the dominant bug class** in native-circuit audits (ZK
  Email Noir audit, Consensys Diligence Dec 2024; Self, zkSecurity). Our masked-equality /
  windowing / product-accumulator gadgets are exactly the high-risk surface. The product
  accumulator already has present-at-first / present-at-last / top-byte-distinguished
  regression tests (`crl.nr`) and a documented `256^19`-vs-`256^21` footgun that was
  caught; keep that level of teeth-verification for every gadget.
- **Patched-crate / blackbox semantics are a trust dependency for everyone.** SP1's
  correctness depends on its patched `p256`/`sha2` matching upstream (a flagged audit
  hazard); ours depends on the Barretenberg `std::ecdsa_secp256r1`/`sha256_var` blackboxes
  being correct. We have fewer hand-written crypto constraints to audit than a
  from-scratch in-Noir curve, but the blackbox is not zero-trust; it is the same class of
  dependency SP1's audit checklist flags, just shifted to the bb backend (hence the
  version-pinning action above).
- **Program-identity pinning.** The vkey *is* our program identity (analogous to
  imageID/program-VKEY in the zkVM camp, e.g. Automata's published SP1 VKEY). Ensure the
  on-chain consumer pins the exact expected `--vkey-name`/circuit hash, not "some valid
  UltraHonk proof." Document who can `update-vkey`/`remove-vkey`.

**Differential testing** — run the same quote + collateral through `dcap-qvl`/QVL and our
witness builder and assert identical public outputs (`TcbStatus`, `Fmspc`, `MrTd`,
`Rtmr0..3`, `CertSerial`) bit-for-bit on a corpus of real quotes. We already depend on
`dcap-qvl` for parsing, so this is the cheap correctness floor before/alongside any audit.
Mirror QVL's verification *ordering* and its TCB-status state machine (per-level SGX/TDX
component SVNs + pcesvn, first-satisfiable level, status→severity, assert `!= Revoked`,
plus the `OutOfDate`/`ConfigNeeded`/`SWHardeningNeeded` nuances); any divergence from
QVL's evaluation order or status mapping is a soundness/completeness gap a reviewer will
flag.

## 5. Open risks / things to double-check

1. **Timestamp is prover-chosen within signed windows.** This is the most consistent gap
   flagged across prior art. We bind a single `Timestamp` and check all windows
   in-circuit, but a malicious host can pick any `Timestamp` inside every signed validity
   window. datachainlab, Automata, RISC Zero-based DCAP, and zk-X509 all push the final
   freshness check to a *trusted on-chain clock*: they commit the *intersection* of all
   collateral validity windows (`[max(notBefore), min(nextUpdate)]`) and let the on-chain
   contract range-check block time against that committed range. **Confirm the Xion-side
   consumer bounds our `Timestamp` public output against chain time**, otherwise
   stale-but-valid replay is possible. Strongly consider emitting the intersected validity
   range as an output so a verifier re-checks freshness at consumption rather than trusting
   our single `Timestamp`.

2. **No TCB-recency / `tcbEvaluationDataNumber` output. Confirmed gap.** datachainlab and
   Automata explicitly defend against a stale-but-validly-signed TCB-Info upgrading status
   by committing `min_tcb_evaluation_data_number` and comparing to an on-chain monotonic
   counter (RISC Zero-based DCAP adds a TCB-R minimum freshness counter checked on-chain).
   Source check: `tcb.nr` binds SVN levels + severity but does **not** parse or output
   `tcbEvaluationDataNumber` (no occurrence in the Noir TCB code). So a prover can today
   use an older-but-still-validly-signed TCB-Info and our timestamp check will not stop it.
   This is a real, confirmed gap: add a `tcbEvaluationDataNumber` (and/or `qeIdentity`
   issueDate) output and have the consumer compare against a monotonic on-chain floor.

3. **Cross-deployment / replay binding.** zk-X509 commits `chainId` + `registryAddress`
   and asserts `registrant == msg.sender`; zkPassport/Self/Reclaim use scoped nullifiers.
   Our public outputs don't bind the proof to a submitter or deployment, so a relayer can
   replay our proof. If any consumer needs replay protection, add a
   caller/recipient/chain-domain binding field to the public inputs.

4. **PCK CRL dual-source (Platform vs Processor). Refuted on source review — NOT a gap.**
   The original sweep flagged this from comment strings, but the data flow is
   issuer-generic. `main.nr:194-197` extracts the intermediate CA key
   (`pca_x/pca_y = extract_subject_pubkey(int_tbs, …)`) from the actual chain cert and
   passes it to `verify_crl_non_membership`, which `cert_link`-verifies the PCK CRL against
   that key (`crl.nr:35`). The leaf is verified against the same extracted key
   (`chain.nr:78`). So whether the PCK leaf chains through Platform CA or Processor CA, the
   CRL is checked against whatever intermediate key is in the witness. The "Platform CA"
   text in `chain.nr:58-77` is comment naming only. No Processor-CA branch is needed. Kept
   here as a record of a verified false positive.

5. **Format coverage is single-shape.** Our vkey covers one quote shape (TDX V4). Automata
   covers V3/V4/V5, SGX+TDX; the entire zkVM camp gets multi-format coverage by recompiling
   the same Rust. Document covered version(s) explicitly; any Intel quote/collateral-format
   change forces circuit re-derivation + new trusted setup (gnark) + new vkey upload. This
   is the maintenance tax of the native approach and should be a stated, budgeted risk, not
   a surprise. The application-defined-precompile convergence threat (§4) means this tax is
   also where a zkVM competitor could erode our efficiency edge while keeping their format
   flexibility.

6. **Audit gap.** Every confirmed-real DCAP competitor is audited (Automata: Trail of Bits
   + OpenZeppelin; datachainlab: Quantstamp; RISC Zero DCAP path: Quantstamp). Native
   circuits carry *higher* audit risk than reusing battle-tested QVL Rust, precisely
   because the bug surface is hand-written constraints, and the prior art proves the bug
   classes are real and shipped: Phala's missing QE-identity check, Automata's PCCS
   timestamp bug, the recurring under-constrained-signal findings in ZK Email/Self. The
   adversarial fan-out hardening (5 rounds gnark, 6 reviews Noir) is good but is not a
   substitute for a circuit-level audit of the SHA-256/ECDSA-P256 blackbox integration and
   the two custom optimizations. Run the `dcap-qvl`/QVL differential tests (§4) as the
   cheap correctness floor before/alongside that audit.

---

*Confidence note: "no public DCAP-specific native circuit exists" is a claim about the
searchable public landscape, not a universal-absence proof. The two source-verified gaps
(`tcbEvaluationDataNumber`, Processor-CA PCK CRL) and the gnark root-constant match were
checked directly against the circuit code.*
