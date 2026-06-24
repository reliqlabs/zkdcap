# zkdcap — agent notes

ZK proof system for Intel TDX DCAP attestation. **Two interchangeable circuits** realize
one verification relation, both self-anchoring (full PCK chain → pinned Intel Root CA,
collateral signatures, dual-CRL revocation, freshness — all in-circuit):
- **Noir / Barretenberg UltraHonk** (`circuits/dcap-noir/`) — deployed primary on
  xion-testnet-2. ~1.95M gates, 21-field packed journal.
- **gnark / Groth16** (`circuits/dcap-gnark/`) — secondary. ~10.7M constraints.

(There is no SP1/zkVM path — it was removed. Don't reintroduce one.)

## Rebuilding the Noir vkey / proof — USE THE SCRIPT

```sh
circuits/dcap-noir/tools/build.sh vk      # compile + vkey  -> target/dcap_full.vk + .vk_hash
circuits/dcap-noir/tools/build.sh proof   # witness + vkey + proof + verify
```

Do NOT hand-run `bb write_vk` unless you know the gotchas (the script encodes them):
- `bb write_vk -o X` treats **X as a directory** (writes `X/vk` + `X/vk_hash`). Passing a
  file path fails with `create_directories: File exists`. The canonical artifact
  `target/dcap_full.vk` is the `vk` file **copied** out of that dir.
- a vkey needs only `nargo compile`; `nargo execute` (compile + witness) is for proving.
- the prove `-timestamp` (unix seconds) must be inside the fixture collateral window
  (`1751624163` works).

Rebuild the vkey manually (`build.sh vk`) after any circuit change — the deployed/
registered vkey must match the current `.nr` source.

## Tests

- Noir: `cd circuits/dcap-noir && nargo test` (inline) + `tools/run_tests.sh` (honest +
  negative harness, 17 cases).
- gnark: `cd circuits/dcap-gnark && go test ./...` (`-skip TestCircuitProveVerify` to skip
  the slow full Groth16 prove).
- Cross-backend journal parity: `python3 circuits/diff-test/cross_backend.py`.

## Verification artifacts (Colosseum)

`.colosseum/` (gitignored, local) holds the intent (`intent.md`, currently v0.2.2), the
zkdcap↔Quartz boundary, the compose-ledger, adversarial attack reports, and the
differential-test plan. The host's Rust workspace needs the `dcap-qvl` crate (git dep).
