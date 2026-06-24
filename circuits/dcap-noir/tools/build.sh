#!/usr/bin/env bash
# Canonical build for the Noir/UltraHonk DCAP circuit. ONE reliable command —
# use this instead of hand-running bb (the gotchas below bite otherwise).
#
#   tools/build.sh vk      # (default) compile + vkey  -> target/dcap_full.vk + .vk_hash
#   tools/build.sh proof   # full: witness + vkey + proof + verify
#
# GOTCHAS this script encodes so you don't have to remember them:
#   - `bb write_vk -o X` treats X as a DIRECTORY (writes X/vk + X/vk_hash). Passing
#     a file path (`-o target/dcap_full.vk`) fails: "create_directories: File exists".
#     The canonical artifact target/dcap_full.vk is that vk file COPIED out.
#   - the prove timestamp (unix seconds) must fall inside the fixture's collateral
#     validity window; 1751624163 (2025-07-04) works for testdata/fixtures/zkdcap.
#   - `nargo compile` is enough for a vkey; `nargo execute` (compile + witness) is
#     only needed to prove.
# Requires nargo (1.0.0-beta.19) + bb (4.0.4) on PATH; this prepends the usual
# install locations.
set -euo pipefail
export PATH="$HOME/.nargo/bin:$HOME/.bb-v4.0.4:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"        # circuits/dcap-noir
cd "$ROOT"
FIX="$ROOT/../dcap-gnark/testdata/fixtures/zkdcap"
MODE="${1:-vk}"

echo "[1] nargo compile (-> target/dcap_full.json)"
nargo compile --package dcap_full

echo "[2] bb write_vk (-> target/dcap_full.vk + .vk_hash)"
VKD="$(mktemp -d)"; trap 'rm -rf "$VKD"' EXIT
bb write_vk -s ultra_honk -b target/dcap_full.json -o "$VKD"
cp "$VKD/vk" target/dcap_full.vk
cp "$VKD/vk_hash" target/dcap_full.vk_hash
echo "    vkey: target/dcap_full.vk  sha256=$(shasum -a 256 target/dcap_full.vk | cut -c1-16)"

if [ "$MODE" = "proof" ]; then
  echo "[3] honest Prover.toml + nargo execute (witness)"
  go run tools/genprover.go tools/toml.go \
    -quote "$FIX/quote.bin" -collateral "$FIX/collateral.json" -timestamp 1751624163 \
    > crates/dcap/Prover.toml
  ( cd crates/dcap && nargo execute )
  echo "[4] bb prove (-> target/proof/) + bb verify"
  PD="$ROOT/target/proof"; rm -rf "$PD"; mkdir -p "$PD"
  bb prove -s ultra_honk -b target/dcap_full.json -w target/dcap_full.gz -k "$VKD/vk" -o "$PD"
  bb verify -s ultra_honk -p "$PD/proof" -k "$VKD/vk" -i "$PD/public_inputs"
  echo "    proof: target/proof/proof ($(wc -c < "$PD/proof" | tr -d ' ') B), public_inputs $(( $(wc -c < "$PD/public_inputs") / 32 )) fields"
fi
echo "done."
