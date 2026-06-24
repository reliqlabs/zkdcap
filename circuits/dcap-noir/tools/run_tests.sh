#!/usr/bin/env bash
# Honest + negative test harness for the secure DCAP Noir circuit.
# Honest witness must solve; each mutation must make nargo execute FAIL.
#
#   tools/run_tests.sh
set -u

export PATH="$HOME/.nargo/bin:$HOME/.bb-v4.0.4:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/../dcap-gnark/testdata/fixtures/zkdcap"
QUOTE="$FIX/quote.bin"
COLL="$FIX/collateral.json"
DCAP="$ROOT/crates/dcap"
GEN="$(mktemp -d)/genprover"

cd "$ROOT/tools" && go build -o "$GEN" genprover.go toml.go || { echo "generator build failed"; exit 1; }

pass=0; fail=0
run() { # name  expect(ok|fail)  mutate
  local name="$1" expect="$2" mutate="$3"
  "$GEN" -quote "$QUOTE" -collateral "$COLL" -mutate "$mutate" > "$DCAP/Prover.toml" 2>/dev/null
  if [ $? -ne 0 ]; then
    # generator itself rejected the mutation (also a valid rejection)
    if [ "$expect" = "fail" ]; then echo "PASS  $name (generator rejected)"; pass=$((pass+1)); else echo "FAIL  $name (generator error on honest)"; fail=$((fail+1)); fi
    return
  fi
  ( cd "$DCAP" && nargo execute >/dev/null 2>&1 )
  local rc=$?
  if [ "$expect" = "ok" ]; then
    if [ $rc -eq 0 ]; then echo "PASS  $name (solves)"; pass=$((pass+1)); else echo "FAIL  $name (should solve, errored)"; fail=$((fail+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "PASS  $name (rejected)"; pass=$((pass+1)); else echo "FAIL  $name (FORGERY ACCEPTED)"; fail=$((fail+1)); fi
  fi
}

echo "== honest =="
run "honest"          ok   ""
echo "== negatives =="
run "G1 fmspc-off"    fail g1-fmspc-off
run "G1 eval-off"     fail g1-eval-off
run "C1 tcb-idx"      fail c1-tcb-idx
run "C1 qe-idx"       fail c1-qe-idx
run "G2 forged-sgx"   fail g2-forged-sgx
run "G5 noncanonical" fail g5-noncanonical
run "C3 cross-status" fail c3-cross-status
run "F1 skip-level"   fail f1-skip-level
run "F2 tdx-crosslvl" fail f2-tdx-crosslvl
run "F3 qe-skip"      fail f3-qe-skip
run "C4 cert-as-crl"  fail c4-cert-as-crl
run "C5 stale-crl"    fail c5-stale-crl
run "ROOT-PIN wrong"  fail root-pin
run "G3 attest-key"   fail g3-attest-key
run "H3 expired-cert" fail expired-cert

echo "== public-input size (Xion x/zk cap = 10240 B / 320 fields) =="
# honest witness -> bb prove -> public_inputs must be <= 10240 B (20 packed fields = 640 B).
"$GEN" -quote "$QUOTE" -collateral "$COLL" > "$DCAP/Prover.toml" 2>/dev/null
( cd "$DCAP" && nargo execute >/dev/null 2>&1 )
PKDIR="$(mktemp -d)"; mkdir -p "$PKDIR/vk" "$PKDIR/proof"
bb write_vk -s ultra_honk -b "$ROOT/target/dcap_full.json" -o "$PKDIR/vk" >/dev/null 2>&1
bb prove -s ultra_honk -b "$ROOT/target/dcap_full.json" -w "$ROOT/target/dcap_full.gz" -k "$PKDIR/vk/vk" -o "$PKDIR/proof" >/dev/null 2>&1
pisz=$(wc -c < "$PKDIR/proof/public_inputs" 2>/dev/null || echo 999999)
if [ "$pisz" -le 10240 ]; then echo "PASS  public_inputs = ${pisz} B (<= 10240)"; pass=$((pass+1)); else echo "FAIL  public_inputs = ${pisz} B (> 10240 cap)"; fail=$((fail+1)); fi

echo ""
echo "RESULT: $pass passed, $fail failed"
echo "(G-2 H1 platform first-status pin is covered by nargo test: der::test_h1_rejects_forward_status)"
# restore the honest Prover.toml
"$GEN" -quote "$QUOTE" -collateral "$COLL" > "$DCAP/Prover.toml" 2>/dev/null
[ $fail -eq 0 ]
