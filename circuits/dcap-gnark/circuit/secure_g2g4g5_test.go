package circuit_test

// Negative tests proving the G2 (misreport), G5 (downgrade), and G4
// (freshness/revocation) soundness gaps are closed. Each forges a witness that
// the pre-hardening circuit would have accepted and asserts the hardened circuit
// rejects it. All use test.IsSolved (no trusted setup) for fast iteration.

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"github.com/reliqlabs/zkdcap/circuits/dcap-gnark/circuit"
	"github.com/reliqlabs/zkdcap/circuits/dcap-gnark/witness"
)

func mustWitness(t *testing.T, ts uint64) *circuit.DcapCircuit {
	t.Helper()
	quoteBytes, coll := loadFixtures(t)
	w, err := witness.BuildWitness(quoteBytes, coll, ts)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}
	return w
}

func expectUnsat(t *testing.T, w *circuit.DcapCircuit, what string) {
	t.Helper()
	if err := test.IsSolved(&circuit.DcapCircuit{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatalf("%s: expected unsatisfiable", what)
	}
}

// === G2: TCB verdict / policy values must match the signed JSON ===

// TestG2ForgedTcbSeverity softens the platform TCB severity below what the
// Intel-signed tcbStatus encodes. The in-circuit tcbStatus extraction must
// reject the witness severity that disagrees with the signed JSON.
func TestG2ForgedTcbSeverity(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	// Level 0 is "UpToDate" (severity 0) in the signed JSON; forcing it to a
	// different code breaks the binding even though the value is "softer".
	w.TcbSeverity[0] = 0xFF // any value != the signed status code
	expectUnsat(t, w, "G2 forged TcbSeverity")
}

// TestG2ZeroQeMask sets the QE attributes mask to zero (vacuous policy). The
// mask is now bound to the signed QE-Identity JSON (real mask is non-zero), so a
// zero mask is unsatisfiable.
func TestG2ZeroQeMask(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	for i := range w.QeIdAttrMask {
		w.QeIdAttrMask[i] = uints.NewU8(0)
	}
	expectUnsat(t, w, "G2 zero QE attributes mask")
}

// TestG2ZeroQeMiscMask: same for the miscselect mask.
func TestG2ZeroQeMiscMask(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	for i := range w.QeIdMiscMask {
		w.QeIdMiscMask[i] = uints.NewU8(0)
	}
	expectUnsat(t, w, "G2 zero QE miscselect mask")
}

// TestG2ForgedPlatformPceSvn lowers the platform PCESVN below the value bound
// from the PCK leaf SGX extension, which would let a stale platform pass.
func TestG2ForgedPlatformPceSvn(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	w.PlatformPceSvn = 0 // real leaf PCESVN is 11
	expectUnsat(t, w, "G2 forged platform PCESVN")
}

// TestG2ForgedPlatformTeeTcbSvn changes a platform TEE TCB SVN away from the
// ISV-signed quote value it is now bound to.
func TestG2ForgedPlatformTeeTcbSvn(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	w.PlatformTeeTcbSvn[0] = uints.NewU8(0xFF)
	expectUnsat(t, w, "G2 forged platform TEE TCB SVN")
}

// TestG2ForgedPlatformCpuSvn changes a platform CPU SVN away from the value
// bound from the PCK leaf SGX extension.
func TestG2ForgedPlatformCpuSvn(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	w.PlatformCpuSvn[0] = uints.NewU8(0xFF)
	expectUnsat(t, w, "G2 forged platform CPU SVN")
}

// TestG2ForgedQeIsvProdId changes the QE isvprodid away from the signed JSON.
func TestG2ForgedQeIsvProdId(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	w.QeIdIsvProdId = 999 // real is 2
	expectUnsat(t, w, "G2 forged QE isvprodid")
}

// === G5: canonical (first-satisfiable) TCB level selection ===

// TestG5NonFirstSatisfiable picks a later, softer-severity TCB level while the
// first (canonical) level is also satisfied. The hardened step8 must reject any
// match index for which an earlier active level is satisfiable.
func TestG5NonFirstSatisfiable(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	// The honest match is level 0 (UpToDate). The platform also satisfies level 1
	// (OutOfDate, lower thresholds), so a downgrade prover would point at idx 1.
	if asInt(w.TcbMatchIdx) != 0 {
		t.Skipf("fixture honest match idx is %v, expected 0", w.TcbMatchIdx)
	}
	w.TcbMatchIdx = 1
	// Final status would then be max(OutOfDate, QE) -> set the public output to
	// match so only the canonical rule (not the status bind) is what rejects.
	w.TcbStatus = severityForLevel(t, 1)
	expectUnsat(t, w, "G5 non-first satisfiable TCB level")
}

// === G4: freshness window + revocation ===

// TestG4TimestampBeforeIssue uses a verification time before the collateral
// issueDate; the validity-window check must reject it.
func TestG4TimestampBeforeIssue(t *testing.T) {
	// 2025-06-01 is before the 2025-06-19 issueDate.
	w := mustWitness(t, 1748736000)
	expectUnsat(t, w, "G4 timestamp before issueDate")
}

// TestG4TimestampAfterNextUpdate uses a time past nextUpdate (collateral
// expired); must reject.
func TestG4TimestampAfterNextUpdate(t *testing.T) {
	// 2025-08-01 is after the 2025-07-19 nextUpdate.
	w := mustWitness(t, 1754006400)
	expectUnsat(t, w, "G4 timestamp after nextUpdate")
}

// The G4 revocation non-membership check (verifyCrlNonMembership) is exercised
// directly against the real Intel-signed PCK CRL in crl_test.go
// (TestG4RevokedSerialRejected / TestG4C4CertPosingAsCrl / TestG4C5StaleCrl),
// which lives in package circuit and can reach the unexported gadget.

// === C1: match-index range check ===

// frModMinus1 is the BN254 scalar field element representing -1 (p-1), i.e. the
// additive inverse of 1. Used to forge an out-of-range match index.
func frModMinus1() *big.Int {
	return new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
}

// TestC1ForgedTcbMatchIdx sets TcbMatchIdx to the field element p-1. Before the
// range check (ToBinary(idx,4)) this forged a UpToDate verdict for any platform:
// the upper bound passed (count-1-idx wraps positive) and every IsZero(idx-m)=0
// made the selection asserts vacuous and muxVar return 0. Must be unsatisfiable.
func TestC1ForgedTcbMatchIdx(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	w.TcbMatchIdx = frModMinus1()
	w.TcbStatus = 0 // the value the attack would forge
	expectUnsat(t, w, "C1 out-of-range TcbMatchIdx")
}

// TestC1ForgedQeTcbMatchIdx: same attack on the QE match index.
func TestC1ForgedQeTcbMatchIdx(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	w.QeTcbMatchIdx = frModMinus1()
	w.TcbStatus = 0
	expectUnsat(t, w, "C1 out-of-range QeTcbMatchIdx")
}

// === C2: per-component SVN thresholds bound to the signed JSON ===

// TestG2ForgedSgxComponentSvn lowers a signed sgx component SVN threshold; with
// bindSvnComponents=true the per-component binding must reject it.
func TestG2ForgedSgxComponentSvn(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	w.TcbSgxComps[0][0] = 0 // real fixture value is 2
	expectUnsat(t, w, "C2 forged sgx component SVN")
}

// TestG2ForgedTdxComponentSvn: same for a tdx component (real value 5).
func TestG2ForgedTdxComponentSvn(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	w.TcbTdxComps[0][0] = 0
	expectUnsat(t, w, "C2 forged tdx component SVN")
}

// === C3: per-level offsets pinned to their level segment ===

// TestC3StatusOffCrossLevel uses an honest match index of 1 (OutOfDate) but
// points level 1's StatusOff at level 0's "tcbStatus":"UpToDate" anchor, forging
// a softer (genuinely-signed) verdict. The C3 containment assert (StatusOff[i]
// inside [lvlStart_i, lvlStart_{i+1})) must reject it.
func TestC3StatusOffCrossLevel(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	// Locate level 0's and level 1's status anchors in the signed TCB-Info.
	_, coll := loadFixtures(t)
	raw := []byte(coll["tcb_info"])
	lvl0Status := indexOf(raw, []byte(`"tcbStatus":"`), 0)
	if lvl0Status < 0 {
		t.Fatal("level 0 status anchor not found")
	}
	// Point level 1's status offset at level 0's status (UpToDate, severity 0)
	// and claim severity 0 for level 1; honest match idx stays where it is.
	w.TcbLvlOff[1].StatusOff = lvl0Status
	w.TcbSeverity[1] = 0
	expectUnsat(t, w, "C3 StatusOff pointing at another level's status")
}

// === F2 (round-3): TdxArrOff must be pinned to its own level ===

// TestF2TdxArrOffCrossLevel points level 1's TdxArrOff at level 0's tdx array.
// Pre-fix this was accepted (the literal anchors and, in this fixture, the values
// even coincide); the round-3 lower-bound pin (TdxArrOff >= the level's PceSvnOff)
// must now reject the cross-level offset.
func TestF2TdxArrOffCrossLevel(t *testing.T) {
	w := mustWitness(t, fixedTimestamp)
	_, coll := loadFixtures(t)
	raw := []byte(coll["tcb_info"])
	lvl0Tdx := indexOf(raw, []byte(`"tdxtcbcomponents":[`), 0) // level 0's tdx array
	if lvl0Tdx < 0 {
		t.Fatal("level 0 tdx array not found")
	}
	w.TcbLvlOff[1].TdxArrOff = lvl0Tdx // an earlier level's tdx array
	expectUnsat(t, w, "F2 TdxArrOff anchored at an earlier level's tdx array")
}

// indexOf returns the byte index of sub in buf at or after start, or -1.
func indexOf(buf, sub []byte, start int) int {
	for i := start; i+len(sub) <= len(buf); i++ {
		match := true
		for j := range sub {
			if buf[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// === helpers ===

func asInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	default:
		return -1
	}
}

// severityForLevel returns the severity code for top-level TCB level i from the
// fixture, used to set the public TcbStatus in the G5 test.
func severityForLevel(t *testing.T, i int) int {
	t.Helper()
	_, coll := loadFixtures(t)
	var ti witness.TcbInfo
	if err := json.Unmarshal([]byte(coll["tcb_info"]), &ti); err != nil {
		t.Fatalf("parse tcb_info: %v", err)
	}
	sev, ok := witness.TcbStatusSeverity[ti.TcbLevels[i].TcbStatus]
	if !ok {
		t.Fatalf("unknown status %q", ti.TcbLevels[i].TcbStatus)
	}
	return sev
}
