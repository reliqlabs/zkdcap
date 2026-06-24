package circuit

// Round-4 QE multi-level negatives (H2). The real fixture has 1 QE level, so the
// QE consecutiveness (F3), the non-last cross-level status bound (L1), and the
// last-level forward-status clamp (H1) are untested end-to-end. qeLevelGadget
// replicates bindQeIdentity's per-level binding loop verbatim over a crafted
// multi-level QE-Identity buffer, so each attack can be driven directly:
//   TestQeSkipLevel       — interior level skip (F3)
//   TestQeCrossLevelStatus — non-last level's status pulled to a later level (L1)
//   TestQeLastLevelForward — last level's status pulled forward (H1)

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

const qeGadgetMax = 512

// qeLevelGadget mirrors the QE-level binding core of bindQeIdentity (F3 + L1 + H1).
type qeLevelGadget struct {
	Buf      [qeGadgetMax]uints.U8
	Len      frontend.Variable
	LvlOff   [MaxQeTcbLevels]frontend.Variable
	StatusOff [MaxQeTcbLevels]frontend.Variable
	IsvSvn   [MaxQeTcbLevels]frontend.Variable
	Severity [MaxQeTcbLevels]frontend.Variable
	Count    frontend.Variable
}

func (c *qeLevelGadget) Define(api frontend.API) error {
	bt := newByteTable(api, c.Buf[:], c.Len)
	isvCtx := []byte(`{"tcb":{"isvsvn":`)
	prevLvl := c.LvlOff[0]
	count := frontend.Variable(1)
	prevActive := frontend.Variable(1)
	for k := 0; k < MaxQeTcbLevels; k++ {
		off := c.LvlOff[k]
		var active frontend.Variable
		if k == 0 {
			active = frontend.Variable(1)
		} else {
			assertGteWide(api, off, prevLvl)
			active = api.Sub(1, api.IsZero(api.Sub(off, prevLvl)))
			api.AssertIsEqual(api.Mul(api.Sub(1, prevActive), active), 0)
			count = api.Add(count, active)
		}

		isvChars := bt.extractFieldLU(off, isvCtx, u16FieldWidth)
		got := parseDecimal(api, isvChars)
		api.AssertIsEqual(api.Mul(active, api.Sub(got, c.IsvSvn[k])), 0)

		stOff := c.StatusOff[k]
		api.AssertIsEqual(api.Mul(active, api.Sub(1, isLessThanVar(api, off, stOff))), 0)
		if k+1 < MaxQeTcbLevels {
			nextOff := c.LvlOff[k+1]
			nextActive := isLessThan(api, k+1, c.Count)
			api.AssertIsEqual(api.Mul(api.Mul(active, nextActive), api.Sub(1, isLessThanVar(api, stOff, nextOff))), 0)
		}
		// round-7: pin first-status for EVERY active level (gate=active), mirroring
		// production bindQeIdentity + the platform side.
		assertNoLiteralInRange(api, bt.buf, off, stOff, jsonStatusCtx, active)

		statusChars := bt.extractStringEnumLU(stOff, jsonStatusCtx, statusReadLen)
		sev := statusSeverityFromBytes(api, statusChars)
		api.AssertIsEqual(api.Mul(active, api.Sub(sev, c.Severity[k])), 0)
		prevLvl = off
		prevActive = active
	}
	api.AssertIsEqual(count, c.Count)
	total := countLiteralOccurrences(api, bt.buf, bt.signedLen, isvCtx)
	api.AssertIsEqual(count, total)
	return nil
}

// craftQeLevels builds a 3-level QE tcbLevels buffer and returns it plus the
// per-level isvsvn-object offsets, tcbStatus offsets, isvsvn values and severity
// codes (UpToDate=0, OutOfDate=4, Revoked=6).
func craftQeLevels() (buf []byte, lvlOff, stOff, svn, sev []int) {
	lvls := []struct {
		svn int
		st  string
		sev int
	}{
		{8, "UpToDate", TcbUpToDate},
		{5, "OutOfDate", TcbOutOfDate},
		{2, "Revoked", TcbRevoked},
	}
	buf = append(buf, []byte(`"tcbLevels":[`)...)
	for i, l := range lvls {
		if i > 0 {
			buf = append(buf, ',')
		}
		lvlOff = append(lvlOff, len(buf))
		buf = append(buf, []byte(`{"tcb":{"isvsvn":`)...)
		buf = append(buf, []byte(itoa(l.svn))...)
		buf = append(buf, []byte(`},"tcbDate":"2024-03-13T00:00:00Z",`)...)
		stOff = append(stOff, len(buf))
		buf = append(buf, []byte(`"tcbStatus":"`+l.st+`"}`)...)
		svn = append(svn, l.svn)
		sev = append(sev, l.sev)
	}
	buf = append(buf, ']')
	return
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func newQeGadget(buf []byte, lvlOff, stOff, svn, sev []int, count int) *qeLevelGadget {
	w := &qeLevelGadget{Len: len(buf), Count: count}
	for i := range w.Buf {
		if i < len(buf) {
			w.Buf[i] = uints.NewU8(buf[i])
		} else {
			w.Buf[i] = uints.NewU8(0)
		}
	}
	lastLvl := lvlOff[len(lvlOff)-1]
	lastSt := stOff[len(stOff)-1]
	for i := 0; i < MaxQeTcbLevels; i++ {
		if i < len(lvlOff) {
			w.LvlOff[i] = lvlOff[i]
			w.StatusOff[i] = stOff[i]
			w.IsvSvn[i] = svn[i]
			w.Severity[i] = sev[i]
		} else {
			// padding repeats the last active level (inactive)
			w.LvlOff[i] = lastLvl
			w.StatusOff[i] = lastSt
			w.IsvSvn[i] = svn[len(svn)-1]
			w.Severity[i] = sev[len(sev)-1]
		}
	}
	return w
}

// TestQeSkipLevel: honest 3-level path satisfiable; skipping the interior level
// (active = {L0, L2}, count 2, total 3) unsatisfiable (F3).
func TestQeSkipLevel(t *testing.T) {
	buf, lvlOff, stOff, svn, sev := craftQeLevels()
	if c := bytes.Count(buf, []byte(`{"tcb":{"isvsvn":`)); c != 3 {
		t.Fatalf("crafted QE buffer has %d isvsvn anchors, want 3", c)
	}

	ok := newQeGadget(buf, lvlOff, stOff, svn, sev, 3)
	if err := test.IsSolved(&qeLevelGadget{}, ok, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("honest 3-level QE path must be satisfiable: %v", err)
	}

	bad := newQeGadget(buf,
		[]int{lvlOff[0], lvlOff[2]}, []int{stOff[0], stOff[2]},
		[]int{svn[0], svn[2]}, []int{sev[0], sev[2]}, 2)
	if err := test.IsSolved(&qeLevelGadget{}, bad, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("F3: skipping an interior QE level must be unsatisfiable")
	}
}

// TestQeCrossLevelStatus: level 0's StatusOff pointed at level 1's status anchor
// (forging a softer non-last-level severity) must be rejected by the L1 upper
// bound (statusOff[0] < lvlOff[1]).
func TestQeCrossLevelStatus(t *testing.T) {
	buf, lvlOff, stOff, svn, sev := craftQeLevels()
	w := newQeGadget(buf, lvlOff, stOff, svn, sev, 3)
	// Point level 0's status at level 1's status (OutOfDate) and claim that sev.
	w.StatusOff[0] = stOff[1]
	w.Severity[0] = sev[1]
	if err := test.IsSolved(&qeLevelGadget{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("L1: QE non-last level status from a later level must be unsatisfiable")
	}
}

// TestQeNonLastLevelForward (round-7): a NON-LAST active QE level (level 0 of 2)
// whose object carries its real status (OutOfDate) AND a second softer
// "tcbStatus":"UpToDate" further forward, still before the next level. Pre-fix
// the first-status pin was gated on isLastActive, so level 0's pin was a no-op
// and a prover could point StatusOff[0] at the softer forward occurrence; the
// next-level upper bound did not catch it (the stray is still < lvlOff[1]). With
// the gate changed to `active`, level 0's status is pinned to the first one
// at-or-after off[0] -> the forge is rejected.
func TestQeNonLastLevelForward(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte(`"tcbLevels":[`)...)
	l0 := len(buf)
	buf = append(buf, []byte(`{"tcb":{"isvsvn":8},"tcbDate":"2024-03-13T00:00:00Z",`)...)
	realL0 := len(buf)
	buf = append(buf, []byte(`"tcbStatus":"OutOfDate",`)...) // level 0 real status
	strayL0 := len(buf)                                       // a softer status still inside level 0
	buf = append(buf, []byte(`"tcbStatus":"UpToDate"},`)...)  // <- stray UpToDate, before level 1
	l1 := len(buf)
	buf = append(buf, []byte(`{"tcb":{"isvsvn":5},"tcbDate":"2024-03-13T00:00:00Z",`)...)
	realL1 := len(buf)
	buf = append(buf, []byte(`"tcbStatus":"Revoked"}]`)...)

	// honest: level 0 status at its real first occurrence -> satisfiable.
	w := newQeGadget(buf,
		[]int{l0, l1}, []int{realL0, realL1},
		[]int{8, 5}, []int{TcbOutOfDate, TcbRevoked}, 2)
	if err := test.IsSolved(&qeLevelGadget{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("honest 2-level QE must be satisfiable: %v", err)
	}
	// forge: level 0 (NON-LAST) status -> the stray softer UpToDate forward of real.
	w.StatusOff[0] = strayL0
	w.Severity[0] = TcbUpToDate
	if err := test.IsSolved(&qeLevelGadget{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("round-7: non-last QE level status forged forward must be unsatisfiable")
	}
}

// TestQeLastLevelForward (H1): the LAST level's StatusOff pointed forward to a
// softer status anchored later than its real status. We craft the last level's
// object to contain its real status (Revoked) AND a trailing stray
// "tcbStatus":"UpToDate" further forward; the prover points StatusOff[last] at
// the stray to forge UpToDate. The "first tcbStatus at-or-after off[last]" pin
// (H1) must reject it because the real Revoked status sits between off[last] and
// the stray. Without H1 this is satisfiable (stray is a genuine signed anchor).
func TestQeLastLevelForward(t *testing.T) {
	// Build a 2-level buffer where the last (2nd) level's object has a stray
	// softer status after its real one.
	var buf []byte
	buf = append(buf, []byte(`"tcbLevels":[`)...)
	l0 := len(buf)
	buf = append(buf, []byte(`{"tcb":{"isvsvn":8},"tcbDate":"2024-03-13T00:00:00Z","tcbStatus":"OutOfDate"},`)...)
	l1 := len(buf)
	buf = append(buf, []byte(`{"tcb":{"isvsvn":5},"tcbDate":"2024-03-13T00:00:00Z","tcbStatus":"Revoked"`)...)
	realLast := bytes.LastIndex(buf, []byte(`"tcbStatus":"`)) // last level's real status
	buf = append(buf, []byte(`,"note":"tcbStatus":"UpToDate"}]`)...) // stray softer status forward
	strayLast := bytes.LastIndex(buf, []byte(`"tcbStatus":"`))

	s0 := bytes.Index(buf, []byte(`"tcbStatus":"`)) // level 0's status (OutOfDate)
	w := newQeGadget(buf,
		[]int{l0, l1}, []int{s0, realLast},
		[]int{8, 5}, []int{TcbOutOfDate, TcbRevoked}, 2)
	// honest must be satisfiable first
	if err := test.IsSolved(&qeLevelGadget{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("honest 2-level QE (last status real) must be satisfiable: %v", err)
	}
	// Forge: point last level's status at the stray UpToDate (forward of real).
	w.StatusOff[1] = strayLast
	w.Severity[1] = TcbUpToDate
	if err := test.IsSolved(&qeLevelGadget{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("H1: last QE level status forged to a forward anchor must be unsatisfiable")
	}
}

// certValidityGadget runs the H3 cert-validity check over a real cert TBS: parse
// notBefore/notAfter at the certValidityCtx anchor and assert notBefore <=
// Timestamp <= notAfter. Mirrors stepCheckFreshness's checkCertValidity. The
// buffer is sized to maxLeafTBS (the largest cert TBS), so it holds the
// intermediate and TCB-Signing TBS too.
type certValidityGadget struct {
	TBS       [maxLeafTBS]uints.U8
	Len       frontend.Variable
	Off       frontend.Variable
	Timestamp frontend.Variable
}

func (c *certValidityGadget) Define(api frontend.API) error {
	checkCertValidity(api, c.TBS[:], c.Off, c.Len, c.Timestamp)
	return nil
}

func solveCertValidity(t *testing.T, tbs []byte, ts uint64) error {
	t.Helper()
	off := bytes.Index(tbs, certValidityCtx)
	if off < 0 {
		t.Fatal("cert Validity anchor not found")
	}
	w := &certValidityGadget{Len: len(tbs), Off: off, Timestamp: ts}
	for i := range w.TBS {
		if i < len(tbs) {
			w.TBS[i] = uints.NewU8(tbs[i])
		} else {
			w.TBS[i] = uints.NewU8(0)
		}
	}
	return test.IsSolved(&certValidityGadget{}, w, ecc.BN254.ScalarField())
}

func loadChainTBS(t *testing.T, chainKey string, idx int) []byte {
	t.Helper()
	col := loadCollateral(t)
	chain := parsePEMChain(t, col[chainKey])
	if idx >= len(chain) {
		t.Fatalf("%s has %d certs, want index %d", chainKey, len(chain), idx)
	}
	return chain[idx].RawTBSCertificate
}

// TestH3LeafValidity (H3): a Timestamp inside the leaf's X.509 validity window is
// satisfiable; one before notBefore or after notAfter is unsatisfiable. The leaf
// window ([2025-02-06, 2032-02-06]) is wider than the JSON/CRL windows, so this
// is the isolating check for the leaf-validity constraint.
func TestH3LeafValidity(t *testing.T) {
	tbs := loadLeafTBS(t)
	if err := solveCertValidity(t, tbs, 20250625000000); err != nil { // in window
		t.Fatalf("in-window timestamp must be satisfiable: %v", err)
	}
	if err := solveCertValidity(t, tbs, 20200101000000); err == nil { // before notBefore
		t.Fatal("H3: timestamp before leaf notBefore must be unsatisfiable")
	}
	if err := solveCertValidity(t, tbs, 20330101000000); err == nil { // after notAfter
		t.Fatal("H3: timestamp after leaf notAfter must be unsatisfiable")
	}
}

// TestH3IntValidity (round-5): intermediate (Platform CA) validity window
// [2018-05-21, 2033-05-21]. In-window satisfiable; outside unsatisfiable.
func TestH3IntValidity(t *testing.T) {
	tbs := loadChainTBS(t, "pck_certificate_chain", 1) // Platform CA
	if err := solveCertValidity(t, tbs, 20250625000000); err != nil {
		t.Fatalf("in-window timestamp must be satisfiable: %v", err)
	}
	if err := solveCertValidity(t, tbs, 20170101000000); err == nil { // before 2018 notBefore
		t.Fatal("H3: timestamp before intermediate notBefore must be unsatisfiable")
	}
	if err := solveCertValidity(t, tbs, 20340101000000); err == nil { // after 2033 notAfter
		t.Fatal("H3: timestamp after intermediate notAfter must be unsatisfiable")
	}
}

// TestH3SignValidity (round-5): TCB-Signing cert validity window
// [2025-05-06, 2032-05-06]. In-window satisfiable; outside unsatisfiable.
func TestH3SignValidity(t *testing.T) {
	tbs := loadChainTBS(t, "tcb_info_issuer_chain", 0) // TCB-Signing
	if err := solveCertValidity(t, tbs, 20250625000000); err != nil {
		t.Fatalf("in-window timestamp must be satisfiable: %v", err)
	}
	if err := solveCertValidity(t, tbs, 20240101000000); err == nil { // before 2025 notBefore
		t.Fatal("H3: timestamp before TCB-Signing notBefore must be unsatisfiable")
	}
	if err := solveCertValidity(t, tbs, 20330101000000); err == nil { // after 2032 notAfter
		t.Fatal("H3: timestamp after TCB-Signing notAfter must be unsatisfiable")
	}
}
