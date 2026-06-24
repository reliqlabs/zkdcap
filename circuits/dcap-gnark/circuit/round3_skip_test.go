package circuit

// Round-3 negatives: prove the level-anchor consecutiveness (F1/F3) and the
// TdxArrOff pin (F2) reject the skip/cross-level forgeries the round-2 code
// allowed. The real fixture is monotone (2 TCB / 1 QE level) so the SKIP attacks
// need a crafted multi-anchor buffer; F1/F3 are exercised by a gadget circuit
// over the exact consecutiveness logic (anchored strictly-increasing active
// starts + countLiteralOccurrences), which is the invariant the full circuit
// relies on. F2 is exercised end-to-end on the real fixture.

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// skipGadget mirrors deriveAndBindTcbLevels' anti-skip core: each active start is
// anchored on jsonLevelCtx and strictly increasing, the count is derived, and
// (F1) the count is asserted equal to the total jsonLevelCtx occurrences in the
// signed prefix. A skipping prover (active starts a strict subsequence of the
// anchors) makes derived count < total -> unsatisfiable.
type skipGadget struct {
	Buf       [maxTcbInfo]uints.U8
	Len       frontend.Variable
	Starts    [8]frontend.Variable // active level starts (slot 0 + provided)
	NumActive frontend.Variable    // how many of Starts are real (rest repeat last)
}

func (c *skipGadget) Define(api frontend.API) error {
	bt := newByteTable(api, c.Buf[:], c.Len)
	prev := c.Starts[0]
	count := frontend.Variable(1)
	prevActive := frontend.Variable(1)
	for i := 0; i < len(c.Starts); i++ {
		start := c.Starts[i]
		var active frontend.Variable
		if i == 0 {
			active = frontend.Variable(1)
		} else {
			assertGte(api, api.Sub(start, prev), 0) // non-decreasing
			active = api.Sub(1, api.IsZero(api.Sub(start, prev)))
			api.AssertIsEqual(api.Mul(api.Sub(1, prevActive), active), 0) // monotonic
			count = api.Add(count, active)
		}
		_ = bt.extractFieldLU(start, jsonLevelCtx, 0) // anchor each active start
		prev = start
		prevActive = active
	}
	api.AssertIsEqual(count, c.NumActive)
	// F1: derived count must equal the total real anchors (no skip).
	total := countLiteralOccurrences(api, bt.buf, bt.signedLen, jsonLevelCtx)
	api.AssertIsEqual(count, total)
	return nil
}

// craft3LevelBuf returns a buffer with exactly 3 jsonLevelCtx anchors and their
// offsets. Each "level" is the anchor literal + filler so anchors are distinct.
func craft3LevelBuf() ([]byte, []int) {
	lvl := jsonLevelCtx
	filler := []byte(`AAAAAAAAAAAAAAAAAAAA`) // 20 bytes, no anchor substring
	var buf []byte
	buf = append(buf, []byte(`{"prefix":"x",`)...) // some non-anchor prefix
	var offs []int
	for i := 0; i < 3; i++ {
		offs = append(offs, len(buf))
		buf = append(buf, lvl...)
		buf = append(buf, filler...)
	}
	return buf, offs
}

func newSkipGadget(buf []byte, starts []int, numActive int) *skipGadget {
	w := &skipGadget{Len: len(buf), NumActive: numActive}
	for i := range w.Buf {
		if i < len(buf) {
			w.Buf[i] = uints.NewU8(buf[i])
		} else {
			w.Buf[i] = uints.NewU8(0)
		}
	}
	last := starts[len(starts)-1]
	for i := 0; i < len(w.Starts); i++ {
		if i < len(starts) {
			w.Starts[i] = starts[i]
		} else {
			w.Starts[i] = last // padding repeats the last active start (inactive)
		}
	}
	return w
}

// TestC3SkipTcbLevel: honest path (all 3 anchors active) is satisfiable; the
// skip path (active = {anchor0, anchor2}, total = 3) is unsatisfiable.
func TestC3SkipTcbLevel(t *testing.T) {
	buf, offs := craft3LevelBuf()
	if c := bytes.Count(buf, jsonLevelCtx); c != 3 {
		t.Fatalf("crafted buffer has %d anchors, want 3", c)
	}

	// Honest: 3 active starts (all anchors), count 3 == total 3 -> satisfiable.
	ok := newSkipGadget(buf, []int{offs[0], offs[1], offs[2]}, 3)
	if err := test.IsSolved(&skipGadget{}, ok, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("honest 3-level path must be satisfiable: %v", err)
	}

	// Skip: active = {anchor0, anchor2} (2 active), but total anchors = 3 ->
	// count(2) != total(3) -> unsatisfiable.
	bad := newSkipGadget(buf, []int{offs[0], offs[2]}, 2)
	if err := test.IsSolved(&skipGadget{}, bad, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("F1: skipping an interior TCB level must be unsatisfiable")
	}
}

// platformStatusGadget mirrors bindTcbLevel's platform status pin (round-6
// platform H1): assert no "tcbStatus":" occurs in [lvlStart, statusOff) and bind
// the parsed severity. A prover pointing statusOff at a softer status forward of
// the level's real (first) status must be rejected.
type platformStatusGadget struct {
	Buf       [maxTcbInfo]uints.U8
	Len       frontend.Variable
	LvlStart  frontend.Variable
	StatusOff frontend.Variable
	Severity  frontend.Variable
}

func (c *platformStatusGadget) Define(api frontend.API) error {
	bt := newByteTable(api, c.Buf[:], c.Len)
	assertNoLiteralInRange(api, bt.buf, c.LvlStart, c.StatusOff, jsonStatusCtx, 1)
	statusChars := bt.extractStringEnumLU(c.StatusOff, jsonStatusCtx, statusReadLen)
	sev := statusSeverityFromBytes(api, statusChars)
	api.AssertIsEqual(sev, c.Severity)
	return nil
}

func newPlatformStatusGadget(buf []byte, lvlStart, statusOff, severity int) *platformStatusGadget {
	w := &platformStatusGadget{Len: len(buf), LvlStart: lvlStart, StatusOff: statusOff, Severity: severity}
	for i := range w.Buf {
		if i < len(buf) {
			w.Buf[i] = uints.NewU8(buf[i])
		} else {
			w.Buf[i] = uints.NewU8(0)
		}
	}
	return w
}

// TestPlatformStatusForward (round-6 platform H1): a platform level whose object
// holds its real status (OutOfDate) AND a stray softer "tcbStatus":"UpToDate"
// forward of it. Pointing StatusOff at the stray (forging UpToDate) must be
// rejected because the real status sits in [lvlStart, strayStatus). The honest
// path (StatusOff at the real first status) is satisfiable.
func TestPlatformStatusForward(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte(`{"tcb":{"sgxtcbcomponents":[...]`)...) // level start filler (contains jsonLevelCtx head)
	lvlStart := 0
	realStatus := len(buf)
	buf = append(buf, []byte(`"tcbStatus":"OutOfDate"`)...)
	buf = append(buf, []byte(`,"note":`)...)
	strayStatus := len(buf)
	buf = append(buf, []byte(`"tcbStatus":"UpToDate"}`)...)

	// honest: StatusOff at the real (first) status -> satisfiable.
	ok := newPlatformStatusGadget(buf, lvlStart, realStatus, TcbOutOfDate)
	if err := test.IsSolved(&platformStatusGadget{}, ok, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("honest platform status must be satisfiable: %v", err)
	}
	// forge: StatusOff at the stray softer UpToDate forward of the real status.
	bad := newPlatformStatusGadget(buf, lvlStart, strayStatus, TcbUpToDate)
	if err := test.IsSolved(&platformStatusGadget{}, bad, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("platform H1: status forged to a forward softer anchor must be unsatisfiable")
	}
}
