package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// G2 (misreport): bind every TCB-verdict comparison value used by step8/step9-10
// to the Intel-signed TCB-Info / QE-Identity JSON. The whole JSON is SHA-256 +
// ECDSA verified in verifyCollateral, so any byte slice extracted at a
// constrained (anchored, bounded) offset is provably the value Intel signed.
// Before this, those values were free witnesses, so a prover could lower a TCB
// threshold or soften a verdict and pass a stale platform.
//
// Anchors used (counts in the real fixture; uniqueness within the signed prefix
// is what makes extractField sound):
//   "sgxtcbcomponents":[   1 per level  (array start; pins component 0)
//   "tdxtcbcomponents":[   1 per level
//   "pcesvn":              1 per level
//   tcbLevelStatusCtx      points at the per-level top-level tcbStatus
//   {"svn":               16 per array  (component object start)
//
// COST CONTROL: each svn/pcesvn/status is read with ONE extractField (one
// shared selector reads the whole anchored run), never a fresh selector per
// byte. The svn components are bound positionally without a count gadget; see
// bindSvnArray for the soundness argument.
//
// RESIDUAL (svn component binding): the per-component dynamic extraction is
// SOUND (see bindSvnArray) but, with the O(buffer) selectorAt/readBytesAtSel
// primitive and MaxTcbLevels slots, it multiplies the whole circuit ~8x
// (measured: 5.59M -> ~46M). pcesvn and tcbStatus (always bound) already close
// the highest-impact misreport vectors: lowering the per-level PCESVN threshold
// and softening the severity verdict. Binding the 16 sgx + 16 tdx component
// SVNs is therefore gated off by default; flip bindSvnComponents to enable it
// once the extraction is moved to a lookup/segment primitive (so the read is no
// longer O(buffer) per field) or the buffer/level caps are tightened.
// bindSvnComponents: bind all 16 sgx + 16 tdx per-level component SVN thresholds
// to the signed JSON. ON now that the logderivlookup byteTable (extract.go) makes
// per-component extraction cost ~3 constraints/byte instead of O(buffer) per
// field, so the full binding is affordable (closes the C2 component-threshold
// residual). See bindSvnArray for the positional-binding soundness argument.
const bindSvnComponents = true

// JSON anchor literals (read-only; the host witness builder locates them with
// bytes.Index via the exported aliases below).
var (
	jsonSvnCtx     = []byte(`{"svn":`)         // component object start
	jsonSgxArrCtx  = []byte(`"sgxtcbcomponents":[`)
	jsonTdxArrCtx  = []byte(`"tdxtcbcomponents":[`)
	jsonPceSvnCtx  = []byte(`"pcesvn":`)
	jsonStatusCtx  = []byte(`"tcbStatus":"`)
	jsonLevelCtx   = []byte(`{"tcb":{"sgxtcbcomponents":`) // unique per top-level level
	jsonTcbLevels  = []byte(`"tcbLevels":[`)
)

// Exported anchor aliases for the host witness builder.
var (
	JsonSvnCtx     = jsonSvnCtx
	JsonSgxArrCtx  = jsonSgxArrCtx
	JsonTdxArrCtx  = jsonTdxArrCtx
	JsonPceSvnCtx  = jsonPceSvnCtx
	JsonStatusCtx  = jsonStatusCtx
	JsonLevelCtx   = jsonLevelCtx
	JsonTcbLevels  = jsonTcbLevels
)

// Max decimal widths for the numeric JSON fields (digits + one terminator that
// parseDecimal needs to see). svn is a u8 (<=3 digits); pcesvn/isvsvn/isvprodid
// are u16 (<=5 digits).
const (
	svnMaxDigits     = 3
	u16MaxDigits     = 5
	svnFieldWidth    = svnMaxDigits + 1 // digits + terminator (',' or '}')
	u16FieldWidth    = u16MaxDigits + 1
)

// statusSeverityFromBytes maps an extracted tcbStatus string (the bytes right
// after the opening quote) to its severity code, by matching each known status
// literal in-circuit. Exactly one must match (asserted), so an unknown/forged
// status string is unsatisfiable. Reads statusReadLen bytes (the longest known
// status) and matches each candidate over its own length, ignoring trailing
// bytes past the closing quote.
func statusSeverityFromBytes(api frontend.API, got []frontend.Variable) frontend.Variable {
	// (literal, severity) for every status Intel emits. The closing '"' bounds
	// each literal, so e.g. "OutOfDate" cannot be a prefix-confused with
	// "OutOfDateConfigurationNeeded": we match the literal AND require the byte
	// right after it to be the closing quote.
	type cand struct {
		lit []byte
		sev int
	}
	cands := []cand{
		{[]byte("UpToDate"), TcbUpToDate},
		{[]byte("SWHardeningNeeded"), TcbSWHardeningNeeded},
		{[]byte("ConfigurationNeeded"), TcbConfigurationNeeded},
		{[]byte("ConfigurationAndSWHardeningNeeded"), TcbConfigurationAndSWHardeningNeeded},
		{[]byte("OutOfDate"), TcbOutOfDate},
		{[]byte("OutOfDateConfigurationNeeded"), TcbOutOfDateConfigurationNeeded},
		{[]byte("Revoked"), TcbRevoked},
	}
	sev := frontend.Variable(0)
	matched := frontend.Variable(0)
	for _, c := range cands {
		if len(c.lit)+1 > len(got) {
			continue // cannot fit this literal + closing quote in the read window
		}
		eq := frontend.Variable(1)
		for j, b := range c.lit {
			eq = api.Mul(eq, api.IsZero(api.Sub(got[j], int(b))))
		}
		// require the closing quote right after the literal (anti-prefix-confusion)
		eq = api.Mul(eq, api.IsZero(api.Sub(got[len(c.lit)], 0x22)))
		sev = api.Add(sev, api.Mul(eq, c.sev))
		matched = api.Add(matched, eq)
	}
	api.AssertIsEqual(matched, 1)
	return sev
}

// statusReadLen is the longest known status literal + closing quote.
const statusReadLen = 33 + 1 // len("ConfigurationAndSWHardeningNeeded")+1

// bindSvnArray binds the 16 component svn values of one tcb component array to
// the signed JSON and asserts each equals the corresponding witness element.
//
// SOUNDNESS (positional binding without a count gadget): component 0's offset
// is pinned to the array-start anchor (arrayOff + len(arrayCtx)), so it is the
// real first component. Components 1..15 use prover-supplied offsets, each
// asserted to (a) sit on the `{"svn":` literal and (b) be preceded by the two
// bytes `},` (the JSON separator between component objects), and the 16 offsets
// are asserted strictly increasing and all strictly less than the level's
// "pcesvn" offset (which closes the array). The array provably contains exactly
// 16 component-start positions in [comp0, pcesvnOff) (it is signed; the host
// knows the schema). Sixteen strictly-increasing, distinct, valid component
// starts drawn from a set of exactly sixteen, with the minimum pinned to the
// true first, must be precisely those sixteen in order. So each off[j] is the
// real j-th component and the parsed svn is the real svn[j].
func bindSvnArray(
	bt *byteTable,
	arrayOff frontend.Variable, arrayCtx []byte,
	svnOffs []frontend.Variable, // offsets of components 1..15 (15 entries)
	pcesvnOff frontend.Variable,
	want []frontend.Variable, // 16 witness svn values to bind
) {
	api := bt.api
	// Component 0: anchored directly on the unique array-start literal followed
	// by `{"svn":` and the value, in one lookup read. This both validates the
	// array-start offset and pins component 0.
	headCtx := append(append([]byte{}, arrayCtx...), jsonSvnCtx...)
	c0 := bt.extractFieldLU(arrayOff, headCtx, svnFieldWidth)
	api.AssertIsEqual(parseDecimal(api, c0), want[0])
	// Offset of component 0's `{"svn":` (start of the separator-equivalent).
	off0 := api.Add(arrayOff, len(arrayCtx))

	// Components 1..15: each anchored on `},{"svn":` (separator + object start)
	// plus the value. The leading `},` proves `off` follows a real component
	// close; strict ordering + the upper bound (pcesvnOff) + component-0 pin
	// force these to be exactly the real components 1..15.
	sepCtx := append([]byte{'}', ','}, jsonSvnCtx...)
	prev := off0
	for k := 0; k < 15; k++ {
		off := svnOffs[k] // points at the `{"svn":` of component k+1
		assertGte(api, api.Sub(off, prev), 1)      // strictly increasing
		assertGte(api, api.Sub(pcesvnOff, off), 1) // inside the array
		// read from off-2 (the separator) through the value
		got := bt.extractFieldLU(api.Sub(off, 2), sepCtx, svnFieldWidth)
		api.AssertIsEqual(parseDecimal(api, got), want[k+1])
		prev = off
	}
}

// bindTcbLevel binds one top-level tcbLevels entry's 16 sgx svn, 16 tdx svn,
// pcesvn, and tcbStatus severity to the signed JSON, asserting each equals the
// corresponding witness array element used by step8/step9-10.
func (c *DcapCircuit) bindTcbLevel(bt *byteTable, i int, lvlStart, lvlEnd, sgxArrOff, active frontend.Variable) {
	api := bt.api
	h := &c.TcbLvlOff[i]

	// C3: pin the prover-supplied PceSvnOff / StatusOff INSIDE this level's
	// extent [lvlStart, lvlEnd). Without this they are free hints anchored only
	// on their literal, so a prover with an honest match index could point
	// StatusOff at a softer level's "tcbStatus":"UpToDate" (still genuinely
	// signed) to forge a softer verdict. lvlEnd is the next level's start (or
	// TcbInfoRawLen for the last level).
	assertGteWide(api, h.PceSvnOff, lvlStart)
	assertGteWide(api, api.Sub(lvlEnd, 1), h.PceSvnOff)
	assertGteWide(api, h.StatusOff, lvlStart)
	assertGteWide(api, api.Sub(lvlEnd, 1), h.StatusOff)

	// H1-platform (round-6): pin StatusOff as the FIRST "tcbStatus":" at-or-after
	// lvlStart, mirroring the QE-side H1 (bindQeIdentity). The [lvlStart, lvlEnd)
	// bound alone is not enough for the LAST active level (extent runs to
	// TcbInfoRawLen) nor for any level if a future/reordered validly-signed
	// TCB-Info carried a second status-shaped literal after the level start: a
	// prover could point StatusOff at a softer forward occurrence and downgrade
	// the platform verdict. Asserting no jsonStatusCtx in [lvlStart, StatusOff)
	// makes the bound status provably this level's, independent of document
	// section ordering. Gated on active (padding slots mirror the last real level).
	assertNoLiteralInRange(api, bt.buf, lvlStart, h.StatusOff, jsonStatusCtx, active)

	// F2 (round-3): pin TdxArrOff to THIS level's extent. The `tdxtcbcomponents":[`
	// literal occurs once per level, so without a lower bound a prover could
	// anchor it on an EARLIER level's tdx array (whose component offsets still
	// pass the < StatusOff check), binding the wrong (higher) thresholds and
	// flipping a satisfied level unsatisfied so canonical-first selects a softer
	// later level. Containment in [pcesvn, StatusOff) ⊂ [lvlStart, lvlEnd) forces
	// it to this level's tdx array (which structurally follows pcesvn).
	assertGteWide(api, h.TdxArrOff, h.PceSvnOff)
	assertGteWide(api, api.Sub(h.StatusOff, 1), h.TdxArrOff)

	// pcesvn (anchored on `"pcesvn":`, parsed as u16).
	pceChars := bt.extractFieldLU(h.PceSvnOff, jsonPceSvnCtx, u16FieldWidth)
	api.AssertIsEqual(parseDecimal(api, pceChars), c.TcbPceSvn[i])

	// sgx + tdx component svn arrays (positional binding). Affordable via the
	// lookup table; see bindSvnArray for the soundness argument. sgxArrOff is
	// derived in-circuit from the (anchored) level start, and the tdx array off
	// is a hint upper-bounded by StatusOff, so both stay in this level.
	if bindSvnComponents {
		sgxWant := make([]frontend.Variable, MaxSgxComponents)
		tdxWant := make([]frontend.Variable, MaxTdxComponents)
		for j := 0; j < MaxSgxComponents; j++ {
			sgxWant[j] = c.TcbSgxComps[i][j]
		}
		for j := 0; j < MaxTdxComponents; j++ {
			tdxWant[j] = c.TcbTdxComps[i][j]
		}
		bindSvnArray(bt, sgxArrOff, jsonSgxArrCtx, h.SgxSvnOff[:], h.PceSvnOff, sgxWant)
		bindSvnArray(bt, h.TdxArrOff, jsonTdxArrCtx, h.TdxSvnOff[:], h.StatusOff, tdxWant)
	} else {
		_ = sgxArrOff
	}

	// tcbStatus severity: anchored on `"tcbStatus":"`, mapped to a severity code.
	// The value can extend into the buffer tail (see extractStringEnumLU).
	statusChars := bt.extractStringEnumLU(h.StatusOff, jsonStatusCtx, statusReadLen)
	api.AssertIsEqual(statusSeverityFromBytes(api, statusChars), c.TcbSeverity[i])
}

// bindQeIdentity binds the QE-Identity policy fields and per-level QE TCB
// thresholds/severities to the signed QE-Identity JSON. It also DERIVES
// QeIdTcbCount from the JSON (L2) instead of trusting the host witness.
func (c *DcapCircuit) bindQeIdentity(api frontend.API, bt *byteTable) {
	h := &c.QeIdOff

	// mrsigner: 64 uppercase-hex chars -> 32 bytes.
	mr := hexBytesToBytes(api, bt.extractFieldLU(h.MrSignerOff, []byte(`"mrsigner":"`), 64))
	for j := 0; j < 32; j++ {
		api.AssertIsEqual(mr[j], c.QeIdMrSigner[j].Val)
	}
	// isvprodid (dec u16).
	api.AssertIsEqual(parseDecimal(api, bt.extractFieldLU(h.IsvProdIdOff, []byte(`"isvprodid":`), u16FieldWidth)), c.QeIdIsvProdId)
	// miscselect + mask (8 hex chars -> 4 bytes each).
	ms := hexBytesToBytes(api, bt.extractFieldLU(h.MiscSelectOff, []byte(`"miscselect":"`), 8))
	mm := hexBytesToBytes(api, bt.extractFieldLU(h.MiscMaskOff, []byte(`"miscselectMask":"`), 8))
	for j := 0; j < 4; j++ {
		api.AssertIsEqual(ms[j], c.QeIdMiscSelect[j].Val)
		api.AssertIsEqual(mm[j], c.QeIdMiscMask[j].Val)
	}
	// attributes + mask (32 hex chars -> 16 bytes each). The mask MUST come from
	// the signed JSON; a zero mask would make the attributes policy vacuous.
	at := hexBytesToBytes(api, bt.extractFieldLU(h.AttrOff, []byte(`"attributes":"`), 32))
	am := hexBytesToBytes(api, bt.extractFieldLU(h.AttrMaskOff, []byte(`"attributesMask":"`), 32))
	for j := 0; j < 16; j++ {
		api.AssertIsEqual(at[j], c.QeIdAttributes[j].Val)
		api.AssertIsEqual(am[j], c.QeIdAttrMask[j].Val)
	}

	// Per QE TCB level: isvsvn (dec u16) + tcbStatus severity. Each level object
	// is `{"tcb":{"isvsvn":N},...,"tcbStatus":"..."}`. Each isvsvn is anchored on
	// the unique-per-object `{"tcb":{"isvsvn":` literal; each status on
	// `"tcbStatus":"`. Offsets are asserted strictly increasing across active
	// levels, and statusOff[k] is asserted to lie between level k's and level
	// k+1's object starts (L1 containment), so isvsvn and status provably come
	// from the SAME level object. QeIdTcbCount is DERIVED here (L2): a slot is
	// active iff its start strictly exceeds the previous (padding repeats the
	// last real start); active is monotonic and the count is asserted equal to
	// the sum of active slots.
	isvCtx := []byte(`{"tcb":{"isvsvn":`)
	// Slot 0 is pinned: the first `{"tcb":{"isvsvn":` after the mrsigner field.
	prevLvl := h.QeLvlOff[0]
	count := frontend.Variable(1)
	prevActive := frontend.Variable(1)
	for k := 0; k < MaxQeTcbLevels; k++ {
		off := h.QeLvlOff[k]
		var active frontend.Variable
		if k == 0 {
			active = frontend.Variable(1)
		} else {
			assertGteWide(api, off, prevLvl) // non-decreasing
			active = api.Sub(1, api.IsZero(api.Sub(off, prevLvl)))
			api.AssertIsEqual(api.Mul(api.Sub(1, prevActive), active), 0) // monotonic
			count = api.Add(count, active)
		}

		isvChars := bt.extractFieldLU(off, isvCtx, u16FieldWidth)
		got := parseDecimal(api, isvChars)
		api.AssertIsEqual(api.Mul(active, api.Sub(got, c.QeIdTcbIsvSvn[k])), 0)

		// status belongs to THIS level's object: off < statusOff < (next level start
		// if there is one, else QeIDRawLen). The lower bound + an upper bound on
		// every active level pins statusOff inside the level's object.
		stOff := h.QeStatusOff[k]
		api.AssertIsEqual(api.Mul(active, api.Sub(1, isLessThanVar(api, off, stOff))), 0)
		var nextActive frontend.Variable = frontend.Variable(0)
		if k+1 < MaxQeTcbLevels {
			nextOff := h.QeLvlOff[k+1]
			nextActive = isLessThan(api, k+1, c.QeIdTcbCount)
			// when level k+1 is active, statusOff[k] must precede its start.
			api.AssertIsEqual(api.Mul(api.Mul(active, nextActive), api.Sub(1, isLessThanVar(api, stOff, nextOff))), 0)
		}
		// H1 (round-4/round-7): pin statusOff as the FIRST "tcbStatus":" at-or-after
		// off for EVERY active QE level (mirrors the platform side in bindTcbLevel).
		// The next-level upper bound (line above) only stops pointing at a LATER
		// level's status; a SECOND status literal WITHIN this level's own object
		// (a validly-signed future/reordered QE-Identity) would still be reachable
		// for non-last levels if this were gated on isLastActive. Asserting no
		// jsonStatusCtx in [off, stOff) makes statusOff unambiguously this level's
		// status, independent of document ordering. (round-7: gate changed from
		// isLastActive -> active to close the non-last-level QE gap.)
		assertNoLiteralInRange(api, bt.buf, off, stOff, jsonStatusCtx, active)
		statusChars := bt.extractStringEnumLU(stOff, jsonStatusCtx, statusReadLen)
		sev := statusSeverityFromBytes(api, statusChars)
		api.AssertIsEqual(api.Mul(active, api.Sub(sev, c.QeIdTcbSeverity[k])), 0)
		prevLvl = off
		prevActive = active
	}
	// L2: derived count must equal the (now non-trusted) witness count.
	api.AssertIsEqual(count, c.QeIdTcbCount)

	// F3 (round-3): force QE level-anchor consecutiveness (no interior skip), the
	// same pigeonhole argument as F1: active count == total isvsvn-object anchors
	// in the signed QE-Identity prefix.
	total := countLiteralOccurrences(api, bt.buf, bt.signedLen, isvCtx)
	api.AssertIsEqual(count, total)
}

// isLessThanVar returns 1 iff a < b for small non-negative variables (< 2^24).
func isLessThanVar(api frontend.API, a, b frontend.Variable) frontend.Variable {
	const n = 24
	shifted := api.Add(api.Sub(b, a), 1<<n)
	bits := api.ToBinary(shifted, n+1)
	isGte := bits[n]
	bNeqA := api.Sub(1, api.IsZero(api.Sub(b, a)))
	return api.Mul(isGte, bNeqA)
}

// countLiteralOccurrences returns the number of positions p in [0, signedLen)
// where buf[p:p+len(lit)] == lit and the whole match fits inside the signed
// prefix (p + len(lit) <= signedLen). Used to force level-anchor consecutiveness
// (round-3 F1/F3): if the active, strictly-increasing, anchored level starts
// number exactly this total, none can be skipped. One pass over the buffer;
// padding past signedLen is excluded by the inWindow gate so a prover cannot
// inflate the total by planting a literal in the unsigned tail.
func countLiteralOccurrences(api frontend.API, buf []uints.U8, signedLen frontend.Variable, lit []byte) frontend.Variable {
	n := len(buf)
	L := len(lit)
	total := frontend.Variable(0)
	for p := 0; p+L <= n; p++ {
		eq := frontend.Variable(1)
		for j := 0; j < L; j++ {
			eq = api.Mul(eq, api.IsZero(api.Sub(buf[p+j].Val, int(lit[j]))))
		}
		// only count matches whose end is within the signed prefix
		inWindow := isLessThanVar(api, p+L-1, signedLen) // (p+L-1) < signedLen
		total = api.Add(total, api.Mul(eq, inWindow))
	}
	return total
}

// assertNoLiteralInRange asserts that, when gate==1, the literal `lit` does NOT
// start at any position p in [lo, hi). Used to pin a status offset as the first
// occurrence at-or-after a level start (round-4 QE H1 + round-6 platform H1).
// When gate==0 it is a no-op.
//
// The [lo, hi) membership is tracked with a running `inside` flag toggled by
// cheap equalities as p increments (inside turns on at p==lo, off at p==hi),
// instead of two O(25-bit) comparisons per position. lo and hi are in-range
// offsets (lo < hi <= n), so each is hit exactly once during the linear scan.
func assertNoLiteralInRange(api frontend.API, buf []uints.U8, lo, hi frontend.Variable, lit []byte, gate frontend.Variable) {
	n := len(buf)
	L := len(lit)
	inside := frontend.Variable(0)
	for p := 0; p+L <= n; p++ {
		// toggle inside on at p==lo, off at p==hi.
		atLo := api.IsZero(api.Sub(lo, p))
		atHi := api.IsZero(api.Sub(hi, p))
		inside = api.Add(inside, atLo) // 0 -> 1 when p==lo
		inside = api.Sub(inside, atHi) // 1 -> 0 when p==hi
		eq := frontend.Variable(1)
		for j := 0; j < L; j++ {
			eq = api.Mul(eq, api.IsZero(api.Sub(buf[p+j].Val, int(lit[j]))))
		}
		// forbid a literal match while inside [lo, hi) when gated.
		api.AssertIsEqual(api.Mul(api.Mul(gate, eq), inside), 0)
	}
}

// stepBindTcbData discharges G2: it binds the TCB-verdict comparison values to
// the signature-anchored collateral and quote.
func (c *DcapCircuit) stepBindTcbData(api frontend.API) (frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable, error) {
	// Build ONE logderivlookup table per signed blob; every field read below is a
	// ~3-constraint lookup instead of an O(buffer) selector (extract.go).
	tcbTbl := newByteTable(api, c.TcbInfoRaw[:], c.TcbInfoRawLen)
	qeTbl := newByteTable(api, c.QeIDRaw[:], c.QeIDRawLen)

	// --- Derive TcbLevelCount from the signed JSON (do not trust it free) and
	// bind every level's verdict values, with each level's offsets pinned to its
	// extent (C3). ---
	c.deriveAndBindTcbLevels(api, tcbTbl)

	// --- QE-Identity policy + QE TCB levels (derives QeIdTcbCount, L2). ---
	c.bindQeIdentity(api, qeTbl)

	// --- Platform SVNs (NOT from the TCB-Info JSON). ---
	// PlatformTeeTcbSvn[i] is the ISV-signed quote's tee_tcb_svn (already in the
	// signed quote, bind it directly).
	for i := 0; i < 16; i++ {
		api.AssertIsEqual(c.PlatformTeeTcbSvn[i].Val, c.SignedQuote[SQ_TeeTcbSvn+i].Val)
	}
	// PlatformCpuSvn / PlatformPceSvn come from the PCK leaf SGX extension, bound
	// at the CPUSVN / PCESVN OID anchors (same bounded extractField pattern as
	// FMSPC). The leaf TBS is chain-anchored and SHA+ECDSA bound (A1).
	cpu := extractField(api, c.LeafTBS[:], c.LeafCpuSvnOff, c.LeafTBSLen, cpuSvnCtx, 16)
	for i := 0; i < 16; i++ {
		api.AssertIsEqual(cpu[i], c.PlatformCpuSvn[i].Val)
	}
	// PCESVN is a DER INTEGER after the OID+tag anchor: [len][value...]. len is
	// 1 or 2; read 3 bytes (len + up to 2 value bytes) and assemble big-endian.
	pce := extractField(api, c.LeafTBS[:], c.LeafPceSvnOff, c.LeafTBSLen, pceSvnCtx, 3)
	lenByte := pce[0]
	is1 := api.IsZero(api.Sub(lenByte, 1))
	is2 := api.IsZero(api.Sub(lenByte, 2))
	api.AssertIsEqual(api.Add(is1, is2), 1) // PCESVN INTEGER is 1 or 2 bytes
	// 1-byte: value = pce[1]; 2-byte: value = pce[1]*256 + pce[2].
	pceVal := api.Select(is2, api.Add(api.Mul(pce[1], 256), pce[2]), pce[1])
	api.AssertIsEqual(pceVal, c.PlatformPceSvn)

	// --- G4 freshness + #2 eval number + #3 freshness/cert validity window
	// (reuses both blob tables). ---
	tcbEval, qeEval, validFrom, validUntil := c.stepCheckFreshness(api, tcbTbl, qeTbl)
	return tcbEval, qeEval, validFrom, validUntil, nil
}

// stepCheckFreshness discharges the validity-window half of G4: the Timestamp
// public input (packed YYYYMMDDhhmmss) must fall within [issueDate, nextUpdate]
// of BOTH Intel-signed collateral blobs. issueDate/nextUpdate are extracted from
// the signed JSON (so a prover cannot widen the window), parsed to the same
// packed integer, and compared. This rejects expired or not-yet-valid
// collateral (e.g. replaying an old TCB-Info whose nextUpdate has passed).
// Returns (tcbEval, qeEval, validFrom, validUntil): both tcbEvaluationDataNumber
// values, emitted separately (#2/#4 — a single min() doesn't close stale-TCB
// selection per issue #4), and the freshness+cert half of the intersected validity
// window (#3, max of lower bounds / min of upper bounds). The caller folds in the
// two CRL windows.
func (c *DcapCircuit) stepCheckFreshness(api frontend.API, tcbTbl, qeTbl *byteTable) (frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable) {
	dateCtx := []byte(`"issueDate":"`)
	nextCtx := []byte(`"nextUpdate":"`)
	const isoLen = 20 // "YYYY-MM-DDThh:mm:ssZ"

	tcbIssue := parseIso8601(api, tcbTbl.extractFieldLU(c.TcbIssueDateOff, dateCtx, isoLen))
	tcbNext := parseIso8601(api, tcbTbl.extractFieldLU(c.TcbNextUpdateOff, nextCtx, isoLen))
	assertGteWide(api, c.Timestamp, tcbIssue) // Timestamp >= issueDate
	assertGteWide(api, tcbNext, c.Timestamp)  // Timestamp <= nextUpdate

	qeIssue := parseIso8601(api, qeTbl.extractFieldLU(c.QeIssueDateOff, dateCtx, isoLen))
	qeNext := parseIso8601(api, qeTbl.extractFieldLU(c.QeNextUpdateOff, nextCtx, isoLen))
	assertGteWide(api, c.Timestamp, qeIssue)
	assertGteWide(api, qeNext, c.Timestamp)

	// H3 (round-4): X.509 validity window for every chain-anchored cert. Each cert
	// TBS is SHA+ECDSA bound (leaf/intermediate via A1, TCB-Signing via A2), so its
	// Validity dates are signed. All three Intel certs encode Validity as UTCTime
	// (30 1e 17 0d anchor, 13-char YYMMDDHHMMSSZ values), so the same gadget covers
	// them. This closes the cert-validity residual: notBefore <= Timestamp <=
	// notAfter for leaf, Platform CA (intermediate), and TCB-Signing.
	leafNb, leafNa := checkCertValidity(api, c.LeafTBS[:], c.LeafValidityOff, c.LeafTBSLen, c.Timestamp)
	intNb, intNa := checkCertValidity(api, c.IntTBS[:], c.IntValidityOff, c.IntTBSLen, c.Timestamp)
	signNb, signNa := checkCertValidity(api, c.SignTBS[:], c.SignValidityOff, c.SignLen, c.Timestamp)

	// #2/#4: tcbEvaluationDataNumber from BOTH signed blobs, returned separately. A
	// single min() lets a stale TCB-Info ride a current QE-Identity past a monotone
	// floor (issue #4); the consumer floor-checks each per-FMSPC.
	evalCtx := []byte(`"tcbEvaluationDataNumber":`)
	tcbEval := parseDecimal(api, tcbTbl.extractFieldLU(c.TcbEvalOff, evalCtx, u16FieldWidth))
	qeEval := parseDecimal(api, qeTbl.extractFieldLU(c.QeEvalOff, evalCtx, u16FieldWidth))

	// #3: fold the freshness + cert windows into [valid_from, valid_until].
	validFrom := maxVarWide(api, maxVarWide(api, tcbIssue, qeIssue), maxVarWide(api, leafNb, maxVarWide(api, intNb, signNb)))
	validUntil := minVarWide(api, minVarWide(api, tcbNext, qeNext), minVarWide(api, leafNa, minVarWide(api, intNa, signNa)))
	return tcbEval, qeEval, validFrom, validUntil
}

// checkCertValidity asserts notBefore <= timestamp <= notAfter for an X.509 cert
// TBS whose Validity is anchored at validityOff on certValidityCtx (30 1e 17 0d,
// UTCTime). notBefore's 13 UTCTime chars follow the anchor; notAfter is the next
// UTCTime at +13 value +2 (17 0d) tag/len. timestamp is the packed
// YYYYMMDDhhmmss verification time.
// Returns the (notBefore, notAfter) packed bounds so the caller can fold them
// into the intersected collateral validity window (#3).
func checkCertValidity(api frontend.API, tbs []uints.U8, validityOff, tbsLen, timestamp frontend.Variable) (frontend.Variable, frontend.Variable) {
	nbChars := extractField(api, tbs, validityOff, tbsLen, certValidityCtx, 13)
	notBefore := parseUtcTime(api, nbChars)
	naOff := api.Add(validityOff, len(certValidityCtx)+13+2)
	naChars := extractField(api, tbs, naOff, tbsLen, nil, 13)
	notAfter := parseUtcTime(api, naChars)
	assertGteWide(api, timestamp, notBefore) // timestamp >= notBefore
	assertGteWide(api, notAfter, timestamp)  // timestamp <= notAfter
	return notBefore, notAfter
}

// deriveAndBindTcbLevels binds every TCB level slot's verdict values and derives
// TcbLevelCount from the JSON instead of trusting it as a free witness.
//
// Each slot i carries a level-start offset (slot 0 pinned to the unique
// "tcbLevels":[{"tcb":{"sgxtcbcomponents": anchor; slots 1.. prover-supplied).
// Every slot's offset is anchored on the per-level literal jsonLevelCtx and
// asserted >= the previous slot's. A slot is "active" iff its start strictly
// exceeds the previous slot's (real levels are strictly increasing; the witness
// builder makes padding slots REPEAT the last real level's start so they are
// non-increasing => inactive). active is asserted monotonic (once 0, stays 0),
// and TcbLevelCount := sum(active). All slots are bound unconditionally; padding
// slots point at the last real level, so their anchors/ordering hold and their
// (repeated) witness values match. step8/step9-10 only read levels < the
// derived count, so repeated padding never changes the verdict.
func (c *DcapCircuit) deriveAndBindTcbLevels(api frontend.API, bt *byteTable) {
	// Level 0 start is pinned to the "tcbLevels":[ array anchor (unique), so
	// slot 0 is provably the real first level.
	head := append(append([]byte{}, jsonTcbLevels...), jsonLevelCtx...)
	_ = bt.extractFieldLU(c.TcbLevelsOff, head, 0) // assert anchor
	lvl0Start := api.Add(c.TcbLevelsOff, len(jsonTcbLevels))

	// First pass: resolve and anchor every slot's level start + active flag.
	starts := make([]frontend.Variable, MaxTcbLevels)
	active := make([]frontend.Variable, MaxTcbLevels)
	prev := lvl0Start
	count := frontend.Variable(1) // slot 0 is always a real level
	prevActive := frontend.Variable(1)
	for i := 0; i < MaxTcbLevels; i++ {
		if i == 0 {
			starts[i] = lvl0Start
			active[i] = frontend.Variable(1)
		} else {
			starts[i] = c.TcbLvlStartOff[i-1]
			assertGte(api, api.Sub(starts[i], prev), 0) // non-decreasing
			active[i] = api.Sub(1, api.IsZero(api.Sub(starts[i], prev)))
			api.AssertIsEqual(api.Mul(api.Sub(1, prevActive), active[i]), 0) // monotonic
			count = api.Add(count, active[i])
		}
		_ = bt.extractFieldLU(starts[i], jsonLevelCtx, 0) // anchor the level start
		prev = starts[i]
		prevActive = active[i]
	}
	api.AssertIsEqual(count, c.TcbLevelCount)

	// F1 (round-3): force the active starts to be ALL the real level anchors in
	// order, not a skippable subsequence. The active starts are already
	// strictly-increasing and each is a jsonLevelCtx anchor; if their number
	// equals the TOTAL count of jsonLevelCtx occurrences in the signed prefix,
	// then by pigeonhole they are exactly those anchors with none skipped. Skipping
	// an interior level would make slot i's extent span two real levels and break
	// bindSvnArray's "exactly 16 components in [comp0, pcesvn)" invariant.
	total := countLiteralOccurrences(api, bt.buf, bt.signedLen, jsonLevelCtx)
	api.AssertIsEqual(count, total)

	// Second pass: bind each level's verdict values, pinning its offsets to the
	// extent [start_i, end_i) where end_i is the next active slot's start, or
	// TcbInfoRawLen when the next slot is padding (so the last real level extends
	// to the end of the signed JSON). C3 uses end_i in bindTcbLevel.
	for i := 0; i < MaxTcbLevels; i++ {
		var end frontend.Variable
		if i+1 < MaxTcbLevels {
			// next slot active -> its start; else end of signed JSON.
			end = api.Select(active[i+1], starts[i+1], c.TcbInfoRawLen)
		} else {
			end = c.TcbInfoRawLen
		}
		// The sgx array anchor begins at start_i + len(`{"tcb":{`); derived in
		// circuit so it is pinned to the (anchored) level start.
		sgxArrOff := api.Add(starts[i], len(`{"tcb":{`))
		c.bindTcbLevel(bt, i, starts[i], end, sgxArrOff, active[i])
	}
}

// isLessThan returns 1 iff a < b for small non-negative values (< 2^16).
func isLessThan(api frontend.API, a int, b frontend.Variable) frontend.Variable {
	// a < b  <=>  b > a. Compute via bit decomposition of (b - a) shifted to
	// stay positive.
	const n = 16
	shifted := api.Add(api.Sub(b, a), 1<<n) // in [1, 2^(n+1)) for |b-a|<2^n
	bits := api.ToBinary(shifted, n+1)
	isGte := bits[n] // 1 iff b >= a
	bNeqA := api.Sub(1, api.IsZero(api.Sub(b, a)))
	return api.Mul(isGte, bNeqA)
}
