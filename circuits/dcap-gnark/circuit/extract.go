package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

// Dynamic byte extraction with literal-context anchoring.
//
// Intel cert/collateral DER is variable-length (serial 20/21 bytes,
// Platform vs Processor issuer, etc.), so field positions are not fixed.
// We therefore let the prover supply each field's offset as a hint and
// constrain it by asserting the unique literal DER context (OID + tag/len)
// at that offset. Because the anchoring literal occurs exactly once in the
// signed TBS, the only offset that satisfies the assertion is the real one,
// and the whole TBS is already SHA-256+ECDSA bound, so the extracted bytes
// are provably the values the issuer signed.

// selectorAt returns s with s[i] == 1 iff i == off (a one-hot vector),
// asserting exactly one bit is set (so off is a real in-range index).
func selectorAt(api frontend.API, n int, off frontend.Variable) []frontend.Variable {
	s := make([]frontend.Variable, n)
	sum := frontend.Variable(0)
	for i := 0; i < n; i++ {
		s[i] = api.IsZero(api.Sub(off, i))
		sum = api.Add(sum, s[i])
	}
	api.AssertIsEqual(sum, 1)
	return s
}

// readBytesAtSel reads k bytes starting at the one-hot position encoded by
// sel: out[j] = sum_i buf[i+j] * sel[i]. Reuses one selector for all k
// bytes, so cost is len(sel) IsZero + k*len(buf) muls.
func readBytesAtSel(api frontend.API, buf []uints.U8, sel []frontend.Variable, k int) []frontend.Variable {
	n := len(buf)
	out := make([]frontend.Variable, k)
	for j := 0; j < k; j++ {
		acc := frontend.Variable(0)
		for i := 0; i+j < n; i++ {
			acc = api.Add(acc, api.Mul(buf[i+j].Val, sel[i]))
		}
		out[j] = acc
	}
	return out
}

// certVersionSerialCtx is the X.509 v3 version field (a0 03 02 01 02 =
// [0]{INTEGER 2}) followed by the serialNumber INTEGER tag (02). Unique at
// the start of every Intel cert TBS, and a stable anchor for the serial
// regardless of the serial's own length.
var certVersionSerialCtx = []byte{0xa0, 0x03, 0x02, 0x01, 0x02, 0x02}

// extractCertSerial returns the canonical 20-byte (big-endian) certificate
// serial. DER encodes the serial INTEGER as 20 or 21 bytes (a leading 0x00
// sign byte appears when the high bit is set), so we read the length byte,
// require it to be 0x14 or 0x15, and select the canonical 20 bytes
// accordingly. `off` is the hinted start of certVersionSerialCtx.
func extractCertSerial(api frontend.API, tbs []uints.U8, off frontend.Variable, signedLen frontend.Variable) []frontend.Variable {
	const ctxN = 6 // len(certVersionSerialCtx)
	// SOUNDNESS (G1): keep the read window inside the signed prefix (see extractField).
	assertGte(api, signedLen, api.Add(off, ctxN+1+21))
	sel := selectorAt(api, len(tbs), off)
	got := readBytesAtSel(api, tbs, sel, ctxN+1+21)
	for j := 0; j < ctxN; j++ {
		api.AssertIsEqual(got[j], int(certVersionSerialCtx[j]))
	}
	lenByte := got[ctxN]
	is20 := api.IsZero(api.Sub(lenByte, 0x14))
	is21 := api.IsZero(api.Sub(lenByte, 0x15))
	api.AssertIsEqual(api.Add(is20, is21), 1) // serial length must be 20 or 21
	raw := got[ctxN+1:]                        // 21 bytes (value, maybe 0x00-prefixed)
	// when 21 bytes, raw[0] must be the 0x00 sign byte
	api.AssertIsEqual(api.Mul(is21, raw[0]), 0)
	out := make([]frontend.Variable, 20)
	for i := 0; i < 20; i++ {
		out[i] = api.Select(is21, raw[i+1], raw[i]) // skip sign byte when present
	}
	return out
}

// extractField anchors at `off` (the start of the literal `ctx`), asserts
// buf[off:off+len(ctx)] == ctx, and returns the `fieldLen` bytes that
// immediately follow the context. The returned bytes are frontend.Variable
// (0..255); callers compare or re-expose them.
func extractField(api frontend.API, buf []uints.U8, off frontend.Variable, signedLen frontend.Variable, ctx []byte, fieldLen int) []frontend.Variable {
	// SOUNDNESS (G1): bound the whole read window to the signature-covered
	// prefix. Without this the prover can point `off` into the unsigned buffer
	// tail (bytes past signedLen are free witness, not covered by the ECDSA/
	// SHA-256 over buf[:signedLen]) and plant a duplicate anchor there to
	// extract attacker-chosen bytes. off + len(ctx) + fieldLen <= signedLen
	// forces extraction to read only signed bytes, where the anchor is unique.
	assertGte(api, signedLen, api.Add(off, len(ctx)+fieldLen))
	sel := selectorAt(api, len(buf), off)
	got := readBytesAtSel(api, buf, sel, len(ctx)+fieldLen)
	for j := range ctx {
		api.AssertIsEqual(got[j], int(ctx[j]))
	}
	return got[len(ctx):]
}

// extractStringEnum anchors on `ctx` at `off` (asserting the literal is inside
// the signed prefix, so `off` is a real, signed anchor position), then reads up
// to `readLen` value bytes that MAY extend past signedLen into the zero-padded
// tail. This is sound ONLY for matching a closed set of known string literals
// each terminated by a sentinel byte (here the JSON closing quote): the literal
// + its closing quote live within the signed bytes, so the match decides on
// signed data; padding bytes past the closing quote cannot manufacture a
// different valid match because the read position is pinned to the signed
// anchor. Used for the variable-length tcbStatus near the end of a JSON blob,
// where reading the longest possible status would overrun signedLen.
func extractStringEnum(api frontend.API, buf []uints.U8, off frontend.Variable, signedLen frontend.Variable, ctx []byte, readLen int) []frontend.Variable {
	// Anchor (and at least one value byte + its closing quote position) must be
	// inside the signed prefix; the remaining value bytes may be padding.
	assertGte(api, signedLen, api.Add(off, len(ctx)+1))
	sel := selectorAt(api, len(buf), off)
	got := readBytesAtSel(api, buf, sel, len(ctx)+readLen)
	for j := range ctx {
		api.AssertIsEqual(got[j], int(ctx[j]))
	}
	return got[len(ctx):]
}

// byteTable wraps a logderivlookup over a signed blob so field extraction reads
// bytes by dynamic index in ~3 constraints each, instead of an O(buffer)
// selectorAt per field. The table entries are the SAME witness bytes the blob's
// SHA-256 hashes (verifyCertSig over buf[:signedLen]), and the log-derivative
// argument proves every returned (index, value) is in the table, so a looked-up
// byte is provably the signed byte: identical soundness to a selector read. Build
// ONE table per blob and reuse it for every field, turning the per-level
// extraction cost from O(levels x buffer) into O(levels) lookups.
type byteTable struct {
	api       frontend.API
	t         logderivlookup.Table
	buf       []uints.U8
	signedLen frontend.Variable
	n         int
}

// newByteTable inserts every byte of buf (compile-time capacity, padding
// included) into a fresh lookup table. Insert cost is O(capacity), like SHA.
func newByteTable(api frontend.API, buf []uints.U8, signedLen frontend.Variable) *byteTable {
	t := logderivlookup.New(api)
	for i := range buf {
		t.Insert(buf[i].Val)
	}
	return &byteTable{api: api, t: t, buf: buf, signedLen: signedLen, n: len(buf)}
}

// readAt returns k bytes starting at off (a dynamic offset) via k lookups.
// logderivlookup panics at solving time if an index is out of bounds, so every
// caller must keep off+k-1 within the table capacity (the G1 bound in
// extractFieldLU does this; extractStringEnumLU relies on the documented
// capacity invariant for status reads near a blob's end).
func (bt *byteTable) readAt(off frontend.Variable, k int) []frontend.Variable {
	if k == 0 {
		return nil
	}
	idxs := make([]frontend.Variable, k)
	for j := 0; j < k; j++ {
		idxs[j] = bt.api.Add(off, j)
	}
	return bt.t.Lookup(idxs...)
}

// extractFieldLU is the lookup-table analogue of extractField: same G1 bound,
// same anchor-literal assertion, same returned tail. Only the read mechanism
// differs (table lookup vs selector).
func (bt *byteTable) extractFieldLU(off frontend.Variable, ctx []byte, fieldLen int) []frontend.Variable {
	api := bt.api
	// SOUNDNESS (G1): keep the whole read window inside the signed prefix.
	assertGte(api, bt.signedLen, api.Add(off, len(ctx)+fieldLen))
	got := bt.readAt(off, len(ctx)+fieldLen)
	for j := range ctx {
		api.AssertIsEqual(got[j], int(ctx[j]))
	}
	return got[len(ctx):]
}

// extractStringEnumLU is the lookup analogue of extractStringEnum: the anchor
// (and one value byte) must be inside the signed prefix; remaining value bytes
// may read into the zero-padded tail. Sound for closing-quote-terminated known
// string literals (tcbStatus): the literal + its closing quote live in the
// signed bytes, so the match decides on signed data; padding (real zero table
// entries) cannot spell a different valid status.
//
// CAPACITY INVARIANT: readAt indexes up to off+len(ctx)+readLen-1, which may
// exceed signedLen but must stay < the table capacity (else logderivlookup
// panics). The blob capacity (maxTcbInfo / maxQeID) is chosen so the last status
// anchor + len(ctx) + readLen fits; see layout.go.
func (bt *byteTable) extractStringEnumLU(off frontend.Variable, ctx []byte, readLen int) []frontend.Variable {
	api := bt.api
	assertGte(api, bt.signedLen, api.Add(off, len(ctx)+1))
	got := bt.readAt(off, len(ctx)+readLen)
	for j := range ctx {
		api.AssertIsEqual(got[j], int(ctx[j]))
	}
	return got[len(ctx):]
}
