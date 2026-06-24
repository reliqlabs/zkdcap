package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// CRL buffer/list capacities (compile-time). Sized to the real Intel CRLs in
// the fixture: the PCK CRL TBS is ~3.2 KB with 57 revoked entries; the Root CA
// CRL is small with no revocations. SHA cost scales with capacity.
const (
	crlSerialLen = 20 // Intel PCK cert serials are 160-bit

	pckCrlMaxTBS     = 3072 // real PCK CRL TBS = 2572; 48x64B SHA blocks, headroom
	pckCrlMaxRevoked = 64

	rootCrlMaxTBS     = 512
	rootCrlMaxRevoked = 8
)

// verifyCrlNonMembership proves (1) the CRL is validly signed by `issuer` (which
// binds every byte of tbs[:tbsLen], including the revoked-serial list), and
// (2) the 20-byte big-endian `targetSerial` does NOT appear as a contiguous
// substring anywhere in the signed tbs. A revoked serial is stored verbatim in
// the CRL's revoked list, so if the target were revoked its bytes would occur in
// the signed tbs and the substring check would fail. Conversely the prover
// cannot suppress a revocation by supplying an empty list: the list is inside
// the signed bytes, so the substring is present whenever the serial is revoked.
//
// This supersedes the per-serial offset-extraction sketched in the original
// verifyCrl note: substring-absence is both cheaper (one pass, no per-serial
// selector) and closes the empty-list gap directly. A 160-bit serial colliding
// with unrelated tbs bytes (dates, OIDs) is cryptographically negligible, and
// targetSerial is itself signature-anchored (the PCK leaf serial), not free.
// crlTbsHeadCtx is the leading DER of a v2 CRL tbsCertList:
//   02 01 01            version INTEGER = 1 (i.e. v2)
//   30 0a 06 08 2a 86 48 ce 3d 04 03 02   signature AlgorithmIdentifier
//                                         (ecdsa-with-SHA256)
// A certificate's tbsCertificate instead begins with the version [0] EXPLICIT
// context tag (a0 03 02 01 02) followed by the serialNumber INTEGER, so it can
// NEVER present this exact byte sequence at offset 0. Anchoring it at offset 0
// of the supplied CRL TBS (C4) stops a prover from passing an issuer-signed
// non-CRL TBS (e.g. another PCK leaf's tbsCertificate, also Platform-CA-signed)
// off as the CRL to bypass revocation.
var crlTbsHeadCtx = []byte{0x02, 0x01, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}

// crlMaxHeaderScan bounds where thisUpdate may sit (it follows version +
// sigAlg + issuer Name, all small). The first UTCTime in a tbsCertList is
// always thisUpdate (version/sigAlg/issuer carry no UTCTime), so we pin it as
// the first `17 0d` in the buffer; this scan bounds that search cheaply.
const crlMaxHeaderScan = 320

// verifyCrlNonMembership proves the supplied CRL is a genuine, current, validly
// signed CRL and that targetSerial is not revoked by it:
//  1. signature by `issuer` over tbs[:tbsLen] (binds every byte),
//  2. C4: tbs begins with the v2 CRL tbsCertList head (crlTbsHeadCtx), so a
//     non-CRL issuer-signed TBS cannot pose as the CRL,
//  3. C5: thisUpdate <= timestamp <= nextUpdate (freshness; rejects a stale CRL
//     replayed before a later revocation),
//  4. substring-absence of targetSerial in the signed tbs (non-membership).
//
// `thisUpdateOff` is a host hint for thisUpdate's UTCTime; it is pinned to the
// FIRST `17 0d` in the buffer (no earlier UTCTime), which is provably thisUpdate.
// nextUpdate is the immediately following UTCTime (compile-time +15 offset).
// `timestamp` is the packed YYYYMMDDhhmmss verification time (same encoding as
// stepCheckFreshness).
func verifyCrlNonMembership(
	api frontend.API,
	tbs []uints.U8,
	tbsLen frontend.Variable,
	issuer *ECDSAPublicKey,
	sig *ECDSASignature,
	targetSerial []frontend.Variable, // 20 canonical DER bytes (from extractCertSerial)
	thisUpdateOff frontend.Variable,
	timestamp frontend.Variable,
) (frontend.Variable, frontend.Variable, error) {
	if err := verifyCertSig(api, tbs, tbsLen, issuer, sig); err != nil {
		return 0, 0, err
	}
	n := len(tbs)

	// C4: structural anchor on the tbsCertList CONTENT (a cert TBS cannot match
	// it). RawTBSRevocationList begins with the DER SEQUENCE header `30 LL[LL]`;
	// skip it, then assert the v2-CRL content head crlTbsHeadCtx (version INTEGER
	// 1 + ecdsa-with-SHA256 AlgorithmIdentifier). A cert's tbsCertificate content
	// instead begins with the version [0] EXPLICIT tag (a0...), so it fails here.
	// DER length forms: tbs[1] < 0x80 => short (header 2 bytes); else
	// tbs[1]&0x7f = number of length bytes (header 2 + that many).
	api.AssertIsEqual(tbs[0].Val, 0x30) // tbsCertList SEQUENCE tag
	lb := tbs[1].Val
	// Intel cert/CRL TBS are long-form: 0x81 (1 length byte) or 0x82 (2). Header
	// size is 3 or 4; content offset is 3 or 4 accordingly.
	is81 := api.IsZero(api.Sub(lb, 0x81))
	is82 := api.IsZero(api.Sub(lb, 0x82))
	api.AssertIsEqual(api.Add(is81, is82), 1) // exactly one long-form shape
	contentOff := api.Add(3, is82)            // 0x81 -> 3, 0x82 -> 4
	head := readBytesAtSel(api, tbs, selectorAt(api, n, contentOff), len(crlTbsHeadCtx))
	for j, b := range crlTbsHeadCtx {
		api.AssertIsEqual(head[j], int(b))
	}

	// C5: freshness. Pin thisUpdate as the first UTCTime, parse both dates.
	// (a) anchor `17 0d` at thisUpdateOff, and bound it to the header region.
	assertGte(api, tbsLen, api.Add(thisUpdateOff, 2+13+2+13)) // both dates fit in signed bytes
	assertGte(api, crlMaxHeaderScan, thisUpdateOff)
	thisTag := readBytesAtSel(api, tbs, selectorAt(api, n, thisUpdateOff), 2)
	api.AssertIsEqual(thisTag[0], 0x17) // UTCTime tag
	api.AssertIsEqual(thisTag[1], 0x0d) // length 13
	// (b) no `17 0d` before thisUpdateOff, so this is the FIRST UTCTime
	//     (== thisUpdate; the header has no other UTCTime).
	for p := 0; p+1 < crlMaxHeaderScan && p+1 < n; p++ {
		isUtc := api.Mul(api.IsZero(api.Sub(tbs[p].Val, 0x17)), api.IsZero(api.Sub(tbs[p+1].Val, 0x0d)))
		before := isLessThanVar(api, p, thisUpdateOff)
		api.AssertIsEqual(api.Mul(isUtc, before), 0) // no UTCTime strictly before thisUpdate
	}
	// (c) parse thisUpdate (value at +2) and nextUpdate (the next UTCTime,
	//     at thisUpdateOff + 2 + 13, with its own `17 0d` tag re-asserted).
	thisVal := readBytesAtSel(api, tbs, selectorAt(api, n, api.Add(thisUpdateOff, 2)), 13)
	thisUpd := parseUtcTime(api, thisVal)
	nextOff := api.Add(thisUpdateOff, 2+13)
	nextTag := readBytesAtSel(api, tbs, selectorAt(api, n, nextOff), 2)
	api.AssertIsEqual(nextTag[0], 0x17)
	api.AssertIsEqual(nextTag[1], 0x0d)
	nextVal := readBytesAtSel(api, tbs, selectorAt(api, n, api.Add(nextOff, 2)), 13)
	nextUpd := parseUtcTime(api, nextVal)
	assertGteWide(api, timestamp, thisUpd) // timestamp >= thisUpdate
	assertGteWide(api, nextUpd, timestamp) // timestamp <= nextUpdate

	// 4. Non-membership: targetSerial absent as a contiguous substring.
	k := len(targetSerial)
	for p := 0; p+k <= n; p++ {
		eq := frontend.Variable(1)
		for j := 0; j < k; j++ {
			eq = api.Mul(eq, api.IsZero(api.Sub(tbs[p+j].Val, targetSerial[j])))
		}
		api.AssertIsEqual(eq, 0)
	}
	// Return the freshness window so the caller can fold it into the intersected
	// collateral validity window (#3).
	return thisUpd, nextUpd, nil
}

// crlSerialCtx anchors a revoked entry's serial inside a CRL TBS. A revoked
// entry is a SEQUENCE { serialNumber INTEGER, revocationDate Time }; the entry
// begins with the SEQUENCE tag (30) + length, then the INTEGER (02) + length.
// Because serials vary (20 or 21 DER bytes) we anchor on the INTEGER tag and
// read the length, mirroring extractCertSerial.

// verifyCrl asserts that the X.509 CRL whose tbsCertList is `tbs[:tbsLen]`
// is validly signed by `issuer`, and that `targetSerial` is NOT in the
// revoked-serial list. This is the optional CRL path (DCAP full
// verification): the PCK CRL (issued by the PCK Platform/Processor CA)
// revokes individual platform PCK certs, and the Root CA CRL revokes
// intermediates. Without it, a genuine-but-revoked platform's leaked PCK
// key can still attest (see docs/intent.md residual; the A1+A2 path does
// not check revocation).
//
// `revoked` is a fixed-capacity list of equal-width serials; unused slots
// are zero-padded and are safe because a real (DER INTEGER) serial is never
// all-zero. `targetSerial` and every `revoked[i]` must be the same width.
//
// SOUNDNESS NOTE: for the non-membership to be meaningful the revoked
// serials must be bound to the hashed tbs (extracted at constrained
// offsets), otherwise a malicious prover could supply an empty list. This
// gadget proves the signature (which binds every tbs byte) and the
// comparison logic; offset-binding of the serials to `tbs` is layered on
// in the full-circuit integration (Step 8) and adds only modest
// assertBytesEqualRange overhead on top of the dominant SHA+ECDSA cost
// measured here.
func verifyCrl(
	api frontend.API,
	tbs []uints.U8,
	tbsLen frontend.Variable,
	issuer *ECDSAPublicKey,
	sig *ECDSASignature,
	targetSerial []uints.U8,
	revoked [][]uints.U8,
) error {
	// 1. CRL signature: a CRL is signed exactly like a cert TBS.
	if err := verifyCertSig(api, tbs, tbsLen, issuer, sig); err != nil {
		return err
	}

	// 2. Non-membership: assert targetSerial != revoked[i] for all i.
	// eq = product over bytes of (targetSerial[j] == revoked[i][j]); a
	// product of equality bits is 1 iff every byte matches. Assert eq == 0.
	for i := range revoked {
		eq := frontend.Variable(1)
		for j := range targetSerial {
			byteEq := api.IsZero(api.Sub(targetSerial[j].Val, revoked[i][j].Val))
			eq = api.Mul(eq, byteEq)
		}
		api.AssertIsEqual(eq, 0)
	}
	return nil
}
