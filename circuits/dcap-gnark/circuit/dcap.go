package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// Define implements the gnark circuit interface. It performs the full
// self-anchoring DCAP path: chain to the pinned Intel root (A1), Intel-signed
// collateral (A2), and quote verification steps 4-10.
func (c *DcapCircuit) Define(api frontend.API) error {
	// ----------------------------------------------------------------
	// Step 0: Bind public measurement inputs from the signed quote
	// ----------------------------------------------------------------
	if err := c.stepBindPublicInputs(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// A1: PCK chain (leaf <- Platform CA <- pinned Intel Root). Binds
	// PckPubKey to the leaf subjectPublicKey, so step 4 below trusts a
	// chain-anchored key rather than a host-supplied one.
	// ----------------------------------------------------------------
	if err := c.stepVerifyChain(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// A2: Intel-signed collateral (TCB-Signing cert + TCB-Info + QE-Identity).
	// ----------------------------------------------------------------
	if err := c.stepVerifyCollateral(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// Bind platform identity (FMSPC) and PCK serial from signature-anchored
	// bytes, and expose them as public outputs for the on-chain revoked set.
	// ----------------------------------------------------------------
	if err := c.stepBindIdentityOutputs(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// Step 4: Verify QE Report signature (PCK signs QE report)
	// ----------------------------------------------------------------
	if err := c.step4VerifyQeReportSig(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// Step 5: Verify QE Report content hash
	//   SHA-256(attest_key || qe_auth_data) == qe_report.report_data[0:32]
	// ----------------------------------------------------------------
	if err := c.step5VerifyQeReportData(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// Step 6: Verify QE Report policy (QE identity matching)
	// ----------------------------------------------------------------
	if err := c.step6VerifyQePolicy(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// Step 7: Verify ISV Report signature (attest key signs quote)
	// ----------------------------------------------------------------
	if err := c.step7VerifyIsvReportSig(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// G2: bind every TCB-verdict comparison value (svn components, pcesvn,
	// tcbStatus, QE policy + QE TCB levels, platform SVNs) to the Intel-signed
	// collateral / ISV-signed quote, so steps 8-10 compare signed data, not
	// free witness.
	// ----------------------------------------------------------------
	tcbEval, qeEval, freshLo, freshHi, err := c.stepBindTcbData(api)
	if err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// Step 8: Match platform TCB level
	// ----------------------------------------------------------------
	if err := c.step8MatchPlatformTcb(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// Steps 9-10: Merge TCB statuses and bind final status
	// ----------------------------------------------------------------
	if err := c.step9and10MergeStatus(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// G4 (revocation): the PCK leaf serial is not in the Platform-CA-signed PCK
	// CRL, and the intermediate serial is not in the Root-CA-signed Root CRL. This
	// step also folds the CRL windows into the validity intersection and binds the
	// #2/#3 public outputs.
	// ----------------------------------------------------------------
	return c.stepVerifyRevocation(api, tcbEval, qeEval, freshLo, freshHi)
}

// stepVerifyRevocation discharges the revocation half of G4. It re-extracts the
// Platform CA subject key from the (chain-anchored) intermediate TBS to verify
// the PCK CRL, uses the pinned Intel root for the Root CA CRL, and proves that
// neither the leaf serial (in the PCK CRL) nor the intermediate serial (in the
// Root CRL) is revoked.
func (c *DcapCircuit) stepVerifyRevocation(api frontend.API, tcbEval, qeEval, freshLo, freshHi frontend.Variable) error {
	// Platform CA subject key (the PCK CRL issuer) from the intermediate TBS.
	ix, iy, err := extractSubjectPubKey(api, c.IntTBS[:], c.IntPubKeyOff, c.IntTBSLen)
	if err != nil {
		return err
	}
	platformCA := ECDSAPublicKey{X: *ix, Y: *iy}

	// Leaf serial (signature-anchored, 20 canonical bytes) for the PCK CRL. The
	// CRL is structurally anchored (C4) and freshness-checked against Timestamp
	// (C5) inside verifyCrlNonMembership.
	leafSerial := extractCertSerial(api, c.LeafTBS[:], c.LeafSerialOff, c.LeafTBSLen)
	pckThis, pckNext, err := verifyCrlNonMembership(api, c.PckCrlTBS[:], c.PckCrlTBSLen, &platformCA, &c.PckCrlSig, leafSerial, c.PckCrlThisUpdateOff, c.Timestamp)
	if err != nil {
		return err
	}

	// Intermediate serial for the Root CA CRL, issued by the pinned root.
	intSerial := extractCertSerial(api, c.IntTBS[:], c.IntSerialOff, c.IntTBSLen)
	root := intelRootCAPubKey()
	rootThis, rootNext, err := verifyCrlNonMembership(api, c.RootCrlTBS[:], c.RootCrlTBSLen, &root, &c.RootCrlSig, intSerial, c.RootCrlThisUpdateOff, c.Timestamp)
	if err != nil {
		return err
	}

	// #3: fold the two CRL windows into the freshness/cert intersection and bind
	// [ValidFrom, ValidUntil]. Every per-window assert held, so freshLo <=
	// Timestamp <= freshHi and each CRL window contains Timestamp; the assert below
	// is a defensive non-empty-intersection guard. The consumer range-checks chain
	// time against [ValidFrom, ValidUntil] instead of trusting the host Timestamp.
	validFrom := maxVarWide(api, freshLo, maxVarWide(api, pckThis, rootThis))
	validUntil := minVarWide(api, freshHi, minVarWide(api, pckNext, rootNext))
	assertGteWide(api, validUntil, validFrom) // non-empty collateral validity intersection
	api.AssertIsEqual(validFrom, c.ValidFrom)
	api.AssertIsEqual(validUntil, c.ValidUntil)

	// #2/#4: bind both tcbEvaluationDataNumber public outputs separately.
	api.AssertIsEqual(tcbEval, c.TcbInfoEvalNum)
	api.AssertIsEqual(qeEval, c.QeIdEvalNum)
	return nil
}

// stepBindPublicInputs binds TDReport fields from the private signed quote
// to the public inputs. The signed quote content is authenticated by the
// ISV ECDSA signature (step 7), so no additional hashing is needed.
func (c *DcapCircuit) stepBindPublicInputs(api frontend.API) error {
	// Bind MrTd from signed quote to public input
	if err := assertBytesEqualRange(api,
		c.SignedQuote[:], SQ_MrTd,
		c.MrTd[:], 0, 48); err != nil {
		return err
	}

	// Bind RTMRs
	if err := assertBytesEqualRange(api, c.SignedQuote[:], SQ_Rtmr0, c.Rtmr0[:], 0, 48); err != nil {
		return err
	}
	if err := assertBytesEqualRange(api, c.SignedQuote[:], SQ_Rtmr1, c.Rtmr1[:], 0, 48); err != nil {
		return err
	}
	if err := assertBytesEqualRange(api, c.SignedQuote[:], SQ_Rtmr2, c.Rtmr2[:], 0, 48); err != nil {
		return err
	}
	if err := assertBytesEqualRange(api, c.SignedQuote[:], SQ_Rtmr3, c.Rtmr3[:], 0, 48); err != nil {
		return err
	}

	// Bind ReportData
	return assertBytesEqualRange(api, c.SignedQuote[:], SQ_ReportData, c.ReportData[:], 0, 64)
}

// stepVerifyChain discharges A1: it proves the PCK leaf chains to the pinned
// Intel SGX Root CA and binds PckPubKey to the leaf subjectPublicKey.
func (c *DcapCircuit) stepVerifyChain(api frontend.API) error {
	return verifyChainToRoot(api,
		c.LeafTBS[:], c.LeafTBSLen, &c.LeafSig, c.LeafPubKeyOff,
		c.IntTBS[:], c.IntTBSLen, &c.IntSig, c.IntPubKeyOff,
		&c.PckPubKey)
}

// stepVerifyCollateral discharges A2: the Intel TCB-Signing cert chains to the
// pinned root and signs both the TCB-Info and QE-Identity JSON documents.
func (c *DcapCircuit) stepVerifyCollateral(api frontend.API) error {
	_, err := verifyCollateral(api,
		c.SignTBS[:], c.SignLen, &c.SignSig, c.SignPubOff,
		c.TcbInfoRaw[:], c.TcbInfoRawLen, &c.TcbInfoSig,
		c.QeIDRaw[:], c.QeIDRawLen, &c.QeIDSig)
	return err
}

// stepBindIdentityOutputs derives the platform FMSPC and PCK serial from the
// signature-anchored leaf/collateral bytes and binds them to the public
// outputs. It also cross-checks that the leaf FMSPC equals the FMSPC inside
// the Intel-signed TCB-Info JSON, so the collateral provably belongs to this
// platform (closing the FMSPC-substitution gap).
func (c *DcapCircuit) stepBindIdentityOutputs(api frontend.API) error {
	// FMSPC from the PCK leaf: 6 raw DER bytes after the FMSPC OID context.
	leafFmspc := extractField(api, c.LeafTBS[:], c.LeafFmspcOff, c.LeafTBSLen, fmspcCtx, fmspcLen)

	// FMSPC from the Intel-signed TCB-Info JSON: 12 uppercase-hex characters
	// after the "fmspc":" anchor, parsed to 6 bytes.
	tcbHex := extractField(api, c.TcbInfoRaw[:], c.TcbInfoFmspcOff, c.TcbInfoRawLen, tcbInfoFmspcCtx, 2*fmspcLen)
	tcbFmspc := hexBytesToBytes(api, tcbHex)

	for i := 0; i < fmspcLen; i++ {
		api.AssertIsEqual(leafFmspc[i], tcbFmspc[i])
		api.AssertIsEqual(leafFmspc[i], c.Fmspc[i].Val)
	}

	// PCK leaf serial -> public output (handles 20/21-byte DER encoding).
	serial := extractCertSerial(api, c.LeafTBS[:], c.LeafSerialOff, c.LeafTBSLen)
	for i := 0; i < certSerialLen; i++ {
		api.AssertIsEqual(serial[i], c.CertSerial[i].Val)
	}
	return nil
}

// step4VerifyQeReportSig verifies the ECDSA-P256 signature over the QE report
// using the PCK public key.
func (c *DcapCircuit) step4VerifyQeReportSig(api frontend.API) error {
	// Hash QE report bytes (384 bytes) with SHA-256
	qeReportHash, err := sha256Fixed(api, c.QeReport[:])
	if err != nil {
		return err
	}

	// Convert hash to P256Fr scalar
	msgScalar, err := bytesToP256Fr(api, qeReportHash)
	if err != nil {
		return err
	}

	// Verify ECDSA signature
	c.PckPubKey.Verify(api, sw_emulated.GetP256Params(), msgScalar, &c.QeReportSig)
	return nil
}

// step5VerifyQeReportData verifies that SHA-256(attest_key || qe_auth_data)
// matches qe_report.report_data[0:32].
func (c *DcapCircuit) step5VerifyQeReportData(api frontend.API) error {
	// Build hash input: attest_key_raw (64 bytes) || qe_auth_data (variable length)
	// Total max = 64 + 32 = 96 bytes
	hashInput := make([]uints.U8, 64+32)
	copy(hashInput[:64], c.AttestKeyRaw[:])
	copy(hashInput[64:], c.QeAuthData[:])

	hashLen := api.Add(64, c.QeAuthDataLen)
	digest, err := sha256VarLen(api, hashInput, hashLen)
	if err != nil {
		return err
	}

	// Compare with QE report's report_data[0:32]
	if err := assertBytesEqual(api, digest[:],
		c.QeReport[QER_ReportData:QER_ReportData+32]); err != nil {
		return err
	}

	// SOUNDNESS (G3): the raw attestation key hashed above (committed in the
	// PCK-signed QE report) must be the SAME key that verifies the quote body in
	// step 7. Otherwise AttestKeyRaw and AttestKeyPub are independent witnesses,
	// and a prover could keep a genuine QE report yet sign a fabricated quote
	// under a self-chosen AttestKeyPub. Bind the emulated point to the raw bytes.
	rawX := make([]frontend.Variable, 32)
	rawY := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		rawX[i] = c.AttestKeyRaw[i].Val
		rawY[i] = c.AttestKeyRaw[32+i].Val
	}
	akx, err := bytesVarToP256Fp(api, rawX)
	if err != nil {
		return err
	}
	aky, err := bytesVarToP256Fp(api, rawY)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[P256Fp](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(akx, &c.AttestKeyPub.X)
	f.AssertIsEqual(aky, &c.AttestKeyPub.Y)
	return nil
}

// step6VerifyQePolicy checks QE identity policy fields against the QE report.
func (c *DcapCircuit) step6VerifyQePolicy(api frontend.API) error {
	// 1. MRSIGNER: exact match
	if err := assertBytesEqual(api,
		c.QeReport[QER_MrSigner:QER_MrSigner+32],
		c.QeIdMrSigner[:]); err != nil {
		return err
	}

	// 2. ISVPRODID: exact match (u16 LE at offset 256)
	qeIsvProdId := u16FromLEBytes(api,
		c.QeReport[QER_IsvProdId], c.QeReport[QER_IsvProdId+1])
	api.AssertIsEqual(qeIsvProdId, c.QeIdIsvProdId)

	// 3. MISCSELECT: masked comparison (u32)
	var qeMisc [4]uints.U8
	copy(qeMisc[:], c.QeReport[QER_MiscSelect:QER_MiscSelect+4])
	if err := assertMaskedBytesEqual(api,
		qeMisc[:], c.QeIdMiscSelect[:], c.QeIdMiscMask[:]); err != nil {
		return err
	}

	// 4. ATTRIBUTES: masked byte-by-byte comparison (16 bytes)
	if err := assertMaskedBytesEqual(api,
		c.QeReport[QER_Attributes:QER_Attributes+16],
		c.QeIdAttributes[:],
		c.QeIdAttrMask[:]); err != nil {
		return err
	}

	// 5. QE TCB matching is handled in step9and10 (the severity is read there)
	return nil
}

// step7VerifyIsvReportSig verifies the ECDSA-P256 signature over the signed
// quote region using the attestation key.
func (c *DcapCircuit) step7VerifyIsvReportSig(api frontend.API) error {
	// Hash signed quote (632 bytes) with SHA-256
	signedHash, err := sha256Fixed(api, c.SignedQuote[:])
	if err != nil {
		return err
	}

	// Convert to P256Fr scalar
	msgScalar, err := bytesToP256Fr(api, signedHash)
	if err != nil {
		return err
	}

	// Verify ECDSA with attestation key
	c.AttestKeyPub.Verify(api, sw_emulated.GetP256Params(), msgScalar, &c.IsvSig)
	return nil
}

// step8MatchPlatformTcb verifies the platform TCB level match and forces the
// CANONICAL (first-satisfiable) level selection (G5). Intel orders tcbLevels
// descending by SVN, so the correct verdict is the FIRST level the platform
// satisfies. A prover must not pick an older, softer-severity level that the
// platform also satisfies.
//
// For each level m we compute a boolean satisfied[m] (all platform components
// >= level m's thresholds) WITHOUT asserting, then require:
//   - satisfied[m] == 0 for every active level m < TcbMatchIdx, and
//   - satisfied[TcbMatchIdx] == 1.
// The platform/TCB-Info FMSPC equality is enforced in stepBindIdentityOutputs;
// the per-level thresholds are bound to the signed JSON in stepBindTcbData.
func (c *DcapCircuit) step8MatchPlatformTcb(api frontend.API) error {
	idx := c.TcbMatchIdx
	// C1 (CRITICAL): range-decompose the match index onto a real slot. Without
	// this, a prover sets idx to a field element like p-1 (the additive inverse
	// of 1): the assertGte upper bound below still passes (count-1-idx wraps to a
	// small positive), every IsZero(idx-m)==0 so isChosen is never 1 and the
	// "chosen must be satisfied" check goes vacuous, and muxVar(TcbSeverity,idx)
	// returns 0 -> a forged UpToDate verdict for any platform. ToBinary(idx,4)
	// forces idx into [0,16) (MaxTcbLevels), and the upper bound then pins it to
	// an active slot.
	api.ToBinary(idx, 4) // MaxTcbLevels = 16 -> 4 bits
	// Hint index within the derived (signed) level count.
	assertGte(api, api.Sub(c.TcbLevelCount, 1), idx)

	for m := 0; m < MaxTcbLevels; m++ {
		sat := c.platformSatisfiesLevel(api, m)
		// active iff m < TcbLevelCount (padding slots repeat the last real level,
		// so they would also be "satisfied"; exclude them from the ordering rule).
		active := isLessThan(api, m, c.TcbLevelCount)
		isChosen := api.IsZero(api.Sub(idx, m))
		before := isLessThanVar(api, m, idx) // m < idx
		// Chosen level must be satisfied.
		api.AssertIsEqual(api.Mul(isChosen, api.Sub(1, sat)), 0)
		// Every active level strictly before the chosen one must be UNsatisfied
		// (else it would be the canonical pick).
		api.AssertIsEqual(api.Mul(api.Mul(active, before), sat), 0)
	}
	return nil
}

// platformSatisfiesLevel returns 1 iff the platform's CPU/PCE/TEE SVNs all meet
// or exceed level m's thresholds (the same comparison step8 used to assert, but
// as a boolean for the canonical-selection rule).
func (c *DcapCircuit) platformSatisfiesLevel(api frontend.API, m int) frontend.Variable {
	ok := frontend.Variable(1)
	// PCE SVN
	ok = api.Mul(ok, gteBool(api, c.PlatformPceSvn, c.TcbPceSvn[m]))
	// SGX components
	for i := 0; i < MaxSgxComponents; i++ {
		ok = api.Mul(ok, gteBool(api, c.PlatformCpuSvn[i].Val, c.TcbSgxComps[m][i]))
	}
	// TDX components
	for i := 0; i < MaxTdxComponents; i++ {
		ok = api.Mul(ok, gteBool(api, c.PlatformTeeTcbSvn[i].Val, c.TcbTdxComps[m][i]))
	}
	return ok
}

// step9and10MergeStatus computes QE TCB status and merges with platform TCB status.
func (c *DcapCircuit) step9and10MergeStatus(api frontend.API) error {
	// Step 9: QE TCB matching with canonical (first-satisfiable) selection (G5).
	qeIdx := c.QeTcbMatchIdx
	qeIsvSvn := u16FromLEBytes(api,
		c.QeReport[QER_IsvSvn], c.QeReport[QER_IsvSvn+1])

	// C1 (CRITICAL): range-decompose the QE match index onto a real slot (same
	// forged-UpToDate-via-out-of-range-index attack as the platform index).
	api.ToBinary(qeIdx, 3) // MaxQeTcbLevels = 8 -> 3 bits
	// Verify QE hint index within the derived (signed) level count.
	assertGte(api, api.Sub(c.QeIdTcbCount, 1), qeIdx)

	// Canonical selection: the chosen QE level must be satisfied
	// (qe_isv_svn >= threshold), and every active level before it must NOT be.
	for m := 0; m < MaxQeTcbLevels; m++ {
		sat := gteBool(api, qeIsvSvn, c.QeIdTcbIsvSvn[m])
		active := isLessThan(api, m, c.QeIdTcbCount)
		isChosen := api.IsZero(api.Sub(qeIdx, m))
		before := isLessThanVar(api, m, qeIdx)
		api.AssertIsEqual(api.Mul(isChosen, api.Sub(1, sat)), 0)
		api.AssertIsEqual(api.Mul(api.Mul(active, before), sat), 0)
	}

	// Get QE severity
	qeSeverity := muxVar(api, c.QeIdTcbSeverity[:], qeIdx)

	// Get platform severity
	platformSeverity := muxVar(api, c.TcbSeverity[:], c.TcbMatchIdx)

	// Step 10: merge = max(platform_severity, qe_severity)
	mergedStatus := maxVar(api, platformSeverity, qeSeverity)

	// Assert merged status != Revoked (6)
	isRevoked := api.IsZero(api.Sub(mergedStatus, TcbRevoked))
	api.AssertIsEqual(isRevoked, 0)

	// Bind to public TcbStatus
	api.AssertIsEqual(mergedStatus, c.TcbStatus)

	return nil
}

// Compile-time interface check
var _ frontend.Circuit = (*DcapCircuit)(nil)
