package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// Define implements the gnark circuit interface. It performs DCAP quote
// verification steps 4-10 (lite path).
func (c *DcapCircuit) Define(api frontend.API) error {
	// ----------------------------------------------------------------
	// Step 0: Compute quote hash and bind public inputs to witness
	// ----------------------------------------------------------------
	if err := c.stepBindPublicInputs(api); err != nil {
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
	// Step 8: Match platform TCB level
	// ----------------------------------------------------------------
	if err := c.step8MatchPlatformTcb(api); err != nil {
		return err
	}

	// ----------------------------------------------------------------
	// Steps 9-10: Merge TCB statuses and bind final status
	// ----------------------------------------------------------------
	return c.step9and10MergeStatus(api)
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
	return assertBytesEqual(api, digest[:],
		c.QeReport[QER_ReportData:QER_ReportData+32])
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

// step8MatchPlatformTcb verifies the platform TCB level match using the host hint.
func (c *DcapCircuit) step8MatchPlatformTcb(api frontend.API) error {
	// 1. FMSPC exact match
	if err := assertBytesEqual(api, c.PlatformFmspc[:], c.TcbInfoFmspc[:]); err != nil {
		return err
	}

	// 2. Verify the hinted TCB level matches
	idx := c.TcbMatchIdx

	// a. PCE SVN: platform >= tcb_level
	tcbPceSvn := muxVar(api, c.TcbPceSvn[:], idx)
	assertGte(api, c.PlatformPceSvn, tcbPceSvn)

	// b. SGX components: cpu_svn[i] >= sgx_comp[i] for all i
	for i := 0; i < MaxSgxComponents; i++ {
		// Build array of tcb_levels[*].sgx_comps[i]
		compArr := make([]frontend.Variable, MaxTcbLevels)
		for j := 0; j < MaxTcbLevels; j++ {
			compArr[j] = c.TcbSgxComps[j][i]
		}
		tcbComp := muxVar(api, compArr, idx)
		assertGte(api, c.PlatformCpuSvn[i].Val, tcbComp)
	}

	// c. TDX components: tee_tcb_svn[i] >= tdx_comp[i] for all i
	for i := 0; i < MaxTdxComponents; i++ {
		compArr := make([]frontend.Variable, MaxTcbLevels)
		for j := 0; j < MaxTcbLevels; j++ {
			compArr[j] = c.TcbTdxComps[j][i]
		}
		tcbComp := muxVar(api, compArr, idx)
		assertGte(api, c.PlatformTeeTcbSvn[i].Val, tcbComp)
	}

	// 3. Verify hint index is within bounds
	assertGte(api, api.Sub(c.TcbLevelCount, 1), idx)

	return nil
}

// step9and10MergeStatus computes QE TCB status and merges with platform TCB status.
func (c *DcapCircuit) step9and10MergeStatus(api frontend.API) error {
	// Step 9: QE TCB matching — verify hint
	qeIdx := c.QeTcbMatchIdx
	qeIsvSvn := u16FromLEBytes(api,
		c.QeReport[QER_IsvSvn], c.QeReport[QER_IsvSvn+1])

	// Verify: qe_report.isv_svn >= qe_tcb_level[qeIdx].isvsvn
	qeTcbThreshold := muxVar(api, c.QeIdTcbIsvSvn[:], qeIdx)
	assertGte(api, qeIsvSvn, qeTcbThreshold)

	// Verify QE hint index within bounds
	assertGte(api, api.Sub(c.QeIdTcbCount, 1), qeIdx)

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
