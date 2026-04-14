package witness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/circuit"
)

// BuildWitness constructs a fully assigned DcapCircuit from raw inputs.
func BuildWitness(quoteBytes []byte, preVerified *PreVerifiedInputs, timestamp uint64) (*circuit.DcapCircuit, error) {
	// Parse quote
	q, err := ParseTDXQuoteV4(quoteBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing quote: %w", err)
	}

	// Parse PCK certificate to extract public key
	pckCert, err := x509.ParseCertificate(preVerified.PckLeafDer)
	if err != nil {
		return nil, fmt.Errorf("parsing PCK cert: %w", err)
	}
	pckPub, ok := pckCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PCK cert does not contain ECDSA key")
	}
	if pckPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("PCK key is not P-256")
	}

	c := &circuit.DcapCircuit{}

	// --- Public inputs ---
	copyU8(c.MrTd[:], q.MrTd[:])
	copyU8(c.Rtmr0[:], q.Rtmr0[:])
	copyU8(c.Rtmr1[:], q.Rtmr1[:])
	copyU8(c.Rtmr2[:], q.Rtmr2[:])
	copyU8(c.Rtmr3[:], q.Rtmr3[:])
	copyU8(c.ReportData[:], q.ReportData[:])
	c.Timestamp = timestamp

	// --- Signed quote ---
	copyU8(c.SignedQuote[:], q.SignedData)

	// --- QE Report ---
	copyU8(c.QeReport[:], q.QeReport[:])

	// --- PCK public key ---
	c.PckPubKey.X = newP256FpElement(pckPub.X)
	c.PckPubKey.Y = newP256FpElement(pckPub.Y)

	// --- QE Report signature ---
	setP256Signature(&c.QeReportSig, q.QeReportSignature[:])

	// --- ISV signature ---
	setP256Signature(&c.IsvSig, q.EcdsaSignature[:])

	// --- Attestation key ---
	copyU8(c.AttestKeyRaw[:], q.AttestationKey[:])
	akX := new(big.Int).SetBytes(q.AttestationKey[:32])
	akY := new(big.Int).SetBytes(q.AttestationKey[32:64])
	c.AttestKeyPub.X = newP256FpElement(akX)
	c.AttestKeyPub.Y = newP256FpElement(akY)

	// --- QE Auth Data (padded to 32) ---
	qeAuth := make([]byte, 32)
	copy(qeAuth, q.QeAuthData)
	copyU8(c.QeAuthData[:], qeAuth)
	c.QeAuthDataLen = len(q.QeAuthData)

	// --- QE Identity policy ---
	copyU8(c.QeIdMrSigner[:], preVerified.QeIdentity.MrSigner[:])
	c.QeIdIsvProdId = int(preVerified.QeIdentity.IsvProdID)
	copyU8(c.QeIdMiscSelect[:], preVerified.QeIdentity.MiscSelect[:])
	copyU8(c.QeIdMiscMask[:], preVerified.QeIdentity.MiscSelectMask[:])
	copyU8(c.QeIdAttributes[:], preVerified.QeIdentity.Attributes[:])
	copyU8(c.QeIdAttrMask[:], preVerified.QeIdentity.AttributesMask[:])

	// --- QE TCB levels ---
	// ISV SVN is u16 LE at offset 258 within QE report
	qeIsvSvnVal := uint16(q.QeReport[258]) | uint16(q.QeReport[259])<<8

	qeMatchIdx := -1
	for i, level := range preVerified.QeIdentity.TcbLevels {
		if i >= circuit.MaxQeTcbLevels {
			break
		}
		c.QeIdTcbIsvSvn[i] = int(level.Tcb.IsvSvn)
		sev, ok := TcbStatusSeverity[level.TcbStatus]
		if !ok {
			return nil, fmt.Errorf("unknown QE TCB status: %s", level.TcbStatus)
		}
		c.QeIdTcbSeverity[i] = sev
		if qeMatchIdx == -1 && qeIsvSvnVal >= level.Tcb.IsvSvn {
			qeMatchIdx = i
		}
	}
	for i := len(preVerified.QeIdentity.TcbLevels); i < circuit.MaxQeTcbLevels; i++ {
		c.QeIdTcbIsvSvn[i] = 0
		c.QeIdTcbSeverity[i] = 0
	}
	c.QeIdTcbCount = len(preVerified.QeIdentity.TcbLevels)
	if qeMatchIdx < 0 {
		return nil, fmt.Errorf("no matching QE TCB level (isv_svn=%d)", qeIsvSvnVal)
	}
	c.QeTcbMatchIdx = qeMatchIdx

	// --- Platform TCB ---
	copyU8(c.PlatformFmspc[:], preVerified.Fmspc[:])

	tcbFmspc, err := hex.DecodeString(preVerified.TcbInfo.Fmspc)
	if err != nil {
		return nil, fmt.Errorf("decoding TCB info FMSPC: %w", err)
	}
	copyU8(c.TcbInfoFmspc[:], tcbFmspc)

	copyU8(c.PlatformCpuSvn[:], preVerified.CpuSvn[:])
	c.PlatformPceSvn = int(preVerified.PceSvn)
	copyU8(c.PlatformTeeTcbSvn[:], q.TeeTcbSvn[:])

	// --- Platform TCB levels ---
	tcbMatchIdx := -1
	for i, level := range preVerified.TcbInfo.TcbLevels {
		if i >= circuit.MaxTcbLevels {
			break
		}
		c.TcbPceSvn[i] = int(level.Tcb.PceSvn)

		for j := 0; j < circuit.MaxSgxComponents; j++ {
			if j < len(level.Tcb.SgxComponents) {
				c.TcbSgxComps[i][j] = int(level.Tcb.SgxComponents[j].Svn)
			} else {
				c.TcbSgxComps[i][j] = 0
			}
		}
		for j := 0; j < circuit.MaxTdxComponents; j++ {
			if j < len(level.Tcb.TdxComponents) {
				c.TcbTdxComps[i][j] = int(level.Tcb.TdxComponents[j].Svn)
			} else {
				c.TcbTdxComps[i][j] = 0
			}
		}

		sev, ok := TcbStatusSeverity[level.TcbStatus]
		if !ok {
			return nil, fmt.Errorf("unknown TCB status: %s", level.TcbStatus)
		}
		c.TcbSeverity[i] = sev

		if tcbMatchIdx == -1 && matchesPlatformTcb(preVerified, q, &level) {
			tcbMatchIdx = i
		}
	}
	for i := len(preVerified.TcbInfo.TcbLevels); i < circuit.MaxTcbLevels; i++ {
		c.TcbPceSvn[i] = 0
		for j := 0; j < circuit.MaxSgxComponents; j++ {
			c.TcbSgxComps[i][j] = 0
		}
		for j := 0; j < circuit.MaxTdxComponents; j++ {
			c.TcbTdxComps[i][j] = 0
		}
		c.TcbSeverity[i] = 0
	}

	tcbCount := len(preVerified.TcbInfo.TcbLevels)
	if tcbCount > circuit.MaxTcbLevels {
		tcbCount = circuit.MaxTcbLevels
	}
	c.TcbLevelCount = tcbCount

	if tcbMatchIdx < 0 {
		return nil, fmt.Errorf("no matching platform TCB level")
	}
	c.TcbMatchIdx = tcbMatchIdx

	// --- Compute final TcbStatus ---
	platformSev := c.TcbSeverity[tcbMatchIdx].(int)
	qeSev := c.QeIdTcbSeverity[qeMatchIdx].(int)
	finalSev := platformSev
	if qeSev > platformSev {
		finalSev = qeSev
	}
	c.TcbStatus = finalSev

	return c, nil
}

// matchesPlatformTcb checks if a TCB level matches the platform's values.
func matchesPlatformTcb(pre *PreVerifiedInputs, q *ParsedQuote, level *TcbLevel) bool {
	if pre.PceSvn < level.Tcb.PceSvn {
		return false
	}
	for i, comp := range level.Tcb.SgxComponents {
		if i < 16 && pre.CpuSvn[i] < comp.Svn {
			return false
		}
	}
	for i, comp := range level.Tcb.TdxComponents {
		if i < 16 && q.TeeTcbSvn[i] < comp.Svn {
			return false
		}
	}
	return true
}

// --- Helper functions ---

// copyU8 sets dst[i] = NewU8(src[i]) for min(len(dst), len(src)) elements.
func copyU8(dst []uints.U8, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	for i := 0; i < n; i++ {
		dst[i] = uints.NewU8(src[i])
	}
}

func newP256FpElement(v *big.Int) emulated.Element[circuit.P256Fp] {
	return emulated.ValueOf[circuit.P256Fp](v)
}

func setP256Signature(sig *circuit.ECDSASignature, raw []byte) {
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:64])
	sig.R = emulated.ValueOf[circuit.P256Fr](r)
	sig.S = emulated.ValueOf[circuit.P256Fr](s)
}
