package witness

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/reliqlabs/zkdcap/circuits/dcap-gnark/circuit"
)

// BuildWitness constructs a fully assigned self-anchoring DcapCircuit from a raw
// TDX quote and the Intel collateral bundle (the dcap-qvl collateral.json map:
// pck_certificate_chain, tcb_info[_signature], qe_identity[_signature], and the
// issuer chains). Every chain/collateral byte the circuit hashes, and every
// hinted offset it anchors on, is derived here.
func BuildWitness(quoteBytes []byte, collateral map[string]string, timestamp uint64) (*circuit.DcapCircuit, error) {
	q, err := ParseTDXQuoteV4(quoteBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing quote: %w", err)
	}

	// --- PCK chain: [leaf, Platform CA, Root] ---
	pckChain, err := parsePEMCerts(collateral["pck_certificate_chain"])
	if err != nil {
		return nil, fmt.Errorf("pck chain: %w", err)
	}
	if len(pckChain) < 3 {
		return nil, fmt.Errorf("expected 3 PCK certs, got %d", len(pckChain))
	}
	leaf, platformCA := pckChain[0], pckChain[1]

	// --- TCB-Signing chain: [TCB-Signing, Root] ---
	tcbChain, err := parsePEMCerts(collateral["tcb_info_issuer_chain"])
	if err != nil {
		return nil, fmt.Errorf("tcb-signing chain: %w", err)
	}
	if len(tcbChain) < 1 {
		return nil, fmt.Errorf("empty tcb-signing chain")
	}
	signing := tcbChain[0]

	// --- Raw signed collateral documents ---
	tcbInfoRaw := []byte(collateral["tcb_info"])
	qeIDRaw := []byte(collateral["qe_identity"])

	var tcbInfo TcbInfo
	if err := json.Unmarshal(tcbInfoRaw, &tcbInfo); err != nil {
		return nil, fmt.Errorf("parse tcb_info: %w", err)
	}
	var qeJSON QeIdentityJSON
	if err := json.Unmarshal(qeIDRaw, &qeJSON); err != nil {
		return nil, fmt.Errorf("parse qe_identity: %w", err)
	}
	qeParsed, err := ParseQeIdentity(&qeJSON)
	if err != nil {
		return nil, fmt.Errorf("parse qe_identity fields: %w", err)
	}

	// --- SGX extensions from the PCK leaf (platform CPU/PCE SVN + FMSPC) ---
	cpuSvn, pceSvn, fmspc, _, err := extractSgxExtensions(leaf)
	if err != nil {
		return nil, fmt.Errorf("sgx extensions: %w", err)
	}

	pckPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pckPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("PCK leaf is not a P-256 ECDSA key")
	}

	c := &circuit.DcapCircuit{}

	// === Public measurement inputs (bound from the signed quote) ===
	copyU8(c.MrTd[:], q.MrTd[:])
	copyU8(c.Rtmr0[:], q.Rtmr0[:])
	copyU8(c.Rtmr1[:], q.Rtmr1[:])
	copyU8(c.Rtmr2[:], q.Rtmr2[:])
	copyU8(c.Rtmr3[:], q.Rtmr3[:])
	copyU8(c.ReportData[:], q.ReportData[:])
	// G4: the circuit interprets Timestamp as a packed YYYYMMDDhhmmss integer so
	// it can be compared against the collateral's ISO-8601 issueDate/nextUpdate
	// without in-circuit calendar arithmetic. Convert the unix-seconds input.
	c.Timestamp = packTimestamp(timestamp)

	// === Public self-anchoring outputs: serial + FMSPC ===
	copyU8(c.CertSerial[:], canonicalSerial(leaf.SerialNumber))
	copyU8(c.Fmspc[:], fmspc[:])

	// === Quote (steps 4-10) ===
	copyU8(c.SignedQuote[:], q.SignedData)
	copyU8(c.QeReport[:], q.QeReport[:])
	c.PckPubKey.X = newP256FpElement(pckPub.X)
	c.PckPubKey.Y = newP256FpElement(pckPub.Y)
	setP256Signature(&c.QeReportSig, q.QeReportSignature[:])
	setP256Signature(&c.IsvSig, q.EcdsaSignature[:])
	copyU8(c.AttestKeyRaw[:], q.AttestationKey[:])
	c.AttestKeyPub.X = newP256FpElement(new(big.Int).SetBytes(q.AttestationKey[:32]))
	c.AttestKeyPub.Y = newP256FpElement(new(big.Int).SetBytes(q.AttestationKey[32:64]))
	qeAuth := make([]byte, 32)
	copy(qeAuth, q.QeAuthData)
	copyU8(c.QeAuthData[:], qeAuth)
	c.QeAuthDataLen = len(q.QeAuthData)

	// === PCK chain (A1) ===
	leafTBS := leaf.RawTBSCertificate
	intTBS := platformCA.RawTBSCertificate
	copyU8(c.LeafTBS[:], leafTBS)
	c.LeafTBSLen = len(leafTBS)
	copyU8(c.IntTBS[:], intTBS)
	c.IntTBSLen = len(intTBS)
	setDERSignature(&c.LeafSig, leaf.Signature)
	setDERSignature(&c.IntSig, platformCA.Signature)
	c.LeafPubKeyOff = mustIndex(leafTBS, circuit.SubjectPubKeyCtx, "leaf subjectPubKey")
	c.IntPubKeyOff = mustIndex(intTBS, circuit.SubjectPubKeyCtx, "intermediate subjectPubKey")
	c.LeafFmspcOff = mustIndex(leafTBS, circuit.FmspcCtx, "leaf FMSPC")
	c.LeafSerialOff = mustIndex(leafTBS, circuit.CertVersionSerialCtx, "leaf version/serial")

	// === Collateral (A2) ===
	signTBS := signing.RawTBSCertificate
	copyU8(c.SignTBS[:], signTBS)
	c.SignLen = len(signTBS)
	setDERSignature(&c.SignSig, signing.Signature)
	c.SignPubOff = mustIndex(signTBS, circuit.SubjectPubKeyCtx, "tcb-signing subjectPubKey")
	c.SignValidityOff = mustIndex(signTBS, circuit.CertValidityCtx, "tcb-signing validity") // H3
	// copyU8 silently truncates a too-large src (it iterates dst), which would
	// make the in-circuit SHA cover only the truncated prefix. Guard the
	// capacity-tightened blobs so an oversized document errors loudly instead.
	if len(tcbInfoRaw) > len(c.TcbInfoRaw) {
		return nil, fmt.Errorf("tcb_info %d bytes exceeds cap %d", len(tcbInfoRaw), len(c.TcbInfoRaw))
	}
	copyU8(c.TcbInfoRaw[:], tcbInfoRaw)
	c.TcbInfoRawLen = len(tcbInfoRaw)
	if err := setRawSignature(&c.TcbInfoSig, collateral["tcb_info_signature"]); err != nil {
		return nil, fmt.Errorf("tcb_info_signature: %w", err)
	}
	c.TcbInfoFmspcOff = mustIndex(tcbInfoRaw, circuit.TcbInfoFmspcCtx, "tcb_info fmspc")
	if len(qeIDRaw) > len(c.QeIDRaw) {
		return nil, fmt.Errorf("qe_identity %d bytes exceeds cap %d", len(qeIDRaw), len(c.QeIDRaw))
	}
	copyU8(c.QeIDRaw[:], qeIDRaw)
	c.QeIDRawLen = len(qeIDRaw)
	if err := setRawSignature(&c.QeIDSig, collateral["qe_identity_signature"]); err != nil {
		return nil, fmt.Errorf("qe_identity_signature: %w", err)
	}

	// === G2 offset hints: TCB-Info JSON level/component anchors ===
	if err := fillTcbInfoOffsets(c, tcbInfoRaw, len(tcbInfo.TcbLevels)); err != nil {
		return nil, fmt.Errorf("tcb_info offsets: %w", err)
	}
	// === G2 offset hints: QE-Identity JSON anchors ===
	if err := fillQeIdOffsets(c, qeIDRaw, len(qeParsed.TcbLevels)); err != nil {
		return nil, fmt.Errorf("qe_identity offsets: %w", err)
	}
	// === G2 offset hints: PCK leaf CPUSVN / PCESVN OID anchors ===
	c.LeafCpuSvnOff = mustIndex(leafTBS, circuit.CpuSvnCtx, "leaf cpusvn")
	c.LeafPceSvnOff = mustIndex(leafTBS, circuit.PceSvnCtx, "leaf pcesvn")
	// === H3: PCK leaf X.509 Validity anchor ===
	c.LeafValidityOff = mustIndex(leafTBS, circuit.CertValidityCtx, "leaf validity")

	// === G4 freshness: validity-window date offsets ===
	c.TcbIssueDateOff = mustIndex(tcbInfoRaw, []byte(`"issueDate":"`), "tcb issueDate")
	c.TcbNextUpdateOff = mustIndex(tcbInfoRaw, []byte(`"nextUpdate":"`), "tcb nextUpdate")
	c.QeIssueDateOff = mustIndex(qeIDRaw, []byte(`"issueDate":"`), "qe issueDate")
	c.QeNextUpdateOff = mustIndex(qeIDRaw, []byte(`"nextUpdate":"`), "qe nextUpdate")

	// === G4 revocation: intermediate serial offset + CRL blobs ===
	c.IntSerialOff = mustIndex(intTBS, circuit.CertVersionSerialCtx, "intermediate version/serial")
	c.IntValidityOff = mustIndex(intTBS, circuit.CertValidityCtx, "intermediate validity") // H3
	pckCrl, rootCrl, err := fillCrls(c, collateral)
	if err != nil {
		return nil, fmt.Errorf("crls: %w", err)
	}

	// === #2 tcbEvaluationDataNumber: offsets + min across both signed blobs ===
	evalCtx := []byte(`"tcbEvaluationDataNumber":`)
	c.TcbEvalOff = mustIndex(tcbInfoRaw, evalCtx, "tcb eval number")
	c.QeEvalOff = mustIndex(qeIDRaw, evalCtx, "qe eval number")
	evalNum := tcbInfo.TcbEvaluationDataNumber
	if qeJSON.TcbEvaluationDataNumber < evalNum {
		evalNum = qeJSON.TcbEvaluationDataNumber
	}
	c.TcbEvalNum = evalNum

	// === #3 intersected collateral validity window [ValidFrom, ValidUntil] ===
	validFrom, validUntil, err := collateralValidityWindow(leaf, platformCA, signing, &tcbInfo, &qeJSON, pckCrl, rootCrl)
	if err != nil {
		return nil, fmt.Errorf("validity window: %w", err)
	}
	c.ValidFrom = validFrom
	c.ValidUntil = validUntil

	// === QE Identity policy ===
	copyU8(c.QeIdMrSigner[:], qeParsed.MrSigner[:])
	c.QeIdIsvProdId = int(qeParsed.IsvProdID)
	copyU8(c.QeIdMiscSelect[:], qeParsed.MiscSelect[:])
	copyU8(c.QeIdMiscMask[:], qeParsed.MiscSelectMask[:])
	copyU8(c.QeIdAttributes[:], qeParsed.Attributes[:])
	copyU8(c.QeIdAttrMask[:], qeParsed.AttributesMask[:])

	// === QE TCB levels ===
	qeIsvSvnVal := uint16(q.QeReport[258]) | uint16(q.QeReport[259])<<8
	qeMatchIdx := -1
	for i, level := range qeParsed.TcbLevels {
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
	// Padding QE levels mirror the last real level (the offsets point there).
	qeLast := len(qeParsed.TcbLevels) - 1
	if qeLast >= circuit.MaxQeTcbLevels {
		qeLast = circuit.MaxQeTcbLevels - 1
	}
	for i := len(qeParsed.TcbLevels); i < circuit.MaxQeTcbLevels; i++ {
		c.QeIdTcbIsvSvn[i] = c.QeIdTcbIsvSvn[qeLast]
		c.QeIdTcbSeverity[i] = c.QeIdTcbSeverity[qeLast]
	}
	c.QeIdTcbCount = len(qeParsed.TcbLevels)
	if qeMatchIdx < 0 {
		return nil, fmt.Errorf("no matching QE TCB level (isv_svn=%d)", qeIsvSvnVal)
	}
	c.QeTcbMatchIdx = qeMatchIdx

	// === Platform TCB ===
	copyU8(c.PlatformCpuSvn[:], cpuSvn[:])
	c.PlatformPceSvn = int(pceSvn)
	copyU8(c.PlatformTeeTcbSvn[:], q.TeeTcbSvn[:])

	tcbMatchIdx := -1
	for i, level := range tcbInfo.TcbLevels {
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
		if tcbMatchIdx == -1 && matchesPlatformTcb(cpuSvn, pceSvn, q.TeeTcbSvn, &level) {
			tcbMatchIdx = i
		}
	}
	// Padding slots mirror the LAST real level: the G2 binding points padding
	// offsets at the last real level in the signed JSON, so the padded witness
	// values must equal that level's values for the in-circuit equality to hold.
	// step8/step9-10 only read levels < the derived count, so this never changes
	// the verdict.
	tcbCount := len(tcbInfo.TcbLevels)
	if tcbCount > circuit.MaxTcbLevels {
		tcbCount = circuit.MaxTcbLevels
	}
	last := tcbCount - 1
	for i := tcbCount; i < circuit.MaxTcbLevels; i++ {
		c.TcbPceSvn[i] = c.TcbPceSvn[last]
		for j := 0; j < circuit.MaxSgxComponents; j++ {
			c.TcbSgxComps[i][j] = c.TcbSgxComps[last][j]
		}
		for j := 0; j < circuit.MaxTdxComponents; j++ {
			c.TcbTdxComps[i][j] = c.TcbTdxComps[last][j]
		}
		c.TcbSeverity[i] = c.TcbSeverity[last]
	}
	c.TcbLevelCount = tcbCount
	if tcbMatchIdx < 0 {
		return nil, fmt.Errorf("no matching platform TCB level")
	}
	c.TcbMatchIdx = tcbMatchIdx

	// === Final TcbStatus = max(platform, QE) severity ===
	platformSev := c.TcbSeverity[tcbMatchIdx].(int)
	qeSev := c.QeIdTcbSeverity[qeMatchIdx].(int)
	finalSev := platformSev
	if qeSev > platformSev {
		finalSev = qeSev
	}
	c.TcbStatus = finalSev

	return c, nil
}

// fillTcbInfoOffsets computes every host-side byte offset the G2 in-circuit
// binding anchors on inside the Intel-signed TCB-Info JSON. It locates the
// top-level "tcbLevels" array, each level object, and within each level the
// component arrays, per-component {"svn": positions, pcesvn, and tcbStatus.
//
// Padding slots (beyond the real level count) repeat the last real level's
// offsets so the in-circuit anchors still hold; the per-slot binding is gated
// by the derived active flag (see deriveAndBindTcbLevels).
func fillTcbInfoOffsets(c *circuit.DcapCircuit, raw []byte, nLevels int) error {
	// Top-level tcbLevels array: the LAST "tcbLevels":[ occurrence is the
	// top-level one (the nested ones inside tdxModuleIdentities come earlier).
	levelsOff := bytes.LastIndex(raw, circuit.JsonTcbLevels)
	if levelsOff < 0 {
		return fmt.Errorf("top-level tcbLevels not found")
	}
	c.TcbLevelsOff = levelsOff

	// Level object starts: each begins with jsonLevelCtx
	// ({"tcb":{"sgxtcbcomponents":). They appear only at the top level.
	var lvlStarts []int
	search := levelsOff
	for {
		idx := bytes.Index(raw[search:], circuit.JsonLevelCtx)
		if idx < 0 {
			break
		}
		lvlStarts = append(lvlStarts, search+idx)
		search += idx + len(circuit.JsonLevelCtx)
	}
	if len(lvlStarts) < nLevels {
		return fmt.Errorf("found %d level starts, expected %d", len(lvlStarts), nLevels)
	}

	clampN := nLevels
	if clampN > circuit.MaxTcbLevels {
		clampN = circuit.MaxTcbLevels
	}
	// Slots 1..MaxTcbLevels-1 carry an explicit start offset; slot 0 is pinned
	// in-circuit. Real slots get their real start; padding repeats the last real.
	lastReal := lvlStarts[clampN-1]
	for i := 1; i < circuit.MaxTcbLevels; i++ {
		if i < clampN {
			c.TcbLvlStartOff[i-1] = lvlStarts[i]
		} else {
			c.TcbLvlStartOff[i-1] = lastReal
		}
	}

	// Per-level field offsets.
	for i := 0; i < circuit.MaxTcbLevels; i++ {
		src := i
		if src >= clampN {
			src = clampN - 1 // padding repeats the last real level
		}
		start := lvlStarts[src]
		// Level extent: up to the next level start (or end of buffer).
		end := len(raw)
		if src+1 < len(lvlStarts) {
			end = lvlStarts[src+1]
		}
		seg := raw[start:end]
		if err := fillLevelOffsets(&c.TcbLvlOff[i], raw, start, seg); err != nil {
			return fmt.Errorf("level %d: %w", i, err)
		}
	}
	return nil
}

// fillLevelOffsets populates one level's component/pcesvn/status offsets.
// `base` is the absolute offset of the level object; `seg` is raw[base:end].
func fillLevelOffsets(h *circuit.TcbLevelOff, raw []byte, base int, seg []byte) error {
	sgxArr := bytes.Index(seg, circuit.JsonSgxArrCtx)
	tdxArr := bytes.Index(seg, circuit.JsonTdxArrCtx)
	pce := bytes.Index(seg, circuit.JsonPceSvnCtx)
	status := bytes.Index(seg, circuit.JsonStatusCtx)
	if sgxArr < 0 || tdxArr < 0 || pce < 0 || status < 0 {
		return fmt.Errorf("missing component/pcesvn/status anchor")
	}
	h.TdxArrOff = base + tdxArr
	h.PceSvnOff = base + pce
	h.StatusOff = base + status
	// SgxArrOff is derived in-circuit from the level start; we do not set it.

	// Per-component {"svn": offsets. The sgx array spans [sgxArr, pce); the tdx
	// array spans [tdxArr, status). Component 0 is pinned in-circuit, so we only
	// record components 1..15.
	sgxOffs := findComponentStarts(seg[sgxArr:pce], base+sgxArr)
	tdxOffs := findComponentStarts(seg[tdxArr:status], base+tdxArr)
	if len(sgxOffs) != 16 || len(tdxOffs) != 16 {
		return fmt.Errorf("expected 16 sgx/tdx components, got %d/%d", len(sgxOffs), len(tdxOffs))
	}
	for k := 0; k < 15; k++ {
		h.SgxSvnOff[k] = sgxOffs[k+1]
		h.TdxSvnOff[k] = tdxOffs[k+1]
	}
	return nil
}

// findComponentStarts returns the absolute offsets of every {"svn": component
// object start within `region` (offset by `base`).
func findComponentStarts(region []byte, base int) []int {
	var offs []int
	search := 0
	for {
		idx := bytes.Index(region[search:], circuit.JsonSvnCtx)
		if idx < 0 {
			break
		}
		offs = append(offs, base+search+idx)
		search += idx + len(circuit.JsonSvnCtx)
	}
	return offs
}

// fillQeIdOffsets computes the QE-Identity JSON anchor offsets.
func fillQeIdOffsets(c *circuit.DcapCircuit, raw []byte, nLevels int) error {
	idx := func(lit string, what string) (int, error) {
		i := bytes.Index(raw, []byte(lit))
		if i < 0 {
			return 0, fmt.Errorf("qe_identity anchor %q (%s) not found", lit, what)
		}
		return i, nil
	}
	var err error
	if c.QeIdOff.MrSignerOff, err = idx(`"mrsigner":"`, "mrsigner"); err != nil {
		return err
	}
	if c.QeIdOff.IsvProdIdOff, err = idx(`"isvprodid":`, "isvprodid"); err != nil {
		return err
	}
	if c.QeIdOff.MiscSelectOff, err = idx(`"miscselect":"`, "miscselect"); err != nil {
		return err
	}
	if c.QeIdOff.MiscMaskOff, err = idx(`"miscselectMask":"`, "miscselectMask"); err != nil {
		return err
	}
	if c.QeIdOff.AttrOff, err = idx(`"attributes":"`, "attributes"); err != nil {
		return err
	}
	if c.QeIdOff.AttrMaskOff, err = idx(`"attributesMask":"`, "attributesMask"); err != nil {
		return err
	}

	// QE TCB level objects: {"tcb":{"isvsvn": and the following tcbStatus.
	isvCtx := []byte(`{"tcb":{"isvsvn":`)
	var lvlOffs []int
	search := 0
	for {
		i := bytes.Index(raw[search:], isvCtx)
		if i < 0 {
			break
		}
		lvlOffs = append(lvlOffs, search+i)
		search += i + len(isvCtx)
	}
	if len(lvlOffs) < nLevels {
		return fmt.Errorf("found %d QE levels, expected %d", len(lvlOffs), nLevels)
	}
	clampN := nLevels
	if clampN > circuit.MaxQeTcbLevels {
		clampN = circuit.MaxQeTcbLevels
	}
	for k := 0; k < circuit.MaxQeTcbLevels; k++ {
		src := k
		if src >= clampN {
			src = clampN - 1
		}
		c.QeIdOff.QeLvlOff[k] = lvlOffs[src]
		// status for this level: first "tcbStatus":" at or after the level start.
		end := len(raw)
		if src+1 < len(lvlOffs) {
			end = lvlOffs[src+1]
		}
		st := bytes.Index(raw[lvlOffs[src]:end], circuit.JsonStatusCtx)
		if st < 0 {
			return fmt.Errorf("qe level %d status not found", src)
		}
		c.QeIdOff.QeStatusOff[k] = lvlOffs[src] + st
	}
	return nil
}

// packTimestamp converts unix seconds (UTC) to the packed YYYYMMDDhhmmss integer
// the circuit compares against the collateral validity window.
func packTimestamp(unix uint64) uint64 {
	return packTime(time.Unix(int64(unix), 0))
}

// packTime packs a time.Time (UTC) into the same YYYYMMDDhhmmss integer the
// circuit derives from UTCTime / ISO-8601 dates (parseUtcTime / parseIso8601).
func packTime(t time.Time) uint64 {
	t = t.UTC()
	return uint64(t.Year())*10000000000 +
		uint64(t.Month())*100000000 +
		uint64(t.Day())*1000000 +
		uint64(t.Hour())*10000 +
		uint64(t.Minute())*100 +
		uint64(t.Second())
}

// packISODate parses an Intel ISO-8601 collateral date ("YYYY-MM-DDThh:mm:ssZ")
// and packs it to the same integer space.
func packISODate(s string) (uint64, error) {
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err != nil {
		return 0, fmt.Errorf("parse date %q: %w", s, err)
	}
	return packTime(t), nil
}

// collateralValidityWindow computes the intersected validity window
// [ValidFrom, ValidUntil] = [max(lower bounds), min(upper bounds)] across every
// signed collateral object (#3), packed YYYYMMDDhhmmss. Each bound is exactly the
// value the circuit derives in-circuit, so the prover-supplied public outputs
// match the circuit's computed fold.
func collateralValidityWindow(leaf, platformCA, signing *x509.Certificate, tcbInfo *TcbInfo, qeJSON *QeIdentityJSON, pckCrl, rootCrl *x509.RevocationList) (uint64, uint64, error) {
	tcbIssue, err := packISODate(tcbInfo.IssueDate)
	if err != nil {
		return 0, 0, err
	}
	tcbNext, err := packISODate(tcbInfo.NextUpdate)
	if err != nil {
		return 0, 0, err
	}
	qeIssue, err := packISODate(qeJSON.IssueDate)
	if err != nil {
		return 0, 0, err
	}
	qeNext, err := packISODate(qeJSON.NextUpdate)
	if err != nil {
		return 0, 0, err
	}
	lowers := []uint64{
		packTime(leaf.NotBefore), packTime(platformCA.NotBefore), packTime(signing.NotBefore),
		tcbIssue, qeIssue,
		packTime(pckCrl.ThisUpdate), packTime(rootCrl.ThisUpdate),
	}
	uppers := []uint64{
		packTime(leaf.NotAfter), packTime(platformCA.NotAfter), packTime(signing.NotAfter),
		tcbNext, qeNext,
		packTime(pckCrl.NextUpdate), packTime(rootCrl.NextUpdate),
	}
	validFrom := lowers[0]
	for _, v := range lowers[1:] {
		if v > validFrom {
			validFrom = v
		}
	}
	validUntil := uppers[0]
	for _, v := range uppers[1:] {
		if v < validUntil {
			validUntil = v
		}
	}
	if validFrom > validUntil {
		return 0, 0, fmt.Errorf("empty collateral validity intersection [%d, %d]", validFrom, validUntil)
	}
	return validFrom, validUntil, nil
}

// fillCrls populates the PCK CRL (Platform-CA-signed) and Root CA CRL
// (Root-signed) TBS bytes and signatures used by the G4 revocation check. It
// returns the parsed CRLs so the caller can fold their validity windows into the
// intersected collateral window (#3).
func fillCrls(c *circuit.DcapCircuit, coll map[string]string) (*x509.RevocationList, *x509.RevocationList, error) {
	pckCrl, err := parseCrlHex(coll["pck_crl"])
	if err != nil {
		return nil, nil, fmt.Errorf("pck_crl: %w", err)
	}
	rootCrl, err := parseCrlHex(coll["root_ca_crl"])
	if err != nil {
		return nil, nil, fmt.Errorf("root_ca_crl: %w", err)
	}
	if len(pckCrl.RawTBSRevocationList) > len(c.PckCrlTBS) {
		return nil, nil, fmt.Errorf("pck crl tbs %d exceeds cap %d", len(pckCrl.RawTBSRevocationList), len(c.PckCrlTBS))
	}
	if len(rootCrl.RawTBSRevocationList) > len(c.RootCrlTBS) {
		return nil, nil, fmt.Errorf("root crl tbs %d exceeds cap %d", len(rootCrl.RawTBSRevocationList), len(c.RootCrlTBS))
	}
	copyU8(c.PckCrlTBS[:], pckCrl.RawTBSRevocationList)
	c.PckCrlTBSLen = len(pckCrl.RawTBSRevocationList)
	setDERSignature(&c.PckCrlSig, pckCrl.Signature)
	c.PckCrlThisUpdateOff = firstUtcTimeOffset(pckCrl.RawTBSRevocationList)
	copyU8(c.RootCrlTBS[:], rootCrl.RawTBSRevocationList)
	c.RootCrlTBSLen = len(rootCrl.RawTBSRevocationList)
	setDERSignature(&c.RootCrlSig, rootCrl.Signature)
	c.RootCrlThisUpdateOff = firstUtcTimeOffset(rootCrl.RawTBSRevocationList)
	return pckCrl, rootCrl, nil
}

// firstUtcTimeOffset returns the offset of the first DER UTCTime (`17 0d`) in a
// CRL tbsCertList, which is thisUpdate (the header has no earlier UTCTime). The
// circuit re-asserts this as the first UTCTime, so a wrong hint is rejected.
func firstUtcTimeOffset(tbs []byte) int {
	idx := bytes.Index(tbs, []byte{0x17, 0x0d})
	if idx < 0 {
		panic("CRL thisUpdate UTCTime not found")
	}
	return idx
}

func parseCrlHex(hexStr string) (*x509.RevocationList, error) {
	der, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(der)
}

// matchesPlatformTcb reports whether a TCB level is satisfied by the platform's
// SVN values (all platform components >= the level's thresholds).
func matchesPlatformTcb(cpuSvn [16]byte, pceSvn uint16, teeTcbSvn [16]byte, level *TcbLevel) bool {
	if pceSvn < level.Tcb.PceSvn {
		return false
	}
	for i, comp := range level.Tcb.SgxComponents {
		if i < 16 && cpuSvn[i] < comp.Svn {
			return false
		}
	}
	for i, comp := range level.Tcb.TdxComponents {
		if i < 16 && teeTcbSvn[i] < comp.Svn {
			return false
		}
	}
	return true
}

// --- Helper functions ---

func parsePEMCerts(pemStr string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(pemStr)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificates found")
	}
	return certs, nil
}

// canonicalSerial returns the 20-byte big-endian serial (left-padded), matching
// the in-circuit extractCertSerial output.
func canonicalSerial(n *big.Int) []byte {
	raw := n.Bytes()
	out := make([]byte, 20)
	if len(raw) > 20 {
		raw = raw[len(raw)-20:]
	}
	copy(out[20-len(raw):], raw)
	return out
}

func mustIndex(buf []byte, ctx []byte, what string) int {
	idx := bytes.Index(buf, ctx)
	if idx < 0 {
		panic(fmt.Sprintf("anchor for %s not found in buffer", what))
	}
	return idx
}

// copyU8 fills all of dst: dst[i] = NewU8(src[i]) where src has data, and
// NewU8(0) for the remaining (padding) bytes. Every element must be assigned
// or the gnark witness parser reports a missing assignment.
func copyU8(dst []uints.U8, src []byte) {
	for i := range dst {
		if i < len(src) {
			dst[i] = uints.NewU8(src[i])
		} else {
			dst[i] = uints.NewU8(0)
		}
	}
}

func newP256FpElement(v *big.Int) emulated.Element[circuit.P256Fp] {
	return emulated.ValueOf[circuit.P256Fp](v)
}

func setP256Signature(sig *circuit.ECDSASignature, raw []byte) {
	sig.R = emulated.ValueOf[circuit.P256Fr](new(big.Int).SetBytes(raw[:32]))
	sig.S = emulated.ValueOf[circuit.P256Fr](new(big.Int).SetBytes(raw[32:64]))
}

// setDERSignature assigns an ECDSA signature parsed from its ASN.1 DER encoding
// (how x509 stores cert/CRL signatures).
func setDERSignature(sig *circuit.ECDSASignature, der []byte) {
	var s struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &s); err != nil {
		panic(fmt.Sprintf("der signature: %v", err))
	}
	sig.R = emulated.ValueOf[circuit.P256Fr](s.R)
	sig.S = emulated.ValueOf[circuit.P256Fr](s.S)
}

// setRawSignature assigns an ECDSA signature from a 64-byte raw r||s hex string
// (how Intel encodes the TCB-Info / QE-Identity signatures).
func setRawSignature(sig *circuit.ECDSASignature, hexStr string) error {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}
	if len(b) != 64 {
		return fmt.Errorf("expected 64-byte raw signature, got %d", len(b))
	}
	sig.R = emulated.ValueOf[circuit.P256Fr](new(big.Int).SetBytes(b[:32]))
	sig.S = emulated.ValueOf[circuit.P256Fr](new(big.Int).SetBytes(b[32:64]))
	return nil
}
