// genprover parses the REAL dcap-qvl fixture (a TDX v4 quote + Intel collateral
// bundle) into the Noir Prover.toml the secure DCAP circuit expects: every chain
// / collateral byte the circuit hashes, every hinted offset it anchors on, the
// per-level TCB-Info / QE-Identity threshold values, the match indices, and the
// packed verification timestamp. Mirrors dcap-gnark/witness/builder.go.
//
// Usage:
//   go run genprover.go -quote ../../dcap-gnark/testdata/fixtures/zkdcap/quote.bin \
//       -collateral ../../dcap-gnark/testdata/fixtures/zkdcap/collateral.json \
//       -timestamp 1750000000 > ../crates/dcap/Prover.toml
//
// Flags allow surgical mutation for negative tests (see -mutate).
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// ---- circuit capacities (must match crates/dcap/src/main.nr + tcb.nr) ----
const (
	leafTBSCap  = 1280
	intTBSCap   = 640
	signTBSCap  = 640
	tcbInfoCap  = 3072
	qeIDCap     = 512
	pckCrlCap   = 3072
	rootCrlCap  = 512
	qeAuthCap   = 32
	qeReportLen = 384
	signedQLen  = 632

	maxTcbLevels     = 16
	maxSgxComponents = 16
	maxTdxComponents = 16
	maxQeTcbLevels   = 8
)

var tcbStatusSeverity = map[string]int{
	"UpToDate":                          0,
	"SWHardeningNeeded":                 1,
	"ConfigurationNeeded":               2,
	"ConfigurationAndSWHardeningNeeded": 3,
	"OutOfDate":                         4,
	"OutOfDateConfigurationNeeded":      5,
	"Revoked":                           6,
}

// ---- anchors (must match crates/dcap globals) ----
var (
	subjectPubKeyCtx     = []byte{0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}
	fmspcCtx             = []byte{0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04, 0x04, 0x06}
	certVersionSerialCtx = []byte{0xa0, 0x03, 0x02, 0x01, 0x02, 0x02}
	cpuSvnCtx            = []byte{0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x12, 0x04, 0x10}
	pceSvnCtx            = []byte{0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x11, 0x02}
	certValidityCtx      = []byte{0x30, 0x1e, 0x17, 0x0d} // Validity SEQUENCE + notBefore UTCTime tag

	tcbInfoFmspcCtx = []byte(`"fmspc":"`)
	jsonTcbLevels   = []byte(`"tcbLevels":[`)
	jsonLevelCtx    = []byte(`{"tcb":{"sgxtcbcomponents":`)
	jsonSgxArrCtx   = []byte(`"sgxtcbcomponents":[`)
	jsonTdxArrCtx   = []byte(`"tdxtcbcomponents":[`)
	jsonSvnCtx      = []byte(`{"svn":`)
	jsonPceSvnCtx   = []byte(`"pcesvn":`)
	jsonStatusCtx   = []byte(`"tcbStatus":"`)
	jsonQeLvlCtx    = []byte(`{"tcb":{"isvsvn":`)
	issueDateCtx    = []byte(`"issueDate":"`)
	nextUpdateCtx   = []byte(`"nextUpdate":"`)
	evalNumberCtx   = []byte(`"tcbEvaluationDataNumber":`)

	mrSignerCtx   = []byte(`"mrsigner":"`)
	isvProdIDCtx  = []byte(`"isvprodid":`)
	miscSelectCtx = []byte(`"miscselect":"`)
	miscMaskCtx   = []byte(`"miscselectMask":"`)
	attrCtx       = []byte(`"attributes":"`)
	attrMaskCtx   = []byte(`"attributesMask":"`)
)

// ---- JSON shapes ----
type tcbComponent struct {
	Svn uint8 `json:"svn"`
}
type tcbInner struct {
	Sgx    []tcbComponent `json:"sgxtcbcomponents"`
	Tdx    []tcbComponent `json:"tdxtcbcomponents"`
	PceSvn uint16         `json:"pcesvn"`
}
type tcbLevel struct {
	Tcb       tcbInner `json:"tcb"`
	TcbStatus string   `json:"tcbStatus"`
}
type tcbInfoDoc struct {
	Fmspc     string     `json:"fmspc"`
	TcbLevels []tcbLevel `json:"tcbLevels"`
}
type qeTcb struct {
	IsvSvn uint16 `json:"isvsvn"`
}
type qeLevel struct {
	Tcb       qeTcb  `json:"tcb"`
	TcbStatus string `json:"tcbStatus"`
}
type qeIDDoc struct {
	MiscSelect     string    `json:"miscselect"`
	MiscSelectMask string    `json:"miscselectMask"`
	Attributes     string    `json:"attributes"`
	AttributesMask string    `json:"attributesMask"`
	MrSigner       string    `json:"mrsigner"`
	IsvProdID      uint16    `json:"isvprodid"`
	TcbLevels      []qeLevel `json:"tcbLevels"`
}

type mutateFlags struct {
	name string
}

func main() {
	quotePath := flag.String("quote", "", "path to quote.bin")
	collPath := flag.String("collateral", "", "path to collateral.json")
	ts := flag.Int64("timestamp", 0, "verification time (unix seconds); 0 = midpoint of TCB-Info validity")
	mutate := flag.String("mutate", "", "negative-test mutation (see source)")
	flag.Parse()
	if *quotePath == "" || *collPath == "" {
		fmt.Fprintln(os.Stderr, "need -quote and -collateral")
		os.Exit(2)
	}
	mf := mutateFlags{name: *mutate}

	quoteBytes, err := os.ReadFile(*quotePath)
	must(err)
	collRaw, err := os.ReadFile(*collPath)
	must(err)
	var coll map[string]string
	must(json.Unmarshal(collRaw, &coll))

	tw := &tomlWriter{}
	if err := build(tw, quoteBytes, coll, *ts, mf); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
	fmt.Print(tw.String())
}

func build(tw *tomlWriter, quoteBytes []byte, coll map[string]string, ts int64, mf mutateFlags) error {
	q, err := parseTDXQuote(quoteBytes)
	if err != nil {
		return fmt.Errorf("quote: %w", err)
	}

	pckChain, err := parsePEM(coll["pck_certificate_chain"])
	if err != nil || len(pckChain) < 3 {
		return fmt.Errorf("pck chain (%d certs): %w", len(pckChain), err)
	}
	leaf, platformCA := pckChain[0], pckChain[1]
	tcbChain, err := parsePEM(coll["tcb_info_issuer_chain"])
	if err != nil || len(tcbChain) < 1 {
		return fmt.Errorf("tcb-signing chain: %w", err)
	}
	signing := tcbChain[0]

	tcbInfoRaw := []byte(coll["tcb_info"])
	qeIDRaw := []byte(coll["qe_identity"])
	var tcbDoc tcbInfoDoc
	must(json.Unmarshal(tcbInfoRaw, &tcbDoc))
	var qeDoc qeIDDoc
	must(json.Unmarshal(qeIDRaw, &qeDoc))

	cpuSvn, pceSvn, fmspc, err := extractSgxExt(leaf)
	if err != nil {
		return fmt.Errorf("sgx ext: %w", err)
	}

	// timestamp: midpoint of TCB-Info validity if not given.
	if ts == 0 {
		issue := parseISO(findStr(tcbInfoRaw, issueDateCtx, 20))
		next := parseISO(findStr(tcbInfoRaw, nextUpdateCtx, 20))
		ts = (issue + next) / 2
	}
	if mf.name == "c5-stale-crl" {
		// push Timestamp a year past the collateral/CRL nextUpdate so the freshness
		// window (Timestamp <= nextUpdate) rejects the replayed stale CRL/collateral.
		next := parseISO(findStr(tcbInfoRaw, nextUpdateCtx, 20))
		ts = next + 365*24*3600
	}
	if mf.name == "expired-cert" {
		// 2033-06-01: past the leaf PCK cert notAfter (2032) but before the
		// intermediate/root notAfter, so check_cert_validity (which runs before the
		// collateral freshness check) rejects with "cert expired". H3/G-1.
		ts = parseISO("2033-06-01T00:00:00Z")
	}
	packedTS := packTimestamp(uint64(ts))

	leafTBS := leaf.RawTBSCertificate
	intTBS := platformCA.RawTBSCertificate
	signTBS := signing.RawTBSCertificate

	// ---- pinned Intel SGX Root CA key (witness, pinned in-circuit) ----
	rootX, _ := hex.DecodeString("0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5")
	rootY, _ := hex.DecodeString("67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394")
	if mf.name == "root-pin" {
		// supply a WRONG root key witness; chain::pin_root must reject it. Guards the
		// bb-4.0.4 assert-pinned-root workaround.
		rootX[0] ^= 0x01
	}
	tw.bytes("root_x", rootX)
	tw.bytes("root_y", rootY)

	// ---- A1 ----
	tw.bytes("leaf_tbs", pad(leafTBS, leafTBSCap))
	tw.num("leaf_len", len(leafTBS))
	tw.bytes("leaf_sig", derSig(leaf.Signature))
	tw.num("leaf_pk_off", mustIdx(leafTBS, subjectPubKeyCtx))
	leafFmspcOff := mustIdx(leafTBS, fmspcCtx)
	if mf.name == "g1-fmspc-off" {
		// plant the FMSPC offset into the unsigned padding tail (>= leaf_len). The
		// G1 bound (off + ctx + len <= signed_len) must reject this.
		leafFmspcOff = len(leafTBS) + 2
	}
	tw.num("leaf_fmspc_off", leafFmspcOff)
	tw.num("leaf_serial_off", mustIdx(leafTBS, certVersionSerialCtx))
	tw.num("leaf_cpu_svn_off", mustIdx(leafTBS, cpuSvnCtx))
	tw.num("leaf_pce_svn_off", mustIdx(leafTBS, pceSvnCtx))
	tw.num("leaf_validity_off", mustIdx(leafTBS, certValidityCtx))
	tw.bytes("int_tbs", pad(intTBS, intTBSCap))
	tw.num("int_len", len(intTBS))
	tw.bytes("int_sig", derSig(platformCA.Signature))
	tw.num("int_pk_off", mustIdx(intTBS, subjectPubKeyCtx))
	tw.num("int_serial_off", mustIdx(intTBS, certVersionSerialCtx))
	tw.num("int_validity_off", mustIdx(intTBS, certValidityCtx))

	// ---- A2 ----
	tw.bytes("sign_tbs", pad(signTBS, signTBSCap))
	tw.num("sign_len", len(signTBS))
	tw.bytes("sign_sig", derSig(signing.Signature))
	tw.num("sign_pk_off", mustIdx(signTBS, subjectPubKeyCtx))
	tw.num("sign_validity_off", mustIdx(signTBS, certValidityCtx))

	if len(tcbInfoRaw) > tcbInfoCap {
		return fmt.Errorf("tcb_info %d exceeds cap %d", len(tcbInfoRaw), tcbInfoCap)
	}
	tw.bytes("tcb_info", pad(tcbInfoRaw, tcbInfoCap))
	tw.num("tcb_info_len", len(tcbInfoRaw))
	tw.bytes("tcb_info_sig", rawSig(coll["tcb_info_signature"]))
	tw.num("tcb_info_fmspc_off", mustIdx(tcbInfoRaw, tcbInfoFmspcCtx))
	tw.num("tcb_levels_off", lastIdx(tcbInfoRaw, jsonTcbLevels))

	if len(qeIDRaw) > qeIDCap {
		return fmt.Errorf("qe_identity %d exceeds cap %d", len(qeIDRaw), qeIDCap)
	}
	tw.bytes("qe_id", pad(qeIDRaw, qeIDCap))
	tw.num("qe_id_len", len(qeIDRaw))
	tw.bytes("qe_id_sig", rawSig(coll["qe_identity_signature"]))

	// freshness offsets
	tw.num("tcb_issue_off", mustIdx(tcbInfoRaw, issueDateCtx))
	tw.num("tcb_next_off", mustIdx(tcbInfoRaw, nextUpdateCtx))
	tw.num("qe_issue_off", mustIdx(qeIDRaw, issueDateCtx))
	tw.num("qe_next_off", mustIdx(qeIDRaw, nextUpdateCtx))
	// tcbEvaluationDataNumber offsets (TCB-recency floor, #2)
	tcbEvalOff := mustIdx(tcbInfoRaw, evalNumberCtx)
	if mf.name == "g1-eval-off" {
		// plant the eval-number offset into the unsigned padding tail (>= tcb_info_len).
		// extract_field's G1 bound (off + ctx + len <= signed_len) must reject it, so a
		// forged eval number cannot be read from outside the signed JSON.
		tcbEvalOff = len(tcbInfoRaw) + 2
	}
	tw.num("tcb_eval_off", tcbEvalOff)
	tw.num("qe_eval_off", mustIdx(qeIDRaw, evalNumberCtx))

	// ---- steps 4-10 ----
	tw.bytes("qe_report", q.QeReport[:])
	tw.bytes("qe_report_sig", lowSRaw(q.QeReportSig[:]))
	tw.bytes("signed_quote", q.SignedData)
	tw.bytes("isv_sig", lowSRaw(q.IsvSig[:]))
	attestX := append([]byte{}, q.AttestKey[:32]...)
	attestY := append([]byte{}, q.AttestKey[32:64]...)
	if mf.name == "g3-attest-key" {
		// substitute a different attestation key. The same (attest_x,attest_y) bytes
		// are hashed into report_data (step 5) AND verify the ISV sig (step 7), so a
		// mismatch breaks the report_data binding (G3) -> reject.
		attestX[0] ^= 0x01
	}
	tw.bytes("attest_x", attestX)
	tw.bytes("attest_y", attestY)
	tw.bytes("qe_auth", pad(q.QeAuth, qeAuthCap))
	tw.num("qe_auth_len", len(q.QeAuth))

	// ---- CRLs ----
	pckCrl, err := parseCRL(coll["pck_crl"])
	if err != nil {
		return fmt.Errorf("pck_crl: %w", err)
	}
	rootCrl, err := parseCRL(coll["root_ca_crl"])
	if err != nil {
		return fmt.Errorf("root_ca_crl: %w", err)
	}
	pckCrlTBS := mutateCRL(pckCrl.RawTBSRevocationList, leaf.RawTBSCertificate, mf)
	if len(pckCrlTBS) > pckCrlCap {
		return fmt.Errorf("pck crl tbs %d exceeds cap %d", len(pckCrlTBS), pckCrlCap)
	}
	tw.bytes("pck_crl_tbs", pad(pckCrlTBS, pckCrlCap))
	tw.num("pck_crl_len", len(pckCrlTBS))
	tw.bytes("pck_crl_sig", derSig(crlSig(pckCrl, leaf, mf)))
	tw.num("pck_crl_thisupd_off", firstUTC(pckCrlTBS))
	if len(rootCrl.RawTBSRevocationList) > rootCrlCap {
		return fmt.Errorf("root crl tbs %d exceeds cap %d", len(rootCrl.RawTBSRevocationList), rootCrlCap)
	}
	tw.bytes("root_crl_tbs", pad(rootCrl.RawTBSRevocationList, rootCrlCap))
	tw.num("root_crl_len", len(rootCrl.RawTBSRevocationList))
	tw.bytes("root_crl_sig", derSig(rootCrl.Signature))
	tw.num("root_crl_thisupd_off", firstUTC(rootCrl.RawTBSRevocationList))

	// ---- measurements / report data / timestamp (PRIVATE witness; the circuit
	// binds them to the signed quote then re-exposes them PACKED as the 17 public
	// output fields, so the on-chain public_inputs fits Xion's 320-field cap). ----
	tw.bytes("mr_td", q.MrTd[:])
	tw.bytes("rtmr0", q.Rtmr0[:])
	tw.bytes("rtmr1", q.Rtmr1[:])
	tw.bytes("rtmr2", q.Rtmr2[:])
	tw.bytes("rtmr3", q.Rtmr3[:])
	tw.bytes("report_data", q.ReportData[:])
	tw.num("timestamp", int(packedTS))
	_ = fmspc

	// ---- TcbBound struct ----
	if err := writeTcbBound(tw, tcbInfoRaw, &tcbDoc, cpuSvn, pceSvn, q.TeeTcbSvn, mf); err != nil {
		return err
	}
	// ---- QeBound struct ----
	if err := writeQeBound(tw, qeIDRaw, &qeDoc, q.QeReport[258], q.QeReport[259], mf); err != nil {
		return err
	}
	return nil
}

// ============================ TcbBound ============================

func writeTcbBound(tw *tomlWriter, raw []byte, doc *tcbInfoDoc, cpuSvn [16]byte, pceSvn uint16, teeSvn [16]byte, mf mutateFlags) error {
	n := len(doc.TcbLevels)
	if n > maxTcbLevels {
		n = maxTcbLevels
	}
	// level starts (top-level level objects)
	levelsOff := bytes.LastIndex(raw, jsonTcbLevels)
	if levelsOff < 0 {
		return fmt.Errorf("top-level tcbLevels not found")
	}
	var lvlStarts []int
	search := levelsOff
	for {
		idx := bytes.Index(raw[search:], jsonLevelCtx)
		if idx < 0 {
			break
		}
		lvlStarts = append(lvlStarts, search+idx)
		search += idx + len(jsonLevelCtx)
	}
	if len(lvlStarts) < n {
		return fmt.Errorf("found %d level starts, expected %d", len(lvlStarts), n)
	}

	// lvl_start hints for slots 1..15 (slot 0 pinned). padding repeats last real.
	lastReal := lvlStarts[n-1]
	lvlStartHints := make([]int, maxTcbLevels-1)
	for i := 1; i < maxTcbLevels; i++ {
		if i < n {
			lvlStartHints[i-1] = lvlStarts[i]
		} else {
			lvlStartHints[i-1] = lastReal
		}
	}

	pceOff := make([]int, maxTcbLevels)
	tdxArrOff := make([]int, maxTcbLevels)
	statusOff := make([]int, maxTcbLevels)
	sgxSvnOff := make([][]int, maxTcbLevels)
	tdxSvnOff := make([][]int, maxTcbLevels)
	pceVal := make([]int, maxTcbLevels)
	sgxComps := make([][]int, maxTcbLevels)
	tdxComps := make([][]int, maxTcbLevels)
	sev := make([]int, maxTcbLevels)

	for i := 0; i < maxTcbLevels; i++ {
		src := i
		if src >= n {
			src = n - 1
		}
		start := lvlStarts[src]
		end := len(raw)
		if src+1 < len(lvlStarts) {
			end = lvlStarts[src+1]
		}
		seg := raw[start:end]
		sgxArr := bytes.Index(seg, jsonSgxArrCtx)
		tdxArr := bytes.Index(seg, jsonTdxArrCtx)
		pce := bytes.Index(seg, jsonPceSvnCtx)
		st := bytes.Index(seg, jsonStatusCtx)
		if sgxArr < 0 || tdxArr < 0 || pce < 0 || st < 0 {
			return fmt.Errorf("level %d missing anchor", i)
		}
		tdxArrOff[i] = start + tdxArr
		pceOff[i] = start + pce
		statusOff[i] = start + st
		sgxStarts := componentStarts(seg[sgxArr:pce], start+sgxArr)
		tdxStarts := componentStarts(seg[tdxArr:st], start+tdxArr)
		if len(sgxStarts) != 16 || len(tdxStarts) != 16 {
			return fmt.Errorf("level %d: %d sgx / %d tdx components", i, len(sgxStarts), len(tdxStarts))
		}
		sgxSvnOff[i] = make([]int, maxSgxComponents-1)
		tdxSvnOff[i] = make([]int, maxTdxComponents-1)
		for k := 0; k < 15; k++ {
			sgxSvnOff[i][k] = sgxStarts[k+1]
			tdxSvnOff[i][k] = tdxStarts[k+1]
		}
		lv := doc.TcbLevels[src]
		pceVal[i] = int(lv.Tcb.PceSvn)
		sgxComps[i] = comps16(lv.Tcb.Sgx)
		tdxComps[i] = comps16(lv.Tcb.Tdx)
		s, ok := tcbStatusSeverity[lv.TcbStatus]
		if !ok {
			return fmt.Errorf("unknown tcb status %q", lv.TcbStatus)
		}
		sev[i] = s
	}

	// match index: canonical first-satisfiable level.
	matchIdx := -1
	for i := 0; i < n; i++ {
		if platformSatisfies(cpuSvn, pceSvn, teeSvn, &doc.TcbLevels[i]) {
			matchIdx = i
			break
		}
	}
	if matchIdx < 0 {
		return fmt.Errorf("no satisfiable platform TCB level")
	}

	// negative mutations on the TcbBound
	levelCount := n
	applyTcbMutation(mf, &matchIdx, &levelCount, statusOff, pceVal, sgxComps, tdxComps, tdxArrOff, lvlStartHints, n)
	n = levelCount

	tw.section("tcb")
	tw.num("level_count", n)
	tw.num("match_idx", matchIdx)
	tw.numArr("lvl_start", lvlStartHints)
	tw.numArr("pce_svn_off", pceOff)
	tw.numArr("tdx_arr_off", tdxArrOff)
	tw.numGrid("sgx_svn_off", sgxSvnOff)
	tw.numGrid("tdx_svn_off", tdxSvnOff)
	tw.numArr("status_off", statusOff)
	tw.numArr("pce_svn", pceVal)
	tw.numGrid("sgx_comps", sgxComps)
	tw.numGrid("tdx_comps", tdxComps)
	tw.numArr("severity", sev)
	return nil
}

// ============================ QeBound ============================

func writeQeBound(tw *tomlWriter, raw []byte, doc *qeIDDoc, isvLo, isvHi byte, mf mutateFlags) error {
	n := len(doc.TcbLevels)
	if n > maxQeTcbLevels {
		n = maxQeTcbLevels
	}
	var lvlOffsAll []int
	search := 0
	for {
		i := bytes.Index(raw[search:], jsonQeLvlCtx)
		if i < 0 {
			break
		}
		lvlOffsAll = append(lvlOffsAll, search+i)
		search += i + len(jsonQeLvlCtx)
	}
	if len(lvlOffsAll) < n {
		return fmt.Errorf("found %d qe levels, expected %d", len(lvlOffsAll), n)
	}

	lvlOff := make([]int, maxQeTcbLevels)
	statusOff := make([]int, maxQeTcbLevels)
	isvsvn := make([]int, maxQeTcbLevels)
	sev := make([]int, maxQeTcbLevels)
	for k := 0; k < maxQeTcbLevels; k++ {
		src := k
		if src >= n {
			src = n - 1
		}
		lvlOff[k] = lvlOffsAll[src]
		end := len(raw)
		if src+1 < len(lvlOffsAll) {
			end = lvlOffsAll[src+1]
		}
		st := bytes.Index(raw[lvlOffsAll[src]:end], jsonStatusCtx)
		if st < 0 {
			return fmt.Errorf("qe level %d status not found", src)
		}
		statusOff[k] = lvlOffsAll[src] + st
		isvsvn[k] = int(doc.TcbLevels[src].Tcb.IsvSvn)
		s, ok := tcbStatusSeverity[doc.TcbLevels[src].TcbStatus]
		if !ok {
			return fmt.Errorf("unknown qe status %q", doc.TcbLevels[src].TcbStatus)
		}
		sev[k] = s
	}

	qeIsv := uint16(isvLo) | uint16(isvHi)<<8
	matchIdx := -1
	for i := 0; i < n; i++ {
		if qeIsv >= doc.TcbLevels[i].Tcb.IsvSvn {
			matchIdx = i
			break
		}
	}
	if matchIdx < 0 {
		return fmt.Errorf("no satisfiable QE TCB level (isv_svn=%d)", qeIsv)
	}

	qeLevelCount := n
	applyQeMutation(mf, &matchIdx, &qeLevelCount, statusOff, isvsvn, lvlOff, n)
	n = qeLevelCount

	tw.section("qe")
	tw.bytesField("mrsigner", hexB(doc.MrSigner, 32))
	tw.num("isvprodid", int(doc.IsvProdID))
	tw.bytesField("miscselect", hexB(doc.MiscSelect, 4))
	tw.bytesField("miscmask", hexB(doc.MiscSelectMask, 4))
	tw.bytesField("attributes", hexB(doc.Attributes, 16))
	tw.bytesField("attrmask", hexB(doc.AttributesMask, 16))
	tw.num("mrsigner_off", mustIdx(raw, mrSignerCtx))
	tw.num("isvprodid_off", mustIdx(raw, isvProdIDCtx))
	tw.num("miscselect_off", mustIdx(raw, miscSelectCtx))
	tw.num("miscmask_off", mustIdx(raw, miscMaskCtx))
	tw.num("attr_off", mustIdx(raw, attrCtx))
	tw.num("attrmask_off", mustIdx(raw, attrMaskCtx))
	tw.num("level_count", n)
	tw.num("match_idx", matchIdx)
	tw.numArr("lvl_off", lvlOff)
	tw.numArr("status_off", statusOff)
	tw.numArr("isvsvn", isvsvn)
	tw.numArr("severity", sev)
	return nil
}

func comps16(c []tcbComponent) []int {
	out := make([]int, maxSgxComponents)
	for i := 0; i < maxSgxComponents; i++ {
		if i < len(c) {
			out[i] = int(c[i].Svn)
		}
	}
	return out
}

func platformSatisfies(cpu [16]byte, pce uint16, tee [16]byte, lv *tcbLevel) bool {
	if pce < lv.Tcb.PceSvn {
		return false
	}
	for i, c := range lv.Tcb.Sgx {
		if i < 16 && cpu[i] < c.Svn {
			return false
		}
	}
	for i, c := range lv.Tcb.Tdx {
		if i < 16 && tee[i] < c.Svn {
			return false
		}
	}
	return true
}

func componentStarts(region []byte, base int) []int {
	var offs []int
	s := 0
	for {
		idx := bytes.Index(region[s:], jsonSvnCtx)
		if idx < 0 {
			break
		}
		offs = append(offs, base+s+idx)
		s += idx + len(jsonSvnCtx)
	}
	return offs
}

// ============================ quote parsing ============================

type parsedQuote struct {
	SignedData   []byte
	TeeTcbSvn    [16]byte
	MrTd         [48]byte
	Rtmr0        [48]byte
	Rtmr1        [48]byte
	Rtmr2        [48]byte
	Rtmr3        [48]byte
	ReportData   [64]byte
	IsvSig       [64]byte
	AttestKey    [64]byte
	QeReport     [384]byte
	QeReportSig  [64]byte
	QeAuth       []byte
}

func parseTDXQuote(raw []byte) (*parsedQuote, error) {
	if len(raw) < signedQLen+4 {
		return nil, fmt.Errorf("quote too short")
	}
	q := &parsedQuote{SignedData: raw[:signedQLen]}
	if binary.LittleEndian.Uint32(raw[4:8]) != 0x81 {
		return nil, fmt.Errorf("not a TDX quote")
	}
	r := raw[48:]
	copy(q.TeeTcbSvn[:], r[0:16])
	copy(q.MrTd[:], r[136:184])
	copy(q.Rtmr0[:], r[328:376])
	copy(q.Rtmr1[:], r[376:424])
	copy(q.Rtmr2[:], r[424:472])
	copy(q.Rtmr3[:], r[472:520])
	copy(q.ReportData[:], r[520:584])

	authOff := signedQLen
	authSize := binary.LittleEndian.Uint32(raw[authOff : authOff+4])
	authOff += 4
	auth := raw[authOff : authOff+int(authSize)]
	copy(q.IsvSig[:], auth[0:64])
	copy(q.AttestKey[:], auth[64:128])
	certType := binary.LittleEndian.Uint16(auth[128:130])
	certBodySize := binary.LittleEndian.Uint32(auth[130:134])
	certBody := auth[134 : 134+int(certBodySize)]
	if certType != 6 {
		return nil, fmt.Errorf("unexpected cert_type %d", certType)
	}
	copy(q.QeReport[:], certBody[0:384])
	copy(q.QeReportSig[:], certBody[384:448])
	authLen := binary.LittleEndian.Uint16(certBody[448:450])
	off := 450
	q.QeAuth = make([]byte, authLen)
	copy(q.QeAuth, certBody[off:off+int(authLen)])
	return q, nil
}

// ============================ cert / crl helpers ============================

func parsePEM(s string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(s)
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
		return nil, fmt.Errorf("no certs")
	}
	return certs, nil
}

func parseCRL(hexStr string) (*x509.RevocationList, error) {
	der, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(der)
}

func extractSgxExt(cert *x509.Certificate) (cpuSvn [16]byte, pceSvn uint16, fmspc [6]byte, err error) {
	const sgxOID = "1.2.840.113741.1.13.1"
	for _, ext := range cert.Extensions {
		if ext.Id.String() == sgxOID {
			hexData := hex.EncodeToString(ext.Value)
			if idx := strings.Index(hexData, "060a2a864886f84d010d0104"); idx >= 0 {
				rem := hexData[idx+24:]
				if o := strings.Index(rem, "0406"); o >= 0 && o < 10 {
					b, _ := hex.DecodeString(rem[o+4 : o+4+12])
					copy(fmspc[:], b)
				}
			}
			if idx := strings.Index(hexData, "060b2a864886f84d010d010212"); idx >= 0 {
				rem := hexData[idx+26:]
				if o := strings.Index(rem, "0410"); o >= 0 && o < 10 {
					b, _ := hex.DecodeString(rem[o+4 : o+4+32])
					copy(cpuSvn[:], b)
				}
			}
			if idx := strings.Index(hexData, "060b2a864886f84d010d010211"); idx >= 0 {
				rem := hexData[idx+26:]
				if o := strings.Index(rem, "0202"); o >= 0 && o < 10 {
					b, _ := hex.DecodeString(rem[o+4 : o+8])
					pceSvn = uint16(b[0])<<8 | uint16(b[1])
				} else if o := strings.Index(rem, "0201"); o >= 0 && o < 10 {
					b, _ := hex.DecodeString(rem[o+4 : o+6])
					pceSvn = uint16(b[0])
				}
			}
			return
		}
	}
	err = fmt.Errorf("SGX ext not found")
	return
}

// p256N is the P-256 group order; lowS normalizes s to the canonical low-s form.
var p256N, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

// lowS returns min(s, N-s). Noir's secp256r1 blackbox rejects high-s signatures
// (malleability guard); ECDSA verification is invariant under this normalization
// (both (r,s) and (r,N-s) are valid for the same message), so this is sound.
func lowS(s *big.Int) *big.Int {
	half := new(big.Int).Rsh(p256N, 1)
	if s.Cmp(half) > 0 {
		return new(big.Int).Sub(p256N, s)
	}
	return s
}

// lowSRaw low-s normalizes a 64-byte raw r||s signature in place (returns a copy).
func lowSRaw(b []byte) []byte {
	r := new(big.Int).SetBytes(b[:32])
	s := new(big.Int).SetBytes(b[32:64])
	return append(b32(r), b32(lowS(s))...)
}

// derSig parses an ASN.1 DER ECDSA signature into 64 raw r||s bytes (low-s).
func derSig(der []byte) []byte {
	var s struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &s); err != nil {
		panic(fmt.Sprintf("der sig: %v", err))
	}
	return append(b32(s.R), b32(lowS(s.S))...)
}

// rawSig decodes a 64-byte raw r||s hex string and low-s normalizes it.
func rawSig(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	must(err)
	if len(b) != 64 {
		panic(fmt.Sprintf("raw sig %d bytes", len(b)))
	}
	r := new(big.Int).SetBytes(b[:32])
	s := new(big.Int).SetBytes(b[32:64])
	return append(b32(r), b32(lowS(s))...)
}

func b32(i *big.Int) []byte {
	b := i.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func firstUTC(tbs []byte) int {
	idx := bytes.Index(tbs, []byte{0x17, 0x0d})
	if idx < 0 {
		panic("CRL thisUpdate not found")
	}
	return idx
}

// ============================ date helpers ============================

func packTimestamp(unix uint64) uint64 {
	t := time.Unix(int64(unix), 0).UTC()
	return uint64(t.Year())*10000000000 + uint64(t.Month())*100000000 +
		uint64(t.Day())*1000000 + uint64(t.Hour())*10000 +
		uint64(t.Minute())*100 + uint64(t.Second())
}

// findStr locates ctx in buf and returns the n value bytes that follow.
func findStr(buf, ctx []byte, n int) string {
	i := bytes.Index(buf, ctx)
	if i < 0 {
		panic("findStr ctx not found")
	}
	return string(buf[i+len(ctx) : i+len(ctx)+n])
}

// parseISO converts "YYYY-MM-DDThh:mm:ssZ" to unix seconds.
func parseISO(s string) int64 {
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	must(err)
	return t.Unix()
}

func hexB(s string, n int) []byte {
	b, err := hex.DecodeString(s)
	must(err)
	if len(b) != n {
		panic(fmt.Sprintf("hex field %q want %d got %d", s, n, len(b)))
	}
	return b
}

// ============================ buffer / index helpers ============================

func pad(src []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, src)
	return out
}

func mustIdx(buf, ctx []byte) int {
	i := bytes.Index(buf, ctx)
	if i < 0 {
		panic(fmt.Sprintf("anchor %x not found", ctx))
	}
	return i
}

func lastIdx(buf, ctx []byte) int {
	i := bytes.LastIndex(buf, ctx)
	if i < 0 {
		panic("anchor not found")
	}
	return i
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// ============================ negative-test mutations ============================
// Each mutation makes ONE forgery the security checks must reject. All are no-ops
// for the honest run (-mutate ""). The negative-test runner asserts nargo execute
// FAILS for each. Mutations target a soundness requirement:
//   g1-fmspc-off     G1: extraction offset planted past signed_len (unsigned tail)
//   g1-eval-off      G1: tcbEvaluationDataNumber offset planted in the unsigned tail (#2)
//   c1-tcb-idx       C1: platform TCB match index out of [0,count)
//   c1-qe-idx        C1: QE match index out of [0,count)
//   g2-forged-sgx    G2: lower a chosen-level SGX SVN threshold (free witness)
//   g5-noncanonical  G5: pick a softer later level the platform also satisfies
//   c3-cross-status  C3: point a level's status at another level's status anchor
//   f1-skip-level    F1: claim fewer active TCB levels than real anchors (skip)
//   f2-tdx-crosslvl  F2: point TdxArrOff at another level's tdx array
//   f3-qe-skip       F3: claim fewer active QE levels than real anchors
//   c4-cert-as-crl   C4: feed a (Platform-CA-signed) cert TBS as the PCK CRL
//   c5-stale-crl     C5: shift Timestamp past the PCK CRL nextUpdate

func mutateCRL(crlTBS, leafTBS []byte, mf mutateFlags) []byte {
	if mf.name == "c4-cert-as-crl" {
		return leafTBS // a cert tbsCertificate posing as the CRL
	}
	return crlTBS
}

func crlSig(crl *x509.RevocationList, leaf *x509.Certificate, mf mutateFlags) []byte {
	if mf.name == "c4-cert-as-crl" {
		return leaf.Signature // the leaf's own Platform-CA signature
	}
	return crl.Signature
}

// applyTcbMutation perturbs the TcbBound witness for the platform-side negatives.
// cap is the buffer capacity (so g1 can plant an offset in the unsigned tail).
func applyTcbMutation(mf mutateFlags, matchIdx, levelCount *int, statusOff, pceVal []int, sgxComps, tdxComps [][]int, tdxArrOff, lvlStart []int, n int) {
	switch mf.name {
	case "c1-tcb-idx":
		*matchIdx = *levelCount // out of range (>= count)
	case "g2-forged-sgx":
		// lower a chosen-level SGX threshold; the planted value won't match the
		// signed JSON byte (binding asserts equality), so it must reject.
		sgxComps[*matchIdx][0] = 0
	case "g5-noncanonical":
		// the real fixture: level 0 UpToDate (satisfied), level 1 OutOfDate. Pick
		// level 1 though level 0 is also satisfied -> canonical rule rejects.
		if n >= 2 {
			*matchIdx = 1
		}
	case "c3-cross-status":
		// point the chosen level's status offset at level 0's status anchor.
		if n >= 2 && *matchIdx != 0 {
			statusOff[*matchIdx] = statusOff[0]
		} else if n >= 2 {
			statusOff[0] = statusOff[1]
		}
	case "f1-skip-level":
		// claim 1 active level when the signed JSON has 2 anchors -> count !=
		// total_anchors assertion (F1) rejects.
		*levelCount = 1
	case "f2-tdx-crosslvl":
		// point level 0's tdx array at level 1's tdx array (different values) ->
		// F2 containment (tdxArrOff in [pcesvn,status)) rejects.
		if n >= 2 {
			tdxArrOff[0] = tdxArrOff[1]
		}
	}
}

func applyQeMutation(mf mutateFlags, matchIdx, levelCount *int, statusOff, isvsvn, lvlOff []int, n int) {
	switch mf.name {
	case "c1-qe-idx":
		*matchIdx = *levelCount // out of range
	case "f3-qe-skip":
		// real QE-Identity has 1 level; claim 0 active is impossible (count>=1), so
		// for a 1-level fixture inflate count to force count != total_anchors.
		*levelCount = *levelCount + 1
	}
}
