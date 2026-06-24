package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// ----- Quote binary layout constants -----

const (
	HeaderLen      = 48
	TDReport10Len  = 584
	EnclaveReportLen = 384
	SignedQuoteLen = HeaderLen + TDReport10Len // 632

	ECDSASigLen    = 64
	ECDSAPubKeyLen = 64
)

// TDReport10 field offsets (relative to start of report, i.e. byte 48 of signed quote)
const (
	TDR_TeeTcbSvn    = 0  // [0..16)   16 bytes
	TDR_MrSeam       = 16 // [16..64)  48 bytes
	TDR_MrSignerSeam = 64 // [64..112) 48 bytes
	TDR_SeamAttrs    = 112 // [112..120) 8 bytes
	TDR_TdAttrs      = 120 // [120..128) 8 bytes
	TDR_Xfam         = 128 // [128..136) 8 bytes
	TDR_MrTd         = 136 // [136..184) 48 bytes
	TDR_MrConfigId   = 184 // [184..232) 48 bytes
	TDR_MrOwner      = 232 // [232..280) 48 bytes
	TDR_MrOwnerCfg   = 280 // [280..328) 48 bytes
	TDR_Rtmr0        = 328 // [328..376) 48 bytes
	TDR_Rtmr1        = 376 // [376..424) 48 bytes
	TDR_Rtmr2        = 424 // [424..472) 48 bytes
	TDR_Rtmr3        = 472 // [472..520) 48 bytes
	TDR_ReportData   = 520 // [520..584) 64 bytes
)

// Absolute offsets within signed quote (header + td_report)
const (
	SQ_TeeTcbSvn  = HeaderLen + TDR_TeeTcbSvn  // 48
	SQ_MrTd       = HeaderLen + TDR_MrTd        // 184
	SQ_Rtmr0      = HeaderLen + TDR_Rtmr0       // 376
	SQ_Rtmr1      = HeaderLen + TDR_Rtmr1       // 424
	SQ_Rtmr2      = HeaderLen + TDR_Rtmr2       // 472
	SQ_Rtmr3      = HeaderLen + TDR_Rtmr3       // 520
	SQ_ReportData = HeaderLen + TDR_ReportData   // 568
)

// EnclaveReport (QE Report) field offsets
const (
	QER_CpuSvn     = 0   // [0..16)    16 bytes
	QER_MiscSelect = 16  // [16..20)   4 bytes (u32 LE)
	QER_Reserved1  = 20  // [20..48)   28 bytes
	QER_Attributes = 48  // [48..64)   16 bytes
	QER_MrEnclave  = 64  // [64..96)   32 bytes
	QER_Reserved2  = 96  // [96..128)  32 bytes
	QER_MrSigner   = 128 // [128..160) 32 bytes
	QER_Reserved3  = 160 // [160..256) 96 bytes
	QER_IsvProdId  = 256 // [256..258) 2 bytes (u16 LE)
	QER_IsvSvn     = 258 // [258..260) 2 bytes (u16 LE)
	QER_Reserved4  = 260 // [260..320) 60 bytes
	QER_ReportData = 320 // [320..384) 64 bytes
)

// TCB status severity encoding (lower = better)
const (
	TcbUpToDate                          = 0
	TcbSWHardeningNeeded                 = 1
	TcbConfigurationNeeded               = 2
	TcbConfigurationAndSWHardeningNeeded = 3
	TcbOutOfDate                         = 4
	TcbOutOfDateConfigurationNeeded      = 5
	TcbRevoked                           = 6
)

// Max array sizes for padded witness fields
const (
	MaxTcbLevels      = 16   // max platform TCB levels
	MaxSgxComponents  = 16   // always 16 SGX TCB components
	MaxTdxComponents  = 16   // always 16 TDX TCB components
	MaxQeTcbLevels    = 8    // max QE identity TCB levels
)

// ----- Circuit type aliases -----

type P256Fp = emulated.P256Fp
type P256Fr = emulated.P256Fr

type ECDSAPublicKey = stdecdsa.PublicKey[P256Fp, P256Fr]
type ECDSASignature = stdecdsa.Signature[P256Fr]

// ----- Circuit definition -----

// DcapCircuit implements the self-anchoring DCAP TDX verification path: the PCK
// cert chain to the pinned Intel SGX Root CA (A1), the Intel-signed collateral
// (A2), and quote verification steps 4-10. Every value the verifier relies on
// is either a public input/output or is constrained in-circuit to a
// signature-anchored source, so a forged proof cannot substitute its own key,
// quote, or collateral.
type DcapCircuit struct {
	// === Public inputs / outputs ===
	// Measurements + report data, bound from the signature-anchored signed quote.
	MrTd       [48]uints.U8 `gnark:",public"`
	Rtmr0      [48]uints.U8 `gnark:",public"`
	Rtmr1      [48]uints.U8 `gnark:",public"`
	Rtmr2      [48]uints.U8 `gnark:",public"`
	Rtmr3      [48]uints.U8 `gnark:",public"`
	ReportData [64]uints.U8 `gnark:",public"`
	// TcbStatus is computed in-circuit (steps 8-10) and exposed as a public output.
	TcbStatus frontend.Variable `gnark:",public"`
	Timestamp frontend.Variable `gnark:",public"`
	// Self-anchoring outputs for the on-chain revoked-set check: the PCK leaf
	// serial and the platform FMSPC, both extracted from signature-bound bytes.
	CertSerial [certSerialLen]uints.U8 `gnark:",public"`
	Fmspc      [fmspcLen]uints.U8      `gnark:",public"`
	// #2 TcbEvalNum = min(tcbEvaluationDataNumber) across the signed TCB-Info and
	// QE-Identity. The host is untrusted, so a stale-but-validly-signed collateral
	// (older eval number) could otherwise be replayed inside its still-open
	// freshness window to pick a more favorable status; the on-chain consumer
	// compares this against a monotonic floor.
	TcbEvalNum frontend.Variable `gnark:",public"`
	// #3 intersected collateral validity window [ValidFrom, ValidUntil], packed
	// YYYYMMDDhhmmss: max of all window lower bounds / min of all upper bounds. The
	// consumer range-checks chain time against this instead of trusting the
	// host-chosen Timestamp, closing the stale-collateral replay gap.
	ValidFrom  frontend.Variable `gnark:",public"`
	ValidUntil frontend.Variable `gnark:",public"`

	// === Quote (steps 4-10) ===

	// Signed quote region (header + TDReport10 = 632 bytes)
	SignedQuote [SignedQuoteLen]uints.U8

	// QE Report (384 bytes, from AuthData)
	QeReport [EnclaveReportLen]uints.U8

	// PCK public key. Constrained equal to the PCK leaf subjectPublicKey by the
	// chain check (verifyChainToRoot), so it is no longer trusted from the host.
	PckPubKey ECDSAPublicKey

	// QE Report ECDSA signature (over QeReport, verified with PckPubKey)
	QeReportSig ECDSASignature

	// ISV (attestation key) ECDSA signature (over SignedQuote)
	IsvSig ECDSASignature

	// Attestation key: raw 64 bytes (x||y) + as P-256 point
	AttestKeyRaw [64]uints.U8
	AttestKeyPub ECDSAPublicKey

	// QE auth data (variable, padded to 32 bytes for our fixture)
	QeAuthData    [32]uints.U8
	QeAuthDataLen frontend.Variable

	// === PCK cert chain (A1: leaf <- Intel SGX PCK Platform CA <- pinned Root) ===
	LeafTBS       [maxLeafTBS]uints.U8
	LeafTBSLen    frontend.Variable
	LeafSig       ECDSASignature
	LeafPubKeyOff frontend.Variable // hint: offset of subjectPublicKey in leaf TBS
	LeafFmspcOff  frontend.Variable // hint: offset of FMSPC extension in leaf TBS
	LeafSerialOff frontend.Variable // hint: offset of version/serial context in leaf TBS
	LeafCpuSvnOff frontend.Variable // hint: offset of CPUSVN OID in leaf TBS (G2)
	LeafPceSvnOff frontend.Variable // hint: offset of PCESVN OID in leaf TBS (G2)
	LeafValidityOff frontend.Variable // hint: offset of Validity SEQUENCE in leaf TBS (H3)

	IntTBS       [maxIntTBS]uints.U8
	IntTBSLen    frontend.Variable
	IntSig       ECDSASignature
	IntPubKeyOff frontend.Variable // hint: offset of subjectPublicKey in intermediate TBS
	IntSerialOff frontend.Variable // hint: offset of version/serial context in intermediate TBS (G4)
	IntValidityOff frontend.Variable // hint: offset of Validity SEQUENCE in intermediate TBS (H3)

	// === Collateral (A2: TCB-Signing cert + TCB-Info + QE-Identity, Intel-signed) ===
	SignTBS    [maxSignTBS]uints.U8
	SignLen    frontend.Variable
	SignSig    ECDSASignature
	SignPubOff frontend.Variable // hint: offset of subjectPublicKey in TCB-Signing TBS
	SignValidityOff frontend.Variable // hint: offset of Validity SEQUENCE in TCB-Signing TBS (H3)

	TcbInfoRaw      [maxTcbInfo]uints.U8
	TcbInfoRawLen   frontend.Variable
	TcbInfoSig      ECDSASignature
	TcbInfoFmspcOff frontend.Variable // hint: offset of "fmspc":" in TCB-Info JSON

	// G2: per-level offset hints into the signed TCB-Info JSON, used to bind the
	// TCB-verdict comparison values (svn components, pcesvn, tcbStatus) to the
	// Intel-signed bytes. One TcbLevelOff per platform TCB level slot.
	TcbLvlOff      [MaxTcbLevels]TcbLevelOff
	TcbLevelsOff   frontend.Variable                   // hint: offset of "tcbLevels":[ (top-level array)
	TcbLvlStartOff [MaxTcbLevels - 1]frontend.Variable // hint: level starts for slots 1..N-1

	QeIDRaw    [maxQeID]uints.U8
	QeIDRawLen frontend.Variable
	QeIDSig    ECDSASignature

	// G2: offset hints into the signed QE-Identity JSON.
	QeIdOff QeIdOffsets

	// G4 (freshness): validity-window date offsets into the signed JSON. The
	// Timestamp public input is interpreted as packed YYYYMMDDhhmmss; the circuit
	// asserts issueDate <= Timestamp <= nextUpdate for both collateral blobs.
	TcbIssueDateOff  frontend.Variable // "issueDate":" in TCB-Info
	TcbNextUpdateOff frontend.Variable // "nextUpdate":" in TCB-Info
	QeIssueDateOff   frontend.Variable // "issueDate":" in QE-Identity
	QeNextUpdateOff  frontend.Variable // "nextUpdate":" in QE-Identity

	// #2 tcbEvaluationDataNumber offsets in the signed TCB-Info / QE-Identity JSON.
	TcbEvalOff frontend.Variable // "tcbEvaluationDataNumber":" in TCB-Info
	QeEvalOff  frontend.Variable // "tcbEvaluationDataNumber":" in QE-Identity

	// G4 (revocation): the Intel-signed PCK CRL (signed by the Platform CA) and
	// Root CA CRL. verifyCrlNonMembership proves each CRL signature and that the
	// chain serial does not occur in the signed revoked list (substring-absence,
	// which also forbids supplying an empty list). The PCK CRL covers the leaf
	// serial; the Root CA CRL covers the intermediate serial.
	PckCrlTBS           [pckCrlMaxTBS]uints.U8
	PckCrlTBSLen        frontend.Variable
	PckCrlSig           ECDSASignature
	PckCrlThisUpdateOff frontend.Variable // hint: thisUpdate UTCTime offset (G4 C5)

	RootCrlTBS           [rootCrlMaxTBS]uints.U8
	RootCrlTBSLen        frontend.Variable
	RootCrlSig           ECDSASignature
	RootCrlThisUpdateOff frontend.Variable // hint: thisUpdate UTCTime offset (G4 C5)

	// === QE Identity policy fields (from the QE-Identity JSON; residual: see dcap.go) ===
	QeIdMrSigner   [32]uints.U8
	QeIdIsvProdId  frontend.Variable // u16
	QeIdMiscSelect [4]uints.U8
	QeIdMiscMask   [4]uints.U8
	QeIdAttributes [16]uints.U8
	QeIdAttrMask   [16]uints.U8

	// QE TCB levels (for QE identity step 6/9)
	QeIdTcbIsvSvn   [MaxQeTcbLevels]frontend.Variable // each level's isvsvn threshold
	QeIdTcbSeverity [MaxQeTcbLevels]frontend.Variable // each level's severity
	QeIdTcbCount    frontend.Variable                 // actual number of levels
	QeTcbMatchIdx   frontend.Variable                 // hint: which level matched

	// === Platform TCB (from the TCB-Info JSON; residual: see dcap.go) ===
	PlatformCpuSvn    [16]uints.U8
	PlatformPceSvn    frontend.Variable // u16
	PlatformTeeTcbSvn [16]uints.U8

	// TCB level data (padded arrays)
	TcbPceSvn     [MaxTcbLevels]frontend.Variable
	TcbSgxComps   [MaxTcbLevels][MaxSgxComponents]frontend.Variable // svn values
	TcbTdxComps   [MaxTcbLevels][MaxTdxComponents]frontend.Variable
	TcbSeverity   [MaxTcbLevels]frontend.Variable
	TcbLevelCount frontend.Variable
	TcbMatchIdx   frontend.Variable // hint: which platform TCB level matched
}

// TcbLevelOff carries the host-supplied byte offsets into the signed TCB-Info
// JSON for one tcbLevels entry (G2 binding). SgxSvnOff/TdxSvnOff hold the
// offsets of components 1..15 (component 0 is pinned to the array-start anchor).
type TcbLevelOff struct {
	// SgxArrOff is NOT a witness field: it is derived in-circuit from the level
	// start (lvlStart + len(`{"tcb":{`)), so the prover cannot move it.
	SgxSvnOff [MaxSgxComponents - 1]frontend.Variable // {"svn": of comps 1..15
	PceSvnOff frontend.Variable                       // "pcesvn":
	TdxArrOff frontend.Variable                       // "tdxtcbcomponents":[
	TdxSvnOff [MaxTdxComponents - 1]frontend.Variable // {"svn": of comps 1..15
	StatusOff frontend.Variable                       // "tcbStatus":"
}

// QeIdOffsets carries the host-supplied byte offsets into the signed
// QE-Identity JSON (G2 binding).
type QeIdOffsets struct {
	MrSignerOff   frontend.Variable
	IsvProdIdOff  frontend.Variable
	MiscSelectOff frontend.Variable
	MiscMaskOff   frontend.Variable
	AttrOff       frontend.Variable
	AttrMaskOff   frontend.Variable
	QeLvlOff      [MaxQeTcbLevels]frontend.Variable // {"tcb":{"isvsvn": per level
	QeStatusOff   [MaxQeTcbLevels]frontend.Variable // "tcbStatus":" per level
}
