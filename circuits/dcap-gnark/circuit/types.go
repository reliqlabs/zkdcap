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

// DcapCircuit implements DCAP quote verification steps 4-10 as a gnark circuit.
type DcapCircuit struct {
	// === Public inputs (DcapJournal) ===
	MrTd       [48]uints.U8       `gnark:",public"`
	Rtmr0      [48]uints.U8       `gnark:",public"`
	Rtmr1      [48]uints.U8       `gnark:",public"`
	Rtmr2      [48]uints.U8       `gnark:",public"`
	Rtmr3      [48]uints.U8       `gnark:",public"`
	ReportData [64]uints.U8       `gnark:",public"`
	TcbStatus  frontend.Variable  `gnark:",public"`
	Timestamp  frontend.Variable  `gnark:",public"`

	// === Private inputs ===

	// Signed quote region (header + TDReport10 = 632 bytes)
	SignedQuote [SignedQuoteLen]uints.U8

	// QE Report (384 bytes, from AuthData)
	QeReport [EnclaveReportLen]uints.U8

	// PCK public key (trusted, from host cert chain validation)
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

	// QE Identity policy fields
	QeIdMrSigner   [32]uints.U8
	QeIdIsvProdId  frontend.Variable // u16
	QeIdMiscSelect [4]uints.U8
	QeIdMiscMask   [4]uints.U8
	QeIdAttributes [16]uints.U8
	QeIdAttrMask   [16]uints.U8

	// QE TCB levels (for QE identity step 6/9)
	QeIdTcbIsvSvn   [MaxQeTcbLevels]frontend.Variable // each level's isvsvn threshold
	QeIdTcbSeverity [MaxQeTcbLevels]frontend.Variable // each level's severity
	QeIdTcbCount    frontend.Variable                  // actual number of levels
	QeTcbMatchIdx   frontend.Variable                  // hint: which level matched

	// Platform TCB levels (step 8)
	PlatformFmspc    [6]uints.U8
	TcbInfoFmspc     [6]uints.U8
	PlatformCpuSvn   [16]uints.U8
	PlatformPceSvn   frontend.Variable // u16
	PlatformTeeTcbSvn [16]uints.U8

	// TCB level data (padded arrays)
	TcbPceSvn     [MaxTcbLevels]frontend.Variable
	TcbSgxComps   [MaxTcbLevels][MaxSgxComponents]frontend.Variable // svn values
	TcbTdxComps   [MaxTcbLevels][MaxTdxComponents]frontend.Variable
	TcbSeverity   [MaxTcbLevels]frontend.Variable
	TcbLevelCount frontend.Variable
	TcbMatchIdx   frontend.Variable // hint: which platform TCB level matched
}
