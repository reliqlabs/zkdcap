package circuit

// Shared in-circuit buffer capacities and DER/JSON anchor literals used by the
// self-anchoring DCAP path (chain + collateral + field extraction). These were
// originally defined in the gadget test files; they live here so the integrated
// DcapCircuit (non-test) can reference them too.
//
// Capacities are COMPILE-TIME sizes: SHA-256 cost scales with the buffer
// capacity, not the runtime length, so each is sized to the largest real
// cert/blob the chain must accept (real sizes noted alongside).
const (
	maxLeafTBS = 1280 // PCK leaf TBS (real = 1180)
	maxIntTBS  = 640  // PCK Platform CA TBS (real = 577)
	maxSignTBS = 640  // Intel TCB-Signing cert TBS (real = 566)
	// maxTcbInfo MUST exceed (last tcbStatus anchor offset + len(`"tcbStatus":"`)
	// + statusReadLen) so the lookup-based status read stays inside the table
	// capacity (logderivlookup panics out of bounds; see extractStringEnumLU).
	// Real fixture: 2934 bytes, last status read ends ~2947, so 3072 (48x64B SHA
	// blocks) gives headroom while saving ~468K SHA constraints vs 4096.
	maxTcbInfo = 3072 // TCB-Info JSON (real = 2934)
	maxQeID    = 512  // QE-Identity JSON (real = 461)

	certSerialLen = 20 // canonical Intel cert serial (160-bit)
	fmspcLen      = 6  // FMSPC is 6 bytes / 12 hex chars
)

// fmspcCtx is the unique literal DER context preceding the FMSPC value in an
// Intel PCK leaf: the FMSPC OID (1.2.840.113741.1.13.1.4) + the 2 bytes before
// the 6-byte OCTET STRING value.
var fmspcCtx = []byte{0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04, 0x04, 0x06}

// tcbInfoFmspcCtx anchors the FMSPC inside the Intel-signed TCB-Info JSON. The
// 12 uppercase-hex characters of the FMSPC immediately follow this literal.
var tcbInfoFmspcCtx = []byte(`"fmspc":"`)

// cpuSvnCtx anchors the platform CPUSVN inside the PCK leaf SGX extension:
// the CPUSVN OID (1.2.840.113741.1.13.1.2.18) + OCTET STRING header (04 10),
// followed by the 16 raw CPUSVN bytes. Unique in the leaf TBS.
var cpuSvnCtx = []byte{0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x12, 0x04, 0x10}

// pceSvnCtx anchors the platform PCESVN inside the PCK leaf SGX extension:
// the PCESVN OID (1.2.840.113741.1.13.1.2.17) + the INTEGER tag (02). The next
// byte is the DER length (1 or 2), then that many big-endian value bytes. The
// in-circuit parser (extractPceSvn) handles the variable INTEGER width.
var pceSvnCtx = []byte{0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x11, 0x02}

// certValidityCtx anchors the X.509 Validity block in an Intel cert TBS: the
// Validity SEQUENCE header (30 1e) + the notBefore UTCTime tag/len (17 0d).
// Unique in the leaf TBS. notBefore's 13 UTCTime chars (YYMMDDHHMMSSZ) follow;
// notAfter is the next UTCTime, at a fixed +15 byte offset (13 value + 17 0d).
// Intel PCK certs use UTCTime (2-digit year, post-2000).
var certValidityCtx = []byte{0x30, 0x1e, 0x17, 0x0d}

// Exported anchor literals so the host-side witness builder (a separate
// package) can compute the hinted offsets via bytes.Index without duplicating
// the byte sequences. These are read-only.
var (
	SubjectPubKeyCtx     = subjectPubKeyCtx
	FmspcCtx             = fmspcCtx
	CertVersionSerialCtx = certVersionSerialCtx
	TcbInfoFmspcCtx      = tcbInfoFmspcCtx
	CpuSvnCtx            = cpuSvnCtx
	PceSvnCtx            = pceSvnCtx
	CertValidityCtx      = certValidityCtx
)
