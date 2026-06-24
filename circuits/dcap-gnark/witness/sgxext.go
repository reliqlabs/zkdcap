package witness

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// extractSgxExtensions pulls the CPU SVN, PCE SVN, and FMSPC out of the Intel
// SGX extension block (OID 1.2.840.113741.1.13.1) of a PCK leaf certificate.
// These feed the platform TCB comparison (step 8).
func extractSgxExtensions(cert *x509.Certificate) (cpuSvn [16]byte, pceSvn uint16, fmspc [6]byte, ppid []byte, err error) {
	const sgxOID = "1.2.840.113741.1.13.1"
	for _, ext := range cert.Extensions {
		if ext.Id.String() == sgxOID {
			return parseSgxExtension(ext.Value)
		}
	}
	err = fmt.Errorf("SGX extensions OID %s not found", sgxOID)
	return
}

// parseSgxExtension scans the DER-encoded SGX extension block by OID prefix.
// The block is a SEQUENCE of OID/value pairs; we locate each field by its OID
// hex and read the following primitive value.
func parseSgxExtension(data []byte) (cpuSvn [16]byte, pceSvn uint16, fmspc [6]byte, ppid []byte, err error) {
	hexData := hex.EncodeToString(data)

	// FMSPC: OID 1.2.840.113741.1.13.1.4, OCTET STRING (6 bytes)
	fmspcOidHex := "060a2a864886f84d010d0104"
	if idx := strings.Index(hexData, fmspcOidHex); idx >= 0 {
		remaining := hexData[idx+len(fmspcOidHex):]
		if octetIdx := strings.Index(remaining, "0406"); octetIdx >= 0 && octetIdx < 10 {
			fmspcHex := remaining[octetIdx+4 : octetIdx+4+12]
			if b, e := hex.DecodeString(fmspcHex); e == nil && len(b) == 6 {
				copy(fmspc[:], b)
			}
		}
	}

	// CPU SVN: OID 1.2.840.113741.1.13.1.2.18, OCTET STRING (16 bytes)
	cpuSvnOidHex := "060b2a864886f84d010d010212"
	if idx := strings.Index(hexData, cpuSvnOidHex); idx >= 0 {
		remaining := hexData[idx+len(cpuSvnOidHex):]
		if octetIdx := strings.Index(remaining, "0410"); octetIdx >= 0 && octetIdx < 10 {
			svnHex := remaining[octetIdx+4 : octetIdx+4+32]
			if b, e := hex.DecodeString(svnHex); e == nil && len(b) == 16 {
				copy(cpuSvn[:], b)
			}
		}
	}

	// PCE SVN: OID 1.2.840.113741.1.13.1.2.17, INTEGER (1 or 2 bytes)
	pceSvnOidHex := "060b2a864886f84d010d010211"
	if idx := strings.Index(hexData, pceSvnOidHex); idx >= 0 {
		remaining := hexData[idx+len(pceSvnOidHex):]
		if intIdx := strings.Index(remaining, "0202"); intIdx >= 0 && intIdx < 10 {
			if b, e := hex.DecodeString(remaining[intIdx+4 : intIdx+8]); e == nil && len(b) == 2 {
				pceSvn = uint16(b[0])<<8 | uint16(b[1])
			}
		} else if intIdx := strings.Index(remaining, "0201"); intIdx >= 0 && intIdx < 10 {
			if b, e := hex.DecodeString(remaining[intIdx+4 : intIdx+6]); e == nil && len(b) == 1 {
				pceSvn = uint16(b[0])
			}
		}
	}

	// PPID: OID 1.2.840.113741.1.13.1.1, OCTET STRING (16 bytes)
	ppidOidHex := "060a2a864886f84d010d0101"
	if idx := strings.Index(hexData, ppidOidHex); idx >= 0 {
		remaining := hexData[idx+len(ppidOidHex):]
		if octetIdx := strings.Index(remaining, "0410"); octetIdx >= 0 && octetIdx < 10 {
			ppid, _ = hex.DecodeString(remaining[octetIdx+4 : octetIdx+4+32])
		}
	}

	return
}
