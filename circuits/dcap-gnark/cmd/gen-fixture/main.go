// gen-fixture extracts PreVerifiedInputs from collateral.json + quote.bin
// and writes pre_verified.json for use by the circuit tests.
package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/witness"
)

// RawCollateral matches the JSON structure from dcap_qvl::collateral.
type RawCollateral struct {
	TcbInfoRaw          string `json:"tcb_info"`
	QeIdentityRaw       string `json:"qe_identity"`
	PckCertificateChain string `json:"pck_certificate_chain"`
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: gen-fixture <quote.bin> <collateral.json> <output.json>")
		os.Exit(1)
	}

	quoteBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatal("read quote: %v", err)
	}
	_ = quoteBytes

	collBytes, err := os.ReadFile(os.Args[2])
	if err != nil {
		fatal("read collateral: %v", err)
	}

	var coll RawCollateral
	if err := json.Unmarshal(collBytes, &coll); err != nil {
		fatal("parse collateral: %v", err)
	}

	// Parse TcbInfo
	var tcbInfo witness.TcbInfo
	if err := json.Unmarshal([]byte(coll.TcbInfoRaw), &tcbInfo); err != nil {
		fatal("parse tcb_info: %v", err)
	}

	// Parse QeIdentity (Intel JSON format with hex strings)
	var qeIdJSON witness.QeIdentityJSON
	if err := json.Unmarshal([]byte(coll.QeIdentityRaw), &qeIdJSON); err != nil {
		fatal("parse qe_identity: %v", err)
	}

	// Extract PCK leaf cert DER
	pckLeafDer, err := extractPckLeafDer(coll.PckCertificateChain)
	if err != nil {
		fatal("extract PCK leaf: %v", err)
	}

	// Extract SGX extensions
	pckCert, err := x509.ParseCertificate(pckLeafDer)
	if err != nil {
		fatal("parse PCK cert: %v", err)
	}

	cpuSvn, pceSvn, fmspc, ppid, err := extractSgxExtensions(pckCert)
	if err != nil {
		fatal("extract SGX extensions: %v", err)
	}

	// Build JSON-serializable PreVerifiedInputs
	pre := witness.PreVerifiedJSON{
		TcbInfo:    tcbInfo,
		QeIdentity: qeIdJSON,
		PckLeafDer: witness.HexBytes(pckLeafDer),
		CpuSvn:     witness.HexFixedBytes16(cpuSvn),
		PceSvn:     pceSvn,
		Fmspc:      witness.HexFixedBytes6(fmspc),
		Ppid:       witness.HexBytes(ppid),
	}

	out, err := json.MarshalIndent(pre, "", "  ")
	if err != nil {
		fatal("marshal: %v", err)
	}

	if err := os.WriteFile(os.Args[3], out, 0644); err != nil {
		fatal("write: %v", err)
	}
	fmt.Printf("Written %s (%d bytes)\n", os.Args[3], len(out))
}

func extractPckLeafDer(chain string) ([]byte, error) {
	block, _ := pem.Decode([]byte(chain))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in PCK cert chain")
	}
	return block.Bytes, nil
}

func extractSgxExtensions(cert *x509.Certificate) (cpuSvn [16]byte, pceSvn uint16, fmspc [6]byte, ppid []byte, err error) {
	sgxOID := "1.2.840.113741.1.13.1"
	for _, ext := range cert.Extensions {
		if ext.Id.String() == sgxOID {
			return parseSgxExtension(ext.Value)
		}
	}
	err = fmt.Errorf("SGX extensions OID %s not found", sgxOID)
	return
}

func parseSgxExtension(data []byte) (cpuSvn [16]byte, pceSvn uint16, fmspc [6]byte, ppid []byte, err error) {
	hexData := hex.EncodeToString(data)

	// FMSPC: OID 1.2.840.113741.1.13.1.4
	fmspcOidHex := "060a2a864886f84d010d0104"
	if idx := strings.Index(hexData, fmspcOidHex); idx >= 0 {
		remaining := hexData[idx+len(fmspcOidHex):]
		if octetIdx := strings.Index(remaining, "0406"); octetIdx >= 0 && octetIdx < 10 {
			fmspcHex := remaining[octetIdx+4 : octetIdx+4+12]
			fmspcBytes, e := hex.DecodeString(fmspcHex)
			if e == nil && len(fmspcBytes) == 6 {
				copy(fmspc[:], fmspcBytes)
			}
		}
	}

	// CPU SVN: OID 1.2.840.113741.1.13.1.2.18
	cpuSvnOidHex := "060b2a864886f84d010d010212"
	if idx := strings.Index(hexData, cpuSvnOidHex); idx >= 0 {
		remaining := hexData[idx+len(cpuSvnOidHex):]
		if octetIdx := strings.Index(remaining, "0410"); octetIdx >= 0 && octetIdx < 10 {
			svnHex := remaining[octetIdx+4 : octetIdx+4+32]
			svnBytes, e := hex.DecodeString(svnHex)
			if e == nil && len(svnBytes) == 16 {
				copy(cpuSvn[:], svnBytes)
			}
		}
	}

	// PCE SVN: OID 1.2.840.113741.1.13.1.2.17
	pceSvnOidHex := "060b2a864886f84d010d010211"
	if idx := strings.Index(hexData, pceSvnOidHex); idx >= 0 {
		remaining := hexData[idx+len(pceSvnOidHex):]
		if intIdx := strings.Index(remaining, "0202"); intIdx >= 0 && intIdx < 10 {
			pceHex := remaining[intIdx+4 : intIdx+8]
			pceBytes, e := hex.DecodeString(pceHex)
			if e == nil && len(pceBytes) == 2 {
				pceSvn = uint16(pceBytes[0])<<8 | uint16(pceBytes[1])
			}
		} else if intIdx := strings.Index(remaining, "0201"); intIdx >= 0 && intIdx < 10 {
			pceHex := remaining[intIdx+4 : intIdx+6]
			pceBytes, e := hex.DecodeString(pceHex)
			if e == nil && len(pceBytes) == 1 {
				pceSvn = uint16(pceBytes[0])
			}
		}
	}

	// PPID: OID 1.2.840.113741.1.13.1.1
	ppidOidHex := "060a2a864886f84d010d0101"
	if idx := strings.Index(hexData, ppidOidHex); idx >= 0 {
		remaining := hexData[idx+len(ppidOidHex):]
		if octetIdx := strings.Index(remaining, "0410"); octetIdx >= 0 && octetIdx < 10 {
			ppidHex := remaining[octetIdx+4 : octetIdx+4+32]
			ppid, _ = hex.DecodeString(ppidHex)
		}
	}

	return
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
