package witness

import (
	"encoding/binary"
	"fmt"
)

// ParsedQuote holds the extracted fields from a TDX v4 quote.
type ParsedQuote struct {
	// Raw signed region (header + TDReport10)
	SignedData []byte // [0..632)

	// Header fields
	Version            uint16
	AttestationKeyType uint16
	TeeType            uint32
	QeSvn              uint16
	PceSvn             uint16

	// TDReport10 fields (offsets relative to report start = byte 48)
	TeeTcbSvn  [16]byte
	MrTd       [48]byte
	Rtmr0      [48]byte
	Rtmr1      [48]byte
	Rtmr2      [48]byte
	Rtmr3      [48]byte
	ReportData [64]byte

	// AuthData fields (extracted from the variable portion after signed data)
	EcdsaSignature     [64]byte // ISV signature (r||s)
	AttestationKey     [64]byte // raw x||y
	QeReport           [384]byte
	QeReportSignature  [64]byte
	QeAuthData         []byte
	CertificateData    []byte // raw cert chain (PEM)
}

const (
	headerLen     = 48
	tdReport10Len = 584
	signedLen     = headerLen + tdReport10Len // 632
)

// ParseTDXQuoteV4 parses a TDX v4 quote binary.
func ParseTDXQuoteV4(raw []byte) (*ParsedQuote, error) {
	if len(raw) < signedLen+4 {
		return nil, fmt.Errorf("quote too short: %d bytes", len(raw))
	}

	q := &ParsedQuote{}
	q.SignedData = raw[:signedLen]

	// Parse header
	q.Version = binary.LittleEndian.Uint16(raw[0:2])
	q.AttestationKeyType = binary.LittleEndian.Uint16(raw[2:4])
	q.TeeType = binary.LittleEndian.Uint32(raw[4:8])
	q.QeSvn = binary.LittleEndian.Uint16(raw[8:10])
	q.PceSvn = binary.LittleEndian.Uint16(raw[10:12])

	if q.Version != 4 && q.Version != 5 {
		return nil, fmt.Errorf("unsupported quote version: %d", q.Version)
	}
	if q.TeeType != 0x00000081 {
		return nil, fmt.Errorf("not a TDX quote (tee_type=0x%x)", q.TeeType)
	}

	// Parse TDReport10 (at offset 48)
	r := raw[headerLen:]
	copy(q.TeeTcbSvn[:], r[0:16])
	copy(q.MrTd[:], r[136:184])
	copy(q.Rtmr0[:], r[328:376])
	copy(q.Rtmr1[:], r[376:424])
	copy(q.Rtmr2[:], r[424:472])
	copy(q.Rtmr3[:], r[472:520])
	copy(q.ReportData[:], r[520:584])

	// Parse AuthData size
	authOff := signedLen
	authSize := binary.LittleEndian.Uint32(raw[authOff : authOff+4])
	authOff += 4

	if authOff+int(authSize) > len(raw) {
		return nil, fmt.Errorf("auth data exceeds quote length")
	}
	auth := raw[authOff : authOff+int(authSize)]

	// Parse AuthDataV4:
	// [0..64)   ECDSA signature
	// [64..128) Attestation key
	// [128..)   CertificationData (type 6 wrapping QEReportCertData)
	if len(auth) < 128+6 {
		return nil, fmt.Errorf("auth data too short: %d", len(auth))
	}
	copy(q.EcdsaSignature[:], auth[0:64])
	copy(q.AttestationKey[:], auth[64:128])

	// Outer CertificationData
	certType := binary.LittleEndian.Uint16(auth[128:130])
	certBodySize := binary.LittleEndian.Uint32(auth[130:134])
	certBody := auth[134 : 134+int(certBodySize)]

	if certType == 6 {
		// QEReportCertificationData
		if err := q.parseQEReportCertData(certBody); err != nil {
			return nil, fmt.Errorf("parsing QE report cert data: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unexpected outer cert_type: %d", certType)
	}

	return q, nil
}

func (q *ParsedQuote) parseQEReportCertData(data []byte) error {
	if len(data) < 384+64+2 {
		return fmt.Errorf("QE report cert data too short: %d", len(data))
	}

	copy(q.QeReport[:], data[0:384])
	copy(q.QeReportSignature[:], data[384:448])

	// QE auth data
	authLen := binary.LittleEndian.Uint16(data[448:450])
	off := 450
	if off+int(authLen) > len(data) {
		return fmt.Errorf("QE auth data exceeds bounds")
	}
	q.QeAuthData = make([]byte, authLen)
	copy(q.QeAuthData, data[off:off+int(authLen)])
	off += int(authLen)

	// Inner CertificationData (cert chain)
	if off+6 > len(data) {
		return fmt.Errorf("no inner cert data")
	}
	innerCertBodySize := binary.LittleEndian.Uint32(data[off+2 : off+6])
	off += 6
	if off+int(innerCertBodySize) > len(data) {
		return fmt.Errorf("inner cert data exceeds bounds")
	}
	q.CertificateData = data[off : off+int(innerCertBodySize)]

	return nil
}
