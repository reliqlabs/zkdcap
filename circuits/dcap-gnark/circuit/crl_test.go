package circuit

// Internal test exercising the optional CRL path (verifyCrl) against the
// REAL Intel CRLs in the fixture collateral, and reporting its marginal
// constraint cost. The PCK CRL (Platform-CA-signed, ~3.2 KB TBS, 57 revoked
// serials) dominates; the Root CA CRL is small. Full optional-CRL-path cost
// = PCK CRL verify + Root CA CRL verify.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// crlSerialLen, pckCrlMaxTBS, pckCrlMaxRevoked, rootCrlMaxTBS, rootCrlMaxRevoked
// are defined in crl.go (shared with the integrated circuit).

// --- generic CRL test circuits (two sizes; gnark arrays need const sizes) ---

type pckCrlCircuit struct {
	TBS          [pckCrlMaxTBS]uints.U8
	TBSLen       frontend.Variable
	Issuer       ECDSAPublicKey
	Sig          ECDSASignature
	TargetSerial [crlSerialLen]uints.U8
	Revoked      [pckCrlMaxRevoked][crlSerialLen]uints.U8
}

func (c *pckCrlCircuit) Define(api frontend.API) error {
	rev := make([][]uints.U8, pckCrlMaxRevoked)
	for i := range c.Revoked {
		rev[i] = c.Revoked[i][:]
	}
	return verifyCrl(api, c.TBS[:], c.TBSLen, &c.Issuer, &c.Sig, c.TargetSerial[:], rev)
}

type rootCrlCircuit struct {
	TBS          [rootCrlMaxTBS]uints.U8
	TBSLen       frontend.Variable
	Issuer       ECDSAPublicKey
	Sig          ECDSASignature
	TargetSerial [crlSerialLen]uints.U8
	Revoked      [rootCrlMaxRevoked][crlSerialLen]uints.U8
}

func (c *rootCrlCircuit) Define(api frontend.API) error {
	rev := make([][]uints.U8, rootCrlMaxRevoked)
	for i := range c.Revoked {
		rev[i] = c.Revoked[i][:]
	}
	return verifyCrl(api, c.TBS[:], c.TBSLen, &c.Issuer, &c.Sig, c.TargetSerial[:], rev)
}

// --- fixture loading ---

func loadCollateral(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("../testdata/fixtures/zkdcap/collateral.json")
	if err != nil {
		t.Fatalf("read collateral: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse collateral: %v", err)
	}
	return m
}

func parsePEMChain(t *testing.T, pemStr string) []*x509.Certificate {
	t.Helper()
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
			t.Fatalf("parse cert: %v", err)
		}
		certs = append(certs, c)
	}
	return certs
}

func loadCRLHex(t *testing.T, hexStr string) *x509.RevocationList {
	t.Helper()
	der, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("crl hex: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	return crl
}

func serialBytes(t *testing.T, n *big.Int) [crlSerialLen]uints.U8 {
	t.Helper()
	raw := n.Bytes()
	if len(raw) > crlSerialLen {
		t.Fatalf("serial %d bytes exceeds %d", len(raw), crlSerialLen)
	}
	var out [crlSerialLen]uints.U8
	pad := crlSerialLen - len(raw) // left-pad big-endian
	for i := 0; i < crlSerialLen; i++ {
		if i < pad {
			out[i] = uints.NewU8(0)
		} else {
			out[i] = uints.NewU8(raw[i-pad])
		}
	}
	return out
}

func pubFromCert(c *x509.Certificate) (*big.Int, *big.Int) {
	pk := c.PublicKey.(*ecdsa.PublicKey)
	return pk.X, pk.Y
}

func sigRS(t *testing.T, der []byte) (*big.Int, *big.Int) {
	t.Helper()
	var s struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &s); err != nil {
		t.Fatalf("crl sig: %v", err)
	}
	return s.R, s.S
}

func tbsToU8(tbs []byte, maxLen int, t *testing.T) []uints.U8 {
	t.Helper()
	if len(tbs) > maxLen {
		t.Fatalf("tbs %d exceeds max %d", len(tbs), maxLen)
	}
	out := make([]uints.U8, maxLen)
	for i := 0; i < maxLen; i++ {
		if i < len(tbs) {
			out[i] = uints.NewU8(tbs[i])
		} else {
			out[i] = uints.NewU8(0)
		}
	}
	return out
}

func zeroSerial() [crlSerialLen]uints.U8 {
	var s [crlSerialLen]uints.U8
	for i := range s {
		s[i] = uints.NewU8(0)
	}
	return s
}

// --- tests ---

// TestVerifyPckCrl: the real PCK CRL (signed by the Platform CA) verifies,
// and the genuine PCK leaf serial is not revoked. Reports the dominant CRL
// cost.
func TestVerifyPckCrl(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"]) // [leaf, platformCA, root]
	if len(chain) != 3 {
		t.Fatalf("expected 3 PCK certs, got %d", len(chain))
	}
	crl := loadCRLHex(t, col["pck_crl"])

	px, py := pubFromCert(chain[1]) // Platform CA signs the PCK CRL
	r, s := sigRS(t, crl.Signature)

	w := &pckCrlCircuit{TBSLen: len(crl.RawTBSRevocationList)}
	copy(w.TBS[:], tbsToU8(crl.RawTBSRevocationList, pckCrlMaxTBS, t))
	w.Issuer.X = emulated.ValueOf[P256Fp](px)
	w.Issuer.Y = emulated.ValueOf[P256Fp](py)
	w.Sig.R = emulated.ValueOf[P256Fr](r)
	w.Sig.S = emulated.ValueOf[P256Fr](s)
	w.TargetSerial = serialBytes(t, chain[0].SerialNumber) // leaf serial
	for i := 0; i < pckCrlMaxRevoked; i++ {
		if i < len(crl.RevokedCertificateEntries) {
			w.Revoked[i] = serialBytes(t, crl.RevokedCertificateEntries[i].SerialNumber)
		} else {
			w.Revoked[i] = zeroSerial()
		}
	}

	if err := test.IsSolved(&pckCrlCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("PCK CRL expected satisfiable: %v", err)
	}
	t.Logf("PCK CRL verified: %d revoked serials, tbs=%d bytes", len(crl.RevokedCertificateEntries), len(crl.RawTBSRevocationList))
}

func TestVerifyRootCrl(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	crl := loadCRLHex(t, col["root_ca_crl"])

	px, py := pubFromCert(chain[2]) // Root CA signs the Root CRL
	r, s := sigRS(t, crl.Signature)

	w := &rootCrlCircuit{TBSLen: len(crl.RawTBSRevocationList)}
	copy(w.TBS[:], tbsToU8(crl.RawTBSRevocationList, rootCrlMaxTBS, t))
	w.Issuer.X = emulated.ValueOf[P256Fp](px)
	w.Issuer.Y = emulated.ValueOf[P256Fp](py)
	w.Sig.R = emulated.ValueOf[P256Fr](r)
	w.Sig.S = emulated.ValueOf[P256Fr](s)
	w.TargetSerial = serialBytes(t, chain[1].SerialNumber) // intermediate serial
	for i := 0; i < rootCrlMaxRevoked; i++ {
		if i < len(crl.RevokedCertificateEntries) {
			w.Revoked[i] = serialBytes(t, crl.RevokedCertificateEntries[i].SerialNumber)
		} else {
			w.Revoked[i] = zeroSerial()
		}
	}

	if err := test.IsSolved(&rootCrlCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("Root CRL expected satisfiable: %v", err)
	}
	t.Logf("Root CA CRL verified: %d revoked serials, tbs=%d bytes", len(crl.RevokedCertificateEntries), len(crl.RawTBSRevocationList))
}

// --- G4 revocation non-membership (substring-absence) ---

type crlNonMemberCircuit struct {
	TBS           [pckCrlMaxTBS]uints.U8
	TBSLen        frontend.Variable
	Issuer        ECDSAPublicKey
	Sig           ECDSASignature
	TargetSerial  [crlSerialLen]frontend.Variable
	ThisUpdateOff frontend.Variable
	Timestamp     frontend.Variable
}

func (c *crlNonMemberCircuit) Define(api frontend.API) error {
	return verifyCrlNonMembership(api, c.TBS[:], c.TBSLen, &c.Issuer, &c.Sig, c.TargetSerial[:], c.ThisUpdateOff, c.Timestamp)
}

func canonicalSerial20(raw []byte) [crlSerialLen]frontend.Variable {
	var out [crlSerialLen]frontend.Variable
	if len(raw) > crlSerialLen {
		raw = raw[len(raw)-crlSerialLen:]
	}
	pad := crlSerialLen - len(raw)
	for i := 0; i < crlSerialLen; i++ {
		if i < pad {
			out[i] = 0
		} else {
			out[i] = int(raw[i-pad])
		}
	}
	return out
}

// crlInWindowTs is a packed YYYYMMDDhhmmss verification time inside the fixture
// PCK CRL validity window (thisUpdate 2025-06-19, nextUpdate 2025-07-19).
const crlInWindowTs = 20250625000000

// solveCrlNonMemberTBS drives verifyCrlNonMembership over arbitrary TBS bytes +
// issuer + signature, used by both the honest path and the C4/C5 negatives.
func solveCrlNonMemberTBS(t *testing.T, tbs []byte, sigDER []byte, issuer *x509.Certificate, serial [crlSerialLen]frontend.Variable, ts uint64) error {
	t.Helper()
	px, py := pubFromCert(issuer)
	r, s := sigRS(t, sigDER)
	thisUpd := bytes.Index(tbs, []byte{0x17, 0x0d})
	if thisUpd < 0 {
		thisUpd = 0
	}
	w := &crlNonMemberCircuit{
		TBSLen:        len(tbs),
		TargetSerial:  serial,
		ThisUpdateOff: thisUpd,
		Timestamp:     ts,
	}
	copy(w.TBS[:], tbsToU8(tbs, pckCrlMaxTBS, t))
	w.Issuer.X = emulated.ValueOf[P256Fp](px)
	w.Issuer.Y = emulated.ValueOf[P256Fp](py)
	w.Sig.R = emulated.ValueOf[P256Fr](r)
	w.Sig.S = emulated.ValueOf[P256Fr](s)
	return test.IsSolved(&crlNonMemberCircuit{}, w, ecc.BN254.ScalarField())
}

func solveCrlNonMember(t *testing.T, crl *x509.RevocationList, issuer *x509.Certificate, serial [crlSerialLen]frontend.Variable) error {
	t.Helper()
	return solveCrlNonMemberTBS(t, crl.RawTBSRevocationList, crl.Signature, issuer, serial, crlInWindowTs)
}

// TestG4RevokedSerialRejected proves the revocation half of G4 against the real
// Intel-signed PCK CRL: the honest (non-revoked) leaf serial is satisfiable, but
// a serial that IS in the signed revoked list is unsatisfiable. The CRL
// signature binds the list, and substring-absence forbids supplying an empty
// list, so a revoked platform cannot attest.
func TestG4RevokedSerialRejected(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"]) // [leaf, platformCA, root]
	crl := loadCRLHex(t, col["pck_crl"])
	if len(crl.RevokedCertificateEntries) == 0 {
		t.Skip("fixture PCK CRL has no revoked entries")
	}

	// Honest leaf serial: not revoked -> satisfiable.
	honest := canonicalSerial20(chain[0].SerialNumber.Bytes())
	if err := solveCrlNonMember(t, crl, chain[1], honest); err != nil {
		t.Fatalf("honest leaf serial must be satisfiable: %v", err)
	}
	// A real revoked serial -> unsatisfiable.
	bad := canonicalSerial20(crl.RevokedCertificateEntries[0].SerialNumber.Bytes())
	if err := solveCrlNonMember(t, crl, chain[1], bad); err == nil {
		t.Fatal("G4: revoked serial must be unsatisfiable")
	}
}

// TestG4C4CertPosingAsCrl (C4): a real Platform-CA-signed PCK leaf tbsCertificate
// (NOT a CRL) is supplied in the CRL TBS slot with the target serial absent. The
// signature verifies (same issuer), but the v2-CRL tbsCertList head anchor must
// reject it so a non-CRL cannot pose as the CRL to bypass revocation.
func TestG4C4CertPosingAsCrl(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"]) // [leaf, platformCA, root]
	leaf := chain[0]
	// leaf TBS is signed by the Platform CA (chain[1]) — exactly the PCK CRL
	// issuer. Use a target serial absent from the leaf TBS.
	absent := canonicalSerial20([]byte{0xde, 0xad, 0xbe, 0xef})
	err := solveCrlNonMemberTBS(t, leaf.RawTBSCertificate, leaf.Signature, chain[1], absent, crlInWindowTs)
	if err == nil {
		t.Fatal("C4: a cert TBS posing as the CRL must be unsatisfiable")
	}
}

// TestG4C5StaleCrl (C5): the validly-signed fixture CRL with a verification time
// AFTER its nextUpdate (2025-07-19) must be rejected as stale.
func TestG4C5StaleCrl(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	crl := loadCRLHex(t, col["pck_crl"])
	honest := canonicalSerial20(chain[0].SerialNumber.Bytes())
	// 2025-08-01 is past nextUpdate 2025-07-19.
	stale := uint64(20250801000000)
	if err := solveCrlNonMemberTBS(t, crl.RawTBSRevocationList, crl.Signature, chain[1], honest, stale); err == nil {
		t.Fatal("C5: a CRL whose nextUpdate < Timestamp must be unsatisfiable")
	}
	// sanity: in-window time is satisfiable.
	if err := solveCrlNonMemberTBS(t, crl.RawTBSRevocationList, crl.Signature, chain[1], honest, crlInWindowTs); err != nil {
		t.Fatalf("C5 sanity: in-window CRL must be satisfiable: %v", err)
	}
}

// TestCrlConstraints reports the constraint cost of each CRL verify and the
// full optional-CRL-path total (PCK + Root).
func TestCrlConstraints(t *testing.T) {
	pck, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pckCrlCircuit{})
	if err != nil {
		t.Fatalf("compile pck crl: %v", err)
	}
	root, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rootCrlCircuit{})
	if err != nil {
		t.Fatalf("compile root crl: %v", err)
	}
	p := pck.GetNbConstraints()
	r := root.GetNbConstraints()
	t.Logf("PCK CRL  (maxTBS=%d, maxRevoked=%d): %d constraints", pckCrlMaxTBS, pckCrlMaxRevoked, p)
	t.Logf("Root CRL (maxTBS=%d, maxRevoked=%d): %d constraints", rootCrlMaxTBS, rootCrlMaxRevoked, r)
	t.Logf("FULL optional CRL path (PCK + Root): %d constraints", p+r)
}
