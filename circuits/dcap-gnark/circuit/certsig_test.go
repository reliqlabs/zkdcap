package circuit

// Internal test (package circuit) so it can exercise the unexported
// verifyCertSig gadget directly. Uses a self-generated P-256 certificate as
// a stand-in for an Intel PCK/intermediate cert: the gadget is cert-agnostic
// (hash the TBS, ECDSA-verify against the issuer key), so this validates the
// universal cert-chain link and measures its per-verify constraint cost
// before real Intel fixtures are wired in (Step 2+).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// maxCertTBS is the fixed in-circuit capacity for a certificate TBS buffer.
// Intel PCK leaf certs (with the SGX extension) are the largest at ~700-900
// bytes; 1024 leaves headroom for serial/validity length drift.
const maxCertTBS = 1024

type certSigTestCircuit struct {
	TBS    [maxCertTBS]uints.U8
	TBSLen frontend.Variable
	Issuer ECDSAPublicKey
	Sig    ECDSASignature
}

func (c *certSigTestCircuit) Define(api frontend.API) error {
	return verifyCertSig(api, c.TBS[:], c.TBSLen, &c.Issuer, &c.Sig)
}

// makeP256Cert generates a self-signed P-256 cert and returns its
// tbsCertificate bytes, the (r,s) signature, and the signer (== issuer for
// self-signed) public-key coordinates.
func makeP256Cert(t *testing.T) (tbs []byte, r, s, pubX, pubY *big.Int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "zkdcap-test"},
		NotBefore:          time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	var ecSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(cert.Signature, &ecSig); err != nil {
		t.Fatalf("unmarshal sig: %v", err)
	}
	if len(cert.RawTBSCertificate) > maxCertTBS {
		t.Fatalf("TBS %d exceeds maxCertTBS %d", len(cert.RawTBSCertificate), maxCertTBS)
	}
	return cert.RawTBSCertificate, ecSig.R, ecSig.S, key.PublicKey.X, key.PublicKey.Y
}

func assignCertSig(tbs []byte, r, s, pubX, pubY *big.Int) *certSigTestCircuit {
	w := &certSigTestCircuit{}
	for i := 0; i < maxCertTBS; i++ {
		if i < len(tbs) {
			w.TBS[i] = uints.NewU8(tbs[i])
		} else {
			w.TBS[i] = uints.NewU8(0)
		}
	}
	w.TBSLen = len(tbs)
	w.Issuer.X = emulated.ValueOf[P256Fp](pubX)
	w.Issuer.Y = emulated.ValueOf[P256Fp](pubY)
	w.Sig.R = emulated.ValueOf[P256Fr](r)
	w.Sig.S = emulated.ValueOf[P256Fr](s)
	return w
}

// TestVerifyCertSig: a genuine P-256 cert signature satisfies the gadget.
// Uses IsSolved (constraint-solver only) rather than a full Groth16 setup so
// the ~2-3M-constraint circuit checks quickly.
func TestVerifyCertSig(t *testing.T) {
	tbs, r, s, px, py := makeP256Cert(t)
	w := assignCertSig(tbs, r, s, px, py)
	if err := test.IsSolved(&certSigTestCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("expected satisfiable, got: %v", err)
	}
}

// TestVerifyCertSigNegative: tampering a TBS byte changes the hash, so the
// issuer signature no longer verifies -> unsatisfiable.
func TestVerifyCertSigNegative(t *testing.T) {
	tbs, r, s, px, py := makeP256Cert(t)
	tbs[10] ^= 0x01
	w := assignCertSig(tbs, r, s, px, py)
	if err := test.IsSolved(&certSigTestCircuit{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected unsatisfiable for tampered TBS, got nil")
	}
}

// TestVerifyCertSigConstraints reports the per-cert-verify constraint cost
// (1 ECDSA-P256 + SHA-256 over maxCertTBS bytes), the empirical datum for
// budgeting the full 2-cert chain + 2 collateral signatures.
func TestVerifyCertSigConstraints(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &certSigTestCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("verifyCertSig constraints (maxCertTBS=%d): %d", maxCertTBS, ccs.GetNbConstraints())
}
