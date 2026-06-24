package circuit

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestHostEcdsaVerify(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	t.Logf("chain has %d certs", len(chain))
	for i, c := range chain {
		t.Logf("[%d] subject=%q issuer=%q sigAlg=%v", i, c.Subject.CommonName, c.Issuer.CommonName, c.SignatureAlgorithm)
	}
	leaf, inter, root := chain[0], chain[1], chain[2]

	// authoritative Go checks
	t.Logf("leaf.CheckSignatureFrom(inter) = %v", leaf.CheckSignatureFrom(inter))
	t.Logf("inter.CheckSignatureFrom(root) = %v", inter.CheckSignatureFrom(root))

	// manual replication for leaf-by-inter
	r, s := sigRS(t, leaf.Signature)
	h := sha256.Sum256(leaf.RawTBSCertificate)
	ip := inter.PublicKey.(*ecdsa.PublicKey)
	t.Logf("manual leaf-by-inter ecdsa.Verify = %v", ecdsa.Verify(ip, h[:], r, s))
	t.Logf("  r=%x", r)
	t.Logf("  s=%x", s)
	t.Logf("  sha256(TBS)=%x", h)
	t.Logf("  len(leaf.Signature)=%d sig=%x", len(leaf.Signature), leaf.Signature)
	_ = big.NewInt(0)
}
