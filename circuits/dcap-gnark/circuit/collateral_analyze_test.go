package circuit

// Host-side layout analysis for A2 (collateral) verification: the
// TCB-Signing issuer chain, collateral JSON sizes, raw signature format,
// and confirmation that the issuer chains root at the pinned Intel Root CA.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestCollateralLayout(t *testing.T) {
	col := loadCollateral(t)

	tcbChain := parsePEMChain(t, col["tcb_info_issuer_chain"])
	qeChain := parsePEMChain(t, col["qe_identity_issuer_chain"])
	t.Logf("tcb_info_issuer_chain: %d certs; qe_identity_issuer_chain: %d certs", len(tcbChain), len(qeChain))
	for i, c := range tcbChain {
		t.Logf("  tcb[%d] subject=%q issuer=%q TBS=%d", i, c.Subject.CommonName, c.Issuer.CommonName, len(c.RawTBSCertificate))
	}
	t.Logf("issuer chains identical: %v", col["tcb_info_issuer_chain"] == col["qe_identity_issuer_chain"])

	// TCB-Signing cert (leaf of the issuer chain) pubkey offset + root match
	signing := tcbChain[0]
	root := tcbChain[1].PublicKey.(*ecdsa.PublicKey)
	off := bytes.Index(signing.RawTBSCertificate, subjectPubKeyCtx)
	t.Logf("TCB-Signing subjPubKey off=%d; signing signed by %q", off, signing.Issuer.CommonName)
	rx, _ := new(big.Int).SetString(intelRootCAX, 16)
	ry, _ := new(big.Int).SetString(intelRootCAY, 16)
	t.Logf("issuer-chain root == pinned Intel root: %v", rx.Cmp(root.X) == 0 && ry.Cmp(root.Y) == 0)

	// host-verify TCB-Signing chains to root, and collateral sigs verify
	t.Logf("signing.CheckSignatureFrom(root) = %v", signing.CheckSignatureFrom(tcbChain[1]))

	// collateral JSON sizes + raw signature parse
	t.Logf("tcb_info JSON len=%d; qe_identity JSON len=%d", len(col["tcb_info"]), len(col["qe_identity"]))
	sigTcb, _ := hex.DecodeString(col["tcb_info_signature"])
	sigQe, _ := hex.DecodeString(col["qe_identity_signature"])
	t.Logf("tcb_info_signature raw bytes=%d (r||s); qe_identity_signature raw bytes=%d", len(sigTcb), len(sigQe))

	// confirm the raw collateral signature verifies host-side over the raw JSON
	signPub := signing.PublicKey.(*ecdsa.PublicKey)
	verifyRaw := func(name, doc string, sig []byte) {
		hd := sha256.Sum256([]byte(doc))
		h := hd[:]
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:64])
		t.Logf("%s host ecdsa.Verify = %v", name, ecdsa.Verify(signPub, h, r, s))
	}
	verifyRaw("tcb_info", col["tcb_info"], sigTcb)
	verifyRaw("qe_identity", col["qe_identity"], sigQe)
}
