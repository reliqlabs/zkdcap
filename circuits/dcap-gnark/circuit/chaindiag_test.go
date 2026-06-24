package circuit

// Diagnostic: isolate which chain link fails by verifying each cert
// signature directly with the issuer key taken straight from the parent
// cert (bypassing extraction and the hard-coded root), so we can tell apart
// a sig/TBS-handling bug from an extraction/constant bug.

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type oneVerifyCircuit struct {
	TBS    [maxLeafTBS]uints.U8
	TBSLen frontend.Variable
	Issuer ECDSAPublicKey
	Sig    ECDSASignature
}

func (c *oneVerifyCircuit) Define(api frontend.API) error {
	return verifyCertSig(api, c.TBS[:], c.TBSLen, &c.Issuer, &c.Sig)
}

func assignOneVerify(tbs []byte, pubX, pubY, r, s *big.Int) *oneVerifyCircuit {
	w := &oneVerifyCircuit{TBSLen: len(tbs)}
	for i := 0; i < maxLeafTBS; i++ {
		if i < len(tbs) {
			w.TBS[i] = uints.NewU8(tbs[i])
		} else {
			w.TBS[i] = uints.NewU8(0)
		}
	}
	w.Issuer.X = emulated.ValueOf[P256Fp](pubX)
	w.Issuer.Y = emulated.ValueOf[P256Fp](pubY)
	w.Sig.R = emulated.ValueOf[P256Fr](r)
	w.Sig.S = emulated.ValueOf[P256Fr](s)
	return w
}

func TestChainDiag(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	leaf, inter, root := chain[0], chain[1], chain[2]
	interPub := inter.PublicKey.(*ecdsa.PublicKey)
	rootPub := root.PublicKey.(*ecdsa.PublicKey)
	lr, ls := sigRS(t, leaf.Signature)
	ir, is := sigRS(t, inter.Signature)

	t.Run("leaf_by_intermediate", func(t *testing.T) {
		w := assignOneVerify(leaf.RawTBSCertificate, interPub.X, interPub.Y, lr, ls)
		if err := test.IsSolved(&oneVerifyCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("leaf-by-intermediate FAILED: %v", err)
		}
		t.Log("leaf-by-intermediate OK")
	})

	t.Run("intermediate_by_root", func(t *testing.T) {
		w := assignOneVerify(inter.RawTBSCertificate, rootPub.X, rootPub.Y, ir, is)
		if err := test.IsSolved(&oneVerifyCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("intermediate-by-root FAILED: %v", err)
		}
		t.Log("intermediate-by-root OK")
	})

	// confirm the hard-coded root constant matches the fixture root key
	rx, _ := new(big.Int).SetString(intelRootCAX, 16)
	ry, _ := new(big.Int).SetString(intelRootCAY, 16)
	if rx.Cmp(rootPub.X) != 0 || ry.Cmp(rootPub.Y) != 0 {
		t.Errorf("hard-coded root != fixture root\n const X=%x\n fix   X=%x", rx, rootPub.X)
	} else {
		t.Log("hard-coded Intel root constant matches fixture root key")
	}
}
