package circuit

// Verifies the self-anchoring PCK chain (verifyChainToRoot) against the REAL
// fixture chain: leaf <- Intel SGX PCK Platform CA <- pinned Intel SGX Root
// CA constant, with the leaf subject key bound to PckPubKey. This is the
// Step 2+3 milestone that discharges assume-clause A1 in-circuit.

import (
	"bytes"
	"crypto/ecdsa"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// maxIntTBS is defined in layout.go (shared with the circuit).

type chainCircuit struct {
	LeafTBS       [maxLeafTBS]uints.U8
	LeafTBSLen    frontend.Variable
	LeafSig       ECDSASignature
	LeafPubKeyOff frontend.Variable

	IntTBS       [maxIntTBS]uints.U8
	IntTBSLen    frontend.Variable
	IntSig       ECDSASignature
	IntPubKeyOff frontend.Variable

	PckPubKey ECDSAPublicKey
}

func (c *chainCircuit) Define(api frontend.API) error {
	return verifyChainToRoot(api,
		c.LeafTBS[:], c.LeafTBSLen, &c.LeafSig, c.LeafPubKeyOff,
		c.IntTBS[:], c.IntTBSLen, &c.IntSig, c.IntPubKeyOff,
		&c.PckPubKey)
}

func assignChain(t *testing.T) (*chainCircuit, *ecdsa.PublicKey) {
	t.Helper()
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	leaf, inter := chain[0], chain[1]
	leafTBS := leaf.RawTBSCertificate
	intTBS := inter.RawTBSCertificate
	lr, ls := sigRS(t, leaf.Signature)
	ir, is := sigRS(t, inter.Signature)
	leafPub := leaf.PublicKey.(*ecdsa.PublicKey)

	w := &chainCircuit{
		LeafTBSLen:    len(leafTBS),
		IntTBSLen:     len(intTBS),
		LeafPubKeyOff: bytes.Index(leafTBS, subjectPubKeyCtx),
		IntPubKeyOff:  bytes.Index(intTBS, subjectPubKeyCtx),
	}
	copy(w.LeafTBS[:], tbsToU8(leafTBS, maxLeafTBS, t))
	copy(w.IntTBS[:], tbsToU8(intTBS, maxIntTBS, t))
	w.LeafSig.R = emulated.ValueOf[P256Fr](lr)
	w.LeafSig.S = emulated.ValueOf[P256Fr](ls)
	w.IntSig.R = emulated.ValueOf[P256Fr](ir)
	w.IntSig.S = emulated.ValueOf[P256Fr](is)
	w.PckPubKey.X = emulated.ValueOf[P256Fp](leafPub.X)
	w.PckPubKey.Y = emulated.ValueOf[P256Fp](leafPub.Y)
	return w, leafPub
}

func TestVerifyChainToRoot(t *testing.T) {
	w, _ := assignChain(t)
	if err := test.IsSolved(&chainCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("chain expected satisfiable: %v", err)
	}
}

// Wrong PckPubKey (use the intermediate's key) must fail the leaf binding.
func TestVerifyChainWrongPubKey(t *testing.T) {
	w, _ := assignChain(t)
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	interPub := chain[1].PublicKey.(*ecdsa.PublicKey)
	w.PckPubKey.X = emulated.ValueOf[P256Fp](interPub.X)
	w.PckPubKey.Y = emulated.ValueOf[P256Fp](interPub.Y)
	if err := test.IsSolved(&chainCircuit{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected unsatisfiable for wrong PckPubKey")
	}
}

func TestChainConstraints(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &chainCircuit{})
	if err != nil {
		t.Fatalf("compile chain: %v", err)
	}
	t.Logf("verifyChainToRoot (leaf<-PlatformCA<-Root): %d constraints", ccs.GetNbConstraints())
}
