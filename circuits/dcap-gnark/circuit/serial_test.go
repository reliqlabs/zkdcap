package circuit

// Validates canonical serial extraction (extractCertSerial) against the real
// PCK leaf, handling the 20/21-byte DER serial encoding.

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type serialExtractCircuit struct {
	TBS            [maxLeafTBS]uints.U8
	SerialOff      frontend.Variable
	SignedLen      frontend.Variable
	ExpectedSerial [20]uints.U8
}

func (c *serialExtractCircuit) Define(api frontend.API) error {
	got := extractCertSerial(api, c.TBS[:], c.SerialOff, c.SignedLen)
	for i := 0; i < 20; i++ {
		api.AssertIsEqual(got[i], c.ExpectedSerial[i].Val)
	}
	return nil
}

func TestExtractSerial(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	leaf := chain[0]
	tbs := leaf.RawTBSCertificate
	off := bytes.Index(tbs, certVersionSerialCtx)
	if off < 0 {
		t.Fatal("version/serial context not found")
	}

	// canonical 20-byte big-endian serial (left-padded)
	ser := leaf.SerialNumber.Bytes()
	var exp [20]byte
	copy(exp[20-len(ser):], ser)

	w := &serialExtractCircuit{SerialOff: off, SignedLen: len(tbs)}
	for i := 0; i < maxLeafTBS; i++ {
		if i < len(tbs) {
			w.TBS[i] = uints.NewU8(tbs[i])
		} else {
			w.TBS[i] = uints.NewU8(0)
		}
	}
	for i := 0; i < 20; i++ {
		w.ExpectedSerial[i] = uints.NewU8(exp[i])
	}

	if err := test.IsSolved(&serialExtractCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("serial extraction expected satisfiable: %v", err)
	}
	t.Logf("serial extracted at off %d: %x (len byte path %d bytes)", off, exp, len(ser))
}

func TestExtractSerialConstraints(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &serialExtractCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("serial extraction: %d constraints", ccs.GetNbConstraints())
}
