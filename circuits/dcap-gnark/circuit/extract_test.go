package circuit

// Validates the dynamic offset-assertion extraction (extractField) against
// the REAL PCK leaf: extract FMSPC anchored on its unique OID context and
// confirm it matches the host-parsed golden value; confirm a wrong offset
// is rejected; report the extraction constraint cost.

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// maxLeafTBS and fmspcCtx are defined in layout.go (shared with the circuit).

type fmspcExtractCircuit struct {
	TBS           [maxLeafTBS]uints.U8
	FmspcOff      frontend.Variable
	SignedLen     frontend.Variable
	ExpectedFmspc [6]uints.U8
}

func (c *fmspcExtractCircuit) Define(api frontend.API) error {
	got := extractField(api, c.TBS[:], c.FmspcOff, c.SignedLen, fmspcCtx, 6)
	for j := 0; j < 6; j++ {
		api.AssertIsEqual(got[j], c.ExpectedFmspc[j].Val)
	}
	return nil
}

func loadLeafTBS(t *testing.T) []byte {
	t.Helper()
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	return chain[0].RawTBSCertificate
}

func assignFmspc(t *testing.T, tbs []byte, off int) *fmspcExtractCircuit {
	t.Helper()
	if off < 0 {
		t.Fatal("fmspc context not found in TBS")
	}
	w := &fmspcExtractCircuit{FmspcOff: off, SignedLen: len(tbs)}
	for i := 0; i < maxLeafTBS; i++ {
		if i < len(tbs) {
			w.TBS[i] = uints.NewU8(tbs[i])
		} else {
			w.TBS[i] = uints.NewU8(0)
		}
	}
	val := tbs[off+len(fmspcCtx) : off+len(fmspcCtx)+6]
	for j := 0; j < 6; j++ {
		w.ExpectedFmspc[j] = uints.NewU8(val[j])
	}
	return w
}

func TestExtractFmspc(t *testing.T) {
	tbs := loadLeafTBS(t)
	off := bytes.Index(tbs, fmspcCtx)
	w := assignFmspc(t, tbs, off)
	if err := test.IsSolved(&fmspcExtractCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("expected satisfiable FMSPC extraction: %v", err)
	}
	t.Logf("FMSPC extracted at offset %d, value=%x", off, tbs[off+len(fmspcCtx):off+len(fmspcCtx)+6])
}

func TestExtractFmspcWrongOffset(t *testing.T) {
	tbs := loadLeafTBS(t)
	off := bytes.Index(tbs, fmspcCtx)
	w := assignFmspc(t, tbs, off)
	w.FmspcOff = off - 1 // anchor literal no longer matches -> unsatisfiable
	if err := test.IsSolved(&fmspcExtractCircuit{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected unsatisfiable for wrong offset")
	}
}

// TestExtractFmspcPlantedPadding is the G1 regression: an attacker keeps the
// genuine TBS as the signed prefix but plants a second fmspcCtx anchor plus
// attacker-chosen bytes in the unsigned padding and points the offset there.
// The off+ctx+field <= signedLen bound must make this unsatisfiable.
func TestExtractFmspcPlantedPadding(t *testing.T) {
	tbs := loadLeafTBS(t)
	realOff := bytes.Index(tbs, fmspcCtx)
	w := assignFmspc(t, tbs, realOff) // SignedLen = len(tbs), TBS padded with zeros
	// plant fmspcCtx + 6 attacker bytes well past the signed length
	plantOff := len(tbs) + 16
	for j, b := range fmspcCtx {
		w.TBS[plantOff+j] = uints.NewU8(b)
	}
	attacker := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11}
	for j := 0; j < 6; j++ {
		w.TBS[plantOff+len(fmspcCtx)+j] = uints.NewU8(attacker[j])
		w.ExpectedFmspc[j] = uints.NewU8(attacker[j]) // ask for the planted value
	}
	w.FmspcOff = plantOff // point at the planted anchor in unsigned padding
	if err := test.IsSolved(&fmspcExtractCircuit{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("G1: planted-padding extraction past signedLen must be unsatisfiable")
	}
}

func TestExtractFmspcConstraints(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &fmspcExtractCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("FMSPC extraction (maxLeafTBS=%d): %d constraints", maxLeafTBS, ccs.GetNbConstraints())
}
