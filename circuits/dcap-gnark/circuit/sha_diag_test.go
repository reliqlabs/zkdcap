package circuit

// Diagnostic: does sha256VarLen over the real (large) cert TBS match the host
// SHA-256? Isolates a hashing bug from an ECDSA bug.

import (
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type shaCircuit struct {
	Data     [maxLeafTBS]uints.U8
	Length   frontend.Variable
	Expected [32]uints.U8
}

func (c *shaCircuit) Define(api frontend.API) error {
	got, err := sha256VarLen(api, c.Data[:], c.Length)
	if err != nil {
		return err
	}
	return assertBytesEqual(api, got[:], c.Expected[:])
}

func TestSha256RealTBS(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	for idx, name := range []string{"leaf", "intermediate", "root"} {
		tbs := chain[idx].RawTBSCertificate
		want := sha256.Sum256(tbs)
		w := &shaCircuit{Length: len(tbs)}
		for i := 0; i < maxLeafTBS; i++ {
			if i < len(tbs) {
				w.Data[i] = uints.NewU8(tbs[i])
			} else {
				w.Data[i] = uints.NewU8(0)
			}
		}
		for i := 0; i < 32; i++ {
			w.Expected[i] = uints.NewU8(want[i])
		}
		if err := test.IsSolved(&shaCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
			t.Errorf("%s (len=%d): sha256VarLen != host SHA-256: %v", name, len(tbs), err)
		} else {
			t.Logf("%s (len=%d): SHA matches", name, len(tbs))
		}
	}
}
