package circuit

// Measures how Groth16 prove time scales with available cores (simulating
// smaller machines via GOMAXPROCS) and reports the proving-key size (the RAM
// driver), on the collateral circuit (3.2M constraints).
// Run: go test ./circuit/ -run TestProveScaling -v -timeout 1800s

import (
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func TestProveScaling(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &collateralCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	var cw countWriter
	if _, err := pk.WriteTo(&cw); err != nil {
		t.Fatalf("pk size: %v", err)
	}
	t.Logf("collateral: constraints=%d  pk size=%.0f MB", ccs.GetNbConstraints(), float64(cw.n)/1e6)

	w, err := frontend.NewWitness(assignCollateral(t), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}

	orig := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(orig)
	for _, n := range []int{2, 4, 8, 18} {
		runtime.GOMAXPROCS(n)
		// discard a warmup-free single timed prove
		t0 := time.Now()
		if _, err := groth16.Prove(ccs, pk, w); err != nil {
			t.Fatalf("prove (GOMAXPROCS=%d): %v", n, err)
		}
		d := time.Since(t0)
		usPerK := float64(d.Microseconds()) / (float64(ccs.GetNbConstraints()) / 1000)
		t.Logf("GOMAXPROCS=%-2d  prove=%-8v  (%.2f us / 1k constraints)", n, d.Round(time.Millisecond), usPerK)
	}
	_ = io.Discard
}
