package circuit

// Real Groth16 setup/prove/verify timing on the largest built gadgets, to
// answer "how long does the proof take" and extrapolate to the full circuit.
// Run: go test ./circuit/ -run TestProveTimings -v -timeout 1800s

import (
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func timeProve(t *testing.T, name string, circuit, witness frontend.Circuit) {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("%s compile: %v", name, err)
	}
	t1 := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("%s setup: %v", name, err)
	}
	tSetup := time.Since(t1)

	w, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("%s witness: %v", name, err)
	}
	t2 := time.Now()
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("%s prove: %v", name, err)
	}
	tProve := time.Since(t2)

	pub, _ := w.Public()
	t3 := time.Now()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("%s verify: %v", name, err)
	}
	tVerify := time.Since(t3)

	t.Logf("%-11s constraints=%-9d setup=%-8v PROVE=%-8v verify=%v",
		name, ccs.GetNbConstraints(),
		tSetup.Round(time.Millisecond), tProve.Round(time.Millisecond), tVerify.Round(time.Millisecond))
}

func TestProveTimings(t *testing.T) {
	chainW, _ := assignChain(t)
	timeProve(t, "chain", &chainCircuit{}, chainW)
	timeProve(t, "collateral", &collateralCircuit{}, assignCollateral(t))
}
