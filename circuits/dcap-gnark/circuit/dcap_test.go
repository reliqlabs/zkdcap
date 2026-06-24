package circuit_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"github.com/reliqlabs/zkdcap/circuits/dcap-gnark/circuit"
	"github.com/reliqlabs/zkdcap/circuits/dcap-gnark/witness"
)

const fixtureDir = "../testdata/fixtures/zkdcap/"

// fixedTimestamp: a verification time INSIDE the fixture collateral's validity
// window (G4). The TCB-Info window is [2025-06-19T10:16:03Z, 2025-07-19], the
// QE-Identity window [2025-06-19T10:32:27Z, 2025-07-19]; 2025-06-25T00:00:00Z
// (unix 1750809600) sits inside both. The circuit interprets this unix value as
// a packed YYYYMMDDhhmmss date (the witness builder converts it).
const fixedTimestamp = uint64(1750809600)

// loadFixtures reads the real dcap-qvl sample quote + Intel collateral bundle.
func loadFixtures(t *testing.T) ([]byte, map[string]string) {
	t.Helper()

	quoteBytes, err := os.ReadFile(fixtureDir + "quote.bin")
	if err != nil {
		t.Fatalf("read quote.bin: %v", err)
	}

	collBytes, err := os.ReadFile(fixtureDir + "collateral.json")
	if err != nil {
		t.Fatalf("read collateral.json: %v", err)
	}
	var coll map[string]string
	if err := json.Unmarshal(collBytes, &coll); err != nil {
		t.Fatalf("parse collateral.json: %v", err)
	}

	return quoteBytes, coll
}

func TestCircuitCompile(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DcapCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Constraints: %d", ccs.GetNbConstraints())
}

// TestCircuitSolves runs the solver (no trusted setup) over the full
// self-anchoring circuit on the real quote + collateral. Fast smoke test.
func TestCircuitSolves(t *testing.T) {
	quoteBytes, coll := loadFixtures(t)

	assignment, err := witness.BuildWitness(quoteBytes, coll, fixedTimestamp)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}

	if err := test.IsSolved(&circuit.DcapCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("expected satisfiable: %v", err)
	}
}

func TestCircuitProveVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full Groth16 prove/verify in -short mode")
	}
	quoteBytes, coll := loadFixtures(t)

	assignment, err := witness.BuildWitness(quoteBytes, coll, fixedTimestamp)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}

	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit.DcapCircuit{}, assignment,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

func TestCircuitNegativeFlippedSig(t *testing.T) {
	quoteBytes, coll := loadFixtures(t)

	assignment, err := witness.BuildWitness(quoteBytes, coll, fixedTimestamp)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}

	// Flip the ISV signature so step 7 verification fails.
	assignment.IsvSig.R = assignment.QeReportSig.R

	if err := test.IsSolved(&circuit.DcapCircuit{}, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected unsatisfiable for flipped ISV signature")
	}
}

// TestCircuitNegativeForgedPckKey proves the self-anchoring property: an
// attacker cannot substitute their own PCK key. PckPubKey is constrained equal
// to the chain leaf's subjectPublicKey, so swapping it (here, to the attestation
// key) breaks the leaf binding.
func TestCircuitNegativeForgedPckKey(t *testing.T) {
	quoteBytes, coll := loadFixtures(t)

	assignment, err := witness.BuildWitness(quoteBytes, coll, fixedTimestamp)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}

	assignment.PckPubKey.X = assignment.AttestKeyPub.X
	assignment.PckPubKey.Y = assignment.AttestKeyPub.Y

	if err := test.IsSolved(&circuit.DcapCircuit{}, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected unsatisfiable for forged PCK key (chain binding must reject)")
	}
}

// TestCircuitNegativeTamperedCollateral flips a byte in the Intel-signed
// TCB-Info JSON; the collateral signature check (A2) must reject it.
func TestCircuitNegativeTamperedCollateral(t *testing.T) {
	quoteBytes, coll := loadFixtures(t)

	assignment, err := witness.BuildWitness(quoteBytes, coll, fixedTimestamp)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}

	// Corrupt a byte well inside the TCB-Info JSON body (ASCII, so 0xFF differs).
	assignment.TcbInfoRaw[100] = uints.NewU8(0xFF)

	if err := test.IsSolved(&circuit.DcapCircuit{}, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected unsatisfiable for tampered TCB-Info collateral")
	}
}
