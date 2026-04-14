package circuit_test

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/circuit"
	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/witness"
)

const fixtureDir = "../testdata/fixtures/zkdcap/"

func loadFixtures(t *testing.T) ([]byte, *witness.PreVerifiedInputs, uint64) {
	t.Helper()

	quoteBytes, err := os.ReadFile(fixtureDir + "quote.bin")
	if err != nil {
		t.Fatalf("read quote.bin: %v", err)
	}

	preBytes, err := os.ReadFile(fixtureDir + "pre_verified.json")
	if err != nil {
		t.Fatalf("read pre_verified.json: %v", err)
	}

	var preJSON witness.PreVerifiedJSON
	if err := json.Unmarshal(preBytes, &preJSON); err != nil {
		t.Fatalf("parse pre_verified.json: %v", err)
	}

	pre, err := preJSON.ToPreVerifiedInputs()
	if err != nil {
		t.Fatalf("convert pre_verified: %v", err)
	}

	tsBytes, err := os.ReadFile(fixtureDir + "timestamp.txt")
	if err != nil {
		t.Fatalf("read timestamp.txt: %v", err)
	}
	ts, err := strconv.ParseUint(strings.TrimSpace(string(tsBytes)), 10, 64)
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}

	return quoteBytes, pre, ts
}

func TestCircuitCompile(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DcapCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Constraints: %d", ccs.GetNbConstraints())
}

func TestCircuitProveVerify(t *testing.T) {
	quoteBytes, pre, ts := loadFixtures(t)

	assignment, err := witness.BuildWitness(quoteBytes, pre, ts)
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
	quoteBytes, pre, ts := loadFixtures(t)

	assignment, err := witness.BuildWitness(quoteBytes, pre, ts)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}

	// Flip a byte in the ISV signature to make verification fail
	assignment.IsvSig.R = assignment.QeReportSig.R // wrong R value

	assert := test.NewAssert(t)
	assert.ProverFailed(&circuit.DcapCircuit{}, assignment,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}
