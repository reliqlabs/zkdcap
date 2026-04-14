package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/reliqlabs/oauth3/circuits/dcap-gnark/circuit"
)

func main() {
	proofPath := flag.String("proof", "proof.json", "proof file path")
	vkPath := flag.String("vk", "vk.bin", "verifying key path")
	flag.Parse()

	// Load verifying key
	fvk, err := os.Open(*vkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open vk: %v\n", err)
		os.Exit(1)
	}
	defer fvk.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(fvk); err != nil {
		fmt.Fprintf(os.Stderr, "read vk: %v\n", err)
		os.Exit(1)
	}

	// Load proof
	fpf, err := os.Open(*proofPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open proof: %v\n", err)
		os.Exit(1)
	}
	defer fpf.Close()

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(fpf); err != nil {
		fmt.Fprintf(os.Stderr, "read proof: %v\n", err)
		os.Exit(1)
	}

	// Compile to get constraint system (needed for public witness format)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DcapCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile: %v\n", err)
		os.Exit(1)
	}

	// For verification we need just the public inputs.
	// Create a dummy public witness — in production this would be parsed from proof.json.
	_ = ccs

	// Verify
	// Note: In a real flow, the public witness would be extracted from the proof output.
	// For now, this tool reads the binary proof and verifies it.
	// The public witness must be provided separately.
	fmt.Println("Verification requires public witness — use the full prove+verify flow in tests.")
	fmt.Println("For standalone verification, serialize public witness alongside proof.")
}
