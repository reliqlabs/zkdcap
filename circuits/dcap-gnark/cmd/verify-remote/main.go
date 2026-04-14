package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// provedResponse is the top-level JSON from the oauth3 middleware (?prove=gnark-gpu-sync).
type provedResponse struct {
	Data       json.RawMessage `json:"data"`
	Proof      proofJSON       `json:"proof"`
	ProverType string          `json:"prover_type"`
}

// proofJSON is the proof object returned by the gnark prove server (passed through by Rust middleware).
type proofJSON struct {
	PiA           []string     `json:"pi_a"`
	PiB           [][]string   `json:"pi_b"`
	PiC           []string     `json:"pi_c"`
	Protocol      string       `json:"protocol"`
	Curve         string       `json:"curve"`
	Commitments   [][]string   `json:"commitments"`
	CommitmentPok []string     `json:"commitment_pok"`
	PublicSignals []string     `json:"public_signals"`
	PublicInputs  interface{}  `json:"public_inputs"` // named map, not used for verification
}

func main() {
	url := flag.String("url", "", "URL to fetch proof from (e.g. https://host/info?prove=gnark-gpu-sync)")
	proofFile := flag.String("proof", "", "local proof JSON file (alternative to -url)")
	vkPath := flag.String("vk", "vk.bin", "verifying key path")
	flag.Parse()

	if *url == "" && *proofFile == "" {
		fmt.Fprintln(os.Stderr, "usage: verify-remote -url <URL> -vk <vk.bin>")
		fmt.Fprintln(os.Stderr, "       verify-remote -proof <file.json> -vk <vk.bin>")
		os.Exit(1)
	}

	// Load verifying key
	fmt.Printf("Loading verifying key from %s...\n", *vkPath)
	fvk, err := os.Open(*vkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open vk: %v\n", err)
		os.Exit(1)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(fvk); err != nil {
		fvk.Close()
		fmt.Fprintf(os.Stderr, "read vk: %v\n", err)
		os.Exit(1)
	}
	fvk.Close()
	vkBn254 := vk.(*groth16_bn254.VerifyingKey)
	nCommitments := len(vkBn254.PublicAndCommitmentCommitted)
	nIC := len(vkBn254.G1.K)
	nPubExpected := nIC - nCommitments - 1 // circuit public inputs (without ONE wire or commitment)
	fmt.Printf("VK loaded: IC=%d, nCommitments=%d, expected public witness=%d\n", nIC, nCommitments, nPubExpected)

	// Get proof JSON
	var responseBytes []byte
	if *url != "" {
		fmt.Printf("Fetching proof from %s...\n", *url)
		t0 := time.Now()
		resp, err := http.Get(*url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fetch: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		responseBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read response: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Response received in %v (%d bytes, status %d)\n", time.Since(t0), len(responseBytes), resp.StatusCode)
		if resp.StatusCode != 200 {
			fmt.Fprintf(os.Stderr, "HTTP %d: %s\n", resp.StatusCode, string(responseBytes[:min(500, len(responseBytes))]))
			os.Exit(1)
		}
	} else {
		responseBytes, err = os.ReadFile(*proofFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read proof file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Proof file loaded (%d bytes)\n", len(responseBytes))
	}

	// Parse response
	var proved provedResponse
	if err := json.Unmarshal(responseBytes, &proved); err != nil {
		// Try parsing as direct proof JSON (not wrapped)
		var pj proofJSON
		if err2 := json.Unmarshal(responseBytes, &pj); err2 != nil {
			fmt.Fprintf(os.Stderr, "parse response: %v\n", err)
			os.Exit(1)
		}
		proved.Proof = pj
	}

	pj := proved.Proof
	fmt.Printf("Proof parsed: protocol=%s, curve=%s, prover=%s\n", pj.Protocol, pj.Curve, proved.ProverType)
	fmt.Printf("  pi_a: %d components\n", len(pj.PiA))
	fmt.Printf("  pi_b: %d rows\n", len(pj.PiB))
	fmt.Printf("  pi_c: %d components\n", len(pj.PiC))
	fmt.Printf("  commitments: %d\n", len(pj.Commitments))
	fmt.Printf("  public_signals: %d\n", len(pj.PublicSignals))

	// Validate we have required fields for verification
	if len(pj.Commitments) < nCommitments {
		fmt.Fprintf(os.Stderr, "\nERROR: proof has %d commitments but VK expects %d.\n", len(pj.Commitments), nCommitments)
		fmt.Fprintln(os.Stderr, "The deployed gnark binary may not include commitment output yet.")
		fmt.Fprintln(os.Stderr, "Update the gnark prove server with -vk flag and redeploy.")
		os.Exit(1)
	}
	if len(pj.PublicSignals) < nPubExpected {
		fmt.Fprintf(os.Stderr, "\nERROR: proof has %d public_signals but expected at least %d.\n", len(pj.PublicSignals), nPubExpected)
		os.Exit(1)
	}

	// Reconstruct gnark proof from JSON
	fmt.Println("\nReconstructing gnark proof...")
	proof, err := reconstructProof(pj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reconstruct proof: %v\n", err)
		os.Exit(1)
	}

	// Reconstruct public witness (first nPubExpected signals, WITHOUT commitment hash)
	pubWit := make(fr.Vector, nPubExpected)
	for i := 0; i < nPubExpected; i++ {
		bi, ok := new(big.Int).SetString(pj.PublicSignals[i], 10)
		if !ok {
			fmt.Fprintf(os.Stderr, "invalid public signal [%d]: %s\n", i, pj.PublicSignals[i])
			os.Exit(1)
		}
		pubWit[i].SetBigInt(bi)
	}
	fmt.Printf("Public witness reconstructed: %d elements\n", len(pubWit))

	// Verify
	fmt.Println("\nRunning groth16.Verify...")
	t0 := time.Now()
	err = groth16_bn254.Verify(proof, vkBn254, pubWit)
	elapsed := time.Since(t0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nVERIFICATION FAILED in %v: %v\n", elapsed, err)
		os.Exit(1)
	}
	fmt.Printf("\nVERIFICATION PASSED in %v\n", elapsed)
}

// reconstructProof builds a gnark bn254 Proof from JSON decimal strings.
func reconstructProof(pj proofJSON) (*groth16_bn254.Proof, error) {
	proof := &groth16_bn254.Proof{}

	// Ar (pi_a)
	ar, err := parseG1(pj.PiA)
	if err != nil {
		return nil, fmt.Errorf("parse pi_a: %w", err)
	}
	proof.Ar = ar

	// Bs (pi_b)
	bs, err := parseG2(pj.PiB)
	if err != nil {
		return nil, fmt.Errorf("parse pi_b: %w", err)
	}
	proof.Bs = bs

	// Krs (pi_c)
	krs, err := parseG1(pj.PiC)
	if err != nil {
		return nil, fmt.Errorf("parse pi_c: %w", err)
	}
	proof.Krs = krs

	// Commitments
	proof.Commitments = make([]bn254.G1Affine, len(pj.Commitments))
	for i, c := range pj.Commitments {
		pt, err := parseG1(c)
		if err != nil {
			return nil, fmt.Errorf("parse commitment[%d]: %w", i, err)
		}
		proof.Commitments[i] = pt
	}

	// CommitmentPok
	if len(pj.CommitmentPok) > 0 {
		pok, err := parseG1(pj.CommitmentPok)
		if err != nil {
			return nil, fmt.Errorf("parse commitment_pok: %w", err)
		}
		proof.CommitmentPok = pok
	}

	return proof, nil
}

// parseG1 converts ["x", "y", "1"] decimal strings to a BN254 G1Affine point.
func parseG1(coords []string) (bn254.G1Affine, error) {
	if len(coords) < 2 {
		return bn254.G1Affine{}, fmt.Errorf("need at least 2 coordinates, got %d", len(coords))
	}
	xBig, ok := new(big.Int).SetString(coords[0], 10)
	if !ok {
		return bn254.G1Affine{}, fmt.Errorf("invalid x coordinate: %s", coords[0])
	}
	yBig, ok := new(big.Int).SetString(coords[1], 10)
	if !ok {
		return bn254.G1Affine{}, fmt.Errorf("invalid y coordinate: %s", coords[1])
	}
	var pt bn254.G1Affine
	pt.X.SetBigInt(xBig)
	pt.Y.SetBigInt(yBig)
	return pt, nil
}

// parseG2 converts [["x0","x1"],["y0","y1"],["1","0"]] decimal strings to a BN254 G2Affine point.
func parseG2(coords [][]string) (bn254.G2Affine, error) {
	if len(coords) < 2 || len(coords[0]) < 2 || len(coords[1]) < 2 {
		return bn254.G2Affine{}, fmt.Errorf("need 2x2 coordinates")
	}

	setBig := func(e *fp.Element, s string) error {
		bi, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return fmt.Errorf("invalid field element: %s", s)
		}
		e.SetBigInt(bi)
		return nil
	}

	var pt bn254.G2Affine
	if err := setBig(&pt.X.A0, coords[0][0]); err != nil {
		return bn254.G2Affine{}, fmt.Errorf("X.A0: %w", err)
	}
	if err := setBig(&pt.X.A1, coords[0][1]); err != nil {
		return bn254.G2Affine{}, fmt.Errorf("X.A1: %w", err)
	}
	if err := setBig(&pt.Y.A0, coords[1][0]); err != nil {
		return bn254.G2Affine{}, fmt.Errorf("Y.A0: %w", err)
	}
	if err := setBig(&pt.Y.A1, coords[1][1]); err != nil {
		return bn254.G2Affine{}, fmt.Errorf("Y.A1: %w", err)
	}
	return pt, nil
}
