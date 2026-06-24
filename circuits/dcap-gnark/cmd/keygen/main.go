// keygen compiles the DCAP circuit, runs groth16.Setup(), and writes
// the constraint system (ccs.bin), proving key (pk.bin), and verifying
// key (vk.bin) to disk.
//
// Usage:
//   go run ./cmd/keygen [--ccs ccs.bin] [--pk pk.bin] [--vk vk.bin]
//
// The vk.bin file is the gnark-native VerifyingKey that gets registered
// on-chain via `xiond tx zk add-vkey`. The ccs.bin is the constraint
// system that long-running provers (e.g.
// verified-rcv/ops/gnark-prove-server) load at boot so they don't have
// to re-compile the circuit on every restart.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/reliqlabs/zkdcap/circuits/dcap-gnark/circuit"
)

func main() {
	ccsPath := flag.String("ccs", "ccs.bin", "output path for constraint system")
	pkPath := flag.String("pk", "pk.bin", "output path for proving key")
	vkPath := flag.String("vk", "vk.bin", "output path for verifying key")
	flag.Parse()

	fmt.Println("Compiling DCAP circuit...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit.DcapCircuit{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Constraints: %d\n", ccs.GetNbConstraints())

	// Persist the constraint system so long-running provers don't have
	// to compile on boot. ~1MB for the DCAP circuit; bind-mount alongside
	// pk.bin and vk.bin.
	fccs, err := os.Create(*ccsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create ccs: %v\n", err)
		os.Exit(1)
	}
	defer fccs.Close()
	if _, err := ccs.WriteTo(fccs); err != nil {
		fmt.Fprintf(os.Stderr, "write ccs: %v\n", err)
		os.Exit(1)
	}
	info, _ := fccs.Stat()
	fmt.Printf("Wrote constraint system: %s (%d bytes)\n", *ccsPath, info.Size())

	fmt.Println("Running groth16.Setup() (this may take a minute)...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		os.Exit(1)
	}

	// Write proving key
	fpk, err := os.Create(*pkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create pk: %v\n", err)
		os.Exit(1)
	}
	defer fpk.Close()
	if _, err := pk.WriteTo(fpk); err != nil {
		fmt.Fprintf(os.Stderr, "write pk: %v\n", err)
		os.Exit(1)
	}
	pkInfo, _ := fpk.Stat()
	fmt.Printf("Wrote proving key: %s (%d bytes)\n", *pkPath, pkInfo.Size())

	// Write verifying key
	fvk, err := os.Create(*vkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create vk: %v\n", err)
		os.Exit(1)
	}
	defer fvk.Close()
	if _, err := vk.WriteTo(fvk); err != nil {
		fmt.Fprintf(os.Stderr, "write vk: %v\n", err)
		os.Exit(1)
	}
	vkInfo, _ := fvk.Stat()
	fmt.Printf("Wrote verifying key: %s (%d bytes)\n", *vkPath, vkInfo.Size())

	fmt.Println("Done. Register vk.bin on-chain with:")
	fmt.Printf("  xiond tx zk add-vkey --name zkdcap-gnark --vkey-bytes $(cat %s | base64) --proof-system PROOF_SYSTEM_GROTH16_GNARK\n", *vkPath)
}
