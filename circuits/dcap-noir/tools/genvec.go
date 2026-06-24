// Generates a valid P-256 ECDSA test vector and prints it as a Noir Prover.toml.
// Stdlib only, runs with `go run genvec.go`. Signature is low-s normalized so
// any conformant verifier (including Noir's secp256r1 black-box) accepts it.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
)

func b32(i *big.Int) []byte {
	b := i.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func arr(b []byte) string {
	s := "["
	for i, x := range b {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("%d", x)
	}
	return s + "]"
}

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	msg := []byte("dcap-noir-p256-phase1-test-vector")
	h := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		panic(err)
	}
	// low-s normalize
	n := elliptic.P256().Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(n, s)
	}

	sig := append(b32(r), b32(s)...)
	px := b32(priv.PublicKey.X)
	py := b32(priv.PublicKey.Y)

	out := fmt.Sprintf(
		"pub_key_x = %s\npub_key_y = %s\nsignature = %s\nhashed_message = %s\n",
		arr(px), arr(py), arr(sig), arr(h[:]),
	)
	if _, err := os.Stdout.WriteString(out); err != nil {
		panic(err)
	}
}
