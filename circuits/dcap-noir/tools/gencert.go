// Generates a cert-link test vector: a TBS body of a given length, an issuer
// P-256 key, and the issuer's ECDSA signature over sha256(tbs). Emits Noir
// Prover.toml with tbs padded to 1024. Usage: go run gencert.go [tbs_len]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strconv"
)

const bufN = 1024

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
	tbsLen := 700
	if len(os.Args) > 1 {
		if n, err := strconv.Atoi(os.Args[1]); err == nil {
			tbsLen = n
		}
	}
	if tbsLen > bufN {
		panic("tbs_len exceeds buffer")
	}

	// deterministic-ish TBS content (value is irrelevant to gate count/timing)
	tbs := make([]byte, bufN)
	for i := 0; i < tbsLen; i++ {
		tbs[i] = byte((i*131 + 7) & 0xff)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(tbs[:tbsLen])
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		panic(err)
	}
	n := elliptic.P256().Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	sig := append(b32(r), b32(s)...)

	out := fmt.Sprintf(
		"tbs = %s\ntbs_len = %d\nissuer_x = %s\nissuer_y = %s\nsig = %s\n",
		arr(tbs), tbsLen, arr(b32(priv.PublicKey.X)), arr(b32(priv.PublicKey.Y)), arr(sig),
	)
	if _, err := os.Stdout.WriteString(out); err != nil {
		panic(err)
	}
}
