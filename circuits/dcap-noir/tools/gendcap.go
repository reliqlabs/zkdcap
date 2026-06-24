// Builds a self-consistent witness for the full DCAP circuit and emits Prover.toml.
// Generates the 7 keypairs, embeds subject pubkeys / FMSPC / serial at the declared
// offsets, and produces the chained ECDSA signatures (root -> platform CA -> leaf,
// root -> tcb-signing -> tcb_info/qe_identity, leaf -> qe_report, attest -> quote).
// Stdlib only: go run gendcap.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
)

var curve = elliptic.P256()

func b32(i *big.Int) []byte {
	b := i.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func arr(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// deterministic root keypair so its pubkey is stable across runs
func rootKey() *ecdsa.PrivateKey {
	seed := []byte("dcap-noir-pinned-intel-sgx-root-ca-measure-01")
	d := new(big.Int).SetBytes(sha256Sum(seed))
	n1 := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d.Mod(d, n1)
	d.Add(d, big.NewInt(1))
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = d
	priv.X, priv.Y = curve.ScalarBaseMult(d.Bytes())
	return priv
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func genKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// sign sha256(msg) with low-s normalization, return r||s (64 bytes)
func sign(priv *ecdsa.PrivateKey, msg []byte) []byte {
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		panic(err)
	}
	half := new(big.Int).Rsh(curve.Params().N, 1)
	if s.Cmp(half) > 0 {
		s = new(big.Int).Sub(curve.Params().N, s)
	}
	return append(b32(r), b32(s)...)
}

func filler(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*131 + 7) & 0xff)
	}
	return b
}

const pubkeyCtx = "\xce\x3d\x03\x01\x07\x03\x42\x00"
const fmspcCtx = "\x06\x0a\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x04\x04\x06"
const serialCtx = "\xa0\x03\x02\x01\x02\x02"
const jsonFmspcCtx = "\"fmspc\":\""

func placePubkey(buf []byte, off int, k *ecdsa.PrivateKey) {
	copy(buf[off:], []byte(pubkeyCtx))
	copy(buf[off+8:], b32(k.X))
	copy(buf[off+40:], b32(k.Y))
}

func main() {
	root := rootKey()
	pca := genKey()
	pck := genKey()
	ts := genKey()
	attest := genKey()

	fmspc := []byte{0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00}
	serial := filler(20)

	// platform CA TBS (640): pubkey at 100
	pcaTBS := filler(640)
	pcaPkOff := 100
	placePubkey(pcaTBS, pcaPkOff, pca)
	pcaLen := 620
	pcaSig := sign(root, pcaTBS[:pcaLen])

	// leaf (PCK) TBS (1280): pubkey@100, fmspc@300, serial@400
	leafTBS := filler(1280)
	leafPkOff, leafFmspcOff, leafSerialOff := 100, 300, 400
	placePubkey(leafTBS, leafPkOff, pck)
	copy(leafTBS[leafFmspcOff:], []byte(fmspcCtx))
	copy(leafTBS[leafFmspcOff+len(fmspcCtx):], fmspc)
	copy(leafTBS[leafSerialOff:], []byte(serialCtx))
	copy(leafTBS[leafSerialOff+len(serialCtx):], serial)
	leafLen := 1000
	leafSig := sign(pca, leafTBS[:leafLen])

	// TCB-Signing TBS (640): pubkey@100
	tsTBS := filler(640)
	tsPkOff := 100
	placePubkey(tsTBS, tsPkOff, ts)
	tsLen := 600
	tsSig := sign(root, tsTBS[:tsLen])

	// TCB-Info JSON (4096): "fmspc":"<hex>" at 50
	tcbJSON := filler(4096)
	tcbFmspcOff := 50
	copy(tcbJSON[tcbFmspcOff:], []byte(jsonFmspcCtx))
	copy(tcbJSON[tcbFmspcOff+len(jsonFmspcCtx):], []byte(hex.EncodeToString(fmspc)))
	tcbLen := 4000
	tcbSig := sign(ts, tcbJSON[:tcbLen])

	// QE-Identity JSON (512)
	qeJSON := filler(512)
	qeLen := 480
	qeSig := sign(ts, qeJSON[:qeLen])

	// QE report (384): report_data[320:352] = sha256(attest_x||attest_y)
	qeReport := filler(384)
	akConcat := append(b32(attest.X), b32(attest.Y)...)
	akHash := sha256.Sum256(akConcat)
	copy(qeReport[320:], akHash[:])
	qeReportSig := sign(pck, qeReport[:384])

	// signed quote (632): mr_td@184, rtmr0..3 @376/424/472/520
	sq := filler(632)
	mrTd := filler(48)
	rtmr0, rtmr1, rtmr2, rtmr3 := filler(48), filler(48), filler(48), filler(48)
	copy(sq[184:], mrTd)
	copy(sq[376:], rtmr0)
	copy(sq[424:], rtmr1)
	copy(sq[472:], rtmr2)
	copy(sq[520:], rtmr3)
	isvSig := sign(attest, sq[:632])

	var sb strings.Builder
	w := func(k, v string) { sb.WriteString(k + " = " + v + "\n") }
	w("root_x", arr(b32(root.X)))
	w("root_y", arr(b32(root.Y)))
	w("platform_ca_tbs", arr(pcaTBS))
	w("platform_ca_len", fmt.Sprintf("%d", pcaLen))
	w("platform_ca_sig", arr(pcaSig))
	w("platform_ca_pk_off", fmt.Sprintf("%d", pcaPkOff))
	w("leaf_tbs", arr(leafTBS))
	w("leaf_len", fmt.Sprintf("%d", leafLen))
	w("leaf_sig", arr(leafSig))
	w("leaf_pk_off", fmt.Sprintf("%d", leafPkOff))
	w("leaf_fmspc_off", fmt.Sprintf("%d", leafFmspcOff))
	w("leaf_serial_off", fmt.Sprintf("%d", leafSerialOff))
	w("tcb_signing_tbs", arr(tsTBS))
	w("tcb_signing_len", fmt.Sprintf("%d", tsLen))
	w("tcb_signing_sig", arr(tsSig))
	w("tcb_signing_pk_off", fmt.Sprintf("%d", tsPkOff))
	w("tcb_info_json", arr(tcbJSON))
	w("tcb_info_len", fmt.Sprintf("%d", tcbLen))
	w("tcb_info_sig", arr(tcbSig))
	w("tcb_info_fmspc_off", fmt.Sprintf("%d", tcbFmspcOff))
	w("qe_identity_json", arr(qeJSON))
	w("qe_identity_len", fmt.Sprintf("%d", qeLen))
	w("qe_identity_sig", arr(qeSig))
	w("qe_report", arr(qeReport))
	w("qe_report_sig", arr(qeReportSig))
	w("signed_quote", arr(sq))
	w("isv_sig", arr(isvSig))
	w("attest_x", arr(b32(attest.X)))
	w("attest_y", arr(b32(attest.Y)))
	w("mr_td", arr(mrTd))
	w("rtmr0", arr(rtmr0))
	w("rtmr1", arr(rtmr1))
	w("rtmr2", arr(rtmr2))
	w("rtmr3", arr(rtmr3))

	if _, err := os.Stdout.WriteString(sb.String()); err != nil {
		panic(err)
	}
}
