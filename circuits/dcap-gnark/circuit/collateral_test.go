package circuit

// Verifies the A2 collateral-signature gadget against the real fixture: the
// Intel TCB-Signing cert chains to the pinned root, and the TCB-Info +
// QE-Identity JSON are signed by it. Reports the constraint cost (dominated
// by the ~2.9 KB TCB-Info JSON SHA).

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// maxSignTBS, maxTcbInfo, maxQeID are defined in layout.go (shared with the circuit).

type collateralCircuit struct {
	SignTBS    [maxSignTBS]uints.U8
	SignLen    frontend.Variable
	SignSig    ECDSASignature
	SignPubOff frontend.Variable

	TcbInfo    [maxTcbInfo]uints.U8
	TcbInfoLen frontend.Variable
	TcbInfoSig ECDSASignature

	QeID    [maxQeID]uints.U8
	QeIDLen frontend.Variable
	QeIDSig ECDSASignature
}

func (c *collateralCircuit) Define(api frontend.API) error {
	_, err := verifyCollateral(api,
		c.SignTBS[:], c.SignLen, &c.SignSig, c.SignPubOff,
		c.TcbInfo[:], c.TcbInfoLen, &c.TcbInfoSig,
		c.QeID[:], c.QeIDLen, &c.QeIDSig)
	return err
}

func fillU8(dst []uints.U8, src []byte) {
	for i := range dst {
		if i < len(src) {
			dst[i] = uints.NewU8(src[i])
		} else {
			dst[i] = uints.NewU8(0)
		}
	}
}

func rawSigRS(t *testing.T, hexStr string) (*big.Int, *big.Int) {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 64 {
		t.Fatalf("raw sig hex: %v len=%d", err, len(b))
	}
	return new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:64])
}

func assignCollateral(t *testing.T) *collateralCircuit {
	t.Helper()
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["tcb_info_issuer_chain"]) // [TCB-Signing, Root]
	signing := chain[0]
	signTBS := signing.RawTBSCertificate
	sr, ss := sigRS(t, signing.Signature) // cert sig is DER
	tir, tis := rawSigRS(t, col["tcb_info_signature"])
	qir, qis := rawSigRS(t, col["qe_identity_signature"])

	w := &collateralCircuit{
		SignLen:    len(signTBS),
		SignPubOff: bytes.Index(signTBS, subjectPubKeyCtx),
		TcbInfoLen: len(col["tcb_info"]),
		QeIDLen:    len(col["qe_identity"]),
	}
	fillU8(w.SignTBS[:], signTBS)
	fillU8(w.TcbInfo[:], []byte(col["tcb_info"]))
	fillU8(w.QeID[:], []byte(col["qe_identity"]))
	w.SignSig.R = emulated.ValueOf[P256Fr](sr)
	w.SignSig.S = emulated.ValueOf[P256Fr](ss)
	w.TcbInfoSig.R = emulated.ValueOf[P256Fr](tir)
	w.TcbInfoSig.S = emulated.ValueOf[P256Fr](tis)
	w.QeIDSig.R = emulated.ValueOf[P256Fr](qir)
	w.QeIDSig.S = emulated.ValueOf[P256Fr](qis)
	return w
}

func TestVerifyCollateral(t *testing.T) {
	w := assignCollateral(t)
	if err := test.IsSolved(&collateralCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("collateral expected satisfiable: %v", err)
	}
}

// tampering the TCB-Info JSON must break its signature.
func TestVerifyCollateralTampered(t *testing.T) {
	w := assignCollateral(t)
	w.TcbInfo[20] = uints.NewU8(0x00) // flip a JSON byte
	if err := test.IsSolved(&collateralCircuit{}, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected unsatisfiable for tampered TCB-Info")
	}
}

func TestCollateralConstraints(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &collateralCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("verifyCollateral (TCB-Signing + TCB-Info + QE-Identity): %d constraints", ccs.GetNbConstraints())
}
