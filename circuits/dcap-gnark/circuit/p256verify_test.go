package circuit

// Compares the per-cert-verify constraint cost of the generic
// stdecdsa.PublicKey.Verify path (what verifyCertSig uses today) against the
// new gnark v0.15.0 evmprecompiles.P256Verify gadget (EIP-7951), to decide
// whether to switch the chain's 4-6 P-256 verifications to the cheaper
// gadget. Both measured over the same 1024-byte TBS buffer so the SHA cost
// is identical and the delta is purely the ECDSA gadget.
//
// NOTE: P256Verify assumes (per its zkEVM contract) that r,s are in [1,n-1]
// and (qx,qy) is a valid non-zero on-curve point. In our chain those hold
// because every verified key was signed by Intel up to the pinned root, but
// a production switch should still add explicit on-curve / range guards for
// any key not transitively anchored. This test measures the raw gadget cost.

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type p256CertSigCircuit struct {
	TBS    [maxCertTBS]uints.U8
	TBSLen frontend.Variable
	Issuer ECDSAPublicKey
	Sig    ECDSASignature
}

func (c *p256CertSigCircuit) Define(api frontend.API) error {
	digest, err := sha256VarLen(api, c.TBS[:], c.TBSLen)
	if err != nil {
		return err
	}
	msg, err := bytesToP256Fr(api, digest)
	if err != nil {
		return err
	}
	res := evmprecompiles.P256Verify(api, msg, &c.Sig.R, &c.Sig.S, &c.Issuer.X, &c.Issuer.Y)
	api.AssertIsEqual(res, 1)
	return nil
}

func assignP256CertSig(src *certSigTestCircuit) *p256CertSigCircuit {
	w := &p256CertSigCircuit{TBSLen: src.TBSLen, Issuer: src.Issuer, Sig: src.Sig}
	w.TBS = src.TBS
	return w
}

func TestP256VerifyGadget(t *testing.T) {
	tbs, r, s, px, py := makeP256Cert(t)
	w := assignP256CertSig(assignCertSig(tbs, r, s, px, py))
	if err := test.IsSolved(&p256CertSigCircuit{}, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("P256Verify expected satisfiable: %v", err)
	}
}

func TestP256VerifyVsStdConstraints(t *testing.T) {
	std, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &certSigTestCircuit{})
	if err != nil {
		t.Fatalf("compile std: %v", err)
	}
	p256, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &p256CertSigCircuit{})
	if err != nil {
		t.Fatalf("compile p256: %v", err)
	}
	a := std.GetNbConstraints()
	b := p256.GetNbConstraints()
	t.Logf("stdecdsa.Verify cert-sig (maxCertTBS=%d): %d constraints", maxCertTBS, a)
	t.Logf("P256Verify     cert-sig (maxCertTBS=%d): %d constraints", maxCertTBS, b)
	t.Logf("delta per verify: %d (%.1f%%)", a-b, 100*float64(a-b)/float64(a))
}
