package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// verifyCertSig asserts that `sig` is a valid ECDSA-P256 signature by
// `issuer` over SHA-256(tbs[:tbsLen]).
//
// This is the core cert-chain link used to build the full (self-anchoring)
// DCAP path: the signed message is a certificate's tbsCertificate byte
// range, and `issuer` is the parent cert's subject public key (for the
// chain root, the hard-coded Intel SGX Root CA key). Composing this over
// PCK leaf <- intermediate <- root, plus the Intel-signed TCB Info / QE
// Identity blobs, discharges assume-clauses A1 (PCK leaf legitimacy /
// chain-to-Intel-root) and A2 (collateral authenticity) inside the proof,
// so the verifier no longer trusts the prover-supplied PckPubKey/collateral
// (see docs/intent.md section 6.1).
//
// `tbs` is a fixed-capacity buffer; only the first `tbsLen` bytes are
// hashed. SHA-256 cost is set by the COMPILE-TIME capacity len(tbs), not
// the runtime length (the gadget runs every padding block regardless), so
// size the buffer to the largest cert/blob the chain must accept. Because
// the entire TBS is hashed and signature-bound, any field later sliced from
// `tbs` at a constrained offset is provably the value the issuer signed.
func verifyCertSig(
	api frontend.API,
	tbs []uints.U8,
	tbsLen frontend.Variable,
	issuer *ECDSAPublicKey,
	sig *ECDSASignature,
) error {
	digest, err := sha256VarLen(api, tbs, tbsLen)
	if err != nil {
		return err
	}
	msg, err := bytesToP256Fr(api, digest)
	if err != nil {
		return err
	}
	issuer.Verify(api, sw_emulated.GetP256Params(), msg, sig)
	return nil
}
