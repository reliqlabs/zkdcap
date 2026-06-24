package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// verifyCollateral discharges assume-clause A2 (collateral authenticity)
// in-circuit:
//  1. the Intel TCB-Signing cert is ECDSA-signed by the pinned Intel Root CA,
//  2. its subject public key is extracted, and
//  3. both the TCB-Info and QE-Identity documents are ECDSA-signed (over
//     their exact raw JSON bytes) by that TCB-Signing key.
//
// The same TCB-Signing cert signs both documents (Intel issues one), so a
// single cert verification + key extraction covers both. After this, every
// field later sliced from the TCB-Info / QE-Identity JSON at a constrained
// offset is provably Intel-signed, so TcbStatus and the QE-identity policy
// are no longer prover-supplied free witness.
//
// signSig is the TCB-Signing cert's DER ECDSA signature (by the root);
// tcbInfoSig / qeIdSig are the collateral's raw 64-byte r||s signatures over
// the raw JSON. The hashing inside verifyCertSig is over the exact signed
// bytes (cert TBS, or raw JSON), matching how Intel signs each.
func verifyCollateral(
	api frontend.API,
	signTBS []uints.U8, signLen frontend.Variable, signSig *ECDSASignature, signPubOff frontend.Variable,
	tcbInfo []uints.U8, tcbInfoLen frontend.Variable, tcbInfoSig *ECDSASignature,
	qeID []uints.U8, qeIDLen frontend.Variable, qeIDSig *ECDSASignature,
) (*ECDSAPublicKey, error) {
	// 1. TCB-Signing cert signed by the pinned Intel Root CA
	root := intelRootCAPubKey()
	if err := verifyCertSig(api, signTBS, signLen, &root, signSig); err != nil {
		return nil, err
	}
	// 2. extract the TCB-Signing subject public key
	sx, sy, err := extractSubjectPubKey(api, signTBS, signPubOff, signLen)
	if err != nil {
		return nil, err
	}
	signPub := ECDSAPublicKey{X: *sx, Y: *sy}
	// 3. TCB-Info signed by the TCB-Signing key (over raw JSON bytes)
	if err := verifyCertSig(api, tcbInfo, tcbInfoLen, &signPub, tcbInfoSig); err != nil {
		return nil, err
	}
	// 4. QE-Identity signed by the same TCB-Signing key
	if err := verifyCertSig(api, qeID, qeIDLen, &signPub, qeIDSig); err != nil {
		return nil, err
	}
	return &signPub, nil
}
