package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// Intel SGX Root CA P-256 public key (the trust anchor pinned in-circuit).
// Cross-checked against the well-known Intel SGX Provisioning Certification
// Root CA. If Intel ever rotates the root, these constants change and the
// vkey must be re-derived + re-registered.
const (
	intelRootCAX = "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5"
	intelRootCAY = "67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394"
)

// subjectPubKeyCtx is the unique literal DER context immediately preceding
// the 65-byte SEC1 subjectPublicKey (04||X||Y) in an Intel cert: the tail of
// the prime256v1 AlgorithmIdentifier (...ce 3d 03 01 07) + BIT STRING header
// (03 42 00). Identical across leaf/intermediate/root.
var subjectPubKeyCtx = []byte{0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}

// intelRootCAPubKey builds the pinned root public key as an in-circuit
// constant (called inside Define).
func intelRootCAPubKey() ECDSAPublicKey {
	x, _ := new(big.Int).SetString(intelRootCAX, 16)
	y, _ := new(big.Int).SetString(intelRootCAY, 16)
	return ECDSAPublicKey{
		X: emulated.ValueOf[P256Fp](x),
		Y: emulated.ValueOf[P256Fp](y),
	}
}

// bytesVarToP256Fp converts 32 big-endian byte variables (0..255 each;
// range-checked via ToBinary) into an emulated P256 base-field element.
func bytesVarToP256Fp(api frontend.API, b []frontend.Variable) (*emulated.Element[P256Fp], error) {
	bits := make([]frontend.Variable, 256)
	for i := 0; i < 32; i++ {
		bb := api.ToBinary(b[31-i], 8) // reverse byte order for LSB-first bit layout
		for j := 0; j < 8; j++ {
			bits[i*8+j] = bb[j]
		}
	}
	f, err := emulated.NewField[P256Fp](api)
	if err != nil {
		return nil, err
	}
	return f.FromBits(bits...), nil
}

// extractSubjectPubKey extracts the 65-byte SEC1 subjectPublicKey at the
// hinted offset (anchored on subjectPubKeyCtx), asserts the 0x04 uncompressed
// marker, and returns (X, Y) as emulated elements.
func extractSubjectPubKey(api frontend.API, tbs []uints.U8, off frontend.Variable, signedLen frontend.Variable) (*emulated.Element[P256Fp], *emulated.Element[P256Fp], error) {
	got := extractField(api, tbs, off, signedLen, subjectPubKeyCtx, 65)
	api.AssertIsEqual(got[0], 0x04)
	x, err := bytesVarToP256Fp(api, got[1:33])
	if err != nil {
		return nil, nil, err
	}
	y, err := bytesVarToP256Fp(api, got[33:65])
	if err != nil {
		return nil, nil, err
	}
	return x, y, nil
}

// bindSubjectPubKey asserts the cert's subjectPublicKey equals `expected`
// (used to tie the PCK leaf's key to the PckPubKey that verifies the QE
// report in step 4).
func bindSubjectPubKey(api frontend.API, tbs []uints.U8, off frontend.Variable, signedLen frontend.Variable, expected *ECDSAPublicKey) error {
	x, y, err := extractSubjectPubKey(api, tbs, off, signedLen)
	if err != nil {
		return err
	}
	f, err := emulated.NewField[P256Fp](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(x, &expected.X)
	f.AssertIsEqual(y, &expected.Y)
	return nil
}

// verifyChainToRoot proves the PCK cert chain anchors to the pinned Intel
// SGX Root CA (assume-clause A1, discharged in-circuit):
//  1. the leaf's subjectPublicKey equals pckPubKey (the key used in step 4),
//  2. the leaf is ECDSA-signed by the intermediate's (Platform CA) key,
//  3. the intermediate is ECDSA-signed by the hard-coded Intel Root CA key.
//
// No prover-supplied "trusted" PckPubKey is required anymore: a forged proof
// would need a chain that verifies under Intel's real root, which the prover
// cannot fabricate.
func verifyChainToRoot(
	api frontend.API,
	leafTBS []uints.U8, leafTBSLen frontend.Variable, leafSig *ECDSASignature, leafPubKeyOff frontend.Variable,
	intTBS []uints.U8, intTBSLen frontend.Variable, intSig *ECDSASignature, intPubKeyOff frontend.Variable,
	pckPubKey *ECDSAPublicKey,
) error {
	// 1. leaf subject pubkey == the PckPubKey used to verify the QE report
	if err := bindSubjectPubKey(api, leafTBS, leafPubKeyOff, leafTBSLen, pckPubKey); err != nil {
		return err
	}
	// 2. extract the intermediate (Platform CA) subject pubkey
	ix, iy, err := extractSubjectPubKey(api, intTBS, intPubKeyOff, intTBSLen)
	if err != nil {
		return err
	}
	platformCA := ECDSAPublicKey{X: *ix, Y: *iy}
	// 3. leaf signed by the Platform CA
	if err := verifyCertSig(api, leafTBS, leafTBSLen, &platformCA, leafSig); err != nil {
		return err
	}
	// 4. intermediate signed by the pinned Intel Root CA
	root := intelRootCAPubKey()
	return verifyCertSig(api, intTBS, intTBSLen, &root, intSig)
}
