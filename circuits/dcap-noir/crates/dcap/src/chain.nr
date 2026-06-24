// A1: the PCK cert chain anchored to the pinned Intel SGX Root CA. The root
// public key is a HARD-CODED circuit constant (not a witness/public input), so a
// forged proof would need a chain verifying under Intel's real root, which the
// prover cannot fabricate.
use crate::der::{cert_link, extract_field};

// Intel SGX Root CA P-256 public key (the pinned trust anchor). Cross-checked
// against the well-known Intel SGX Provisioning Certification Root CA. If Intel
// rotates the root these constants change and the vkey must be re-derived.
//   X = 0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5
//   Y = 67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394
pub global INTEL_ROOT_X: [u8; 32] = [
    0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda, 0x10,
    0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25, 0xf5,
];
pub global INTEL_ROOT_Y: [u8; 32] = [
    0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a, 0xac,
    0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73, 0x94,
];

// subjectPubKey DER context: tail of the prime256v1 AlgorithmIdentifier
// (...ce 3d 03 01 07) + BIT STRING header (03 42 00). Then 04 || X(32) || Y(32).
pub global SUBJECT_PUBKEY_CTX: [u8; 8] = [0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];

// The pinned root key arrives as a private witness and is PINNED here to the
// hard-coded constant by per-byte assertion. This keeps the trust anchor
// non-forgeable (the assertion is in the vkey; any prover must supply exactly
// these bytes) while avoiding a bb 4.0.4 backend bug that mis-sizes a circuit
// when a compile-time-constant [u8;32] flows into the secp256r1 blackbox
// alongside dynamic-offset reads on a SHA'd buffer. Returns the pinned bytes.
pub fn pin_root(root_x: [u8; 32], root_y: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    for i in 0..32 {
        assert(root_x[i] == INTEL_ROOT_X[i], "root_x not pinned Intel root");
        assert(root_y[i] == INTEL_ROOT_Y[i], "root_y not pinned Intel root");
    }
    (root_x, root_y)
}

// Extract the 65-byte SEC1 subjectPublicKey at `off` (anchored), assert the 0x04
// uncompressed marker, return (X, Y) as 32-byte big-endian arrays.
pub fn extract_subject_pubkey<let N: u32>(
    tbs: [u8; N],
    off: u32,
    signed_len: u32,
) -> ([u8; 32], [u8; 32]) {
    let got: [u8; 65] = extract_field(tbs, off, signed_len, SUBJECT_PUBKEY_CTX);
    assert(got[0] == 0x04, "subjectPubKey not uncompressed");
    let mut x = [0; 32];
    let mut y = [0; 32];
    for i in 0..32 {
        x[i] = got[1 + i];
        y[i] = got[33 + i];
    }
    (x, y)
}

// Verify the PCK chain to the pinned root and return the leaf (PCK) public key:
//  1. intermediate (Platform CA) signed by the pinned Intel Root CA,
//  2. leaf signed by the extracted Platform CA key,
//  3. the leaf subjectPublicKey is returned as the PCK key for step 4.
pub fn verify_chain_to_root<let LN: u32, let IN: u32>(
    leaf_tbs: [u8; LN],
    leaf_len: u32,
    leaf_sig: [u8; 64],
    leaf_pk_off: u32,
    int_tbs: [u8; IN],
    int_len: u32,
    int_sig: [u8; 64],
    int_pk_off: u32,
    root_x: [u8; 32],
    root_y: [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    // 2/4: intermediate signed by the pinned root (root_x/root_y pinned by caller).
    cert_link(int_tbs, int_len, root_x, root_y, int_sig);
    let (pca_x, pca_y) = extract_subject_pubkey(int_tbs, int_pk_off, int_len);

    // 3: leaf signed by the Platform CA.
    cert_link(leaf_tbs, leaf_len, pca_x, pca_y, leaf_sig);

    // 1: PCK leaf subject pubkey -> used to verify the QE report (step 4).
    extract_subject_pubkey(leaf_tbs, leaf_pk_off, leaf_len)
}
