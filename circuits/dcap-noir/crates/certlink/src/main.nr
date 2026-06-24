// Phase 2: one cert-chain link. SHA-256 over a variable-length TBS body, then
// one secp256r1 verify of the issuer signature over that digest. This is the
// gnark verifyCertSig analogue (832,408 R1CS in gnark). TBS buffer is padded to
// 1024 bytes (covers a PCK leaf/intermediate TBS); sha256_var hashes tbs[:len].
use sha256::sha256_var;

fn main(
    tbs: [u8; 1024],
    tbs_len: u32,
    issuer_x: [u8; 32],
    issuer_y: [u8; 32],
    sig: [u8; 64],
) {
    let hash = sha256_var(tbs, tbs_len as u64);
    let valid = std::ecdsa_secp256r1::verify_signature(issuer_x, issuer_y, sig, hash);
    assert(valid);
}
