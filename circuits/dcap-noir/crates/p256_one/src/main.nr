// Phase 1 measurement circuit: one secp256r1 (P-256) ECDSA verify via the
// std black-box. This is the unit cost that drives the whole DCAP circuit
// (the gnark equivalent is ~832k R1CS per verify). We measure real ACIR/gate
// count and prove time here before scaling up.
fn main(
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    hashed_message: pub [u8; 32],
) {
    let valid = std::ecdsa_secp256r1::verify_signature(
        pub_key_x,
        pub_key_y,
        signature,
        hashed_message,
    );
    assert(valid);
}
