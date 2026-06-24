// A2: Intel-signed collateral. The TCB-Signing cert chains to the pinned root
// and signs both the TCB-Info and QE-Identity JSON documents (Intel issues one
// TCB-Signing cert that signs both). After this, every field later sliced from
// the JSON at a constrained offset is provably Intel-signed.
use crate::chain::extract_subject_pubkey;
use crate::der::cert_link;

// Verify the collateral chain and return the TCB-Signing subject public key.
//  1. TCB-Signing cert signed by the pinned Intel Root CA (root pinned by caller),
//  2. extract its subject public key,
//  3. TCB-Info JSON signed by that key,
//  4. QE-Identity JSON signed by that key.
pub fn verify_collateral<let SN: u32, let TN: u32, let QN: u32>(
    sign_tbs: [u8; SN],
    sign_len: u32,
    sign_sig: [u8; 64],
    sign_pk_off: u32,
    tcb_info: [u8; TN],
    tcb_info_len: u32,
    tcb_info_sig: [u8; 64],
    qe_id: [u8; QN],
    qe_id_len: u32,
    qe_id_sig: [u8; 64],
    root_x: [u8; 32],
    root_y: [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    cert_link(sign_tbs, sign_len, root_x, root_y, sign_sig);
    let (sx, sy) = extract_subject_pubkey(sign_tbs, sign_pk_off, sign_len);
    cert_link(tcb_info, tcb_info_len, sx, sy, tcb_info_sig);
    cert_link(qe_id, qe_id_len, sx, sy, qe_id_sig);
    (sx, sy)
}
