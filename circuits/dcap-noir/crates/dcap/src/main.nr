// Secure Noir/Barretenberg DCAP (Intel TDX) attestation circuit.
//
// Mirrors the hardened gnark design: the proving key is PUBLIC, so every value
// the verifier trusts is either public I/O or is constrained in-circuit to a
// signature-anchored / SHA-hashed / hard-coded source. A forged proof cannot
// substitute its own key, quote, or collateral.
//
//   A1  PCK chain: leaf <- Platform CA <- pinned Intel SGX Root CA (constant)
//   A2  collateral: TCB-Signing cert <- root; TCB-Info + QE-Identity JSON signed
//   4-10 quote: QE report (PCK-signed), report_data binds attest key (G3),
//        QE identity policy, ISV signature, public measurement binding
//   G2  TCB-status binding from the signed JSON (per-level thresholds + status)
//   G5  canonical first-satisfiable level selection; severity merge
//   G4  revocation (CRL non-membership, C4 structure anchor + C5 freshness) and
//        collateral freshness windows
//
// Public I/O: MrTd, Rtmr0..3, ReportData, TcbStatus, Timestamp, CertSerial, Fmspc.
mod der;
mod parse;
mod chain;
mod collateral;
mod steps;
mod tcb;
mod crl;

use crate::chain::verify_chain_to_root;
use crate::collateral::verify_collateral;
use crate::der::{extract_cert_serial, extract_field};
use crate::parse::hex_to_bytes;
use crate::steps::{
    bind_public_measurements, qe_isv_svn, step4_verify_qe_report_sig, step5_verify_qe_report_data,
    step6_verify_qe_policy, step7_verify_isv_sig, tee_tcb_svn,
};
use crate::tcb::{
    bind_qe_identity, bind_tcb_levels, merge_status, platform_pce_svn_from_leaf, QeBound, TcbBound,
};
use crate::crl::verify_crl_non_membership;

// Buffer capacities (compile-time; SHA cost scales with capacity, sized to the
// largest real cert/blob). Match the gnark layout caps.
global LEAF_TBS_CAP: u32 = 1280; // PCK leaf TBS (real ~1180)
global INT_TBS_CAP: u32 = 640; // Platform CA TBS (real ~577)
global SIGN_TBS_CAP: u32 = 640; // TCB-Signing TBS (real ~566)
global TCB_INFO_CAP: u32 = 3072; // TCB-Info JSON (real ~2934)
global QE_ID_CAP: u32 = 512; // QE-Identity JSON (real ~461)
global PCK_CRL_CAP: u32 = 3072; // PCK CRL TBS (real ~2572)
global ROOT_CRL_CAP: u32 = 512; // Root CA CRL TBS
global QE_AUTH_CAP: u32 = 32;

// FMSPC OID context in the PCK leaf: OID 1.2.840.113741.1.13.1.4 + OCTET STRING
// header (04 06), followed by the 6 FMSPC bytes.
global FMSPC_CTX: [u8; 14] =
    [0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04, 0x04, 0x06];
// "fmspc":" anchor in the TCB-Info JSON (12 uppercase-hex chars follow).
global TCB_INFO_FMSPC_CTX: [u8; 9] = [0x22, 0x66, 0x6d, 0x73, 0x70, 0x63, 0x22, 0x3a, 0x22];

fn main(
    // Pinned Intel SGX Root CA key, supplied as a private witness and asserted
    // equal to the hard-coded constant in-circuit (see chain::pin_root). This is
    // the trust anchor; the assertion makes it non-forgeable.
    root_x: [u8; 32],
    root_y: [u8; 32],
    // --- A1 PCK chain ---
    leaf_tbs: [u8; LEAF_TBS_CAP],
    leaf_len: u32,
    leaf_sig: [u8; 64],
    leaf_pk_off: u32,
    leaf_fmspc_off: u32,
    leaf_serial_off: u32,
    leaf_cpu_svn_off: u32,
    leaf_pce_svn_off: u32,
    leaf_validity_off: u32,
    int_tbs: [u8; INT_TBS_CAP],
    int_len: u32,
    int_sig: [u8; 64],
    int_pk_off: u32,
    int_serial_off: u32,
    int_validity_off: u32,
    // --- A2 collateral ---
    sign_tbs: [u8; SIGN_TBS_CAP],
    sign_len: u32,
    sign_sig: [u8; 64],
    sign_pk_off: u32,
    sign_validity_off: u32,
    tcb_info: [u8; TCB_INFO_CAP],
    tcb_info_len: u32,
    tcb_info_sig: [u8; 64],
    tcb_info_fmspc_off: u32,
    tcb_levels_off: u32,
    tcb: TcbBound,
    qe_id: [u8; QE_ID_CAP],
    qe_id_len: u32,
    qe_id_sig: [u8; 64],
    qe: QeBound,
    // freshness date offsets
    tcb_issue_off: u32,
    tcb_next_off: u32,
    qe_issue_off: u32,
    qe_next_off: u32,
    // --- steps 4-10 ---
    qe_report: [u8; 384],
    qe_report_sig: [u8; 64],
    signed_quote: [u8; 632],
    isv_sig: [u8; 64],
    attest_x: [u8; 32],
    attest_y: [u8; 32],
    qe_auth: [u8; QE_AUTH_CAP],
    qe_auth_len: u32,
    // --- G4 revocation CRLs ---
    pck_crl_tbs: [u8; PCK_CRL_CAP],
    pck_crl_len: u32,
    pck_crl_sig: [u8; 64],
    pck_crl_thisupd_off: u32,
    root_crl_tbs: [u8; ROOT_CRL_CAP],
    root_crl_len: u32,
    root_crl_sig: [u8; 64],
    root_crl_thisupd_off: u32,
    // --- measurements / report data (PRIVATE witness; bound to the signed quote
    // below, then re-exposed in PACKED form as the public outputs) ---
    mr_td: [u8; 48],
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
    report_data: [u8; 64],
    timestamp: u64,
) -> pub [Field; 17] {
    // Pin the witness root to the hard-coded Intel SGX Root CA constant.
    let (rx, ry) = crate::chain::pin_root(root_x, root_y);

    // ---- A1: chain to pinned root; bind PCK leaf key ----
    let (pck_x, pck_y) = verify_chain_to_root(
        leaf_tbs, leaf_len, leaf_sig, leaf_pk_off, int_tbs, int_len, int_sig, int_pk_off, rx, ry,
    );

    // ---- A2: collateral signed by TCB-Signing <- root ----
    let _ = verify_collateral(
        sign_tbs, sign_len, sign_sig, sign_pk_off, tcb_info, tcb_info_len, tcb_info_sig, qe_id,
        qe_id_len, qe_id_sig, rx, ry,
    );

    // ---- H3: X.509 validity windows (notBefore <= Timestamp <= notAfter) for
    // every chain-anchored cert. Each TBS is SHA+ECDSA bound, so its dates are
    // signed; this rejects an expired/decommissioned cert replayed with fresh
    // collateral. ----
    crate::der::check_cert_validity(leaf_tbs, leaf_validity_off, leaf_len, timestamp);
    crate::der::check_cert_validity(int_tbs, int_validity_off, int_len, timestamp);
    crate::der::check_cert_validity(sign_tbs, sign_validity_off, sign_len, timestamp);

    // ---- identity outputs: FMSPC (leaf == TCB-Info JSON) + PCK serial ----
    let leaf_fmspc: [u8; 6] = extract_field(leaf_tbs, leaf_fmspc_off, leaf_len, FMSPC_CTX);
    let tcb_fmspc_hex: [u8; 12] =
        extract_field(tcb_info, tcb_info_fmspc_off, tcb_info_len, TCB_INFO_FMSPC_CTX);
    let tcb_fmspc = hex_to_bytes(tcb_fmspc_hex);
    for i in 0..6 {
        assert(leaf_fmspc[i] == tcb_fmspc[i], "leaf/tcb_info fmspc mismatch");
    }
    let serial = extract_cert_serial(leaf_tbs, leaf_serial_off, leaf_len);

    // ---- steps 4-7 ----
    step4_verify_qe_report_sig(qe_report, pck_x, pck_y, qe_report_sig);
    step5_verify_qe_report_data(qe_report, attest_x, attest_y, qe_auth, qe_auth_len);
    step6_verify_qe_policy(
        qe_report, qe.mrsigner, qe.isvprodid, qe.miscselect, qe.miscmask, qe.attributes,
        qe.attrmask,
    );
    step7_verify_isv_sig(signed_quote, attest_x, attest_y, isv_sig);
    bind_public_measurements(signed_quote, mr_td, rtmr0, rtmr1, rtmr2, rtmr3, report_data);

    // ---- G2: bind TCB-verdict values from the signed JSON; platform SVNs ----
    let platform_tee = tee_tcb_svn(signed_quote);
    let platform_cpu: [u8; 16] =
        extract_field(leaf_tbs, leaf_cpu_svn_off, leaf_len, crate::tcb::CPU_SVN_CTX);
    let platform_pce = platform_pce_svn_from_leaf(leaf_tbs, leaf_pce_svn_off, leaf_len);

    // platform TCB levels (G2 + C3 + F1/F2 + H1 + G5 canonical selection)
    let platform_sev = bind_tcb_levels(
        tcb_info, tcb_info_len, tcb_levels_off, tcb, platform_cpu, platform_pce, platform_tee,
    );

    // QE identity levels (G2 + F3 + H1 + G5)
    let qe_sev = bind_qe_identity(qe_id, qe_id_len, qe, qe_isv_svn(qe_report));

    // ---- steps 9-10: merge severity; assert != Revoked ----
    let tcb_status = merge_status(platform_sev, qe_sev);

    // ---- G4 freshness windows: issueDate <= Timestamp <= nextUpdate ----
    crate::tcb::check_freshness(
        tcb_info, tcb_info_len, tcb_issue_off, tcb_next_off, qe_id, qe_id_len, qe_issue_off,
        qe_next_off, timestamp,
    );

    // ---- G4 revocation: leaf serial not in PCK CRL; int serial not in Root CRL ----
    let (pca_x, pca_y) = crate::chain::extract_subject_pubkey(int_tbs, int_pk_off, int_len);
    verify_crl_non_membership(
        pck_crl_tbs, pck_crl_len, pca_x, pca_y, pck_crl_sig, serial, pck_crl_thisupd_off, timestamp,
    );
    let int_serial = extract_cert_serial(int_tbs, int_serial_off, int_len);
    verify_crl_non_membership(
        root_crl_tbs, root_crl_len, rx, ry, root_crl_sig, int_serial, root_crl_thisupd_off,
        timestamp,
    );

    // ---- pack the public outputs into 17 BN254 field elements (Xion x/zk caps
    // UltraHonk public inputs at 320 fields; one-byte-per-field would be 332).
    // Every byte below is already bound to the signed quote / leaf / collateral,
    // so the packed values are non-forgeable; this only changes the encoding.
    // Layout (must match the on-chain unpacker): mr_td, rtmr0..3 (2 limbs each),
    // report_data (3 limbs), tcb_status, timestamp, cert_serial, fmspc. ----
    let (mr0, mr1) = crate::parse::pack_48(mr_td);
    let (r00, r01) = crate::parse::pack_48(rtmr0);
    let (r10, r11) = crate::parse::pack_48(rtmr1);
    let (r20, r21) = crate::parse::pack_48(rtmr2);
    let (r30, r31) = crate::parse::pack_48(rtmr3);
    let (rd0, rd1, rd2) = crate::parse::pack_64(report_data);
    [
        mr0, mr1, // 1-2   mr_td
        r00, r01, // 3-4   rtmr0
        r10, r11, // 5-6   rtmr1
        r20, r21, // 7-8   rtmr2
        r30, r31, // 9-10  rtmr3
        rd0, rd1, rd2, // 11-13 report_data
        tcb_status as Field, // 14    tcb_status
        timestamp as Field, // 15    timestamp
        crate::parse::pack_be(serial), // 16    cert_serial[20]
        crate::parse::pack_be(leaf_fmspc), // 17    fmspc[6]
    ]
}
