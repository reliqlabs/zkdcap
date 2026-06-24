// Quote verification steps 4-10: QE report signature (PCK), QE report_data binds
// the attestation key (G3), QE identity policy (step 6), ISV signature over the
// signed quote (step 7), and the public measurement bindings.
//
// G3 note: the secp256r1 blackbox takes the public key as raw (x,y) bytes, so
// the "point" is exactly the byte representation. Hashing the SAME attest_x ||
// attest_y bytes into report_data (step 5) and verifying the ISV signature with
// those same bytes (step 7) binds the committed key to the signing key with no
// separate point-to-bytes equality needed.
use crate::der::cert_link;
use crate::parse::u16_le;
use sha256::sha256_var;

// Signed-quote (header + TDReport10) absolute offsets.
global SQ_TEE_TCB_SVN: u32 = 48; // [48..64)  16 bytes
global SQ_MR_TD: u32 = 184; // [184..232) 48 bytes
global SQ_RTMR0: u32 = 376;
global SQ_RTMR1: u32 = 424;
global SQ_RTMR2: u32 = 472;
global SQ_RTMR3: u32 = 520;
global SQ_REPORT_DATA: u32 = 568; // [568..632) 64 bytes

// EnclaveReport (QE report) field offsets.
global QER_MISC_SELECT: u32 = 16; // [16..20) 4 bytes
global QER_ATTRIBUTES: u32 = 48; // [48..64) 16 bytes
global QER_MR_SIGNER: u32 = 128; // [128..160) 32 bytes
global QER_ISV_PROD_ID: u32 = 256; // [256..258) u16 LE
global QER_ISV_SVN: u32 = 258; // [258..260) u16 LE
global QER_REPORT_DATA: u32 = 320; // [320..384) 64 bytes

// Step 4: QE report (384 bytes) signed by the PCK leaf key.
pub fn step4_verify_qe_report_sig(qe_report: [u8; 384], pck_x: [u8; 32], pck_y: [u8; 32], sig: [u8; 64]) {
    cert_link(qe_report, 384, pck_x, pck_y, sig);
}

// Step 5: SHA-256(attest_key_raw || qe_auth_data[:len]) == qe_report.report_data[0:32].
// attest_x/attest_y are the raw attestation key bytes; the same bytes verify the
// ISV signature in step 7 (G3 bind).
pub fn step5_verify_qe_report_data<let A: u32>(
    qe_report: [u8; 384],
    attest_x: [u8; 32],
    attest_y: [u8; 32],
    qe_auth: [u8; A],
    qe_auth_len: u32,
) {
    let mut hash_input: [u8; 64 + A] = [0; 64 + A];
    for i in 0..32 {
        hash_input[i] = attest_x[i];
        hash_input[32 + i] = attest_y[i];
    }
    for i in 0..A {
        hash_input[64 + i] = qe_auth[i];
    }
    let digest = sha256_var(hash_input, 64 + qe_auth_len);
    for i in 0..32 {
        assert(digest[i] == qe_report[QER_REPORT_DATA + i], "qe report_data mismatch");
    }
}

// Step 6: QE identity policy against the QE report. mrsigner exact, isvprodid
// exact, miscselect + attributes masked. The policy values + masks are bound to
// the signed QE-Identity JSON in tcb.nr; the mask must come from the JSON (a zero
// mask would make the policy vacuous).
pub fn step6_verify_qe_policy(
    qe_report: [u8; 384],
    qe_mrsigner: [u8; 32],
    qe_isvprodid: u32,
    qe_miscselect: [u8; 4],
    qe_miscmask: [u8; 4],
    qe_attributes: [u8; 16],
    qe_attrmask: [u8; 16],
) {
    for i in 0..32 {
        assert(qe_report[QER_MR_SIGNER + i] == qe_mrsigner[i], "qe mrsigner mismatch");
    }
    let report_prodid = u16_le(qe_report[QER_ISV_PROD_ID], qe_report[QER_ISV_PROD_ID + 1]);
    assert(report_prodid == qe_isvprodid, "qe isvprodid mismatch");
    for i in 0..4 {
        assert(
            (qe_report[QER_MISC_SELECT + i] & qe_miscmask[i]) == (qe_miscselect[i] & qe_miscmask[i]),
            "qe miscselect mismatch",
        );
    }
    for i in 0..16 {
        assert(
            (qe_report[QER_ATTRIBUTES + i] & qe_attrmask[i]) == (qe_attributes[i] & qe_attrmask[i]),
            "qe attributes mismatch",
        );
    }
}

// Step 7: ISV signature over the signed quote (632 bytes) by the attestation key.
pub fn step7_verify_isv_sig(signed_quote: [u8; 632], attest_x: [u8; 32], attest_y: [u8; 32], sig: [u8; 64]) {
    cert_link(signed_quote, 632, attest_x, attest_y, sig);
}

// Bind the public measurement inputs from the (ISV-signed) signed quote.
pub fn bind_public_measurements(
    signed_quote: [u8; 632],
    mr_td: [u8; 48],
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
    report_data: [u8; 64],
) {
    for i in 0..48 {
        assert(signed_quote[SQ_MR_TD + i] == mr_td[i], "mr_td mismatch");
        assert(signed_quote[SQ_RTMR0 + i] == rtmr0[i], "rtmr0 mismatch");
        assert(signed_quote[SQ_RTMR1 + i] == rtmr1[i], "rtmr1 mismatch");
        assert(signed_quote[SQ_RTMR2 + i] == rtmr2[i], "rtmr2 mismatch");
        assert(signed_quote[SQ_RTMR3 + i] == rtmr3[i], "rtmr3 mismatch");
    }
    for i in 0..64 {
        assert(signed_quote[SQ_REPORT_DATA + i] == report_data[i], "report_data mismatch");
    }
}

// Read the platform TEE TCB SVN (16 bytes) from the signed quote.
pub fn tee_tcb_svn(signed_quote: [u8; 632]) -> [u8; 16] {
    let mut out = [0; 16];
    for i in 0..16 {
        out[i] = signed_quote[SQ_TEE_TCB_SVN + i];
    }
    out
}

// QE report isv_svn (u16 LE) for step-9 QE TCB matching.
pub fn qe_isv_svn(qe_report: [u8; 384]) -> u32 {
    u16_le(qe_report[QER_ISV_SVN], qe_report[QER_ISV_SVN + 1])
}
