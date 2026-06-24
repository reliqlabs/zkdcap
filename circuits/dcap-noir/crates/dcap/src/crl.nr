// G4 revocation: prove a CRL is a genuine, current, validly-signed CRL and that
// the target serial is not revoked by it.
//  1. signature by `issuer` over tbs[:len] (binds every byte, incl. revoked list),
//  2. C4: tbs begins with the v2 CRL tbsCertList head, so a non-CRL issuer-signed
//     TBS (e.g. another cert's tbsCertificate) cannot pose as the CRL,
//  3. C5: thisUpdate <= timestamp <= nextUpdate (rejects a stale CRL replayed
//     before a later revocation),
//  4. non-membership of the target serial via a rolling 20-byte fingerprint with
//     a product accumulator (exact, not probabilistic; see section 4 below).
use crate::der::cert_link;
use crate::parse::parse_utctime;

// v2 CRL tbsCertList content head: version INTEGER = 1 (02 01 01) + signature
// AlgorithmIdentifier ecdsa-with-SHA256 (30 0a 06 08 2a 86 48 ce 3d 04 03 02). A
// cert's tbsCertificate content instead begins with the version [0] EXPLICIT tag
// (a0 ...), so it can never present this sequence.
global CRL_TBS_HEAD_CTX: [u8; 15] =
    [0x02, 0x01, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

// thisUpdate sits after version + sigAlg + issuer Name (all small, no UTCTime),
// so it is the FIRST UTCTime in the tbsCertList. This bounds that search.
global CRL_MAX_HEADER_SCAN: u32 = 320;

pub fn verify_crl_non_membership<let N: u32>(
    tbs: [u8; N],
    tbs_len: u32,
    issuer_x: [u8; 32],
    issuer_y: [u8; 32],
    sig: [u8; 64],
    target_serial: [u8; 20],
    this_upd_off: u32,
    timestamp: u64,
) {
    // 1. signature over the whole TBS.
    cert_link(tbs, tbs_len, issuer_x, issuer_y, sig);

    // 2. C4: structural anchor on the tbsCertList CONTENT. The TBS is a DER
    // SEQUENCE (30 LL[LL]); skip the header, then assert the v2-CRL content head.
    assert(tbs[0] == 0x30, "crl not a SEQUENCE");
    let lb = tbs[1];
    let is81 = lb == 0x81;
    let is82 = lb == 0x82;
    assert(is81 | is82, "crl length not long-form");
    let content_off: u32 = if is82 { 4 } else { 3 };
    for j in 0..15 {
        assert(tbs[content_off + j] == CRL_TBS_HEAD_CTX[j], "not a v2 CRL tbsCertList");
    }

    // 3. C5: freshness. thisUpdate is the first UTCTime; parse it and nextUpdate.
    // (a) anchor `17 0d` (UTCTime, len 13) at this_upd_off, bound to the header.
    assert(this_upd_off + 2 + 13 + 2 + 13 <= tbs_len, "crl dates out of signed prefix");
    assert(this_upd_off <= CRL_MAX_HEADER_SCAN, "crl thisUpdate beyond header");
    assert(tbs[this_upd_off] == 0x17, "thisUpdate not UTCTime");
    assert(tbs[this_upd_off + 1] == 0x0d, "thisUpdate not 13 bytes");
    // (b) no `17 0d` strictly before this_upd_off -> it is the FIRST UTCTime.
    for p in 0..(CRL_MAX_HEADER_SCAN) {
        if p + 1 < N {
            let is_utc = (tbs[p] == 0x17) & (tbs[p + 1] == 0x0d);
            assert(!(is_utc & (p < this_upd_off)), "UTCTime before thisUpdate");
        }
    }
    // (c) parse thisUpdate (value at +2) and nextUpdate (next UTCTime at +15).
    let mut this_val = [0; 13];
    for i in 0..13 {
        this_val[i] = tbs[this_upd_off + 2 + i];
    }
    let this_upd = parse_utctime(this_val);
    let next_off = this_upd_off + 2 + 13;
    assert(tbs[next_off] == 0x17, "nextUpdate not UTCTime");
    assert(tbs[next_off + 1] == 0x0d, "nextUpdate not 13 bytes");
    let mut next_val = [0; 13];
    for i in 0..13 {
        next_val[i] = tbs[next_off + 2 + i];
    }
    let next_upd = parse_utctime(next_val);
    assert(timestamp >= this_upd, "crl not yet valid");
    assert(timestamp <= next_upd, "crl stale");

    // 4. non-membership: the serial does not occur as a 20-byte window in the signed
    // tbs (see serial_window_product for the exact, non-probabilistic argument).
    assert(serial_window_product(tbs, target_serial) != 0, "serial revoked");
}

// Rolling 20-byte fingerprint with a PRODUCT accumulator; returns 0 iff
// target_serial occurs as a contiguous 20-byte window in tbs[0..N]. EXACTLY
// EQUIVALENT to the per-position 20-byte equality scan, not a probabilistic hash:
// a 20-byte serial is 160 bits < BN254's 254-bit field, so the big-endian integer
// of any 20-byte window is an INJECTIVE encoding (no two distinct 20-byte strings
// share a value). Define fp(p) = big-endian int of tbs[p..p+20] and tgt =
// big-endian int of the serial; then fp(p) == tgt iff the 20 bytes are
// byte-identical. The field is prime, so prod = product over p of (fp(p) - tgt) is
// zero iff SOME window equals tgt (a product is 0 iff a factor is 0). Asserting
// prod != 0 is therefore the SAME predicate as the per-byte scan, with one inverse
// total instead of one per position. fp rolls as
// fp(p+1) = (fp(p) - tbs[p]*256^19)*256 + tbs[p+20]; the subtracted top byte makes
// the intermediate a 19-byte int < 256^19, so the field arithmetic never wraps
// (all values < 256^20 < field). tbs bytes are range-checked u8, so injectivity
// holds for EVERY prover input. (c19 is derived by a fold, not a hand-counted hex
// literal, to remove the 256^19-vs-256^21 footgun.)
fn serial_window_product<let N: u32>(tbs: [u8; N], target_serial: [u8; 20]) -> Field {
    let mut c19: Field = 1;
    for _k in 0..19 {
        c19 = c19 * 256;
    }
    let mut tgt: Field = 0;
    for j in 0..20 {
        tgt = tgt * 256 + target_serial[j] as Field;
    }
    let mut fp: Field = 0;
    for j in 0..20 {
        fp = fp * 256 + tbs[j] as Field;
    }
    let mut prod: Field = fp - tgt;
    for p in 0..(N - 20) {
        fp = (fp - tbs[p] as Field * c19) * 256 + tbs[p + 20] as Field;
        prod = prod * (fp - tgt);
    }
    prod
}

// A 20-byte serial planted in the buffer -> product hits 0 (revoked detected);
// a serial absent from the buffer -> product nonzero (honest non-membership).
#[test]
fn test_serial_window_present_is_zero() {
    let mut tbs: [u8; 80] = [0xaa; 80];
    let mut serial: [u8; 20] = [0; 20];
    for j in 0..20 {
        serial[j] = (j as u8) + 1; // 1..20, distinct, != 0xaa filler
        tbs[30 + j] = serial[j]; // plant the serial at offset 30
    }
    assert(serial_window_product(tbs, serial) == 0);
}

#[test]
fn test_serial_window_absent_is_nonzero() {
    let tbs: [u8; 80] = [0xaa; 80];
    let mut serial: [u8; 20] = [0; 20];
    for j in 0..20 {
        serial[j] = (j as u8) + 1; // not present in an all-0xaa buffer
    }
    assert(serial_window_product(tbs, serial) != 0);
}

// Boundary coverage (cross-family auditor suggestion): a revoked serial planted at
// the FIRST window (offset 0, the init factor) and the LAST window (offset N-20,
// the final loop iteration) must both be detected. Guards the coverage edges where
// an off-by-one in the init/loop bounds would hide a revocation.
#[test]
fn test_serial_window_present_at_first() {
    let mut tbs: [u8; 80] = [0xaa; 80];
    let mut serial: [u8; 20] = [0; 20];
    for j in 0..20 {
        serial[j] = (j as u8) + 1;
        tbs[j] = serial[j]; // window 0
    }
    assert(serial_window_product(tbs, serial) == 0);
}

#[test]
fn test_serial_window_present_at_last() {
    let mut tbs: [u8; 80] = [0xaa; 80];
    let mut serial: [u8; 20] = [0; 20];
    for j in 0..20 {
        serial[j] = (j as u8) + 1;
        tbs[60 + j] = serial[j]; // window N-20 = 60 (last window, final loop iteration)
    }
    assert(serial_window_product(tbs, serial) == 0);
}

// The c19 constant MUST be 256^19 (the 256^21 bug let a revoked serial pass): a
// near-miss serial differing only in its top byte must NOT collide with a planted
// window. Guards the fold against an off-by-two-bytes regression.
#[test]
fn test_serial_window_top_byte_distinguished() {
    let mut tbs: [u8; 80] = [0xaa; 80];
    let mut planted: [u8; 20] = [0; 20];
    for j in 0..20 {
        planted[j] = (j as u8) + 1;
        tbs[30 + j] = planted[j];
    }
    let mut other = planted;
    other[0] = 0xff; // differ only in the most-significant byte
    assert(serial_window_product(tbs, other) != 0);
}
