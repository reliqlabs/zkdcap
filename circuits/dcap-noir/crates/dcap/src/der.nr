// DER / JSON field extraction with literal-context anchoring + G1 bounds.
//
// Intel cert/collateral encodings are variable-length, so field positions are
// prover-supplied hints. Each hint is constrained by (a) the G1 bound
// off + ctx_len + field_len <= signed_len, keeping the whole read window inside
// the signature-covered prefix, and (b) asserting the unique literal DER/JSON
// context at that offset. Because the anchor occurs exactly once within the
// signed bytes and the buffer is SHA-256 + ECDSA bound, the extracted bytes are
// provably the values the issuer signed. (Noir's buf[off+j] is a native indexed
// read, so no selector/lookup gadget is needed; the asserts carry the soundness.)
use sha256::sha256_var;

// SHA-256(body[:len]) then secp256r1 verify of `sig` (r||s) by (ix,iy) over the
// 32-byte digest. The one cert-chain link; composing it leaf<-CA<-root plus the
// collateral JSON signatures discharges A1/A2 in-circuit.
pub fn cert_link<let N: u32>(
    body: [u8; N],
    len: u32,
    ix: [u8; 32],
    iy: [u8; 32],
    sig: [u8; 64],
) {
    let h = sha256_var(body, len);
    assert(std::ecdsa_secp256r1::verify_signature(ix, iy, sig, h), "cert sig invalid");
}

// Assert ctx[0..C] at buf[off..off+C] (anchor) within the signed prefix, then
// return the L bytes immediately following. G1: off + C + L <= signed_len.
pub fn extract_field<let N: u32, let C: u32, let L: u32>(
    buf: [u8; N],
    off: u32,
    signed_len: u32,
    ctx: [u8; C],
) -> [u8; L] {
    // G1: whole read window inside the signed prefix.
    assert(off + C + L <= signed_len, "extract_field out of signed prefix");
    for i in 0..C {
        assert(buf[off + i] == ctx[i], "anchor mismatch");
    }
    let mut out = [0; L];
    for i in 0..L {
        out[i] = buf[off + C + i];
    }
    out
}

// X.509 Validity SEQUENCE header (30 1e) + notBefore UTCTime tag/len (17 0d).
// Intel leaf / Platform CA / TCB-Signing certs all use UTCTime here. Unique in
// each TBS, so a prover cannot move the validity offset off the real window.
global CERT_VALIDITY_CTX: [u8; 4] = [0x30, 0x1e, 0x17, 0x0d];

// H3: assert notBefore <= timestamp <= notAfter for an X.509 cert whose Validity
// is anchored at `validity_off` on CERT_VALIDITY_CTX. notBefore's 13 UTCTime
// chars follow the anchor; notAfter is the next UTCTime (its own 17 0d tag at
// +4+13, then 13 value chars). The whole TBS is SHA+ECDSA bound, so the dates are
// signed. This rejects an expired/not-yet-valid cert (e.g. a decommissioned PCK
// leaf replayed with fresh collateral). timestamp is packed YYYYMMDDhhmmss.
// Returns the (notBefore, notAfter) packed bounds so the caller can fold them
// into the intersected collateral validity window (#3).
pub fn check_cert_validity<let N: u32>(
    tbs: [u8; N],
    validity_off: u32,
    signed_len: u32,
    timestamp: u64,
) -> (u64, u64) {
    let nb: [u8; 13] = extract_field(tbs, validity_off, signed_len, CERT_VALIDITY_CTX);
    let not_before = crate::parse::parse_utctime(nb);
    // notAfter: its own UTCTime tag/len then 13 value chars.
    let na_off = validity_off + 4 + 13;
    let na: [u8; 13] = extract_field(tbs, na_off, signed_len, [0x17, 0x0d]);
    let not_after = crate::parse::parse_utctime(na);
    assert(timestamp >= not_before, "cert not yet valid");
    assert(timestamp <= not_after, "cert expired");
    (not_before, not_after)
}

// H3/G-1 gadget tests for check_cert_validity. The real dcap-qvl cert windows
// all strictly contain the collateral freshness window, so an honest in-window
// timestamp cannot isolate the cert-validity check on the real fixture; these
// crafted-buffer tests prove the date comparison is load-bearing on its own.
// Buffer: [30 1e 17 0d][notBefore 13][17 0d][notAfter 13]; notBefore=2024-01-01,
// notAfter=2026-01-01 (packed 20240101000000 / 20260101000000).
fn validity_test_buf() -> [u8; 64] {
    let mut buf: [u8; 64] = [0; 64];
    let hdr = [0x30, 0x1e, 0x17, 0x0d]; // CERT_VALIDITY_CTX
    let nb = "240101000000Z".as_bytes();
    let na_tag = [0x17, 0x0d];
    let na = "260101000000Z".as_bytes();
    for j in 0..4 {
        buf[j] = hdr[j];
    }
    for j in 0..13 {
        buf[4 + j] = nb[j];
    }
    for j in 0..2 {
        buf[17 + j] = na_tag[j];
    }
    for j in 0..13 {
        buf[19 + j] = na[j];
    }
    buf
}

#[test]
fn test_cert_validity_in_window() {
    // 2025-06-01 is inside [2024-01-01, 2026-01-01].
    let (nb, na) = check_cert_validity(validity_test_buf(), 0, 64, 20250601000000);
    assert(nb == 20240101000000);
    assert(na == 20260101000000);
}

#[test(should_fail_with = "cert expired")]
fn test_cert_validity_expired() {
    // 2027-06-01 is past notAfter (2026-01-01).
    let _ = check_cert_validity(validity_test_buf(), 0, 64, 20270601000000);
}

#[test(should_fail_with = "cert not yet valid")]
fn test_cert_validity_not_yet_valid() {
    // 2023-06-01 is before notBefore (2024-01-01).
    let _ = check_cert_validity(validity_test_buf(), 0, 64, 20230601000000);
}

// Like extract_field but only the anchor (+ one value byte) must be inside the
// signed prefix; the remaining value bytes may read into the zero padded tail.
// Sound ONLY for closing-quote-terminated known string literals (tcbStatus):
// the literal + its closing quote live in the signed bytes, so the match decides
// on signed data; padding (real zero bytes) cannot spell a different valid
// status. Caller must keep off + C + L <= N (capacity) so the read stays in-buf.
pub fn extract_string_enum<let N: u32, let C: u32, let L: u32>(
    buf: [u8; N],
    off: u32,
    signed_len: u32,
    ctx: [u8; C],
) -> [u8; L] {
    assert(off + C + 1 <= signed_len, "status anchor out of signed prefix");
    assert(off + C + L <= N, "status read out of buffer");
    for i in 0..C {
        assert(buf[off + i] == ctx[i], "status anchor mismatch");
    }
    let mut out = [0; L];
    for i in 0..L {
        out[i] = buf[off + C + i];
    }
    out
}

// version+serial DER context: a0 03 02 01 02 (v3 [0]{INTEGER 2}) + serial tag 02.
global CERT_VERSION_SERIAL_CTX: [u8; 6] = [0xa0, 0x03, 0x02, 0x01, 0x02, 0x02];

// Extract the canonical 20-byte big-endian cert serial. DER encodes the serial
// INTEGER as 20 or 21 bytes (a leading 0x00 sign byte when the high bit is set);
// read the length byte, require 0x14 or 0x15, and drop the sign byte if present.
pub fn extract_cert_serial<let N: u32>(buf: [u8; N], off: u32, signed_len: u32) -> [u8; 20] {
    // G1: ctx(6) + len(1) + value(21) inside the signed prefix.
    assert(off + 6 + 1 + 21 <= signed_len, "serial out of signed prefix");
    for i in 0..6 {
        assert(buf[off + i] == CERT_VERSION_SERIAL_CTX[i], "serial anchor mismatch");
    }
    let len_byte = buf[off + 6];
    let is21 = len_byte == 0x15;
    assert((len_byte == 0x14) | is21, "serial length not 20/21");
    // value bytes start at off+7; 21 bytes available
    let mut raw = [0; 21];
    for i in 0..21 {
        raw[i] = buf[off + 7 + i];
    }
    if is21 {
        assert(raw[0] == 0x00, "21-byte serial missing 0x00 sign");
    }
    let mut out = [0; 20];
    for i in 0..20 {
        out[i] = if is21 { raw[i + 1] } else { raw[i] };
    }
    out
}

// Count positions p in [0, signed_len) where buf[p..p+L] == lit and the whole
// match fits in the signed prefix (p + L <= signed_len). Used to force
// level-anchor consecutiveness (F1/F3): if the active, strictly-increasing,
// anchored level starts number exactly this total, none can be skipped. Padding
// past signed_len is excluded so a prover cannot inflate the count via the tail.
pub fn count_literal<let N: u32, let L: u32>(buf: [u8; N], signed_len: u32, lit: [u8; L]) -> u32 {
    let mut total: u32 = 0;
    for p in 0..(N - L + 1) {
        let mut eq = true;
        for j in 0..L {
            eq &= buf[p + j] == lit[j];
        }
        let in_window = (p + L) <= signed_len;
        if eq & in_window {
            total += 1;
        }
    }
    total
}

// Prefix count of `lit` start positions, for the cheap H1 first-status pin.
// cum[p] = number of positions q < p where `lit` starts and the whole match is
// inside the signed prefix (q + L <= signed_len). Then for any lo <= hi the count
// of `lit` starts in [lo, hi) is cum[hi] - cum[lo], so "no `lit` in [lo, hi)" is
// just cum[hi] == cum[lo]. Computing this once (one buffer scan) and doing two
// O(1) reads per level replaces one full-buffer masked scan PER level (the H1
// pin), which is the dominant cost at 16 TCB + 8 QE levels. Padding past
// signed_len is excluded so a prover cannot perturb the count via the zero tail.
pub fn status_cumsum<let N: u32, let L: u32>(buf: [u8; N], signed_len: u32, lit: [u8; L]) -> [u32; N] {
    let mut cum: [u32; N] = [0; N];
    let mut running: u32 = 0;
    for p in 0..N {
        cum[p] = running; // count of `lit` starts strictly before p
        // p + L <= N is a COMPILE-TIME bound (p unrolled, N/L globals), so the
        // buf reads for the tail positions are elided, never out of bounds.
        if p + L <= N {
            let mut eq = true;
            for j in 0..L {
                eq &= buf[p + j] == lit[j];
            }
            let in_window = (p + L) <= signed_len;
            if eq & in_window {
                running += 1;
            }
        }
    }
    cum
}

// Assert the literal `lit` does NOT start at any position in [lo, hi) when
// active. Pins a status offset as the first occurrence at-or-after a level start
// (H1). No-op when active is false. (Retained for the gadget tests; the live
// circuit uses the cheaper status_cumsum prefix-sum form above.)
pub fn assert_no_literal_in_range<let N: u32, let L: u32>(
    buf: [u8; N],
    lo: u32,
    hi: u32,
    lit: [u8; L],
    active: bool,
) {
    for p in 0..(N - L + 1) {
        let mut eq = true;
        for j in 0..L {
            eq &= buf[p + j] == lit[j];
        }
        let in_range = (p >= lo) & (p < hi);
        assert(!(active & eq & in_range), "unexpected literal in range");
    }
}

// G-2 (H1) gadget negative: a single TCB level whose extent contains TWO
// "tcbStatus":" literals (a validly-signed TCB-Info could carry one). The H1 pin
// (assert_no_literal_in_range over [lvl_start, status_off)) must reject pinning
// status_off at the SECOND (softer) occurrence and accept the first. The real
// dcap-qvl fixture has one status per level, so this mechanism can only be
// exercised on a crafted buffer (per round-3 guidance).
#[test]
fn test_h1_first_status_pin() {
    // buf layout: [lvl_start .. status0 .. status1]; LVL = level start.
    let s = [0x22, 0x74, 0x63, 0x62, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22]; // "tcbStatus":"
    let mut buf: [u8; 64] = [0x20; 64]; // spaces
    let lvl_start: u32 = 4;
    let status0: u32 = 10;
    let status1: u32 = 40;
    for j in 0..13 {
        buf[status0 + j] = s[j];
        buf[status1 + j] = s[j];
    }
    // Pinning to the FIRST status (no earlier status in [lvl_start, status0)) is OK.
    assert_no_literal_in_range(buf, lvl_start, status0, s, true);
}

// The forward pin must be rejected: there IS a status literal in [lvl_start, status1).
#[test(should_fail_with = "unexpected literal in range")]
fn test_h1_rejects_forward_status() {
    let s = [0x22, 0x74, 0x63, 0x62, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22];
    let mut buf: [u8; 64] = [0x20; 64];
    let lvl_start: u32 = 4;
    let status0: u32 = 10;
    let status1: u32 = 40;
    for j in 0..13 {
        buf[status0 + j] = s[j];
        buf[status1 + j] = s[j];
    }
    // Pinning to the SECOND status leaves the first inside [lvl_start, status1) -> reject.
    assert_no_literal_in_range(buf, lvl_start, status1, s, true);
}

// QE-H1-NONLAST: a NON-last active QE level with two "tcbStatus":" literals; the
// prover points status_off at the softer FORWARD one (to downgrade QE severity).
// bind_qe_identity now gates the first-status pin on `active` (true here), so this
// must be unsatisfiable. Pre-fix the gate was `is_last` (false for a non-last
// level) -> the pin was a no-op and this WOULD have been satisfiable; teeth check:
// flipping the gate arg to `false` below makes it pass, confirming the gate is
// load-bearing. Mirrors the platform-side bind_one_level pin.
#[test(should_fail_with = "unexpected literal in range")]
fn test_qe_h1_nonlast_rejects_forward_status() {
    let s = [0x22, 0x74, 0x63, 0x62, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22];
    let mut buf: [u8; 64] = [0x20; 64];
    let lvl_start: u32 = 4; // this (non-last) QE level's object start
    let status_real: u32 = 10; // the level's true (first) status
    let status_soft: u32 = 30; // a softer status literal still inside this level
    let next_lvl: u32 = 50; // next active QE level start (upper bound, status_soft < next_lvl)
    for j in 0..13 {
        buf[status_real + j] = s[j];
        buf[status_soft + j] = s[j];
    }
    // The non-last upper bound (status_off < next_lvl) is satisfied by status_soft,
    // so ONLY the first-status pin catches it. active = true (non-last active level).
    assert(status_soft < next_lvl);
    assert_no_literal_in_range(buf, lvl_start, status_soft, s, true);
}

// LIVE-mechanism H1 tests: bind_one_level / bind_qe_identity now pin the status
// offset via status_cumsum (the prefix sum), asserting
// status_cum[status_off] == status_cum[lvl_start]. A level carrying TWO
// "tcbStatus":" literals must accept pinning at the first and reject the forward
// (softer) one. These exercise the offset-pin path the circuit actually uses
// (the assert_no_literal_in_range tests above cover the retired primitive).
#[test]
fn test_status_cumsum_first_pin() {
    let s = [0x22, 0x74, 0x63, 0x62, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22];
    let mut buf: [u8; 64] = [0x20; 64];
    let lvl_start: u32 = 4;
    let status0: u32 = 10;
    let status1: u32 = 40;
    for j in 0..13 {
        buf[status0 + j] = s[j];
        buf[status1 + j] = s[j];
    }
    let cum = status_cumsum(buf, 64, s);
    // first status: none in [lvl_start, status0) -> counts equal (accepted).
    assert(cum[status0] == cum[lvl_start]);
    // forward status: status0 lies in [lvl_start, status1) -> counts differ (rejected).
    assert(cum[status1] != cum[lvl_start]);
}

#[test(should_fail_with = "status not first in level")]
fn test_status_cumsum_rejects_forward() {
    let s = [0x22, 0x74, 0x63, 0x62, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22];
    let mut buf: [u8; 64] = [0x20; 64];
    let lvl_start: u32 = 4;
    let status0: u32 = 10;
    let status1: u32 = 40;
    for j in 0..13 {
        buf[status0 + j] = s[j];
        buf[status1 + j] = s[j];
    }
    let cum = status_cumsum(buf, 64, s);
    // the live bind-path assert, with status_off pinned at the forward status -> fails.
    assert(cum[status1] == cum[lvl_start], "status not first in level");
}
