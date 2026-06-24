// G2 + G5: bind every TCB-verdict comparison value to the Intel-signed TCB-Info
// / QE-Identity JSON (the whole JSON is SHA-256 + ECDSA verified), derive the
// level counts from the signed bytes, pin per-level offsets to their own level
// segment (C3/F2), forbid level-skipping (F1/F3) and bound the last level (H1),
// then select the CANONICAL first-satisfiable level (G5) with a range-checked
// index (C1) and merge severities.
use crate::der::{count_literal, extract_field, extract_string_enum, status_cumsum};
use crate::parse::{parse_decimal, parse_iso8601};

global MAX_TCB_LEVELS: u32 = 16;
global MAX_SGX_COMPONENTS: u32 = 16;
global MAX_TDX_COMPONENTS: u32 = 16;
global MAX_QE_TCB_LEVELS: u32 = 8;

// TCB status severity codes (lower = better). Matches gnark / the witness map.
global TCB_UP_TO_DATE: u32 = 0;
global TCB_SW_HARDENING_NEEDED: u32 = 1;
global TCB_CONFIGURATION_NEEDED: u32 = 2;
global TCB_CONFIG_AND_SW_HARDENING_NEEDED: u32 = 3;
global TCB_OUT_OF_DATE: u32 = 4;
global TCB_OUT_OF_DATE_CONFIG_NEEDED: u32 = 5;
global TCB_REVOKED: u32 = 6;

// JSON anchor literals.
global JSON_TCB_LEVELS: [u8; 13] =
    [0x22, 0x74, 0x63, 0x62, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x73, 0x22, 0x3a, 0x5b]; // "tcbLevels":[
// {"tcb":{"sgxtcbcomponents": (unique per top-level level object)
global JSON_LEVEL_CTX: [u8; 27] = [
    0x7b, 0x22, 0x74, 0x63, 0x62, 0x22, 0x3a, 0x7b, 0x22, 0x73, 0x67, 0x78, 0x74, 0x63, 0x62, 0x63,
    0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x3a,
];
global JSON_SGX_ARR_CTX: [u8; 20] = [
    0x22, 0x73, 0x67, 0x78, 0x74, 0x63, 0x62, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74,
    0x73, 0x22, 0x3a, 0x5b,
]; // "sgxtcbcomponents":[
global JSON_TDX_ARR_CTX: [u8; 20] = [
    0x22, 0x74, 0x64, 0x78, 0x74, 0x63, 0x62, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74,
    0x73, 0x22, 0x3a, 0x5b,
]; // "tdxtcbcomponents":[
global JSON_SVN_CTX: [u8; 7] = [0x7b, 0x22, 0x73, 0x76, 0x6e, 0x22, 0x3a]; // {"svn":
global JSON_PCESVN_CTX: [u8; 9] = [0x22, 0x70, 0x63, 0x65, 0x73, 0x76, 0x6e, 0x22, 0x3a]; // "pcesvn":
global JSON_STATUS_CTX: [u8; 13] =
    [0x22, 0x74, 0x63, 0x62, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3a, 0x22]; // "tcbStatus":"
// {"tcb":{"isvsvn": (unique per QE level object)
global JSON_QE_LVL_CTX: [u8; 17] = [
    0x7b, 0x22, 0x74, 0x63, 0x62, 0x22, 0x3a, 0x7b, 0x22, 0x69, 0x73, 0x76, 0x73, 0x76, 0x6e, 0x22,
    0x3a,
]; // {"tcb":{"isvsvn":
// "{"tcb":{" prefix length, used to derive the sgx-array offset from a level start.
global TCB_OPEN_LEN: u32 = 8; // len of {"tcb":{

// CPUSVN OID anchor in the PCK leaf SGX extension + OCTET STRING (04 10) header.
pub global CPU_SVN_CTX: [u8; 15] =
    [0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x12, 0x04, 0x10];
// PCESVN OID anchor + INTEGER tag (02). The next byte is the DER length (1 or 2).
global PCE_SVN_CTX: [u8; 14] =
    [0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x11, 0x02];

// Field decimal widths (digits + 1 terminator). svn is u8 (<=3), the u16 fields
// (pcesvn/isvsvn/isvprodid) are <=5 digits.
global SVN_FIELD_WIDTH: u32 = 4;
global U16_FIELD_WIDTH: u32 = 6;
// Longest status literal + closing quote ("ConfigurationAndSWHardeningNeeded").
global STATUS_READ_LEN: u32 = 34;

// Host-supplied per-level offsets + witness values for the TCB-Info JSON.
pub struct TcbBound {
    pub level_count: u32, // derived count (also asserted equal in-circuit)
    pub match_idx: u32, // canonical level index (range-checked)
    pub lvl_start: [u32; MAX_TCB_LEVELS - 1], // starts for slots 1..N-1 (slot 0 pinned)
    pub pce_svn_off: [u32; MAX_TCB_LEVELS],
    pub tdx_arr_off: [u32; MAX_TCB_LEVELS],
    pub sgx_svn_off: [[u32; MAX_SGX_COMPONENTS - 1]; MAX_TCB_LEVELS], // comps 1..15
    pub tdx_svn_off: [[u32; MAX_TDX_COMPONENTS - 1]; MAX_TCB_LEVELS],
    pub status_off: [u32; MAX_TCB_LEVELS],
    pub pce_svn: [u32; MAX_TCB_LEVELS], // witness threshold values
    pub sgx_comps: [[u32; MAX_SGX_COMPONENTS]; MAX_TCB_LEVELS],
    pub tdx_comps: [[u32; MAX_TDX_COMPONENTS]; MAX_TCB_LEVELS],
    pub severity: [u32; MAX_TCB_LEVELS],
}

// Host-supplied QE-Identity policy fields, per-level offsets + witness values.
pub struct QeBound {
    pub mrsigner: [u8; 32],
    pub isvprodid: u32,
    pub miscselect: [u8; 4],
    pub miscmask: [u8; 4],
    pub attributes: [u8; 16],
    pub attrmask: [u8; 16],
    pub mrsigner_off: u32,
    pub isvprodid_off: u32,
    pub miscselect_off: u32,
    pub miscmask_off: u32,
    pub attr_off: u32,
    pub attrmask_off: u32,
    pub level_count: u32,
    pub match_idx: u32,
    pub lvl_off: [u32; MAX_QE_TCB_LEVELS],
    pub status_off: [u32; MAX_QE_TCB_LEVELS],
    pub isvsvn: [u32; MAX_QE_TCB_LEVELS],
    pub severity: [u32; MAX_QE_TCB_LEVELS],
}

// Map an extracted tcbStatus string (bytes after the opening quote, closing-quote
// terminated) to its severity. Exactly one known literal must match (asserted),
// so an unknown/forged status is unsatisfiable. The closing-quote check after
// each literal prevents prefix confusion ("OutOfDate" vs "OutOfDate...").
fn status_severity(got: [u8; STATUS_READ_LEN]) -> u32 {
    let mut sev: u32 = 0;
    let mut matched: u32 = 0;
    sev += match_status(got, "UpToDate".as_bytes(), TCB_UP_TO_DATE, &mut matched);
    sev += match_status(got, "SWHardeningNeeded".as_bytes(), TCB_SW_HARDENING_NEEDED, &mut matched);
    sev += match_status(got, "ConfigurationNeeded".as_bytes(), TCB_CONFIGURATION_NEEDED, &mut matched);
    sev += match_status(
        got,
        "ConfigurationAndSWHardeningNeeded".as_bytes(),
        TCB_CONFIG_AND_SW_HARDENING_NEEDED,
        &mut matched,
    );
    sev += match_status(got, "OutOfDate".as_bytes(), TCB_OUT_OF_DATE, &mut matched);
    sev += match_status(
        got,
        "OutOfDateConfigurationNeeded".as_bytes(),
        TCB_OUT_OF_DATE_CONFIG_NEEDED,
        &mut matched,
    );
    sev += match_status(got, "Revoked".as_bytes(), TCB_REVOKED, &mut matched);
    assert(matched == 1, "unknown tcbStatus");
    sev
}

// Returns sev if `got` starts with lit followed by a closing quote, else 0;
// increments *matched on a hit.
fn match_status<let M: u32>(got: [u8; STATUS_READ_LEN], lit: [u8; M], sev: u32, matched: &mut u32) -> u32 {
    let mut eq = true;
    for j in 0..M {
        eq &= got[j] == lit[j];
    }
    eq &= got[M] == 0x22; // closing quote right after the literal
    *matched += eq as u32;
    if eq { sev } else { 0 }
}

// Bind the 16 component svn values of one component array (positional binding):
// component 0 is pinned to arrayOff + len(arrayCtx); components 1..15 are
// prover-supplied offsets, each asserted to sit on `},{"svn":` (the separator +
// object start), strictly increasing, and < end_off (the field that closes the
// array). Sixteen strictly-increasing valid component starts drawn from exactly
// sixteen, with the minimum pinned to the true first, are precisely those sixteen
// in order, so off[j] is the real j-th component.
fn bind_svn_array<let N: u32, let AC: u32>(
    buf: [u8; N],
    signed_len: u32,
    array_off: u32,
    array_ctx: [u8; AC],
    svn_offs: [u32; MAX_SGX_COMPONENTS - 1],
    end_off: u32,
    want: [u32; MAX_SGX_COMPONENTS],
) {
    // Component 0: anchored on array_ctx then {"svn": then the value.
    let mut head: [u8; AC + 7] = [0; AC + 7];
    for i in 0..AC {
        head[i] = array_ctx[i];
    }
    for i in 0..7 {
        head[AC + i] = JSON_SVN_CTX[i];
    }
    let c0: [u8; SVN_FIELD_WIDTH] = extract_field(buf, array_off, signed_len, head);
    assert(parse_decimal(c0) == want[0], "sgx/tdx comp0 mismatch");
    let off0 = array_off + AC;

    // separator + object start: },{"svn":
    let sep_ctx: [u8; 9] = [0x7d, 0x2c, 0x7b, 0x22, 0x73, 0x76, 0x6e, 0x22, 0x3a];
    let mut prev = off0;
    for k in 0..(MAX_SGX_COMPONENTS - 1) {
        let off = svn_offs[k]; // points at {"svn": of component k+1
        assert(off > prev, "components not strictly increasing");
        assert(off < end_off, "component past array end");
        // read from off-2 (the separator) through the value
        let got: [u8; SVN_FIELD_WIDTH] = extract_field(buf, off - 2, signed_len, sep_ctx);
        assert(parse_decimal(got) == want[k + 1], "component svn mismatch");
        prev = off;
    }
}

// Bind one TCB level's 16 sgx + 16 tdx svn, pcesvn, and tcbStatus severity to the
// signed JSON, pinning every offset to this level's extent [lvl_start, lvl_end).
fn bind_one_level<let N: u32>(
    buf: [u8; N],
    signed_len: u32,
    i: u32,
    t: TcbBound,
    lvl_start: u32,
    lvl_end: u32,
    active: bool,
    status_cum: [u32; N],
) {
    // C3: pcesvn / status offsets inside this level's extent.
    let pce_off = t.pce_svn_off[i];
    let status_off = t.status_off[i];
    let tdx_off = t.tdx_arr_off[i];
    assert(pce_off >= lvl_start, "pcesvn before level");
    assert(pce_off < lvl_end, "pcesvn past level");
    assert(status_off >= lvl_start, "status before level");
    assert(status_off < lvl_end, "status past level");
    // F2: TdxArrOff inside [pcesvn, status), a subrange of this level (after pcesvn).
    assert(tdx_off >= pce_off, "tdx array before pcesvn");
    assert(tdx_off < status_off, "tdx array past status");
    // H1 (mirror the QE side): pin status_off as the FIRST "tcbStatus":" at-or-after
    // the level start. Without this, the C3 [lvl_start, lvl_end) bound still permits
    // a softer tcbStatus occurrence later in the SAME level (a validly-signed
    // TCB-Info could carry a second status literal after the level start). The
    // prefix sum status_cum gives the number of status literals strictly before any
    // offset; equality at status_off and lvl_start means NONE in [lvl_start,
    // status_off), so status_off is the first at-or-after lvl_start. (status_off
    // itself is a real "tcbStatus":" anchor via extract_string_enum below, and
    // status_off >= lvl_start was just asserted.) Gated on active. NOTE: a global
    // count is unsound here because "tcbStatus":" also appears in
    // tdxModuleIdentities[].tcbLevels, outside the platform tcbLevels region.
    // INVARIANT (keep extract_string_enum co-located): status_cumsum's in_window
    // gate counts only literals with q + 13 <= signed_len. It can never drop one in
    // [lvl_start, status_off) because extract_string_enum(status_off) below asserts
    // status_off + 13 + 1 <= signed_len, so status_off <= signed_len - 14 and every
    // q < status_off has q + 13 < signed_len (always counted). A refactor that pins
    // H1 without also bounding this status_off via extract_string_enum would break it.
    assert(!active | (status_cum[status_off] == status_cum[lvl_start]), "status not first in level");

    // pcesvn
    let pce_chars: [u8; U16_FIELD_WIDTH] = extract_field(buf, pce_off, signed_len, JSON_PCESVN_CTX);
    assert(parse_decimal(pce_chars) == t.pce_svn[i], "pcesvn mismatch");

    // sgx array: offset derived from level start (pinned), so the prover cannot move it.
    let sgx_arr_off = lvl_start + TCB_OPEN_LEN;
    bind_svn_array(
        buf, signed_len, sgx_arr_off, JSON_SGX_ARR_CTX, t.sgx_svn_off[i], pce_off, t.sgx_comps[i],
    );
    // tdx array: structurally pinned to [pcesvn, status).
    bind_svn_array(
        buf, signed_len, tdx_off, JSON_TDX_ARR_CTX, t.tdx_svn_off[i], status_off, t.tdx_comps[i],
    );

    // tcbStatus severity
    let status_chars: [u8; STATUS_READ_LEN] =
        extract_string_enum(buf, status_off, signed_len, JSON_STATUS_CTX);
    assert(status_severity(status_chars) == t.severity[i], "severity mismatch");
}

// Derive the platform PCE SVN from the leaf SGX extension PCESVN OID anchor. The
// INTEGER is 1 or 2 value bytes after the [len] byte; assemble big-endian.
pub fn platform_pce_svn_from_leaf<let N: u32>(leaf: [u8; N], off: u32, signed_len: u32) -> u32 {
    let pce: [u8; 3] = extract_field(leaf, off, signed_len, PCE_SVN_CTX);
    let len_byte = pce[0];
    let is2 = len_byte == 2;
    assert((len_byte == 1) | is2, "pcesvn INTEGER not 1/2 bytes");
    if is2 {
        (pce[1] as u32) * 256 + pce[2] as u32
    } else {
        pce[1] as u32
    }
}

// Bind all TCB levels, derive the count (F1 anti-skip), and select the canonical
// first-satisfiable level (G5) with a range-checked index (C1). Returns the
// chosen level's severity.
pub fn bind_tcb_levels<let N: u32>(
    buf: [u8; N],
    signed_len: u32,
    levels_off: u32,
    t: TcbBound,
    platform_cpu: [u8; 16],
    platform_pce: u32,
    platform_tee: [u8; 16],
) -> u32 {
    // Level 0 start pinned to the "tcbLevels":[ anchor then the level object.
    let mut head: [u8; 13 + 27] = [0; 13 + 27];
    for i in 0..13 {
        head[i] = JSON_TCB_LEVELS[i];
    }
    for i in 0..27 {
        head[13 + i] = JSON_LEVEL_CTX[i];
    }
    let _: [u8; 0] = extract_field(buf, levels_off, signed_len, head); // assert anchor
    let lvl0_start = levels_off + 13;

    // First pass: resolve starts + active flags.
    let mut starts: [u32; MAX_TCB_LEVELS] = [0; MAX_TCB_LEVELS];
    let mut active: [bool; MAX_TCB_LEVELS] = [false; MAX_TCB_LEVELS];
    starts[0] = lvl0_start;
    active[0] = true;
    let mut prev = lvl0_start;
    let mut prev_active = true;
    let mut count: u32 = 1;
    for i in 1..MAX_TCB_LEVELS {
        let s = t.lvl_start[i - 1];
        assert(s >= prev, "level starts not non-decreasing");
        let act = s != prev;
        // monotonic: once inactive, stays inactive.
        assert(!(!prev_active & act), "level active flag not monotonic");
        starts[i] = s;
        active[i] = act;
        if act {
            count += 1;
        }
        prev = s;
        prev_active = act;
    }
    // each start must be a real level anchor.
    for i in 0..MAX_TCB_LEVELS {
        assert_level_anchor(buf, signed_len, starts[i]);
    }
    assert(count == t.level_count, "derived tcb level count mismatch");

    // F1: active starts == total level anchors -> none skipped (pigeonhole).
    let total = count_literal(buf, signed_len, JSON_LEVEL_CTX);
    assert(count == total, "tcb level anchors skipped");

    // H1 prefix sum: one scan of the status anchor, reused by every level below.
    let status_cum = status_cumsum(buf, signed_len, JSON_STATUS_CTX);

    // Second pass: bind each level over its extent [start_i, end_i).
    for i in 0..MAX_TCB_LEVELS {
        let mut end = signed_len;
        if i + 1 < MAX_TCB_LEVELS {
            if active[i + 1] {
                end = starts[i + 1];
            }
        }
        bind_one_level(buf, signed_len, i, t, starts[i], end, active[i], status_cum);
    }

    // G5 + C1: canonical first-satisfiable selection.
    select_canonical_tcb(t, platform_cpu, platform_pce, platform_tee)
}

// Assert `start` sits on the per-level anchor JSON_LEVEL_CTX, inside the signed prefix.
fn assert_level_anchor<let N: u32>(buf: [u8; N], signed_len: u32, start: u32) {
    let _: [u8; 0] = extract_field(buf, start, signed_len, JSON_LEVEL_CTX);
}

// 1 iff the platform's CPU/PCE/TEE SVNs all meet or exceed level m's thresholds.
fn platform_satisfies(
    t: TcbBound,
    m: u32,
    platform_cpu: [u8; 16],
    platform_pce: u32,
    platform_tee: [u8; 16],
) -> bool {
    let mut ok = platform_pce >= t.pce_svn[m];
    for i in 0..MAX_SGX_COMPONENTS {
        ok &= platform_cpu[i] as u32 >= t.sgx_comps[m][i];
    }
    for i in 0..MAX_TDX_COMPONENTS {
        ok &= platform_tee[i] as u32 >= t.tdx_comps[m][i];
    }
    ok
}

// Canonical (first-satisfiable) selection: the chosen level must be satisfied and
// every active level before it must be unsatisfied. C1: match_idx < level_count
// (a typed u32 with an explicit bound; no field-wrapped index possible).
fn select_canonical_tcb(
    t: TcbBound,
    platform_cpu: [u8; 16],
    platform_pce: u32,
    platform_tee: [u8; 16],
) -> u32 {
    let idx = t.match_idx;
    assert(idx < t.level_count, "tcb match idx out of range");
    let mut sev: u32 = 0;
    for m in 0..MAX_TCB_LEVELS {
        let sat = platform_satisfies(t, m, platform_cpu, platform_pce, platform_tee);
        let active = m < t.level_count;
        let chosen = m == idx;
        let before = m < idx;
        if chosen {
            assert(sat, "chosen tcb level unsatisfied");
            sev = t.severity[m];
        }
        // every active level before the chosen one must be unsatisfied.
        assert(!(active & before & sat), "earlier tcb level satisfiable");
    }
    sev
}

// Bind QE-Identity policy fields + per-level QE TCB to the signed JSON (F3
// anti-skip, H1 last-level bound), and select the canonical QE level severity.
pub fn bind_qe_identity<let N: u32>(buf: [u8; N], signed_len: u32, q: QeBound, qe_isvsvn: u32) -> u32 {
    // mrsigner: 64 hex chars -> 32 bytes.
    let mr_hex: [u8; 64] = extract_field(buf, q.mrsigner_off, signed_len, "\"mrsigner\":\"".as_bytes());
    let mr = crate::parse::hex_to_bytes(mr_hex);
    for j in 0..32 {
        assert(mr[j] == q.mrsigner[j], "qe mrsigner json mismatch");
    }
    // isvprodid (dec u16).
    let prodid_chars: [u8; U16_FIELD_WIDTH] =
        extract_field(buf, q.isvprodid_off, signed_len, "\"isvprodid\":".as_bytes());
    assert(parse_decimal(prodid_chars) == q.isvprodid, "qe isvprodid json mismatch");
    // miscselect + mask (8 hex -> 4 bytes).
    let ms_hex: [u8; 8] = extract_field(buf, q.miscselect_off, signed_len, "\"miscselect\":\"".as_bytes());
    let mm_hex: [u8; 8] =
        extract_field(buf, q.miscmask_off, signed_len, "\"miscselectMask\":\"".as_bytes());
    let ms = crate::parse::hex_to_bytes(ms_hex);
    let mm = crate::parse::hex_to_bytes(mm_hex);
    for j in 0..4 {
        assert(ms[j] == q.miscselect[j], "qe miscselect json mismatch");
        assert(mm[j] == q.miscmask[j], "qe miscmask json mismatch");
    }
    // attributes + mask (32 hex -> 16 bytes). The mask must come from the JSON.
    let at_hex: [u8; 32] = extract_field(buf, q.attr_off, signed_len, "\"attributes\":\"".as_bytes());
    let am_hex: [u8; 32] =
        extract_field(buf, q.attrmask_off, signed_len, "\"attributesMask\":\"".as_bytes());
    let at = crate::parse::hex_to_bytes(at_hex);
    let am = crate::parse::hex_to_bytes(am_hex);
    for j in 0..16 {
        assert(at[j] == q.attributes[j], "qe attributes json mismatch");
        assert(am[j] == q.attrmask[j], "qe attrmask json mismatch");
    }

    // Per-level QE TCB: isvsvn (dec u16) + status severity. Slot 0 pinned; slots
    // 1.. derived active (start strictly exceeds previous). status pinned to the
    // level object (off < statusOff < next start, H1 first-status for the last).
    let mut prev_lvl = q.lvl_off[0];
    let mut count: u32 = 1;
    let mut prev_active = true;
    let mut sev_out: u32 = 0;
    assert(q.match_idx < q.level_count, "qe match idx out of range");

    // H1 prefix sum over the QE-Identity buffer (see bind_one_level / der::status_cumsum).
    let status_cum = status_cumsum(buf, signed_len, JSON_STATUS_CTX);

    for k in 0..MAX_QE_TCB_LEVELS {
        let off = q.lvl_off[k];
        let mut active = true;
        if k != 0 {
            assert(off >= prev_lvl, "qe level not non-decreasing");
            active = off != prev_lvl;
            assert(!(!prev_active & active), "qe active flag not monotonic");
            if active {
                count += 1;
            }
        }

        let isv_chars: [u8; U16_FIELD_WIDTH] = extract_field(buf, off, signed_len, JSON_QE_LVL_CTX);
        let got = parse_decimal(isv_chars);
        assert(!active | (got == q.isvsvn[k]), "qe isvsvn json mismatch");

        // status belongs to this level's object.
        let st_off = q.status_off[k];
        assert(!active | (off < st_off), "qe status before level");
        if k + 1 < MAX_QE_TCB_LEVELS {
            let next_off = q.lvl_off[k + 1];
            let next_active = (k + 1) < q.level_count;
            // when next level active, statusOff[k] must precede its start.
            assert(!(active & next_active) | (st_off < next_off), "qe status past next level");
        }
        // H1: for EVERY active level, statusOff is the FIRST "tcbStatus":" at-or-after
        // the level start (mirror the platform side). Gating on `active` (not
        // `is_last`) closes QE-H1-NONLAST: without it a non-last active level's
        // status_off could be pointed at a softer second status literal inside the
        // level. status_cum[st_off]==status_cum[off] means no status literal in
        // [off, st_off); combined with off < st_off this pins status_off to this
        // level's first status. (st_off is a real anchor via extract_string_enum
        // below, whose st_off + 13 + 1 <= signed_len bound is also what keeps the
        // in_window gate from dropping any literal in [off, st_off) -- same
        // co-location invariant as the platform side; keep them together.)
        assert(!active | (status_cum[st_off] == status_cum[off]), "qe status not first in level");

        let status_chars: [u8; STATUS_READ_LEN] =
            extract_string_enum(buf, st_off, signed_len, JSON_STATUS_CTX);
        let sev = status_severity(status_chars);
        assert(!active | (sev == q.severity[k]), "qe severity json mismatch");

        // canonical selection bookkeeping
        if k == q.match_idx {
            assert(qe_isvsvn >= q.isvsvn[k], "chosen qe level unsatisfied");
            sev_out = q.severity[k];
        }
        let before = k < q.match_idx;
        let sat = qe_isvsvn >= q.isvsvn[k];
        assert(!(active & before & sat), "earlier qe level satisfiable");

        prev_lvl = off;
        prev_active = active;
    }
    assert(count == q.level_count, "derived qe level count mismatch");
    // F3: active count == total QE level anchors -> none skipped.
    let total = count_literal(buf, signed_len, JSON_QE_LVL_CTX);
    assert(count == total, "qe level anchors skipped");

    sev_out
}

// Step 10: merged status = max(platform, QE); assert != Revoked.
pub fn merge_status(platform_sev: u32, qe_sev: u32) -> u32 {
    let merged = if platform_sev >= qe_sev { platform_sev } else { qe_sev };
    assert(merged != TCB_REVOKED, "tcb revoked");
    merged
}

// G4 freshness: issueDate <= Timestamp <= nextUpdate for both collateral blobs.
pub fn check_freshness<let TN: u32, let QN: u32>(
    tcb_info: [u8; TN],
    tcb_info_len: u32,
    tcb_issue_off: u32,
    tcb_next_off: u32,
    qe_id: [u8; QN],
    qe_id_len: u32,
    qe_issue_off: u32,
    qe_next_off: u32,
    timestamp: u64,
) {
    let issue_ctx = "\"issueDate\":\"".as_bytes();
    let next_ctx = "\"nextUpdate\":\"".as_bytes();
    let tcb_issue = parse_iso8601(extract_field(tcb_info, tcb_issue_off, tcb_info_len, issue_ctx));
    let tcb_next = parse_iso8601(extract_field(tcb_info, tcb_next_off, tcb_info_len, next_ctx));
    assert(timestamp >= tcb_issue, "tcb_info not yet valid");
    assert(timestamp <= tcb_next, "tcb_info expired");
    let qe_issue = parse_iso8601(extract_field(qe_id, qe_issue_off, qe_id_len, issue_ctx));
    let qe_next = parse_iso8601(extract_field(qe_id, qe_next_off, qe_id_len, next_ctx));
    assert(timestamp >= qe_issue, "qe_identity not yet valid");
    assert(timestamp <= qe_next, "qe_identity expired");
}
