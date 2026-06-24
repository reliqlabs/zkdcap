// ASCII / DER value parsing used to derive comparison values from
// signature-anchored bytes. Every parser here operates on bytes already proven
// to be inside a signed prefix (the caller's G1 bound), so the parsed numbers
// are the values the issuer signed.

// Decode one ASCII hex char (0-9, A-F, a-f) to 0..15, asserting it is valid hex.
pub fn hex_nibble(x: u8) -> u8 {
    let mut val: u8 = 0;
    let mut matched: u8 = 0;
    for d in 0..10 {
        let is = (x == 0x30 + d as u8) as u8;
        val += is * d as u8;
        matched += is;
    }
    for d in 0..6 {
        let is_u = (x == 0x41 + d as u8) as u8;
        let is_l = (x == 0x61 + d as u8) as u8;
        let hit = is_u + is_l;
        val += hit * (10 + d as u8);
        matched += hit;
    }
    assert(matched == 1, "invalid hex char");
    val
}

// Convert 2*N ASCII hex chars (big-endian) into N bytes.
pub fn hex_to_bytes<let N: u32>(chars: [u8; N]) -> [u8; N / 2] {
    let mut out = [0; N / 2];
    for i in 0..N / 2 {
        out[i] = hex_nibble(chars[2 * i]) * 16 + hex_nibble(chars[2 * i + 1]);
    }
    out
}

// Parse an unsigned ASCII-decimal integer from chars[0..W]. The number runs
// from chars[0] until the first non-digit (the JSON delimiter ',' '}' or '"').
// Asserts the first char is a digit (field present) and that no digit reappears
// after the run ends (rejects embedded garbage like "1,2"). Values fit in u32
// (svn 0..255, pcesvn/isvsvn/isvprodid 0..65535).
pub fn parse_decimal<let W: u32>(chars: [u8; W]) -> u32 {
    let mut acc: u32 = 0;
    let mut live: bool = true;
    for i in 0..W {
        let ch = chars[i];
        let is_digit = (ch >= 0x30) & (ch <= 0x39);
        // guard the subtraction: u8 underflows (panics) for non-digit bytes.
        let val = if is_digit { (ch - 0x30) as u32 } else { 0 };
        if i == 0 {
            assert(is_digit, "decimal field must start with a digit");
        } else {
            // once the digit run ended, a later digit is forbidden
            assert(!(!live & is_digit), "non-canonical decimal");
        }
        let take = live & is_digit;
        if take {
            acc = acc * 10 + val;
        }
        live = take;
    }
    acc
}

// Parse a fixed-format ISO-8601 timestamp "YYYY-MM-DDThh:mm:ssZ" into a packed
// order-preserving integer YYYYMMDDhhmmss (lexicographic == chronological for
// the fixed width, so >= / <= on the packed value is a valid date comparison).
pub fn parse_iso8601(s: [u8; 20]) -> u64 {
    let digit_pos: [u32; 14] = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    let mut acc: u64 = 0;
    for k in 0..14 {
        let ch = s[digit_pos[k]];
        assert((ch >= 0x30) & (ch <= 0x39), "iso8601 non-digit");
        acc = acc * 10 + (ch - 0x30) as u64;
    }
    acc
}

// Parse a 13-char DER UTCTime "YYMMDDHHMMSSZ" into the same packed
// YYYYMMDDhhmmss integer as parse_iso8601, assuming century 20xx (Intel PKI is
// post-2000). Order-preserving, so a >= / <= comparison is a valid date check.
pub fn parse_utctime(s: [u8; 13]) -> u64 {
    let mut acc: u64 = 20; // century prefix => 20YY
    for p in 0..12 {
        let ch = s[p];
        assert((ch >= 0x30) & (ch <= 0x39), "utctime non-digit");
        acc = acc * 10 + (ch - 0x30) as u64;
    }
    acc
}

// u16 from two little-endian bytes.
pub fn u16_le(lo: u8, hi: u8) -> u32 {
    lo as u32 + (hi as u32) * 256
}

// Bound folds for the collateral validity intersection (#3). All window bounds
// (cert notBefore/notAfter, CRL thisUpdate/nextUpdate, collateral issueDate/
// nextUpdate) parse to the same packed YYYYMMDDhhmmss u64, so a max of the lower
// bounds and a min of the upper bounds give the intersected validity window
// [valid_from, valid_until] in that same comparable space.
pub fn max_u64(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

pub fn min_u64(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}

// Pack K bytes (big-endian) into one BN254 field element: value = sum b[i] *
// 256^(K-1-i). K must be <= 31 (248 bits < the 254-bit field) so the integer is
// injective and never wraps. Used to shrink the public-input encoding (each byte
// was its own 32-byte field element; Xion x/zk caps UltraHonk public inputs at
// 320 fields). The packed value is a deterministic function of the (already
// signature-bound) bytes, so exposing it as a public output reveals nothing the
// bytes didn't and stays non-forgeable.
pub fn pack_be<let K: u32>(b: [u8; K]) -> Field {
    assert(K <= 31, "pack_be limb too wide");
    let mut acc: Field = 0;
    for i in 0..K {
        acc = acc * 256 + b[i] as Field;
    }
    acc
}

// Pack a contiguous big-endian byte range b[lo..lo+LEN] (LEN <= 31) into one field.
pub fn pack_range<let N: u32, let LEN: u32>(b: [u8; N], lo: u32) -> Field {
    assert(LEN <= 31, "pack_range limb too wide");
    let mut acc: Field = 0;
    for i in 0..LEN {
        acc = acc * 256 + b[lo + i] as Field;
    }
    acc
}

// A 48-byte measurement -> 2 limbs: [0..31], [31..48] (17 bytes).
pub fn pack_48(b: [u8; 48]) -> (Field, Field) {
    (pack_range::<48, 31>(b, 0), pack_range::<48, 17>(b, 31))
}

// report_data[64] -> 3 limbs: [0..31], [31..62], [62..64] (2 bytes).
pub fn pack_64(b: [u8; 64]) -> (Field, Field, Field) {
    (
        pack_range::<64, 31>(b, 0), pack_range::<64, 31>(b, 31), pack_range::<64, 2>(b, 62),
    )
}
