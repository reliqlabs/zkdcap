use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use num_bigint::BigUint;
use num_traits::{One, Zero};

// ── BN254 constants ──────────────────────────────────────────────────────

/// BN254 base field prime
const BN254_P_STR: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

/// BN254 curve equation: y² = x³ + 3
const BN254_B: u64 = 3;

/// BN254 G2 twist curve b' coefficient: b_twist = 3 / (9 + u)
/// From gnark-crypto bn254 parameters
const B_TWIST_C0: &str =
    "19485874751759354771024239261021720505790618469301721065564631296452457478373";
const B_TWIST_C1: &str =
    "266929791119991161246907387137283842545076965332900288569378510910307636690";

/// Compressed point flag bits (gnark convention)
const FLAG_SMALLEST: u8 = 0x80;
const FLAG_INFINITY: u8 = 0x40;
const FLAG_MASK: u8 = FLAG_SMALLEST | FLAG_INFINITY;

// ── CLI ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "zkdcap-vkey-converter",
    about = "Convert SP1 Groth16 vkey to SnarkJS verification_key.json"
)]
struct Args {
    /// Path to gnark vk.bin file
    #[arg(long, group = "input")]
    vk_bin: Option<PathBuf>,

    /// Use embedded SP1 v5.0.0 Groth16 vkey constants
    #[arg(long, group = "input")]
    sp1_v5: bool,

    /// Output file (default: stdout)
    #[arg(long, short)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let vkey = if args.sp1_v5 {
        load_sp1_v5_constants()
    } else if let Some(path) = args.vk_bin {
        let data = std::fs::read(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        parse_gnark_vkey(&data)?
    } else {
        bail!("specify either --vk-bin <path> or --sp1-v5");
    };

    let json = format_snarkjs_vkey(&vkey)?;
    let pretty = serde_json::to_string_pretty(&json)?;

    if let Some(path) = args.output {
        std::fs::write(&path, &pretty)?;
        eprintln!("wrote {}", path.display());
    } else {
        println!("{pretty}");
    }

    Ok(())
}

// ── Groth16 verification key types ───────────────────────────────────────

/// G1 affine point (BN254 base field)
struct G1Point {
    x: BigUint,
    y: BigUint,
}

/// G2 affine point (BN254 Fp2 extension)
struct G2Point {
    x: Fp2,
    y: Fp2,
}

/// Parsed Groth16 verification key
struct Groth16Vkey {
    alpha: G1Point,
    beta: G2Point,
    gamma: G2Point,
    delta: G2Point,
    ic: Vec<G1Point>,
}

// ── Fp arithmetic (mod p) ────────────────────────────────────────────────

fn p() -> BigUint {
    BigUint::parse_bytes(BN254_P_STR.as_bytes(), 10).unwrap()
}

fn fp_add(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a + b) % p
}

fn fp_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % p
    } else {
        p - ((b - a) % p)
    }
}

fn fp_mul(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a * b) % p
}

fn fp_neg(a: &BigUint, p: &BigUint) -> BigUint {
    if a.is_zero() {
        BigUint::zero()
    } else {
        p - (a % p)
    }
}

fn fp_inv(a: &BigUint, p: &BigUint) -> BigUint {
    // Fermat's little theorem: a^(-1) = a^(p-2) mod p
    a.modpow(&(p - BigUint::from(2u32)), p)
}

/// Square root in Fp. BN254 p ≡ 3 mod 4, so sqrt(a) = a^((p+1)/4).
fn fp_sqrt(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    let exp = (p + BigUint::one()) >> 2; // (p+1)/4
    let root = a.modpow(&exp, p);
    if &fp_mul(&root, &root, p) == a {
        Some(root)
    } else {
        None
    }
}

/// Is this element the "smallest" of {y, p-y}?
/// gnark convention: smallest means value ≤ (p-1)/2.
fn fp_is_smallest(a: &BigUint, p: &BigUint) -> bool {
    let half = (p - BigUint::one()) >> 1;
    *a <= half
}

// ── Fp2 arithmetic (Fp[u] / (u² + 1)) ───────────────────────────────────

#[derive(Clone)]
struct Fp2 {
    c0: BigUint, // real part
    c1: BigUint, // imaginary part (coefficient of u)
}

impl Fp2 {
    fn zero() -> Self {
        Fp2 {
            c0: BigUint::zero(),
            c1: BigUint::zero(),
        }
    }

    fn add(&self, other: &Fp2, p: &BigUint) -> Fp2 {
        Fp2 {
            c0: fp_add(&self.c0, &other.c0, p),
            c1: fp_add(&self.c1, &other.c1, p),
        }
    }

    fn mul(&self, other: &Fp2, p: &BigUint) -> Fp2 {
        // (a0 + a1*u)(b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u
        Fp2 {
            c0: fp_sub(
                &fp_mul(&self.c0, &other.c0, p),
                &fp_mul(&self.c1, &other.c1, p),
                p,
            ),
            c1: fp_add(
                &fp_mul(&self.c0, &other.c1, p),
                &fp_mul(&self.c1, &other.c0, p),
                p,
            ),
        }
    }

    fn square(&self, p: &BigUint) -> Fp2 {
        self.mul(self, p)
    }

    fn neg(&self, p: &BigUint) -> Fp2 {
        Fp2 {
            c0: fp_neg(&self.c0, p),
            c1: fp_neg(&self.c1, p),
        }
    }

    /// Square root in Fp2 using the norm-based algorithm.
    fn sqrt(&self, p: &BigUint) -> Option<Fp2> {
        // Special case: imaginary part is zero
        if self.c1.is_zero() {
            if let Some(root) = fp_sqrt(&self.c0, p) {
                return Some(Fp2 {
                    c0: root,
                    c1: BigUint::zero(),
                });
            }
            // c0 is not a QR in Fp; try sqrt(-c0) → result is purely imaginary
            let neg_c0 = fp_neg(&self.c0, p);
            if let Some(root) = fp_sqrt(&neg_c0, p) {
                return Some(Fp2 {
                    c0: BigUint::zero(),
                    c1: root,
                });
            }
            return None;
        }

        // General case: norm = c0² + c1² (norm of Fp2 element, since u² = -1)
        let norm = fp_add(
            &fp_mul(&self.c0, &self.c0, p),
            &fp_mul(&self.c1, &self.c1, p),
            p,
        );
        let t = fp_sqrt(&norm, p)?;

        let two = BigUint::from(2u32);
        let two_inv = fp_inv(&two, p);

        // Try alpha = (c0 + t) / 2
        let alpha = fp_mul(&fp_add(&self.c0, &t, p), &two_inv, p);
        if let Some(b0) = fp_sqrt(&alpha, p) {
            let denom = fp_mul(&two, &b0, p);
            let b1 = fp_mul(&self.c1, &fp_inv(&denom, p), p);
            return Some(Fp2 { c0: b0, c1: b1 });
        }

        // Try alpha = (c0 - t) / 2
        let alpha = fp_mul(&fp_sub(&self.c0, &t, p), &two_inv, p);
        if let Some(b0) = fp_sqrt(&alpha, p) {
            let denom = fp_mul(&two, &b0, p);
            let b1 = fp_mul(&self.c1, &fp_inv(&denom, p), p);
            return Some(Fp2 { c0: b0, c1: b1 });
        }

        None
    }

    /// gnark lexicographic "smallest" comparison for Fp2.
    /// Compares c1 (imaginary) first, then c0 (real).
    fn is_smallest(&self, p: &BigUint) -> bool {
        let neg = self.neg(p);
        if self.c1 != neg.c1 {
            fp_is_smallest(&self.c1, p)
        } else {
            fp_is_smallest(&self.c0, p)
        }
    }
}

// ── gnark binary format parser ───────────────────────────────────────────

/// Parse gnark Groth16 VerifyingKey from binary.
/// Auto-detects compressed vs uncompressed format.
fn parse_gnark_vkey(data: &[u8]) -> Result<Groth16Vkey> {
    let p = p();

    // Try uncompressed first (larger, easier to parse — no decompression needed)
    // Uncompressed layout: G1(64) + G2(128)*3 + u32(4) + G1(64)*n
    // Minimum with 1 IC point: 64 + 384 + 4 + 64 = 516
    if data.len() >= 516 {
        if let Ok(vkey) = parse_uncompressed(data, &p) {
            return Ok(vkey);
        }
    }

    // Try compressed
    // Compressed layout: G1(32) + G2(64)*3 + u32(4) + G1(32)*n
    // Minimum with 1 IC point: 32 + 192 + 4 + 32 = 260
    if data.len() >= 260 {
        return parse_compressed(data, &p);
    }

    bail!(
        "vk.bin too small ({} bytes) — expected ≥260 (compressed) or ≥516 (uncompressed)",
        data.len()
    );
}

fn parse_uncompressed(data: &[u8], p: &BigUint) -> Result<Groth16Vkey> {
    let mut cursor = 0;

    let alpha = read_g1_uncompressed(data, &mut cursor)?;
    let beta = read_g2_uncompressed(data, &mut cursor)?;
    let gamma = read_g2_uncompressed(data, &mut cursor)?;
    let delta = read_g2_uncompressed(data, &mut cursor)?;

    let num_ic = read_u32_be(data, &mut cursor)? as usize;
    if num_ic == 0 || num_ic > 100 {
        bail!("invalid IC count {num_ic} — not uncompressed format?");
    }

    let remaining = data.len() - cursor;
    let needed = num_ic * 64;
    if remaining < needed {
        bail!("not enough data for {num_ic} uncompressed IC points");
    }

    // Validate alpha is on curve
    let y_sq = fp_add(
        &fp_mul(&fp_mul(&alpha.x, &alpha.x, p), &alpha.x, p),
        &BigUint::from(BN254_B),
        p,
    );
    let y_check = fp_mul(&alpha.y, &alpha.y, p);
    if y_sq != y_check {
        bail!("alpha not on curve — not uncompressed format");
    }

    let mut ic = Vec::with_capacity(num_ic);
    for _ in 0..num_ic {
        ic.push(read_g1_uncompressed(data, &mut cursor)?);
    }

    Ok(Groth16Vkey {
        alpha,
        beta,
        gamma,
        delta,
        ic,
    })
}

fn parse_compressed(data: &[u8], p: &BigUint) -> Result<Groth16Vkey> {
    let mut cursor = 0;

    let alpha = read_g1_compressed(data, &mut cursor, p)
        .context("failed to decompress alpha G1")?;
    let beta = read_g2_compressed(data, &mut cursor, p)
        .context("failed to decompress beta G2")?;
    let gamma = read_g2_compressed(data, &mut cursor, p)
        .context("failed to decompress gamma G2")?;
    let delta = read_g2_compressed(data, &mut cursor, p)
        .context("failed to decompress delta G2")?;

    let num_ic = read_u32_be(data, &mut cursor)? as usize;
    if num_ic == 0 || num_ic > 100 {
        bail!("invalid IC count: {num_ic}");
    }

    let mut ic = Vec::with_capacity(num_ic);
    for i in 0..num_ic {
        ic.push(
            read_g1_compressed(data, &mut cursor, p)
                .with_context(|| format!("failed to decompress IC[{i}]"))?,
        );
    }

    Ok(Groth16Vkey {
        alpha,
        beta,
        gamma,
        delta,
        ic,
    })
}

// ── Point readers ────────────────────────────────────────────────────────

fn read_u32_be(data: &[u8], cursor: &mut usize) -> Result<u32> {
    if *cursor + 4 > data.len() {
        bail!("unexpected EOF reading u32 at offset {}", *cursor);
    }
    let val = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into()?);
    *cursor += 4;
    Ok(val)
}

fn read_bytes<'a>(data: &'a [u8], cursor: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *cursor + n > data.len() {
        bail!("unexpected EOF reading {} bytes at offset {}", n, *cursor);
    }
    let slice = &data[*cursor..*cursor + n];
    *cursor += n;
    Ok(slice)
}

fn read_g1_uncompressed(data: &[u8], cursor: &mut usize) -> Result<G1Point> {
    let bytes = read_bytes(data, cursor, 64)?;
    Ok(G1Point {
        x: BigUint::from_bytes_be(&bytes[0..32]),
        y: BigUint::from_bytes_be(&bytes[32..64]),
    })
}

fn read_g2_uncompressed(data: &[u8], cursor: &mut usize) -> Result<G2Point> {
    // gnark RawBytes order: X.A0, X.A1, Y.A0, Y.A1
    let bytes = read_bytes(data, cursor, 128)?;
    Ok(G2Point {
        x: Fp2 {
            c0: BigUint::from_bytes_be(&bytes[0..32]),
            c1: BigUint::from_bytes_be(&bytes[32..64]),
        },
        y: Fp2 {
            c0: BigUint::from_bytes_be(&bytes[64..96]),
            c1: BigUint::from_bytes_be(&bytes[96..128]),
        },
    })
}

fn read_g1_compressed(data: &[u8], cursor: &mut usize, p: &BigUint) -> Result<G1Point> {
    let bytes = read_bytes(data, cursor, 32)?;
    let flags = bytes[0];

    if flags & FLAG_INFINITY != 0 {
        return Ok(G1Point {
            x: BigUint::zero(),
            y: BigUint::zero(),
        });
    }

    let want_smallest = flags & FLAG_SMALLEST != 0;

    // Clear flag bits to get X coordinate
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(bytes);
    x_bytes[0] &= !FLAG_MASK;

    let x = BigUint::from_bytes_be(&x_bytes);

    // y² = x³ + 3
    let x2 = fp_mul(&x, &x, p);
    let x3 = fp_mul(&x2, &x, p);
    let y_sq = fp_add(&x3, &BigUint::from(BN254_B), p);

    let y = fp_sqrt(&y_sq, p).context("G1: no square root for y²")?;

    // Choose correct Y based on gnark sign convention
    let y = if want_smallest == fp_is_smallest(&y, p) {
        y
    } else {
        fp_neg(&y, p)
    };

    Ok(G1Point { x, y })
}

fn read_g2_compressed(data: &[u8], cursor: &mut usize, p: &BigUint) -> Result<G2Point> {
    // gnark compressed G2: 64 bytes = X.A1 (32B, with flags) + X.A0 (32B)
    let bytes = read_bytes(data, cursor, 64)?;
    let flags = bytes[0];

    if flags & FLAG_INFINITY != 0 {
        return Ok(G2Point {
            x: Fp2::zero(),
            y: Fp2::zero(),
        });
    }

    let want_smallest = flags & FLAG_SMALLEST != 0;

    // Parse X: A1 first (with flags cleared), then A0
    let mut a1_bytes = [0u8; 32];
    a1_bytes.copy_from_slice(&bytes[0..32]);
    a1_bytes[0] &= !FLAG_MASK;

    let x = Fp2 {
        c0: BigUint::from_bytes_be(&bytes[32..64]), // A0 = real
        c1: BigUint::from_bytes_be(&a1_bytes),      // A1 = imaginary
    };

    // y² = x³ + b_twist
    let b_twist = Fp2 {
        c0: BigUint::parse_bytes(B_TWIST_C0.as_bytes(), 10).unwrap(),
        c1: BigUint::parse_bytes(B_TWIST_C1.as_bytes(), 10).unwrap(),
    };

    let x2 = x.square(p);
    let x3 = x2.mul(&x, p);
    let y_sq = x3.add(&b_twist, p);

    let y = y_sq.sqrt(p).context("G2: no square root for y² in Fp2")?;

    // Choose correct Y based on gnark lexicographic sign convention
    let y = if want_smallest == y.is_smallest(p) {
        y
    } else {
        y.neg(p)
    };

    Ok(G2Point { x, y })
}

// ── SP1 v5.0.0 embedded constants ────────────────────────────────────────

/// Load SP1 v5.0.0 Groth16 vkey from Solidity verifier constants.
/// Source: sp1-contracts/contracts/src/v5.0.0/Groth16Verifier.sol
/// Note: Solidity stores NEGATED beta/gamma/delta Y coordinates.
fn load_sp1_v5_constants() -> Groth16Vkey {
    let p = p();

    let alpha = G1Point {
        x: dec("20491192805390485299153009773594534940189261866228447918068658471970481763042"),
        y: dec("9383485363053290200918347156157836566562967994039712273449902621266178545958"),
    };

    // Solidity has BETA_NEG — negate Y to get positive beta
    let beta = G2Point {
        x: Fp2 {
            c0: dec("6375614351688725206403948262868962793625744043794305715222011528459656738731"),
            c1: dec("4252822878758300859123897981450591353533073413197771768651442665752259397132"),
        },
        y: Fp2 {
            c0: fp_neg(
                &dec("11383000245469012944693504663162918391286475477077232690815866754273895001727"),
                &p,
            ),
            c1: fp_neg(
                &dec("41207766310529818958173054109690360505148424997958324311878202295167071904"),
                &p,
            ),
        },
    };

    let gamma = G2Point {
        x: Fp2 {
            c0: dec("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
            c1: dec("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
        },
        y: Fp2 {
            c0: fp_neg(
                &dec("13392588948715843804641432497768002650278120570034223513918757245338268106653"),
                &p,
            ),
            c1: fp_neg(
                &dec("17805874995975841540914202342111839520379459829704422454583296818431106115052"),
                &p,
            ),
        },
    };

    let delta = G2Point {
        x: Fp2 {
            c0: dec("1807939758600928081661535078044266309701426477869595321608690071623627252461"),
            c1: dec("13017767206419180294867239590191240882490168779777616723978810680471506089190"),
        },
        y: Fp2 {
            c0: fp_neg(
                &dec("11385252965472363874004017020523979267854101512663014352368174256411716100034"),
                &p,
            ),
            c1: fp_neg(
                &dec("707821308472421780425082520239282952693670279239989952629124761519869475067"),
                &p,
            ),
        },
    };

    let ic = vec![
        // CONSTANT (IC[0])
        G1Point {
            x: dec("17203997695518370725253383800612862082040222186834248316724952811913305748878"),
            y: dec("282619892079818506885924724237935832196325815176482254129420869757043108110"),
        },
        // PUB_0 (IC[1])
        G1Point {
            x: dec("2763789253671512309630211343474627955637016507408470052385640371173442321228"),
            y: dec("7070003421332099028511324531870215047017050364545890942981741487547942466073"),
        },
        // PUB_1 (IC[2])
        G1Point {
            x: dec("2223923876691923064813371578678400285087400227347901303400514986210692294428"),
            y: dec("3228708299174762375496115493137156328822199374794870011715145604387710550517"),
        },
    ];

    Groth16Vkey {
        alpha,
        beta,
        gamma,
        delta,
        ic,
    }
}

fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).expect("invalid decimal constant")
}

// ── SnarkJS JSON output ──────────────────────────────────────────────────

fn format_snarkjs_vkey(vkey: &Groth16Vkey) -> Result<serde_json::Value> {
    let n_public = vkey.ic.len() - 1; // IC has nPublic + 1 elements

    let ic: Vec<serde_json::Value> = vkey
        .ic
        .iter()
        .map(|pt| g1_to_json(pt))
        .collect();

    Ok(serde_json::json!({
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": n_public,
        "vk_alpha_1": g1_to_json(&vkey.alpha),
        "vk_beta_2": g2_to_json(&vkey.beta),
        "vk_gamma_2": g2_to_json(&vkey.gamma),
        "vk_delta_2": g2_to_json(&vkey.delta),
        "vk_alphabeta_12": compute_alpha_beta_placeholder(),
        "IC": ic,
    }))
}

fn g1_to_json(pt: &G1Point) -> serde_json::Value {
    serde_json::json!([pt.x.to_string(), pt.y.to_string(), "1"])
}

fn g2_to_json(pt: &G2Point) -> serde_json::Value {
    // SnarkJS format: [[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]
    serde_json::json!([
        [pt.x.c0.to_string(), pt.x.c1.to_string()],
        [pt.y.c0.to_string(), pt.y.c1.to_string()],
        ["1", "0"]
    ])
}

/// Placeholder for vk_alphabeta_12 (GT element from e(alpha, beta)).
/// circom2gnark recomputes this from alpha and beta, so the value here
/// is not used for verification. We include it for JSON compatibility.
fn compute_alpha_beta_placeholder() -> serde_json::Value {
    // 2x3x2 array of zero strings — circom2gnark ignores this field
    serde_json::json!([
        [["0","0"],["0","0"],["0","0"]],
        [["0","0"],["0","0"],["0","0"]]
    ])
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp_sqrt() {
        let p = p();
        // sqrt(4) = 2
        let four = BigUint::from(4u32);
        let root = fp_sqrt(&four, &p).unwrap();
        assert!(root == BigUint::from(2u32) || root == fp_neg(&BigUint::from(2u32), &p));
    }

    #[test]
    fn test_fp_inv() {
        let p = p();
        let a = BigUint::from(7u32);
        let inv = fp_inv(&a, &p);
        assert_eq!(fp_mul(&a, &inv, &p), BigUint::one());
    }

    #[test]
    fn test_fp2_sqrt() {
        let p = p();
        // Create a known Fp2 element, square it, then take sqrt
        let original = Fp2 {
            c0: BigUint::from(3u32),
            c1: BigUint::from(5u32),
        };
        let squared = original.square(&p);
        let root = squared.sqrt(&p).expect("sqrt should exist");

        // Verify root² = squared
        let check = root.square(&p);
        assert_eq!(check.c0, squared.c0);
        assert_eq!(check.c1, squared.c1);
    }

    #[test]
    fn test_g1_roundtrip() {
        // Use the SP1 v5.0.0 alpha point — known to be on the curve
        let p = p();
        let x = dec("20491192805390485299153009773594534940189261866228447918068658471970481763042");
        let y = dec("9383485363053290200918347156157836566562967994039712273449902621266178545958");

        // Verify it's on the curve: y² = x³ + 3
        let x3 = fp_mul(&fp_mul(&x, &x, &p), &x, &p);
        let rhs = fp_add(&x3, &BigUint::from(BN254_B), &p);
        let y2 = fp_mul(&y, &y, &p);
        assert_eq!(y2, rhs, "alpha should be on curve");
    }

    #[test]
    fn test_sp1_v5_output() {
        let vkey = load_sp1_v5_constants();
        let json = format_snarkjs_vkey(&vkey).unwrap();

        assert_eq!(json["protocol"], "groth16");
        assert_eq!(json["curve"], "bn128");
        assert_eq!(json["nPublic"], 2);

        // Check alpha
        let alpha = &json["vk_alpha_1"];
        assert_eq!(
            alpha[0],
            "20491192805390485299153009773594534940189261866228447918068658471970481763042"
        );

        // Check IC length
        assert_eq!(json["IC"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_compressed_g1_roundtrip() {
        let p = p();
        // Known point: alpha from SP1 v5
        let x = dec("20491192805390485299153009773594534940189261866228447918068658471970481763042");
        let y = dec("9383485363053290200918347156157836566562967994039712273449902621266178545958");

        // Compress: store X with sign bit
        let mut compressed = [0u8; 32];
        let x_bytes = x.to_bytes_be();
        let start = 32 - x_bytes.len();
        compressed[start..].copy_from_slice(&x_bytes);

        if fp_is_smallest(&y, &p) {
            compressed[0] |= FLAG_SMALLEST;
        }

        // Decompress
        let mut cursor = 0;
        let result = read_g1_compressed(&compressed, &mut cursor, &p).unwrap();

        assert_eq!(result.x, x);
        assert_eq!(result.y, y);
    }
}
