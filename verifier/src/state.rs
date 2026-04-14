use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    /// Name of the verification key registered in Xion's ZK module
    pub vkey_name: String,
    /// Expected SP1 program vkey hash (BN254 field element, decimal string).
    /// When set, public_inputs[0] must match this value.
    pub sp1_vkey_hash: Option<String>,
    /// Max allowed drift (seconds) between journal verification_timestamp and block time.
    /// Default: 3600 (1 hour).
    pub max_timestamp_drift_secs: u64,
    /// Accepted TCB statuses. If empty, all valid statuses are accepted.
    /// Example: ["UpToDate", "SWHardeningNeeded"]
    pub accepted_tcb_statuses: Vec<String>,
    /// If set, only these addresses can submit verification proofs.
    pub allowed_verifiers: Option<Vec<Addr>>,
    /// If set, journal report_data must match this hex-encoded value.
    pub expected_report_data: Option<String>,
}

#[cw_serde]
#[derive(Default)]
pub struct ExpectedMeasurements {
    pub mr_td: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr0: Option<String>,
    pub check_rtmr0: bool,
    pub rtmr3: Option<String>,
}

#[cw_serde]
pub struct VerificationRecord {
    pub quote_verified: bool,
    pub measurements_verified: bool,
    pub all_passed: bool,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
    pub mr_td: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
    pub report_data: String,
    pub mismatches: Vec<String>,
    pub verifier: Addr,
    pub block_height: u64,
    pub block_time: u64,
    pub zkvm: String,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const EXPECTED_MEASUREMENTS: Item<ExpectedMeasurements> = Item::new("expected_measurements");
pub const VERIFICATIONS: Map<&str, VerificationRecord> = Map::new("verifications");
