use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[allow(unused_imports)]
use crate::state::{Config, ExpectedMeasurements, VerificationRecord};

#[cw_serde]
pub struct ExpectedMeasurementsMsg {
    pub mr_td: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr0: Option<String>,
    pub check_rtmr0: bool,
    pub rtmr3: Option<String>,
}

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Option<String>,
    /// Name of the verification key registered in Xion's ZK module
    pub vkey_name: String,
    /// Expected SP1 program vkey hash (BN254 field element, decimal string).
    pub sp1_vkey_hash: Option<String>,
    /// Max allowed drift (seconds) between journal timestamp and block time. Default: 3600.
    pub max_timestamp_drift_secs: Option<u64>,
    /// Accepted TCB statuses. If empty/None, all valid statuses are accepted.
    pub accepted_tcb_statuses: Option<Vec<String>>,
    /// If set, only these addresses can submit verification proofs.
    pub allowed_verifiers: Option<Vec<String>>,
    /// If set, journal report_data must match this hex-encoded value.
    pub expected_report_data: Option<String>,
    pub expected_measurements: Option<ExpectedMeasurementsMsg>,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Verify a DCAP attestation via ZK proof
    VerifyAttestation {
        /// SnarkJS-format Groth16 proof JSON bytes
        proof: Binary,
        /// Decimal field element strings (public inputs to the Groth16 circuit)
        public_inputs: Vec<String>,
        /// Serialized DcapJournal (JSON bytes)
        journal: Binary,
    },
    SetExpectedMeasurements(ExpectedMeasurementsMsg),
    UpdateConfig {
        admin: Option<String>,
        vkey_name: Option<String>,
        sp1_vkey_hash: Option<String>,
        max_timestamp_drift_secs: Option<u64>,
        accepted_tcb_statuses: Option<Vec<String>>,
        allowed_verifiers: Option<Vec<String>>,
        expected_report_data: Option<String>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Config)]
    GetConfig {},
    #[returns(ExpectedMeasurements)]
    GetExpectedMeasurements {},
    #[returns(VerificationRecord)]
    GetVerification { quote_hash: String },
}

#[cw_serde]
pub struct MigrateMsg {}
