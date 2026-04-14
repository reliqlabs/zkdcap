use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, GrpcQuery, MessageInfo,
    QueryRequest, Response, Uint256,
};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::error::{ContractError, ContractResult};
use crate::msg::{ExecuteMsg, ExpectedMeasurementsMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::state::{
    Config, ExpectedMeasurements, VerificationRecord, CONFIG,
    EXPECTED_MEASUREMENTS, VERIFICATIONS,
};

const CONTRACT_NAME: &str = "crates.io:zkdcap-verifier";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default max timestamp drift: 1 hour
const DEFAULT_MAX_TIMESTAMP_DRIFT_SECS: u64 = 3600;

// ── Protobuf types for Xion ZK module ──────────────────────────────────

/// xion.zk.v1.QueryVerifyRequest
#[derive(Clone, PartialEq, Message)]
struct QueryVerifyRequest {
    #[prost(bytes = "vec", tag = "1")]
    proof: Vec<u8>,
    #[prost(string, repeated, tag = "2")]
    public_inputs: Vec<String>,
    #[prost(string, tag = "3")]
    vkey_name: String,
    #[prost(uint64, tag = "4")]
    vkey_id: u64,
}

/// xion.zk.v1.ProofVerifyResponse
#[derive(Clone, PartialEq, Message)]
struct ProofVerifyResponse {
    #[prost(bool, tag = "1")]
    verified: bool,
}

// ── DcapJournal (mirror of zkdcap-core, no zkVM deps in contract) ──────

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct DcapJournal {
    #[serde(with = "hex::serde")]
    quote_hash: [u8; 32],
    quote_verified: bool,
    tcb_status: String,
    advisory_ids: Vec<String>,
    mr_td: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
    report_data: String,
    verification_timestamp: u64,
}

// ── Entry points ────────────────────────────────────────────────────────

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> ContractResult<Response> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = msg
        .admin
        .map(|a| deps.api.addr_validate(&a))
        .transpose()?
        .unwrap_or(info.sender);

    let allowed_verifiers = msg
        .allowed_verifiers
        .map(|addrs| {
            addrs
                .iter()
                .map(|a| deps.api.addr_validate(a))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    CONFIG.save(
        deps.storage,
        &Config {
            admin: admin.clone(),
            vkey_name: msg.vkey_name,
            sp1_vkey_hash: msg.sp1_vkey_hash,
            max_timestamp_drift_secs: msg
                .max_timestamp_drift_secs
                .unwrap_or(DEFAULT_MAX_TIMESTAMP_DRIFT_SECS),
            accepted_tcb_statuses: msg.accepted_tcb_statuses.unwrap_or_default(),
            allowed_verifiers,
            expected_report_data: msg.expected_report_data,
        },
    )?;

    if let Some(m) = msg.expected_measurements {
        EXPECTED_MEASUREMENTS.save(
            deps.storage,
            &ExpectedMeasurements {
                mr_td: m.mr_td,
                rtmr1: m.rtmr1,
                rtmr2: m.rtmr2,
                rtmr0: m.rtmr0,
                check_rtmr0: m.check_rtmr0,
                rtmr3: m.rtmr3,
            },
        )?;
    }

    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> ContractResult<Response> {
    match msg {
        ExecuteMsg::VerifyAttestation {
            proof,
            public_inputs,
            journal,
        } => execute_verify(deps, env, info, proof, public_inputs, journal),
        ExecuteMsg::SetExpectedMeasurements(m) => set_expected_measurements(deps, info, m),
        ExecuteMsg::UpdateConfig {
            admin,
            vkey_name,
            sp1_vkey_hash,
            max_timestamp_drift_secs,
            accepted_tcb_statuses,
            allowed_verifiers,
            expected_report_data,
        } => update_config(
            deps,
            info,
            admin,
            vkey_name,
            sp1_vkey_hash,
            max_timestamp_drift_secs,
            accepted_tcb_statuses,
            allowed_verifiers,
            expected_report_data,
        ),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> ContractResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => Ok(to_json_binary(&CONFIG.load(deps.storage)?)?),
        QueryMsg::GetExpectedMeasurements {} => {
            Ok(to_json_binary(&EXPECTED_MEASUREMENTS.load(deps.storage)?)?)
        }
        QueryMsg::GetVerification { quote_hash } => {
            Ok(to_json_binary(&VERIFICATIONS.load(deps.storage, &quote_hash)?)?)
        }
    }
}

#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> ContractResult<Response> {
    let version = cw2::get_contract_version(deps.storage)?;
    if version.contract != CONTRACT_NAME {
        return Err(ContractError::InvalidJournal {
            reason: format!("cannot migrate from {}", version.contract),
        });
    }
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "migrate"))
}

// ── Execute handlers ────────────────────────────────────────────────────

fn execute_verify(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proof: Binary,
    public_inputs: Vec<String>,
    journal: Binary,
) -> ContractResult<Response> {
    let config = CONFIG.load(deps.storage)?;

    // 0. Access control: check allowed verifiers
    if let Some(ref allowed) = config.allowed_verifiers {
        if !allowed.contains(&info.sender) {
            return Err(ContractError::NotAllowedVerifier);
        }
    }

    // 1. Verify Groth16 proof via Xion ZK module
    let verify_req = QueryVerifyRequest {
        proof: proof.to_vec(),
        public_inputs: public_inputs.clone(),
        vkey_name: config.vkey_name,
        vkey_id: 0,
    };

    let mut req_bytes = Vec::new();
    verify_req.encode(&mut req_bytes)?;

    let grpc_query = QueryRequest::Grpc(GrpcQuery {
        path: "/xion.zk.v1.Query/ProofVerify".to_string(),
        data: Binary::from(req_bytes),
    });

    let resp_bytes: Binary = deps.querier.query(&grpc_query)?;
    let verify_resp = ProofVerifyResponse::decode(resp_bytes.as_slice())?;

    if !verify_resp.verified {
        return Err(ContractError::ProofVerificationFailed);
    }

    // 2. Verify journal binding and optional vkey hash
    let journal_hash = Sha256::digest(journal.as_slice());

    if let Some(ref expected_vkey_hash) = config.sp1_vkey_hash {
        // SP1 format: public_inputs[0] = vkey hash, public_inputs[1] = masked sha256(journal)
        if public_inputs.len() < 2 {
            return Err(ContractError::JournalBindingMismatch {
                expected: "2 public inputs for SP1".to_string(),
                actual: format!("{} inputs", public_inputs.len()),
            });
        }

        // Check vkey hash binding (public_inputs[0])
        if public_inputs[0] != *expected_vkey_hash {
            return Err(ContractError::VkeyHashMismatch {
                expected: expected_vkey_hash.clone(),
                actual: public_inputs[0].clone(),
            });
        }

        // Check journal hash binding (public_inputs[1])
        // SP1 masks top 3 bits to fit in BN254 scalar field
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&journal_hash);
        hash_bytes[0] &= 0x1F;
        let expected_journal = Uint256::from_be_bytes(hash_bytes).to_string();
        if public_inputs[1] != expected_journal {
            return Err(ContractError::JournalBindingMismatch {
                expected: expected_journal,
                actual: public_inputs[1].clone(),
            });
        }
    } else {
        // Generic format: public_inputs[0] = 0x{sha256(journal)}
        let expected_input = format!("0x{}", hex::encode(journal_hash));
        if public_inputs.first().map(|s| s.as_str()) != Some(expected_input.as_str()) {
            return Err(ContractError::JournalBindingMismatch {
                expected: expected_input,
                actual: public_inputs.first().cloned().unwrap_or_default(),
            });
        }
    }

    // 3. Parse journal
    let j: DcapJournal = serde_json::from_slice(journal.as_slice())
        .map_err(|e| ContractError::InvalidJournal {
            reason: e.to_string(),
        })?;

    if !j.quote_verified {
        return Err(ContractError::QuoteNotVerified);
    }

    // 4. Validate timestamp drift
    let block_time = env.block.time.seconds();
    let drift = if j.verification_timestamp > block_time {
        j.verification_timestamp - block_time
    } else {
        block_time - j.verification_timestamp
    };
    if drift > config.max_timestamp_drift_secs {
        return Err(ContractError::TimestampDriftExceeded {
            journal: j.verification_timestamp,
            block: block_time,
            max_drift: config.max_timestamp_drift_secs,
        });
    }

    // 5. Validate TCB status policy
    if !config.accepted_tcb_statuses.is_empty()
        && !config.accepted_tcb_statuses.contains(&j.tcb_status)
    {
        return Err(ContractError::UnacceptableTcbStatus {
            status: j.tcb_status,
        });
    }

    // 6. Validate report_data
    if let Some(ref expected_rd) = config.expected_report_data {
        if j.report_data != *expected_rd {
            return Err(ContractError::ReportDataMismatch {
                expected: expected_rd.clone(),
                actual: j.report_data.clone(),
            });
        }
    }

    // 7. Replay protection
    let quote_hash = hex::encode(j.quote_hash);
    if VERIFICATIONS.has(deps.storage, &quote_hash) {
        return Err(ContractError::AlreadyVerified);
    }

    // 8. Check measurements against expected (including RTMR3)
    let mut mismatches = Vec::new();

    let measurements_verified = match EXPECTED_MEASUREMENTS.may_load(deps.storage)? {
        Some(expected) => {
            let before = mismatches.len();
            check_measurement(&expected.mr_td, &j.mr_td, "mr_td", &mut mismatches);
            check_measurement(&expected.rtmr1, &j.rtmr1, "rtmr1", &mut mismatches);
            check_measurement(&expected.rtmr2, &j.rtmr2, "rtmr2", &mut mismatches);
            if expected.check_rtmr0 {
                if let Some(ref exp_rtmr0) = expected.rtmr0 {
                    check_measurement(exp_rtmr0, &j.rtmr0, "rtmr0", &mut mismatches);
                }
            }
            if let Some(ref exp_rtmr3) = expected.rtmr3 {
                check_measurement(exp_rtmr3, &j.rtmr3, "rtmr3", &mut mismatches);
            }
            mismatches.len() == before
        }
        None => true,
    };

    let all_passed = measurements_verified;

    let record = VerificationRecord {
        quote_verified: true,
        measurements_verified,
        all_passed,
        tcb_status: j.tcb_status.clone(),
        advisory_ids: j.advisory_ids.clone(),
        mr_td: j.mr_td,
        rtmr0: j.rtmr0,
        rtmr1: j.rtmr1,
        rtmr2: j.rtmr2,
        rtmr3: j.rtmr3,
        report_data: j.report_data,
        mismatches,
        verifier: info.sender,
        block_height: env.block.height,
        block_time: env.block.time.seconds(),
        zkvm: "sp1".to_string(),
    };

    VERIFICATIONS.save(deps.storage, &quote_hash, &record)?;

    Ok(Response::new()
        .add_attribute("action", "verify_attestation")
        .add_attribute("quote_hash", &quote_hash)
        .add_attribute("tcb_status", &j.tcb_status)
        .add_attribute("all_passed", all_passed.to_string())
        .add_attribute("measurements_verified", measurements_verified.to_string()))
}

fn set_expected_measurements(
    deps: DepsMut,
    info: MessageInfo,
    msg: ExpectedMeasurementsMsg,
) -> ContractResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }

    EXPECTED_MEASUREMENTS.save(
        deps.storage,
        &ExpectedMeasurements {
            mr_td: msg.mr_td,
            rtmr1: msg.rtmr1,
            rtmr2: msg.rtmr2,
            rtmr0: msg.rtmr0,
            check_rtmr0: msg.check_rtmr0,
            rtmr3: msg.rtmr3,
        },
    )?;

    Ok(Response::new().add_attribute("action", "set_expected_measurements"))
}

#[allow(clippy::too_many_arguments)]
fn update_config(
    deps: DepsMut,
    info: MessageInfo,
    admin: Option<String>,
    vkey_name: Option<String>,
    sp1_vkey_hash: Option<String>,
    max_timestamp_drift_secs: Option<u64>,
    accepted_tcb_statuses: Option<Vec<String>>,
    allowed_verifiers: Option<Vec<String>>,
    expected_report_data: Option<String>,
) -> ContractResult<Response> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized);
    }

    if let Some(new_admin) = admin {
        config.admin = deps.api.addr_validate(&new_admin)?;
    }
    if let Some(new_vkey) = vkey_name {
        config.vkey_name = new_vkey;
    }
    if let Some(hash) = sp1_vkey_hash {
        if hash.is_empty() {
            config.sp1_vkey_hash = None;
        } else {
            config.sp1_vkey_hash = Some(hash);
        }
    }
    if let Some(drift) = max_timestamp_drift_secs {
        config.max_timestamp_drift_secs = drift;
    }
    if let Some(statuses) = accepted_tcb_statuses {
        config.accepted_tcb_statuses = statuses;
    }
    if let Some(verifiers) = allowed_verifiers {
        if verifiers.is_empty() {
            config.allowed_verifiers = None;
        } else {
            config.allowed_verifiers = Some(
                verifiers
                    .iter()
                    .map(|a| deps.api.addr_validate(a))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
    }
    if let Some(rd) = expected_report_data {
        if rd.is_empty() {
            config.expected_report_data = None;
        } else {
            config.expected_report_data = Some(rd);
        }
    }

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "update_config"))
}

fn check_measurement(expected: &str, actual: &str, field: &str, mismatches: &mut Vec<String>) {
    if expected != actual {
        mismatches.push(format!(
            "{}: expected={}, actual={}",
            field, expected, actual
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Addr;

    fn default_instantiate_msg() -> InstantiateMsg {
        InstantiateMsg {
            admin: None,
            vkey_name: "zkdcap-sp1".to_string(),
            sp1_vkey_hash: None,
            max_timestamp_drift_secs: None,
            accepted_tcb_statuses: None,
            allowed_verifiers: None,
            expected_report_data: None,
            expected_measurements: None,
        }
    }

    #[test]
    fn test_journal_parsing() {
        let journal_json = serde_json::json!({
            "quote_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "quote_verified": true,
            "tcb_status": "UpToDate",
            "advisory_ids": [],
            "mr_td": "abcd",
            "rtmr0": "1234",
            "rtmr1": "5678",
            "rtmr2": "9abc",
            "rtmr3": "def0",
            "report_data": "aabb",
            "verification_timestamp": 1700000000
        });

        let bytes = serde_json::to_vec(&journal_json).unwrap();
        let j: DcapJournal = serde_json::from_slice(&bytes).unwrap();

        assert!(j.quote_verified);
        assert_eq!(j.tcb_status, "UpToDate");
        assert_eq!(j.mr_td, "abcd");
    }

    #[test]
    fn test_check_measurement_match() {
        let mut mismatches = Vec::new();
        check_measurement("abc", "abc", "mr_td", &mut mismatches);
        assert!(mismatches.is_empty());
    }

    #[test]
    fn test_check_measurement_mismatch() {
        let mut mismatches = Vec::new();
        check_measurement("abc", "def", "mr_td", &mut mismatches);
        assert_eq!(mismatches.len(), 1);
        assert!(mismatches[0].contains("mr_td"));
    }

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };

        let msg = default_instantiate_msg();

        let res = instantiate(deps.as_mut(), cosmwasm_std::testing::mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes[0].value, "instantiate");

        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.admin, Addr::unchecked("creator"));
        assert_eq!(config.vkey_name, "zkdcap-sp1");
        assert_eq!(config.sp1_vkey_hash, None);
        assert_eq!(config.max_timestamp_drift_secs, DEFAULT_MAX_TIMESTAMP_DRIFT_SECS);
        assert!(config.accepted_tcb_statuses.is_empty());
        assert!(config.allowed_verifiers.is_none());
        assert!(config.expected_report_data.is_none());
    }

    #[test]
    fn test_instantiate_with_sp1_vkey_hash() {
        let mut deps = mock_dependencies();
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };

        let msg = InstantiateMsg {
            sp1_vkey_hash: Some("12345678".to_string()),
            ..default_instantiate_msg()
        };

        instantiate(deps.as_mut(), cosmwasm_std::testing::mock_env(), info, msg).unwrap();

        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.sp1_vkey_hash, Some("12345678".to_string()));
    }

    #[test]
    fn test_instantiate_with_tcb_policy() {
        let mut deps = mock_dependencies();
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };

        let msg = InstantiateMsg {
            accepted_tcb_statuses: Some(vec!["UpToDate".to_string()]),
            ..default_instantiate_msg()
        };

        instantiate(deps.as_mut(), cosmwasm_std::testing::mock_env(), info, msg).unwrap();

        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.accepted_tcb_statuses, vec!["UpToDate".to_string()]);
    }

    #[test]
    fn test_instantiate_with_allowed_verifiers() {
        let mut deps = mock_dependencies();
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };

        let v1 = deps.api.addr_make("verifier1");
        let v2 = deps.api.addr_make("verifier2");

        let msg = InstantiateMsg {
            allowed_verifiers: Some(vec![v1.to_string(), v2.to_string()]),
            ..default_instantiate_msg()
        };

        instantiate(deps.as_mut(), cosmwasm_std::testing::mock_env(), info, msg).unwrap();

        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.allowed_verifiers, Some(vec![v1, v2]));
    }

    #[test]
    fn test_sp1_journal_hash_masking() {
        let journal_data = b"test journal data";
        let hash = Sha256::digest(journal_data);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash);
        hash_bytes[0] &= 0x1F; // mask top 3 bits
        let decimal = Uint256::from_be_bytes(hash_bytes).to_string();

        assert!(!decimal.is_empty());
        // Top 3 bits masked means value < 2^253
        assert!(decimal.len() <= 77);
    }

    #[test]
    fn test_update_config_clear_sp1_vkey_hash() {
        let mut deps = mock_dependencies();
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };

        let msg = InstantiateMsg {
            sp1_vkey_hash: Some("12345678".to_string()),
            ..default_instantiate_msg()
        };
        instantiate(deps.as_mut(), cosmwasm_std::testing::mock_env(), info.clone(), msg).unwrap();

        // Clear sp1_vkey_hash by passing empty string
        let res = execute(
            deps.as_mut(),
            cosmwasm_std::testing::mock_env(),
            info,
            ExecuteMsg::UpdateConfig {
                admin: None,
                vkey_name: None,
                sp1_vkey_hash: Some("".to_string()),
                max_timestamp_drift_secs: None,
                accepted_tcb_statuses: None,
                allowed_verifiers: None,
                expected_report_data: None,
            },
        )
        .unwrap();
        assert_eq!(res.attributes[0].value, "update_config");

        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.sp1_vkey_hash, None);
    }

    #[test]
    fn test_update_config_unauthorized() {
        let mut deps = mock_dependencies();
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };
        instantiate(
            deps.as_mut(),
            cosmwasm_std::testing::mock_env(),
            info,
            default_instantiate_msg(),
        )
        .unwrap();

        let bad_info = MessageInfo {
            sender: Addr::unchecked("attacker"),
            funds: vec![],
        };
        let err = execute(
            deps.as_mut(),
            cosmwasm_std::testing::mock_env(),
            bad_info,
            ExecuteMsg::UpdateConfig {
                admin: Some("attacker".to_string()),
                vkey_name: None,
                sp1_vkey_hash: None,
                max_timestamp_drift_secs: None,
                accepted_tcb_statuses: None,
                allowed_verifiers: None,
                expected_report_data: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized));
    }

    #[test]
    fn test_set_expected_measurements_with_rtmr3() {
        let mut deps = mock_dependencies();
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };
        instantiate(
            deps.as_mut(),
            cosmwasm_std::testing::mock_env(),
            info.clone(),
            default_instantiate_msg(),
        )
        .unwrap();

        execute(
            deps.as_mut(),
            cosmwasm_std::testing::mock_env(),
            info,
            ExecuteMsg::SetExpectedMeasurements(ExpectedMeasurementsMsg {
                mr_td: "aaaa".to_string(),
                rtmr1: "bbbb".to_string(),
                rtmr2: "cccc".to_string(),
                rtmr0: None,
                check_rtmr0: false,
                rtmr3: Some("dddd".to_string()),
            }),
        )
        .unwrap();

        let m = EXPECTED_MEASUREMENTS.load(&deps.storage).unwrap();
        assert_eq!(m.rtmr3, Some("dddd".to_string()));
    }
}
