use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("unauthorized")]
    Unauthorized,

    #[error("sender not in allowed verifiers list")]
    NotAllowedVerifier,

    #[error("proof verification failed")]
    ProofVerificationFailed,

    #[error("journal binding mismatch: expected={expected}, actual={actual}")]
    JournalBindingMismatch { expected: String, actual: String },

    #[error("invalid journal: {reason}")]
    InvalidJournal { reason: String },

    #[error("quote not verified in journal")]
    QuoteNotVerified,

    #[error("quote already verified")]
    AlreadyVerified,

    #[error("vkey hash mismatch: expected={expected}, actual={actual}")]
    VkeyHashMismatch { expected: String, actual: String },

    #[error("measurement mismatch: {field} expected={expected}, actual={actual}")]
    MeasurementMismatch {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("timestamp drift too large: journal={journal}, block={block}, max_drift={max_drift}")]
    TimestampDriftExceeded {
        journal: u64,
        block: u64,
        max_drift: u64,
    },

    #[error("unacceptable TCB status: {status}")]
    UnacceptableTcbStatus { status: String },

    #[error("report_data mismatch: expected={expected}, actual={actual}")]
    ReportDataMismatch { expected: String, actual: String },

    #[error("protobuf encode error: {0}")]
    ProstEncode(#[from] prost::EncodeError),

    #[error("protobuf decode error: {0}")]
    ProstDecode(#[from] prost::DecodeError),
}

pub type ContractResult<T> = Result<T, ContractError>;
