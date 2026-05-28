use powehi_domain::error::DomainError;
use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum GrpcError {
    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc status: {0}")]
    Status(#[from] Status),
    #[error("circuit open for region: {0}")]
    CircuitOpen(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

impl From<GrpcError> for DomainError {
    fn from(e: GrpcError) -> Self {
        match e {
            GrpcError::CircuitOpen(region) => {
                DomainError::Internal(format!("circuit breaker open for region {region}"))
            }
            GrpcError::InvalidRequest(msg) => DomainError::InvalidInput(msg),
            _ => DomainError::Internal(e.to_string()),
        }
    }
}

/// Convert a domain error to a gRPC Status.
///
/// Security: internal error details are NOT forwarded to callers — only stable
/// error codes + generic messages. Epoch numbers and SQL/infra details are
/// logged server-side and returned as opaque "internal error" to peers.
pub fn domain_err_to_status(e: &DomainError) -> Status {
    match e {
        DomainError::NotFound(_) => Status::not_found("not found"),
        DomainError::AlreadyExists(_) => Status::already_exists("already exists"),
        DomainError::Unauthorized => Status::unauthenticated("unauthorized"),
        DomainError::InvalidInput(msg) => Status::invalid_argument(msg),
        // Epoch/region mismatch details must not leak to peer — attacker can use
        // them to probe server state. Return a generic precondition failure.
        DomainError::EpochMismatch { .. } => Status::failed_precondition("epoch mismatch"),
        DomainError::RegionMismatch { .. } => Status::failed_precondition("region mismatch"),
        // Internal errors are logged server-side; never forwarded verbatim.
        DomainError::Internal(_) => Status::internal("internal error"),
    }
}
