use thiserror::Error;

#[derive(Debug, Error)]
pub enum R2Error {
    #[error("S3 error: {0}")]
    S3(String),
    #[error("presign error: {0}")]
    Presign(String),
}
