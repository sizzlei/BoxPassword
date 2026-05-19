//! 도메인 에러 타입.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found")]
    NotFound,
}

pub type CoreResult<T> = Result<T, CoreError>;
