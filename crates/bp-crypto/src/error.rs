use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("kdf failure: {0}")]
    Kdf(String),
    /// AEAD 복호 실패는 잘못된 키든 변조든 동일하게 다룹니다.
    #[error("aead authentication failed")]
    Aead,
    #[error("malformed sealed bytes")]
    Format,
    #[error("rng failure: {0}")]
    Rng(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
