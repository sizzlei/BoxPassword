//! BoxOTP 등 외부 OTP 제공자를 끼워 넣기 위한 추상화.
//!
//! v0.1에서는 실제 통신을 구현하지 않습니다.
//! 트레잇 경계만 정의해 두고, 추후 BoxOTP 스펙이 확정되면 별도 구현체를
//! `bp_otp::providers::box_otp` 모듈로 추가할 예정입니다.
#![forbid(unsafe_code)]

use bp_core::EntryId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("provider unavailable")]
    Unavailable,
    #[error("not linked")]
    NotLinked,
    #[error("transport: {0}")]
    Transport(String),
}

pub type OtpResult<T> = Result<T, OtpError>;

/// 외부 OTP 제공자(BoxOTP 등)에서의 계정 참조.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpAccountRef {
    pub provider: String,
    pub account_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpCode {
    pub digits: String,
    pub remaining_seconds: u32,
}

/// BoxPassword가 의존하는 OTP 제공자 인터페이스.
///
/// 실제 구현은 v0.1 이후 작성됩니다. 그동안 [`DummyOtpProvider`]를 사용해
/// 회귀 테스트를 유지합니다.
pub trait OtpProvider: Send + Sync {
    fn provider_id(&self) -> &'static str;
    fn list_accounts(&self) -> OtpResult<Vec<OtpAccountRef>>;
    fn current_code(&self, account: &OtpAccountRef) -> OtpResult<OtpCode>;
    fn link(&self, entry_id: EntryId, account: OtpAccountRef) -> OtpResult<()>;
}

/// 항상 `Unavailable`을 반환하는 더미 구현. UI 자리잡기 + 테스트용.
pub struct DummyOtpProvider;

impl OtpProvider for DummyOtpProvider {
    fn provider_id(&self) -> &'static str {
        "dummy"
    }
    fn list_accounts(&self) -> OtpResult<Vec<OtpAccountRef>> {
        Err(OtpError::Unavailable)
    }
    fn current_code(&self, _account: &OtpAccountRef) -> OtpResult<OtpCode> {
        Err(OtpError::Unavailable)
    }
    fn link(&self, _entry_id: EntryId, _account: OtpAccountRef) -> OtpResult<()> {
        Err(OtpError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_provider_is_unavailable() {
        let p = DummyOtpProvider;
        assert_eq!(p.provider_id(), "dummy");
        assert!(matches!(p.list_accounts(), Err(OtpError::Unavailable)));
    }
}
