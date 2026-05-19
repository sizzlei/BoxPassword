//! 앱 상태 — 열려 있는 Vault 핸들 1개와 부수 정보.

use std::path::{Path, PathBuf};

use bp_storage::{StorageResult, Vault};

pub struct AppState {
    pub vault: Vault,
}

impl AppState {
    pub fn open<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        Ok(Self { vault: Vault::open(path)? })
    }
}

/// 기본 Vault 파일 경로.
///
/// 환경 변수 `BOX_PASSWORD_VAULT_PATH`가 있으면 그 값을 사용합니다(개발용 오버라이드).
/// 그렇지 않으면 OS별 표준 데이터 디렉터리 아래 `BoxPassword/vault.db`.
pub fn default_vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("BOX_PASSWORD_VAULT_PATH") {
        return PathBuf::from(p);
    }
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("BoxPassword").join("vault.db")
}
