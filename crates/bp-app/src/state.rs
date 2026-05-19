//! 앱 상태 — 열려 있는 Vault 핸들 1개와 부수 정보.

use std::path::{Path, PathBuf};

use bp_storage::{StorageResult, Vault};

pub struct AppState {
    pub vault: Vault,
    /// UI 잠금 플래그.
    ///
    /// keychain 자동 잠금 해제가 켜진 상태에서 사용자가 명시적으로 잠그면
    /// vault 자체는 메모리에 unlock 상태로 두되 (트레이 / Quick Search 가
    /// 계속 동작하도록) 이 플래그만 true 로 올려서 UI 가 잠금 화면을
    /// 그리게 합니다. keychain 이 꺼져 있을 때는 lock_vault 가 진짜로
    /// `vault.lock()` 까지 호출하므로 이 플래그와 `vault.is_unlocked()` 가
    /// 동시에 변합니다.
    pub ui_locked: bool,
}

impl AppState {
    pub fn open<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        Ok(Self {
            vault: Vault::open(path)?,
            ui_locked: false,
        })
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
