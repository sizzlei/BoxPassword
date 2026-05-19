//! macOS Keychain / Windows Credential Manager / Linux Secret Service 에
//! Vault Key 를 보관하기 위한 얇은 래퍼.
//!
//! 첫 저장 시 OS가 권한 다이얼로그를 띄울 수 있습니다(특히 macOS).
//! 키는 base64 로 인코딩해 저장됩니다.

use data_encoding::BASE64;
use keyring::error::Error as KeyringError;

const SERVICE: &str = "com.boxpassword.app";
const ACCOUNT: &str = "vault-key";

fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| format!("keychain entry: {e}"))
}

pub fn save(key: &[u8]) -> Result<(), String> {
    let b64 = BASE64.encode(key);
    entry()?
        .set_password(&b64)
        .map_err(|e| format!("keychain save: {e}"))?;
    // 저장 직후 자체 검증 — 다음에 못 읽으면 의미가 없으므로 set 직후 get 으로 확인.
    let verify = entry()?.get_password();
    match verify {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "저장은 성공한 것으로 보이나 직후 재조회 실패 ({e}). 자격 증명 저장소 접근이 차단되었거나 OS 권한 다이얼로그에서 '거부'를 누르셨을 수 있습니다."
        )),
    }
}

pub fn load() -> Result<Vec<u8>, String> {
    let e = entry()?;
    let b64 = e.get_password().map_err(|e| format!("keychain load: {e}"))?;
    BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("keychain base64 decode: {e}"))
}

pub fn clear() -> Result<(), String> {
    // delete_credential 은 항목이 없으면 에러를 낼 수 있으므로 무시.
    let _ = entry().and_then(|e| {
        e.delete_credential().map_err(|err| format!("{err}"))
    });
    Ok(())
}

/// 항목 존재 여부 + (없을 때) 사유. UI 진단용.
pub fn has_entry_detailed() -> (bool, Option<String>) {
    let e = match entry() {
        Ok(e) => e,
        Err(err) => return (false, Some(format!("Entry::new 실패: {err}"))),
    };
    match e.get_password() {
        Ok(_) => (true, None),
        Err(KeyringError::NoEntry) => (false, Some("NoEntry (저장되지 않았거나 OS가 접근을 차단)".into())),
        Err(err) => (false, Some(format!("get_password 실패: {err}"))),
    }
}

pub fn has_entry() -> bool {
    has_entry_detailed().0
}
