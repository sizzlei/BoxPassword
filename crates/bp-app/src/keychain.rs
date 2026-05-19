//! macOS Keychain / Windows Credential Manager / Linux Secret Service 에
//! Vault Key 를 보관하기 위한 얇은 래퍼.
//!
//! 첫 저장 시 OS가 권한 다이얼로그를 띄울 수 있습니다(특히 macOS).
//! 키는 base64 로 인코딩해 저장됩니다.

use data_encoding::BASE64;

const SERVICE: &str = "com.boxpassword.app";
const ACCOUNT: &str = "vault-key";

fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| format!("keychain entry: {e}"))
}

pub fn save(key: &[u8]) -> Result<(), String> {
    let b64 = BASE64.encode(key);
    entry()?
        .set_password(&b64)
        .map_err(|e| format!("keychain save: {e}"))
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

pub fn has_entry() -> bool {
    match entry() {
        Ok(e) => e.get_password().is_ok(),
        Err(_) => false,
    }
}
