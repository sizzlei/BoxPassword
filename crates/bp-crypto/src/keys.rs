//! 마스터 키 / 볼트 키 래퍼.
//!
//! `Drop` 시 자동으로 0으로 덮어쓰기 위해 [`zeroize::ZeroizeOnDrop`]을 사용합니다.
//! `Debug` 구현은 의도적으로 키 바이트를 노출하지 않습니다.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{random_bytes, CryptoResult};

/// 키 길이(32바이트, AES-256-GCM 기준).
pub const KEY_LEN: usize = 32;

/// 마스터 비밀번호에서 도출한 단기 키. 잠금 해제 직후 즉시 폐기됩니다.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; KEY_LEN]);

impl MasterKey {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey").field("bytes", &"<redacted>").finish()
    }
}

/// Vault 본체 봉인을 담당하는 장기 키. 잠금 해제된 동안 메모리에 머무릅니다.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey(pub [u8; KEY_LEN]);

impl VaultKey {
    /// 새 32바이트 키를 CSPRNG로 생성합니다.
    pub fn generate() -> CryptoResult<Self> {
        let mut b = [0u8; KEY_LEN];
        random_bytes(&mut b)?;
        Ok(Self(b))
    }
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKey").field("bytes", &"<redacted>").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_bytes() {
        let k = VaultKey::generate().unwrap();
        let s = format!("{:?}", k);
        assert!(s.contains("<redacted>"));
    }

    #[test]
    fn generated_keys_differ() {
        let a = VaultKey::generate().unwrap();
        let b = VaultKey::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
