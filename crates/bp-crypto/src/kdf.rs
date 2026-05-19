//! Argon2id 기반 마스터 키 도출.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use crate::{CryptoError, CryptoResult};

/// 권장 솔트 길이.
pub const SALT_LEN: usize = 16;
/// 마스터 키 길이(32바이트).
pub const MASTER_KEY_LEN: usize = 32;

/// Argon2id 파라미터.
///
/// 기본값은 OWASP 권고에 가깝게 (m=64MiB, t=3, p=1).
/// 디바이스 성능에 따라 [`KdfParams::auto_tune`]로 조정할 수 있습니다(v0.2 예정).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// m_cost (KiB 단위). 기본 65536 == 64 MiB.
    pub memory_kib: u32,
    /// t_cost (반복 횟수).
    pub iterations: u32,
    /// p_cost (병렬도).
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 }
    }
}

impl KdfParams {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
    pub fn from_json(s: &str) -> CryptoResult<Self> {
        serde_json::from_str(s).map_err(|e| CryptoError::Kdf(e.to_string()))
    }
}

/// 마스터 비밀번호와 salt로부터 32바이트 마스터 키를 도출합니다.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> CryptoResult<[u8; MASTER_KEY_LEN]> {
    if salt.len() < 8 {
        return Err(CryptoError::Kdf("salt too short".into()));
    }
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(MASTER_KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; MASTER_KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        // 테스트 속도를 위해 의도적으로 약한 파라미터.
        KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn deterministic_with_same_inputs() {
        let salt = b"0123456789abcdef";
        let p = fast_params();
        let k1 = derive_master_key(b"hunter2", salt, &p).unwrap();
        let k2 = derive_master_key(b"hunter2", salt, &p).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_password_yields_different_key() {
        let salt = b"0123456789abcdef";
        let p = fast_params();
        let k1 = derive_master_key(b"hunter2", salt, &p).unwrap();
        let k2 = derive_master_key(b"correct horse battery staple", salt, &p).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_salt_yields_different_key() {
        let p = fast_params();
        let k1 = derive_master_key(b"hunter2", b"0123456789abcdef", &p).unwrap();
        let k2 = derive_master_key(b"hunter2", b"fedcba9876543210", &p).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn rejects_too_short_salt() {
        let p = fast_params();
        assert!(derive_master_key(b"hunter2", b"short", &p).is_err());
    }
}
