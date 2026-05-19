//! AES-256-GCM 봉인 / 해제.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::{random_bytes, CryptoError, CryptoResult};

/// 봉인 포맷 버전.
pub const SEAL_VERSION: u8 = 1;
/// AES-256-GCM 식별자.
pub const ALG_AES_256_GCM: u8 = 1;
/// GCM nonce 길이.
pub const NONCE_LEN: usize = 12;
/// GCM 인증 태그 길이.
pub const TAG_LEN: usize = 16;
/// 봉인 헤더 길이([ver:u8 | alg:u8 | nonce:12]).
pub const SEAL_HEADER_LEN: usize = 2 + NONCE_LEN;

/// 평문을 봉인합니다.
///
/// AAD는 봉인 슬롯을 식별하는 안정적인 바이트열이어야 합니다(예: `"vault_key"`,
/// `entry_id.as_bytes()`, `"secret"` 등). 잘못된 AAD로는 해제할 수 없습니다.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Aead)?;

    let mut out = Vec::with_capacity(SEAL_HEADER_LEN + ct.len());
    out.push(SEAL_VERSION);
    out.push(ALG_AES_256_GCM);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 봉인을 해제합니다. 잘못된 키/AAD/변조는 모두 [`CryptoError::Aead`]로 동일하게 보고됩니다.
pub fn open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    if sealed.len() < SEAL_HEADER_LEN + TAG_LEN {
        return Err(CryptoError::Format);
    }
    if sealed[0] != SEAL_VERSION {
        return Err(CryptoError::Format);
    }
    if sealed[1] != ALG_AES_256_GCM {
        return Err(CryptoError::Format);
    }
    let nonce = Nonce::from_slice(&sealed[2..2 + NONCE_LEN]);
    let body = &sealed[SEAL_HEADER_LEN..];

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    cipher
        .decrypt(nonce, Payload { msg: body, aad })
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let pt = b"the launch codes are 0000".to_vec();
        let sealed = seal(&key, &pt, b"entry-1/secret").unwrap();
        let back = open(&key, &sealed, b"entry-1/secret").unwrap();
        assert_eq!(pt, back);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [7u8; 32];
        let bad = [8u8; 32];
        let sealed = seal(&key, b"hi", b"aad").unwrap();
        assert!(matches!(open(&bad, &sealed, b"aad"), Err(CryptoError::Aead)));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"hi", b"correct").unwrap();
        assert!(matches!(open(&key, &sealed, b"wrong"), Err(CryptoError::Aead)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [7u8; 32];
        let mut sealed = seal(&key, b"hi", b"aad").unwrap();
        let n = sealed.len();
        sealed[n - 1] ^= 0x01;
        assert!(matches!(open(&key, &sealed, b"aad"), Err(CryptoError::Aead)));
    }

    #[test]
    fn nonces_differ_per_seal() {
        let key = [7u8; 32];
        let a = seal(&key, b"same", b"aad").unwrap();
        let b = seal(&key, b"same", b"aad").unwrap();
        assert_ne!(a, b, "재봉인 시 nonce가 같으면 평문이 같아도 다른 결과가 나와야 합니다");
    }

    #[test]
    fn short_bytes_rejected() {
        let key = [7u8; 32];
        assert!(matches!(open(&key, &[], b""), Err(CryptoError::Format)));
        assert!(matches!(open(&key, &[1, 1, 0, 0], b""), Err(CryptoError::Format)));
    }
}
