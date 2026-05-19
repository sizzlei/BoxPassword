//! Argon2id 기반 KDF와 AES-256-GCM AEAD 래퍼.
//!
//! 봉인 포맷은 일부러 단순하게 잡았습니다:
//!
//! ```text
//! [ version:u8 | alg_id:u8 | nonce:12 | ciphertext... | tag:16 ]
//! ```
//!
//! 여기서 nonce는 봉인할 때마다 새로 뽑은 CSPRNG 12바이트입니다.
//! AAD에는 항목 id 같은 식별자를 넣어, 다른 슬롯의 봉인을 잘못된 위치에
//! 끼워 넣는 공격(snip-and-paste)을 차단합니다.
#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod totp;

pub use aead::{open, seal, ALG_AES_256_GCM, NONCE_LEN, SEAL_HEADER_LEN, SEAL_VERSION, TAG_LEN};
pub use error::{CryptoError, CryptoResult};
pub use kdf::{derive_master_key, KdfParams, MASTER_KEY_LEN, SALT_LEN};
pub use keys::{MasterKey, VaultKey, KEY_LEN};

/// CSPRNG에서 보안 난수를 채워 넣습니다.
pub fn random_bytes(buf: &mut [u8]) -> CryptoResult<()> {
    getrandom::getrandom(buf).map_err(|e| CryptoError::Rng(e.to_string()))
}
