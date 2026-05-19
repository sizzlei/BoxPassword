//! RFC 6238 TOTP — 알고리즘/주기/자릿수 가변.
//!
//! 지원: SHA-1 / SHA-256 / SHA-512, 주기 1~3600초, 자릿수 6~10.
//! 입력은 `otpauth://totp/...?secret=BASE32&algorithm=SHA1&period=30&digits=6&...`
//! URL 또는 raw base32 시크릿(파라미터 누락 시 기본값 SHA1/30/6).
//!
//! 후방 호환을 위해 `parse_seed`, `current_code(&[u8])` 등 기존 API는
//! 기본 설정으로 동작하는 얇은 래퍼로 유지합니다.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

pub const DEFAULT_PERIOD: u64 = 30;
pub const DEFAULT_DIGITS: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Algorithm {
    #[default]
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Some(Algorithm::Sha1),
            "SHA256" | "SHA-256" => Some(Algorithm::Sha256),
            "SHA512" | "SHA-512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TotpConfig {
    pub algorithm: Algorithm,
    pub period: u64,
    pub digits: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self { algorithm: Algorithm::default(), period: DEFAULT_PERIOD, digits: DEFAULT_DIGITS }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedTotp {
    pub seed: Vec<u8>,
    pub config: TotpConfig,
}

fn hotp_with(secret: &[u8], counter: u64, algorithm: Algorithm, digits: u32) -> u32 {
    let bytes: Vec<u8> = match algorithm {
        Algorithm::Sha1 => {
            let mut m = <Hmac<Sha1>>::new_from_slice(secret).expect("any key length");
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut m = <Hmac<Sha256>>::new_from_slice(secret).expect("any key length");
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut m = <Hmac<Sha512>>::new_from_slice(secret).expect("any key length");
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
    };
    let last = *bytes.last().expect("hmac output non-empty");
    let offset = (last & 0x0f) as usize;
    let code = u32::from_be_bytes([
        bytes[offset] & 0x7f,
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    code % 10u32.pow(digits)
}

pub fn code_at(secret: &[u8], unix_secs: u64, config: &TotpConfig) -> (String, u64, u64) {
    let period = config.period.max(1);
    let step = unix_secs / period;
    let remaining = period - (unix_secs % period);
    let code = hotp_with(secret, step, config.algorithm, config.digits);
    (format!("{:0width$}", code, width = config.digits as usize), remaining, period)
}

pub fn current_with(secret: &[u8], config: &TotpConfig) -> (String, u64, u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    code_at(secret, now, config)
}

/// 기본 SHA1/30/6 로 동작하는 후방 호환 래퍼.
pub fn current_code(secret: &[u8]) -> (String, u64, u64) {
    current_with(secret, &TotpConfig::default())
}

/// otpauth URL 또는 raw base32 시크릿을 파싱.
pub fn parse(input: &str) -> Result<ParsedTotp, String> {
    let mut config = TotpConfig::default();
    let secret_b32: String = if input.starts_with("otpauth://") {
        let (_, query) = input
            .split_once('?')
            .ok_or_else(|| "otpauth URL에 쿼리가 없습니다".to_string())?;
        let mut secret: Option<String> = None;
        for kv in query.split('&') {
            let Some((k, v)) = kv.split_once('=') else { continue };
            // URL decode minimal — 우리 케이스에는 거의 +/% 없음
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(v.to_string()),
                "algorithm" => {
                    if let Some(a) = Algorithm::parse(v) { config.algorithm = a; }
                }
                "period" => {
                    if let Ok(p) = v.parse::<u64>() { if p > 0 && p <= 3600 { config.period = p; } }
                }
                "digits" => {
                    if let Ok(d) = v.parse::<u32>() { if (6..=10).contains(&d) { config.digits = d; } }
                }
                _ => {}
            }
        }
        secret.ok_or_else(|| "otpauth URL에 secret 파라미터가 없습니다".to_string())?
    } else {
        input.to_string()
    };

    let normalized: String = secret_b32
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.is_empty() {
        return Err("빈 시드".into());
    }
    let seed = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|e| format!("base32 디코드 실패: {e}"))?;
    Ok(ParsedTotp { seed, config })
}

/// 후방 호환 래퍼: 시드 바이트만 필요할 때.
pub fn parse_seed(input: &str) -> Result<Vec<u8>, String> {
    parse(input).map(|p| p.seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vector_sha1_first() {
        let secret = b"12345678901234567890";
        let (code, _r, _p) = code_at(secret, 59, &TotpConfig { algorithm: Algorithm::Sha1, period: 30, digits: 6 });
        assert_eq!(code, "287082");
    }

    #[test]
    fn rfc6238_vector_sha256_t1() {
        // RFC 6238 부록 B SHA-256 키는 32바이트 ASCII "12345678901234567890123456789012"
        let secret = b"12345678901234567890123456789012";
        let (code, _, _) = code_at(secret, 59,
            &TotpConfig { algorithm: Algorithm::Sha256, period: 30, digits: 8 });
        // RFC 표기 46119246 — 8자리 일치.
        assert_eq!(code, "46119246");
    }

    #[test]
    fn rfc6238_vector_sha512_t1() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let (code, _, _) = code_at(secret, 59,
            &TotpConfig { algorithm: Algorithm::Sha512, period: 30, digits: 8 });
        // RFC 표기 90693936
        assert_eq!(code, "90693936");
    }

    #[test]
    fn parse_otpauth_with_full_params() {
        let url = "otpauth://totp/Ex?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&period=60&digits=8";
        let p = parse(url).unwrap();
        assert_eq!(p.config.algorithm, Algorithm::Sha256);
        assert_eq!(p.config.period, 60);
        assert_eq!(p.config.digits, 8);
    }

    #[test]
    fn parse_raw_base32_defaults() {
        let p = parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(p.config.algorithm, Algorithm::Sha1);
        assert_eq!(p.config.period, 30);
        assert_eq!(p.config.digits, 6);
    }

    #[test]
    fn invalid_params_fall_back_to_default() {
        let url = "otpauth://totp/Ex?secret=JBSWY3DPEHPK3PXP&algorithm=BOGUS&period=99999&digits=3";
        let p = parse(url).unwrap();
        // 알고리즘은 무시되고 기본 SHA1, period/digits도 범위 밖이면 기본 유지
        assert_eq!(p.config.algorithm, Algorithm::Sha1);
        assert_eq!(p.config.period, 30);
        assert_eq!(p.config.digits, 6);
    }
}
