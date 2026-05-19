//! 패스워드 / 패스프레이즈 생성기 + 강도 평가.
//!
//! 모든 무작위성은 [`rand::rngs::OsRng`](OS CSPRNG)에서 가져옵니다.
//! 정책은 [`bp_core::PasswordPolicy`]에 정의되어 있고, 여기서는 그에 맞춰 후보를 만듭니다.
#![forbid(unsafe_code)]

mod passphrase;
mod random;
mod strength;
mod wordlist;

pub use passphrase::generate_passphrase;
pub use random::generate_random;
pub use strength::{estimate_strength, StrengthSummary};

use bp_core::{GeneratorMode, PasswordPolicy};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GenError {
    #[error("invalid policy: {0}")]
    Policy(String),
}

pub type GenResult<T> = Result<T, GenError>;

/// 주어진 정책에 따라 `count`개의 패스워드 후보를 생성합니다.
pub fn generate(policy: &PasswordPolicy, count: usize) -> GenResult<Vec<String>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let s = match &policy.mode {
            GeneratorMode::Random => generate_random(policy)?,
            GeneratorMode::Passphrase { words, separator, capitalize } => {
                generate_passphrase(*words, separator, *capitalize)?
            }
        };
        out.push(s);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_policy() -> PasswordPolicy {
        PasswordPolicy::default()
    }

    #[test]
    fn generates_requested_count() {
        let p = random_policy();
        let out = generate(&p, 5).unwrap();
        assert_eq!(out.len(), 5);
        for s in &out {
            assert_eq!(s.len(), p.length as usize);
        }
    }

    #[test]
    fn candidates_are_distinct() {
        // 같은 정책으로 여러 번 돌렸을 때 후보가 같지 않아야 합니다(확률적).
        let p = random_policy();
        let out = generate(&p, 5).unwrap();
        let uniq: std::collections::HashSet<_> = out.iter().collect();
        assert!(uniq.len() >= 4, "duplicates surfaced too often: {:?}", out);
    }
}
