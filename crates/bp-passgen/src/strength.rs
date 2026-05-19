//! zxcvbn 기반 강도 평가 래퍼.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct StrengthSummary {
    /// 0(가장 약함) ~ 4(가장 강함).
    pub score: u8,
    /// 화면에 그대로 표시 가능한 라벨(한글).
    pub label: &'static str,
    /// 추정 추측 횟수의 log10. 시각화/정렬용.
    pub guesses_log10: f64,
    /// 사용자에게 보여줄 경고 한 줄(있을 때만).
    pub feedback: Option<String>,
}

pub fn estimate_strength(password: &str) -> StrengthSummary {
    let est = zxcvbn::zxcvbn(password, &[]);
    let score: u8 = est.score().into();
    let label = match score {
        0 => "매우 약함",
        1 => "약함",
        2 => "보통",
        3 => "강함",
        _ => "매우 강함",
    };
    let feedback = est
        .feedback()
        .and_then(|f| f.warning().map(|w| w.to_string()));
    StrengthSummary {
        score,
        label,
        guesses_log10: est.guesses_log10(),
        feedback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_passwords_score_low() {
        assert!(estimate_strength("123456").score <= 1);
        assert!(estimate_strength("password").score <= 1);
    }

    #[test]
    fn strong_passwords_score_high() {
        let s = estimate_strength("Tr0ub4dor-correct-horse-battery!");
        assert!(s.score >= 3, "expected ≥3, got {}", s.score);
    }
}
