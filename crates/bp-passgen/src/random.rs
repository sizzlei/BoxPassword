//! 정책 기반 무작위 패스워드 생성.

use bp_core::PasswordPolicy;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::{GenError, GenResult};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &[u8] = b"0123456789";
const SYMBOL: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

/// 가독성 모드에서 제외할 시각적으로 혼동되는 문자.
const CONFUSABLE: &[u8] = b"0OoIl1|`'\"";

pub fn generate_random(p: &PasswordPolicy) -> GenResult<String> {
    if p.length < 4 {
        return Err(GenError::Policy("length must be ≥ 4".into()));
    }
    if p.length > 256 {
        return Err(GenError::Policy("length must be ≤ 256".into()));
    }

    let mut classes: Vec<Vec<u8>> = Vec::new();
    if p.lower {
        classes.push(filter_pool(LOWER, p));
    }
    if p.upper {
        classes.push(filter_pool(UPPER, p));
    }
    if p.digit {
        classes.push(filter_pool(DIGIT, p));
    }
    if p.symbol {
        let custom = p.symbol_set.as_deref().unwrap_or("");
        let base: &[u8] = if custom.is_empty() { SYMBOL } else { custom.as_bytes() };
        classes.push(filter_pool(base, p));
    }

    if classes.is_empty() {
        return Err(GenError::Policy("no character classes enabled".into()));
    }
    if classes.iter().any(|c| c.is_empty()) {
        return Err(GenError::Policy("a class became empty after exclusions".into()));
    }

    let mut rng = OsRng;
    let len = p.length as usize;

    let mut chars: Vec<u8> = Vec::with_capacity(len);

    if p.require_each_class {
        if classes.len() > len {
            return Err(GenError::Policy("length too short for required classes".into()));
        }
        for c in &classes {
            chars.push(*c.choose(&mut rng).unwrap());
        }
    }

    // 모든 클래스를 합친 풀.
    let mut union: Vec<u8> = Vec::new();
    for c in &classes {
        union.extend(c.iter().copied());
    }

    while chars.len() < len {
        let candidate = *union.choose(&mut rng).unwrap();
        if violates_repeat(&chars, candidate, p.max_repeat) {
            continue;
        }
        chars.push(candidate);
    }

    chars.shuffle(&mut rng);
    if p.max_repeat > 0 {
        smooth_runs(&mut chars, p.max_repeat, &mut rng);
    }

    Ok(String::from_utf8(chars).expect("ASCII only"))
}

fn filter_pool(base: &[u8], p: &PasswordPolicy) -> Vec<u8> {
    let excl = p.exclude_chars.as_bytes();
    base.iter()
        .copied()
        .filter(|b| !excl.contains(b))
        .filter(|b| !(p.readable && CONFUSABLE.contains(b)))
        .collect()
}

fn violates_repeat(s: &[u8], c: u8, max_repeat: u8) -> bool {
    if max_repeat == 0 {
        return false;
    }
    let max = max_repeat as usize;
    if s.len() < max {
        return false;
    }
    s[s.len() - max..].iter().all(|x| *x == c)
}

fn has_run(s: &[u8], max_repeat: u8) -> bool {
    if max_repeat == 0 {
        return false;
    }
    let mut run = 1usize;
    for w in s.windows(2) {
        if w[0] == w[1] {
            run += 1;
        } else {
            run = 1;
        }
        if run > max_repeat as usize {
            return true;
        }
    }
    false
}

fn smooth_runs(s: &mut [u8], max_repeat: u8, rng: &mut impl Rng) {
    // 단순 휴리스틱: run 발견 위치를 무작위 인덱스와 스왑.
    // O(n) 시도로 수렴하며, 안 풀리면 그대로 둡니다(정책상 매우 짧은 시퀀스에서만 발생 가능).
    for _ in 0..s.len() * 2 {
        if !has_run(s, max_repeat) {
            return;
        }
        let mut bad = None;
        let mut run = 1usize;
        for i in 1..s.len() {
            if s[i] == s[i - 1] {
                run += 1;
            } else {
                run = 1;
            }
            if run > max_repeat as usize {
                bad = Some(i);
                break;
            }
        }
        if let Some(i) = bad {
            let j = rng.gen_range(0..s.len());
            s.swap(i, j);
        } else {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_core::GeneratorMode;

    fn p(length: u16) -> PasswordPolicy {
        PasswordPolicy {
            name: "t".into(),
            length,
            lower: true,
            upper: true,
            digit: true,
            symbol: true,
            symbol_set: None,
            exclude_chars: String::new(),
            require_each_class: true,
            readable: true,
            max_repeat: 2,
            dictionary_block: true,
            mode: GeneratorMode::Random,
        }
    }

    #[test]
    fn produces_correct_length() {
        let pw = generate_random(&p(24)).unwrap();
        assert_eq!(pw.len(), 24);
    }

    #[test]
    fn rejects_too_short() {
        let mut pol = p(2);
        pol.length = 2;
        assert!(generate_random(&pol).is_err());
    }

    #[test]
    fn require_each_class_is_respected() {
        let pol = p(20);
        for _ in 0..20 {
            let pw = generate_random(&pol).unwrap();
            let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
            let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
            let has_digit = pw.chars().any(|c| c.is_ascii_digit());
            let has_symbol = pw.chars().any(|c| !c.is_ascii_alphanumeric());
            assert!(has_lower && has_upper && has_digit && has_symbol, "missing class in {pw}");
        }
    }

    #[test]
    fn readable_mode_excludes_confusables() {
        let pol = p(40);
        for _ in 0..20 {
            let pw = generate_random(&pol).unwrap();
            for c in CONFUSABLE.iter() {
                assert!(!pw.as_bytes().contains(c), "confusable {} in {pw}", *c as char);
            }
        }
    }

    #[test]
    fn exclude_chars_are_respected() {
        let mut pol = p(40);
        pol.exclude_chars = "abc".into();
        for _ in 0..10 {
            let pw = generate_random(&pol).unwrap();
            assert!(!pw.contains('a') && !pw.contains('b') && !pw.contains('c'));
        }
    }

    #[test]
    fn no_classes_is_error() {
        let mut pol = p(20);
        pol.lower = false;
        pol.upper = false;
        pol.digit = false;
        pol.symbol = false;
        assert!(generate_random(&pol).is_err());
    }
}
