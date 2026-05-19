//! Diceware 스타일 패스프레이즈 생성.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;

use crate::wordlist::WORDS;
use crate::{GenError, GenResult};

pub fn generate_passphrase(words: u8, separator: &str, capitalize: bool) -> GenResult<String> {
    if !(2..=16).contains(&words) {
        return Err(GenError::Policy("word count must be in 2..=16".into()));
    }
    let mut rng = OsRng;
    let parts: Vec<String> = (0..words)
        .map(|_| {
            let w = WORDS.choose(&mut rng).copied().unwrap_or("");
            if capitalize {
                let mut chars = w.chars();
                match chars.next() {
                    Some(c) => c.to_uppercase().chain(chars).collect::<String>(),
                    None => String::new(),
                }
            } else {
                w.to_string()
            }
        })
        .collect();
    Ok(parts.join(separator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_correct_word_count() {
        for n in [2u8, 4, 6, 8] {
            let s = generate_passphrase(n, "-", false).unwrap();
            assert_eq!(s.split('-').count(), n as usize);
        }
    }

    #[test]
    fn capitalize_capitalizes_first_letter() {
        let s = generate_passphrase(3, "-", true).unwrap();
        for part in s.split('-') {
            assert!(part.chars().next().unwrap().is_ascii_uppercase());
        }
    }

    #[test]
    fn rejects_extremes() {
        assert!(generate_passphrase(1, "-", false).is_err());
        assert!(generate_passphrase(17, "-", false).is_err());
    }
}
