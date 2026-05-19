//! 임베디드 단어 사전 (256 단어).
//!
//! 출처: 짧고 평이한 영어 단어를 직접 큐레이션. EFF Diceware 7776 단어 사전 도입은
//! 후속 마일스톤(M4.1)에서 다룹니다. 8 비트/단어 기준으로
//! 8단어 패스프레이즈 ≈ 64 비트, 10단어 ≈ 80 비트의 엔트로피를 가집니다.

pub const WORDS: &[&str] = &[
    "able", "acid", "acorn", "actor", "adapt", "admit", "adopt", "agent",
    "agree", "aim", "airy", "alarm", "album", "alert", "alike", "alive",
    "allow", "alloy", "alone", "along", "alpha", "also", "amber", "amend",
    "amid", "ample", "angle", "ankle", "antic", "apple", "apron", "arch",
    "arena", "argue", "arise", "arm", "armor", "army", "aroma", "arrow",
    "art", "ask", "aspen", "aster", "atlas", "atom", "aunt", "aura",
    "auto", "awake", "award", "awoke", "axis", "badge", "bagel", "bake",
    "balm", "bank", "barn", "base", "bath", "bay", "beach", "bead",
    "beam", "bean", "bear", "beat", "bed", "bee", "belt", "bench",
    "berry", "best", "big", "bike", "bill", "bind", "bingo", "bird",
    "black", "blade", "blank", "blast", "blaze", "blend", "bless", "blind",
    "blink", "block", "blood", "bloom", "blow", "blue", "blunt", "board",
    "boat", "body", "bold", "bolt", "bone", "book", "boom", "boost",
    "boot", "born", "bow", "box", "brain", "brake", "branch", "brass",
    "brave", "bread", "break", "brick", "brief", "bring", "broad", "brook",
    "brown", "brush", "build", "bulb", "bunch", "bunny", "burn", "bush",
    "busy", "butter", "cabin", "cable", "cake", "calm", "camel", "cap",
    "cape", "carbon", "card", "cargo", "carrot", "carry", "cart", "cash",
    "cast", "castle", "cat", "catch", "cedar", "cell", "chain", "chair",
    "chalk", "champ", "chant", "chaos", "charm", "chart", "chase", "cheap",
    "check", "cheek", "cheer", "chef", "chess", "chest", "chief", "child",
    "chill", "chime", "choir", "choose", "chop", "chunk", "cider", "circle",
    "city", "civic", "claim", "clamp", "clan", "clap", "clash", "class",
    "claw", "clay", "clean", "clear", "clerk", "click", "cliff", "climb",
    "clip", "cloak", "clock", "close", "cloud", "clown", "club", "clue",
    "clump", "coach", "coal", "coast", "coat", "cobra", "coin", "cold",
    "color", "colt", "comb", "come", "comic", "cook", "cool", "coral",
    "cord", "core", "corn", "cost", "cotton", "cough", "count", "court",
    "cover", "crab", "craft", "crane", "crash", "crate", "crawl", "crazy",
    "cream", "creek", "crest", "crew", "cricket", "crisp", "crop", "cross",
    "crown", "cruise", "crumb", "crunch", "crush", "cube", "cup", "curl",
    "curse", "curve", "cycle", "daily", "dairy", "dance", "dare", "dart",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_expected_size() {
        assert_eq!(WORDS.len(), 256);
    }

    #[test]
    fn wordlist_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for w in WORDS {
            assert!(seen.insert(*w), "duplicate: {w}");
        }
    }

    #[test]
    fn wordlist_words_are_lowercase_ascii() {
        for w in WORDS {
            assert!(!w.is_empty());
            assert!(w.chars().all(|c| c.is_ascii_lowercase()));
        }
    }
}
