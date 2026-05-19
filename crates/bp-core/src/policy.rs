//! 패스워드 생성 정책(규칙).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum GeneratorMode {
    Random,
    Passphrase { words: u8, separator: String, capitalize: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub name: String,
    pub length: u16,
    pub lower: bool,
    pub upper: bool,
    pub digit: bool,
    pub symbol: bool,
    pub symbol_set: Option<String>,
    pub exclude_chars: String,
    pub require_each_class: bool,
    pub readable: bool,
    pub max_repeat: u8,
    pub dictionary_block: bool,
    pub mode: GeneratorMode,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            name: "default".into(),
            length: 20,
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
}
