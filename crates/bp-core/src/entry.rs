//! 자격 증명 항목(Entry) 도메인 타입.
//!
//! v0.1에서는 비밀 필드 자체는 평문 `String`으로 다루되,
//! 디스크에 저장될 때는 `bp-storage`/`bp-crypto`를 거쳐 AEAD로 봉인합니다.
//! 메모리 누수 최소화는 사용 지점에서 [`zeroize`]로 처리합니다.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// 항목 식별자.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryId(pub Uuid);

impl EntryId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn parse(s: &str) -> Option<Self> {
        Uuid::parse_str(s).ok().map(Self)
    }
}

impl Default for EntryId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 새 항목을 만들 때 호출자가 채우는 입력.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub secret: String,
}

/// 메모리 상의 항목. 비밀은 `secret`에 들어있고, 화면 전달 시 호출자가 절제합니다.
#[derive(Debug)]
pub struct Entry {
    pub id: EntryId,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub secret: String,
    pub current_version: u32,
    pub updated_at: OffsetDateTime,
}

/// 리스트 화면에 노출해도 되는 메타데이터(평문 필드만).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub current_version: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub favorite: bool,
    pub group_id: Option<i64>,
    pub group_name: Option<String>,
    pub group_color: Option<String>,
    pub has_totp: bool,
    pub has_notes: bool,
    /// TOTP 알고리즘 (SHA1/SHA256/SHA512). 시드 없으면 None.
    pub totp_algorithm: Option<String>,
    pub totp_period: Option<u32>,
    pub totp_digits: Option<u32>,
    /// 비밀번호 변경 권장 주기(일). NULL이면 사용 안 함.
    pub rotation_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRow {
    pub id: i64,
    pub name: String,
    pub color: Option<String>,
    /// 이 그룹에 속한 항목 수(서버 측 집계).
    pub entry_count: i64,
}
