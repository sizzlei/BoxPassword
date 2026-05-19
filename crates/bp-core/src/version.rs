//! 항목의 변경 이력(버전) 메타데이터.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::entry::EntryId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryVersion {
    pub entry_id: EntryId,
    pub version: u32,
    pub created_at: OffsetDateTime,
    /// 변경 사유 메모(평문, 마스터 키로는 별도 봉인하지 않음 — 식별 정보 금지).
    pub reason: Option<String>,
}

/// 화면에 표시 가능한 버전 메타데이터(평문 필드만, 봉인된 비밀은 포함하지 않음).
#[derive(Debug, Clone, Serialize)]
pub struct EntryVersionSummary {
    pub version: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub reason: Option<String>,
    /// 현재 활성 버전인지 여부.
    pub is_current: bool,
}
