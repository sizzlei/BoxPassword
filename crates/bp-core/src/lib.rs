//! BoxPassword 도메인 타입과 유스케이스의 자리.
//!
//! 이 크레이트는 외부 I/O(파일/네트워크)나 암호화 구현에 직접 의존하지 않습니다.
//! 저장소와 암호화는 각각 [`bp_storage`]와 [`bp_crypto`] 크레이트에서 다룹니다.
//!
//! v0.1에서는 골격만 정의해 두며, 실제 유스케이스는 마일스톤별로 채워 넣습니다.
#![forbid(unsafe_code)]

pub mod entry;
pub mod error;
pub mod policy;
pub mod version;

pub use entry::{Entry, EntryId, EntrySummary, GroupRow, NewEntry};
pub use error::{CoreError, CoreResult};
pub use policy::{GeneratorMode, PasswordPolicy};
pub use version::{EntryVersion, EntryVersionSummary};
